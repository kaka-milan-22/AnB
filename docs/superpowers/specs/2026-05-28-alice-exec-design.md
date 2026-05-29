# Design: `alice exec` + `alice write` stderr routing

**Target**: v1.4.0
**Date**: 2026-05-28
**Status**: Approved, pending implementation plan.

## Context

The AnB threat model promises that AI agents never see plaintext on their visible stdout — `alice read` redacts to `<agent-vault:key>` placeholders, `alice write` restores them. The intent is that the agent operates on placeholders and the plaintext only exists inside Bob and inside the consumer process.

Real usage exposed the last-mile gap. `alice write /dev/stdout` (or `alice write -`) is a UNIX-style filter: restored plaintext goes to stdout, and so does the `✓ Written ...` confirmation. Any agent harness that captures both stdout and stderr — Playwright dumps on assertion failure, `bash set -x`, Claude Code stdout echo, CI runner log capture — re-introduces the plaintext into the agent's visible context.

The structural problem is bigger than which stream the confirmation lands on. Plaintext-on-stdout is fundamentally incompatible with "agent never sees plaintext" because any consumer of that stdout that the agent can read is a leak channel. Fixing the confirmation routing is a band-aid; the real fix is a consumer surface where plaintext **never reaches a stream the agent can read** — the value flows from Bob → alice memory → child process env, and `alice` itself disappears (via `syscall.Exec`) before any output happens.

This design specifies both: the architectural fix (`alice exec`) and the band-aid (`alice write` confirmations to stderr + `--quiet`).

## Scope

Two changes, landing on one branch, two commits (plus README bump):

1. **`alice exec`** — new subcommand. Plaintext substitution from vault placeholders into child-process env vars, then `syscall.Exec` the child. The alice process is replaced; nothing it writes ever appears on agent-visible stdout.

2. **`alice write` stderr routing + `--quiet`** — status/confirmation lines route to stderr; new `--quiet` flag suppresses them entirely. Preserves the existing `alice write /dev/stdout` behavior for legitimate non-agent uses but shrinks the agent-visible leak surface to just the restored content itself.

## `alice exec` design

### CLI surface

```
alice exec [--env KEY=<value-with-placeholders>]... [--dir DIR] -- <cmd> [args...]
```

- `--env KEY=VALUE` may be repeated. `VALUE` is arbitrary text; it may contain zero or more `<agent-vault:key>` placeholders mixed with literal text, identical semantics to `alice write` template restoration (free interpolation). Canonical examples:
  - `--env API_KEY=<agent-vault:openai-key>` (whole-value placeholder)
  - `--env DSN=postgres://app:<agent-vault:db-pw>@db.host/prod` (URL embed)
  - `--env LOG_LEVEL=debug` (no placeholder; literal pass-through is allowed)
- `KEY` matches `^[A-Za-z_][A-Za-z0-9_]*$` (POSIX env name).
- `--` separates alice flags from child argv. **No placeholder substitution on child argv** — argv may be in `/proc/<pid>/cmdline` (Linux: world-readable 0o644) so it must contain only operator-visible literal references like `$API_KEY`, not the secret itself.
- `--dir` follows the existing alice convention (override state dir; rarely needed).
- **No TTY requirement**. This is the agent-invokable safe path. The point of the subcommand is that agents can call it without seeing plaintext.

### Data flow

```
1. Parse --env list → collect referenced vault keys (deduped).
2. Resolve all referenced keys in one DecryptMany batch via the existing
   internal/client.Client (reuses the decryptAllValues batching pattern).
3. For each --env value, run redact.Restore(value, lookupFn) → resolved
   env list of strings "KEY=resolved-value".
4. exec.LookPath(cmd) → absolute path of the child binary.
5. Build mergedEnv with EXPLICIT dedupe (do NOT rely on append-then-let-
   syscall-deduplicate; execve(2)'s duplicate-key behavior is
   implementation-defined — glibc, musl, and macOS libc typically take
   the FIRST match via getenv, but POSIX does not pin this):
     mergedEnv := slices.Clone(resolved)
     overriddenNames := set of all KEY from --env
     for _, e := range os.Environ():
         if name(e) not in overriddenNames:
             append e to mergedEnv
   Result: resolved entries always win, inherited entries that don't
   collide pass through, no duplicates in the slice at all.
6. fmt.Fprintf(os.Stderr, "→ exec %s with env=%v\n", cmd, keysList)
   (audit hint in operator's terminal scrollback; key names only, never
   plaintext)
7. syscall.Exec(absPath, append([]string{cmd}, args...), mergedEnv)
   → alice's process image is REPLACED by the child. alice's stdout/
   stderr/stdin fds are inherited; alice's heap (which holds the
   plaintexts) is discarded by the kernel.
```

### Critical invariant

From step 3 (plaintexts materialized in alice's heap as `[]string`) to step 7 (`syscall.Exec`), the plaintext lives only in process memory. No fd writes happen. Step 7 hands fds to the child via inheritance — but the child's stdout/stderr is the child's responsibility; **alice itself never wrote plaintext anywhere**.

This is the architectural difference from `alice write /dev/stdout`: there is no point at which alice's stdout carries a secret.

### Env inheritance

The child inherits alice's env (`os.Environ()`) merged with `--env` (latter overrides on name collision). Standard `exec.Command` semantics. A clean-env mode is YAGNI; operators who want it can wrap with `env -i alice exec ...`.

### Child stdout/stderr

Inherited from alice's caller (terminal or pipe). Exit code of `alice exec` equals the child's exit code, via `syscall.Exec`'s standard process-replacement semantics — no special handling required.

### Error model (fail-closed)

`alice exec` must NEVER exec the child if any of these conditions hold:

- `--env KEY=VALUE` malformed (no `=`, empty KEY, KEY not POSIX-valid).
- Any `<agent-vault:key>` in any `--env` value references a key not in alice's vault.
- Bob unreachable (mTLS dial failure).
- Bob is locked (no master key held).
- DecryptMany returns any partial failure.
- `exec.LookPath(cmd)` fails.

On any of the above: alice prints an actionable error to stderr and exits non-zero. The child binary is never invoked. This prevents the degenerate failure mode where alice fails partway through and the child runs with the literal `<agent-vault:key>` string as an env value.

### Audit trail

Bob's existing `audit.Printf("ALLOW identity=%q op=%s keys=%v", ...)` already records which keys were decrypted by which identity. `alice exec` adds one line to its OWN stderr at step 6 above:

```
→ exec /usr/local/bin/curl with env=[API_KEY]
```

— so the operator running alice (or reviewing terminal scrollback) sees what was just authorized, without any plaintext.

No new audit channel is added on the alice side; Bob's existing audit log is canonical.

### `alice exec` does NOT need TTY

Explicitly: `requireTTY()` / `requireStdoutTTY()` are not called. This is the agent-invokable safe-mode command — that is its purpose.

The trust boundary shifts to "operator has decided alice exec is safe-mode + audits the agent's command lines". The argv-only-literals constraint (Q1) means operator-visible review of agent commands shows exactly which vault keys are being requested. The agent can request keys, but can't include plaintext in any field the agent itself can introspect.

## `alice write` stderr routing

### Changes

- Every status line in `cmdWrite` that currently goes to `fmt.Println(...)` (stdout) moves to `fmt.Fprintln(os.Stderr, ...)`. This includes the `✓ Written ...` confirmation and any "↳ restored N placeholders, M missing" diagnostic.
- New `--quiet` flag suppresses these stderr status lines entirely. With `--quiet`, stderr is silent; stdout receives only the restored content (when target is `/dev/stdout`/`-`) or nothing (when target is a file path).
- The restored content itself, when written to `/dev/stdout`/`-`, continues to land on stdout. This preserves legitimate non-agent uses (`alice write - < template > out.txt`).

### What this fixes vs doesn't

- Fixes: an agent harness that captures stdout for content-grep'ing no longer also captures `✓ Written ...`. The visible-on-stdout surface is the restored content only.
- Does NOT fix: the restored content itself on stdout when target is `/dev/stdout` is still a leak channel for any agent harness reading stdout. **`alice exec` is the architectural fix for that case**; `alice write --quiet` is just damage control for legacy scripts.

## Security model — explicit boundary

**`alice exec` eliminates** these leak vectors:
- Plaintext on alice's own stdout (the `alice write /dev/stdout` problem).
- Plaintext echoed into agent context via upstream/downstream script `set -x`, error dumps, runner log capture.
- Plaintext in shell history (argv contains only `<agent-vault:k>` placeholders, never resolved values).

**`alice exec` does NOT eliminate**:
- The child process printing the secret to its own stdout/stderr/network. `curl -v` dumping request headers, an app that logs auth tokens, etc. The child is responsible for its own output discipline; alice has no way to sandbox it without breaking the use case.
- Same-uid processes reading the child's env via `/proc/<pid>/environ` (Linux) or `ps eww` (macOS). Env-as-secret-channel is a standard Unix tradeoff; better than argv (cmdline is often world-readable) but worse than a true memory-only channel.
- Memory introspection — `gdb`, ptrace into the child, kernel core dumps. These are outside the AnB threat model.

The trust boundary moves from "alice + the entire surrounding pipeline" to "alice + the specific child command + same-uid process access". This is strictly stronger than today's stdout-based model.

## Files touched

| File | Change | ~LOC |
|---|---|---|
| `cmd/alice/main.go` | cmds map: add `"exec": cmdExec`; usage table: add row; package doc comment: add `exec` to the safe-list | +5 |
| `cmd/alice/safe.go` | New `cmdExec` function: flag parse, `--env KEY=VAL` split, dedupe-key collection, `client.DecryptMany` call, `redact.Restore` on each env value, `exec.LookPath` + `syscall.Exec`, fail-closed error paths, audit stderr line | +90 |
| `cmd/alice/safe.go` | `cmdWrite` status lines: `fmt.Println` → `fmt.Fprintln(os.Stderr, ...)`; new `--quiet` flag | +5 / -5 |
| `cmd/alice/safe_test.go` (new or extended) | Unit-test `--env KEY=VAL` parsing, key-name validation, placeholder extraction, fail-closed paths. Mock the client.Client for DecryptMany. | +80 |
| `e2e/full_test.go` | `TestAliceExec` — spin up CA + Bob, set a secret, invoke `alice exec --env FOO=<agent-vault:k> -- /bin/sh -c 'printf "%s" "$FOO" > $1' _ outfile`, read outfile, assert plaintext matches. Plus a fail-closed test (unknown key → child never runs). | +70 |
| `README.md` | Features: new bullet "agent-safe exec". Daily use: `alice exec` example with curl. Command table (safe): new row. Trust boundary: a sentence about what env-channel-vs-argv buys. | +25 |
| `internal/redact/redact.go` | Verify `Restore` works on single-line strings (probably no change needed; it takes a `content string`). | 0 expected |

**Total**: ~200 lines source + ~150 lines tests + ~25 lines docs.

## Verification

End-to-end after merge:

1. `go test ./...` green (incl. new alice exec unit + e2e tests).
2. `go vet ./...` clean; `gofmt -l .` silent.
3. `alice exec --help` shows the flag list and usage.
4. `alice exec --env FOO=<agent-vault:somekey> -- /bin/sh -c 'echo "$FOO"'` prints the plaintext on stdout (the child's stdout, not alice's — alice has already `Exec`'d away by then).
5. `alice exec --env FOO=<agent-vault:nonexistent-key> -- echo hi` exits non-zero and does NOT run `echo` (verifiable by checking the absence of `hi` in output).
6. `alice exec --env FOO=<agent-vault:k> -- echo "$FOO"` prints the LITERAL string `$FOO` (child shell unexpanded, since the child is `echo` directly without a shell).
7. `alice exec --env FOO=<agent-vault:k> -- bash -c 'echo "$FOO"'` prints the plaintext (bash expands).
8. `alice write --quiet -` writes restored content with no status lines on either stream.
9. `alice write -` writes restored content to stdout AND status lines to stderr (no longer to stdout).
10. README's new `alice exec` example runs end-to-end against a fresh AnB install.

## Version

**v1.4.0** — minor bump. `alice exec` is a new user-visible subcommand; `alice write` gains a new flag and shifts stream routing for status lines. No breaking changes for callers that don't read alice's stdout for status info.

## Out of scope

- Clean-env mode for `alice exec` (use `env -i alice exec ...`).
- Per-invocation operator gate flag (`--gate` / `--prompt-on-each`). Operators wanting human-in-loop can wrap alice exec in their own approval tool.
- Audit log on the alice side beyond the one stderr hint. Bob's audit is canonical.
- Allowing placeholders in child argv. Q1 settled this: no.
- `alice exec --policy <name>` style allowlist of commands. YAGNI — current model is "operator vets the agent's command lines" which is one-level-up review.
- Sandboxing the child (seccomp, cgroups, network deny). Out of AnB's scope.
