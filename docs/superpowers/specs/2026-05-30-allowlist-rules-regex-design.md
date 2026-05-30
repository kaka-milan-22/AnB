# AnB v3.0.0 — Regex-based Allowlist Rules

> **Status:** Draft, awaiting operator review.
> **Replaces:** v2.0 strict-equality + v2.1 TTY confirm-and-append model in `exec-allowlist.json`.
> **Breaking:** Yes — major version bump. File format changes from JSON to plain text; existing entries auto-migrate.

## Why

v2.0's strict-equality allowlist (each `args` position byte-for-byte exact, length exact, `env` set-equality) was deliberately rigid to keep agent-issued commands honest. v2.1 added an auto-bless TTY prompt so operators could iterate without hand-editing JSON every time.

Six months of real use surfaced two tensions:

1. **Repeated-shape operator workflows hit auto-bless N times.** Encrypting 50 files with `encipherr encrypt file <path>` needs 50 strict entries or 50 `yes` prompts. Operator either bloats `exec-allowlist.json` with one-off entries (stale within a day) or pipes `yes |` to bypass — the latter being precisely the reflex-yes failure mode v2.1's prompt was meant to prevent.

2. **Agent workflows have similar shape but lower trust.** An agent that wants to call `gh issue view 1234`, `gh issue view 5678`, `gh issue view 9012` would face the same N-entries-or-N-prompts cost as the operator. v2.6.1 docs steer operators toward `alice shell` for their own batches, but `alice shell` is TTY-only — agents still hit the original allowlist.

The v2.x answer to both is "one strict rule per invocation shape." This works but inflates the allowlist file with templated entries that differ only in a positional argument. Operators stop reviewing the file because there's nothing meaningful to review — just paths and IDs.

We tried two patch-style fixes during design (per-position `null` wildcards; trailing `*` + per-position `null`; structured matching with `oneof`/`glob`/`regex` pattern objects). All of them traded simplicity for expressiveness in ways that operators don't reliably reason about — wildcards in JSON arrays are easy to mis-author, glob patterns aren't filesystem-aware so they don't actually constrain paths, and matching "this subcommand or that subcommand" required either alternation syntax or duplicate entries.

The elegant primitive is **one regex per line.** Operator writes a regex that matches the entire `cmd args...` string. AnB matches against it. No JSON schema, no field discrimination, no pattern-type taxonomy.

## Goal

Replace `exec-allowlist.json`'s structured matching with a plain-text rules file where each line is a Go RE2 regex matched against the shellescape-joined `cmd args...` invocation string. Auto-bless still works, but writes a fully-escaped literal regex line that an operator can manually loosen later.

## Non-goals

- Per-rule rate limiting (v2.5 has identity-level rate limit; out of scope for v3.0)
- Sandbox / capability integration (e.g., `sandbox-exec` profile per rule) — future work
- Path-traversal protection (`..` segment rejection, symlink resolution) — regex matches argv strings; the binary decides how to interpret them
- Generic argv parser (recognizing flags vs positionals) — AnB does not pretend to parse 1000 different CLI grammars
- Hardcoded script-host blacklist (`sh -c`, `python -c`, etc.) — operator writes their own rules; if they explicitly bless `sh -c <pattern>`, that's their call

## File format

**Path:** `~/.anb/alice/exec-allowlist.rules` (override via `--dir` or `$ANB_ALICE_DIR` as usual).

**Encoding:** UTF-8, LF-terminated lines.

**Line types:**

| Line | Meaning |
|---|---|
| Empty | Ignored. |
| Whitespace-only | Ignored. |
| Begins with `#` (after optional whitespace trim) | Comment. Ignored. |
| Any other | A rule. Parsed as three tab-separated fields. |

**Rule line format:** `<regex>\t<env-csv>\t<#comment>` — tab-separated, three fields, last two optional.

- **Field 1 (regex, required):** Go RE2 regex pattern. **Implicitly anchored** — alice wraps in `^(?:...)$` at compile time. Operator may add their own `^`/`$` for clarity; redundant but harmless.
- **Field 2 (env-csv, optional):** Comma-separated allowed env-var names. Whitespace around names is trimmed. Empty string means *no `--env` flags allowed for this rule*. May be `*` (single-char marker) to mean *any env-var name allowed* (intentionally rare; document loudly).
- **Field 3 (comment, optional):** Must start with `#` after the tab. Anything after `#` is the rule's audit label. Empty `# ` is allowed (no label).

**Examples:**

```text
# Allow encipherr file ops with the ENCIPHERR_KEY env.
^/Users/bbwave03/\.local/bin/encipherr (encrypt|decrypt) file '?[^']+'?$	ENCIPHERR_KEY	# encipherr file ops

# Allow gh issue read-only operations.
^/opt/homebrew/bin/gh issue view [0-9]+$	GH_TOKEN	# gh issue view ro

# Allow kubectl logs/describe in production with any pod name.
^/opt/homebrew/bin/kubectl (logs|describe) -n production [a-z0-9-]+( --tail [0-9]+)?$	KUBECONFIG	# kubectl prod read

# bob list-keys takes no env.
^/Users/bbwave03/go/bin/bob list-keys$		# bob list-keys

# n9e login takes two env vars; either can be passed in any subset.
^/usr/bin/node /Users/bbwave03/work/n9e-login\.js$	N9E_USERNAME,N9E_PASSWORD	# n9e login
```

**Errors at parse time** (fail the whole file with a friendly stderr message and line number, no rules loaded → all `alice exec` denies):

- Regex compile error
- Field 2 contains invalid env-var name (must match `^[A-Za-z_][A-Za-z0-9_]*$` per POSIX) — except for the literal `*` marker
- Field 3 present but doesn't start with `#`
- More than 3 tab-separated fields per line

## Match semantics

**Canonicalization** — alice constructs the match string as:

```text
match_str = shellescape(cmd) + " " + shellescape(arg1) + " " + ... + shellescape(argN)
```

`shellescape` uses POSIX single-quote rules:

- If arg has no special chars (`[A-Za-z0-9_\-./:=@,]`), unchanged.
- Otherwise wrapped in single quotes, with embedded single quotes encoded `'\''`.

Examples:

| argv | match_str |
|---|---|
| `["/usr/bin/echo", "hello"]` | `/usr/bin/echo hello` |
| `["/usr/bin/echo", "hello world"]` | `/usr/bin/echo 'hello world'` |
| `["/usr/bin/echo", "it's"]` | `/usr/bin/echo 'it'\''s'` |
| `["/usr/bin/echo", ""]` | `/usr/bin/echo ''` |
| `["/.../encipherr", "encrypt", "file", "/tmp/foo.txt"]` | `/.../encipherr encrypt file /tmp/foo.txt` |
| `["/.../encipherr", "encrypt", "file", "/tmp/has space.txt"]` | `/.../encipherr encrypt file '/tmp/has space.txt'` |

**Rule iteration** — Rules are evaluated top-to-bottom. First matching rule wins.

**Regex match** — `regexp.MustCompile("^(?:" + rule_regex + ")$").MatchString(match_str)`. Go's RE2: linear time, no backtracking, no ReDoS.

**Env match** — given the matching rule's `env-csv`:

| env-csv | Operator's `--env` keys must satisfy |
|---|---|
| Empty | `len(--env) == 0` |
| `KEY1` | `{--env keys} ⊆ {KEY1}` — zero or one `--env KEY1` |
| `KEY1,KEY2,KEY3` | `{--env keys} ⊆ {KEY1, KEY2, KEY3}` — any subset |
| `*` | No restriction. Document loudly; operator's call |

**Subset (not equality)** because operator listing N env names declares the maximum allowed set; passing fewer is always safer. Operator who needs "must have exactly KEY1" writes two rules (one with KEY1, one without) — but typically they wouldn't.

**No match** — Deny.

## Default deny

If `exec-allowlist.rules` does not exist, `alice exec` denies all invocations and prints an init hint:

```text
✗ alice exec: no allowlist rules.
  Create /Users/bbwave03/.anb/alice/exec-allowlist.rules to bless commands.
  Run any command to see the auto-bless prompt (TTY required).
```

If the file exists but contains zero non-comment rules, same hard-deny but with a different hint pointing at the empty file.

## Auto-bless flow (TTY)

When `alice exec`'s invocation does not match any rule AND both stdin and stderr are TTYs, alice prompts:

```text
✗ alice exec: invocation not in allowlist.rules.

  cmd:  /Users/bbwave03/.local/bin/encipherr
  args: ["encrypt", "file", "/tmp/foo.txt"]
  env:  ["ENCIPHERR_KEY"]

To allow exactly this invocation, append to ~/.anb/alice/exec-allowlist.rules:

  ^/Users/bbwave03/\.local/bin/encipherr encrypt file /tmp/foo\.txt$	ENCIPHERR_KEY

(This is a fully-escaped LITERAL regex. Edit by hand to add wildcards.)

Append this rule and re-run your command? Type 'yes' to confirm [y/N]:
```

On `yes`:

1. Compute the candidate rule line as: `^` + `regexp.QuoteMeta(match_str)` + `$\t` + sorted CSV of env keys + `\t# auto-blessed <RFC3339-Z>`
2. Open `exec-allowlist.rules` `O_APPEND|O_CREATE|0o600`; append `"\n" + line + "\n"`; close. Or atomic write if file exists.
3. Print `✓ appended` and exit non-zero with "re-run your command" — same two-stage semantics as v2.1.

On anything other than `yes`: silent exit non-zero (v2.1 `errExecDenied` sentinel preserved).

**Auto-blessed rule is always fully literal-escaped.** Operator who wants to widen it (e.g., turn the specific file path into `[^/]+\.txt`) vim-edits the line. AnB never auto-generates a non-literal regex — the operator's review of the file is the trust boundary for wildcards.

## Migration from v2.x JSON

First run of v3.0+ alice with state directory:

```text
if exists(.rules):
    use it.
elif exists(.json):
    read .json
    for each entry: generate one .rules line
    write .rules atomically (0o600)
    rename .json → .json.bak
    log to stderr: "migrated v2.x exec-allowlist.json → exec-allowlist.rules; original kept as .json.bak"
else:
    scaffold an empty .rules with a header comment.
```

**JSON → rules line conversion** for each entry `{label, cmd, args, env}`:

```text
literal_match_str = regexp.QuoteMeta(shellescape(cmd) + " " + shellescape(arg1) + " " + ...)
rule = "^" + literal_match_str + "$" + "\t" + join(",", env) + "\t# " + label
```

Concretely:

```json
// v2.x JSON entry
{
  "label": "encipherr encrypt /tmp/foo.txt",
  "cmd":   "/Users/bbwave03/.local/bin/encipherr",
  "args":  ["encrypt", "file", "/tmp/foo.txt"],
  "env":   ["ENCIPHERR_KEY"]
}
```

migrates to:

```text
^/Users/bbwave03/\.local/bin/encipherr encrypt file /tmp/foo\.txt$	ENCIPHERR_KEY	# encipherr encrypt /tmp/foo.txt
```

Migration is **strictly behavior-preserving** for each v2.x entry — the literal-anchored regex matches exactly the same invocation that the JSON strict-equality entry matched. Operator who wants to merge / widen rules does so manually post-migration.

## Helper: `alice exec --show-match-string`

New flag (no daemon round-trip, no exec): print the canonical match_str for the given invocation without running it. Useful for operators writing rules.

```sh
$ alice exec --show-match-string -- /Users/bbwave03/.local/bin/encipherr encrypt file "/tmp/has space.txt"
/Users/bbwave03/.local/bin/encipherr encrypt file '/tmp/has space.txt'
```

Operator pastes this into the rules file and constructs a regex around it.

## Audit log

`bob.log` JSON ALLOW event gains a `rule` field carrying the audit label (Field 3 minus the leading `#`), or the rule's line number if no label:

```json
{"ts":"2026-05-30T12:34:56Z","kind":"ALLOW","identity":"alice-local","op":"decryptMany","keys":["encipherr-key"],"reason":"[encipherr file ops]","rule":"encipherr file ops"}
```

For `--reason "..."` invocations, `reason` remains operator-supplied; `rule` is the matched rule's label, independently. Operator can grep audit log by either field.

## Out of scope (v3.0)

- Per-rule rate limit (extend `authz.json::rate_limits` if needed; rules file is matching only)
- Sandbox profiles (sandbox-exec, AppArmor, etc.) per rule
- Path canonicalization (regex matches argv strings; `..` traversal is the binary's problem)
- Glob shorthand (`[*]`, `*`, etc.) as syntactic sugar over regex — operator writes RE2 directly
- File-format includes (`@include /etc/anb/global.rules`) — single file simpler
- Auto-loosening (alice suggests a wildcard pattern after observing N similar literal rules) — operator edits manually
- TUI / `alice allowlist edit` command — operator uses vim

## Open risks

**1. Operator writes `.*` by accident.** A rule like `^.*$\t*\t# everything` matches any invocation with any env. AnB **detects this at load** and refuses to start if any rule matches every-string — specifically, refuse if `^(?:RULE)$` compiles to a regex whose `MatchString("")` AND `MatchString("/")` AND `MatchString("../../etc/passwd")` all return true (heuristic for "trivially matches everything"). Operator gets a friendly error and must narrow.

**2. Forgetting anchors.** Mitigated by implicit `^...$` wrapping at compile time; operator cannot turn it off.

**3. ReDoS.** Mitigated by Go RE2 (linear time, no backtracking). Plus per-rule regex size limit (4 KB) so a rule line can't be pathological.

**4. Shellescape quoting confusion.** Operator writes `.+` expecting to match the path but doesn't realize args with spaces are single-quoted in canonical form. Mitigated by the `alice exec --show-match-string` helper that operators run during rule authoring.

**5. Multiple matching rules.** First match wins, so rule order matters. Operator who writes specific-rules-before-general-rules wins; reverse order silently over-matches. **README explains** the top-down semantics.

**6. Rule file lost.** Without `exec-allowlist.rules`, all alice exec deny. Operator re-creates from `bob.log` audit history (`grep '"rule":'` for inventory) or from `.json.bak` after migration. Backup story unchanged from v2.x (`scripts/anb-backup.sh` captures it).

**7. CLAUDE.md dotfile rule.** `exec-allowlist.rules` lives under `~/.anb/alice/`. Per CLAUDE.md, Claude doesn't read this dotfile path without operator consent. Auto-migration and auto-bless are exec-time alice operations, not Claude operations — they run under alice's process, not Claude's. No conflict.

## Reference implementation outline

(Detailed task breakdown lives in the writing-plans pass; this is just scope sanity.)

**New package** `internal/aclrules/`:
- `Rule struct { Regex *regexp.Regexp; EnvAllow []string; EnvAny bool; Label string; LineNo int; Raw string }`
- `Parse(io.Reader) ([]Rule, []error)` — line-by-line, no I/O dependencies
- `LoadFile(path string) ([]Rule, error)` — reads file + delegates to Parse
- `(*Rule).Matches(matchStr string, envKeys []string) bool`
- `Canonicalize(cmd string, args []string) string` — shellescape join
- `LiteralRule(cmd string, args []string, envKeys []string, label string) string` — auto-bless output line

**Modify `cmd/alice/exec.go`:**
- `cmdExec` replaces JSON allowlist load with `aclrules.LoadFile`
- `matchAllowlist` rewritten as iterate-and-Match against rules
- Auto-bless writes to `.rules` not `.json`
- `--show-match-string` flag

**Modify `cmd/alice/sensitive.go::cmdEnroll`:**
- Scaffold `.rules` instead of `.json` for new installs
- Header comment in the scaffold explains the format

**Modify `cmd/alice/main.go`:**
- One-time migration: if `.json` exists and `.rules` doesn't, migrate then rename

**Modify `internal/server/server.go`:**
- Audit log `ALLOW` includes `rule: "<label>"` field
- No proto/wire change; `rule` is a server-side log field, not transmitted

**Tests:**
- `aclrules.Parse` — comment / blank / 3-col / unparseable regex / empty env / star env
- `aclrules.Canonicalize` — argv with/without specials, edge cases (empty arg, embedded quote)
- `aclrules.Rule.Matches` — anchor enforcement, subset env, no-match
- Migration: synthetic `.json` → expected `.rules` content
- E2E: rule file in temp dir + alice exec match/no-match paths
- E2E: auto-bless TTY simulation (via piped stdin reading "yes\n")
- Trivial-match-everything detection refuses load

Estimated **~680 LOC code + ~400 LOC tests** + ~120 lines README.

## Open questions (for operator review before plan)

1. **`*` env marker** — keep or drop? If kept, operator can write rules with arbitrary env-name set. Mostly useful for *trust-this-binary-with-any-env* capabilities (e.g., a trusted internal CLI). Default leaning: keep, with bold doc warning.
2. **Trivial-match-everything detection** — too clever? Operator might want `^.*$` for testing. Maybe just stderr-warn instead of refusing to load.
3. **`--show-match-string` location** — flag on `exec`, or its own subcommand `alice match-string -- cmd args`? The latter is more discoverable; the former is one-fewer commands to memorize.
4. **Backward compat:** keep reading `.json` indefinitely (don't migrate, run both formats), or one-shot migrate + rename? Default leaning: one-shot migrate (cleaner state).
5. **Label as third column with `#`** — what if operator wants a literal `#` in regex (e.g., URL fragment)? Tab-separator means the `#` is only special at the start of column 3. URLs with `#` in column 1 are fine since they're in a different field. Confirmed safe; flag explicitly for the reviewer's pass.

---

## Spec self-review

**Placeholder scan:** no TBDs or hand-waves. All design choices have rationale or "out of scope" marker.

**Internal consistency:** match semantics, auto-bless flow, migration story, and audit log all use the same canonicalization function. No contradictions surfaced.

**Scope check:** focused on the allowlist file model. Doesn't touch wire protocol, K rotation, vault encryption, or alice/bob binaries beyond allowlist code paths. Single-PR scope.

**Ambiguity check:** the "subset" semantics for env-csv was the historical sharp edge — explicitly documented with example table.

Ready for operator review.
