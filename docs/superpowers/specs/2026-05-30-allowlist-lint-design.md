# AnB v3.1.0 — `alice allowlist-check` Lint Command

> **Status:** Approved (inline brainstorming, 2026-05-30). Operator confirmed design + scope.
> **Type:** Additive — no breaking changes, no wire change, pure new CLI surface + new helper package.

## Why

v3.0 hands operators regex authoring power for `exec-allowlist.rules`. With power comes footguns: an operator can write `^/bin/sh -c .+$` (granting shell access to any agent), `^.+$\t*` (allow everything), or `^/Users/me/.local/bin/foo` (unescaped `.` matches `/Users/me/Xlocal/bin/foo`). The trivial-match-everything heuristic catches `^.*$` but not `^.+$`, and most operator footguns are not catchable at LoadFile time without losing legitimate flexibility.

A separate lint pass — opt-in, operator-invoked — surfaces these classes of issues with concrete hints. Two-stage trust:

- **LoadFile** stays strict on hard errors (parse failures, trivial-match-everything) and refuses to load the whole file.
- **`alice allowlist-check`** runs the same parse + a broader set of heuristics and reports findings with severity + suggestion. Operator opts in by running it; CI / pre-commit hooks could automate.

## Goal

Add a new `alice allowlist-check` subcommand that reads an allowlist rules file, runs lint checks, and reports findings in three severities (danger / warning / info). Exit code reflects severity.

## Non-goals

- `--fix` mode (auto-rewrite rules) — deferred. Manual operator review is the trust gate.
- Network-side checks (e.g., verifying that a regex's intended URL allowlist matches DNS reality) — out of scope.
- Cross-rule shadow detection (rule A masks rule B due to first-match-wins) — deferred to a future patch; simple per-rule lints only in v3.1.
- Replacing the LoadFile-time validation — that stays as the load-time gate. Lint is operator-invoked.

## CLI

```
alice allowlist-check [--file PATH] [--strict] [--dir DIR]
```

| Flag | Meaning |
|---|---|
| `--file PATH` | Lint this file instead of the default `<state>/exec-allowlist.rules`. Useful for pre-commit checks of a candidate rules file. |
| `--strict` | Exit non-zero on WARNINGs (default: only DANGER / parse errors exit non-zero). |
| `--dir DIR` | Standard state dir override (same as other alice commands). Ignored if `--file` is given. |

No subcommands (`alice allowlist-check` is the leaf). No interactive mode.

## Lint checks

Each rule is examined independently (no cross-rule analysis in v3.1). Findings carry:

```go
type Finding struct {
    Severity string  // "DANGER" | "WARNING" | "INFO"
    LineNo   int     // 1-based line in source file
    Rule     string  // the raw rule line, for context
    Message  string  // one-line description of the issue
    Hint     string  // concrete suggestion or a corrected example
}
```

### v3.1 lint catalogue

| # | ID | Severity | Detect | Hint |
|---|---|---|---|---|
| 1 | `trivial-match` | DANGER | regex matches a set of sentinel strings that no real cmd path should simultaneously match: `"a"`, `"X"`, `"/"`, `"/bin/sh"`, `"../../etc/passwd"`, `"some random string"`. If ALL match → flagged. Catches `^.*$`, `^.+$`, `^.{0,N}$` etc. | "narrow with a literal prefix; run `alice exec --show-match-string` to see the form your regex must match" |
| 2 | `script-host` | DANGER | regex matches one of the known script-host paths followed by `-c <anything>`. Checks against the hardcoded list: `/bin/sh`, `/bin/bash`, `/bin/zsh`, `/bin/dash`, `/usr/bin/python`, `/usr/bin/python3`, `/opt/homebrew/bin/python3`, `/usr/bin/perl`, `/usr/bin/awk`, `/usr/bin/jq`, `/opt/homebrew/bin/jq`. Test by `r.Regex.MatchString(host + " -c arbitrary")`. | "this grants arbitrary code execution; remove or restrict to specific scripts (allowlist a `*.py` path, never `python -c`)" |
| 3 | `env-wildcard` | WARNING | `r.EnvAny == true` (env column is `*`) | "list specific env names if possible; `*` accepts any name and weakens audit" |
| 4 | `unescaped-dot` | WARNING | regex source contains a literal `.` outside of a character class or escape. Heuristic: scan the raw regex string, count `.` that aren't preceded by `\`, aren't inside `[...]`, aren't inside `(?:...)`-style groups. If found in what LOOKS like a path component (between `/` chars), flag. | "regex `.` matches any char; use `\\.` for literal dot. Auto-blessed rules already escape correctly" |
| 5 | `no-label` | INFO | `r.Label == ""` | "add `\\t# <label>` as third column; without a label the audit-line shows `rule=line:N` which is less searchable" |

**Notes on heuristics:**

- `trivial-match`: must be **inclusive** (catch more than LoadFile's heuristic) since lint is a softer gate. Six sentinels with AND give very low false-positive rate.
- `script-host`: hardcoded list intentionally; future tools added there in v3.x patches. The match logic is "does this rule's regex match `<host> -c <something>`?" not "is the cmd path equal to a host" (operators might write the host with optional suffixes).
- `unescaped-dot`: heuristic is best-effort. False positives possible (e.g., `[a.b]` is a char class). Mark as WARNING, not DANGER — operator reviews.
- `no-label`: INFO only — labels aren't required by parse semantics; just an audit ergonomic.

## Output format

Plain text. UTF-8 emoji for severity markers (with text fallback if `NO_COLOR` env set — same convention as alice's other commands... actually alice doesn't have that yet, skip).

```
Checking /Users/bbwave03/.anb/alice/exec-allowlist.rules
3 rules loaded, 4 findings.

🚨 line 12: script-host (DANGER)
  ^/bin/sh -c .+$	*	# quick shell
  Hint: this grants arbitrary code execution; remove or restrict to specific scripts.

⚠ line 8: env-wildcard (WARNING)
  ^/usr/bin/curl .+$	*	# debug curl
  Hint: list specific env names (e.g. AUTH_TOKEN) unless the binary truly needs unrestricted env.

⚠ line 5: unescaped-dot (WARNING)
  ^/Users/me/.local/bin/encipherr (encrypt|decrypt) file .+$
  Hint: regex `.` matches any char. Change to `\.` for literal dot:
    ^/Users/me/\.local/bin/encipherr (encrypt|decrypt) file .+$

ℹ line 15: no-label (INFO)
  ^/usr/bin/cat .+$	K
  Hint: add `\t# <label>` as third column for audit attribution.

Summary: 3 rules, 1 danger, 2 warnings, 1 info
```

Last line is parseable: `Summary: N rules, X danger, Y warnings, Z info`.

## Parse-error handling

If the file has parse errors (lines that fail `aclrules.parseLine`), the lint command:

1. Reports each parse error first (severity: `ERROR`, exits 1 regardless of `--strict`)
2. Still runs lint on the rules that DID parse
3. Final summary mentions both

This differs from `LoadFile`'s refuse-the-whole-file behavior — operator wants ALL feedback in one pass when running lint.

## Exit codes

| Condition | Exit |
|---|---|
| No findings, no parse errors | 0 |
| Parse errors OR DANGER findings | 1 |
| Only WARNINGs and `--strict` flag | 2 |
| Only WARNINGs without `--strict` | 0 |
| Only INFO findings | 0 |

The `--strict` mode is for CI / pre-commit hooks that want hard-fail on anything questionable.

## File structure

| File | Role | Status |
|---|---|---|
| `internal/aclrules/lint.go` | `Lint([]Rule, raw []string) []Finding` — pure function, no I/O. Takes parsed rules + the raw source lines (for `unescaped-dot` which needs the regex source string). | Create (~150 LOC) |
| `internal/aclrules/lint_test.go` | Unit tests for each lint check + Severity enum + helper that runs lint against synthetic rules. | Create (~250 LOC) |
| `cmd/alice/allowlist.go` | `cmdAllowlistCheck` — flag parsing, file loading (via `aclrules.Parse` directly so partial parsing works), invokes `aclrules.Lint`, formats output. | Create (~120 LOC) |
| `cmd/alice/main.go` | Add `"allowlist-check": cmdAllowlistCheck` to the cmds map + usage row. | Modify (+2 LOC) |
| `README.md` | New section "Linting your allowlist" with example output. Cross-reference from "Allowlist rules format" section. | Modify (~60 LOC) |

Total estimated: ~250 LOC code + ~250 LOC tests + ~60 lines README.

## Implementation outline

### `internal/aclrules/lint.go`

```go
package aclrules

import (
    "fmt"
    "regexp"
    "strings"
)

type Severity string

const (
    SeverityDanger  Severity = "DANGER"
    SeverityWarning Severity = "WARNING"
    SeverityInfo    Severity = "INFO"
)

type Finding struct {
    ID       string // "trivial-match", "script-host", "env-wildcard", etc.
    Severity Severity
    LineNo   int
    Rule     string // raw rule line
    Message  string
    Hint     string
}

// Lint runs all lint checks over the given rules. Rules are assumed to
// be the output of Parse (no nil regex). The returned findings are
// sorted by line number, then by severity descending.
func Lint(rules []Rule) []Finding {
    var out []Finding
    for _, r := range rules {
        if f := lintTrivialMatch(r); f != nil { out = append(out, *f) }
        if f := lintScriptHost(r); f != nil { out = append(out, *f) }
        if f := lintEnvWildcard(r); f != nil { out = append(out, *f) }
        if f := lintUnescapedDot(r); f != nil { out = append(out, *f) }
        if f := lintNoLabel(r); f != nil { out = append(out, *f) }
    }
    return out
}

// (each lintX function returns *Finding or nil)
```

### `cmd/alice/allowlist.go`

```go
package main

import (
    "flag"
    "fmt"
    "os"
    "path/filepath"

    "github.com/kaka-milan-22/AnB/v3/internal/aclrules"
    "github.com/kaka-milan-22/AnB/v3/internal/localvault"
)

func cmdAllowlistCheck(args []string) error {
    fs := newFS("allowlist-check")
    fileFlag := fs.String("file", "", "rules file to check (default: state dir's exec-allowlist.rules)")
    strictFlag := fs.Bool("strict", false, "exit non-zero on WARNINGs as well as DANGERs")
    dir := dirFlag(fs)
    _ = fs.Parse(args)

    path := *fileFlag
    if path == "" {
        s := localvault.Open(*dir)
        path = filepath.Join(s.Dir, "exec-allowlist.rules")
    }

    f, err := os.Open(path)
    if err != nil { return err }
    defer f.Close()

    fmt.Printf("Checking %s\n", path)

    rules, parseErrs := aclrules.Parse(f)
    fmt.Printf("%d rules loaded", len(rules))

    findings := aclrules.Lint(rules)
    fmt.Printf(", %d findings.\n\n", len(findings) + len(parseErrs))

    // Print parse errors first
    for _, e := range parseErrs {
        fmt.Printf("❌ ERROR: %v\n\n", e)
    }

    // Print lint findings
    for _, fnd := range findings {
        emoji := map[aclrules.Severity]string{
            aclrules.SeverityDanger:  "🚨",
            aclrules.SeverityWarning: "⚠",
            aclrules.SeverityInfo:    "ℹ",
        }[fnd.Severity]
        fmt.Printf("%s line %d: %s (%s)\n  %s\n  Hint: %s\n\n",
            emoji, fnd.LineNo, fnd.ID, fnd.Severity, fnd.Rule, fnd.Hint)
    }

    // Summary + exit code
    var danger, warning, info int
    for _, fnd := range findings {
        switch fnd.Severity {
        case aclrules.SeverityDanger:  danger++
        case aclrules.SeverityWarning: warning++
        case aclrules.SeverityInfo:    info++
        }
    }
    fmt.Printf("Summary: %d rules, %d danger, %d warnings, %d info\n",
        len(rules), danger, warning, info)

    if len(parseErrs) > 0 || danger > 0 {
        os.Exit(1)
    }
    if *strictFlag && warning > 0 {
        os.Exit(2)
    }
    return nil
}
```

## README integration

Add a section "Linting your allowlist" right after "Allowlist rules format" section. Example:

```markdown
### Linting your allowlist

`alice allowlist-check` runs heuristic checks over your rules file
and reports footguns:

```sh
$ alice allowlist-check
Checking /Users/you/.anb/alice/exec-allowlist.rules
3 rules loaded, 1 finding.

🚨 line 5: script-host (DANGER)
  ^/bin/sh -c .+$	*	# debug
  Hint: this grants arbitrary code execution; remove or restrict.

Summary: 3 rules, 1 danger, 0 warnings, 0 info
```

Useful in pre-commit hooks (`alice allowlist-check --strict` exits
non-zero on warnings too) or CI of dotfile repos.
```

## Spec self-review

**Placeholder scan:** no TBDs, no "TODO", no "handle errors appropriately". All lint checks have concrete heuristic + concrete hint text.

**Internal consistency:** the five lint checks each have a stable ID; severities documented; exit codes mapped 1:1 from severities + `--strict`; `Finding` struct fields appear in `lint.go` + `allowlist.go` consistently.

**Scope check:** focused on one subcommand + one helper package. No protocol changes, no wire changes, no breaking. v3.1.0 minor bump.

**Ambiguity check:** `unescaped-dot` heuristic is fuzzy (could false-positive on `[a.b]`). Marked WARNING, not DANGER. Operator reviews. Doc'd.

Open question for operator review: should the lint command output ALSO be machine-parseable (JSON, `--format=json` flag)? Default leaning: no, v3.1 first ship — human-readable plain text + parseable summary line is enough. Add JSON in v3.2 if CI consumers need.
