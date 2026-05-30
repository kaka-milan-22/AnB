# AnB v3.1.0 — `alice allowlist-check` Lint Command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** New `alice allowlist-check` subcommand that lints `exec-allowlist.rules` and reports operator footguns (regex matches everything, script-host wildcards, env=`*`, unescaped `.`, missing label) in three severity levels with exit-code mapping.

**Architecture:** New `internal/aclrules/lint.go` exposes pure `Lint([]Rule) []Finding`. Five lint functions, each `func lintX(r Rule) *Finding` (nil = no finding). New `cmd/alice/allowlist.go::cmdAllowlistCheck` wires the flag parsing, file loading via `aclrules.Parse` (partial parse OK), pretty-print, exit codes. No wire change.

**Tech Stack:** Go 1.26 (existing). Stdlib only — `regexp` (existing in aclrules), `strings`, `fmt`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-05-30-allowlist-lint-design.md`

---

## File Structure

| File | Role | Status |
|---|---|---|
| `internal/aclrules/lint.go` | `Severity`, `Finding`, `Lint([]Rule) []Finding`, five unexported `lintX(r Rule) *Finding` checks | Create (~150 LOC) |
| `internal/aclrules/lint_test.go` | Per-check unit tests + `Lint` integration tests | Create (~250 LOC) |
| `cmd/alice/allowlist.go` | `cmdAllowlistCheck` — flag parsing + file load + lint + format + exit | Create (~120 LOC) |
| `cmd/alice/main.go` | Dispatcher: add `"allowlist-check": cmdAllowlistCheck`; usage row | Modify (+3 LOC) |
| `README.md` | New "Linting your allowlist" subsection under Allowlist rules format | Modify (~60 LOC) |

Total ~250 LOC code + ~250 LOC tests + ~60 lines README.

---

### Task L1: `Finding` + `Severity` types + `Lint` skeleton

**Files:**
- Create: `internal/aclrules/lint.go`
- Create: `internal/aclrules/lint_test.go`

Establish the types and the dispatch loop. Each lint check is a `func(Rule) *Finding`; `Lint` iterates all rules × all checks and collects non-nil findings. Tests verify the types exist + Lint returns an empty slice on empty input.

- [ ] **Step 1: Write the failing tests**

Create `internal/aclrules/lint_test.go`:

```go
package aclrules

import (
	"strings"
	"testing"
)

func TestLintEmpty(t *testing.T) {
	findings := Lint(nil)
	if len(findings) != 0 {
		t.Errorf("Lint(nil) = %v, want []", findings)
	}
}

func TestLintEmptyRulesSlice(t *testing.T) {
	findings := Lint([]Rule{})
	if len(findings) != 0 {
		t.Errorf("Lint([]Rule{}) = %v, want []", findings)
	}
}

func TestSeverityConstants(t *testing.T) {
	// Lock the string values — they appear in operator-facing output.
	if string(SeverityDanger) != "DANGER" {
		t.Errorf("SeverityDanger = %q, want %q", SeverityDanger, "DANGER")
	}
	if string(SeverityWarning) != "WARNING" {
		t.Errorf("SeverityWarning = %q, want %q", SeverityWarning, "WARNING")
	}
	if string(SeverityInfo) != "INFO" {
		t.Errorf("SeverityInfo = %q, want %q", SeverityInfo, "INFO")
	}
}

func TestFindingFieldsAccessible(t *testing.T) {
	// Compile-time check that the Finding struct has the expected fields.
	f := Finding{
		ID:       "test",
		Severity: SeverityDanger,
		LineNo:   1,
		Rule:     "raw",
		Message:  "msg",
		Hint:     "hint",
	}
	if f.ID != "test" || f.LineNo != 1 {
		t.Error("Finding fields not assignable")
	}
}

// mustParseOneRule is defined in aclrules_test.go (Task A3); reuse it.

func TestLintBenignRuleProducesNoFindings(t *testing.T) {
	// A well-formed, narrow, labeled rule should produce zero findings
	// from the no-op skeleton in this task. (Later tasks add lints that
	// may flag things; this test verifies the dispatch loop is benign
	// when no checks have been wired in yet.)
	r := mustParseOne(t, "^/bin/echo hello$\tKEY\t# echo hello")
	findings := Lint([]Rule{r})
	// Skeleton has zero checks wired → expect zero findings.
	if len(findings) != 0 {
		t.Errorf("expected zero findings from skeleton; got %v", findings)
	}
}

// Suppress unused-import warning until later tasks add tests that use strings.
var _ = strings.Contains
```

- [ ] **Step 2: Run tests to verify they fail**

```sh
cd /Users/bbwave03/claude/anb
go test ./internal/aclrules/ -count=1 -run 'TestLint\|TestSeverity\|TestFinding' -v
```

Expected: build error (`undefined: Lint`, `undefined: Severity`, `undefined: Finding`, `undefined: SeverityDanger`).

- [ ] **Step 3: Implement the skeleton**

Create `internal/aclrules/lint.go`:

```go
package aclrules

// Severity is the lint-finding severity level. String values are
// operator-visible (appear in alice allowlist-check output and in
// CI log scraping).
type Severity string

const (
	SeverityDanger  Severity = "DANGER"
	SeverityWarning Severity = "WARNING"
	SeverityInfo    Severity = "INFO"
)

// Finding is one lint hit on one rule.
type Finding struct {
	ID       string   // stable identifier (e.g. "trivial-match", "script-host")
	Severity Severity // DANGER | WARNING | INFO
	LineNo   int      // 1-based line in source file
	Rule     string   // raw rule line, for context
	Message  string   // one-line description of the issue
	Hint     string   // concrete suggestion or corrected example
}

// lintCheck is the signature each individual check must satisfy.
type lintCheck func(r Rule) *Finding

// lintChecks is the registry of all enabled checks. Tasks L2-L6 each
// append one entry to this slice.
var lintChecks = []lintCheck{
	// Tasks L2-L6 add entries here.
}

// Lint runs every registered check against every rule. Findings are
// returned in (line, check-registration) order; no sorting beyond that.
func Lint(rules []Rule) []Finding {
	var out []Finding
	for _, r := range rules {
		for _, check := range lintChecks {
			if f := check(r); f != nil {
				out = append(out, *f)
			}
		}
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/aclrules/ -count=1 -run 'TestLint\|TestSeverity\|TestFinding' -v
```

Expected: all 4 tests PASS.

- [ ] **Step 5: Vet + fmt + full pkg**

```sh
go vet ./internal/aclrules/
gofmt -l internal/aclrules/
go test ./internal/aclrules/ -count=1
```

Expected: silent, all prior tests still pass.

- [ ] **Step 6: Commit**

```sh
git add internal/aclrules/lint.go internal/aclrules/lint_test.go
git commit -m "$(cat <<'EOF'
feat(aclrules): Lint skeleton — Severity, Finding, dispatch loop

Foundation for v3.1's alice allowlist-check command. Each lint
check is a func(Rule) *Finding; Lint() iterates the lintChecks
registry against all rules and collects non-nil hits.

Five checks (trivial-match, script-host, env-wildcard,
unescaped-dot, no-label) land as separate commits in tasks L2-L6,
each appending one entry to the lintChecks slice.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task L2: `trivial-match` check (DANGER)

**Files:**
- Modify: `internal/aclrules/lint.go`
- Modify: `internal/aclrules/lint_test.go`

Flag rules whose regex matches a battery of sentinel strings simultaneously. Catches `^.*$`, `^.+$`, `^.{0,100}$`, `.*` permutations.

- [ ] **Step 1: Write the failing tests**

Append to `internal/aclrules/lint_test.go`:

```go
func TestLintTrivialMatchStar(t *testing.T) {
	// ^.*$ matches literally everything including empty.
	r := mustParseOne(t, "^.*$\t*\t# trivially permissive")
	findings := Lint([]Rule{r})
	if len(findings) != 1 || findings[0].ID != "trivial-match" {
		t.Fatalf("expected 1 trivial-match finding; got %v", findings)
	}
	if findings[0].Severity != SeverityDanger {
		t.Errorf("Severity = %q, want DANGER", findings[0].Severity)
	}
	if findings[0].LineNo != 1 {
		t.Errorf("LineNo = %d, want 1", findings[0].LineNo)
	}
}

func TestLintTrivialMatchPlus(t *testing.T) {
	// ^.+$ matches any non-empty string. LoadFile's heuristic doesn't
	// catch this (empty string fails) but Lint's broader heuristic does.
	r := mustParseOne(t, "^.+$\tKEY\t# plus-permissive")
	findings := Lint([]Rule{r})
	if len(findings) != 1 || findings[0].ID != "trivial-match" {
		t.Fatalf("expected trivial-match finding; got %v", findings)
	}
}

func TestLintTrivialMatchRangeQuantifier(t *testing.T) {
	// ^.{0,1000}$ also accepts a huge range of strings.
	r := mustParseOne(t, "^.{0,1000}$\tKEY\t# range")
	findings := Lint([]Rule{r})
	if len(findings) != 1 || findings[0].ID != "trivial-match" {
		t.Fatalf("expected trivial-match finding; got %v", findings)
	}
}

func TestLintTrivialMatchNarrowDoesNotFire(t *testing.T) {
	// A narrow regex should NOT trip trivial-match.
	r := mustParseOne(t, "^/bin/echo .+$\tKEY\t# echo with arg")
	findings := Lint([]Rule{r})
	for _, f := range findings {
		if f.ID == "trivial-match" {
			t.Errorf("narrow regex incorrectly flagged as trivial-match: %v", f)
		}
	}
}
```

- [ ] **Step 2: Run to verify they fail**

```sh
go test ./internal/aclrules/ -count=1 -run 'TestLintTrivialMatch' -v
```

Expected: 3 failures (FAIL — expected finding, got none). `NarrowDoesNotFire` passes vacuously.

- [ ] **Step 3: Implement `lintTrivialMatch`**

In `internal/aclrules/lint.go`, append:

```go
// trivialMatchSentinels are inputs that no realistic command-allowlist
// rule should accept simultaneously. If a rule's regex matches all of
// them, it's a regex-matches-everything pattern that should be tightened.
//
// Six sentinels with AND give very low false-positive rate:
// - "" empty
// - "/" root
// - "/bin/sh" a real (dangerous) cmd path
// - "../../etc/passwd" path traversal
// - "a" single char
// - "some random string" arbitrary string
var trivialMatchSentinels = []string{
	"",
	"/",
	"/bin/sh",
	"../../etc/passwd",
	"a",
	"some random string",
}

func lintTrivialMatch(r Rule) *Finding {
	for _, s := range trivialMatchSentinels {
		if !r.Regex.MatchString(s) {
			return nil // rule rejects at least one sentinel → not trivial
		}
	}
	return &Finding{
		ID:       "trivial-match",
		Severity: SeverityDanger,
		LineNo:   r.LineNo,
		Rule:     r.Raw,
		Message:  "regex matches every input string (trivial-match-everything)",
		Hint:     "narrow with a literal prefix; run `alice exec --show-match-string -- <cmd> <args>` to see exactly what string your regex must match",
	}
}
```

And wire it into the registry — find the `lintChecks` declaration and update:

```go
var lintChecks = []lintCheck{
	lintTrivialMatch,
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/aclrules/ -count=1 -run 'TestLintTrivialMatch' -v
```

Expected: 4 PASS.

- [ ] **Step 5: Full pkg + vet + fmt**

```sh
go test ./internal/aclrules/ -count=1
go vet ./internal/aclrules/
gofmt -l internal/aclrules/
```

Expected: green / silent.

- [ ] **Step 6: Commit**

```sh
git add internal/aclrules/lint.go internal/aclrules/lint_test.go
git commit -m "$(cat <<'EOF'
feat(aclrules): lint check 'trivial-match' (DANGER)

Flags rules whose regex matches every input string (the canonical
operator footgun). Six-sentinel AND test: empty, root, /bin/sh,
traversal-y string, single char, random string. If ALL match → flag.

Broader than LoadFile's heuristic which only checks 3 sentinels —
LoadFile must stay conservative (refuses to load the whole file on
hit), Lint is opt-in and softer (just reports).

Catches: ^.*$, ^.+$, ^.{0,N}$, .*$, and similar variants.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task L3: `script-host` check (DANGER)

**Files:**
- Modify: `internal/aclrules/lint.go`
- Modify: `internal/aclrules/lint_test.go`

Flag rules whose regex covers `<host> -c <anything>` for any known script-execution binary. These grant arbitrary code execution.

- [ ] **Step 1: Write the failing tests**

Append to `internal/aclrules/lint_test.go`:

```go
func TestLintScriptHostSh(t *testing.T) {
	r := mustParseOne(t, "^/bin/sh -c .+$\t*\t# debug shell")
	findings := Lint([]Rule{r})
	got := findID(findings, "script-host")
	if got == nil {
		t.Fatalf("expected script-host finding; got %v", findings)
	}
	if got.Severity != SeverityDanger {
		t.Errorf("Severity = %q, want DANGER", got.Severity)
	}
}

func TestLintScriptHostPython(t *testing.T) {
	r := mustParseOne(t, "^/usr/bin/python3 -c .+$\tK")
	if got := findID(Lint([]Rule{r}), "script-host"); got == nil {
		t.Errorf("expected script-host finding for python3")
	}
}

func TestLintScriptHostBash(t *testing.T) {
	r := mustParseOne(t, "^/bin/bash -c .+$\tK")
	if got := findID(Lint([]Rule{r}), "script-host"); got == nil {
		t.Errorf("expected script-host finding for bash")
	}
}

func TestLintScriptHostJqRaw(t *testing.T) {
	// jq -r '<expression>' allows expression-language execution; treat as script-host.
	r := mustParseOne(t, "^/opt/homebrew/bin/jq -r .+$\tK")
	if got := findID(Lint([]Rule{r}), "script-host"); got == nil {
		t.Errorf("expected script-host finding for jq -r")
	}
}

func TestLintNonScriptHostDoesNotFire(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo .+$\tK")
	if got := findID(Lint([]Rule{r}), "script-host"); got != nil {
		t.Errorf("echo should not trip script-host; got %v", got)
	}
}

func TestLintScriptHostBlockedSpecificScript(t *testing.T) {
	// Allowing a specific .py script (not -c inline) is NOT script-host.
	r := mustParseOne(t, `^/usr/bin/python3 /Users/me/safe\.py( [^ ]+)*$` + "\tK")
	if got := findID(Lint([]Rule{r}), "script-host"); got != nil {
		t.Errorf("specific script path should not trip script-host; got %v", got)
	}
}

// findID returns the first finding with the given ID, or nil if none.
func findID(findings []Finding, id string) *Finding {
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i]
		}
	}
	return nil
}
```

- [ ] **Step 2: Run to verify they fail**

```sh
go test ./internal/aclrules/ -count=1 -run 'TestLintScriptHost\|TestLintNonScriptHost' -v
```

Expected: 4 failures (the 4 positive cases). 2 negative cases pass vacuously.

- [ ] **Step 3: Implement `lintScriptHost`**

In `internal/aclrules/lint.go`, append:

```go
// scriptHosts are absolute paths to binaries that interpret a -c
// argument (or equivalent) as code. A rule that matches any of these
// followed by `-c <anything>` grants arbitrary code execution.
var scriptHosts = []string{
	"/bin/sh",
	"/bin/bash",
	"/bin/zsh",
	"/bin/dash",
	"/bin/ksh",
	"/usr/bin/python",
	"/usr/bin/python3",
	"/opt/homebrew/bin/python3",
	"/usr/bin/perl",
	"/opt/homebrew/bin/perl",
	"/usr/bin/awk",
	"/usr/bin/gawk",
	"/opt/homebrew/bin/awk",
}

// jqHosts get a separate check because jq's "-r" mode evaluates a
// query expression which is functionally code-exec for our purposes.
var jqHosts = []string{
	"/usr/bin/jq",
	"/opt/homebrew/bin/jq",
}

func lintScriptHost(r Rule) *Finding {
	// Check each known script host followed by " -c <stuff>".
	for _, host := range scriptHosts {
		// Probe: does the rule match `<host> -c something`?
		// We try a few `something` values to defeat trivial regex bounds.
		probes := []string{
			host + " -c x",
			host + " -c 'echo evil'",
			host + " -c " + "any-thing-here",
		}
		hit := true
		for _, p := range probes {
			if !r.Regex.MatchString(p) {
				hit = false
				break
			}
		}
		if hit {
			return &Finding{
				ID:       "script-host",
				Severity: SeverityDanger,
				LineNo:   r.LineNo,
				Rule:     r.Raw,
				Message:  "regex matches script-host " + host + " with arbitrary -c argument (arbitrary code execution)",
				Hint:     "remove this rule, OR allowlist a specific script file path (e.g. ^" + host + ` /Users/me/safe\.py$\tKEY) instead of '-c'`,
			}
		}
	}
	// Separate probe for jq -r (expression language).
	for _, host := range jqHosts {
		probes := []string{
			host + " -r .",
			host + " -r '.foo'",
			host + " -r any-expression",
		}
		hit := true
		for _, p := range probes {
			if !r.Regex.MatchString(p) {
				hit = false
				break
			}
		}
		if hit {
			return &Finding{
				ID:       "script-host",
				Severity: SeverityDanger,
				LineNo:   r.LineNo,
				Rule:     r.Raw,
				Message:  "regex matches " + host + " -r with arbitrary expression (jq expression language is code-exec class)",
				Hint:     "constrain the expression with a literal pattern, or remove this rule",
			}
		}
	}
	return nil
}
```

Wire into the registry (replace the existing list):

```go
var lintChecks = []lintCheck{
	lintTrivialMatch,
	lintScriptHost,
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/aclrules/ -count=1 -run 'TestLintScriptHost\|TestLintNonScriptHost' -v
```

Expected: 6 PASS.

- [ ] **Step 5: Full pkg + vet + fmt**

```sh
go test ./internal/aclrules/ -count=1
go vet ./internal/aclrules/
gofmt -l internal/aclrules/
```

Expected: green / silent.

- [ ] **Step 6: Commit**

```sh
git add internal/aclrules/lint.go internal/aclrules/lint_test.go
git commit -m "$(cat <<'EOF'
feat(aclrules): lint check 'script-host' (DANGER)

Flags rules whose regex matches one of the hardcoded script-host
paths followed by '-c <anything>'. These grant arbitrary code
execution to any agent whose argv reaches the rule.

Hardcoded list covers POSIX shells (sh/bash/zsh/dash/ksh), python
(both /usr/bin and /opt/homebrew paths), perl, awk variants. jq
gets its own probe — `-r <expression>` is functionally code-exec.

Uses multiple probe strings to defeat trivial regex bounds: if the
rule matches all probes for a given host, flagged. Specific-script
allowlists (e.g. ^/usr/bin/python3 /Users/me/safe\\.py$) do NOT
match the `-c` probes and are correctly NOT flagged.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task L4: `env-wildcard` check (WARNING)

**Files:**
- Modify: `internal/aclrules/lint.go`
- Modify: `internal/aclrules/lint_test.go`

Flag rules with `env` column set to `*` (`r.EnvAny == true`). Operator-side warning that the rule accepts any env-var name.

- [ ] **Step 1: Write the failing tests**

Append to `internal/aclrules/lint_test.go`:

```go
func TestLintEnvWildcard(t *testing.T) {
	r := mustParseOne(t, "^/usr/bin/curl .+$\t*\t# debug curl")
	got := findID(Lint([]Rule{r}), "env-wildcard")
	if got == nil {
		t.Fatalf("expected env-wildcard finding; got %v", Lint([]Rule{r}))
	}
	if got.Severity != SeverityWarning {
		t.Errorf("Severity = %q, want WARNING", got.Severity)
	}
}

func TestLintEnvWildcardEmptyDoesNotFire(t *testing.T) {
	// Empty env column → EnvAllow=[], EnvAny=false. NOT a wildcard.
	r := mustParseOne(t, "^/bin/echo$\t\t# no env")
	if got := findID(Lint([]Rule{r}), "env-wildcard"); got != nil {
		t.Errorf("empty env should not trip env-wildcard; got %v", got)
	}
}

func TestLintEnvWildcardSpecificDoesNotFire(t *testing.T) {
	r := mustParseOne(t, "^/bin/x$\tK1,K2")
	if got := findID(Lint([]Rule{r}), "env-wildcard"); got != nil {
		t.Errorf("specific env names should not trip env-wildcard; got %v", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

```sh
go test ./internal/aclrules/ -count=1 -run 'TestLintEnvWildcard' -v
```

Expected: 1 failure (positive case), 2 vacuous passes.

- [ ] **Step 3: Implement `lintEnvWildcard`**

In `internal/aclrules/lint.go`, append:

```go
func lintEnvWildcard(r Rule) *Finding {
	if !r.EnvAny {
		return nil
	}
	return &Finding{
		ID:       "env-wildcard",
		Severity: SeverityWarning,
		LineNo:   r.LineNo,
		Rule:     r.Raw,
		Message:  "env column is '*' — any env-var name accepted",
		Hint:     "list specific env names (e.g. AUTH_TOKEN) unless the binary truly needs unrestricted env. '*' is safe only for binaries that don't leak env content via output",
	}
}
```

Wire into the registry:

```go
var lintChecks = []lintCheck{
	lintTrivialMatch,
	lintScriptHost,
	lintEnvWildcard,
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/aclrules/ -count=1 -run 'TestLintEnvWildcard' -v
```

Expected: 3 PASS.

- [ ] **Step 5: Full pkg + vet + fmt**

```sh
go test ./internal/aclrules/ -count=1
go vet ./internal/aclrules/
gofmt -l internal/aclrules/
```

Expected: green / silent.

- [ ] **Step 6: Commit**

```sh
git add internal/aclrules/lint.go internal/aclrules/lint_test.go
git commit -m "$(cat <<'EOF'
feat(aclrules): lint check 'env-wildcard' (WARNING)

Flags rules with env column set to '*'. The rule passes Parse + Load
fine (operator may have a legitimate reason), but lint warns:
- Any env-var name reaches the child process
- Audit log no longer constrains which env vars were exposed
- Binaries that print env (env / printenv / bash echo $X) leak it

Operator may dismiss the warning if the binary is trusted not to
leak env content. v3.1 first ship surfaces it; doesn't refuse.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task L5: `unescaped-dot` check (WARNING)

**Files:**
- Modify: `internal/aclrules/lint.go`
- Modify: `internal/aclrules/lint_test.go`

Heuristic: a literal `.` in the regex column that's surrounded by `/` (so it's "in the path") and not preceded by `\` is likely an unescaped path component.

- [ ] **Step 1: Write the failing tests**

Append to `internal/aclrules/lint_test.go`:

```go
func TestLintUnescapedDotInPath(t *testing.T) {
	// `.local` — the `.` is unescaped, matches any char.
	r := mustParseOne(t, "^/Users/me/.local/bin/foo .+$\tK")
	got := findID(Lint([]Rule{r}), "unescaped-dot")
	if got == nil {
		t.Fatalf("expected unescaped-dot finding; got %v", Lint([]Rule{r}))
	}
	if got.Severity != SeverityWarning {
		t.Errorf("Severity = %q, want WARNING", got.Severity)
	}
}

func TestLintEscapedDotDoesNotFire(t *testing.T) {
	r := mustParseOne(t, `^/Users/me/\.local/bin/foo .+$` + "\tK")
	if got := findID(Lint([]Rule{r}), "unescaped-dot"); got != nil {
		t.Errorf("escaped dot should not trip unescaped-dot; got %v", got)
	}
}

func TestLintNoDotDoesNotFire(t *testing.T) {
	r := mustParseOne(t, "^/usr/bin/echo .+$\tK")
	if got := findID(Lint([]Rule{r}), "unescaped-dot"); got != nil {
		t.Errorf("regex without literal dot should not trip; got %v", got)
	}
}

func TestLintDotInQuantifierDoesNotFire(t *testing.T) {
	// `.+` and `.*` use `.` as a regex metacharacter, not a path char.
	// We only flag `.` that appears INSIDE a path component (between slashes).
	r := mustParseOne(t, "^/bin/cat .+$\tK")
	if got := findID(Lint([]Rule{r}), "unescaped-dot"); got != nil {
		t.Errorf("trailing .+ should not trip unescaped-dot; got %v", got)
	}
}

func TestLintMultipleUnescapedDots(t *testing.T) {
	// Multiple unescaped dots in path → still one finding (don't spam).
	r := mustParseOne(t, "^/Users/me/.foo/.bar/baz$\tK")
	findings := Lint([]Rule{r})
	count := 0
	for _, f := range findings {
		if f.ID == "unescaped-dot" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 unescaped-dot finding (deduplicated); got %d", count)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

```sh
go test ./internal/aclrules/ -count=1 -run 'TestLintUnescapedDot\|TestLintEscapedDot\|TestLintNoDot\|TestLintDotInQuantifier\|TestLintMultipleUnescapedDots' -v
```

Expected: 2 failures (positive cases — `InPath` and `MultipleUnescapedDots`). Others pass vacuously.

- [ ] **Step 3: Implement `lintUnescapedDot`**

In `internal/aclrules/lint.go`, append:

```go
// unescapedDotInPath looks for `.` characters in the regex that:
//   - aren't preceded by `\` (escape)
//   - are flanked by `/` chars within 1-30 characters (i.e. inside a
//     path component, not as a regex metacharacter for an arg)
//
// Heuristic — false positives possible (e.g., inside a character class
// `[.]` the `.` is a literal). Returns WARNING, not DANGER.
func lintUnescapedDot(r Rule) *Finding {
	// The Raw column may contain tab-separated env+label; only inspect
	// the regex column (everything before the first tab, if any).
	regexCol := r.Raw
	if i := indexOfByte(regexCol, '\t'); i >= 0 {
		regexCol = regexCol[:i]
	}

	for i := 0; i < len(regexCol); i++ {
		if regexCol[i] != '.' {
			continue
		}
		if i > 0 && regexCol[i-1] == '\\' {
			continue // already escaped
		}
		// Must have a `/` within 30 chars on at least one side
		// (heuristic for "inside a path component").
		left := false
		for j := i - 1; j >= 0 && j >= i-30; j-- {
			if regexCol[j] == '/' {
				left = true
				break
			}
			if regexCol[j] == ' ' || regexCol[j] == '\t' {
				break // crossed into arg space
			}
		}
		right := false
		for j := i + 1; j < len(regexCol) && j <= i+30; j++ {
			if regexCol[j] == '/' {
				right = true
				break
			}
			if regexCol[j] == ' ' || regexCol[j] == '\t' || regexCol[j] == '$' {
				break // crossed out of path
			}
		}
		if left && right {
			return &Finding{
				ID:       "unescaped-dot",
				Severity: SeverityWarning,
				LineNo:   r.LineNo,
				Rule:     r.Raw,
				Message:  "regex contains unescaped `.` in a path component (matches any char, not just literal dot)",
				Hint:     "use `\\.` for literal dot; auto-blessed rules already escape correctly. e.g. /Users/me/.local → /Users/me/\\.local",
			}
		}
	}
	return nil
}

// indexOfByte is a tiny wrapper to avoid importing strings/bytes for one call.
func indexOfByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
```

Wire into the registry:

```go
var lintChecks = []lintCheck{
	lintTrivialMatch,
	lintScriptHost,
	lintEnvWildcard,
	lintUnescapedDot,
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/aclrules/ -count=1 -run 'TestLintUnescapedDot\|TestLintEscapedDot\|TestLintNoDot\|TestLintDotInQuantifier\|TestLintMultipleUnescapedDots' -v
```

Expected: 5 PASS.

- [ ] **Step 5: Full pkg + vet + fmt**

```sh
go test ./internal/aclrules/ -count=1
go vet ./internal/aclrules/
gofmt -l internal/aclrules/
```

Expected: green / silent.

- [ ] **Step 6: Commit**

```sh
git add internal/aclrules/lint.go internal/aclrules/lint_test.go
git commit -m "$(cat <<'EOF'
feat(aclrules): lint check 'unescaped-dot' (WARNING)

Heuristic: literal `.` in the regex column, flanked by `/` chars
within 30 chars on each side (i.e. inside a path component), not
escaped by a preceding `\`. Flagged as WARNING because:
- false-positives possible (e.g. /a.b/ might be intentional in
  a char-class context; this heuristic doesn't track [...] state)
- operator owns the call to dismiss

Returns at most one finding per rule (don't spam on multi-dot paths).

Auto-blessed rules go through regexp.QuoteMeta and don't trigger
this lint — only operator-hand-edited rules are at risk.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task L6: `no-label` check (INFO)

**Files:**
- Modify: `internal/aclrules/lint.go`
- Modify: `internal/aclrules/lint_test.go`

Flag rules with empty `Label`. Pure ergonomic finding (audit-line shows `rule=line:N` instead of `rule=[label]`).

- [ ] **Step 1: Write the failing tests**

Append to `internal/aclrules/lint_test.go`:

```go
func TestLintNoLabel(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo$\tK")
	got := findID(Lint([]Rule{r}), "no-label")
	if got == nil {
		t.Fatalf("expected no-label finding; got %v", Lint([]Rule{r}))
	}
	if got.Severity != SeverityInfo {
		t.Errorf("Severity = %q, want INFO", got.Severity)
	}
}

func TestLintLabelPresentDoesNotFire(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo$\tK\t# echo")
	if got := findID(Lint([]Rule{r}), "no-label"); got != nil {
		t.Errorf("rule with label should not trip no-label; got %v", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

```sh
go test ./internal/aclrules/ -count=1 -run 'TestLintNoLabel\|TestLintLabelPresent' -v
```

Expected: 1 failure.

- [ ] **Step 3: Implement `lintNoLabel`**

In `internal/aclrules/lint.go`, append:

```go
func lintNoLabel(r Rule) *Finding {
	if r.Label != "" {
		return nil
	}
	return &Finding{
		ID:       "no-label",
		Severity: SeverityInfo,
		LineNo:   r.LineNo,
		Rule:     r.Raw,
		Message:  "rule has no label",
		Hint:     "add `\\t# <label>` as third column. Without a label, audit-line stderr shows `rule=line:N` (less searchable than `rule=[name]`)",
	}
}
```

Wire into the registry:

```go
var lintChecks = []lintCheck{
	lintTrivialMatch,
	lintScriptHost,
	lintEnvWildcard,
	lintUnescapedDot,
	lintNoLabel,
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/aclrules/ -count=1 -run 'TestLintNoLabel\|TestLintLabelPresent' -v
```

Expected: 2 PASS.

- [ ] **Step 5: Full pkg integration test**

Append one combined test to `internal/aclrules/lint_test.go`:

```go
func TestLintMultipleFindingsPerRule(t *testing.T) {
	// A rule that's trivial-match AND env-wildcard AND no-label should
	// produce three findings.
	r := mustParseOne(t, "^.+$\t*")
	findings := Lint([]Rule{r})
	wantIDs := map[string]bool{"trivial-match": false, "env-wildcard": false, "no-label": false}
	for _, f := range findings {
		if _, ok := wantIDs[f.ID]; ok {
			wantIDs[f.ID] = true
		}
	}
	for id, found := range wantIDs {
		if !found {
			t.Errorf("expected finding %q; got %v", id, findings)
		}
	}
}

func TestLintMultipleRulesIndependent(t *testing.T) {
	r1 := mustParseOne(t, "^/bin/echo$\tK\t# echo")          // clean
	r2 := mustParseOne(t, "^.*$\t*\t# yolo")                 // trivial + env-wildcard
	findings := Lint([]Rule{r1, r2})
	// r1 should produce zero findings; r2 should produce 2.
	for _, f := range findings {
		if f.LineNo == r1.LineNo {
			t.Errorf("clean rule produced finding: %v", f)
		}
	}
}
```

- [ ] **Step 6: Run all lint tests + vet + fmt**

```sh
go test ./internal/aclrules/ -count=1 -run 'TestLint' -v
go test ./internal/aclrules/ -count=1
go vet ./internal/aclrules/
gofmt -l internal/aclrules/
```

Expected: all green / silent.

- [ ] **Step 7: Commit**

```sh
git add internal/aclrules/lint.go internal/aclrules/lint_test.go
git commit -m "$(cat <<'EOF'
feat(aclrules): lint check 'no-label' (INFO) + multi-finding tests

Last of the v3.1 lint checks. INFO-level — labels aren't required
by parse semantics; just a pure ergonomic. Without a label, alice's
audit-line stderr shows `rule=line:N` instead of `rule=[name]`,
which is harder to grep + correlate across files.

Two integration tests added: (1) a rule that trips multiple checks
produces multiple findings (no de-duplication across check IDs);
(2) clean rules don't pollute findings for adjacent dirty rules.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task L7: `cmd/alice/allowlist.go` — `cmdAllowlistCheck`

**Files:**
- Create: `cmd/alice/allowlist.go`
- Modify: `cmd/alice/main.go`

Wire the new subcommand. Reads the rules file via `aclrules.Parse` directly (NOT `LoadFile`) so the lint command can show parse errors alongside lint findings. Formats output with emoji severity markers and a parseable summary line. Sets exit code per the matrix in the spec.

- [ ] **Step 1: Create `cmd/alice/allowlist.go`**

Create the file:

```go
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kaka-milan-22/AnB/v3/internal/aclrules"
	"github.com/kaka-milan-22/AnB/v3/internal/localvault"
)

// cmdAllowlistCheck — lint pass over exec-allowlist.rules. Reports
// parse errors + lint findings with severity. Exit codes:
//   0  no findings, no parse errors
//   1  parse errors OR DANGER findings present
//   2  only WARNINGs present AND --strict flag set
func cmdAllowlistCheck(args []string) error {
	fs := newFS("allowlist-check")
	fileFlag := fs.String("file", "", "rules file to check (default: <state>/exec-allowlist.rules)")
	strictFlag := fs.Bool("strict", false, "exit non-zero on WARNINGs as well as DANGERs")
	dir := dirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := *fileFlag
	if path == "" {
		s := localvault.Open(*dir)
		path = filepath.Join(s.Dir, "exec-allowlist.rules")
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	rules, parseErrs := aclrules.Parse(f)
	findings := aclrules.Lint(rules)

	fmt.Printf("Checking %s\n", path)
	fmt.Printf("%d rules loaded, %d findings.\n\n", len(rules), len(findings)+len(parseErrs))

	// Parse errors first (operator must fix these before findings matter).
	for _, e := range parseErrs {
		fmt.Printf("❌ ERROR: %v\n\n", e)
	}

	// Lint findings.
	for _, fnd := range findings {
		emoji := severityEmoji(fnd.Severity)
		fmt.Printf("%s line %d: %s (%s)\n  %s\n  Hint: %s\n\n",
			emoji, fnd.LineNo, fnd.ID, fnd.Severity, fnd.Rule, fnd.Hint)
	}

	// Summary.
	var danger, warning, info int
	for _, fnd := range findings {
		switch fnd.Severity {
		case aclrules.SeverityDanger:
			danger++
		case aclrules.SeverityWarning:
			warning++
		case aclrules.SeverityInfo:
			info++
		}
	}
	fmt.Printf("Summary: %d rules, %d danger, %d warnings, %d info\n",
		len(rules), danger, warning, info)

	// Exit code.
	if len(parseErrs) > 0 || danger > 0 {
		os.Exit(1)
	}
	if *strictFlag && warning > 0 {
		os.Exit(2)
	}
	return nil
}

func severityEmoji(s aclrules.Severity) string {
	switch s {
	case aclrules.SeverityDanger:
		return "🚨"
	case aclrules.SeverityWarning:
		return "⚠"
	case aclrules.SeverityInfo:
		return "ℹ"
	}
	return "?"
}
```

- [ ] **Step 2: Wire into `cmd/alice/main.go` dispatcher**

Find the `cmds` map in `cmd/alice/main.go` (around line 39-45 — the line where read/write/has/list/etc are registered). Add `allowlist-check`:

```go
	cmds := map[string]func([]string) error{
		"read": cmdRead, "write": cmdWrite, "has": cmdHas, "list": cmdList, "status": cmdStatus, "exec": cmdExec,
		"set": cmdSet, "get": cmdGet, "rm": cmdRm, "import": cmdImport, "gen": cmdGen,
		"init": cmdInit, "scan": cmdScan, "template": cmdTemplate, "shell": cmdShell,
		"rekey": cmdRekey, "rekey-status": cmdRekeyStatus, "rekey-from-zero": cmdRekeyFromZero,
		"enroll": cmdEnroll, "install-cert": cmdInstallCert,
		"allowlist-check": cmdAllowlistCheck,
	}
```

Find the `usage()` function in the same file. After the row for `install-cert`, add:

```go
	fmt.Fprintf(w, row, "allowlist-check [opts]", "Lint exec-allowlist.rules — report dangerous patterns")
```

- [ ] **Step 3: Build + run smoke**

```sh
cd /Users/bbwave03/claude/anb
go build ./...
go vet ./...
gofmt -l .
```

All silent.

```sh
go install ./cmd/alice
alice allowlist-check --help 2>&1 | head -5
```

Expected: flag listing for `--file`, `--strict`, `--dir`.

- [ ] **Step 4: Manual smoke against a temp rules file**

Create a deliberately-dirty rules file and check:

```sh
cat > /tmp/dirty.rules <<'EOF'
# Test rules with several footguns
^/bin/sh -c .+$	*	# danger: shell
^/usr/bin/curl .+$	*	# warning: env wildcard
^/Users/me/.local/bin/foo$	K	# warning: unescaped dot
^/usr/bin/cat .+$	K	# clean — has label, no warnings
^/usr/bin/no-label$	K
EOF

alice allowlist-check --file /tmp/dirty.rules
echo "exit was: $?"
```

Expected output: 1 DANGER (script-host), 2-3 WARNINGs (env-wildcard, unescaped-dot), 1 INFO (no-label). Exit code 1 (danger present).

```sh
alice allowlist-check --file /tmp/dirty.rules --strict
echo "exit was: $?"
```

Same output. Exit code still 1 because danger > 0 takes priority over strict-mode-warning.

```sh
# Clean version — no findings
cat > /tmp/clean.rules <<'EOF'
^/usr/bin/cat .+$	K	# cat with key
EOF
alice allowlist-check --file /tmp/clean.rules
echo "exit was: $?"
```

Expected: zero findings, exit 0.

Cleanup:

```sh
rm /tmp/dirty.rules /tmp/clean.rules
```

- [ ] **Step 5: Commit**

```sh
git add cmd/alice/allowlist.go cmd/alice/main.go
git commit -m "$(cat <<'EOF'
feat(alice): allowlist-check subcommand

Reads exec-allowlist.rules (default state-dir, override via --file)
and reports parse errors + lint findings with severity emoji and
hints. Exit codes: 0 clean | 1 danger/parse-error | 2 warning-only
with --strict.

Uses aclrules.Parse directly (not LoadFile) so the command shows
ALL parse errors at once instead of refusing the file. Lint runs
against the rules that did parse — operator gets full feedback in
one pass.

Wired into cmd/alice/main.go dispatcher + usage table.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task L8: README "Linting your allowlist" section

**Files:**
- Modify: `README.md`

Add a new subsection inside the "Allowlist rules format" section. Operator-facing docs with one realistic example output.

- [ ] **Step 1: Locate the insertion point**

```sh
cd /Users/bbwave03/claude/anb
grep -n '^## Allowlist rules format\|^### Auto-bless\|^---' README.md | head -10
```

Find the line numbers for "Allowlist rules format" section and the `---` that ends it. Insert the new subsection before that `---`.

- [ ] **Step 2: Add the section**

Insert before the closing `---` of the Allowlist rules section:

```markdown
### Linting your allowlist

`alice allowlist-check` runs heuristic checks over your rules file
and reports operator footguns:

```text
$ alice allowlist-check
Checking /Users/you/.anb/alice/exec-allowlist.rules
4 rules loaded, 3 findings.

🚨 line 3: script-host (DANGER)
  ^/bin/sh -c .+$	*	# debug shell
  Hint: remove this rule, OR allowlist a specific script file path (e.g. ^/bin/sh /Users/me/safe.sh$	KEY) instead of '-c'.

⚠ line 7: env-wildcard (WARNING)
  ^/usr/bin/curl .+$	*	# debug curl
  Hint: list specific env names (e.g. AUTH_TOKEN) unless the binary truly needs unrestricted env.

ℹ line 12: no-label (INFO)
  ^/usr/bin/cat .+$	K
  Hint: add `\t# <label>` as third column for audit attribution.

Summary: 4 rules, 1 danger, 1 warnings, 1 info
```

**Severities:**

| Level | When | Exit code (default) | Exit code (`--strict`) |
|---|---|---|---|
| `DANGER` | regex matches everything, or covers a script-host with arbitrary `-c` argument | 1 | 1 |
| `WARNING` | env column is `*`, or regex has unescaped `.` in a path component | 0 | 2 |
| `INFO` | rule has no `# label` | 0 | 0 |

Plus parse errors (lines that fail `aclrules.Parse`) always exit 1.

**Flags:**

- `--file PATH` — check a specific file (useful for testing candidate rules before committing)
- `--strict` — exit non-zero on WARNINGs too (suitable for CI / pre-commit hooks)

**When to run:** before adding a hand-written rule, before a release, or in a pre-commit hook on the same machine that holds the rules file. The check is purely local — no daemon round-trip, no decrypts.
```

The exact insertion point: just before the line that's `---` separating the Allowlist rules section from the next section.

- [ ] **Step 3: Sanity check fences + counts**

```sh
grep -c '^```' README.md     # MUST be even (fences balanced)
grep -c 'allowlist-check' README.md  # MUST be ≥ 4 (multiple references)
```

- [ ] **Step 4: Visual diff**

```sh
git diff README.md | head -120
```

Verify the new subsection rendered correctly — no broken markdown.

- [ ] **Step 5: Commit**

```sh
git add README.md
git commit -m "$(cat <<'EOF'
docs(readme): 'Linting your allowlist' section for v3.1

New subsection under 'Allowlist rules format' documenting
alice allowlist-check: severities table, exit code matrix, flags,
when to run. One realistic example output covering all three
severity emoji classes (DANGER / WARNING / INFO) so operators
recognize them in their own output.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task L9: Operator smoke

**Files:** None — operational verification.

The implementer cannot drive interactive smoke. User runs in their terminal:

- [ ] **Step 1: Install fresh binary**

```sh
cd /Users/bbwave03/claude/anb
go install ./cmd/alice
```

- [ ] **Step 2: Run lint against the live rules file**

```sh
alice allowlist-check
echo "exit was: $?"
```

Expected: scans `~/.anb/alice/exec-allowlist.rules`. May find INFO-level "no-label" for any rule that was hand-added without a label. Should not find DANGER unless operator has script-host or trivial-match rules.

- [ ] **Step 3: --strict mode**

```sh
alice allowlist-check --strict
echo "exit was: $?"
```

Expected: exit code 0 (no warnings) or 2 (warnings present, strict mode flags them).

- [ ] **Step 4: --file override against a candidate file**

```sh
cp ~/.anb/alice/exec-allowlist.rules /tmp/candidate.rules
echo '^.*$\t*\t# yolo trivial' >> /tmp/candidate.rules
alice allowlist-check --file /tmp/candidate.rules
echo "exit was: $?"
rm /tmp/candidate.rules
```

Expected: trivial-match DANGER reported, exit 1.

- [ ] **Step 5: Report back**

Confirm to controller: which severities fired against the live rules, and which exit codes were observed.

---

### Task L10: Final review + PR + tag v3.1.0

**Files:** None — release engineering.

- [ ] **Step 1: Pre-PR sanity**

```sh
cd /Users/bbwave03/claude/anb
go test ./... -count=1
go vet ./...
gofmt -l .
git log --oneline main..HEAD
git diff --stat main..HEAD
```

All green/silent.

- [ ] **Step 2: Dispatch final branch-wide reviewer**

Mirror the v3.0 final review pattern. `general-purpose` subagent, model `sonnet`, prompt covers:

1. **Lint heuristics rigor** — false-positive rate for `unescaped-dot`? Any way to construct a "looks-narrow but matches everything" regex that trivial-match misses?
2. **Script-host completeness** — any common script host missing? (e.g., `osascript` on macOS, `ruby -e`, `node -e`)
3. **Exit-code matrix correctness** — verify priority: parse-error > danger > warning > info
4. **--file ergonomics** — operator can pass relative path? Tests at relative paths?
5. **Performance** — Lint() iterates rules × checks; each check has a few regex MatchString calls. Trivial for any operator-sized allowlist.

Report Critical / Important / Minor with file:line refs.

- [ ] **Step 3: Address findings**

For any Critical or Important, dispatch fix subagent; re-review until clean.

- [ ] **Step 4: Push + PR**

```sh
git push -u origin feat/allowlist-lint
gh pr create --base main --head feat/allowlist-lint \
  --title "feat: alice allowlist-check lint command (v3.1.0)" \
  --body "<PR body — see spec for source>"
```

PR body summarizes: new subcommand, 5 lint checks, exit code matrix, no breaking changes.

- [ ] **Step 5: Squash-merge + tag v3.1.0 + GitHub release**

After approval:

```sh
gh pr merge <PR#> --squash --delete-branch --subject "<subject>" --body "<body>"
git checkout main && git pull --ff-only
git tag -a v3.1.0 <merge-sha> -m "AnB v3.1.0 — alice allowlist-check lint command

<full notes — see spec>"
git push origin v3.1.0
gh release create v3.1.0 --title "AnB v3.1.0 — alice allowlist-check" --notes "<full notes>"
```

- [ ] **Step 6: Verify `go install`**

```sh
go install github.com/kaka-milan-22/AnB/v3/cmd/alice@v3.1.0
alice version
alice allowlist-check --help 2>&1 | head -3
```

Expected: `alice v3.1.0`, subcommand registers, flag listing visible.

- [ ] **Step 7: Done**

Update task list. Tell controller v3.1.0 shipped.

---

## Self-Review

### Spec coverage

Walking through `docs/superpowers/specs/2026-05-30-allowlist-lint-design.md`:

- **CLI** (`alice allowlist-check --file --strict --dir`) → Task L7
- **Lint checks 1-5** → Tasks L2-L6, one per check
- **Output format** (emoji, summary line) → Task L7
- **Parse-error handling** (show all + still run lint on parsed rules) → Task L7 uses `Parse` not `LoadFile` ✓
- **Exit code matrix** → Task L7 implementation block
- **README section** → Task L8
- **Smoke + release** → Tasks L9, L10
- **Out-of-scope items** (no `--fix`, no JSON output, no cross-rule shadow detection) not in plan, by design

### Placeholder scan

No "TBD", "implement later", "appropriate error handling". Every step shows the actual code. Tests are concrete, not abstracted "test the behavior" placeholders.

### Type consistency

- `Severity` type + `SeverityDanger` / `SeverityWarning` / `SeverityInfo` constants — same names L1 onward
- `Finding` struct: `ID`, `Severity`, `LineNo`, `Rule`, `Message`, `Hint` — consistent in L1-L8
- `Lint([]Rule) []Finding` signature — L1 fixed, L2-L6 don't change it (just append to `lintChecks` registry)
- `lintTrivialMatch`, `lintScriptHost`, `lintEnvWildcard`, `lintUnescapedDot`, `lintNoLabel` — all `func(r Rule) *Finding`
- `findID` test helper — defined L3 step 1, used by L3-L7 tests
- `mustParseOne` — pre-existing from A3 (aclrules_test.go), reused

Plan is internally consistent.

### Known deviations

None vs spec. The spec is small and the plan implements it 1:1.
