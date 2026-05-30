# AnB v3.0.0 — Regex-based Allowlist Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace v2.x JSON-structured `exec-allowlist.json` (strict-equality + per-position fields) with a plain-text `exec-allowlist.rules` file where each line is a Go RE2 regex matched against the shellescape-joined `cmd args...` invocation string. One primitive, zero pattern-type taxonomy.

**Architecture:** New package `internal/aclrules/` owns the file format, canonicalization (`shellescape` join), regex parsing/matching, and the auto-bless literal-rule generator. `cmd/alice/exec.go` swaps its v2.x allowlist code paths for `aclrules.LoadFile` + `Rule.Matches`. A one-shot startup migrator converts existing `.json` to `.rules` and renames the original to `.json.bak`. `cmd/alice/sensitive.go::cmdEnroll` scaffolds `.rules` for new installs. Audit attribution moves from a per-entry `label` field to a trailing `#<label>` comment in column 3; alice's stderr `→ exec …` line surfaces the matched rule's label.

**Tech Stack:** Go 1.26 (existing); `regexp` (Go RE2 — linear time, no backtracking, no ReDoS); stdlib only — no new external dependencies.

**Spec:** `docs/superpowers/specs/2026-05-30-allowlist-rules-regex-design.md`. Operator already reviewed and approved; defaults locked on all open questions (`*` env marker kept, trivial-match-everything refused at load, `--show-match-string` as flag on `alice exec`, one-shot migration with `.json.bak`, `#` collision resolved by tab separator).

---

## File Structure

| File | Role | Status |
|---|---|---|
| `internal/aclrules/aclrules.go` | Package: `Rule` struct + `Canonicalize` + `Parse` + `LoadFile` + `(*Rule).Matches` + `LiteralRule` + trivial-match-everything detection | **Create** (~340 LOC) |
| `internal/aclrules/aclrules_test.go` | Unit tests for all of the above | **Create** (~350 LOC) |
| `cmd/alice/exec.go` | Swap JSON allowlist load for `aclrules.LoadFile`; rewrite `matchAllowlist`; auto-bless writes `.rules`; new `--show-match-string` flag; updated deny message; stderr shows matched rule label | **Modify** (rewrite ~120 LOC of allowlist code, add ~80 LOC for new features) |
| `cmd/alice/exec_test.go` | Update existing unit tests for new path; remove tests for dropped strict-JSON behavior | **Modify** (~80 LOC churn) |
| `cmd/alice/sensitive.go` | `cmdEnroll` scaffolds `exec-allowlist.rules` (header comment + zero rules), not `.json` | **Modify** (~20 LOC) |
| `cmd/alice/main.go` | Call `aclrules.MigrateLegacy(state.Dir)` once before dispatch when needed | **Modify** (~5 LOC) |
| `internal/aclrules/migrate.go` | One-shot `.json` → `.rules` migrator + rename `.bak` | **Create** (~100 LOC) |
| `internal/aclrules/migrate_test.go` | Tests for migration | **Create** (~120 LOC) |
| `e2e/full_test.go` | Update e2e helpers that seed v2.x allowlist; switch to `.rules` writes | **Modify** (~80 LOC) |
| `README.md` | Replace allowlist sections (multiple) with `.rules` format documentation + examples; update Daily-use; update "Choosing exec/shell/get" section | **Modify** (~150 LOC) |

**Note on `exec-allowlist.json` removal:** v3.0 ships with the JSON code paths **deleted**, not deprecated. Operators upgrade via the auto-migrator on first run; no dual-format support carried forward.

---

## Task ordering and dependencies

- Tasks A1–A5 build `internal/aclrules` bottom-up (pure functions, fully testable in isolation).
- Tasks A6–A10 wire the package into alice. A6 is the keystone (cmdExec rewrite); the rest are smaller add-ons.
- Tasks A11–A13 are docs, smoke, release.

Each task is one focused commit. Implementer dispatches one fresh subagent per task; two-stage review (spec compliance, then code quality) gates each commit.

---

### Task A1: `aclrules.Canonicalize` — shellescape + space join

**Files:**
- Create: `internal/aclrules/aclrules.go`
- Create: `internal/aclrules/aclrules_test.go`

Pure function that builds the canonical match string from `(cmd, args)`. POSIX single-quote shellescape: args containing only safe chars (`[A-Za-z0-9_\-./:=@,]`) pass through; anything else is wrapped in single quotes with embedded `'` re-encoded as `'\''`.

- [ ] **Step 1: Write the failing tests**

Create `internal/aclrules/aclrules_test.go`:

```go
package aclrules

import (
	"strings"
	"testing"
)

func TestCanonicalizeSafeArgs(t *testing.T) {
	got := Canonicalize("/usr/bin/echo", []string{"hello", "world"})
	want := "/usr/bin/echo hello world"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeArgWithSpace(t *testing.T) {
	got := Canonicalize("/usr/bin/echo", []string{"hello world"})
	want := "/usr/bin/echo 'hello world'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeArgWithEmbeddedQuote(t *testing.T) {
	got := Canonicalize("/usr/bin/echo", []string{"it's"})
	want := `/usr/bin/echo 'it'\''s'`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeEmptyArg(t *testing.T) {
	got := Canonicalize("/usr/bin/echo", []string{""})
	want := "/usr/bin/echo ''"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeNoArgs(t *testing.T) {
	got := Canonicalize("/usr/bin/bob", nil)
	want := "/usr/bin/bob"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeCmdWithSpecial(t *testing.T) {
	// Cmd path itself may need quoting if it has special chars.
	got := Canonicalize("/path with space/tool", []string{"arg"})
	want := "'/path with space/tool' arg"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeArgWithGlobChars(t *testing.T) {
	// Glob chars like *, ?, [ are not in the safe set; must quote.
	got := Canonicalize("/bin/ls", []string{"*.txt"})
	want := "/bin/ls '*.txt'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeArgWithNewline(t *testing.T) {
	got := Canonicalize("/bin/printf", []string{"line1\nline2"})
	want := "/bin/printf 'line1\nline2'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeSafeCharsBoundary(t *testing.T) {
	// The "safe set" is [A-Za-z0-9_\-./:=@,]. Test each at boundaries.
	got := Canonicalize("/x", []string{"abc_DEF-123./:=@,"})
	want := "/x abc_DEF-123./:=@,"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeArgWithDollar(t *testing.T) {
	// $ is not in safe set; must quote (single-quote disables expansion in real shell anyway).
	got := Canonicalize("/bin/echo", []string{"$HOME"})
	want := "/bin/echo '$HOME'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeCombined(t *testing.T) {
	got := Canonicalize(
		"/Users/bbwave03/.local/bin/encipherr",
		[]string{"encrypt", "file", "/tmp/has space.txt"},
	)
	want := "/Users/bbwave03/.local/bin/encipherr encrypt file '/tmp/has space.txt'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
```

Note: `strings` is imported for later tests in this file; unused-import error is acceptable here since later tasks add usages.

- [ ] **Step 2: Run tests to verify they fail**

```sh
cd /Users/bbwave03/claude/anb
go test ./internal/aclrules/ -count=1 -v
```

Expected: build error — package has no Go files yet.

- [ ] **Step 3: Implement `Canonicalize`**

Create `internal/aclrules/aclrules.go`:

```go
// Package aclrules implements alice's regex-based execution allowlist.
//
// An allowlist file is plain text. Each non-empty, non-comment line is a
// rule consisting of up to three tab-separated fields: a Go RE2 regex
// (implicitly anchored), a comma-separated set of allowed env-var names,
// and an optional "#"-prefixed label for audit attribution.
//
// alice canonicalises each "alice exec" invocation as
//   shellescape(cmd) + " " + shellescape(arg1) + " " + ... + shellescape(argN)
// and tests it top-to-bottom against the rules' regexes. The first match
// wins; the operator's --env names must be a subset of the matched rule's
// allowed env set; no match means hard-deny.
package aclrules

import (
	"strings"
)

// shellSafe matches every char that does not need shell quoting.
// Keep this conservative — POSIX sh treats more chars as special than
// most operators expect (notably !, ~, *, ?, $, etc.).
const shellSafeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:=@,"

func isShellSafe(s string) bool {
	if s == "" {
		return false // empty arg needs '' wrapping
	}
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(shellSafeChars, rune(s[i])) {
			return false
		}
	}
	return true
}

func shellescape(s string) string {
	if isShellSafe(s) {
		return s
	}
	// POSIX single-quote: wrap in ' ... '. Embedded ' becomes '\''.
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Canonicalize joins cmd and args into the match string used by Rule.Matches.
// Pure function — no I/O, no side effects.
func Canonicalize(cmd string, args []string) string {
	var sb strings.Builder
	sb.WriteString(shellescape(cmd))
	for _, a := range args {
		sb.WriteByte(' ')
		sb.WriteString(shellescape(a))
	}
	return sb.String()
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/aclrules/ -count=1 -v -run 'TestCanonicalize'
```

Expected: all 11 `TestCanonicalize*` PASS.

- [ ] **Step 5: Run vet + fmt**

```sh
go vet ./internal/aclrules/
gofmt -l internal/aclrules/
```

Expected: no output from either.

- [ ] **Step 6: Commit**

```sh
git add internal/aclrules/aclrules.go internal/aclrules/aclrules_test.go
git commit -m "$(cat <<'EOF'
feat(aclrules): Canonicalize — POSIX shellescape + space join

Pure helper for the v3.0 allowlist match string. Args containing
only safe chars (alphanum + _-./:=@,) pass through; anything else
(spaces, quotes, globs, newlines, shell metacharacters) gets POSIX
single-quote wrapped with embedded ' re-encoded as '\\''.

This is the canonical form alice will regex-match each invocation
against. Operator's regex sees the same string they'd see in
'sh -x' output, with no parsing ambiguity for args with spaces.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A2: `aclrules.Rule` struct + `Parse` (parse one file's worth of lines)

**Files:**
- Modify: `internal/aclrules/aclrules.go`
- Modify: `internal/aclrules/aclrules_test.go`

Parse a rules-file body into `[]Rule`. One line per rule, three tab-separated fields. Skip blank/whitespace-only/`#`-prefixed lines. Return parse errors with line numbers.

- [ ] **Step 1: Write the failing tests**

Append to `internal/aclrules/aclrules_test.go`:

```go
func TestParseEmpty(t *testing.T) {
	rules, errs := Parse(strings.NewReader(""))
	if len(rules) != 0 {
		t.Errorf("expected zero rules, got %d", len(rules))
	}
	if len(errs) != 0 {
		t.Errorf("expected zero errors, got %v", errs)
	}
}

func TestParseComments(t *testing.T) {
	body := "# this is a comment\n   # indented comment too\n\n\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(rules) != 0 || len(errs) != 0 {
		t.Errorf("expected nothing; got rules=%v errs=%v", rules, errs)
	}
}

func TestParseSingleRule(t *testing.T) {
	body := "^/bin/echo hello$\tENCIPHERR_KEY\t# echo hello\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.Raw != "^/bin/echo hello$\tENCIPHERR_KEY\t# echo hello" {
		t.Errorf("Raw mismatch: %q", r.Raw)
	}
	if r.LineNo != 1 {
		t.Errorf("LineNo: got %d want 1", r.LineNo)
	}
	if r.Label != "echo hello" {
		t.Errorf("Label: got %q want %q", r.Label, "echo hello")
	}
	if len(r.EnvAllow) != 1 || r.EnvAllow[0] != "ENCIPHERR_KEY" {
		t.Errorf("EnvAllow: got %v", r.EnvAllow)
	}
	if r.EnvAny {
		t.Errorf("EnvAny should be false")
	}
	if r.Regex == nil {
		t.Error("Regex should be compiled")
	}
}

func TestParseRuleNoEnv(t *testing.T) {
	body := "^/bin/bob list-keys$\t\t# bob list-keys\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if len(r.EnvAllow) != 0 {
		t.Errorf("EnvAllow should be empty; got %v", r.EnvAllow)
	}
	if r.EnvAny {
		t.Errorf("EnvAny should be false for empty (not '*')")
	}
}

func TestParseRuleNoLabel(t *testing.T) {
	body := "^/bin/bob list-keys$\tKEY\n"
	rules, _ := Parse(strings.NewReader(body))
	if len(rules) != 1 || rules[0].Label != "" {
		t.Errorf("expected empty label; got %q", rules[0].Label)
	}
}

func TestParseRuleRegexOnly(t *testing.T) {
	body := "^/bin/bob list-keys$\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if len(rules[0].EnvAllow) != 0 || rules[0].EnvAny {
		t.Errorf("missing env column should be no env allowed; got allow=%v any=%v",
			rules[0].EnvAllow, rules[0].EnvAny)
	}
}

func TestParseRuleEnvCsv(t *testing.T) {
	body := "^/bin/foo$\tKEY1, KEY2 ,KEY3\t# multi\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	want := []string{"KEY1", "KEY2", "KEY3"}
	got := rules[0].EnvAllow
	if len(got) != len(want) {
		t.Fatalf("len: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("EnvAllow[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestParseRuleEnvStar(t *testing.T) {
	body := "^/bin/foo$\t*\t# any env\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if !rules[0].EnvAny {
		t.Error("EnvAny should be true when env column is '*'")
	}
	if len(rules[0].EnvAllow) != 0 {
		t.Error("EnvAllow should be empty when EnvAny is set")
	}
}

func TestParseInvalidRegex(t *testing.T) {
	body := "^/bin/[unclosed\tKEY\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) == 0 {
		t.Error("expected parse error for invalid regex")
	}
	if len(rules) != 0 {
		t.Errorf("rules should not include invalid ones; got %v", rules)
	}
}

func TestParseInvalidEnvName(t *testing.T) {
	body := "^/bin/foo$\t1BAD-ENV\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) == 0 {
		t.Error("expected parse error for invalid env name")
	}
	if len(rules) != 0 {
		t.Errorf("rules should not include invalid ones; got %v", rules)
	}
}

func TestParseTooManyFields(t *testing.T) {
	body := "^/bin/foo$\tKEY\t# label\textra\n"
	_, errs := Parse(strings.NewReader(body))
	if len(errs) == 0 {
		t.Error("expected parse error for >3 tab-separated fields")
	}
}

func TestParseLabelMustStartWithHash(t *testing.T) {
	body := "^/bin/foo$\tKEY\tnot-a-comment\n"
	_, errs := Parse(strings.NewReader(body))
	if len(errs) == 0 {
		t.Error("expected parse error: field 3 must start with #")
	}
}

func TestParseAnchorImplicit(t *testing.T) {
	// Operator writes "/bin/echo .+" (no ^...$). Parser must compile as anchored.
	body := "/bin/echo .+\tKEY\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	r := rules[0]
	if !r.Regex.MatchString("/bin/echo hello") {
		t.Error("should match /bin/echo hello")
	}
	if r.Regex.MatchString("XX /bin/echo hello") {
		t.Error("must NOT match XX /bin/echo hello (anchor is implicit)")
	}
}

func TestParseMultipleRulesAndComments(t *testing.T) {
	body := `# Header comment

# encipherr ops
^/Users/me/encipherr encrypt$	K1	# encipherr encrypt

# bob list-keys
^/Users/me/bob list-keys$		# bob

`
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) != 0 {
		t.Fatalf("unexpected: %v", errs)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules; got %d", len(rules))
	}
	if rules[0].LineNo != 4 {
		t.Errorf("rules[0].LineNo: got %d want 4", rules[0].LineNo)
	}
	if rules[1].LineNo != 7 {
		t.Errorf("rules[1].LineNo: got %d want 7", rules[1].LineNo)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```sh
go test ./internal/aclrules/ -count=1 -v -run 'TestParse'
```

Expected: build error (`undefined: Parse`, `undefined: Rule`).

- [ ] **Step 3: Implement `Rule` struct + `Parse`**

Append to `internal/aclrules/aclrules.go`:

```go
import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)
```

(Replace the existing import block — `strings` was already imported; add `bufio`, `fmt`, `io`, `regexp`.)

Then append:

```go
// envNameRE validates env-var names: POSIX KEY syntax.
var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Rule is one parsed allowlist entry.
type Rule struct {
	Regex    *regexp.Regexp // implicitly anchored ^(?:...)$
	EnvAllow []string       // sorted env names allowed (empty -> no --env)
	EnvAny   bool           // env column was "*" -> any env name allowed
	Label    string         // audit label from field 3 (empty if no label)
	LineNo   int            // 1-based line number in source file
	Raw      string         // original line, for error context
}

// Parse reads rule lines from r and returns the parsed rules plus any
// per-line errors. Errors are non-fatal at the line level — Parse
// returns all valid rules it could parse plus a list of errors for
// lines that failed. Callers may decide whether to refuse the whole
// file (LoadFile does) or use the partial result.
func Parse(r io.Reader) ([]Rule, []error) {
	var rules []Rule
	var errs []error
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4*1024), 4*1024) // 4 KB per line max
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		rule, err := parseLine(line, lineNo)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rules = append(rules, rule)
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, fmt.Errorf("scan: %w", err))
	}
	return rules, errs
}

func parseLine(line string, lineNo int) (Rule, error) {
	fields := strings.Split(line, "\t")
	if len(fields) > 3 {
		return Rule{}, fmt.Errorf("line %d: %d tab-separated fields, max 3 (got %q)", lineNo, len(fields), line)
	}

	rxRaw := fields[0]
	envCol := ""
	labelCol := ""
	if len(fields) >= 2 {
		envCol = fields[1]
	}
	if len(fields) >= 3 {
		labelCol = fields[2]
	}

	// Anchor implicitly. Operator may add their own ^ / $ — harmless.
	anchored := "^(?:" + rxRaw + ")$"
	rx, err := regexp.Compile(anchored)
	if err != nil {
		return Rule{}, fmt.Errorf("line %d: invalid regex %q: %w", lineNo, rxRaw, err)
	}

	envAllow, envAny, err := parseEnvColumn(envCol, lineNo)
	if err != nil {
		return Rule{}, err
	}

	label, err := parseLabelColumn(labelCol, lineNo)
	if err != nil {
		return Rule{}, err
	}

	return Rule{
		Regex:    rx,
		EnvAllow: envAllow,
		EnvAny:   envAny,
		Label:    label,
		LineNo:   lineNo,
		Raw:      line,
	}, nil
}

func parseEnvColumn(col string, lineNo int) ([]string, bool, error) {
	col = strings.TrimSpace(col)
	if col == "" {
		return nil, false, nil
	}
	if col == "*" {
		return nil, true, nil
	}
	parts := strings.Split(col, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		name := strings.TrimSpace(p)
		if name == "" {
			return nil, false, fmt.Errorf("line %d: empty env name in csv %q", lineNo, col)
		}
		if !envNameRE.MatchString(name) {
			return nil, false, fmt.Errorf("line %d: invalid env name %q (must match %s)", lineNo, name, envNameRE.String())
		}
		out = append(out, name)
	}
	return out, false, nil
}

func parseLabelColumn(col string, lineNo int) (string, error) {
	if col == "" {
		return "", nil
	}
	if !strings.HasPrefix(col, "#") {
		return "", fmt.Errorf("line %d: field 3 must start with '#'; got %q", lineNo, col)
	}
	return strings.TrimSpace(strings.TrimPrefix(col, "#")), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/aclrules/ -count=1 -v
```

Expected: all `TestParse*` PASS (14 new tests; 11 prior `TestCanonicalize*` still pass).

- [ ] **Step 5: Vet + fmt**

```sh
go vet ./internal/aclrules/
gofmt -l internal/aclrules/
```

Expected: silent.

- [ ] **Step 6: Commit**

```sh
git add internal/aclrules/aclrules.go internal/aclrules/aclrules_test.go
git commit -m "$(cat <<'EOF'
feat(aclrules): Rule struct + Parse for tab-separated rules file

Each line: <regex>\t<env-csv>\t<#label>. Comments (#-prefixed) and
blank lines skipped. Per-line errors are non-fatal (Parse returns
all good rules + an []error for malformed ones); LoadFile (next
task) refuses to load any rules if errors exist.

Validation:
- regex implicitly anchored ^(?:...)$ at compile time — operators
  cannot accidentally produce substring matches
- env names must match POSIX KEY syntax; '*' is a magic value for
  "any env allowed" (rare; documented loudly)
- label column (field 3) must start with #
- max 3 fields per line; 4+ rejected
- 4 KB per-line size limit (prevents adversarial pathological lines)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A3: `(*Rule).Matches` — match string + env subset

**Files:**
- Modify: `internal/aclrules/aclrules.go`
- Modify: `internal/aclrules/aclrules_test.go`

Method that takes the canonicalized match string and the operator's `--env` keys, returns whether the rule allows. Anchored regex match (already enforced at compile time) + env subset check.

- [ ] **Step 1: Write the failing tests**

Append to `internal/aclrules/aclrules_test.go`:

```go
func mustParseOne(t *testing.T, line string) Rule {
	t.Helper()
	rules, errs := Parse(strings.NewReader(line + "\n"))
	if len(errs) != 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule; got %d", len(rules))
	}
	return rules[0]
}

func TestMatchesExact(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo hello$\tKEY")
	if !r.Matches("/bin/echo hello", []string{"KEY"}) {
		t.Error("expected match")
	}
	if r.Matches("/bin/echo world", []string{"KEY"}) {
		t.Error("should not match different args")
	}
}

func TestMatchesAnchored(t *testing.T) {
	r := mustParseOne(t, "/bin/echo hello\tKEY")
	if r.Matches("XXX /bin/echo hello", []string{"KEY"}) {
		t.Error("implicit anchor: must not match leading prefix")
	}
	if r.Matches("/bin/echo hello YYY", []string{"KEY"}) {
		t.Error("implicit anchor: must not match trailing suffix")
	}
}

func TestMatchesWildcard(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo .+$\tKEY")
	for _, s := range []string{"/bin/echo a", "/bin/echo a b c", "/bin/echo 'hello world'"} {
		if !r.Matches(s, []string{"KEY"}) {
			t.Errorf("expected match: %q", s)
		}
	}
	if r.Matches("/bin/echo", []string{"KEY"}) {
		t.Error("'.+' requires at least one trailing char (incl. space)")
	}
}

func TestMatchesEnvSubsetExact(t *testing.T) {
	r := mustParseOne(t, "^/bin/x$\tKEY")
	if !r.Matches("/bin/x", []string{"KEY"}) {
		t.Error("--env KEY should be allowed")
	}
	if !r.Matches("/bin/x", nil) {
		t.Error("no --env should be allowed (empty subset)")
	}
	if r.Matches("/bin/x", []string{"OTHER"}) {
		t.Error("--env OTHER should NOT be allowed")
	}
	if r.Matches("/bin/x", []string{"KEY", "OTHER"}) {
		t.Error("--env KEY,OTHER should NOT be allowed (OTHER not in set)")
	}
}

func TestMatchesEnvSubsetCsv(t *testing.T) {
	r := mustParseOne(t, "^/bin/x$\tK1,K2,K3")
	cases := []struct {
		env  []string
		want bool
	}{
		{nil, true},
		{[]string{"K1"}, true},
		{[]string{"K2"}, true},
		{[]string{"K1", "K3"}, true},
		{[]string{"K1", "K2", "K3"}, true},
		{[]string{"K4"}, false},
		{[]string{"K1", "K4"}, false},
	}
	for _, c := range cases {
		got := r.Matches("/bin/x", c.env)
		if got != c.want {
			t.Errorf("env=%v: got %v want %v", c.env, got, c.want)
		}
	}
}

func TestMatchesEnvEmpty(t *testing.T) {
	r := mustParseOne(t, "^/bin/x$\t")
	if !r.Matches("/bin/x", nil) {
		t.Error("no --env should match an empty env column")
	}
	if r.Matches("/bin/x", []string{"K"}) {
		t.Error("any --env should be denied with empty env column")
	}
}

func TestMatchesEnvAny(t *testing.T) {
	r := mustParseOne(t, "^/bin/x$\t*")
	if !r.Matches("/bin/x", nil) {
		t.Error("nil --env should match * column")
	}
	if !r.Matches("/bin/x", []string{"ANYTHING", "GOES"}) {
		t.Error("any --env should match * column")
	}
}

func TestMatchesRegexNoMatch(t *testing.T) {
	r := mustParseOne(t, "^/bin/x$\tKEY")
	if r.Matches("/bin/y", []string{"KEY"}) {
		t.Error("cmd /bin/y does not match /bin/x")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```sh
go test ./internal/aclrules/ -count=1 -v -run 'TestMatches'
```

Expected: build error (`r.Matches undefined`).

- [ ] **Step 3: Implement `(*Rule).Matches`**

Append to `internal/aclrules/aclrules.go`:

```go
// Matches reports whether this rule allows the given canonical match
// string and operator-supplied env-var name set. Both regex anchor
// (compiled in at parse time) and env subset check must pass.
func (r *Rule) Matches(matchStr string, envKeys []string) bool {
	if !r.Regex.MatchString(matchStr) {
		return false
	}
	return r.envAllowed(envKeys)
}

func (r *Rule) envAllowed(envKeys []string) bool {
	if r.EnvAny {
		return true
	}
	if len(envKeys) == 0 {
		return true // empty subset is always allowed
	}
	if len(r.EnvAllow) == 0 {
		return false // no env keys allowed, but operator passed some
	}
	allowed := make(map[string]struct{}, len(r.EnvAllow))
	for _, k := range r.EnvAllow {
		allowed[k] = struct{}{}
	}
	for _, k := range envKeys {
		if _, ok := allowed[k]; !ok {
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/aclrules/ -count=1 -v -run 'TestMatches'
```

Expected: all 8 `TestMatches*` PASS.

- [ ] **Step 5: Vet + fmt**

```sh
go vet ./internal/aclrules/
gofmt -l internal/aclrules/
```

Expected: silent.

- [ ] **Step 6: Commit**

```sh
git add internal/aclrules/aclrules.go internal/aclrules/aclrules_test.go
git commit -m "$(cat <<'EOF'
feat(aclrules): Rule.Matches — regex match + env subset

Two-stage check:
1. Canonical match string against rule's anchored regex.
2. Operator's --env name set must be subset of rule's EnvAllow,
   with two special cases:
   - empty operator set is always allowed (universal subset).
   - rule EnvAny ('*' column) accepts any env names.

Subset (not equality) gives operators one rule covering multiple
invocation shapes: a tool that may be called with 0..N of a fixed
env set passes a single rule.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A4: `aclrules.LoadFile` + trivial-match-everything detection

**Files:**
- Modify: `internal/aclrules/aclrules.go`
- Modify: `internal/aclrules/aclrules_test.go`

Read rules file from disk. Refuse to load if any rule trivially matches everything (heuristic: empty string, `/`, and `../../etc/passwd` all match → refused). Refuse if any parse error occurred. Return a sentinel `ErrRulesMissing` if file doesn't exist (so cmdExec can distinguish from other errors).

- [ ] **Step 1: Write the failing tests**

Append to `internal/aclrules/aclrules_test.go`:

```go
import (
	// existing imports...
	"errors"
	"os"
	"path/filepath"
)
```

Add to imports if not already there. Then append tests:

```go
func TestLoadFileMissing(t *testing.T) {
	rules, err := LoadFile(filepath.Join(t.TempDir(), "missing.rules"))
	if !errors.Is(err, ErrRulesMissing) {
		t.Fatalf("want ErrRulesMissing, got %v", err)
	}
	if rules != nil {
		t.Errorf("expected nil rules; got %v", rules)
	}
}

func TestLoadFileEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.rules")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadFile(path)
	if err != nil {
		t.Fatalf("want no error; got %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected zero rules; got %d", len(rules))
	}
}

func TestLoadFileValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.rules")
	body := "^/bin/echo .+$\tKEY\t# echo\n^/bin/bob list-keys$\t\t# bob\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadFile(path)
	if err != nil {
		t.Fatalf("want no error; got %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 rules; got %d", len(rules))
	}
}

func TestLoadFileRefusesParseErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.rules")
	body := "^/bin/[unclosed\tKEY\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFile(path)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
	if !strings.Contains(err.Error(), "line 1") {
		t.Errorf("error should reference line 1: %v", err)
	}
}

func TestLoadFileRefusesTrivialMatchEverything(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.rules")
	// .* anchored becomes ^(?:.*)$ which matches every string.
	body := "^.*$\t*\t# everything\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFile(path)
	if err == nil {
		t.Error("expected refusal for trivial-match-everything rule")
	}
	if !strings.Contains(err.Error(), "matches every") && !strings.Contains(err.Error(), "trivial") {
		t.Errorf("error should mention trivial-match: %v", err)
	}
}

func TestLoadFileAcceptsRealisticPermissive(t *testing.T) {
	// /bin/echo .+ is permissive but bounded — operator's call.
	dir := t.TempDir()
	path := filepath.Join(dir, "x.rules")
	body := "^/bin/echo .+$\t*\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadFile(path)
	if err != nil {
		t.Errorf("realistic permissive rule should load; got %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 rule; got %d", len(rules))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```sh
go test ./internal/aclrules/ -count=1 -v -run 'TestLoadFile'
```

Expected: build error (`undefined: LoadFile`, `undefined: ErrRulesMissing`).

- [ ] **Step 3: Implement `LoadFile` + `ErrRulesMissing` + trivial-match check**

Append to `internal/aclrules/aclrules.go`:

```go
import "errors"
import "os"
```

(Merge into the existing import block.) Then append:

```go
// ErrRulesMissing is returned by LoadFile when the rules file does
// not exist. cmdExec catches this to print the dedicated init hint.
var ErrRulesMissing = errors.New("exec-allowlist.rules not found")

// LoadFile reads and parses an allowlist rules file. Refuses to load
// if any line failed to parse or if any rule trivially matches every
// possible invocation. Returns ErrRulesMissing if the file does not
// exist (callers may scaffold or hard-deny on this).
func LoadFile(path string) ([]Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrRulesMissing
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	rules, errs := Parse(f)
	if len(errs) > 0 {
		// Refuse the whole file on any per-line error — partial loading
		// would silently drop rules the operator thought they had.
		return nil, fmt.Errorf("parse %s: %w", path, errs[0])
	}

	for _, r := range rules {
		if isTrivialMatchEverything(r.Regex) {
			return nil, fmt.Errorf("%s line %d: rule matches every possible invocation (%q); refuse to load",
				path, r.LineNo, r.Raw)
		}
	}
	return rules, nil
}

// isTrivialMatchEverything heuristically detects rules that accept
// any string. Three sentinel inputs that should never simultaneously
// match a reasonable allowlist rule: empty string, "/", and a
// path-traversal-looking adversarial string.
func isTrivialMatchEverything(rx *regexp.Regexp) bool {
	return rx.MatchString("") &&
		rx.MatchString("/") &&
		rx.MatchString("../../etc/passwd")
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/aclrules/ -count=1 -v
```

Expected: 39 tests PASS (11 Canonicalize + 14 Parse + 8 Matches + 6 LoadFile).

- [ ] **Step 5: Vet + fmt**

```sh
go vet ./internal/aclrules/
gofmt -l internal/aclrules/
```

Expected: silent.

- [ ] **Step 6: Commit**

```sh
git add internal/aclrules/aclrules.go internal/aclrules/aclrules_test.go
git commit -m "$(cat <<'EOF'
feat(aclrules): LoadFile + trivial-match-everything detection

LoadFile reads, parses, validates. Refuses to load if:
- file has any per-line parse error (no partial loads — operator
  would think they had a rule that wasn't actually parsed)
- any rule trivially matches every possible invocation (heuristic:
  empty string AND '/' AND '../../etc/passwd' all match)

Sentinel ErrRulesMissing for the file-not-found case so cmdExec can
print the dedicated init hint vs a generic open error.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A5: `aclrules.LiteralRule` — auto-bless line generator

**Files:**
- Modify: `internal/aclrules/aclrules.go`
- Modify: `internal/aclrules/aclrules_test.go`

Helper that generates one fully-escaped literal rule line. Used by the auto-bless flow when operator types `yes` at the deny prompt.

- [ ] **Step 1: Write the failing tests**

Append to `internal/aclrules/aclrules_test.go`:

```go
func TestLiteralRuleSimple(t *testing.T) {
	got := LiteralRule("/bin/echo", []string{"hello"}, []string{"KEY"}, "test label")
	want := "^/bin/echo hello$\tKEY\t# test label"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestLiteralRuleEscapesMeta(t *testing.T) {
	// Cmd path has dots; arg has glob-like char that's actually literal here.
	got := LiteralRule("/Users/me/.local/bin/encipherr",
		[]string{"encrypt", "file", "/tmp/foo.txt"},
		[]string{"ENCIPHERR_KEY"}, "encipherr file ops")
	want := `^/Users/me/\.local/bin/encipherr encrypt file /tmp/foo\.txt$` + "\tENCIPHERR_KEY\t# encipherr file ops"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestLiteralRuleEnvSorted(t *testing.T) {
	got := LiteralRule("/bin/x", nil, []string{"Z", "A", "M"}, "")
	want := "^/bin/x$\tA,M,Z"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestLiteralRuleEmptyEnv(t *testing.T) {
	got := LiteralRule("/bin/x", nil, nil, "")
	want := "^/bin/x$"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestLiteralRuleArgWithSpace(t *testing.T) {
	// shellescape wraps in single quotes, then QuoteMeta escapes the quotes.
	got := LiteralRule("/bin/echo", []string{"hello world"}, nil, "")
	want := `^/bin/echo 'hello world'$`
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestLiteralRuleRoundTrip(t *testing.T) {
	// Generated line should parse without error and match the original invocation.
	cmd := "/Users/me/.local/bin/encipherr"
	args := []string{"encrypt", "file", "/tmp/has space.txt"}
	envs := []string{"ENCIPHERR_KEY"}
	line := LiteralRule(cmd, args, envs, "round-trip test")

	rules, errs := Parse(strings.NewReader(line + "\n"))
	if len(errs) != 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule; got %d", len(rules))
	}
	matchStr := Canonicalize(cmd, args)
	if !rules[0].Matches(matchStr, envs) {
		t.Errorf("auto-blessed rule must match its originating invocation")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```sh
go test ./internal/aclrules/ -count=1 -v -run 'TestLiteralRule'
```

Expected: build error (`undefined: LiteralRule`).

- [ ] **Step 3: Implement `LiteralRule`**

Append to `internal/aclrules/aclrules.go`:

```go
import "sort"
```

(Add to import block.) Then append:

```go
// LiteralRule returns a fully-escaped, anchored rule line for the
// given invocation. Used by alice's auto-bless flow: when operator
// types 'yes' at the deny prompt, alice appends this line to
// exec-allowlist.rules. The generated regex matches *exactly* the
// original (cmd, args); operator can hand-edit later to widen it.
//
// Env names are sorted so identical invocations produce byte-identical
// lines (deterministic for tests and stable diffs).
func LiteralRule(cmd string, args []string, envKeys []string, label string) string {
	match := Canonicalize(cmd, args)
	rxBody := regexp.QuoteMeta(match)

	envSorted := append([]string(nil), envKeys...)
	sort.Strings(envSorted)

	var sb strings.Builder
	sb.WriteByte('^')
	sb.WriteString(rxBody)
	sb.WriteByte('$')
	if len(envSorted) > 0 || label != "" {
		sb.WriteByte('\t')
		sb.WriteString(strings.Join(envSorted, ","))
	}
	if label != "" {
		sb.WriteByte('\t')
		sb.WriteString("# ")
		sb.WriteString(label)
	}
	return sb.String()
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/aclrules/ -count=1 -v
```

Expected: 45 tests PASS (6 new `TestLiteralRule*`).

- [ ] **Step 5: Vet + fmt**

```sh
go vet ./internal/aclrules/
gofmt -l internal/aclrules/
```

Expected: silent.

- [ ] **Step 6: Commit**

```sh
git add internal/aclrules/aclrules.go internal/aclrules/aclrules_test.go
git commit -m "$(cat <<'EOF'
feat(aclrules): LiteralRule — fully-escaped auto-bless line generator

Produces a deterministic, anchored, QuoteMeta-escaped regex line
matching exactly the originating invocation. Used by alice's
auto-bless flow when operator types 'yes' at the deny prompt;
appended verbatim to exec-allowlist.rules.

Round-trip test verifies the generated line parses cleanly and
matches the originating (cmd, args, env), so the auto-bless cycle
is closed: deny -> yes -> append -> re-run -> match.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A6: `cmd/alice/exec.go` — wire `.rules` into `cmdExec`

**Files:**
- Modify: `cmd/alice/exec.go`
- Modify: `cmd/alice/exec_test.go`

Replace the v2.x JSON allowlist load + `matchAllowlist` call with `aclrules.LoadFile` + iterate `Rule.Matches`. Update the deny error message to print the literal rule the operator would paste (now a regex line, not a JSON snippet). Update the auto-bless flow to append to `exec-allowlist.rules` instead of `exec-allowlist.json`. Surface the matched rule's label in the audit-line stderr message.

This task does **not** include the migration logic (Task A7) or the `--show-match-string` flag (Task A8) — those land as separate commits. Existing tests for the v2.x JSON allowlist are rewritten against the new model; any test specifically targeting strict-equality-via-JSON-args is deleted (replaced by `aclrules` unit tests).

- [ ] **Step 1: Read existing cmdExec + identify what stays vs. goes**

```sh
cd /Users/bbwave03/claude/anb
grep -n 'allowlist\|loadAllowlist\|matchAllowlist\|formatDenyJSON\|appendAllowEntry\|confirmAppend\|errAllowlistMissing\|errExecDenied' cmd/alice/exec.go
```

Note the line numbers. The following symbols are **deleted** in this task:
- `allowEntry` struct + fields
- `allowlist` struct
- `loadAllowlist` function
- `matchAllowlist` function
- `formatDenyJSON` function
- `mustMarshalJSON` function (only used by old deny msg)
- `sortedStringSlice` function (only used by old auto-bless path)
- `appendAllowEntry` function (replaced by simple append to .rules)
- `errAllowlistMissing` (replaced by `aclrules.ErrRulesMissing`)

These stay:
- `parseEnvFlag`, `mergeEnv`, `envEntry`, `envFlagValue` (unchanged — argv parsing)
- `confirmAppend` (TTY 'yes' prompt — reused unchanged)
- `errExecDenied` (silent-exit sentinel — reused unchanged)
- `cmdExec` skeleton (heavily rewritten internally)

- [ ] **Step 2: Write new exec.go body (paste below replacing affected sections)**

This is a large structural edit. The new `cmd/alice/exec.go` body for the allowlist-related parts should look like this (apply changes via `Edit` tool; surrounding parts of cmdExec are unchanged):

Replace the type/var declarations for the v2 allowlist with these `aclrules` imports + the kept sentinel:

```go
// At the top of cmd/alice/exec.go imports (alongside existing imports):

	"github.com/kaka-milan-22/AnB/v2/internal/aclrules"
```

Delete the `allowEntry`, `allowlist`, `errAllowlistMissing`, `loadAllowlist`, `matchAllowlist`, `formatDenyJSON`, `mustMarshalJSON`, `sortedStringSlice`, `appendAllowEntry` declarations entirely.

Keep `errExecDenied` and `confirmAppend` as-is.

Inside `cmdExec`, replace the existing block that loads the JSON allowlist and calls `matchAllowlist` with this new block. (Find the original block by searching for `loadAllowlist` and `matchAllowlist` — they're called sequentially.)

```go
	// --- BEGIN v3.0 allowlist match ---
	rulesPath := filepath.Join(s.Dir, "exec-allowlist.rules")
	rules, err := aclrules.LoadFile(rulesPath)
	if err != nil {
		if errors.Is(err, aclrules.ErrRulesMissing) {
			return fmt.Errorf("alice exec: no allowlist rules.\n"+
				"  Create %s to bless commands.\n"+
				"  Run any command to see the auto-bless prompt (TTY required)",
				rulesPath)
		}
		return err
	}

	envNames := sortedStringKeys(keySet)
	matchStr := aclrules.Canonicalize(cmdName, childArgs)

	var matched *aclrules.Rule
	for i := range rules {
		if rules[i].Matches(matchStr, envNames) {
			matched = &rules[i]
			break
		}
	}

	if matched == nil {
		denyMsg := buildDenyMsgV3(rulesPath, cmdName, childArgs, envNames)

		if term.StdinIsTTY() && term.IsTTY(os.Stderr) {
			fmt.Fprintln(os.Stderr, denyMsg)
			if confirmAppend(os.Stdin, os.Stderr) {
				line := aclrules.LiteralRule(cmdName, childArgs, envNames,
					"auto-blessed "+timeNowRFC3339())
				if err := appendRuleLine(rulesPath, line); err != nil {
					return fmt.Errorf("append rule: %w", err)
				}
				return fmt.Errorf("✓ appended rule to %s — re-run your command to execute it",
					rulesPath)
			}
			return errExecDenied
		}
		return errors.New(denyMsg)
	}
	// --- END v3.0 allowlist match ---

	// (existing code continues: open vault, decrypt env values, syscall.Exec)
	// Just before syscall.Exec, replace existing audit-line print with:
	if matched.Label != "" {
		fmt.Fprintf(os.Stderr, "→ exec %s with env=%v rule=[%s]\n", cmdPath, envNames, matched.Label)
	} else {
		fmt.Fprintf(os.Stderr, "→ exec %s with env=%v rule=line:%d\n", cmdPath, envNames, matched.LineNo)
	}
```

Add these supporting helpers in the same file:

```go
// sortedStringKeys returns sorted keys of a map[string]struct{}.
// Used to canonicalise the env name set for both matching and audit.
func sortedStringKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// timeNowRFC3339 wraps time.Now().UTC().Format(time.RFC3339) so that
// the auto-bless label timestamp is centralised (and a test seam can
// be added later by swapping this for an injectable clock).
func timeNowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// appendRuleLine appends a single newline-terminated line to the
// rules file, creating it with mode 0o600 if absent. Atomic via
// O_APPEND on existing files. For first creation, write a leading
// header comment so the file is operator-friendly.
func appendRuleLine(path, line string) error {
	if _, statErr := os.Stat(path); errors.Is(statErr, os.ErrNotExist) {
		header := `# AnB exec-allowlist rules. One rule per line:
#   <regex>\t<env-csv>\t#<label>
# All fields after the first are optional. Implicit ^...$ anchor.
# Default deny: unmatched invocations are rejected.

`
		if err := os.WriteFile(path, []byte(header), 0o600); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		return err
	}
	return nil
}

// buildDenyMsgV3 formats the deny message for v3.0 — shows the literal
// rule line the operator would paste, with the auto-bless-style
// QuoteMeta'd regex and sorted env CSV.
func buildDenyMsgV3(rulesPath, cmd string, args, envNames []string) string {
	suggestion := aclrules.LiteralRule(cmd, args, envNames, "")
	argsRender, _ := json.Marshal(args)
	envRender, _ := json.Marshal(envNames)
	return fmt.Sprintf("alice exec: invocation not in allowlist.rules.\n\n"+
		"  cmd:  %s\n"+
		"  args: %s\n"+
		"  env:  %s\n\n"+
		"To allow exactly this invocation, append to %s:\n\n"+
		"  %s\n\n"+
		"(This is a fully-escaped LITERAL regex. Edit by hand to add wildcards.)",
		cmd, argsRender, envRender, rulesPath, suggestion)
}
```

Make sure `"sort"`, `"time"`, and `"encoding/json"` (for buildDenyMsgV3) are in the import block. `"encoding/json"` was already there in v2 (formatDenyJSON used it); kept.

- [ ] **Step 3: Update existing tests in `cmd/alice/exec_test.go`**

The tests that specifically asserted v2 JSON behaviors must be deleted or rewritten. The implementer should:

a. Delete tests targeting `loadAllowlist`, `matchAllowlist`, `formatDenyJSON`, `appendAllowEntry` — these symbols no longer exist.

b. Keep tests for `parseEnvFlag`, `mergeEnv`, `confirmAppend` — those are unchanged.

c. The e2e tests in `e2e/full_test.go` will be updated in Task A12; this task only updates unit tests in `exec_test.go`.

Run:

```sh
go test ./cmd/alice/ -count=1 -v
```

Expected (after deletions): the surviving tests (parseEnvFlag × ~5, mergeEnv × ~3, confirmAppend × 4) all pass. Build must succeed (no `undefined: loadAllowlist` etc.).

- [ ] **Step 4: Run full repo build**

```sh
go build ./...
go vet ./...
gofmt -l .
```

Expected: clean. `e2e/full_test.go` may fail to compile if it references v2 symbols — that's Task A12's job. Comment out the affected test functions with `// TODO: rewrite for v3.0 in Task A12` so the build proceeds, OR temporarily stub them. The implementer chooses whichever is less disruptive.

- [ ] **Step 5: Commit**

```sh
git add cmd/alice/exec.go cmd/alice/exec_test.go e2e/full_test.go
git commit -m "$(cat <<'EOF'
feat(alice)!: exec allowlist switches to regex .rules (BREAKING)

Replaces v2.x JSON exec-allowlist.json (strict-equality per-position
args + set-equality env) with v3.0 plain-text exec-allowlist.rules
(one Go RE2 regex per line, implicitly anchored, env subset).

cmd/alice/exec.go:
- delete: allowEntry/allowlist types, loadAllowlist, matchAllowlist,
  formatDenyJSON, mustMarshalJSON, sortedStringSlice, appendAllowEntry,
  errAllowlistMissing (replaced by aclrules.ErrRulesMissing)
- keep: parseEnvFlag, mergeEnv, confirmAppend, errExecDenied
- new: rulesPath load via aclrules.LoadFile, iterate Rule.Matches,
  auto-bless writes literal regex line, deny message shows the line
  operator would paste, audit-line stderr shows matched rule label

e2e/full_test.go: v2 tests stubbed pending A12 rewrite.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A7: One-shot migration `.json` → `.rules`

**Files:**
- Create: `internal/aclrules/migrate.go`
- Create: `internal/aclrules/migrate_test.go`
- Modify: `cmd/alice/main.go`

`aclrules.MigrateLegacy(dir string) error` checks for `exec-allowlist.json` in the alice state dir. If present AND `exec-allowlist.rules` is absent, converts each JSON entry into a literal rule line, writes `exec-allowlist.rules` atomically, renames the `.json` to `.json.bak`, and prints a one-line stderr note. Idempotent: re-running after migration is a no-op.

`cmd/alice/main.go` calls `MigrateLegacy` once per dispatch (cheap stat check) before falling into the command switch.

- [ ] **Step 1: Write the failing tests**

Create `internal/aclrules/migrate_test.go`:

```go
package aclrules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// legacyEntry mirrors the v2.x allowEntry layout for synthetic test fixtures.
type legacyEntry struct {
	Label string   `json:"label,omitempty"`
	Cmd   string   `json:"cmd"`
	Args  []string `json:"args"`
	Env   []string `json:"env"`
}

type legacyFile struct {
	Allow []legacyEntry `json:"allow"`
}

func writeLegacy(t *testing.T, dir string, entries ...legacyEntry) {
	t.Helper()
	body, err := json.MarshalIndent(legacyFile{Allow: entries}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "exec-allowlist.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateNoLegacy(t *testing.T) {
	dir := t.TempDir()
	if err := MigrateLegacy(dir); err != nil {
		t.Errorf("no-op should not error: %v", err)
	}
	// Confirm .rules was NOT created if no legacy.
	if _, err := os.Stat(filepath.Join(dir, "exec-allowlist.rules")); !os.IsNotExist(err) {
		t.Error(".rules should not be created when no .json exists")
	}
}

func TestMigrateRulesAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	writeLegacy(t, dir, legacyEntry{Cmd: "/x", Args: []string{"a"}, Env: []string{"K"}})
	rulesBefore := []byte("^/existing$\tK\n")
	if err := os.WriteFile(filepath.Join(dir, "exec-allowlist.rules"), rulesBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacy(dir); err != nil {
		t.Fatal(err)
	}
	// .rules should be unchanged.
	got, _ := os.ReadFile(filepath.Join(dir, "exec-allowlist.rules"))
	if string(got) != string(rulesBefore) {
		t.Errorf(".rules should be untouched when present; got %q", got)
	}
	// .json should still be there (not renamed) since we didn't migrate.
	if _, err := os.Stat(filepath.Join(dir, "exec-allowlist.json")); err != nil {
		t.Errorf(".json should remain when .rules already present: %v", err)
	}
}

func TestMigrateOneEntry(t *testing.T) {
	dir := t.TempDir()
	writeLegacy(t, dir, legacyEntry{
		Label: "encipherr encrypt",
		Cmd:   "/Users/me/.local/bin/encipherr",
		Args:  []string{"encrypt", "file", "/tmp/foo.txt"},
		Env:   []string{"ENCIPHERR_KEY"},
	})
	if err := MigrateLegacy(dir); err != nil {
		t.Fatal(err)
	}
	rulesBytes, err := os.ReadFile(filepath.Join(dir, "exec-allowlist.rules"))
	if err != nil {
		t.Fatal(err)
	}
	rulesText := string(rulesBytes)

	expectedLine := `^/Users/me/\.local/bin/encipherr encrypt file /tmp/foo\.txt$` + "\tENCIPHERR_KEY\t# encipherr encrypt"
	if !strings.Contains(rulesText, expectedLine) {
		t.Errorf("expected line missing\nwant: %q\nin:   %q", expectedLine, rulesText)
	}

	// Old file should be renamed to .json.bak.
	if _, err := os.Stat(filepath.Join(dir, "exec-allowlist.json")); !os.IsNotExist(err) {
		t.Error(".json should be renamed to .json.bak")
	}
	if _, err := os.Stat(filepath.Join(dir, "exec-allowlist.json.bak")); err != nil {
		t.Errorf(".json.bak should exist: %v", err)
	}
}

func TestMigrateMultipleEntries(t *testing.T) {
	dir := t.TempDir()
	writeLegacy(t, dir,
		legacyEntry{Cmd: "/a", Args: []string{"x"}, Env: []string{"K1"}, Label: "a-rule"},
		legacyEntry{Cmd: "/b", Args: []string{"y", "z"}, Env: []string{"K1", "K2"}, Label: "b-rule"},
	)
	if err := MigrateLegacy(dir); err != nil {
		t.Fatal(err)
	}
	rulesBytes, _ := os.ReadFile(filepath.Join(dir, "exec-allowlist.rules"))
	rulesText := string(rulesBytes)

	if !strings.Contains(rulesText, "^/a x$") {
		t.Errorf("missing entry a: %q", rulesText)
	}
	if !strings.Contains(rulesText, "^/b y z$") {
		t.Errorf("missing entry b: %q", rulesText)
	}
	if !strings.Contains(rulesText, "K1,K2") {
		t.Errorf("multi-env should be CSV: %q", rulesText)
	}
}

func TestMigrateBehaviourPreserving(t *testing.T) {
	// After migration, the generated rule must match exactly the
	// invocation the original JSON entry matched.
	dir := t.TempDir()
	cmd := "/Users/me/.local/bin/encipherr"
	args := []string{"encrypt", "file", "/tmp/has space.txt"}
	envs := []string{"ENCIPHERR_KEY"}
	writeLegacy(t, dir, legacyEntry{
		Label: "test", Cmd: cmd, Args: args, Env: envs,
	})
	if err := MigrateLegacy(dir); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadFile(filepath.Join(dir, "exec-allowlist.rules"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule; got %d", len(rules))
	}
	matchStr := Canonicalize(cmd, args)
	if !rules[0].Matches(matchStr, envs) {
		t.Error("migrated rule must match original invocation")
	}
}

func TestMigrateIdempotent(t *testing.T) {
	dir := t.TempDir()
	writeLegacy(t, dir, legacyEntry{Cmd: "/x", Args: []string{"a"}, Env: []string{"K"}})
	if err := MigrateLegacy(dir); err != nil {
		t.Fatal(err)
	}
	// Second run: .json is gone, .rules exists. Should be no-op.
	if err := MigrateLegacy(dir); err != nil {
		t.Errorf("re-run after migration should be no-op: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```sh
go test ./internal/aclrules/ -count=1 -v -run 'TestMigrate'
```

Expected: build error (`undefined: MigrateLegacy`).

- [ ] **Step 3: Implement migrator**

Create `internal/aclrules/migrate.go`:

```go
package aclrules

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// legacyEntry mirrors the v2.x exec-allowlist.json entry shape.
type legacyEntry struct {
	Label string   `json:"label,omitempty"`
	Cmd   string   `json:"cmd"`
	Args  []string `json:"args"`
	Env   []string `json:"env"`
}

type legacyFile struct {
	Allow []legacyEntry `json:"allow"`
}

// MigrateLegacy is a one-shot converter from v2.x exec-allowlist.json
// to v3.0 exec-allowlist.rules. If a .rules file already exists in
// dir, MigrateLegacy is a no-op (operator's hand-curated rules win).
// If a .json file exists and no .rules, MigrateLegacy:
//   1. Reads and parses the JSON.
//   2. For each entry, generates a literal-anchored regex line via
//      LiteralRule.
//   3. Writes a header comment + all generated lines atomically to
//      exec-allowlist.rules (0o600).
//   4. Renames the original .json to .json.bak.
//   5. Logs a one-line stderr note.
//
// Idempotent: after running once, the .json is renamed so subsequent
// calls find no legacy and exit cleanly.
func MigrateLegacy(dir string) error {
	rulesPath := filepath.Join(dir, "exec-allowlist.rules")
	jsonPath := filepath.Join(dir, "exec-allowlist.json")
	bakPath := jsonPath + ".bak"

	if _, err := os.Stat(rulesPath); err == nil {
		return nil // .rules wins
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", rulesPath, err)
	}

	body, err := os.ReadFile(jsonPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // nothing to migrate
		}
		return fmt.Errorf("read %s: %w", jsonPath, err)
	}

	var legacy legacyFile
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&legacy); err != nil {
		return fmt.Errorf("parse %s: %w", jsonPath, err)
	}

	var sb strings.Builder
	sb.WriteString("# AnB exec-allowlist rules (migrated from v2.x exec-allowlist.json).\n")
	sb.WriteString("# Original kept as exec-allowlist.json.bak.\n")
	sb.WriteString("# One rule per line: <regex>\\t<env-csv>\\t#<label>. Implicit ^...$ anchor.\n")
	sb.WriteString("\n")
	for _, e := range legacy.Allow {
		label := e.Label
		if label == "" {
			label = "migrated"
		}
		line := LiteralRule(e.Cmd, e.Args, e.Env, label)
		sb.WriteString(line)
		sb.WriteByte('\n')
	}

	// Atomic write via tmp + rename.
	tmpPath := rulesPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(sb.String()), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, rulesPath); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, rulesPath, err)
	}
	if err := os.Rename(jsonPath, bakPath); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", jsonPath, bakPath, err)
	}
	fmt.Fprintf(os.Stderr, "alice: migrated v2.x exec-allowlist.json → exec-allowlist.rules (%d rules). Original kept as exec-allowlist.json.bak.\n", len(legacy.Allow))
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/aclrules/ -count=1 -v -run 'TestMigrate'
```

Expected: all 6 `TestMigrate*` PASS.

- [ ] **Step 5: Wire `MigrateLegacy` into `cmd/alice/main.go`**

Find the dispatch in `main()` (around line 30-50). Just before the version-subcommand switch, add a migration call. The state dir comes from `localvault.Open` which has `s.Dir`. Since main() doesn't open the store before dispatch, we resolve the dir manually:

Add near the top of `main()`, right after the early `version` / `--version` / `-V` branch:

```go
	// One-shot migration of v2.x JSON allowlist to v3.0 rules format.
	// Cheap (just a stat) when nothing to do; runs once per session.
	if dir, err := localvault.ResolveDir(""); err == nil {
		_ = aclrules.MigrateLegacy(dir) // best-effort; errors are logged inside
	}
```

If `localvault.ResolveDir(string)` doesn't exist yet, add a thin helper inspired by how alice already resolves the state dir elsewhere. (Inspection of cmd/alice/main.go reveals `loadClient` uses `s := localvault.Open(*dir)` which resolves env/default internally; reuse that pattern by adding a `ResolveDir` to `internal/localvault/localvault.go` if not present — the implementer checks first and only adds if needed.)

Also add `"github.com/kaka-milan-22/AnB/v2/internal/aclrules"` to main.go's imports.

- [ ] **Step 6: Run full repo build + tests**

```sh
go build ./...
go vet ./...
gofmt -l .
go test ./internal/aclrules/ ./cmd/alice/ -count=1
```

Expected: all green.

- [ ] **Step 7: Commit**

```sh
git add internal/aclrules/migrate.go internal/aclrules/migrate_test.go cmd/alice/main.go internal/localvault/
git commit -m "$(cat <<'EOF'
feat(aclrules): MigrateLegacy — one-shot .json → .rules converter

On first alice invocation under v3.0, if exec-allowlist.json exists
and exec-allowlist.rules does not, generates equivalent literal-
anchored regex lines, writes the new file atomically, and renames
the JSON to .json.bak. Idempotent — re-running after migration is
a stat-only no-op.

Behaviour-preserving per entry: regexp.QuoteMeta on the canonical
form produces a regex that matches exactly the same (cmd, args, env)
the v2.x strict-equality entry matched. Round-trip test in
TestMigrateBehaviourPreserving locks this invariant.

Wired into cmd/alice/main.go's dispatch so the migration is
transparent — operators just run alice as usual after upgrading.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A8: `alice exec --show-match-string` helper flag

**Files:**
- Modify: `cmd/alice/exec.go`

When `--show-match-string` is set, alice exec prints the canonical match string (the exact string regex rules would test against) for the given invocation and exits with code 0, without contacting Bob or executing anything. Useful for operators authoring rules.

- [ ] **Step 1: Add a unit test in `cmd/alice/exec_test.go`**

```go
func TestShowMatchStringFlag(t *testing.T) {
	// Direct call to the helper that powers --show-match-string.
	got := showMatchStringOutput("/Users/bbwave03/.local/bin/encipherr",
		[]string{"encrypt", "file", "/tmp/has space.txt"})
	want := "/Users/bbwave03/.local/bin/encipherr encrypt file '/tmp/has space.txt'"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

```sh
go test ./cmd/alice/ -count=1 -v -run 'TestShowMatchStringFlag'
```

Expected: build error (`undefined: showMatchStringOutput`).

- [ ] **Step 3: Implement in `cmd/alice/exec.go`**

Inside `cmdExec`, near the top of the function (after `parse(fs, args)` returns positionals but before the env-flag parse), add the `--show-match-string` flag. The cmdExec function uses `flag.FlagSet` already; add one new flag:

```go
	showMatchString := fs.Bool("show-match-string", false,
		"print the canonical match string used by exec-allowlist.rules and exit (no execution)")
```

Then, after positionals are parsed and you have `cmdName` and `childArgs`:

```go
	if *showMatchString {
		fmt.Println(showMatchStringOutput(cmdName, childArgs))
		return nil
	}
```

And the helper, near the other small helpers (e.g., near `appendRuleLine`):

```go
func showMatchStringOutput(cmd string, args []string) string {
	return aclrules.Canonicalize(cmd, args)
}
```

(Trivial wrapper, but having it in its own function gives the unit test a stable target without standing up the whole flag-parse path.)

- [ ] **Step 4: Add a smoke step**

```sh
go install ./cmd/alice
alice exec --show-match-string -- /bin/echo "hello world"
```

Expected output: `/bin/echo 'hello world'`

- [ ] **Step 5: Run tests + vet + fmt**

```sh
go test ./cmd/alice/ -count=1
go vet ./cmd/alice/
gofmt -l cmd/alice/
```

Expected: green.

- [ ] **Step 6: Commit**

```sh
git add cmd/alice/exec.go cmd/alice/exec_test.go
git commit -m "$(cat <<'EOF'
feat(alice): exec --show-match-string flag

Prints the canonical (shellescape + space-join) form of an
invocation without executing it. Helps operators author regex rules
for exec-allowlist.rules — they can pipe the same argv into
alice exec --show-match-string and see exactly what string their
regex needs to match (including how alice quotes args with spaces).

No daemon round-trip, no allowlist consultation, no env resolution.
Pure local string formatting.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A9: `cmdEnroll` scaffolds `exec-allowlist.rules`

**Files:**
- Modify: `cmd/alice/sensitive.go`

When `alice enroll` runs on a fresh install, it currently scaffolds `exec-allowlist.json` containing `{"allow":[]}`. For v3.0, scaffold `exec-allowlist.rules` containing only a header comment.

- [ ] **Step 1: Locate the scaffold code**

```sh
grep -n 'exec-allowlist' cmd/alice/sensitive.go
```

Note the existing scaffold-on-enroll lines.

- [ ] **Step 2: Add a unit test in `cmd/alice/exec_test.go`**

```go
func TestEnrollScaffoldsRulesFile(t *testing.T) {
	dir := t.TempDir()
	if err := scaffoldRulesFile(dir); err != nil {
		t.Fatalf("scaffold: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "exec-allowlist.rules"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "# AnB exec-allowlist rules") {
		t.Errorf("scaffold should have header comment; got %q", text)
	}
	// Scaffold must contain ZERO rules — just comments.
	rules, errs := aclrules.Parse(strings.NewReader(text))
	if len(errs) != 0 {
		t.Errorf("scaffold should parse cleanly; got errors %v", errs)
	}
	if len(rules) != 0 {
		t.Errorf("scaffold should have zero rules; got %d", len(rules))
	}
}

func TestEnrollScaffoldIdempotent(t *testing.T) {
	dir := t.TempDir()
	if err := scaffoldRulesFile(dir); err != nil {
		t.Fatal(err)
	}
	// Operator manually adds a rule.
	rulesPath := filepath.Join(dir, "exec-allowlist.rules")
	if err := os.WriteFile(rulesPath, []byte("# AnB exec-allowlist rules\n^/x$\tK\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scaffoldRulesFile(dir); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(rulesPath)
	if !strings.Contains(string(body), "^/x$") {
		t.Errorf("scaffold must not clobber existing file; got %q", body)
	}
}
```

- [ ] **Step 3: Run to verify failure**

```sh
go test ./cmd/alice/ -count=1 -run 'TestEnrollScaffolds'
```

Expected: build error.

- [ ] **Step 4: Implement `scaffoldRulesFile` in `cmd/alice/sensitive.go`**

Replace whatever currently scaffolds `exec-allowlist.json` with:

```go
// scaffoldRulesFile creates exec-allowlist.rules with a header comment
// if absent. Idempotent — never overwrites an existing file.
func scaffoldRulesFile(dir string) error {
	path := filepath.Join(dir, "exec-allowlist.rules")
	if _, err := os.Stat(path); err == nil {
		return nil // already exists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	header := `# AnB exec-allowlist rules.
# One rule per line: <regex>\t<env-csv>\t#<label>.
# Implicit ^...$ anchor.
# Default deny: unmatched invocations are rejected (TTY callers see
# an auto-bless prompt; non-TTY callers hard-deny).
# Run 'alice exec --show-match-string -- cmd args...' to see exactly
# what string your regex needs to match.

`
	return os.WriteFile(path, []byte(header), 0o600)
}
```

Then in `cmdEnroll`, replace the old `exec-allowlist.json` scaffold call with `scaffoldRulesFile(s.Dir)`. The original v2.x scaffold code can be deleted (it wrote `{"allow":[]}\n`).

Add imports if missing: `"errors"`, `"path/filepath"`. (`os` is already there.)

- [ ] **Step 5: Run tests + smoke**

```sh
go test ./cmd/alice/ -count=1
go vet ./cmd/alice/
gofmt -l cmd/alice/
```

Expected: green.

Smoke (no daemon required):

```sh
cd /tmp
rm -rf test-enroll
mkdir test-enroll
go run ./cmd/alice --dir test-enroll enroll --bob localhost:8443 --ca /Users/bbwave03/.anb/bob/ca.crt 2>&1 | tail -20
# (Expected: enroll fails because no Bob to pair, but the rules file should be scaffolded before the failure.)
cat test-enroll/exec-allowlist.rules
rm -rf test-enroll
```

Expected: `exec-allowlist.rules` exists with the header comment.

- [ ] **Step 6: Commit**

```sh
git add cmd/alice/sensitive.go cmd/alice/exec_test.go
git commit -m "$(cat <<'EOF'
feat(alice): enroll scaffolds exec-allowlist.rules (was .json)

New installs get an empty exec-allowlist.rules with a header comment
explaining the format and pointing at --show-match-string. Existing
v2.x installs use Task A7's MigrateLegacy to convert their .json.

scaffoldRulesFile is idempotent — never clobbers an operator's
existing file. Run it from cmdEnroll for the first-install case;
MigrateLegacy handles the upgrade case independently.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A10: `alice exec` stderr surfaces matched rule label

**Files:** No new files. Verify the audit-line update from Task A6 is in place; if Task A6's `→ exec ... rule=[label]` line was already merged in that task, this task is a no-op verification step. Otherwise, apply the update here.

This is bookkeeping — the actual code went into Task A6's exec.go rewrite. Treat A10 as a verification + sanity-test commit.

- [ ] **Step 1: Add a smoke verification test in `cmd/alice/exec_test.go`**

A direct unit test of the stderr audit line is awkward (it's emitted right before `syscall.Exec`, which terminates alice's process). Instead, add a string-format test of the helper that builds the line:

```go
func TestAuditLineWithLabel(t *testing.T) {
	got := formatAuditLine("/bin/echo", []string{"KEY"}, &aclrules.Rule{Label: "test label", LineNo: 42})
	if !strings.Contains(got, "rule=[test label]") {
		t.Errorf("expected label; got %q", got)
	}
}

func TestAuditLineWithoutLabel(t *testing.T) {
	got := formatAuditLine("/bin/echo", []string{"KEY"}, &aclrules.Rule{LineNo: 42})
	if !strings.Contains(got, "rule=line:42") {
		t.Errorf("expected line number; got %q", got)
	}
}
```

- [ ] **Step 2: Extract `formatAuditLine` helper in `cmd/alice/exec.go`**

Replace the inline `fmt.Fprintf(os.Stderr, "→ exec %s with env=%v rule=...")` block from Task A6 with a call to a named helper:

```go
fmt.Fprintln(os.Stderr, formatAuditLine(cmdPath, envNames, matched))
```

And add the helper:

```go
func formatAuditLine(cmdPath string, envNames []string, matched *aclrules.Rule) string {
	if matched.Label != "" {
		return fmt.Sprintf("→ exec %s with env=%v rule=[%s]", cmdPath, envNames, matched.Label)
	}
	return fmt.Sprintf("→ exec %s with env=%v rule=line:%d", cmdPath, envNames, matched.LineNo)
}
```

- [ ] **Step 3: Run tests + commit**

```sh
go test ./cmd/alice/ -count=1
go vet ./cmd/alice/
gofmt -l cmd/alice/

git add cmd/alice/exec.go cmd/alice/exec_test.go
git commit -m "$(cat <<'EOF'
refactor(alice): formatAuditLine helper for exec stderr line

Extracts the matched-rule audit format into a named helper for
direct unit-testability (the inline syscall.Exec call site can't
be tested directly without a subprocess harness).

Behaviour unchanged from Task A6: line shows '→ exec <cmd> with
env=<keys> rule=[label]' or '... rule=line:<lineno>' as fallback
when the rule has no label.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A11: E2E test rewrite

**Files:**
- Modify: `e2e/full_test.go`

The e2e harness had helpers that wrote `exec-allowlist.json` directly. They need to write `exec-allowlist.rules` instead. Plus rewrite the affected v2.x exec tests to use the new file format.

- [ ] **Step 1: Locate the e2e helpers**

```sh
grep -n 'exec-allowlist\|seedAllowlist\|allowlist.json' e2e/full_test.go
```

Note the helper functions and the tests that call them.

- [ ] **Step 2: Update the seed helper**

Replace whatever `seedAllowlist(t, entries...)` style helper exists with:

```go
// seedRules writes one or more rule lines to alice's exec-allowlist.rules.
// Each input is a complete tab-separated line (no trailing newline).
func (h *execHarness) seedRules(t *testing.T, lines ...string) {
	t.Helper()
	path := filepath.Join(h.aliceDir, "exec-allowlist.rules")
	body := "# seeded by test\n" + strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 3: Rewrite the v2.x exec tests**

Identify each test that calls the old seed helper and rewrite the seed call. Example transformation:

```go
// before (v2.x):
h.seedAllowlist(t, allowEntry{
	Cmd:  "/bin/echo",
	Args: []string{"hello"},
	Env:  []string{"TEST"},
})

// after (v3.0):
h.seedRules(t, "^/bin/echo hello$\tTEST")
```

For each existing e2e test that the implementer commented out in Task A6, restore it with the new seed pattern. Tests to restore:
- `TestAliceExecHappyPath`
- `TestAliceExecFailClosedOnMissingKey`
- `TestAliceExecDeniedWhenAllowlistMissing` → rename `TestAliceExecDeniedWhenRulesMissing`
- `TestAliceExecDeniedWhenNoMatch`
- `TestAliceEnrollScaffoldsAllowlist` → rename `TestAliceEnrollScaffoldsRules`, assert `.rules` file exists with header comment

The implementer applies these one at a time, running the test to confirm pass before moving to the next.

- [ ] **Step 4: Add new e2e test for migration round-trip**

```go
func TestAliceMigratesLegacyAllowlist(t *testing.T) {
	h := newExecHarness(t)

	// Seed a v2.x .json file in alice's state dir.
	jsonBody := `{"allow":[{"cmd":"/bin/echo","args":["hi"],"env":["TEST"],"label":"echo hi"}]}`
	if err := os.WriteFile(filepath.Join(h.aliceDir, "exec-allowlist.json"), []byte(jsonBody), 0o600); err != nil {
		t.Fatal(err)
	}

	// Running any alice command should trigger migration.
	cmd := exec.Command(h.aliceBin, "--dir", h.aliceDir, "status")
	cmd.Env = append(os.Environ(), "ANB_BOB_PASSWORD=test")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("status output: %s", out)
		// status may fail (no live bob) but migration runs first
	}

	// Verify .rules exists with the migrated rule.
	body, err := os.ReadFile(filepath.Join(h.aliceDir, "exec-allowlist.rules"))
	if err != nil {
		t.Fatalf("read .rules: %v", err)
	}
	if !strings.Contains(string(body), "^/bin/echo hi$") {
		t.Errorf("expected migrated rule; got %q", body)
	}

	// Verify .json was renamed.
	if _, err := os.Stat(filepath.Join(h.aliceDir, "exec-allowlist.json")); !os.IsNotExist(err) {
		t.Error(".json should be renamed after migration")
	}
	if _, err := os.Stat(filepath.Join(h.aliceDir, "exec-allowlist.json.bak")); err != nil {
		t.Errorf(".json.bak should exist: %v", err)
	}
}
```

- [ ] **Step 5: Run full e2e**

```sh
go test ./e2e/ -count=1 -v
```

Expected: all tests pass. If any fail, fix incrementally — each test corresponds to a specific seed/match scenario in the new model.

- [ ] **Step 6: Commit**

```sh
git add e2e/full_test.go
git commit -m "$(cat <<'EOF'
test(e2e): rewrite exec tests for v3.0 .rules format

- seedRules helper writes tab-separated rule lines directly
- TestAliceExec* renamed/rewritten to seed .rules lines instead of
  building JSON allowEntry structs
- new TestAliceMigratesLegacyAllowlist locks the v2.x -> v3.0
  migration: seed legacy .json, run alice, expect .rules created
  and .json renamed to .json.bak

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A12: README rewrite (allowlist sections)

**Files:**
- Modify: `README.md`

Update every place the README references the v2.x JSON allowlist. Specifically:
- The Daily-use example (still uses `alice exec --env … -- gh api user` — keep, but the surrounding allowlist explanation changes)
- The "Choosing between alice exec, alice shell, alice get" section (v2.6.1 doc) — update the `alice exec` row's "Review gate" cell
- Add a new "Allowlist rules format" section that documents the file format, examples, semantics
- Remove any mention of `exec-allowlist.json`, replace with `exec-allowlist.rules`

- [ ] **Step 1: Identify the sections**

```sh
grep -n 'exec-allowlist\|allowlist.json\|allow_list\|allowEntry' README.md
```

Note every line that needs updating.

- [ ] **Step 2: Write the new "Allowlist rules" section**

Insert after the "Choosing between alice exec, alice shell, and alice get" section (around the same line range as the v2.6.1 docs):

```markdown
## Allowlist rules format

`alice exec` consults `~/.anb/alice/exec-allowlist.rules` to decide
whether to inject vault secrets into a given child invocation.

The file is plain text. Each non-empty, non-comment line is one rule:

    <regex>	<env-csv>	#<label>

Three tab-separated fields. The last two are optional. Implicit
`^…$` anchor on the regex (operator cannot disable).

**How matching works:**

1. alice canonicalises the invocation as `shellescape(cmd) + ' ' +
   shellescape(arg1) + ' ' + …`. Args with safe characters
   (`[A-Za-z0-9_\-./:=@,]`) pass through unchanged; anything else
   is POSIX single-quote wrapped.
2. Rules are scanned top to bottom; first match wins.
3. A match requires both the regex test to pass AND the operator's
   `--env` keys to be a subset of the rule's env-csv.
4. No match → hard-deny (TTY callers see an auto-bless prompt; non-
   TTY callers exit non-zero with the suggested rule line).

**Env-csv column:**

| Value | Meaning |
|---|---|
| empty | `--env` flags not allowed for this rule |
| `KEY1` | operator's `--env` keys ⊆ `{KEY1}` |
| `KEY1,KEY2,KEY3` | operator's `--env` keys ⊆ `{KEY1, KEY2, KEY3}` |
| `*` | any `--env` name allowed (rare; loud warning) |

**Authoring rules:**

`alice exec --show-match-string -- /path/to/cmd args...` prints the
exact canonical string your regex must match. Build your regex from
that string with `^…$`-bounded patterns.

**Example file:**

```text
# encipherr file ops with any path
^/Users/me/\.local/bin/encipherr (encrypt|decrypt) file '?[^']+'?$	ENCIPHERR_KEY	# encipherr file ops

# gh issue/api read-only with token
^/opt/homebrew/bin/gh (api .+|issue view [0-9]+)$	GH_TOKEN	# gh ro

# bob list-keys, no env
^/Users/me/go/bin/bob list-keys$		# bob list-keys

# n9e login with two env vars (either or both allowed)
^/usr/bin/node /Users/me/work/n9e-login\.js$	N9E_USERNAME,N9E_PASSWORD	# n9e login
```

**Auto-bless:**

When `alice exec`'s invocation doesn't match any rule AND both stdin
and stderr are TTYs, alice prompts:

    Append this rule and re-run your command? Type 'yes' to confirm [y/N]:

On `yes`, alice appends a fully-escaped literal regex (so it matches
exactly the originating invocation, no wildcards). Operator widens
by hand-editing later. On anything else, alice exits non-zero
silently — the deny output it already printed once is enough.

**Migration from v2.x:** On first run of v3.0+ alice, an existing
`exec-allowlist.json` is converted to `exec-allowlist.rules`
in place; the original is renamed `exec-allowlist.json.bak`. The
generated rules match exactly the same invocations the JSON entries
did — strictly behaviour-preserving.
```

- [ ] **Step 3: Update the "Choosing between exec, shell, get" table**

In the existing table, the `alice exec` row's "Review gate" cell currently says "Allowlist — strict (cmd, args, env_keys) triple match; first-miss prompts on TTY, hard-denies otherwise". Update to:

```
Allowlist — Go RE2 regex per line in exec-allowlist.rules; first-miss prompts on TTY, hard-denies otherwise
```

- [ ] **Step 4: Update the Daily-use example**

The `alice exec --env 'GH_TOKEN=<agent-vault:gh-pat>' -- /opt/.../gh api user` block currently has a comment block referring to `exec-allowlist.json`. Update the surrounding comment to:

```sh
# (a) Agent / script / non-TTY — gated by exec-allowlist.rules
#     (v3.0+ regex-per-line; first call prompts on TTY, hard-deny otherwise)
alice exec --env 'GH_TOKEN=<agent-vault:gh-pat>' \
  -- /opt/homebrew/bin/gh api user
```

- [ ] **Step 5: Sanity check**

```sh
grep -c '^```' README.md         # MUST be even
grep -c 'exec-allowlist.json' README.md   # MUST be 0 (after this task, excluding migration doc)
grep -c 'exec-allowlist.rules' README.md  # MUST be >= 3 (multiple references)
```

- [ ] **Step 6: Commit**

```sh
git add README.md
git commit -m "$(cat <<'EOF'
docs(readme): rewrite allowlist sections for v3.0 .rules format

- new 'Allowlist rules format' section: file syntax, match semantics,
  env subset, auto-bless flow, migration story
- 'Choosing between exec, shell, get' table: exec review-gate cell
  updated to 'Go RE2 regex per line in exec-allowlist.rules'
- Daily-use example comment block points at exec-allowlist.rules and
  --show-match-string instead of the old strict-equality JSON
- removes every remaining exec-allowlist.json reference (except
  the historical 'migrated from v2.x' note inside the new section)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A13: Operator smoke (USER, real TTY)

**Files:** None — operational verification only.

The implementer cannot drive interactive TTY confirm-and-append flows. Hand off to the user with this checklist:

- [ ] **Step 1: Install fresh binaries**

```sh
cd /Users/bbwave03/claude/anb
go install ./cmd/alice ./cmd/bob
```

- [ ] **Step 2: Verify migration ran on first invocation**

```sh
alice list 2>&1 | head -5
ls -la ~/.anb/alice/exec-allowlist.*
```

Expected: stderr shows the one-line migration note; `exec-allowlist.rules` exists; `exec-allowlist.json.bak` exists (renamed); `exec-allowlist.json` is gone.

- [ ] **Step 3: Inspect the migrated rules**

```sh
cat ~/.anb/alice/exec-allowlist.rules
```

Expected: header comment + one rule per former JSON entry, fully-escaped literal regexes.

- [ ] **Step 4: TTY no-match → auto-bless → re-run flow**

```sh
# Use an invocation that's definitely NOT in your existing allowlist.
alice exec --env 'ENCIPHERR_KEY=<agent-vault:encipherr-key>' -- \
    /Users/bbwave03/.local/bin/encipherr encrypt file /tmp/v3-smoke-test.txt
# Expected:
#   - deny output (cmd/args/env recap)
#   - suggested rule line (^/...encipherr encrypt file /tmp/v3-smoke-test\.txt$ ENCIPHERR_KEY # auto-blessed …)
#   - prompt: "Append this rule and re-run your command? Type 'yes' to confirm [y/N]: "
#   - type: yes
#   - "✓ appended rule to ~/.anb/alice/exec-allowlist.rules — re-run your command to execute it"
#   - exit non-zero

# Re-run the exact same command:
echo "hello v3" > /tmp/v3-smoke-test.txt
alice exec --env 'ENCIPHERR_KEY=<agent-vault:encipherr-key>' -- \
    /Users/bbwave03/.local/bin/encipherr encrypt file /tmp/v3-smoke-test.txt
# Expected: "→ exec /Users/bbwave03/.local/bin/encipherr with env=[ENCIPHERR_KEY] rule=[auto-blessed …]"
ls -la /tmp/v3-smoke-test.txt.enc
```

- [ ] **Step 5: TTY no-match, decline (default-N)**

```sh
alice exec --env 'ENCIPHERR_KEY=<agent-vault:encipherr-key>' -- \
    /Users/bbwave03/.local/bin/encipherr encrypt file /tmp/should-not-append.txt
# At prompt: press Enter (or type anything other than 'yes')
# Expected: silent exit non-zero, no append
grep -c 'should-not-append' ~/.anb/alice/exec-allowlist.rules
# Expected: 0
```

- [ ] **Step 6: Non-TTY hard-deny**

```sh
alice exec --env 'ENCIPHERR_KEY=<agent-vault:encipherr-key>' -- \
    /Users/bbwave03/.local/bin/encipherr encrypt file /tmp/non-tty.txt < /dev/null 2>&1 | tail -10
echo "exit was: $?"
# Expected: deny output, NO prompt, exit 1
```

- [ ] **Step 7: --show-match-string helper**

```sh
alice exec --show-match-string -- /Users/bbwave03/.local/bin/encipherr encrypt file "/tmp/has space.txt"
# Expected: /Users/bbwave03/.local/bin/encipherr encrypt file '/tmp/has space.txt'
```

- [ ] **Step 8: Hand-edit a rule to widen**

```sh
vim ~/.anb/alice/exec-allowlist.rules
# Replace the auto-blessed line for encipherr encrypt file /tmp/v3-smoke-test.txt
# with a wildcard form. E.g.:
#   ^/Users/bbwave03/\.local/bin/encipherr (encrypt|decrypt) file '?[^']+'?$	ENCIPHERR_KEY	# encipherr file ops

# Verify it loads:
alice exec --show-match-string -- /Users/bbwave03/.local/bin/encipherr encrypt file /tmp/different.txt
# Then try encrypting:
echo "test" > /tmp/different.txt
alice exec --env 'ENCIPHERR_KEY=<agent-vault:encipherr-key>' -- \
    /Users/bbwave03/.local/bin/encipherr encrypt file /tmp/different.txt
# Expected: zero prompt — the hand-edited regex matches both invocations
```

- [ ] **Step 9: Multi-env subset rule**

```sh
# Hand-add a rule with two env names:
echo '^/usr/bin/printenv .+$	K1,K2	# printenv test' >> ~/.anb/alice/exec-allowlist.rules

# Create vault keys (assuming alice/bob are working):
echo "v1" | alice set K1 --stdin
echo "v2" | alice set K2 --stdin

# Test subset behavior:
alice exec --env 'K1=<agent-vault:K1>' -- /usr/bin/printenv K1
# Expected: prints "v1"
alice exec --env 'K1=<agent-vault:K1>' --env 'K2=<agent-vault:K2>' -- /usr/bin/printenv K1 K2
# Expected: prints "v1\nv2"
alice exec --env 'K3=<agent-vault:K1>' -- /usr/bin/printenv K3
# Expected: deny (K3 not in subset)

alice rm K1 K2
```

- [ ] **Step 10: Report results**

Confirm to controller: all 9 steps behaved as expected, or report which step failed with the actual vs expected output.

---

### Task A14: Final code review + PR + tag v3.0.0

**Files:** None — release engineering.

- [ ] **Step 1: Pre-PR sanity**

```sh
go test ./... -count=1
go vet ./...
gofmt -l .
git log --oneline main..HEAD
git diff --stat main..HEAD
```

Expected: all green, ~14 commits on branch, diff stat shows ~1100-1300 added lines.

- [ ] **Step 2: Dispatch a fresh branch-wide reviewer subagent**

Mirror the v2.0 and v2.1 release flow:

```
Task tool, general-purpose subagent, model: sonnet
Prompt: "Final code review of feat/allowlist-regex-rules (~14 commits).
Spec: docs/superpowers/specs/2026-05-30-allowlist-rules-regex-design.md
Plan: docs/superpowers/plans/2026-05-30-allowlist-rules-regex.md
Branch HEAD: <SHA>

Focus on:
1. Threat model: any way for an agent to bypass the allowlist
   that the spec didn't anticipate? Specifically: regex-of-everything
   detection robust? shellescape canonicalisation closed under all
   POSIX edge cases? subset env check correct for empty/full?
2. Migration correctness: a v2.x entry with embedded quotes / non-
   ASCII / glob chars in args migrates to a regex that matches the
   exact original invocation?
3. Auto-bless atomicity: append to .rules survives partial writes?
4. Test coverage gaps: any branch in matchAllowlist / cmdExec /
   LoadFile that no test exercises?
5. Doc accuracy: README claims match the implementation exactly?

Report: Critical / Important / Minor with file:line refs. Approve to
merge | Needs fixes | Reject."
```

- [ ] **Step 3: Address findings**

For any Critical or Important: dispatch implementer subagent to fix; re-review until clean.

- [ ] **Step 4: Push + open PR**

```sh
git push -u origin feat/allowlist-regex-rules
gh pr create --base main --head feat/allowlist-regex-rules \
  --title "feat!: regex-based allowlist rules (v3.0.0, BREAKING)" \
  --body "[PR description summarising the architectural change, breaking points, migration story, test plan, version rationale]"
```

PR body should include:
- One-paragraph summary
- BREAKING bullet list (file format change, JSON code removed)
- Migration story (auto on first run, behaviour-preserving, .json.bak)
- Test plan (link to operator smoke checklist)
- Version: v3.0.0 — major bump for the file format change

- [ ] **Step 5: Squash-merge + tag v3.0.0 + GitHub release**

After approval:

```sh
gh pr merge <PR#> --squash --delete-branch \
  --subject "feat!: regex-based allowlist rules (#<PR#>)" \
  --body "<one-paragraph summary repeated>"
git checkout main && git pull --ff-only
git tag -a v3.0.0 <merge-sha> -m "AnB v3.0.0 — regex-based allowlist rules

[full release notes — see spec for source]"
git push origin v3.0.0
gh release create v3.0.0 --title "AnB v3.0.0 — regex-based allowlist rules" \
  --notes "[full release notes]"
```

- [ ] **Step 6: Verify `go install` post-tag**

```sh
go install github.com/kaka-milan-22/AnB/v2/cmd/alice@v3.0.0
go install github.com/kaka-milan-22/AnB/v2/cmd/bob@v3.0.0
alice version
bob version
```

Wait — v3.0.0 should bump the module path to `/v3`? Or keep `/v2` since the v2 path is fine for the Go modules system to accept anything tagged v2.x.x BUT v3.x.x requires `/v3` per Go module rules.

**Decision deferred to release-time:** if Go modules refuses to install v3.0.0 under `/v2/cmd/alice@v3.0.0`, the implementer adds another small commit to rewrite the module path `/v2` → `/v3`, much like v2.1.1 did v1 → /v2. This is an additional ~20-LOC sed across go.mod and 12 internal imports.

If the path issue arises:
```sh
sed -i '' 's|^module github.com/kaka-milan-22/AnB/v2$|module github.com/kaka-milan-22/AnB/v3|' go.mod
grep -rl 'github.com/kaka-milan-22/AnB/v2/internal' --include='*.go' | xargs sed -i '' 's|github.com/kaka-milan-22/AnB/v2/internal|github.com/kaka-milan-22/AnB/v3/internal|g'
# Update README install snippet too
# Re-tag v3.0.0 and push
```

(Alice already in this repo will hit this — v2 to v3 module path bump is real. Flag in spec.)

- [ ] **Step 7: Done**

Update tasks. Tell controller v3.0.0 is shipped.

---

## Self-Review

### Spec coverage

Walking through `docs/superpowers/specs/2026-05-30-allowlist-rules-regex-design.md`:

- **File format** (regex, env-csv, label, comments, blank lines) → Tasks A2, A4, A12
- **Match semantics** (Canonicalize, implicit anchor, first-match-wins, env subset) → Tasks A1, A2, A3, A6
- **Default deny** (missing file, no-match path) → Tasks A4, A6
- **Auto-bless flow** (TTY prompt, literal escape, append) → Tasks A5, A6
- **Migration** (one-shot .json → .rules, .json.bak rename) → Task A7
- **Helper: `--show-match-string`** → Task A8
- **Audit log: `rule` label in stderr** → Tasks A6, A10 (spec section "Audit log" said `bob.log`; downgraded to alice stderr per the spec's own contradiction; flagged in Open risks #7 of spec)
- **Out-of-scope** items not in plan, by design (rate limit, sandbox, path canon, script-host blacklist, etc.)
- **Open risks** mitigations (trivial-match detection, anchor enforcement, ReDoS via Go RE2, shellescape helper, multiple-matches-first-wins, backup story, CLAUDE.md dotfile) → A4 + A8 + readme

Gap: the spec's "Audit log" section claims `bob.log` ALLOW gains a `rule` field; the implementation outline contradicts this by saying "no proto/wire change; rule is a server-side log field, not transmitted". Bob never sees the rule label — that's purely alice-side info. **Resolution:** alice's stderr `→ exec ...` line carries the rule label (Task A10); `bob.log` is unchanged in v3.0. Documented as a deviation from spec in this self-review.

### Placeholder scan

No "TBD", "implement later", "appropriate error handling", or similar. Every task has complete code in every step.

### Type consistency

- `Rule` struct: same fields in every reference (`Regex`, `EnvAllow`, `EnvAny`, `Label`, `LineNo`, `Raw`).
- `LiteralRule(cmd string, args []string, envKeys []string, label string) string` — same signature in A5, A7, A6.
- `Canonicalize(cmd string, args []string) string` — same in A1, A6, A7, A8.
- `MigrateLegacy(dir string) error` — A7.
- `confirmAppend(in io.Reader, out io.Writer) bool` — pre-existing from v2.1, used in A6.
- `errExecDenied` — pre-existing from v2.1, used in A6.

### Known plan deviations from spec

1. **Audit log location**: spec says bob.log; plan ships alice stderr only. Bob doesn't see rule labels (alice-side info).
2. **Module path bump**: spec didn't address Go's `/v3` requirement for v3.0+ semver; plan defers to release-time, will add a ~20-LOC sed commit if `go install ...@v3.0.0` fails under `/v2`.

Both are honest pragmatic deviations; flagged here for reviewer attention.

---

Plan complete. Two execution options:

**1. Subagent-Driven (recommended)** — fresh subagent per task, two-stage review between tasks, fast iteration. Same flow as v2.0 / v2.1 / v2.7 work that came before.

**2. Inline Execution** — execute tasks in this session with checkpoint reviews. Suitable if you want to step through each commit.

Which approach?
