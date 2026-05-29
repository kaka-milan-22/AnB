# `alice exec` default-deny allowlist + v1.4 review followups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship v2.0.0: `alice exec` becomes default-deny via a strict (cmd, args, env_keys) allowlist at `~/.anb/alice/exec-allowlist.json`. Missing file → hard-deny with init hint. Missing match → hard-deny with copy-paste-ready JSON. Bundled: `parseEnvFlag` rejects empty `--env KEY=`; README Trust boundary discloses the same-uid env channel.

**Architecture:** All allowlist logic lives in `cmd/alice/exec.go`. New types `allowEntry` + `allowlist` (JSON-backed); pure functions `loadAllowlist(dir)` and `matchAllowlist(inv, list)` are independently testable. `cmdExec` reorders to do allowlist check BEFORE vault lookup / Bob round-trip — fail-closed without ever opening an mTLS connection if the invocation is not pre-approved. `cmd/alice/sensitive.go`'s `cmdEnroll` scaffolds `{"allow":[]}` to the state dir (idempotent — never clobbers an existing file). e2e tests gain coverage for missing-file, no-match, and match paths.

**Tech Stack:** Go 1.26 (existing). Stdlib only: `encoding/json` (with `DisallowUnknownFields`), `path/filepath` (`IsAbs`), `slices` (for `Clone`/`Sort`/`Equal`). Reuses existing `localvault.Open`, `redact.Restore`, `client.Client.DecryptMany`.

**Spec:** `docs/superpowers/specs/2026-05-29-alice-exec-allowlist-design.md` (committed at 189b0a1). Read this before starting; it has the threat-model rationale, deny-message templates, validation rules, and out-of-scope list.

---

## File Structure

| File | Role | Status |
|---|---|---|
| `cmd/alice/exec.go` | (1) `parseEnvFlag` adds empty-VALUE rejection. (2) New types `allowEntry`, `allowlist`. (3) New `loadAllowlist(dir)`. (4) New `matchAllowlist(inv, list)`. (5) New `formatDenyJSON(inv)` helper. (6) `cmdExec` restructured: allowlist gate BEFORE vault/Bob; deny templates printed to stderr on file-missing or no-match. | Modify |
| `cmd/alice/exec_test.go` | New unit tests covering empty-VALUE rejection, allowlist load (valid / malformed / non-abs / bad-env-name / unknown-field), match (exact equality / arg order / env set equality / no wildcards / empty args+env). | Modify (+~250 LOC) |
| `cmd/alice/sensitive.go` | `cmdEnroll` after `SaveConfig`, scaffolds `exec-allowlist.json` with `{"allow":[]}\n` (mode 0o600) if not present. Idempotent — existing file is left alone. | Modify (~8 LOC) |
| `e2e/full_test.go` | Update `TestAliceExecHappyPath` + `TestAliceExecFailClosedOnMissingKey` to seed an allowlist (they'd otherwise be denied by the new default). Add `TestAliceExecDeniedWhenAllowlistMissing`, `TestAliceExecDeniedWhenNoMatch`, `TestAliceEnrollScaffoldsAllowlist`. | Modify (+~120 LOC) |
| `README.md` | Trust boundary new bullet (env-channel disclosure for alice exec). Features bullet rewrite (default-deny allowlist). Daily-use example shows setup flow. Command-table row description updated. Install snippet v1.4.0 → v2.0.0. | Modify (~40 LOC) |

---

### Task EA1: `parseEnvFlag` rejects empty VALUE

**Files:**
- Modify: `cmd/alice/exec.go`
- Modify: `cmd/alice/exec_test.go`

Spec calls for one new error path: `--env KEY=` (empty after the `=`) is rejected with a clear message. Pre-allowlist hygiene; lands in its own commit because it's independently scoped.

- [ ] **Step 1: Write the failing test**

Append to `cmd/alice/exec_test.go` (after `TestParseEnvFlagAllowsEqualsInValue`, before `sortedKeys` helper):

```go
func TestParseEnvFlagRejectsEmptyValue(t *testing.T) {
	_, _, err := parseEnvFlag([]string{"KEY="})
	if err == nil {
		t.Fatal("expected error for empty VALUE")
	}
	if !strings.Contains(err.Error(), "VALUE may not be empty") {
		t.Fatalf("error message should mention empty VALUE; got: %v", err)
	}
}
```

You will need to add `"strings"` to the test file's imports if it isn't already there.

- [ ] **Step 2: Run test to verify it fails**

```sh
cd /Users/bbwave03/claude/anb
go test ./cmd/alice/ -run TestParseEnvFlagRejectsEmptyValue -v
```

Expected: FAIL — current code accepts `KEY=` and returns no error.

- [ ] **Step 3: Add the empty-VALUE check**

In `cmd/alice/exec.go`, find `parseEnvFlag`. After the existing `envKeyRE.MatchString(name)` check, insert:

```go
		if val == "" {
			return nil, nil, fmt.Errorf("--env %q: VALUE may not be empty (use unset env, or set a literal placeholder like <agent-vault:k>)", e)
		}
```

The full block, for context:

```go
func parseEnvFlag(raw []string) ([]envEntry, map[string]struct{}, error) {
	entries := make([]envEntry, 0, len(raw))
	keys := make(map[string]struct{})
	for _, e := range raw {
		idx := strings.IndexByte(e, '=')
		if idx <= 0 {
			return nil, nil, fmt.Errorf("--env %q: missing '=' or empty KEY (expected KEY=VALUE)", e)
		}
		name, val := e[:idx], e[idx+1:]
		if !envKeyRE.MatchString(name) {
			return nil, nil, fmt.Errorf("--env %q: KEY %q must match %s", e, name, envKeyRE.String())
		}
		if val == "" {
			return nil, nil, fmt.Errorf("--env %q: VALUE may not be empty (use unset env, or set a literal placeholder like <agent-vault:k>)", e)
		}
		entries = append(entries, envEntry{Name: name, Value: val})
		for _, k := range redact.ExtractPlaceholders(val) {
			keys[k] = struct{}{}
		}
	}
	return entries, keys, nil
}
```

- [ ] **Step 4: Run tests and verify they pass**

```sh
go test ./cmd/alice/ -v
go vet ./cmd/alice/
gofmt -l cmd/alice/
```

All tests PASS (existing 10 + new 1 = 11). Vet silent. fmt silent.

- [ ] **Step 5: Commit**

```sh
git add cmd/alice/exec.go cmd/alice/exec_test.go
git commit -m "$(cat <<'EOF'
fix(alice): parseEnvFlag rejects empty --env VALUE

v1.4.0 accepted --env KEY= (empty VALUE) and produced KEY= in the
child env. Not a security issue but ambiguous intent. The v2.0
allowlist makes intent explicit everywhere else; rejecting empty
VALUE here closes the inconsistency.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task EA2: `allowEntry` + `allowlist` types + `loadAllowlist`

**Files:**
- Modify: `cmd/alice/exec.go`
- Modify: `cmd/alice/exec_test.go`

JSON loading + validation. Pure function (file I/O wrapped, but no Bob interaction, no syscall.Exec).

- [ ] **Step 1: Write the failing tests**

Append to `cmd/alice/exec_test.go`:

```go
func TestLoadAllowlistAcceptsValid(t *testing.T) {
	dir := t.TempDir()
	body := `{
		"allow": [
			{"cmd": "/usr/bin/echo", "args": ["hello"], "env": []},
			{"cmd": "/opt/homebrew/bin/gh", "args": ["api", "user"], "env": ["GH_TOKEN"]}
		]
	}`
	if err := os.WriteFile(filepath.Join(dir, "exec-allowlist.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := loadAllowlist(dir)
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}
	if len(list.Allow) != 2 {
		t.Fatalf("want 2 entries, got %d", len(list.Allow))
	}
	if list.Allow[0].Cmd != "/usr/bin/echo" {
		t.Fatalf("entry 0 cmd = %q", list.Allow[0].Cmd)
	}
	if !reflect.DeepEqual(list.Allow[1].Args, []string{"api", "user"}) {
		t.Fatalf("entry 1 args = %v", list.Allow[1].Args)
	}
	if !reflect.DeepEqual(list.Allow[1].Env, []string{"GH_TOKEN"}) {
		t.Fatalf("entry 1 env = %v", list.Allow[1].Env)
	}
}

func TestLoadAllowlistReturnsSpecificErrorWhenMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := loadAllowlist(dir)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !errors.Is(err, errAllowlistMissing) {
		t.Fatalf("want errAllowlistMissing, got %v", err)
	}
}

func TestLoadAllowlistRejectsMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "exec-allowlist.json"), []byte(`{"allow":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadAllowlist(dir)
	if err == nil {
		t.Fatal("expected JSON parse error")
	}
}

func TestLoadAllowlistRejectsUnknownTopLevelField(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "exec-allowlist.json"), []byte(`{"deny":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadAllowlist(dir)
	if err == nil {
		t.Fatal("expected error for unknown top-level field")
	}
}

func TestLoadAllowlistRejectsUnknownEntryField(t *testing.T) {
	dir := t.TempDir()
	body := `{"allow":[{"cmd":"/usr/bin/echo","args":["x"],"env":[],"extra":"oops"}]}`
	if err := os.WriteFile(filepath.Join(dir, "exec-allowlist.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadAllowlist(dir)
	if err == nil {
		t.Fatal("expected error for unknown entry field")
	}
}

func TestLoadAllowlistRejectsNonAbsoluteCmd(t *testing.T) {
	dir := t.TempDir()
	body := `{"allow":[{"cmd":"curl","args":["x"],"env":[]}]}`
	if err := os.WriteFile(filepath.Join(dir, "exec-allowlist.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadAllowlist(dir)
	if err == nil {
		t.Fatal("expected error for non-absolute cmd")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("error should mention 'absolute'; got: %v", err)
	}
}

func TestLoadAllowlistRejectsBadEnvName(t *testing.T) {
	dir := t.TempDir()
	body := `{"allow":[{"cmd":"/usr/bin/echo","args":[],"env":["1bad"]}]}`
	if err := os.WriteFile(filepath.Join(dir, "exec-allowlist.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadAllowlist(dir)
	if err == nil {
		t.Fatal("expected error for bad env name")
	}
}
```

Add imports as needed to the test file: `"errors"`, `"os"`, `"path/filepath"`, `"reflect"`, `"strings"`. Several may already be present from EA1; only add what's missing.

- [ ] **Step 2: Run tests to verify they fail**

```sh
go test ./cmd/alice/ -run 'TestLoadAllowlist' -v
```

Expected: build error `undefined: loadAllowlist`, `undefined: errAllowlistMissing`.

- [ ] **Step 3: Implement types + `loadAllowlist`**

Append to `cmd/alice/exec.go` (after the existing `mergeEnv` function). First, ensure imports include `"encoding/json"`, `"errors"`, `"path/filepath"`. Then add:

```go
// allowEntry is one strict-match entry in the alice exec allowlist.
type allowEntry struct {
	Cmd  string   `json:"cmd"`
	Args []string `json:"args"`
	Env  []string `json:"env"`
}

// allowlist is the on-disk shape of ~/.anb/alice/exec-allowlist.json.
type allowlist struct {
	Allow []allowEntry `json:"allow"`
}

// errAllowlistMissing is returned by loadAllowlist when the file does
// not exist. cmdExec catches this to print the dedicated init hint
// instead of a generic file-not-found error.
var errAllowlistMissing = errors.New("exec-allowlist.json not found")

// loadAllowlist reads and validates ~/.anb/alice/exec-allowlist.json (or
// the equivalent path in the given dir). Returns errAllowlistMissing if
// the file does not exist. Validates each entry: cmd absolute, env
// names POSIX. Strict JSON parsing (DisallowUnknownFields) so typos
// like "cmm:" or "arsg:" fail loud at load time.
func loadAllowlist(dir string) (*allowlist, error) {
	path := filepath.Join(dir, "exec-allowlist.json")
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errAllowlistMissing
		}
		return nil, fmt.Errorf("exec-allowlist.json: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var list allowlist
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("exec-allowlist.json: %w", err)
	}

	for i, e := range list.Allow {
		if !filepath.IsAbs(e.Cmd) {
			return nil, fmt.Errorf("exec-allowlist.json: entry %d cmd %q must be an absolute path", i, e.Cmd)
		}
		for _, n := range e.Env {
			if !envKeyRE.MatchString(n) {
				return nil, fmt.Errorf("exec-allowlist.json: entry %d env name %q must match %s", i, n, envKeyRE.String())
			}
		}
	}
	return &list, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./cmd/alice/ -v
go vet ./cmd/alice/
gofmt -l cmd/alice/
```

All tests pass. Vet silent. fmt silent.

- [ ] **Step 5: Commit**

```sh
git add cmd/alice/exec.go cmd/alice/exec_test.go
git commit -m "$(cat <<'EOF'
feat(alice): allowlist types + loadAllowlist with strict JSON parsing

Loads ~/.anb/alice/exec-allowlist.json with json.Decoder +
DisallowUnknownFields so typos fail loud at load time. Returns a
sentinel errAllowlistMissing for the file-not-found case so cmdExec
can print the dedicated init hint instead of a generic IO error.
Validates each entry: cmd must be absolute path, env names must match
POSIX env-var syntax.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task EA3: `matchAllowlist` strict-equality

**Files:**
- Modify: `cmd/alice/exec.go`
- Modify: `cmd/alice/exec_test.go`

Pure function. Strict byte-for-byte cmd + args; env_keys as a sorted set.

- [ ] **Step 1: Write the failing tests**

Append to `cmd/alice/exec_test.go`:

```go
func TestMatchAllowlistExactEquality(t *testing.T) {
	list := &allowlist{Allow: []allowEntry{
		{Cmd: "/usr/bin/echo", Args: []string{"hello"}, Env: []string{}},
		{Cmd: "/opt/homebrew/bin/gh", Args: []string{"api", "user"}, Env: []string{"GH_TOKEN"}},
	}}
	hit := matchAllowlist("/opt/homebrew/bin/gh", []string{"api", "user"}, []string{"GH_TOKEN"}, list)
	if hit == nil {
		t.Fatal("expected match for gh api user")
	}
	if hit.Cmd != "/opt/homebrew/bin/gh" {
		t.Fatalf("matched wrong entry: %+v", hit)
	}
}

func TestMatchAllowlistRejectsExtraSpaceInArg(t *testing.T) {
	list := &allowlist{Allow: []allowEntry{
		{Cmd: "/usr/bin/echo", Args: []string{"hello"}, Env: []string{}},
	}}
	hit := matchAllowlist("/usr/bin/echo", []string{"hello "}, []string{}, list)
	if hit != nil {
		t.Fatalf("trailing space in arg should not match: %+v", hit)
	}
}

func TestMatchAllowlistRejectsDifferentArgOrder(t *testing.T) {
	list := &allowlist{Allow: []allowEntry{
		{Cmd: "/usr/bin/git", Args: []string{"push", "origin", "main"}, Env: []string{}},
	}}
	hit := matchAllowlist("/usr/bin/git", []string{"push", "main", "origin"}, []string{}, list)
	if hit != nil {
		t.Fatal("swapped arg positions should not match")
	}
}

func TestMatchAllowlistRejectsLengthMismatch(t *testing.T) {
	list := &allowlist{Allow: []allowEntry{
		{Cmd: "/usr/bin/echo", Args: []string{"a", "b"}, Env: []string{}},
	}}
	if matchAllowlist("/usr/bin/echo", []string{"a"}, []string{}, list) != nil {
		t.Fatal("shorter args should not match")
	}
	if matchAllowlist("/usr/bin/echo", []string{"a", "b", "c"}, []string{}, list) != nil {
		t.Fatal("longer args should not match")
	}
}

func TestMatchAllowlistEnvKeysAreSetEqual(t *testing.T) {
	list := &allowlist{Allow: []allowEntry{
		{Cmd: "/usr/bin/echo", Args: []string{}, Env: []string{"A", "B"}},
	}}
	// invocation has same names in different order → matches
	if matchAllowlist("/usr/bin/echo", []string{}, []string{"B", "A"}, list) == nil {
		t.Fatal("env order should not matter")
	}
	// extra env key → no match
	if matchAllowlist("/usr/bin/echo", []string{}, []string{"A", "B", "C"}, list) != nil {
		t.Fatal("extra env key should not match")
	}
	// missing env key → no match
	if matchAllowlist("/usr/bin/echo", []string{}, []string{"A"}, list) != nil {
		t.Fatal("missing env key should not match")
	}
	// renamed env key → no match
	if matchAllowlist("/usr/bin/echo", []string{}, []string{"A", "C"}, list) != nil {
		t.Fatal("renamed env key should not match")
	}
}

func TestMatchAllowlistNoWildcards(t *testing.T) {
	// A literal "*" in an entry should match ONLY a literal "*" in the
	// invocation — not act as a wildcard.
	list := &allowlist{Allow: []allowEntry{
		{Cmd: "/usr/bin/echo", Args: []string{"*"}, Env: []string{}},
	}}
	if matchAllowlist("/usr/bin/echo", []string{"anything"}, []string{}, list) != nil {
		t.Fatal("literal '*' must not act as wildcard")
	}
	if matchAllowlist("/usr/bin/echo", []string{"*"}, []string{}, list) == nil {
		t.Fatal("literal '*' should match literal '*'")
	}
}

func TestMatchAllowlistFirstMatchInFileOrderWins(t *testing.T) {
	list := &allowlist{Allow: []allowEntry{
		{Cmd: "/usr/bin/echo", Args: []string{"x"}, Env: []string{}},
		{Cmd: "/usr/bin/echo", Args: []string{"x"}, Env: []string{}}, // duplicate
	}}
	hit := matchAllowlist("/usr/bin/echo", []string{"x"}, []string{}, list)
	if hit != &list.Allow[0] {
		t.Fatal("first match should win")
	}
}

func TestMatchAllowlistEmptyArgsAndEnv(t *testing.T) {
	list := &allowlist{Allow: []allowEntry{
		{Cmd: "/usr/bin/true", Args: []string{}, Env: []string{}},
	}}
	if matchAllowlist("/usr/bin/true", []string{}, []string{}, list) == nil {
		t.Fatal("empty args+env should match an empty-args+empty-env entry")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```sh
go test ./cmd/alice/ -run 'TestMatchAllowlist' -v
```

Expected: `undefined: matchAllowlist`.

- [ ] **Step 3: Implement matchAllowlist**

Append to `cmd/alice/exec.go`. Make sure `"slices"` is in the import block.

```go
// matchAllowlist returns the first entry in list.Allow whose cmd, args,
// and env-key set exactly match the invocation, or nil if no entry
// matches. Strict byte-for-byte equality on cmd and on each args
// position; envKeys treated as a set (order-independent), exact
// membership equality.
func matchAllowlist(cmd string, args, envKeys []string, list *allowlist) *allowEntry {
	for i, e := range list.Allow {
		if e.Cmd != cmd {
			continue
		}
		if len(e.Args) != len(args) {
			continue
		}
		argsOK := true
		for j := range args {
			if args[j] != e.Args[j] {
				argsOK = false
				break
			}
		}
		if !argsOK {
			continue
		}
		if len(e.Env) != len(envKeys) {
			continue
		}
		a := slices.Clone(envKeys)
		b := slices.Clone(e.Env)
		slices.Sort(a)
		slices.Sort(b)
		if !slices.Equal(a, b) {
			continue
		}
		return &list.Allow[i]
	}
	return nil
}
```

- [ ] **Step 4: Run tests + full pkg**

```sh
go test ./cmd/alice/ -v
go vet ./cmd/alice/
gofmt -l cmd/alice/
```

All pass / clean / silent.

- [ ] **Step 5: Commit**

```sh
git add cmd/alice/exec.go cmd/alice/exec_test.go
git commit -m "$(cat <<'EOF'
feat(alice): matchAllowlist — strict (cmd, args, env_keys) equality

cmd and each args position are byte-for-byte equal. env_keys are
treated as a set (sorted, compared with slices.Equal). No wildcards,
no regex, no prefix matching — '*' / '?' in an entry are literal
characters. First match in file order wins (duplicates do not error).
Empty args / empty env are first-class (match empty invocations).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task EA4: `cmdExec` wires the allowlist (default-deny + deny templates)

**Files:**
- Modify: `cmd/alice/exec.go`

This is the integration commit. cmdExec gains allowlist load + match calls BEFORE any Bob interaction. New helper `formatDenyJSON(cmd, args, envKeys)` produces the copy-paste-ready JSON for the no-match deny template.

- [ ] **Step 1: Add `formatDenyJSON` helper**

Append to `cmd/alice/exec.go`:

```go
// formatDenyJSON produces a 2-space-indented JSON entry the operator
// can paste verbatim into allow[] in exec-allowlist.json. envKeys is
// sorted so identical invocations produce identical suggestions
// (operator can grep their allowlist for the entry without map-order
// flakiness).
func formatDenyJSON(cmd string, args, envKeys []string) string {
	argsJSON, _ := json.Marshal(args)
	envSorted := slices.Clone(envKeys)
	slices.Sort(envSorted)
	envJSON, _ := json.Marshal(envSorted)
	return fmt.Sprintf("  {\n    \"cmd\":  %q,\n    \"args\": %s,\n    \"env\":  %s\n  }",
		cmd, argsJSON, envJSON)
}
```

- [ ] **Step 2: Replace `cmdExec` with the allowlist-gated version**

Locate the existing `cmdExec` in `cmd/alice/exec.go` (you wrote it in v1.4.0). Replace its entire body with the version below. The reorganization moves the allowlist check BEFORE vault / Bob interaction so a denied invocation never opens an mTLS connection.

```go
func cmdExec(args []string) error {
	// Split alice flags from child argv at the first standalone "--".
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		return fmt.Errorf("usage: alice exec [--env KEY=VALUE]... -- <cmd> [args...]")
	}
	aliceArgs := args[:sep]
	childArgv := args[sep+1:]
	if len(childArgv) == 0 {
		return fmt.Errorf("usage: alice exec [--env KEY=VALUE]... -- <cmd> [args...]")
	}

	fs := newFS("exec")
	dir := dirFlag(fs)
	var envs envFlagValue
	fs.Var(&envs, "env", "KEY=VALUE for the child; VALUE may contain <agent-vault:key> placeholders (repeatable)")
	if err := fs.Parse(aliceArgs); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional args before --: %v (place args after --)", fs.Args())
	}

	// Parse --env flags. Empty VALUE is rejected here (see EA1).
	parsed, keySet, err := parseEnvFlag(envs.vals)
	if err != nil {
		return err
	}

	// Allowlist gate (v2.0+). The cmd and args after "--" plus the SET of
	// --env KEY names are matched against ~/.anb/alice/exec-allowlist.json.
	// Default-deny: missing file → init hint; no match → copy-paste-ready
	// JSON in the error.
	cmdName := childArgv[0]
	childArgs := childArgv[1:]
	envNames := make([]string, 0, len(parsed))
	for _, p := range parsed {
		envNames = append(envNames, p.Name)
	}

	if !filepath.IsAbs(cmdName) {
		return fmt.Errorf("alice exec: cmd %q must be an absolute path "+
			"(e.g. /opt/homebrew/bin/curl); see ~/.anb/alice/exec-allowlist.json", cmdName)
	}

	s := localvault.Open(*dir)
	list, err := loadAllowlist(s.Dir)
	if err != nil {
		if errors.Is(err, errAllowlistMissing) {
			return fmt.Errorf("%s/exec-allowlist.json not found.\n\n"+
				"alice exec is default-deny since v2.0.0. To enable any invocation,\n"+
				"the allowlist file must exist (even if empty).\n\n"+
				"Initialize with:\n"+
				"    echo '{\"allow\":[]}' > %s/exec-allowlist.json\n\n"+
				"Then re-run your alice exec command; the error will give you the\n"+
				"exact triple to append.",
				s.Dir, s.Dir)
		}
		return err
	}

	if matchAllowlist(cmdName, childArgs, envNames, list) == nil {
		return fmt.Errorf("alice exec: invocation not in allowlist.\n\n"+
			"  cmd:  %s\n"+
			"  args: %s\n"+
			"  env:  %s\n\n"+
			"To allow exactly this invocation, append to allow[] in\n"+
			"%s/exec-allowlist.json:\n\n"+
			"%s\n\n"+
			"Note: strict byte-for-byte equality on cmd, args (each position),\n"+
			"and env name set. Any change — extra whitespace, different arg\n"+
			"position, extra/missing env name — requires a new entry.\n"+
			"Wildcards are not supported.",
			cmdName,
			mustMarshalJSON(childArgs),
			mustMarshalJSON(sortedKeys(envNames)),
			s.Dir,
			formatDenyJSON(cmdName, childArgs, envNames))
	}

	// Past the gate — proceed with vault lookup, decrypt, restore, exec.
	plaintexts := map[string]string{}
	if len(keySet) > 0 {
		v, lerr := s.Load()
		if lerr != nil {
			return lerr
		}
		keys := make([]string, 0, len(keySet))
		packed := make([]string, 0, len(keySet))
		for k := range keySet {
			e, ok := v.Get(k)
			if !ok {
				return fmt.Errorf("vault has no key %q (--env references it but it's not stored — refusing to exec)", k)
			}
			keys = append(keys, k)
			packed = append(packed, e.Value)
		}
		cl, _, cerr := loadClient(s)
		if cerr != nil {
			return cerr
		}
		pts, derr := cl.DecryptMany(keys, packed)
		if derr != nil {
			return derr
		}
		for i, k := range keys {
			plaintexts[k] = pts[i]
		}
	}

	resolved := make([]string, 0, len(parsed))
	overridden := make(map[string]struct{}, len(parsed))
	for _, e := range parsed {
		rr := redact.Restore(e.Value, func(k string) (string, bool) {
			pt, ok := plaintexts[k]
			return pt, ok
		})
		if len(rr.Missing) > 0 {
			return fmt.Errorf("--env %s: unresolved placeholders %v", e.Name, rr.Missing)
		}
		resolved = append(resolved, e.Name+"="+rr.Content)
		overridden[e.Name] = struct{}{}
	}

	merged := mergeEnv(resolved, overridden, os.Environ())

	cmdPath, err := exec.LookPath(cmdName)
	if err != nil {
		return fmt.Errorf("exec lookup %q: %w", cmdName, err)
	}

	fmt.Fprintf(os.Stderr, "→ exec %s with env=%v\n", cmdPath, envNames)

	return syscall.Exec(cmdPath, childArgv, merged)
}

// mustMarshalJSON returns the JSON encoding of v; intended for inputs
// that cannot fail (string slices). Used inside the deny error to embed
// the "cmd:" "args:" "env:" recap that mirrors what would go into the
// allowlist file.
func mustMarshalJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// sortedKeys returns a fresh sorted copy of a slice. Used by the deny
// error to print env names in a stable order.
func sortedKeys(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}
```

Make sure `"errors"`, `"path/filepath"`, `"slices"` are imported (some were added in EA2/EA3 already; check). The `"localvault"` import already exists.

- [ ] **Step 3: Build + full repo test**

```sh
cd /Users/bbwave03/claude/anb
go build ./...
go vet ./...
gofmt -l .
go test ./...
```

The existing `cmd/alice` unit tests still pass (parseEnvFlag, mergeEnv, loadAllowlist, matchAllowlist). The e2e tests `TestAliceExecHappyPath` and `TestAliceExecFailClosedOnMissingKey` **will start failing** because v2.0 alice exec now needs an allowlist. That's expected — EA6 updates them. Don't fix the e2e in this commit.

Confirm the failing tests are exactly those two (and no others):

```sh
go test ./e2e/ -run 'TestAliceExec' -v 2>&1 | tail -30
```

Expected: `TestAliceExecHappyPath` and `TestAliceExecFailClosedOnMissingKey` FAIL with allowlist-missing or no-match errors. `TestAliceExec...` is the only family that should fail. `TestFullFlow`, `TestLockedBobRefuses`, `TestPairingEnrollEndToEnd` continue to pass.

- [ ] **Step 4: Smoke-build alice + manual sanity (don't touch live state)**

```sh
go install ./cmd/alice
mkdir -p /tmp/exec-allowlist-smoke
ANB_ALICE_DIR=/tmp/exec-allowlist-smoke alice exec --env 'X=<agent-vault:k>' -- /bin/echo hi 2>&1 | head -10
# expected: "not found" deny message + init hint
echo '{"allow":[]}' > /tmp/exec-allowlist-smoke/exec-allowlist.json
ANB_ALICE_DIR=/tmp/exec-allowlist-smoke alice exec --env 'X=<agent-vault:k>' -- /bin/echo hi 2>&1 | head -20
# expected: "not in allowlist" deny + copy-paste JSON
rm -rf /tmp/exec-allowlist-smoke
```

The smoke doesn't need a real Bob — both denials fire before any mTLS connection is attempted.

- [ ] **Step 5: Commit**

```sh
git add cmd/alice/exec.go
git commit -m "$(cat <<'EOF'
feat(alice)!: exec default-deny via allowlist gate (BREAKING)

alice exec now requires ~/.anb/alice/exec-allowlist.json. Missing
file → init-hint deny. No matching (cmd, args, env_keys) entry →
copy-paste-ready JSON in the deny error.

The allowlist gate runs BEFORE vault lookup and Bob round-trip; a
denied invocation never opens an mTLS connection. Past the gate the
flow is unchanged from v1.4.0 (decrypt, restore, mergeEnv, LookPath,
syscall.Exec).

cmd must be absolute (rejected with a separate error before
allowlist load).

E2E tests for TestAliceExec* will fail until EA6 seeds an allowlist
in the test harness — intentional intermediate state on this branch.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task EA5: `alice enroll` scaffolds `exec-allowlist.json`

**Files:**
- Modify: `cmd/alice/sensitive.go`
- Modify: `e2e/full_test.go` (new test `TestAliceEnrollScaffoldsAllowlist`)

`cmdEnroll` writes `{"allow":[]}\n` to `exec-allowlist.json` at mode `0o600` if no such file exists. Idempotent — never clobbers an existing operator-curated allowlist.

- [ ] **Step 1: Read the current cmdEnroll**

```sh
sed -n '440,500p' /Users/bbwave03/claude/anb/cmd/alice/sensitive.go
```

Identify the `SaveConfig` call (last write before the success message).

- [ ] **Step 2: Add the scaffold after `SaveConfig`**

After the existing `if err := s.SaveConfig(...); err != nil { return err }` block in `cmdEnroll`, insert:

```go
	// v2.0+: scaffold an empty exec-allowlist.json so the first alice exec
	// call gets a "not in allowlist" deny (with copy-paste suggestion)
	// rather than a "file not found" error. Idempotent: never clobber an
	// existing allowlist.
	allowPath := filepath.Join(s.Dir, "exec-allowlist.json")
	if _, err := os.Stat(allowPath); errors.Is(err, os.ErrNotExist) {
		if err := s.WriteFile("exec-allowlist.json", []byte(`{"allow":[]}`+"\n"), 0o600); err != nil {
			return err
		}
	}
```

Add `"errors"` to the file's imports if it isn't already present.

- [ ] **Step 3: Write the e2e test for the scaffold**

Append to `e2e/full_test.go`:

```go
func TestAliceEnrollScaffoldsAllowlist(t *testing.T) {
	h := newExecHarness(t)
	defer h.cleanup()

	allow := filepath.Join(h.aliceDir, "exec-allowlist.json")
	st, err := os.Stat(allow)
	if err != nil {
		t.Fatalf("exec-allowlist.json should exist after enroll: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("exec-allowlist.json mode = %o, want 0o600", st.Mode().Perm())
	}
	b, err := os.ReadFile(allow)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != `{"allow":[]}` {
		t.Fatalf("scaffold content = %q, want {\"allow\":[]}", string(b))
	}
}
```

The test assumes `newExecHarness` (added in v1.4.0) already enrolls Alice and writes the cert chain. The scaffold has to happen inside whatever helper enrolls; if `newExecHarness` does its own cert writing without calling `cmdEnroll`, this test won't find the scaffold. Verify by reading the harness:

```sh
grep -n 'newExecHarness\|aliceEnroll\|cmdEnroll' /Users/bbwave03/claude/anb/e2e/full_test.go | head
```

If the harness writes config.json directly (bypassing `cmdEnroll`), you'll need to ALSO call the alice subprocess's enroll command to actually exercise `cmdEnroll`. The clean approach: have the harness ALWAYS scaffold an allowlist explicitly (after enrollment-equivalent setup), so other tests don't depend on the cmdEnroll side effect.

If the harness sets up state without calling cmdEnroll, this test should instead spawn the alice binary's enroll subcommand against a temp dir and check the file. Implementer judgment: pick whichever produces a deterministic test.

- [ ] **Step 4: Run tests**

```sh
go build ./...
go test ./cmd/alice/ -v
go test ./e2e/ -run 'TestAliceEnrollScaffoldsAllowlist' -v
go vet ./...
gofmt -l .
```

The new e2e test should pass. Other tests unchanged.

- [ ] **Step 5: Commit**

```sh
git add cmd/alice/sensitive.go e2e/full_test.go
git commit -m "$(cat <<'EOF'
feat(alice): cmdEnroll scaffolds exec-allowlist.json

After SaveConfig, write {"allow":[]} (0o600) to the state dir if not
present. Idempotent — existing operator-curated allowlists are
preserved on re-enroll.

Mirrors bob init's authz.json.example scaffold (v1.3.1). Newly
enrolled Alices get a "no match" deny (with copy-paste suggestion)
on first alice exec, rather than a "file not found" error.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task EA6: e2e — update existing 2 tests + add 2 deny-path tests

**Files:**
- Modify: `e2e/full_test.go`

`TestAliceExecHappyPath` and `TestAliceExecFailClosedOnMissingKey` were written pre-allowlist and need to seed a matching allowlist entry. Plus two new tests for the deny paths.

- [ ] **Step 1: Read the existing harness to find where allowlist should be seeded**

```sh
grep -n 'newExecHarness\|alicePath\|aliceDir' /Users/bbwave03/claude/anb/e2e/full_test.go | head -20
```

Identify the `execHarness` struct fields (likely `aliceDir`, `alicePath`, etc.) and where the state dir is prepared.

- [ ] **Step 2: Add a helper to seed an allowlist entry**

Add to `e2e/full_test.go` (place it near `newExecHarness` for cohesion):

```go
// seedAllowlist writes ~/.anb/alice/exec-allowlist.json (under h.aliceDir)
// with the given entries. Overwrites any existing file.
func (h *execHarness) seedAllowlist(t *testing.T, entries ...string) {
	t.Helper()
	body := `{"allow":[` + strings.Join(entries, ",") + `]}`
	if err := os.WriteFile(filepath.Join(h.aliceDir, "exec-allowlist.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
```

Each `entries` element is one entry's JSON body, e.g. `{"cmd":"/bin/sh","args":["-c","printf '%s' \"$FOO\" > \"$1\"","_","outfile"],"env":["FOO"]}`. The helper joins them with commas inside `allow[]`.

- [ ] **Step 3: Update `TestAliceExecHappyPath` to seed a matching allowlist**

Find the existing `TestAliceExecHappyPath` test. After `newExecHarness(t)` and the seed-secret call but BEFORE the `exec.Command(h.alicePath, "exec", ...)` invocation, add a `seedAllowlist` call whose entry exactly matches the planned invocation. Adapt to your actual command. For example, if the test's invocation is:

```go
exec.Command(h.alicePath,
    "exec",
    "--env", "FOO=<agent-vault:smoke-secret>",
    "--",
    "/bin/sh", "-c", `printf '%s' "$FOO" > "$1"`, "_", outFile,
)
```

Then the seed call is (note `outFile` is a runtime value; use it as a literal in the entry):

```go
h.seedAllowlist(t, fmt.Sprintf(`{
    "cmd":  "/bin/sh",
    "args": ["-c", "printf '%%s' \"$FOO\" > \"$1\"", "_", %q],
    "env":  ["FOO"]
}`, outFile))
```

The `%%s` is the literal `%s` (escaped from fmt.Sprintf). The `%q` is the JSON-quoted `outFile` path.

Run only this test to confirm it passes:

```sh
go test ./e2e/ -run TestAliceExecHappyPath -v
```

- [ ] **Step 4: Update `TestAliceExecFailClosedOnMissingKey` similarly**

Same pattern — the test's invocation needs a matching allowlist entry so the failure mode being tested (missing vault key) actually fires AFTER allowlist matches, not BEFORE. Adapt to the test's actual command + outFile.

Run:

```sh
go test ./e2e/ -run TestAliceExecFailClosedOnMissingKey -v
```

- [ ] **Step 5: Add `TestAliceExecDeniedWhenAllowlistMissing`**

Append to `e2e/full_test.go`:

```go
func TestAliceExecDeniedWhenAllowlistMissing(t *testing.T) {
	h := newExecHarness(t)
	defer h.cleanup()

	// IMPORTANT: do NOT seed an allowlist. cmdEnroll's scaffold (EA5)
	// writes one by default, so we must remove it.
	_ = os.Remove(filepath.Join(h.aliceDir, "exec-allowlist.json"))

	outFile := filepath.Join(h.tmpDir, "should-not-exist.txt")
	cmd := exec.Command(h.alicePath,
		"exec",
		"--env", "FOO=<agent-vault:any>",
		"--",
		"/bin/sh", "-c", `printf '%s' "$FOO" > "$1"`, "_", outFile,
	)
	cmd.Env = append(os.Environ(), "ANB_ALICE_DIR="+h.aliceDir)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected alice exec to fail without an allowlist file")
	}
	if !strings.Contains(stderr.String(), "exec-allowlist.json not found") {
		t.Logf("stderr was: %s", stderr.String())
		t.Fatal("expected 'exec-allowlist.json not found' in stderr")
	}
	if _, err := os.Stat(outFile); !os.IsNotExist(err) {
		t.Fatal("child should NOT have run; outFile exists")
	}
}
```

- [ ] **Step 6: Add `TestAliceExecDeniedWhenNoMatch`**

Append to `e2e/full_test.go`:

```go
func TestAliceExecDeniedWhenNoMatch(t *testing.T) {
	h := newExecHarness(t)
	defer h.cleanup()

	// Seed an allowlist with an entry that does NOT match what we'll
	// invoke (different cmd / args / env).
	h.seedAllowlist(t, `{
		"cmd":  "/usr/bin/true",
		"args": [],
		"env":  []
	}`)

	outFile := filepath.Join(h.tmpDir, "should-not-exist.txt")
	cmd := exec.Command(h.alicePath,
		"exec",
		"--env", "FOO=<agent-vault:any>",
		"--",
		"/bin/sh", "-c", `printf '%s' "$FOO" > "$1"`, "_", outFile,
	)
	cmd.Env = append(os.Environ(), "ANB_ALICE_DIR="+h.aliceDir)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected alice exec to fail with no-match")
	}
	out := stderr.String()
	if !strings.Contains(out, "invocation not in allowlist") {
		t.Logf("stderr was: %s", out)
		t.Fatal("expected 'invocation not in allowlist' in stderr")
	}
	// Confirm the copy-paste JSON snippet is included.
	if !strings.Contains(out, `"cmd":  "/bin/sh"`) {
		t.Logf("stderr was: %s", out)
		t.Fatal("expected suggested JSON entry with /bin/sh to be in stderr")
	}
	if _, err := os.Stat(outFile); !os.IsNotExist(err) {
		t.Fatal("child should NOT have run; outFile exists")
	}
}
```

- [ ] **Step 7: Run the full e2e suite**

```sh
go test ./e2e/ -v 2>&1 | tail -30
go test ./... 2>&1 | tail -10
go vet ./...
gofmt -l .
```

All tests pass. Vet/fmt silent.

- [ ] **Step 8: Commit**

```sh
git add e2e/full_test.go
git commit -m "$(cat <<'EOF'
test(e2e): allowlist gate — update v1.4 tests + cover deny paths

- TestAliceExecHappyPath and TestAliceExecFailClosedOnMissingKey now
  seed an allowlist matching their invocation so they reach the
  vault-lookup phase (previously they would fail at the new gate).
- TestAliceExecDeniedWhenAllowlistMissing: file removed → alice exec
  fails with "exec-allowlist.json not found" + init hint; child does
  not run.
- TestAliceExecDeniedWhenNoMatch: allowlist exists but no entry
  matches → alice exec fails with "invocation not in allowlist" + a
  copy-paste JSON snippet matching the invocation; child does not
  run.

seedAllowlist helper on execHarness writes the file with given
entries (overwriting any pre-existing scaffold).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task EA7: README — Trust boundary + Features + table + Daily-use + v2.0.0

**Files:**
- Modify: `README.md`

Five doc edits + install snippet bump. Source content is in the spec (`docs/superpowers/specs/2026-05-29-alice-exec-allowlist-design.md`, "README Trust boundary update" section).

- [ ] **Step 1: Read the current README to find each landmark**

```sh
cd /Users/bbwave03/claude/anb
grep -n 'Agent-safe exec\|## Trust boundary\|Daily use\|alice exec \[--env\|v1\.4\.0' README.md
```

Identify exact line numbers for: Features bullet, Trust boundary bullets, Daily-use example, command-table row, install snippet (5 v1.4.0 references).

- [ ] **Step 2: Rewrite the Features "Agent-safe exec" bullet**

Find the current bullet (introduced in v1.4.0). Replace it with:

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

- [ ] **Step 3: Add the env-channel bullet to "Trust boundary (read this)"**

Append AFTER the existing "Enrollment pairing is a human OOB check" bullet (last in the Trust boundary list):

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

- [ ] **Step 4: Update the Daily-use `alice exec` example**

Find the existing alice exec example (uses `<agent-vault:gh-pat>` and curl). Replace it with the setup-flow version:

```sh
# v2.0.0+: alice exec is default-deny via ~/.anb/alice/exec-allowlist.json.
# `alice enroll` scaffolds an empty {"allow":[]} for you. To allow a new
# invocation: run it once, copy the suggested JSON from the deny error
# into allow[], re-run. Then subsequent identical calls go through
# without further prompting.
#
# NOTE: single-quote --env values so the shell doesn't expand `<` / `>`.
alice exec --env 'GH_TOKEN=<agent-vault:gh-pat>' \
  -- /opt/homebrew/bin/gh api user
```

- [ ] **Step 5: Update the alice safe command-table row for `alice exec`**

Find the row (added in v1.4.0). Replace its description:

```markdown
| `alice exec [--env KEY=V]... -- <cmd> [args...]` | Match against `~/.anb/alice/exec-allowlist.json`; on hit, resolve placeholders and `syscall.Exec` the child. Default-deny — see Authorization / allowlist sections for the JSON schema. |
```

- [ ] **Step 6: Bump install snippet v1.4.0 → v2.0.0**

```sh
grep -c 'v1\.4\.0' README.md     # confirm count (should be 5)
sed -i '' 's/v1\.4\.0/v2.0.0/g' README.md
grep -c 'v1\.4\.0' README.md     # MUST be 0
grep -c 'v2\.0\.0' README.md     # MUST be 5
```

(On Linux: drop the `''`.)

- [ ] **Step 7: Sanity-check Markdown integrity**

```sh
grep -c '^```' README.md       # MUST be even (code fences balanced)
grep -E '^\|' README.md | head -40   # command-table rows present, pipe counts consistent per table
```

- [ ] **Step 8: Commit**

```sh
git add README.md
git commit -m "$(cat <<'EOF'
docs(readme): alice exec default-deny allowlist + Trust boundary + v2.0.0

- Features bullet rewritten: "Agent-safe exec (operator-allowlisted)"
  with the default-deny + (cmd, args, env_keys) triple semantics.
- Trust boundary adds an env-channel disclosure: same-uid processes
  can read alice exec's child env via /proc/<pid>/environ (Linux) or
  ps eww (macOS).
- Daily-use example shows the setup flow: enroll scaffolds the empty
  allowlist; first invocation deny prints the JSON to paste.
- Command-table row points at the allowlist file.
- Install snippet bumped to v2.0.0 (5 occurrences).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task EA8: Operator smoke (USER, real TTY)

**Files:** None — operational verification.

Subagent cannot drive. Owner runs in iTerm/Warp:

- [ ] **Step 1: Install fresh binaries**

```sh
cd /Users/bbwave03/claude/anb
go install ./cmd/bob ./cmd/alice
```

- [ ] **Step 2: Migrate your local allowlist setup**

You're an already-enrolled operator, so `alice enroll`'s scaffold doesn't fire for you. Create the file by hand:

```sh
ls -la ~/.anb/alice/exec-allowlist.json 2>&1   # likely "No such file"
echo '{"allow":[]}' > ~/.anb/alice/exec-allowlist.json
chmod 0600 ~/.anb/alice/exec-allowlist.json
```

- [ ] **Step 3: File-missing path (intentionally trigger)**

```sh
mv ~/.anb/alice/exec-allowlist.json /tmp/allowlist-backup.json
alice exec --env 'X=<agent-vault:n9euser>' -- /bin/echo hi 2>&1 | head -10
# expected: "exec-allowlist.json not found" + init hint + exit non-zero
mv /tmp/allowlist-backup.json ~/.anb/alice/exec-allowlist.json
```

- [ ] **Step 4: No-match deny path**

```sh
alice exec --env 'TEST=<agent-vault:n9euser>' -- /bin/sh -c 'echo "got: $TEST"' 2>&1 | head -25
# expected: "invocation not in allowlist" + a JSON snippet you can paste
```

- [ ] **Step 5: Append the suggested entry, re-run**

Edit `~/.anb/alice/exec-allowlist.json` and paste the suggested entry into `allow[]`. Re-run:

```sh
alice exec --env 'TEST=<agent-vault:n9euser>' -- /bin/sh -c 'echo "got: $TEST"'
# expected: → exec /bin/sh with env=[TEST] (stderr)
#           got: <plaintext> (stdout)
```

- [ ] **Step 6: Strict equality verification (any byte change → deny)**

Try the same invocation with a trailing space anywhere in the `-c` arg or a different env name:

```sh
alice exec --env 'TEST=<agent-vault:n9euser>' -- /bin/sh -c 'echo "got: $TEST" ' 2>&1 | head -10
# expected: deny (the trailing space inside the -c arg changes args[1])
alice exec --env 'OTHER=<agent-vault:n9euser>' -- /bin/sh -c 'echo "got: $OTHER"' 2>&1 | head -10
# expected: deny (different env name AND different -c arg → no match)
```

- [ ] **Step 7: parseEnvFlag empty-VALUE rejection**

```sh
alice exec --env 'KEY=' -- /bin/echo hi 2>&1 | head -3
# expected: "--env "KEY=": VALUE may not be empty ..." → exit non-zero
```

- [ ] **Step 8: Daemon reachability sanity**

```sh
alice status
# expected: Bob status: unlocked
```

- [ ] **Step 9: No commit — operational only**

If anything misbehaves, fix the relevant prior task and amend its commit. Otherwise proceed to EA9.

---

### Task EA9: Final review + PR + v2.0.0 release

**Files:** None — release engineering.

- [ ] **Step 1: Full test suite + vet + fmt + branch sanity**

```sh
cd /Users/bbwave03/claude/anb
go test ./...
go vet ./...
gofmt -l .
git log --oneline main..HEAD              # ~7 commits (EA1-EA7)
git diff --stat main..HEAD                # confirm files touched match the file-structure table
```

All green / clean / silent.

- [ ] **Step 2: Dispatch the final branch-wide code reviewer**

Use the same pattern as previous PRs in this branch series: dispatch a `general-purpose` subagent with model `sonnet`, hand it the spec at `docs/superpowers/specs/2026-05-29-alice-exec-allowlist-design.md` and the branch HEAD, ask for spec-coverage + quality findings (Critical / Important / Minor).

- [ ] **Step 3: Push branch + open PR**

```sh
git push -u origin feat/exec-allowlist
gh pr create --base main --head feat/exec-allowlist --title "feat!: alice exec default-deny allowlist + v1.4 review followups (BREAKING)" --body "$(cat <<'EOF'
## Summary

v1.4.0's `alice exec` defaulted to allowing any invocation operator/agent constructed. A follow-up security review surfaced that absolute-path mitigation alone leaves the agent-binary-choice attack surface wide open: the system has hundreds of network-capable binaries (`curl` / `wget` / `nc` / `ssh` / `dig +short evil/$T` / `python -c 'urllib...'`), and operator review of "is this binary safe?" requires knowledge they don't have for every system tool.

v2.0 fixes it via **default-deny + strict (cmd, args, env_keys) triple allowlist**. Operator pre-blesses each known-good invocation in `~/.anb/alice/exec-allowlist.json`. Matched invocations run `syscall.Exec` without TTY prompting (restoring v1.4's agent-autonomous property for blessed patterns). Unmatched invocations hard-deny with a **copy-paste-ready JSON snippet** the operator appends to `allow[]`; subsequent identical calls then pass.

Plus two small followups bundled in the same release:
- `parseEnvFlag` rejects empty `--env KEY=` (pre-allowlist hygiene).
- README Trust boundary discloses the same-uid env channel (`/proc/<pid>/environ`, `ps eww`).

Spec: `docs/superpowers/specs/2026-05-29-alice-exec-allowlist-design.md` (committed at 189b0a1).

## Breaking changes

- `alice exec` requires `~/.anb/alice/exec-allowlist.json` to exist. `alice enroll` scaffolds an empty `{"allow":[]}` for new installs. Existing operators upgrade with one line: `echo '{"allow":[]}' > ~/.anb/alice/exec-allowlist.json`.
- Per-invocation: cmd must be absolute, AND `(cmd, args, env_keys)` triple must match an entry in `allow[]`. Strict byte-for-byte equality; no wildcards.
- `--env KEY=` (empty VALUE) is rejected.

No wire protocol changes. No `internal/proto` / `internal/server` / `internal/client` / `internal/authz` modifications. `bob` daemon is unchanged.

## Branch sequence

```
<EA7 sha> docs(readme): alice exec default-deny allowlist + Trust boundary + v2.0.0
<EA6 sha> test(e2e): allowlist gate — update v1.4 tests + cover deny paths
<EA5 sha> feat(alice): cmdEnroll scaffolds exec-allowlist.json
<EA4 sha> feat(alice)!: exec default-deny via allowlist gate (BREAKING)
<EA3 sha> feat(alice): matchAllowlist — strict (cmd, args, env_keys) equality
<EA2 sha> feat(alice): allowlist types + loadAllowlist with strict JSON parsing
<EA1 sha> fix(alice): parseEnvFlag rejects empty --env VALUE
```

## Test Plan

- [x] `go test ./...` green (new unit tests for empty-VALUE rejection, allowlist load/validate, matchAllowlist strict equality, no-wildcards, env set equality; updated + new e2e tests for missing-file deny, no-match deny, scaffold-on-enroll)
- [x] `go vet ./...` clean
- [x] `gofmt -l .` silent
- [x] Operator smoke against live Bob daemon: file-missing deny, no-match deny with copy-paste JSON, append-and-re-run flow, strict equality (whitespace + env rename both deny), parseEnvFlag empty-VALUE rejection, `alice status` confirms mTLS

## Version

**v2.0.0** — breaking (allowlist file required; alice exec callers must migrate). No API or wire changes.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 4: Squash-merge after PR approval**

```sh
gh pr merge <PR#> --squash --delete-branch --subject "feat!: alice exec default-deny allowlist + v1.4 review followups (#<PR#>)" --body "<one-paragraph summary>"
git checkout main && git pull --ff-only
```

- [ ] **Step 5: Tag v2.0.0 and create GH release**

```sh
git tag -a v2.0.0 <merge-sha> -m "AnB v2.0.0 — alice exec default-deny allowlist"
git push origin v2.0.0
gh release create v2.0.0 --title "AnB v2.0.0 — alice exec default-deny allowlist" --notes "<full release notes covering: breaking change + migration + new allowlist semantics + strict equality rationale + bundled followups>"
```

---

## Self-Review

### Spec coverage check

- ✅ Allowlist file location + permissions (`~/.anb/alice/exec-allowlist.json` at 0o600) — Task EA2, EA5
- ✅ JSON format with `allow[]` of `{cmd, args, env}` — Task EA2
- ✅ Strict byte-for-byte cmd, args; env_keys as sorted-set equality — Task EA3
- ✅ Wildcards explicitly NOT supported — Task EA3 (TestMatchAllowlistNoWildcards)
- ✅ DisallowUnknownFields — Task EA2 (loadAllowlist + TestLoadAllowlistRejectsUnknownTopLevelField / UnknownEntryField)
- ✅ Missing-file → init-hint deny — Task EA4 (errAllowlistMissing branch)
- ✅ No-match → copy-paste-JSON deny — Task EA4 (formatDenyJSON + matchAllowlist nil branch)
- ✅ First-match-wins for duplicates — Task EA3 (TestMatchAllowlistFirstMatchInFileOrderWins)
- ✅ Empty args/env handled — Task EA3 (TestMatchAllowlistEmptyArgsAndEnv)
- ✅ Validation: cmd absolute, env POSIX — Task EA2 (loadAllowlist validation block + TestLoadAllowlistRejectsNonAbsoluteCmd / BadEnvName)
- ✅ Invocation cmd absolute (separate from entry validation) — Task EA4 (filepath.IsAbs check before loadAllowlist)
- ✅ Allowlist gate runs BEFORE vault lookup / Bob round-trip — Task EA4 (placement in cmdExec)
- ✅ TTY NOT required for matched invocations — Task EA4 (no requireTTY call)
- ✅ `alice enroll` scaffolds `{"allow":[]}` (0o600), idempotent — Task EA5
- ✅ parseEnvFlag rejects empty VALUE — Task EA1
- ✅ README Trust boundary env-channel disclosure — Task EA7 (Step 3)
- ✅ Features bullet rewrite — Task EA7 (Step 2)
- ✅ Daily-use example shows setup flow — Task EA7 (Step 4)
- ✅ Command-table row update — Task EA7 (Step 5)
- ✅ Install snippet v2.0.0 — Task EA7 (Step 6)
- ✅ Verification matrix from spec — Tasks EA8 (operator smoke) + EA1-EA6 (automated tests)

### Placeholder scan

No `TBD`, `TODO`, `implement later`, `add appropriate error handling`, or `similar to Task N` patterns. Every code-changing step shows complete code. Every command has expected output described.

### Type / signature consistency

- `allowEntry struct { Cmd, Args, Env }` — defined EA2, used EA3, EA4
- `allowlist struct { Allow []allowEntry }` — defined EA2, used EA3, EA4
- `errAllowlistMissing` — defined EA2, used EA4
- `loadAllowlist(dir string) (*allowlist, error)` — defined EA2, called EA4
- `matchAllowlist(cmd string, args, envKeys []string, list *allowlist) *allowEntry` — defined EA3, called EA4
- `formatDenyJSON(cmd string, args, envKeys []string) string` — defined EA4, used EA4
- `mustMarshalJSON(v any) string` and `sortedKeys(s []string) []string` — defined EA4, used in cmdExec's deny message

All consistent across tasks.

### One ambiguity I'm flagging

In Task EA5 Step 3, the e2e test depends on whether the existing `newExecHarness` already calls `cmdEnroll` (so the scaffold fires) or sets up state directly (so it doesn't). I gave the implementer judgment guidance to either fix the harness or spawn the alice binary's `enroll` subcommand. This is the one design decision I deferred to the implementer because it depends on harness internals that may have shifted since the AE5 commit.

If the harness currently bypasses `cmdEnroll`, the simplest fix is: have `newExecHarness` call `cmdEnroll` via subprocess (just like the other alice subcommands the e2e already uses). That's ~3 lines added to the harness setup. Alternatively, the test can spawn `alice enroll` against a fresh temp dir not shared with the harness — also fine, slightly more isolated.
