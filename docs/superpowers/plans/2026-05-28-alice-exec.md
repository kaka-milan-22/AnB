# `alice exec` + `alice write` stderr Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `alice exec --env KEY=<agent-vault:k> -- <cmd> <args>` as the agent-safe execution path that resolves vault placeholders into the child's env and `syscall.Exec`s the child — alice's process disappears, plaintext never reaches alice's own stdout. Plus a band-aid: `alice write` confirmation lines route to stderr with a new `--quiet` flag.

**Architecture:** New `cmd/alice/exec.go` housing `cmdExec` plus two pure helpers (`parseEnvFlag`, `mergeEnv`) that are unit-testable without Bob. `cmd/alice/safe.go`'s `cmdWrite` gets a one-touch refactor moving status `fmt.Println` calls to `fmt.Fprintln(os.Stderr, ...)` and adding a `--quiet` boolean. Integration is verified end-to-end against a real Bob in `e2e/full_test.go::TestAliceExec`.

**Tech Stack:** Go 1.26 (existing). Stdlib only: `flag`, `os/exec` (LookPath), `syscall` (Exec), `regexp`, `strings`. Reuses `internal/redact.Restore`, `internal/localvault`, `internal/client.Client.DecryptMany`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-05-28-alice-exec-design.md` (committed at e2f8205) — read this before starting; it has the security model, error model, env-dedup semantics, and the exhaustive verification checklist.

---

## File Structure

| File | Role | Status |
|---|---|---|
| `cmd/alice/exec.go` | `cmdExec`, the `envFlag` repeating-flag type, `parseEnvFlag`, `mergeEnv`. New file, isolates the ~120 LOC of exec logic from safe.go which is already 271 lines. | Create |
| `cmd/alice/exec_test.go` | Pure-function unit tests for `parseEnvFlag` and `mergeEnv`. No Bob, no network. | Create |
| `cmd/alice/main.go` | One-line wiring: add `"exec": cmdExec` to `cmds`; add one row to the usage table; one line in the package doc comment. | Modify (~5 lines) |
| `cmd/alice/safe.go` | `cmdWrite`: route status `fmt.Println` to stderr; add `--quiet` boolean flag. | Modify (~5 lines net) |
| `e2e/full_test.go` | `TestAliceExec` — real CA + Bob daemon, set a secret, exec a child that writes env to a file, assert plaintext arrived. Plus a fail-closed test (`<agent-vault:nonexistent>` → alice non-zero, child never runs). | Modify (+~80 lines) |
| `README.md` | Features bullet, Daily-use example, command-table row, install snippet bumped to v1.4.0. | Modify (~20 lines) |

---

### Task AE1: `parseEnvFlag` — pure parser

**Files:**
- Create: `cmd/alice/exec.go`
- Create: `cmd/alice/exec_test.go`

`parseEnvFlag` takes the raw `--env` argument list (already split by Go's flag package), validates each entry, and returns parsed entries + the set of vault keys referenced. Pure function, no I/O. Drives every subsequent error-model decision for `cmdExec`.

- [ ] **Step 1: Write the failing tests**

Create `/Users/bbwave03/claude/anb/cmd/alice/exec_test.go`:

```go
package main

import (
	"reflect"
	"sort"
	"testing"
)

func TestParseEnvFlagAcceptsValidEntries(t *testing.T) {
	entries, keys, err := parseEnvFlag([]string{
		"API_KEY=<agent-vault:openai-key>",
		"DSN=postgres://app:<agent-vault:db-pw>@host/prod",
		"LOG_LEVEL=debug",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantEntries := []envEntry{
		{Name: "API_KEY", Value: "<agent-vault:openai-key>"},
		{Name: "DSN", Value: "postgres://app:<agent-vault:db-pw>@host/prod"},
		{Name: "LOG_LEVEL", Value: "debug"},
	}
	if !reflect.DeepEqual(entries, wantEntries) {
		t.Fatalf("entries: got %v want %v", entries, wantEntries)
	}
	gotKeys := sortedKeys(keys)
	wantKeys := []string{"db-pw", "openai-key"}
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Fatalf("keys: got %v want %v", gotKeys, wantKeys)
	}
}

func TestParseEnvFlagRejectsMissingEquals(t *testing.T) {
	if _, _, err := parseEnvFlag([]string{"NOEQUALS"}); err == nil {
		t.Fatal("expected error for missing '='")
	}
}

func TestParseEnvFlagRejectsEmptyName(t *testing.T) {
	if _, _, err := parseEnvFlag([]string{"=value"}); err == nil {
		t.Fatal("expected error for empty KEY")
	}
}

func TestParseEnvFlagRejectsInvalidName(t *testing.T) {
	for _, bad := range []string{"1KEY=v", "K-Y=v", "K.Y=v", " KEY=v"} {
		if _, _, err := parseEnvFlag([]string{bad}); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestParseEnvFlagAcceptsNoPlaceholders(t *testing.T) {
	entries, keys, err := parseEnvFlag([]string{"PATH=/usr/bin", "LANG=en_US.UTF-8"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries len = %d want 2", len(entries))
	}
	if len(keys) != 0 {
		t.Fatalf("keys should be empty, got %v", keys)
	}
}

func TestParseEnvFlagDedupesReferencedKeys(t *testing.T) {
	_, keys, err := parseEnvFlag([]string{
		"A=<agent-vault:shared>",
		"B=<agent-vault:shared>",
		"C=prefix<agent-vault:shared>suffix",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("want 1 unique key, got %v", keys)
	}
	if _, ok := keys["shared"]; !ok {
		t.Fatalf("missing key 'shared': %v", keys)
	}
}

func TestParseEnvFlagAllowsEqualsInValue(t *testing.T) {
	entries, _, err := parseEnvFlag([]string{"OPTS=--foo=bar --baz=qux"})
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].Name != "OPTS" || entries[0].Value != "--foo=bar --baz=qux" {
		t.Fatalf("split at first '=' broken: %+v", entries[0])
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
```

- [ ] **Step 2: Run test to verify it fails**

```sh
cd /Users/bbwave03/claude/anb
go test ./cmd/alice/ -run TestParseEnvFlag -v
```

Expected: build failure with `undefined: parseEnvFlag` and `undefined: envEntry`.

- [ ] **Step 3: Write minimal implementation**

Create `/Users/bbwave03/claude/anb/cmd/alice/exec.go`:

```go
package main

import (
	"fmt"
	"regexp"
	"strings"
)

// envEntry is one parsed --env flag: a POSIX env name and its (possibly
// placeholder-containing) value.
type envEntry struct {
	Name  string
	Value string
}

// placeholderRE matches <agent-vault:KEY> exactly like internal/redact's
// private regex. Re-declared here so cmd/alice can extract referenced keys
// without exporting the redact regex.
var placeholderRE = regexp.MustCompile(`<agent-vault:([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)>`)

// envNameRE pins POSIX env name syntax: leading letter or underscore,
// then letters / digits / underscores.
var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// parseEnvFlag validates each raw --env entry (KEY=VALUE form, POSIX KEY)
// and collects the set of vault keys referenced via <agent-vault:k>
// placeholders in any VALUE. Pure function — no I/O, no decryption.
func parseEnvFlag(raw []string) ([]envEntry, map[string]struct{}, error) {
	entries := make([]envEntry, 0, len(raw))
	keys := make(map[string]struct{})
	for _, e := range raw {
		idx := strings.IndexByte(e, '=')
		if idx <= 0 {
			return nil, nil, fmt.Errorf("--env %q: missing '=' or empty KEY (expected KEY=VALUE)", e)
		}
		name, val := e[:idx], e[idx+1:]
		if !envNameRE.MatchString(name) {
			return nil, nil, fmt.Errorf("--env %q: KEY %q must match %s", e, name, envNameRE)
		}
		entries = append(entries, envEntry{Name: name, Value: val})
		for _, m := range placeholderRE.FindAllStringSubmatch(val, -1) {
			keys[m[1]] = struct{}{}
		}
	}
	return entries, keys, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

```sh
go test ./cmd/alice/ -run TestParseEnvFlag -v
```

Expected: PASS — all 7 test functions green.

Also:

```sh
go vet ./cmd/alice/
gofmt -l cmd/alice/
```

Both silent.

- [ ] **Step 5: Commit**

```sh
git add cmd/alice/exec.go cmd/alice/exec_test.go
git commit -m "$(cat <<'EOF'
feat(alice): parseEnvFlag — validate --env KEY=VALUE + collect placeholders

Pure parser for the upcoming alice exec subcommand. Validates POSIX env
names, splits on the first '=' (so values may contain '='), and scans
each value with the redact regex to surface the set of vault keys that
will need batch-decryption from Bob.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task AE2: `mergeEnv` — explicit dedup

**Files:**
- Modify: `cmd/alice/exec.go`
- Modify: `cmd/alice/exec_test.go`

Per spec, env merging uses explicit dedup (resolved entries always win, parent passthrough drops same-name entries) instead of relying on execve's implementation-defined duplicate-key behavior.

- [ ] **Step 1: Write the failing tests**

Append to `cmd/alice/exec_test.go`:

```go
func TestMergeEnvResolvedWinsOverParent(t *testing.T) {
	parent := []string{"PATH=/usr/bin", "API_KEY=oldvalue", "HOME=/h"}
	resolved := []string{"API_KEY=newvalue", "EXTRA=x"}
	overridden := map[string]struct{}{"API_KEY": {}, "EXTRA": {}}

	got := mergeEnv(resolved, overridden, parent)

	wantHas := []string{"API_KEY=newvalue", "PATH=/usr/bin", "HOME=/h", "EXTRA=x"}
	for _, w := range wantHas {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("merged env missing %q; got=%v", w, got)
		}
	}
	for _, g := range got {
		if g == "API_KEY=oldvalue" {
			t.Fatalf("parent's API_KEY=oldvalue should have been dropped; got=%v", got)
		}
	}
	if len(got) != 4 {
		t.Fatalf("merged len = %d want 4 (no dups); got=%v", len(got), got)
	}
}

func TestMergeEnvSkipsMalformedParentEntries(t *testing.T) {
	parent := []string{"OKAY=1", "NOEQ", "=valueonly", "ALSO=fine"}
	resolved := []string{}
	overridden := map[string]struct{}{}
	got := mergeEnv(resolved, overridden, parent)
	// Malformed entries (no '=' or empty name) are passed through unchanged —
	// alice does not curate the parent env beyond dedup against --env names.
	// We just need to be sure they don't crash mergeEnv.
	if len(got) != 4 {
		t.Fatalf("merged len = %d want 4 (pass-through, no crash); got=%v", len(got), got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```sh
go test ./cmd/alice/ -run TestMergeEnv -v
```

Expected: `undefined: mergeEnv`.

- [ ] **Step 3: Write minimal implementation**

Append to `cmd/alice/exec.go`:

```go
// mergeEnv builds the env slice for syscall.Exec. resolved entries (the
// --env values with placeholders restored) come first; parent entries
// (from os.Environ()) follow, EXCEPT any whose name appears in
// overridden. Explicit dedup avoids relying on execve(2)'s
// implementation-defined behavior for duplicate keys (glibc / musl /
// macOS libc all take the FIRST match via getenv but POSIX does not pin
// this).
func mergeEnv(resolved []string, overridden map[string]struct{}, parent []string) []string {
	out := make([]string, 0, len(resolved)+len(parent))
	out = append(out, resolved...)
	for _, kv := range parent {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			// Malformed entry — preserve verbatim (it's not for us to clean).
			out = append(out, kv)
			continue
		}
		name := kv[:idx]
		if _, ok := overridden[name]; ok {
			continue
		}
		out = append(out, kv)
	}
	return out
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
feat(alice): mergeEnv — explicit dedup for syscall.Exec env

resolved (--env-derived) entries come first; parent os.Environ() entries
follow EXCEPT any whose name appears in overridden. Avoids relying on
execve's implementation-defined behavior for duplicate keys — glibc,
musl, and macOS libc all take FIRST via getenv but POSIX does not
require it.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task AE3: `cmdExec` orchestration + wiring

**Files:**
- Modify: `cmd/alice/exec.go`
- Modify: `cmd/alice/main.go`

Wire all pieces: parse args, split on `--`, parseEnvFlag, load client, batch decrypt, restore placeholders, mergeEnv, lookpath, syscall.Exec. No unit tests at this layer (syscall.Exec replaces the process); integration coverage comes in AE5 (e2e).

- [ ] **Step 1: Implement cmdExec**

Append to `cmd/alice/exec.go`:

```go
import (
	// add to existing import block:
	"flag"
	"os"
	"os/exec"
	"syscall"

	"github.com/kaka-milan-22/AnB/internal/localvault"
	"github.com/kaka-milan-22/AnB/internal/redact"
)

// envFlagValue is a flag.Value that accumulates repeated --env occurrences.
type envFlagValue struct{ vals []string }

func (e *envFlagValue) String() string     { return strings.Join(e.vals, ",") }
func (e *envFlagValue) Set(v string) error { e.vals = append(e.vals, v); return nil }

// cmdExec — agent-safe execution path. Resolves <agent-vault:k> placeholders
// inside --env values via Bob (mTLS DecryptMany), builds the child's env with
// explicit dedup, then syscall.Exec's the child. alice's process image is
// replaced; alice's heap (with the plaintexts) is discarded by the kernel;
// alice's stdout/stderr/stdin fds are inherited by the child.
//
// Argv (everything after --) is NOT scanned for placeholders — Linux
// /proc/<pid>/cmdline is world-readable by default, so secrets in argv would
// leak to any uid on the box. --env values land in child env only (still
// same-uid visible via ps eww / /proc/<pid>/environ, but strictly stronger
// than argv).
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

	// Parse and validate --env entries; collect distinct vault keys referenced.
	parsed, keySet, err := parseEnvFlag(envs.vals)
	if err != nil {
		return err
	}

	// Resolve all referenced vault keys via one DecryptMany round-trip.
	plaintexts := map[string]string{}
	if len(keySet) > 0 {
		s := localvault.Open(*dir)
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

	// Restore placeholders in each --env value. Fail-closed on any unresolved
	// placeholder (paranoid: shouldn't happen because we already validated
	// against the vault above, but defensive).
	resolved := make([]string, 0, len(parsed))
	overridden := make(map[string]struct{}, len(parsed))
	envNames := make([]string, 0, len(parsed))
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
		envNames = append(envNames, e.Name)
	}

	mergedEnv := mergeEnv(resolved, overridden, os.Environ())

	cmdPath, err := exec.LookPath(childArgv[0])
	if err != nil {
		return fmt.Errorf("exec lookup %q: %w", childArgv[0], err)
	}

	// Audit hint to operator's stderr — key NAMES only, never plaintext.
	fmt.Fprintf(os.Stderr, "→ exec %s with env=%v\n", cmdPath, envNames)

	// syscall.Exec replaces alice's process image; the plaintexts in alice's
	// heap are discarded by the kernel. fds 0/1/2 are inherited by the child.
	return syscall.Exec(cmdPath, childArgv, mergedEnv)
}

```

`flag` is imported because `newFS` returns `*flag.FlagSet` and `fs.Var` takes a `flag.Value`. No `var _ = flag.ErrHelp` workaround needed.

- [ ] **Step 2: Wire cmdExec into cmds map**

Open `/Users/bbwave03/claude/anb/cmd/alice/main.go`. Find the `cmds := map[string]func([]string) error{` block (around line 31). Add `"exec": cmdExec,` to the safe-section line. The safe-section currently reads:

```go
"read": cmdRead, "write": cmdWrite, "has": cmdHas, "list": cmdList, "status": cmdStatus,
```

Add `exec` so it reads:

```go
"read": cmdRead, "write": cmdWrite, "has": cmdHas, "list": cmdList, "status": cmdStatus, "exec": cmdExec,
```

- [ ] **Step 3: Add the usage table row**

In the same `main.go`, find the `usage()` function. The safe-command block currently has rows for `read`, `write`, `has`, `list`, `status`. Add immediately after the `status` row:

```go
	fmt.Fprintf(w, row, "exec [--env KEY=V]... -- <cmd>", "Resolve <agent-vault:k> in --env values, syscall.Exec the child (safe for agents)")
```

- [ ] **Step 4: Update the package doc comment**

In the same `main.go`, the package-doc block around line 7 lists the safe / sensitive / setup commands. The safe line currently reads:

```go
//	safe (agent + human):     read  write  has  list  status
```

Change to:

```go
//	safe (agent + human):     read  write  has  list  status  exec
```

- [ ] **Step 5: Build + vet + fmt + full repo test**

```sh
cd /Users/bbwave03/claude/anb
go build ./...
go vet ./...
gofmt -l .
go test ./...
```

All green / clean / silent. The existing unit tests under `cmd/alice/` (which is just `exec_test.go` from AE1+AE2) continue to pass; everything else under `internal/` and `e2e/` unaffected.

- [ ] **Step 6: Commit**

```sh
git add cmd/alice/exec.go cmd/alice/main.go
git commit -m "$(cat <<'EOF'
feat(alice): exec subcommand — agent-safe placeholder→child-env path

alice exec [--env KEY=VALUE]... -- <cmd> [args...]

Resolves <agent-vault:k> placeholders inside --env values via Bob
(DecryptMany batch), builds the child's env with explicit dedup
(resolved wins), then syscall.Execs the child. alice's process is
replaced, plaintext never reaches alice's own stdout. argv after --
is NOT scanned for placeholders (Linux /proc/<pid>/cmdline is
world-readable by default — secrets only in env).

Fail-closed: malformed --env, unknown KEY name, missing vault key,
Bob unreachable / locked, exec.LookPath failure — all return non-zero
before child is ever invoked.

No TTY required. This is the agent-invokable safe-mode command.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task AE4: `alice write` → stderr routing + `--quiet`

**Files:**
- Modify: `cmd/alice/safe.go`

The current `cmdWrite` (around line 57 in safe.go pre-changes) emits status lines via `fmt.Println` (stdout). Move them to `fmt.Fprintln(os.Stderr, ...)` and add a `--quiet` flag that suppresses them.

- [ ] **Step 1: Read the current cmdWrite**

```sh
sed -n '50,140p' /Users/bbwave03/claude/anb/cmd/alice/safe.go
```

Note every `fmt.Println(...)` or `fmt.Printf(...)` call that emits status / confirmation messages (NOT the restored content output). Typical hits: `✓ Written to ...`, `↳ restored N placeholders, M missing`, `⚠ unresolved placeholders: ...`.

The restored content itself is written via `os.WriteFile(target, ...)` or `os.Stdout.Write(...)` when target is `-`/`/dev/stdout`. **Do NOT touch the content output** — only status/diagnostic lines.

- [ ] **Step 2: Apply the routing change**

For each status line in `cmdWrite`:

- `fmt.Println(...)` → `if !*quiet { fmt.Fprintln(os.Stderr, ...) }`
- `fmt.Printf(...)` (status only — not content) → `if !*quiet { fmt.Fprintf(os.Stderr, ...) }`

Add the `--quiet` flag at the top of `cmdWrite`'s flag setup. The function currently has:

```go
func cmdWrite(args []string) error {
	fs := newFS("write")
	dir := dirFlag(fs)
	content := fs.String("content", "", "...")
	// ... other flags ...
```

Add:

```go
	quiet := fs.Bool("quiet", false, "suppress status lines on stderr; emit only restored content")
```

Then guard each status emission with `if !*quiet { fmt.Fprintln(os.Stderr, ...) }`.

- [ ] **Step 3: Build + verify the test suite still passes**

```sh
cd /Users/bbwave03/claude/anb
go build ./...
go vet ./...
gofmt -l .
go test ./...
```

All green. The existing tests don't assert on cmdWrite's stdout content for status lines (they go through the localvault internals), so no test should regress. If one does, it was depending on stdout-status behavior — update the assertion to check stderr instead.

- [ ] **Step 4: Manual smoke (optional, by user — subagents can't drive interactive)**

```sh
# expected: restored content on stdout, status on stderr
echo 'hello <agent-vault:does-not-exist> world' | ./bin/alice write - 2>/tmp/stderr.txt
cat /tmp/stderr.txt   # should contain the "↳ N missing" diagnostic
```

If your local alice binary isn't fresh, `go install ./cmd/alice` first.

- [ ] **Step 5: Commit**

```sh
git add cmd/alice/safe.go
git commit -m "$(cat <<'EOF'
fix(alice): write status → stderr; add --quiet to suppress

Status / confirmation lines in alice write (✓ Written, ↳ restored N
placeholders M missing, ⚠ unresolved) move from stdout to stderr.
Agent harnesses that capture stdout for content-grep'ing no longer
also capture confirmation text. --quiet suppresses status lines
entirely (stderr silent, stdout receives only restored content).

This is the band-aid for the alice write /dev/stdout leak surface;
the architectural fix is alice exec (this PR).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task AE5: e2e — `TestAliceExec` happy path + fail-closed

**Files:**
- Modify: `e2e/full_test.go`

Library-level end-to-end against a real Bob daemon: store a secret, invoke `alice exec` from the test as a subprocess, have the child write its env value to a file, read the file, assert the plaintext arrived. Plus a missing-key test asserting alice exits non-zero and the child never runs.

- [ ] **Step 1: Read the existing e2e to find harness conventions**

```sh
sed -n '1,80p' /Users/bbwave03/claude/anb/e2e/full_test.go
```

Identify the helper that spins up CA + Bob + Alice (used by `TestFullFlow` and `TestPairingEnrollEndToEnd`). Note where alice's state dir is, where the binary is built, and how subprocesses are invoked (`exec.Command` with the built alice binary path).

If the existing tests already build the alice binary and put the state dir at a known temp path, reuse that. If not, you'll need to:

- `go build -o $tmpdir/alice ./cmd/alice` once at test setup
- Set `ANB_ALICE_DIR=$tmpdir` to point the test alice at the test state dir
- Run the alice subprocess against the test Bob

- [ ] **Step 2: Append the test functions**

At the end of `/Users/bbwave03/claude/anb/e2e/full_test.go`:

```go
func TestAliceExecHappyPath(t *testing.T) {
	// Stand up the standard test harness (Bob + Alice enrolled, alice binary
	// built into a temp dir). If the existing helper is named differently,
	// adapt the call.
	h := newHarness(t)
	defer h.cleanup()

	// Store a secret via alice set --stdin --force.
	h.aliceRun(t, []string{"set", "smoke-secret", "--stdin", "--force"}, "the-actual-plaintext\n")

	// Now run alice exec with a child that writes $FOO to a file path passed
	// as an arg, so we can read it back and assert.
	outFile := filepath.Join(h.tmpDir, "exec-out.txt")
	h.aliceRunOk(t, []string{
		"exec",
		"--env", "FOO=<agent-vault:smoke-secret>",
		"--", "/bin/sh", "-c", "printf '%s' \"$FOO\" > \"$1\"", "_", outFile,
	}, "")

	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if string(got) != "the-actual-plaintext" {
		t.Fatalf("child wrote %q, want %q", got, "the-actual-plaintext")
	}
}

func TestAliceExecFailClosedOnMissingKey(t *testing.T) {
	h := newHarness(t)
	defer h.cleanup()

	// Do NOT store the key.
	outFile := filepath.Join(h.tmpDir, "should-not-exist.txt")
	err := h.aliceRunErr(t, []string{
		"exec",
		"--env", "FOO=<agent-vault:nonexistent-key>",
		"--", "/bin/sh", "-c", "printf '%s' \"$FOO\" > \"$1\"", "_", outFile,
	}, "")
	if err == nil {
		t.Fatal("expected alice exec to fail when --env references a missing key")
	}
	if _, statErr := os.Stat(outFile); !os.IsNotExist(statErr) {
		t.Fatalf("child should NOT have run; outFile exists: stat=%v", statErr)
	}
}
```

This depends on three harness helpers (`newHarness`, `aliceRun`, `aliceRunOk`, `aliceRunErr`) that the existing `e2e/full_test.go` may or may not have. If the existing tests use different names, adapt accordingly. If they're missing entirely (e.g., the existing e2e uses an inline pattern), refactor the inline pattern into helpers in a separate prep step or inline the alice-binary-invocation pattern into the test bodies.

The KEY pattern is:
- Build alice binary once at test setup (or use `t.TempDir()` for state).
- For aliceRun: `cmd := exec.Command(alicePath, args...)`, set `cmd.Env = append(os.Environ(), "ANB_ALICE_DIR=...")`, `cmd.Stdin` if stdin needed, run, check exit code.
- aliceRunErr is the same but expects non-zero exit.

If the existing pattern in the file is simpler (e.g., calls into `cmd/alice` packages directly without subprocess), do NOT do that for `cmdExec` — `syscall.Exec` replaces the current Go test process, which would terminate the test runner. You MUST run alice as a subprocess for the exec test.

- [ ] **Step 3: Run the new tests**

```sh
cd /Users/bbwave03/claude/anb
go test ./e2e/ -run 'TestAliceExec' -v
go test ./... 2>&1 | tail -15
```

Both tests pass. Full repo green.

- [ ] **Step 4: Commit**

```sh
git add e2e/full_test.go
git commit -m "$(cat <<'EOF'
test(e2e): alice exec happy path + fail-closed-on-missing-key

Two integration tests against a real Bob daemon:
- happy path: set a secret, alice exec --env FOO=<agent-vault:k> --
  /bin/sh -c 'printf %s "$FOO" > $1' -- outfile; read outfile, assert
  the plaintext arrived intact.
- fail-closed: --env references a key that doesn't exist in the vault;
  alice exits non-zero AND the child never runs (outfile MUST NOT
  exist).

The exec test runs alice as a subprocess (not as an in-process Go
call) because syscall.Exec replaces the calling process — invoking
it in-process would kill the test runner.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task AE6: README — Features bullet + Daily-use example + command table

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add Features bullet**

Open `README.md`. Find the "## Features" section. Insert a new bullet AFTER the "Safe / sensitive split" bullet (around the v1.3.2 layout):

```markdown
- **Agent-safe exec** — `alice exec --env KEY=<agent-vault:k> -- <cmd> <args>`
  resolves vault placeholders into the child's env and `syscall.Exec`s the
  child. The alice process disappears; plaintext never reaches alice's own
  stdout. Argv-side placeholders are explicitly disallowed (Linux
  `/proc/<pid>/cmdline` is world-readable). Companion: `alice write --quiet`
  now routes status lines to stderr.
```

- [ ] **Step 2: Add Daily-use example**

Find the "### 3. Daily use" section (around line 200 in the current README). After the existing alice set / list / get examples, add:

```sh
# agent-safe exec: env value resolved from vault, plaintext only in child env
alice exec --env GITHUB_TOKEN=<agent-vault:gh-pat> \
  -- curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user
```

- [ ] **Step 3: Add command-table row**

Find the "### alice — safe (agent + human, no TTY)" table. Add a row at the bottom:

```markdown
| `alice exec [--env KEY=V]... -- <cmd> [args...]` | Resolve `<agent-vault:k>` in `--env` values, then `syscall.Exec` the child. Plaintext never on alice's stdout. |
```

- [ ] **Step 4: Update alice write row to document --quiet + stderr**

Find the "alice write" row in the same table. Append to the description:

```
. Status lines go to stderr; `--quiet` suppresses them.
```

- [ ] **Step 5: Bump install snippet to v1.4.0**

Find the Install section. Replace every `v1.3.2` with `v1.4.0` (3 places in the code block + 1 in the "Replace `vX.Y.Z` with `@latest`" hint line):

```sh
sed -i '' 's/v1\.3\.2/v1.4.0/g' /Users/bbwave03/claude/anb/README.md
```

(Use `sed -i` without `''` on Linux.)

- [ ] **Step 6: Verify no stale version references**

```sh
grep -n 'v1\.3\.2' /Users/bbwave03/claude/anb/README.md
```

Empty.

- [ ] **Step 7: Commit**

```sh
git add README.md
git commit -m "$(cat <<'EOF'
docs(readme): document alice exec + write --quiet, bump install v1.4.0

Features bullet, Daily-use example (GitHub API call via curl with
$GITHUB_TOKEN from vault), command-table row for alice exec, and a
short note appended to alice write's row about stderr / --quiet.
Install snippet bumped to v1.4.0 so the tag lands at a
self-consistent commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task AE7: Local smoke (USER, real TTY)

**Files:** None (operator verification).

Subagent cannot drive — requires a live Bob daemon and an interactive terminal. User runs:

- [ ] **Step 1: Install fresh binaries**

```sh
cd /Users/bbwave03/claude/anb
go install ./cmd/bob ./cmd/alice
```

- [ ] **Step 2: Confirm the new subcommand surfaces in help**

```sh
alice --help 2>&1 | grep -i exec    # should show the exec row
alice exec 2>&1 | head -3            # should show usage error pointing at "--"
```

- [ ] **Step 3: Run the happy-path example end-to-end**

```sh
# uses an existing key from your vault; replace n9euser if needed
alice exec --env TEST_VAR=<agent-vault:n9euser> \
  -- /bin/sh -c 'echo "got: $TEST_VAR"'
```

Expected on stderr: `→ exec /bin/sh with env=[TEST_VAR]`
Expected on stdout: `got: <the-secret>`

- [ ] **Step 4: Confirm fail-closed on a non-existent key**

```sh
alice exec --env BOGUS=<agent-vault:definitely-not-there> -- /bin/sh -c 'echo SHOULD NOT RUN' 2>&1
echo "alice exited: $?"
```

Expected: alice prints the "refusing to exec" error to stderr, exits non-zero, `SHOULD NOT RUN` is NOT printed.

- [ ] **Step 5: Verify `alice write --quiet`**

```sh
echo 'hello <agent-vault:nonexistent> world' | alice write -        # stderr has the missing-key diagnostic
echo 'hello <agent-vault:nonexistent> world' | alice write --quiet - # stderr silent
```

Both write `hello <agent-vault:nonexistent> world` to stdout (placeholder left intact because the key doesn't exist); first prints diagnostics on stderr, second is silent.

- [ ] **Step 6: No commit — operational only**

If any smoke step misbehaves, fix the relevant prior task and amend its commit. Otherwise proceed to AE8.

---

### Task AE8: Final review + PR + v1.4.0 release

**Files:** None (release engineering).

- [ ] **Step 1: Full test suite + vet + fmt**

```sh
cd /Users/bbwave03/claude/anb
go test ./...
go vet ./...
gofmt -l .
```

All green / clean / silent.

- [ ] **Step 2: Diff summary**

```sh
git log --oneline main..HEAD
git --no-pager diff main..HEAD --stat
```

Expected: 6 commits (AE1, AE2, AE3, AE4, AE5, AE6) + README install bump landed inside AE6. ~200 source lines + ~150 test lines + ~25 README lines.

- [ ] **Step 3: Dispatch the final branch-wide code reviewer**

Use the same pattern as `feat/enrollment-pairing` (PR #1) and `feat/server-hardening-v1.3.2` (PR #4): dispatch a `general-purpose` subagent with model `sonnet`, hand it the spec at `docs/superpowers/specs/2026-05-28-alice-exec-design.md` and the branch HEAD, ask for spec-coverage + quality findings classified Critical / Important / Minor.

- [ ] **Step 4: Push branch + open PR**

```sh
git push -u origin feat/alice-exec
gh pr create --base main --head feat/alice-exec --title "feat: alice exec — agent-safe placeholder→child-env path" --body "$(cat <<'EOF'
## Summary

New `alice exec --env KEY=<agent-vault:k> -- <cmd> <args>` subcommand: the architectural fix for the `alice write /dev/stdout` plaintext-on-stdout leak. Plus a band-aid: `alice write` status lines move to stderr and a new `--quiet` flag suppresses them entirely.

`alice exec` resolves vault placeholders into the child's env, `syscall.Exec`s the child, and disappears — plaintext never reaches alice's own stdout. Argv-side placeholders are explicitly disallowed (Linux `/proc/<pid>/cmdline` is world-readable by default). Fail-closed on every error path (missing key, malformed flag, Bob unreachable, exec lookup failure).

Spec: docs/superpowers/specs/2026-05-28-alice-exec-design.md

## Test Plan

- [x] `go test ./...` green (new unit tests for parseEnvFlag + mergeEnv; new e2e for happy path + fail-closed-on-missing-key)
- [x] `go vet ./...` clean
- [x] `gofmt -l .` silent
- [x] Operator smoke: `alice exec --env FOO=<agent-vault:k> -- /bin/sh -c 'echo "$FOO"'` prints plaintext on child stdout, audit hint on alice stderr
- [x] Fail-closed: `--env FOO=<agent-vault:nonexistent>` exits non-zero, child never runs
- [x] `alice write --quiet -` silent on stderr, restored content on stdout

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 5: Squash-merge + tag v1.4.0 + GH release**

After PR is approved:

```sh
gh pr merge <PR#> --squash --delete-branch --subject "feat: alice exec — agent-safe placeholder→child-env path (#<PR#>)" --body "<summary>"
git checkout main && git pull --ff-only
git tag -a v1.4.0 <merge-sha> -m "AnB v1.4.0 — alice exec (agent-safe placeholder→child-env path)"
git push origin v1.4.0
gh release create v1.4.0 --title "AnB v1.4.0 — alice exec" --notes "<release notes from spec>"
```

---

## Self-Review

### Spec coverage check

- ✅ `alice exec` CLI surface (`--env`, `--dir`, `--` boundary) → Task AE3 step 1
- ✅ Free interpolation in `--env` values (Q2 free interpolation) → Task AE1 tests
- ✅ argv NOT scanned for placeholders → Task AE3 step 1 (docstring + no argv processing in cmdExec)
- ✅ No TTY required → Task AE3 (no `requireTTY()` call)
- ✅ Data-flow steps 1-7 from spec → Task AE3 step 1 (mirrors the data flow)
- ✅ Explicit env dedup (resolved wins, parent passthrough drops collisions) → Task AE2
- ✅ Fail-closed cases (malformed flag, missing key, Bob unreachable / locked, LookPath fail) → Task AE3 step 1 covers all branches; AE1 tests cover parser; AE5 tests cover end-to-end missing-key path
- ✅ Audit hint on alice stderr (key names only) → Task AE3 step 1
- ✅ Child stdout/stderr/exit-code inheritance via syscall.Exec → Task AE3 step 1 (syscall.Exec semantics)
- ✅ `alice write` stderr routing + `--quiet` → Task AE4
- ✅ Documentation: Features bullet, Daily-use example, command table, install bump → Task AE6
- ✅ Verification matrix (10 items from spec) covered by Tasks AE1-AE7 collectively

### Placeholder scan

No `TBD`, `TODO`, `implement later`, `add appropriate error handling`, `similar to Task N`, or other red flags. Every step that changes code shows the exact code. Every command has expected output documented.

### Type / signature consistency

- `parseEnvFlag([]string) ([]envEntry, map[string]struct{}, error)` — defined in AE1, used in AE3.
- `mergeEnv([]string, map[string]struct{}, []string) []string` — defined in AE2, used in AE3.
- `envEntry{Name, Value}` — defined in AE1, used in AE3.
- `envFlagValue` — defined and used in AE3 (one task).
- `placeholderRE`, `envNameRE` — defined in AE1, used by `parseEnvFlag` in AE1.

All consistent across tasks.

### Open question for the engineer

If `e2e/full_test.go` doesn't already expose a `newHarness` / `aliceRun*` style helper that the AE5 tests assume, the implementer should EITHER:

(a) Inline the alice-subprocess pattern directly in the two test functions (cleaner, no helper churn).
(b) Extract a small helper at the bottom of `full_test.go` and use it from both new tests.

Either is fine. (a) is the lower-friction default; pick (b) if the inline pattern would duplicate >10 lines per test.
