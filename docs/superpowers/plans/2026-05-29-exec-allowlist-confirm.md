# `alice exec` deny-with-confirm-prompt (v2.1.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When `alice exec` denies an invocation for being not-in-allowlist AND stdin is a TTY, prompt the operator with `[y/N]` after the existing deny output; on full-word `yes` confirmation, atomically append the triple to `exec-allowlist.json` and exit non-zero with a clear "re-run to execute" message (two-stage flow — operator must re-run the command). Non-TTY (agent / pipe) callers see no prompt, get hard-deny exactly as today (v2.0 invariant preserved).

**Architecture:** Two pure(-ish) helpers in `cmd/alice/exec.go` — `confirmAppend(in io.Reader, out io.Writer) bool` (reads stdin, accepts only the literal word `yes` case-insensitive, anything else returns false) and `appendAllowEntry(dir string, entry allowEntry) error` (atomic read-parse-append-writeAtomic via the existing `localvault` helper). The deny branch in `cmdExec` gains one new code path gated on `term.StdinIsTTY()`; `cmd/alice/main.go`'s dispatcher gains a 3-line check so a ✓-prefixed error string is printed without the ✗ wrapping.

**Tech Stack:** Go 1.26 (existing). Stdlib only: `bufio`, `encoding/json`, `io`, `strings`. Reuses `internal/term.StdinIsTTY` (existing TTY check), `internal/localvault.Store.WriteFile` (atomic), `allowEntry`/`allowlist` types from v2.0.

**Spec:** Design captured inline in this plan (small additive extension of v2.0 — no separate spec doc). Two explicit decisions locked during brainstorming:
1. Confirmation word: must type the full word `yes` (case-insensitive, trimmed). Single `y` does NOT count.
2. After append: alice prints `✓ appended` and exits non-zero. Operator must re-run the command manually (two-stage flow; no auto-execute).

---

## File Structure

| File | Role | Status |
|---|---|---|
| `cmd/alice/exec.go` | New `confirmAppend` + `appendAllowEntry` helpers. `cmdExec` deny branch: if `term.StdinIsTTY()`, print deny output, call `confirmAppend(os.Stdin, os.Stderr)`; on true call `appendAllowEntry(s.Dir, entry)`, return a ✓-prefixed error that the dispatcher will print without ✗ wrapping. | Modify (~60 LOC) |
| `cmd/alice/exec_test.go` | Unit tests for both helpers. confirmAppend tested via `strings.Reader` (not a TTY — the TTY gate lives one layer up in cmdExec). appendAllowEntry tested with `t.TempDir`. | Modify (+~120 LOC) |
| `cmd/alice/main.go` | Dispatcher tweak: 3 lines. If `err.Error()` starts with `"✓ "`, print without the `✗ ` wrapping but keep the non-zero exit. Single escape hatch for "intentional non-zero with a success-marker message". | Modify (~5 LOC) |
| `README.md` | Daily-use example mentions the prompt flow as a faster alternative to "open editor, paste, save". Trust boundary note about TTY-only — agents still get hard-deny. Install snippet bump v2.0.0 → v2.1.0. | Modify (~20 LOC) |
| `e2e/full_test.go` | No new test required — the existing `TestAliceExecDeniedWhenNoMatch` runs as a subprocess (no TTY), already verifies the non-TTY hard-deny path. Adding a test for the TTY-prompt branch would require a pty library (not currently a dep) — covered by operator smoke (EAC6) instead. Sanity-check only. | No change |

---

### Task EAC1: `confirmAppend` helper + unit tests

**Files:**
- Modify: `cmd/alice/exec.go`
- Modify: `cmd/alice/exec_test.go`

Pure(-ish) function: reads one line from `in`, prints a prompt to `out`, returns true iff the trimmed-lowercase input equals exactly `"yes"`. Caller is responsible for the TTY check (we do not gate TTY here so tests can pass strings).

- [ ] **Step 1: Write the failing tests**

Append to `cmd/alice/exec_test.go`:

```go
func TestConfirmAppendAcceptsYes(t *testing.T) {
	for _, input := range []string{"yes\n", "YES\n", "Yes\n", "  yes  \n", "yes"} {
		var out bytes.Buffer
		got := confirmAppend(strings.NewReader(input), &out)
		if !got {
			t.Fatalf("input %q: want true, got false (prompt was: %q)", input, out.String())
		}
	}
}

func TestConfirmAppendRejectsY(t *testing.T) {
	// Single 'y' is intentionally NOT accepted — operator must type full word.
	for _, input := range []string{"y\n", "Y\n", " y\n"} {
		var out bytes.Buffer
		got := confirmAppend(strings.NewReader(input), &out)
		if got {
			t.Fatalf("input %q: want false (only 'yes' is accepted), got true", input)
		}
	}
}

func TestConfirmAppendDefaultsToNo(t *testing.T) {
	// Empty input (just Enter), no input, and any other non-"yes" string
	// all return false.
	for _, input := range []string{"\n", "", "no\n", "yes please\n", "yes\nmore\n"} {
		var out bytes.Buffer
		got := confirmAppend(strings.NewReader(input), &out)
		if got {
			t.Fatalf("input %q: want false (default N), got true", input)
		}
	}
}

func TestConfirmAppendPrintsPrompt(t *testing.T) {
	var out bytes.Buffer
	_ = confirmAppend(strings.NewReader("no\n"), &out)
	prompt := out.String()
	if !strings.Contains(prompt, "yes") {
		t.Fatalf("prompt should mention 'yes' as the confirmation word; got: %q", prompt)
	}
	if !strings.Contains(prompt, "[y/N]") && !strings.Contains(prompt, "yes/N") {
		t.Fatalf("prompt should display the default-N hint; got: %q", prompt)
	}
}
```

Make sure `bytes` is in the test file's imports. `strings` already is.

- [ ] **Step 2: Run tests to verify they fail**

```sh
cd /Users/bbwave03/claude/anb
go test ./cmd/alice/ -run 'TestConfirmAppend' -v
```

Expected: build error `undefined: confirmAppend`.

- [ ] **Step 3: Implement `confirmAppend`**

Append to `cmd/alice/exec.go`. Add `bufio` and `io` to the import block if not already present.

```go
// confirmAppend prints a "type 'yes' to confirm" prompt to out and reads
// one line from in. Returns true iff the trimmed-lowercase input is
// exactly "yes" — a single "y" does NOT count, deliberately, because the
// caller's next action (appending to the allowlist + signalling
// "operator approved") deserves two friction characters more than the
// reflex-key "y".
func confirmAppend(in io.Reader, out io.Writer) bool {
	fmt.Fprint(out, "\nAppend this entry to exec-allowlist.json? Type 'yes' to confirm [y/N]: ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	return strings.ToLower(strings.TrimSpace(line)) == "yes"
}
```

Note: this is the ONE place in `cmd/alice/` that still uses `bufio.NewReader(in)` — the v1.3.1 footgun was about RE-creating bufio readers on os.Stdin where the previous reader's read-ahead would drop bytes. Here, `in` is either an `os.File` (TTY) for the operator path or a `strings.Reader` for tests — neither chains additional reads from the same source after this call, so there's no drain risk. (Confirm by reading cmdExec: after `confirmAppend` returns true, cmdExec exits via the dispatcher; if false, cmdExec also returns. Nothing further reads stdin.)

- [ ] **Step 4: Run tests + full pkg**

```sh
go test ./cmd/alice/ -v
go vet ./cmd/alice/
gofmt -l cmd/alice/
```

All tests pass (existing 29 + new 4 = 33). Vet silent. fmt silent.

- [ ] **Step 5: Commit**

```sh
git add cmd/alice/exec.go cmd/alice/exec_test.go
git commit -m "$(cat <<'EOF'
feat(alice): confirmAppend — strict 'yes'-only prompt reader

Pure reader-side helper for the upcoming deny-with-confirm flow.
Accepts only the trimmed-lowercase word "yes" (case-insensitive);
single "y" and anything else returns false. Two extra characters of
friction over reflex-key "y" — the next action (mutating the
allowlist) deserves it.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task EAC2: `appendAllowEntry` helper + unit tests

**Files:**
- Modify: `cmd/alice/exec.go`
- Modify: `cmd/alice/exec_test.go`

Reads `exec-allowlist.json`, parses it (reusing the v2.0 `loadAllowlist` validation), appends the entry to `Allow`, writes back atomically via `localvault.Store.WriteFile` (existing tmp+rename helper). The atomic write is necessary so a crash mid-append doesn't truncate the operator's allowlist.

- [ ] **Step 1: Write the failing tests**

Append to `cmd/alice/exec_test.go`:

```go
func TestAppendAllowEntryAppendsToEmptyList(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "exec-allowlist.json"), []byte(`{"allow":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := allowEntry{Cmd: "/usr/bin/echo", Args: []string{"hi"}, Env: []string{}}
	if err := appendAllowEntry(dir, entry); err != nil {
		t.Fatalf("appendAllowEntry: %v", err)
	}
	list, err := loadAllowlist(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Allow) != 1 {
		t.Fatalf("want 1 entry after append, got %d", len(list.Allow))
	}
	if list.Allow[0].Cmd != "/usr/bin/echo" || !reflect.DeepEqual(list.Allow[0].Args, []string{"hi"}) {
		t.Fatalf("appended entry mismatch: %+v", list.Allow[0])
	}
}

func TestAppendAllowEntryPreservesExisting(t *testing.T) {
	dir := t.TempDir()
	body := `{"allow":[{"cmd":"/usr/bin/echo","args":["a"],"env":[]}]}`
	if err := os.WriteFile(filepath.Join(dir, "exec-allowlist.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := allowEntry{Cmd: "/opt/homebrew/bin/gh", Args: []string{"api", "user"}, Env: []string{"GH_TOKEN"}}
	if err := appendAllowEntry(dir, entry); err != nil {
		t.Fatal(err)
	}
	list, err := loadAllowlist(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Allow) != 2 {
		t.Fatalf("want 2 entries (1 existing + 1 appended), got %d", len(list.Allow))
	}
	if list.Allow[0].Cmd != "/usr/bin/echo" {
		t.Fatalf("existing entry was clobbered: %+v", list.Allow[0])
	}
	if list.Allow[1].Cmd != "/opt/homebrew/bin/gh" {
		t.Fatalf("new entry missing or wrong position: %+v", list.Allow[1])
	}
}

func TestAppendAllowEntryWritesValidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "exec-allowlist.json"), []byte(`{"allow":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := allowEntry{
		Cmd:  "/bin/sh",
		Args: []string{"-c", `echo "got: $TEST"`},
		Env:  []string{"TEST"},
	}
	if err := appendAllowEntry(dir, entry); err != nil {
		t.Fatal(err)
	}
	// Re-load via loadAllowlist (strict JSON with DisallowUnknownFields) to
	// confirm the on-disk file is well-formed.
	list, err := loadAllowlist(dir)
	if err != nil {
		t.Fatalf("written file does not round-trip through loadAllowlist: %v", err)
	}
	if !reflect.DeepEqual(list.Allow[0], entry) {
		t.Fatalf("round-trip mismatch: got %+v want %+v", list.Allow[0], entry)
	}
}

func TestAppendAllowEntryFailsIfFileMissing(t *testing.T) {
	dir := t.TempDir()
	// Do NOT create exec-allowlist.json.
	entry := allowEntry{Cmd: "/usr/bin/echo", Args: []string{}, Env: []string{}}
	err := appendAllowEntry(dir, entry)
	if err == nil {
		t.Fatal("expected error when allowlist file is missing")
	}
	if !errors.Is(err, errAllowlistMissing) {
		t.Fatalf("want errAllowlistMissing, got %v", err)
	}
}

func TestAppendAllowEntryWritesAtomicMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "exec-allowlist.json"), []byte(`{"allow":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := allowEntry{Cmd: "/usr/bin/echo", Args: []string{}, Env: []string{}}
	if err := appendAllowEntry(dir, entry); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "exec-allowlist.json"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode after append = %o, want 0o600", st.Mode().Perm())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```sh
go test ./cmd/alice/ -run 'TestAppendAllowEntry' -v
```

Expected: build error `undefined: appendAllowEntry`.

- [ ] **Step 3: Implement `appendAllowEntry`**

Append to `cmd/alice/exec.go` (after the other allowlist helpers). The implementation reuses `loadAllowlist` to read+validate, then uses `localvault.Open(dir).WriteFile(...)` for atomic write back.

```go
// appendAllowEntry reads exec-allowlist.json from dir, parses it,
// appends entry to Allow, and writes back atomically (via the existing
// localvault writeAtomic helper). Returns errAllowlistMissing if the
// file does not exist — callers should not attempt to "create + append"
// because the missing file is itself an operator-deliberate state
// (default-deny scaffold; see cmdEnroll).
func appendAllowEntry(dir string, entry allowEntry) error {
	list, err := loadAllowlist(dir)
	if err != nil {
		return err
	}
	list.Allow = append(list.Allow, entry)

	// Re-marshal with stable indentation matching the scaffold style so
	// the file remains human-editable after auto-appends.
	body, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal allowlist: %w", err)
	}
	body = append(body, '\n')

	s := localvault.Open(dir)
	return s.WriteFile("exec-allowlist.json", body, 0o600)
}
```

- [ ] **Step 4: Verify**

```sh
go test ./cmd/alice/ -v
go vet ./cmd/alice/
gofmt -l cmd/alice/
```

All tests pass (existing 33 + new 5 = 38). Vet silent. fmt silent.

- [ ] **Step 5: Commit**

```sh
git add cmd/alice/exec.go cmd/alice/exec_test.go
git commit -m "$(cat <<'EOF'
feat(alice): appendAllowEntry — atomic read-modify-write of exec-allowlist.json

Reads via loadAllowlist (strict JSON validation), appends, writes back
via localvault.Store.WriteFile (existing tmp+rename atomic helper).
Preserves 0o600. Missing file returns errAllowlistMissing — callers
must not auto-create (the missing scaffold is an operator-deliberate
default-deny state, not a bootstrap state).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task EAC3: Wire confirm-prompt into `cmdExec` + dispatcher escape hatch

**Files:**
- Modify: `cmd/alice/exec.go`
- Modify: `cmd/alice/main.go`

`cmdExec`'s deny branch (when `matchAllowlist` returns nil) gets one new code path: if `term.StdinIsTTY()`, print the existing deny output, call `confirmAppend`. On true, call `appendAllowEntry` and return a ✓-prefixed error message. On false (or non-TTY), return the existing deny error unchanged.

`cmd/alice/main.go`'s error dispatcher gains a 3-line check: if the error message starts with `"✓ "`, print without the `"✗ "` wrapping but keep the non-zero exit.

- [ ] **Step 1: Read the current cmdExec deny block**

```sh
cd /Users/bbwave03/claude/anb
grep -n 'matchAllowlist(cmdName' cmd/alice/exec.go
```

Note the line number. Read the surrounding ~25 lines so you see the exact deny-error format.

- [ ] **Step 2: Modify the deny branch**

In `cmd/alice/exec.go`, find the block:

```go
if matchAllowlist(cmdName, childArgs, envNames, list) == nil {
    return fmt.Errorf("alice exec: invocation not in allowlist.\n\n  cmd:  %s\n  args: %s\n  env:  %s\n\nTo allow exactly this invocation, append to allow[] in\n%s/exec-allowlist.json:\n\n%s\n\nNote: strict byte-for-byte equality on cmd, args (each position),\nand env name set. Any change — extra whitespace, different arg\nposition, extra/missing env name — requires a new entry.\nWildcards are not supported.",
        cmdName,
        mustMarshalJSON(childArgs),
        mustMarshalJSON(sortedStringSlice(envNames)),
        s.Dir,
        formatDenyJSON(cmdName, childArgs, envNames))
}
```

Replace with:

```go
if matchAllowlist(cmdName, childArgs, envNames, list) == nil {
    denyMsg := fmt.Sprintf("alice exec: invocation not in allowlist.\n\n  cmd:  %s\n  args: %s\n  env:  %s\n\nTo allow exactly this invocation, append to allow[] in\n%s/exec-allowlist.json:\n\n%s\n\nNote: strict byte-for-byte equality on cmd, args (each position),\nand env name set. Any change — extra whitespace, different arg\nposition, extra/missing env name — requires a new entry.\nWildcards are not supported.",
        cmdName,
        mustMarshalJSON(childArgs),
        mustMarshalJSON(sortedStringSlice(envNames)),
        s.Dir,
        formatDenyJSON(cmdName, childArgs, envNames))

    // TTY-only convenience: offer to append the entry now. Non-TTY
    // callers (agents, pipes) get the hard-deny exactly as before.
    if term.StdinIsTTY() {
        fmt.Fprintln(os.Stderr, denyMsg)
        if confirmAppend(os.Stdin, os.Stderr) {
            entry := allowEntry{
                Cmd:  cmdName,
                Args: childArgs,
                Env:  sortedStringSlice(envNames),
            }
            if err := appendAllowEntry(s.Dir, entry); err != nil {
                return fmt.Errorf("append allowlist entry: %w", err)
            }
            return fmt.Errorf("✓ appended entry to %s/exec-allowlist.json — re-run your command to execute it",
                s.Dir)
        }
    }

    return errors.New(denyMsg)
}
```

Confirm that `cmd/alice/exec.go` already imports `github.com/kaka-milan-22/AnB/internal/term`. If not, add it. Also confirm `errors` is imported (it was added in EA2).

- [ ] **Step 3: Modify the dispatcher in main.go**

In `cmd/alice/main.go`, find the error-handling block in `main()`. It looks like:

```go
if err := fn(os.Args[2:]); err != nil {
    fmt.Fprintf(os.Stderr, "✗ %v\n", err)
    os.Exit(1)
}
```

Replace with:

```go
if err := fn(os.Args[2:]); err != nil {
    // Errors whose message starts with "✓ " are intentional non-zero
    // exits with a success-marker (e.g. alice exec auto-append asks
    // the operator to re-run). Print without the ✗ wrapping but keep
    // the non-zero exit so script chains do not proceed as if the
    // child ran.
    if msg := err.Error(); strings.HasPrefix(msg, "✓ ") {
        fmt.Fprintln(os.Stderr, msg)
    } else {
        fmt.Fprintf(os.Stderr, "✗ %v\n", err)
    }
    os.Exit(1)
}
```

Add `"strings"` to main.go's import block if it isn't already there (it might be from earlier work).

- [ ] **Step 4: Build + verify**

```sh
go build ./...
go vet ./...
gofmt -l .
go test ./cmd/alice/ -v 2>&1 | tail -5
go test ./... 2>&1 | tail -10
```

All 38 cmd/alice unit tests pass. Full repo green. The existing e2e `TestAliceExecDeniedWhenNoMatch` continues to pass because subprocess invocations don't have a TTY — the new TTY-only branch doesn't fire, the hard-deny path is preserved.

- [ ] **Step 5: Manual smoke (build only — interactive smoke is in EAC6)**

```sh
go install ./cmd/alice
# Build sanity: no TTY when piped, hard-deny preserved.
mkdir -p /tmp/exec-confirm-smoke
echo '{"allow":[]}' > /tmp/exec-confirm-smoke/exec-allowlist.json
ANB_ALICE_DIR=/tmp/exec-confirm-smoke alice exec --env 'X=<agent-vault:k>' -- /bin/echo hi < /dev/null 2>&1 | head -25
# Expected: deny output as v2.0 — NO interactive prompt (stdin is /dev/null, not a TTY).
rm -rf /tmp/exec-confirm-smoke
```

If the prompt fires from /dev/null input, the TTY check is wrong — debug before proceeding.

- [ ] **Step 6: Commit**

```sh
git add cmd/alice/exec.go cmd/alice/main.go
git commit -m "$(cat <<'EOF'
feat(alice): exec deny offers TTY confirm-and-append flow

When alice exec hard-denies for "not in allowlist" AND stdin is a
TTY, prompt the operator to type 'yes' to append the entry to
exec-allowlist.json. On confirm, append atomically + exit non-zero
with a "re-run to execute" message — operator must re-run the
command manually (two-stage flow; no auto-execute).

Non-TTY callers (agents, pipes, scripts) see no prompt; hard-deny
exactly as v2.0. The v2.0 trust invariant — "agent can never widen
the allowlist" — holds because the prompt requires a TTY.

cmd/alice/main.go dispatcher gains a 3-line check so error
messages starting with "✓ " are printed without the "✗ " wrapping
but still trigger a non-zero exit (preserves &&-chaining semantics:
downstream commands do not run after an append-and-exit).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task EAC4: README — Daily-use mentions the prompt + install v2.1.0

**Files:**
- Modify: `README.md`

Three edits: Daily-use example mentions the prompt flow; Trust boundary appends a sentence about TTY-only; install snippet bump.

- [ ] **Step 1: Locate landmarks**

```sh
cd /Users/bbwave03/claude/anb
grep -n 'v2\.0\.0\|alice exec --env.*GH_TOKEN\|alice exec env values are same-uid' README.md
```

Identify line numbers for: Daily-use example, Trust boundary alice exec bullet, 5 install-snippet `v2.0.0` references.

- [ ] **Step 2: Update the Daily-use example**

Find the existing `alice exec --env 'GH_TOKEN=<agent-vault:gh-pat>'` block. Replace the surrounding comment to mention the prompt:

```sh
# v2.0.0+: alice exec is default-deny via ~/.anb/alice/exec-allowlist.json.
# `alice enroll` scaffolds an empty {"allow":[]} for you. To allow a new
# invocation: run it once. The deny error shows you the exact JSON
# triple to add. On a TTY (interactive operator), alice also prompts
# `Type 'yes' to confirm` — answering yes atomically appends the entry
# and exits with "re-run to execute"; you re-run the command manually.
# Non-TTY callers (agents, pipes) never see the prompt — hard-deny only.
#
# NOTE: single-quote --env values so the shell doesn't expand `<` / `>`.
alice exec --env 'GH_TOKEN=<agent-vault:gh-pat>' \
  -- /opt/homebrew/bin/gh api user
```

- [ ] **Step 3: Append to the Trust boundary "alice exec env" bullet**

Find the bullet starting with `**`alice exec` env values are same-uid visible.**`. Locate its final sentence (`...the trust boundary is "alice + the operator-blessed binaries + same-uid process access".`). Append:

```
 The TTY confirm-and-append flow added in v2.1 is operator-only — agents and pipes never reach the prompt, so the allowlist can only be widened by a human at the terminal.
```

(One sentence, appended to the same bullet.)

- [ ] **Step 4: Bump install snippet v2.0.0 → v2.1.0**

```sh
grep -c 'v2\.0\.0' README.md     # confirm count
sed -i '' 's/v2\.0\.0/v2.1.0/g' README.md
grep -c 'v2\.0\.0' README.md     # MUST be 0
grep -c 'v2\.1\.0' README.md     # MUST equal the pre-edit v2.0.0 count
```

(Linux: drop the `''`.)

This replaces ALL occurrences including the "since v2.0.0" mention in the Features bullet. That's fine — the bullet stays accurate semantically (default-deny started at v2.0.0; v2.1 just adds the prompt convenience).

Actually, wait — the Features bullet says "default-deny since v2.0.0". That sentence is historically correct: default-deny WAS introduced in v2.0. Bumping it to "since v2.1.0" would be wrong. Restore that one occurrence:

```sh
grep -n 'default-deny since v2\.1\.0' README.md
# If found, change back to v2.0.0:
sed -i '' 's/default-deny since v2\.1\.0/default-deny since v2.0.0/g' README.md
grep -n 'default-deny since' README.md   # should now show v2.0.0
```

- [ ] **Step 5: Verify rendering integrity**

```sh
grep -c '^```' README.md          # MUST be even
grep -c 'v2\.0\.0' README.md      # exactly 1 (the historical "since v2.0.0")
grep -c 'v2\.1\.0' README.md      # exactly 5 (install snippet only)
```

- [ ] **Step 6: Commit**

```sh
git add README.md
git commit -m "$(cat <<'EOF'
docs(readme): alice exec v2.1 confirm-and-append flow + install v2.1.0

- Daily-use example mentions the new TTY-only "type 'yes' to confirm"
  prompt as a faster alternative to the manual vim/paste workflow.
  Non-TTY behavior (agents, pipes) is unchanged — hard-deny.
- Trust boundary bullet for env-channel gets one appended sentence
  noting the prompt is operator-only (allowlist can only be widened
  by a human at the terminal).
- Install snippet bumped v2.0.0 → v2.1.0 (5 occurrences). The Features
  bullet's "default-deny since v2.0.0" historical reference preserved.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task EAC5: Operator smoke (USER, real TTY)

**Files:** None — operational verification.

Subagent cannot drive — the new prompt requires a real TTY. User runs in iTerm/Warp:

- [ ] **Step 1: Install fresh binaries**

```sh
cd /Users/bbwave03/claude/anb
go install ./cmd/bob ./cmd/alice
```

- [ ] **Step 2: No-match deny → "yes" → atomic append → re-run flow**

```sh
# Use an invocation NOT yet in your allowlist. Adjust env key name to
# force a no-match if your existing v2.0 allowlist already covers this.
alice exec --env 'WORLD=<agent-vault:n9euser>' -- /bin/sh -c 'echo "hello $WORLD"'
# Expected:
#   - existing deny output (cmd/args/env recap + copy-paste JSON)
#   - new prompt: "Append this entry to exec-allowlist.json? Type 'yes' to confirm [y/N]: "
#   - Type: yes
#   - "✓ appended entry to ~/.anb/alice/exec-allowlist.json — re-run your command to execute it"
#   - Exit non-zero (echo $? should print 1)
echo "exit was: $?"

# Now re-run the exact same command:
alice exec --env 'WORLD=<agent-vault:n9euser>' -- /bin/sh -c 'echo "hello $WORLD"'
# Expected:
#   - matches, audit hint "→ exec /bin/sh with env=[WORLD]"
#   - child stdout: "hello <plaintext>"
```

- [ ] **Step 3: Default-N path (just press Enter or type "y")**

```sh
# Use a different non-matching invocation.
alice exec --env 'FOO=<agent-vault:n9euser>' -- /bin/sh -c 'echo "got: $FOO"' 2>&1 | tail -5
# At the prompt: press Enter (empty) → exits with original deny error, no append.
# Verify the allowlist was NOT modified:
grep -c 'FOO' ~/.anb/alice/exec-allowlist.json
# Expected: 0
```

Repeat the same call, this time type `y` (single letter):

```sh
alice exec --env 'FOO=<agent-vault:n9euser>' -- /bin/sh -c 'echo "got: $FOO"' 2>&1 | tail -5
# At the prompt: type just "y" + Enter → should reject (only "yes" counts)
# Verify still not appended:
grep -c 'FOO' ~/.anb/alice/exec-allowlist.json
# Expected: 0
```

- [ ] **Step 4: Non-TTY path preserved (pipe stdin)**

```sh
# Pipe an empty stdin so it's NOT a TTY. The prompt MUST NOT fire.
alice exec --env 'PIPE_TEST=<agent-vault:n9euser>' -- /bin/sh -c 'echo "$PIPE_TEST"' < /dev/null 2>&1 | tail -5
# Expected: original deny output, NO interactive prompt, exit non-zero.
echo "exit was: $?"
```

This is the security-critical invariant: agents calling alice exec via pipe / non-TTY paths cannot widen the allowlist.

- [ ] **Step 5: Inspect the appended JSON**

```sh
cat ~/.anb/alice/exec-allowlist.json
```

Should show valid JSON with the entry from Step 2 (`WORLD` key, the echo command). MarshalIndent with 2-space indent — human-readable.

- [ ] **Step 6: No commit — operational only**

If anything misbehaves, fix the relevant prior task and amend its commit. Otherwise proceed to EAC6.

---

### Task EAC6: Final review + PR + v2.1.0 release

**Files:** None — release engineering.

- [ ] **Step 1: Full test suite + vet + fmt + branch sanity**

```sh
cd /Users/bbwave03/claude/anb
go test ./...
go vet ./...
gofmt -l .
git log --oneline main..HEAD
git diff --stat main..HEAD
```

All green/clean/silent.

- [ ] **Step 2: Dispatch the final branch-wide code reviewer**

Use the same pattern as v2.0's final reviewer: dispatch a `general-purpose` subagent with model `sonnet`, hand it this plan + the branch HEAD, ask for spec-coverage + quality findings (Critical / Important / Minor).

- [ ] **Step 3: Push branch + open PR**

```sh
git push -u origin feat/exec-allowlist-confirm
gh pr create --base main --head feat/exec-allowlist-confirm --title "feat(alice): exec deny offers TTY confirm-and-append flow (v2.1.0)" --body "$(cat <<'EOF'
## Summary

v2.0 introduced the default-deny allowlist and a copy-paste-JSON deny error. The operator workflow today is 5 steps: see deny, open editor, paste, save, re-run. v2.1 collapses that to **2 steps for the TTY case**: see deny + type `yes` → alice atomically appends the entry and exits with "re-run to execute" → operator re-runs.

Non-TTY callers (agents, pipes, scripts) get **exactly the v2.0 hard-deny** — no prompt, no append path. The v2.0 trust invariant ("agent can never widen the allowlist") is preserved because the prompt requires a TTY, which prompt-injected agents do not have.

Two deliberate friction choices:
- Confirmation word is the full word `yes` (case-insensitive). Single `y` does NOT count.
- After append, alice exits non-zero with "re-run your command to execute". No auto-execute — operator must re-issue the command. Preserves the two-stage flow + safe `&&`-chaining (downstream commands don't accidentally run after a confirm-and-append).

## Test Plan

- [x] `go test ./...` green (9 new unit tests: confirmAppend × 4, appendAllowEntry × 5)
- [x] `go vet ./...` clean
- [x] `gofmt -l .` silent
- [x] Operator smoke against live Bob daemon: confirm-and-append flow with `yes`, default-N with Enter, rejection of single `y`, non-TTY hard-deny preserved (via `< /dev/null`), atomic append produces valid JSON

## Version

**v2.1.0** — minor bump. No API or wire protocol changes; pure additive on top of v2.0.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 4: Squash-merge + tag v2.1.0 + GH release**

After PR approval:

```sh
gh pr merge <PR#> --squash --delete-branch --subject "feat(alice): exec deny offers TTY confirm-and-append flow (#<PR#>)" --body "<one-paragraph summary>"
git checkout main && git pull --ff-only
git tag -a v2.1.0 <merge-sha> -m "AnB v2.1.0 — alice exec deny offers TTY confirm-and-append"
git push origin v2.1.0
gh release create v2.1.0 --title "AnB v2.1.0 — alice exec confirm-and-append" --notes "<full release notes covering: UX improvement + TTY-only + 'yes' requirement + two-stage exit-non-zero rationale + agent-autonomy invariant preserved>"
```

---

## Self-Review

### Spec coverage check (against the brainstormed design)

- ✅ Default N — Task EAC1 (`confirmAppend` rejects everything except `"yes"`)
- ✅ Full word `yes` required (not `y`) — Task EAC1 (`TestConfirmAppendRejectsY`)
- ✅ TTY required (non-TTY = no prompt, hard-deny preserved) — Task EAC3 (gated on `term.StdinIsTTY()`)
- ✅ Atomic append via `localvault.Store.WriteFile` — Task EAC2
- ✅ After append, exit non-zero with "re-run to execute" — Task EAC3 (`✓` prefix on error message + dispatcher escape hatch)
- ✅ No auto-execute (two-stage flow) — Task EAC3 (`return ...` rather than fall through to the past-the-gate code)
- ✅ Daily-use docs the new prompt — Task EAC4
- ✅ Trust boundary mentions TTY-only — Task EAC4
- ✅ Install v2.0.0 → v2.1.0 — Task EAC4
- ✅ Operator smoke verifies all paths (yes / default-N / single-y rejected / non-TTY hard-deny) — Task EAC5

### Placeholder scan

No `TBD`, `TODO`, `implement later`, `add appropriate error handling`, or `similar to Task N` patterns. Every code-changing step shows the complete code. Every command has expected output documented.

### Type / signature consistency

- `confirmAppend(in io.Reader, out io.Writer) bool` — defined EAC1, called EAC3
- `appendAllowEntry(dir string, entry allowEntry) error` — defined EAC2, called EAC3
- `allowEntry` — pre-existing from v2.0
- `errAllowlistMissing` — pre-existing from v2.0, used in EAC2 return path

All consistent across tasks. No new types beyond what's listed.

### Known absent: in-process TTY-prompt e2e test

The new TTY prompt path can only be exercised end-to-end via a pty, which adds a dependency. Operator smoke (EAC5) provides the verification instead. Unit tests cover both helpers thoroughly; the integration "TTY → prompt fires" gap is bridged by the smoke. Acceptable trade-off for v2.1 patch-style release; if the prompt logic becomes more complex in a future iteration, introduce a pty test dep then.
