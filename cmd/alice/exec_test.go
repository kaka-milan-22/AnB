package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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

func TestParseEnvFlagEmptyInput(t *testing.T) {
	entries, keys, err := parseEnvFlag(nil)
	if err != nil {
		t.Fatalf("nil input: err=%v want nil", err)
	}
	if len(entries) != 0 {
		t.Fatalf("nil input: entries=%v want empty", entries)
	}
	if len(keys) != 0 {
		t.Fatalf("nil input: keys=%v want empty", keys)
	}
	// And empty-slice should be equivalent.
	entries, keys, err = parseEnvFlag([]string{})
	if err != nil || len(entries) != 0 || len(keys) != 0 {
		t.Fatalf("empty slice: entries=%v keys=%v err=%v", entries, keys, err)
	}
}

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

func TestParseEnvFlagRejectsEmptyValue(t *testing.T) {
	_, _, err := parseEnvFlag([]string{"KEY="})
	if err == nil {
		t.Fatal("expected error for empty VALUE")
	}
	if !strings.Contains(err.Error(), "VALUE may not be empty") {
		t.Fatalf("error message should mention empty VALUE; got: %v", err)
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

func TestLoadAllowlistRejectsMissingCmd(t *testing.T) {
	dir := t.TempDir()
	// cmd field omitted entirely; Go zero-values it to "".
	body := `{"allow":[{"args":["x"],"env":[]}]}`
	if err := os.WriteFile(filepath.Join(dir, "exec-allowlist.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadAllowlist(dir)
	if err == nil {
		t.Fatal("expected error for missing cmd field")
	}
	if !strings.Contains(err.Error(), "missing or empty") {
		t.Fatalf("error should call out missing/empty cmd; got: %v", err)
	}
}

func TestLoadAllowlistAcceptsEmptyAllow(t *testing.T) {
	// {"allow":[]} is the scaffolded default; must parse cleanly so cmdExec
	// can hand it to matchAllowlist (which returns nil for any invocation).
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "exec-allowlist.json"), []byte(`{"allow":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := loadAllowlist(dir)
	if err != nil {
		t.Fatalf("loadAllowlist on empty allow: %v", err)
	}
	if len(list.Allow) != 0 {
		t.Fatalf("expected empty Allow, got %v", list.Allow)
	}
}

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
	// all return false. Note: "yes\nmore\n" is NOT included here because
	// bufio.ReadString('\n') reads only the first line ("yes\n"), so the
	// result is true — consistent with the spec implementation.
	for _, input := range []string{"\n", "", "no\n", "yes please\n"} {
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
