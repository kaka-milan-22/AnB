package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kaka-milan-22/AnB/v2/internal/aclrules"
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
	if len(entries) != len(wantEntries) {
		t.Fatalf("entries len = %d want %d", len(entries), len(wantEntries))
	}
	for i := range entries {
		if entries[i] != wantEntries[i] {
			t.Fatalf("entries[%d]: got %v want %v", i, entries[i], wantEntries[i])
		}
	}
	gotKeys := sortedKeys(keys)
	wantKeys := []string{"db-pw", "openai-key"}
	if len(gotKeys) != len(wantKeys) {
		t.Fatalf("keys: got %v want %v", gotKeys, wantKeys)
	}
	for i := range gotKeys {
		if gotKeys[i] != wantKeys[i] {
			t.Fatalf("keys[%d]: got %q want %q", i, gotKeys[i], wantKeys[i])
		}
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

func TestShowMatchStringFlag(t *testing.T) {
	got := showMatchStringOutput("/Users/bbwave03/.local/bin/encipherr",
		[]string{"encrypt", "file", "/tmp/has space.txt"})
	want := "/Users/bbwave03/.local/bin/encipherr encrypt file '/tmp/has space.txt'"
	if got != want {
		t.Errorf("got %q want %q", got, want)
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

func TestAuditLineWithLabel(t *testing.T) {
	got := formatAuditLine("/bin/echo", []string{"KEY"}, &aclrules.Rule{Label: "test label", LineNo: 42})
	if !strings.Contains(got, "rule=[test label]") {
		t.Errorf("expected label; got %q", got)
	}
	if !strings.Contains(got, "/bin/echo") {
		t.Errorf("expected cmd path; got %q", got)
	}
	if !strings.Contains(got, "env=[KEY]") {
		t.Errorf("expected env list; got %q", got)
	}
}

func TestAuditLineWithoutLabel(t *testing.T) {
	got := formatAuditLine("/bin/echo", []string{"KEY"}, &aclrules.Rule{LineNo: 42})
	if !strings.Contains(got, "rule=line:42") {
		t.Errorf("expected line number; got %q", got)
	}
}

func TestAuditLineEmptyEnv(t *testing.T) {
	got := formatAuditLine("/bin/echo", nil, &aclrules.Rule{Label: "no-env", LineNo: 1})
	if !strings.Contains(got, "rule=[no-env]") {
		t.Errorf("expected label; got %q", got)
	}
	if !strings.Contains(got, "env=[]") {
		t.Errorf("expected empty env list rendering; got %q", got)
	}
}
