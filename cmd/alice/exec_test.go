package main

import (
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
