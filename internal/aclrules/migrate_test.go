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
	got, _ := os.ReadFile(filepath.Join(dir, "exec-allowlist.rules"))
	if string(got) != string(rulesBefore) {
		t.Errorf(".rules should be untouched when present; got %q", got)
	}
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
	if err := MigrateLegacy(dir); err != nil {
		t.Errorf("re-run after migration should be no-op: %v", err)
	}
}
