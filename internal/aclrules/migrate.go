package aclrules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// migrLegacyEntry mirrors the v2.x exec-allowlist.json entry shape.
type migrLegacyEntry struct {
	Label string   `json:"label,omitempty"`
	Cmd   string   `json:"cmd"`
	Args  []string `json:"args"`
	Env   []string `json:"env"`
}

type migrLegacyFile struct {
	Allow []migrLegacyEntry `json:"allow"`
}

// MigrateLegacy is a one-shot converter from v2.x exec-allowlist.json
// to v3.0 exec-allowlist.rules. If a .rules file already exists in
// dir, MigrateLegacy is a no-op (operator's hand-curated rules win).
// If a .json file exists and no .rules, MigrateLegacy:
//  1. Reads and parses the JSON.
//  2. For each entry, generates a literal-anchored regex line via
//     LiteralRule.
//  3. Writes a header comment + all generated lines atomically to
//     exec-allowlist.rules (0o600).
//  4. Renames the original .json to .json.bak.
//  5. Logs a one-line stderr note.
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
		return logAndReturn(fmt.Errorf("stat %s: %w", rulesPath, err))
	}

	body, err := os.ReadFile(jsonPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // nothing to migrate
		}
		return logAndReturn(fmt.Errorf("read %s: %w", jsonPath, err))
	}

	var legacy migrLegacyFile
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&legacy); err != nil {
		return logAndReturn(fmt.Errorf("parse %s: %w", jsonPath, err))
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
		return logAndReturn(fmt.Errorf("write %s: %w", tmpPath, err))
	}
	if err := os.Rename(tmpPath, rulesPath); err != nil {
		return logAndReturn(fmt.Errorf("rename %s -> %s: %w", tmpPath, rulesPath, err))
	}
	if err := os.Rename(jsonPath, bakPath); err != nil {
		return logAndReturn(fmt.Errorf("rename %s -> %s: %w", jsonPath, bakPath, err))
	}
	fmt.Fprintf(os.Stderr, "alice: migrated v2.x exec-allowlist.json → exec-allowlist.rules (%d rules). Original kept as exec-allowlist.json.bak.\n", len(legacy.Allow))
	return nil
}

// logAndReturn prints a one-line note to stderr and returns the error.
// Used by MigrateLegacy because the caller (main.go) discards the
// return value (best-effort migration); without this, a malformed
// .json would silently fail and the operator would only learn about
// it when alice exec hard-denies with "no allowlist rules".
func logAndReturn(err error) error {
	fmt.Fprintf(os.Stderr, "alice: migration failed: %v\n", err)
	return err
}
