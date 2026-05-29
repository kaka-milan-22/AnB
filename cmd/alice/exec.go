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
		if !envKeyRE.MatchString(name) {
			return nil, nil, fmt.Errorf("--env %q: KEY %q must match %s", e, name, envKeyRE)
		}
		entries = append(entries, envEntry{Name: name, Value: val})
		for _, m := range placeholderRE.FindAllStringSubmatch(val, -1) {
			keys[m[1]] = struct{}{}
		}
	}
	return entries, keys, nil
}
