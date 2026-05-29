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
			return nil, nil, fmt.Errorf("--env %q: KEY %q must match %s", e, name, envKeyRE.String())
		}
		entries = append(entries, envEntry{Name: name, Value: val})
		for _, m := range placeholderRE.FindAllStringSubmatch(val, -1) {
			keys[m[1]] = struct{}{}
		}
	}
	return entries, keys, nil
}

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
