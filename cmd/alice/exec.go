package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/kaka-milan-22/AnB/internal/localvault"
	"github.com/kaka-milan-22/AnB/internal/redact"
)

// envEntry is one parsed --env flag: a POSIX env name and its (possibly
// placeholder-containing) value.
type envEntry struct {
	Name  string
	Value string
}

// parseEnvFlag validates each raw --env entry (KEY=VALUE form, POSIX KEY)
// and collects the set of vault keys referenced via <agent-vault:k>
// placeholders in any VALUE. Pure function — no I/O, no decryption.
// Delegates placeholder extraction to redact.ExtractPlaceholders so the
// regex lives in one place (no risk of drift if the placeholder grammar
// ever changes).
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

// loadAllowlist reads and validates exec-allowlist.json from the given
// state dir. Returns errAllowlistMissing if the file does not exist.
// Validates each entry: cmd must be an absolute path, env names must
// match POSIX env-var syntax. Strict JSON parsing (DisallowUnknownFields)
// so typos like "cmm:" or "arsg:" fail loud at load time.
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
		if e.Cmd == "" {
			return nil, fmt.Errorf("exec-allowlist.json: entry %d cmd is missing or empty (field \"cmd\" required)", i)
		}
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

	merged := mergeEnv(resolved, overridden, os.Environ())

	cmdPath, err := exec.LookPath(childArgv[0])
	if err != nil {
		return fmt.Errorf("exec lookup %q: %w", childArgv[0], err)
	}

	// Audit hint to operator's stderr — key NAMES only, never plaintext.
	fmt.Fprintf(os.Stderr, "→ exec %s with env=%v\n", cmdPath, envNames)

	// syscall.Exec replaces alice's process image; the plaintexts in alice's
	// heap are discarded by the kernel. fds 0/1/2 are inherited by the child.
	return syscall.Exec(cmdPath, childArgv, merged)
}
