package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/kaka-milan-22/AnB/internal/localvault"
	"github.com/kaka-milan-22/AnB/internal/redact"
	"github.com/kaka-milan-22/AnB/internal/term"
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

// matchAllowlist returns the first entry in list.Allow whose cmd, args,
// and env-key set exactly match the invocation, or nil if no entry
// matches. Strict byte-for-byte equality on cmd and on each args
// position; envKeys treated as a set (order-independent), exact
// membership equality.
func matchAllowlist(cmd string, args, envKeys []string, list *allowlist) *allowEntry {
	for i, e := range list.Allow {
		if e.Cmd != cmd {
			continue
		}
		if len(e.Args) != len(args) {
			continue
		}
		argsOK := true
		for j := range args {
			if args[j] != e.Args[j] {
				argsOK = false
				break
			}
		}
		if !argsOK {
			continue
		}
		if len(e.Env) != len(envKeys) {
			continue
		}
		a := slices.Clone(envKeys)
		b := slices.Clone(e.Env)
		slices.Sort(a)
		slices.Sort(b)
		if !slices.Equal(a, b) {
			continue
		}
		return &list.Allow[i]
	}
	return nil
}

// formatDenyJSON produces a 2-space-indented JSON entry the operator
// can paste verbatim into allow[] in exec-allowlist.json. envKeys is
// sorted so identical invocations produce identical suggestions
// (operator can grep their allowlist for the entry without map-order
// flakiness).
func formatDenyJSON(cmd string, args, envKeys []string) string {
	argsJSON, _ := json.Marshal(args)
	envSorted := slices.Clone(envKeys)
	slices.Sort(envSorted)
	envJSON, _ := json.Marshal(envSorted)
	return fmt.Sprintf("  {\n    \"cmd\":  %q,\n    \"args\": %s,\n    \"env\":  %s\n  }",
		cmd, argsJSON, envJSON)
}

// mustMarshalJSON returns the JSON encoding of v; intended for inputs
// that cannot fail (string slices). Used inside the deny error to embed
// the "cmd:" "args:" "env:" recap that mirrors what would go into the
// allowlist file.
func mustMarshalJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// sortedStringSlice returns a fresh sorted copy of a slice. Used by the
// deny error to print env names in a stable order.
func sortedStringSlice(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// envFlagValue is a flag.Value that accumulates repeated --env occurrences.
type envFlagValue struct{ vals []string }

func (e *envFlagValue) String() string     { return strings.Join(e.vals, ",") }
func (e *envFlagValue) Set(v string) error { e.vals = append(e.vals, v); return nil }

// cmdExec — agent-safe execution path. Requires a strict (cmd, args,
// env-key-set) match against ~/.anb/alice/exec-allowlist.json (v2.0+).
// Denied invocations fail before any vault I/O or mTLS connection.
// Matched invocations resolve <agent-vault:k> placeholders inside --env
// values via Bob (mTLS DecryptMany), build the child's env with
// explicit dedup, then syscall.Exec the child. alice's process image is
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

	// Parse --env flags. Empty VALUE is rejected here (see EA1).
	parsed, keySet, err := parseEnvFlag(envs.vals)
	if err != nil {
		return err
	}

	// Allowlist gate (v2.0+). cmd + args after "--" plus the SET of --env
	// KEY names are matched against ~/.anb/alice/exec-allowlist.json.
	// Default-deny: missing file → init hint; no match → copy-paste-ready
	// JSON in the error. Runs BEFORE vault lookup / Bob round-trip — a
	// denied invocation never opens an mTLS connection.
	cmdName := childArgv[0]
	childArgs := childArgv[1:]
	envNames := make([]string, 0, len(parsed))
	for _, p := range parsed {
		envNames = append(envNames, p.Name)
	}

	if !filepath.IsAbs(cmdName) {
		return fmt.Errorf("alice exec: cmd %q must be an absolute path "+
			"(e.g. /opt/homebrew/bin/curl); see ~/.anb/alice/exec-allowlist.json", cmdName)
	}

	s := localvault.Open(*dir)
	list, err := loadAllowlist(s.Dir)
	if err != nil {
		if errors.Is(err, errAllowlistMissing) {
			return fmt.Errorf("%s/exec-allowlist.json not found.\n\n"+
				"alice exec is default-deny since v2.0.0. To enable any invocation,\n"+
				"the allowlist file must exist (even if empty).\n\n"+
				"Initialize with:\n"+
				"    echo '{\"allow\":[]}' > %s/exec-allowlist.json\n\n"+
				"Then re-run your alice exec command; the error will give you the\n"+
				"exact triple to append.",
				s.Dir, s.Dir)
		}
		return err
	}

	if matchAllowlist(cmdName, childArgs, envNames, list) == nil {
		denyMsg := fmt.Sprintf("alice exec: invocation not in allowlist.\n\n"+
			"  cmd:  %s\n"+
			"  args: %s\n"+
			"  env:  %s\n\n"+
			"To allow exactly this invocation, append to allow[] in\n"+
			"%s/exec-allowlist.json:\n\n"+
			"%s\n\n"+
			"Note: strict byte-for-byte equality on cmd, args (each position),\n"+
			"and env name set. Any change — extra whitespace, different arg\n"+
			"position, extra/missing env name — requires a new entry.\n"+
			"Wildcards are not supported.",
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

	// Past the gate — proceed with vault lookup, decrypt, restore, exec.
	plaintexts := map[string]string{}
	if len(keySet) > 0 {
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

	resolved := make([]string, 0, len(parsed))
	overridden := make(map[string]struct{}, len(parsed))
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
	}

	merged := mergeEnv(resolved, overridden, os.Environ())

	cmdPath, err := exec.LookPath(cmdName)
	if err != nil {
		return fmt.Errorf("exec lookup %q: %w", cmdName, err)
	}

	fmt.Fprintf(os.Stderr, "→ exec %s with env=%v\n", cmdPath, envNames)

	return syscall.Exec(cmdPath, childArgv, merged)
}

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

// confirmAppend prints a "type 'yes' to confirm" prompt to out and reads
// one line from in. Returns true iff the trimmed-lowercase input is
// exactly "yes" — a single "y" does NOT count, deliberately, because the
// caller's next action (appending to the allowlist + signalling
// "operator approved") deserves two friction characters more than the
// reflex-key "y".
//
// Caller must ensure no further reads from in occur after this call:
// the internal bufio.Reader may have consumed bytes beyond the first
// newline (read-ahead). In cmdExec the caller exits the process via
// the dispatcher immediately after either branch (append or deny),
// so no subsequent stdin read happens.
func confirmAppend(in io.Reader, out io.Writer) bool {
	fmt.Fprint(out, "\nAppend this entry to exec-allowlist.json? Type 'yes' to confirm [y/N]: ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	return strings.ToLower(strings.TrimSpace(line)) == "yes"
}
