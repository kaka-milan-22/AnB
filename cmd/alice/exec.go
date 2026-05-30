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
	"strings"
	"syscall"
	"time"

	"github.com/kaka-milan-22/AnB/v3/internal/aclrules"
	"github.com/kaka-milan-22/AnB/v3/internal/localvault"
	"github.com/kaka-milan-22/AnB/v3/internal/redact"
	"github.com/kaka-milan-22/AnB/v3/internal/term"
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
		// Fail-closed on near-miss placeholders. A value like `<my-key>` looks
		// like a vault reference but doesn't match the strict
		// `<agent-vault:KEY>` grammar — without this check it would slip
		// through as a literal string and confuse the child process (the
		// classic symptom: a downstream tool reports the env value is the
		// wrong format because it received the literal `<my-key>` instead
		// of the resolved secret).
		if bad := redact.FindSuspiciousPlaceholders(val); len(bad) > 0 {
			first := bad[0]
			inner := first[1 : len(first)-1] // strip `<` and `>`
			if keyFormat.MatchString(inner) {
				return nil, nil, fmt.Errorf(
					"--env %q: value contains %q which looks like a placeholder but is missing the `agent-vault:` prefix. Did you mean `<agent-vault:%s>`?",
					e, first, inner)
			}
			return nil, nil, fmt.Errorf(
				"--env %q: value contains %q which looks like a placeholder but doesn't match the `<agent-vault:KEY>` grammar (valid KEY is lowercase alphanumeric + hyphens)",
				e, first)
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

// errExecDenied signals "operator declined the TTY confirm-and-append
// prompt; the deny output was already printed before the prompt, so
// do not print anything else". The dispatcher in main.go recognizes
// this sentinel and exits non-zero silently. Without it, the
// dispatcher would re-print the deny message a second time after the
// operator had already read it once.
var errExecDenied = errors.New("alice exec: declined")

// envFlagValue is a flag.Value that accumulates repeated --env occurrences.
type envFlagValue struct{ vals []string }

func (e *envFlagValue) String() string     { return strings.Join(e.vals, ",") }
func (e *envFlagValue) Set(v string) error { e.vals = append(e.vals, v); return nil }

// cmdExec — agent-safe execution path. Requires a regex match against
// ~/.anb/alice/exec-allowlist.rules (v3.0+). Denied invocations fail
// before any vault I/O or mTLS connection. Matched invocations resolve
// <agent-vault:k> placeholders inside --env values via Bob (mTLS
// DecryptMany), build the child's env with explicit dedup, then
// syscall.Exec the child. alice's process image is replaced; alice's
// heap (with the plaintexts) is discarded by the kernel; alice's
// stdout/stderr/stdin fds are inherited by the child.
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
	reasonFlag := fs.String("reason", "", `audit-only "why" string; logged in Bob's ALLOW line. If unset, a matched allowlist entry's label (if any) is used as "[label]".`)
	showMatchString := fs.Bool("show-match-string", false,
		"print the canonical match string used by exec-allowlist.rules and exit (no execution)")
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

	// Allowlist gate (v3.0+). cmd + args after "--" plus the SET of --env
	// KEY names are matched against ~/.anb/alice/exec-allowlist.rules.
	// Default-deny: missing file → init hint; no match → copy-paste-ready
	// rule line in the error. Runs BEFORE vault lookup / Bob round-trip — a
	// denied invocation never opens an mTLS connection.
	cmdName := childArgv[0]
	childArgs := childArgv[1:]

	if *showMatchString {
		fmt.Println(showMatchStringOutput(cmdName, childArgs))
		return nil
	}

	envNames := make([]string, 0, len(parsed))
	for _, p := range parsed {
		envNames = append(envNames, p.Name)
	}

	if !filepath.IsAbs(cmdName) {
		return fmt.Errorf("alice exec: cmd %q must be an absolute path "+
			"(e.g. /opt/homebrew/bin/curl); see exec-allowlist.rules", cmdName)
	}

	s := localvault.Open(*dir)

	rulesPath := filepath.Join(s.Dir, "exec-allowlist.rules")
	rules, err := aclrules.LoadFile(rulesPath)
	if err != nil {
		if errors.Is(err, aclrules.ErrRulesMissing) {
			hint := fmt.Sprintf("alice exec: no allowlist rules.\n"+
				"  Create %s to bless commands.\n"+
				"  Run any command to see the auto-bless prompt (TTY required)",
				rulesPath)
			// If a legacy .json (or its .bak) exists in the state dir, the
			// operator likely hit a migration failure. Surface a targeted hint
			// rather than telling them to "create the file" (which won't help).
			if _, statErr := os.Stat(filepath.Join(s.Dir, "exec-allowlist.json")); statErr == nil {
				hint += fmt.Sprintf("\n\n  NOTE: %s/exec-allowlist.json exists but did not migrate cleanly.\n"+
					"  Run 'alice list' to see the migration error; fix the JSON or remove\n"+
					"  the .json file to start fresh.",
					s.Dir)
			} else if _, statErr := os.Stat(filepath.Join(s.Dir, "exec-allowlist.json.bak")); statErr == nil {
				hint += fmt.Sprintf("\n\n  NOTE: %s/exec-allowlist.json.bak exists but no .rules file was found.\n"+
					"  The migration ran but .rules may have been removed. Re-run 'alice migrate'\n"+
					"  or manually restore from the .bak file.",
					s.Dir)
			}
			return fmt.Errorf("%s", hint)
		}
		return err
	}

	matchStr := aclrules.Canonicalize(cmdName, childArgs)

	var matched *aclrules.Rule
	for i := range rules {
		if rules[i].Matches(matchStr, envNames) {
			matched = &rules[i]
			break
		}
	}

	if matched == nil {
		denyMsg := buildDenyMsgV3(rulesPath, cmdName, childArgs, envNames)

		// TTY-only convenience: offer to append the entry now. Non-TTY
		// callers (agents, pipes) get the hard-deny exactly as before.
		// Require BOTH stdin AND stderr to be TTYs — otherwise the prompt
		// is invisible (stderr redirected) or unanswerable (stdin piped),
		// and the operator would be typing into a black hole.
		if term.StdinIsTTY() && term.IsTTY(os.Stderr) {
			fmt.Fprintln(os.Stderr, denyMsg)
			if confirmAppend(os.Stdin, os.Stderr) {
				line := aclrules.LiteralRule(cmdName, childArgs, envNames,
					"auto-blessed "+timeNowRFC3339())
				if err := appendRuleLine(rulesPath, line); err != nil {
					return fmt.Errorf("append rule: %w", err)
				}
				return fmt.Errorf("✓ appended rule to %s — re-run your command to execute it",
					rulesPath)
			}
			// Operator declined — denyMsg already on stderr (above), so
			// return the silent sentinel: dispatcher exits non-zero
			// without printing a second copy of the deny output.
			return errExecDenied
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
		// Operator-supplied --reason wins; otherwise fall back to the
		// matched entry's label (formatted as "[label]" so audit consumers
		// can tell at a glance it came from the allowlist, not the caller).
		reason := *reasonFlag
		if reason == "" && matched.Label != "" {
			reason = "[" + matched.Label + "]"
		}
		cl.SetReason(reason)
		pts, rewraps, derr := cl.DecryptMany(keys, packed)
		if derr != nil {
			return derr
		}
		if _, werr := applyRewraps(s, keys, rewraps); werr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to write back rewrapped entries: %v\n", werr)
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

	fmt.Fprintln(os.Stderr, formatAuditLine(cmdPath, envNames, matched))

	return syscall.Exec(cmdPath, childArgv, merged)
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
	fmt.Fprint(out, "\nAppend this entry to exec-allowlist.rules? Type 'yes' to confirm [y/N]: ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	return strings.ToLower(strings.TrimSpace(line)) == "yes"
}

// formatAuditLine builds the "→ exec ..." stderr message for a matched
// invocation. Surfaces the matched rule's audit label if set, falls
// back to its line number for traceability.
func formatAuditLine(cmdPath string, envNames []string, matched *aclrules.Rule) string {
	if matched.Label != "" {
		return fmt.Sprintf("→ exec %s with env=%v rule=[%s]", cmdPath, envNames, matched.Label)
	}
	return fmt.Sprintf("→ exec %s with env=%v rule=line:%d", cmdPath, envNames, matched.LineNo)
}

// timeNowRFC3339 wraps time.Now().UTC().Format(time.RFC3339) for the
// auto-bless label timestamp.
func timeNowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// showMatchStringOutput returns the canonical (shellescape + space-join)
// form of an invocation — the exact string that rule regexes are tested
// against. Tiny wrapper around aclrules.Canonicalize so the
// --show-match-string flag can be unit-tested without spinning up the
// full flag-parse path.
func showMatchStringOutput(cmd string, args []string) string {
	return aclrules.Canonicalize(cmd, args)
}

// appendRuleLine appends a single newline-terminated rule line to the
// rules file. Creates the file with mode 0o600 if it does not exist
// (with a header comment so first-write looks operator-friendly).
//
// Concurrency note: O_CREATE|O_APPEND|O_WRONLY opens (or creates) the
// file in a single syscall. POSIX O_APPEND guarantees per-write
// atomicity on Linux and APFS, so two simultaneous appends produce two
// intact lines (in some order) without interleaving. The header is
// written only when Stat reports size==0 after open, which is
// substantially narrower than the previous Stat→WriteFile→OpenFile
// sequence. Two concurrent creators might both see size==0 and each
// write a header; that produces duplicate headers but no rule loss —
// the parser skips comment lines and the file remains loadable. For
// AnB's single-operator threat model this is sufficient.
func appendRuleLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() == 0 {
		header := `# AnB exec-allowlist rules. One rule per line:
#   <regex>\t<env-csv>\t#<label>
# All fields after the first are optional. Implicit ^...$ anchor.
# Default deny: unmatched invocations are rejected.

`
		if _, err := f.WriteString(header); err != nil {
			return err
		}
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		return err
	}
	return nil
}

// buildDenyMsgV3 formats the deny message for v3.0 — shows the literal
// rule line the operator would paste (regex form, not JSON).
func buildDenyMsgV3(rulesPath, cmd string, args, envNames []string) string {
	suggestion := aclrules.LiteralRule(cmd, args, envNames, "")
	argsRender, _ := json.Marshal(args)
	envRender, _ := json.Marshal(envNames)
	return fmt.Sprintf("alice exec: invocation not in allowlist.rules.\n\n"+
		"  cmd:  %s\n"+
		"  args: %s\n"+
		"  env:  %s\n\n"+
		"To allow exactly this invocation, append to %s:\n\n"+
		"  %s\n\n"+
		"(This is a fully-escaped LITERAL regex. Edit by hand to add wildcards.)",
		cmd, argsRender, envRender, rulesPath, suggestion)
}
