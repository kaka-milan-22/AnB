package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/kaka-milan-22/AnB/v2/internal/localvault"
	"github.com/kaka-milan-22/AnB/v2/internal/redact"
	"github.com/kaka-milan-22/AnB/v2/internal/term"
)

// cmdShell — spawn an interactive sub-shell with --env values injected.
// Analogous to `aws-vault exec`. TTY-gated (stdin + stderr must both be
// terminals) instead of allowlisted: a human at the keyboard is the
// implicit authorization. Agents and pipes are structurally locked out
// because they can't fake a TTY pair.
//
// Default cmd: argv after "--" if given, otherwise [$SHELL] with /bin/sh
// fallback. The first element must be an absolute path (matches the
// `alice exec` invariant — keeps the audit trail meaningful).
//
// Sets ALICE_SHELL=1 in the child so operator rc files can mark the
// prompt ("you're in an alice-managed shell, don't paste pwds here").
//
// Audit reason defaults to "[shell]" when --reason isn't given.
func cmdShell(args []string) error {
	// Split alice flags from optional sub-shell argv at the first "--".
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	var aliceArgs, childArgv []string
	if sep < 0 {
		aliceArgs = args
		childArgv = nil
	} else {
		aliceArgs = args[:sep]
		childArgv = args[sep+1:]
	}

	fs := newFS("shell")
	dir := dirFlag(fs)
	var envs envFlagValue
	fs.Var(&envs, "env", "KEY=VALUE for the child; VALUE may contain <agent-vault:key> placeholders (repeatable)")
	reasonFlag := fs.String("reason", "", `audit-only "why" string; logged in Bob's ALLOW line. Defaults to "[shell]".`)
	if err := fs.Parse(aliceArgs); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional args before --: %v (put sub-shell args after --)", fs.Args())
	}

	// TTY-gate: both stdin (for the shell) and stderr (for prompts /
	// status). If either is redirected, the operator isn't really
	// "at the keyboard" — refuse and point them at alice exec.
	if !term.StdinIsTTY() || !term.IsTTY(os.Stderr) {
		return fmt.Errorf("alice shell requires both stdin and stderr to be interactive terminals " +
			"(non-TTY callers should use `alice exec` with an allowlist entry)")
	}

	parsed, keySet, err := parseEnvFlag(envs.vals)
	if err != nil {
		return err
	}

	// Resolve sub-shell cmd path. Default to $SHELL with /bin/sh fallback.
	if len(childArgv) == 0 {
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
		childArgv = []string{shell}
	}
	cmdName := childArgv[0]
	if !filepath.IsAbs(cmdName) {
		// Resolve via PATH but require we end up with an absolute path
		// (consistent with alice exec — audit logs always carry abs paths).
		resolved, lerr := exec.LookPath(cmdName)
		if lerr != nil {
			return fmt.Errorf("shell lookup %q: %w", cmdName, lerr)
		}
		cmdName = resolved
		childArgv[0] = resolved
	}

	// Fetch + decrypt referenced vault keys (same shape as alice exec).
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
				return fmt.Errorf("vault has no key %q (--env references it but it's not stored — refusing to spawn shell)", k)
			}
			keys = append(keys, k)
			packed = append(packed, e.Value)
		}
		cl, _, cerr := loadClient(s)
		if cerr != nil {
			return cerr
		}
		reason := *reasonFlag
		if reason == "" {
			reason = "[shell]"
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

	// Build the child's env: resolved --env entries + parent env + the
	// ALICE_SHELL marker.
	resolved := make([]string, 0, len(parsed)+1)
	overridden := make(map[string]struct{}, len(parsed)+1)
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
	resolved = append(resolved, "ALICE_SHELL=1")
	overridden["ALICE_SHELL"] = struct{}{}

	merged := mergeEnv(resolved, overridden, os.Environ())

	envNames := make([]string, 0, len(parsed))
	for _, p := range parsed {
		envNames = append(envNames, p.Name)
	}
	fmt.Fprintf(os.Stderr, "→ shell %s with env=%v (set ALICE_SHELL=1)\n", cmdName, envNames)

	return syscall.Exec(cmdName, childArgv, merged)
}
