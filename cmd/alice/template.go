package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kaka-milan-22/AnB/v2/internal/localvault"
	"github.com/kaka-milan-22/AnB/v2/internal/redact"
)

// template <src> <dst> — render <src>'s <agent-vault:k> placeholders into
// <dst> with explicit mode (and optional owner). Deploy-style sibling of
// `alice write`: where `write` is a pipe-friendly stdin→file convenience,
// `template` is "source file → target path with the perms you want".
// Atomic write (tmp + rename) so a half-written secrets file never appears.
//
// Human-only (TTY required) — writes plaintext secrets to disk; the same
// rationale that gates `alice set`. --owner usually needs root, which is
// another reason an operator should be present.
func cmdTemplate(args []string) error {
	fs := newFS("template")
	dir := dirFlag(fs)
	modeFlag := fs.String("mode", "0600", `octal mode for the rendered file (default 0600 — secrets-safe)`)
	ownerFlag := fs.String("owner", "", `chown the result to "user:group" (e.g. "myapp:myapp" or "501:20"); requires root`)
	reason := fs.String("reason", "", `audit-only "why"; logged in Bob's ALLOW line`)
	pos := parse(fs, args)
	if len(pos) != 2 {
		return fmt.Errorf("usage: alice template <src> <dst> [--mode 0600] [--owner u:g] [--reason R]")
	}
	src, dst := pos[0], pos[1]

	requireTTY("alice template")

	mode, err := parseOctalMode(*modeFlag)
	if err != nil {
		return err
	}
	uid, gid, doChown, err := parseOwner(*ownerFlag)
	if err != nil {
		return err
	}

	srcBytes, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	srcText := string(srcBytes)

	// Pull only the placeholders this template needs (avoids decrypting the
	// whole vault when the file references one key).
	keys := redact.ExtractPlaceholders(srcText)
	plaintexts := map[string]string{}
	if len(keys) > 0 {
		s := localvault.Open(*dir)
		v, lerr := s.Load()
		if lerr != nil {
			return lerr
		}
		packed := make([]string, 0, len(keys))
		known := make([]string, 0, len(keys))
		for _, k := range keys {
			e, ok := v.Get(k)
			if !ok {
				return fmt.Errorf("vault has no key %q referenced by %s — refusing to render", k, src)
			}
			known = append(known, k)
			packed = append(packed, e.Value)
		}
		cl, _, cerr := loadClient(s)
		if cerr != nil {
			return cerr
		}
		cl.SetReason(*reason)
		pts, derr := cl.DecryptMany(known, packed)
		if derr != nil {
			return derr
		}
		for i, k := range known {
			plaintexts[k] = pts[i]
		}
	}

	rr := redact.Restore(srcText, func(k string) (string, bool) {
		pt, ok := plaintexts[k]
		return pt, ok
	})
	if len(rr.Missing) > 0 {
		return fmt.Errorf("unresolved placeholders in %s: %v", src, rr.Missing)
	}

	if err := atomicWriteFile(dst, []byte(rr.Content), mode); err != nil {
		return err
	}
	if doChown {
		if err := os.Chown(dst, uid, gid); err != nil {
			return fmt.Errorf("chown %s to %d:%d: %w (typically requires root)", dst, uid, gid, err)
		}
	}

	fmt.Fprintf(os.Stderr, "✓ Rendered %s → %s (%d placeholder%s restored, mode %s)\n",
		src, dst, len(rr.Restored), plural(len(rr.Restored)), *modeFlag)
	return nil
}

// parseOctalMode parses an octal mode string like "0600" / "640" into
// os.FileMode. Empty input is an error; rejecting it forces the operator
// to think about file perms instead of inheriting a default that bites.
func parseOctalMode(s string) (os.FileMode, error) {
	if s == "" {
		return 0, fmt.Errorf("--mode is required (e.g. 0600)")
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("--mode %q: not an octal number (e.g. 0600 / 640)", s)
	}
	if n > 0o7777 {
		return 0, fmt.Errorf("--mode %q: too large (max 7777)", s)
	}
	return os.FileMode(n), nil
}

// parseOwner accepts "user:group" / "uid:gid" / "" (no chown).
func parseOwner(s string) (uid, gid int, do bool, err error) {
	if s == "" {
		return 0, 0, false, nil
	}
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, 0, false, fmt.Errorf(`--owner %q: expected "user:group" or "uid:gid"`, s)
	}
	uid, err = resolveUID(parts[0])
	if err != nil {
		return 0, 0, false, err
	}
	gid, err = resolveGID(parts[1])
	if err != nil {
		return 0, 0, false, err
	}
	return uid, gid, true, nil
}

func resolveUID(s string) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	u, err := user.Lookup(s)
	if err != nil {
		return 0, fmt.Errorf("--owner user %q: %w", s, err)
	}
	n, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, fmt.Errorf("--owner: user %q has non-numeric uid %q", s, u.Uid)
	}
	return n, nil
}

func resolveGID(s string) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	g, err := user.LookupGroup(s)
	if err != nil {
		return 0, fmt.Errorf("--owner group %q: %w", s, err)
	}
	n, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("--owner: group %q has non-numeric gid %q", s, g.Gid)
	}
	return n, nil
}

// atomicWriteFile writes data to path via a temp file + rename, then
// forces the mode (defends against umask stripping bits). The temp file
// is created in the same directory so the rename is on one filesystem.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".alice-template-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best-effort: if rename succeeded, this Remove fails harmlessly.
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmpName, path, err)
	}
	return nil
}
