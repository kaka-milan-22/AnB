package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Unit tests for the pure pieces of cmdTemplate. The full network path
// (DecryptMany via Bob) is covered by the cmd/alice e2e harness; here
// we pin the file-system / mode / parse behavior so refactors don't drift.

func TestParseOctalMode(t *testing.T) {
	cases := []struct {
		in   string
		want os.FileMode
		err  bool
	}{
		{"0600", 0o600, false},
		{"600", 0o600, false},
		{"0640", 0o640, false},
		{"0755", 0o755, false},
		{"", 0, true},
		{"0888", 0, true}, // not octal
		{"10000", 0, true},
	}
	for _, c := range cases {
		got, err := parseOctalMode(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parseOctalMode(%q): want error, got mode %o", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseOctalMode(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseOctalMode(%q) = %o, want %o", c.in, got, c.want)
		}
	}
}

func TestParseOwnerEmpty(t *testing.T) {
	uid, gid, do, err := parseOwner("")
	if err != nil || do || uid != 0 || gid != 0 {
		t.Fatalf("empty --owner: want (0,0,false,nil), got (%d,%d,%v,%v)", uid, gid, do, err)
	}
}

func TestParseOwnerNumeric(t *testing.T) {
	uid, gid, do, err := parseOwner("501:20")
	if err != nil {
		t.Fatalf("parseOwner: %v", err)
	}
	if !do || uid != 501 || gid != 20 {
		t.Fatalf("got (uid=%d gid=%d do=%v)", uid, gid, do)
	}
}

func TestParseOwnerMalformed(t *testing.T) {
	for _, s := range []string{":g", "u:", ":", "u"} {
		if _, _, _, err := parseOwner(s); err == nil {
			t.Errorf("parseOwner(%q): expected error", s)
		}
	}
}

// atomicWriteFile + the mode arg are the load-bearing security promise of
// `alice template` (rendered secrets must be 0600 by default and the
// write must be atomic so partial files don't appear). Test both.
func TestAtomicWriteFilePreservesMode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.env")
	body := []byte("TOKEN=v3rys3cret\n")
	if err := atomicWriteFile(target, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("content mismatch")
	}
	st, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", st.Mode().Perm())
	}
}

func TestAtomicWriteFileNoTempLeftover(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.env")
	if err := atomicWriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "out.env" {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected only out.env after atomicWriteFile, got %v", names)
	}
}

func TestAtomicWriteFileOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.env")
	if err := os.WriteFile(target, []byte("OLD\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(target, []byte("NEW\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "NEW\n" {
		t.Fatalf("content not overwritten, got %q", string(got))
	}
	st, _ := os.Stat(target)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode after overwrite = %o, want 0600", st.Mode().Perm())
	}
}

// Smoke: stderr line wording (a refactor that silently changes it is worth
// catching). We use fmt.Sprintf with the same format we use in the command.
func TestRenderedMessageWording(t *testing.T) {
	// 1 placeholder
	msg := fmt.Sprintf("✓ Rendered %s → %s (%d placeholder%s restored, mode %s)",
		"a.tpl", "a.out", 1, plural(1), "0600")
	if !strings.Contains(msg, "1 placeholder restored") {
		t.Errorf("singular form drift: %q", msg)
	}
	// 3 placeholders
	msg = fmt.Sprintf("✓ Rendered %s → %s (%d placeholder%s restored, mode %s)",
		"a.tpl", "a.out", 3, plural(3), "0600")
	if !strings.Contains(msg, "3 placeholders restored") {
		t.Errorf("plural form drift: %q", msg)
	}
}
