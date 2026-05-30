package aclrules

import (
	"strings"
	"testing"
)

func TestCanonicalizeSafeArgs(t *testing.T) {
	got := Canonicalize("/usr/bin/echo", []string{"hello", "world"})
	want := "/usr/bin/echo hello world"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeArgWithSpace(t *testing.T) {
	got := Canonicalize("/usr/bin/echo", []string{"hello world"})
	want := "/usr/bin/echo 'hello world'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeArgWithEmbeddedQuote(t *testing.T) {
	got := Canonicalize("/usr/bin/echo", []string{"it's"})
	want := `/usr/bin/echo 'it'\''s'`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeEmptyArg(t *testing.T) {
	got := Canonicalize("/usr/bin/echo", []string{""})
	want := "/usr/bin/echo ''"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeNoArgs(t *testing.T) {
	got := Canonicalize("/usr/bin/bob", nil)
	want := "/usr/bin/bob"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeCmdWithSpecial(t *testing.T) {
	got := Canonicalize("/path with space/tool", []string{"arg"})
	want := "'/path with space/tool' arg"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeArgWithGlobChars(t *testing.T) {
	got := Canonicalize("/bin/ls", []string{"*.txt"})
	want := "/bin/ls '*.txt'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeArgWithNewline(t *testing.T) {
	got := Canonicalize("/bin/printf", []string{"line1\nline2"})
	want := "/bin/printf 'line1\nline2'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeSafeCharsBoundary(t *testing.T) {
	// The "safe set" is [A-Za-z0-9_\-./:=@,]. Test each at boundaries.
	got := Canonicalize("/x", []string{"abc_DEF-123./:=@,"})
	want := "/x abc_DEF-123./:=@,"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeArgWithDollar(t *testing.T) {
	got := Canonicalize("/bin/echo", []string{"$HOME"})
	want := "/bin/echo '$HOME'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeCombined(t *testing.T) {
	got := Canonicalize(
		"/Users/bbwave03/.local/bin/encipherr",
		[]string{"encrypt", "file", "/tmp/has space.txt"},
	)
	want := "/Users/bbwave03/.local/bin/encipherr encrypt file '/tmp/has space.txt'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

var _ = strings.Contains // ensure import is used if tests reference it
