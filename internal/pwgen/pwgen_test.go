package pwgen

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

func hasClass(s, class string) bool { return strings.ContainsAny(s, class) }

func TestApple(t *testing.T) {
	re := regexp.MustCompile(`^[A-Za-z0-9]{6}(-[A-Za-z0-9]{6})*$`)
	for g := 1; g <= 8; g++ {
		for i := 0; i < 200; i++ {
			p, err := Generate(Apple, g)
			if err != nil {
				t.Fatalf("apple g=%d: %v", g, err)
			}
			if !re.MatchString(p) {
				t.Fatalf("apple g=%d bad format: %q", g, p)
			}
			if got := strings.Count(p, "-") + 1; got != g {
				t.Fatalf("apple g=%d: want %d groups, got %d (%q)", g, g, got, p)
			}
			if want := g*6 + (g - 1); len(p) != want {
				t.Fatalf("apple g=%d: len want %d got %d", g, want, len(p))
			}
			body := strings.ReplaceAll(p, "-", "")
			if !hasClass(body, lower) || !hasClass(body, upper) || !hasClass(body, digits) {
				t.Fatalf("apple g=%d missing a class: %q", g, p)
			}
		}
	}
}

func TestFull(t *testing.T) {
	pool := lower + upper + digits + symbols
	for _, n := range []int{8, 20, 100} {
		for i := 0; i < 200; i++ {
			p, err := Generate(Full, n)
			if err != nil {
				t.Fatalf("full n=%d: %v", n, err)
			}
			if len(p) != n {
				t.Fatalf("full n=%d: len got %d", n, len(p))
			}
			for _, c := range p {
				if !strings.ContainsRune(pool, c) {
					t.Fatalf("full: char %q outside pool in %q", c, p)
				}
			}
			if !hasClass(p, lower) || !hasClass(p, upper) || !hasClass(p, digits) || !hasClass(p, symbols) {
				t.Fatalf("full n=%d missing a class: %q", n, p)
			}
		}
	}
}

func TestPIN(t *testing.T) {
	for _, n := range []int{4, 6, 32} {
		p, err := Generate(PIN, n)
		if err != nil {
			t.Fatalf("pin n=%d: %v", n, err)
		}
		if len(p) != n {
			t.Fatalf("pin len got %d want %d", len(p), n)
		}
		for _, c := range p {
			if !strings.ContainsRune(digits, c) {
				t.Fatalf("pin non-digit %q in %q", c, p)
			}
		}
	}
}

func TestPassphrase(t *testing.T) {
	if len(words) != 7776 {
		t.Fatalf("wordlist: want 7776 words, got %d", len(words))
	}
	trailing := regexp.MustCompile(`^\d{2}$`)
	for _, n := range []int{3, 5, 12} {
		p, err := Generate(Passphrase, n)
		if err != nil {
			t.Fatalf("passphrase n=%d: %v", n, err)
		}
		segs := strings.Split(p, "-")
		if len(segs) != n+1 { // n words + a trailing 2-digit number
			t.Fatalf("passphrase n=%d: want %d segments, got %d (%q)", n, n+1, len(segs), p)
		}
		if !trailing.MatchString(segs[len(segs)-1]) {
			t.Fatalf("passphrase n=%d: bad trailing number %q", n, segs[len(segs)-1])
		}
		caps := 0
		for _, w := range segs[:n] {
			if w == "" {
				t.Fatalf("empty word segment in %q", p)
			}
			if w[0] >= 'A' && w[0] <= 'Z' {
				caps++
			}
		}
		if caps != 1 {
			t.Fatalf("passphrase n=%d: want exactly 1 capitalized word, got %d (%q)", n, caps, p)
		}
	}
}

func TestGenerateBounds(t *testing.T) {
	cases := []struct {
		s    Style
		size int
	}{
		{Apple, 9}, {Apple, -1},
		{Full, 7}, {Full, 101},
		{Passphrase, 2}, {Passphrase, 13},
		{PIN, 3}, {PIN, 33},
		{AES256, 16}, {AES256, 31}, {AES256, 33}, // only 32 is valid
		{"bogus", 5},
	}
	for _, c := range cases {
		if _, err := Generate(c.s, c.size); err == nil {
			t.Fatalf("expected error for style=%q size=%d", c.s, c.size)
		}
	}
}

// AES256 must produce a 44-char URL-safe base64 string ending with `=`
// that decodes to exactly 32 bytes — the exact wire format encipherr
// genkey / Fernet keygen / most AES-256 tooling expects. Sample 200
// times to make sure the encoder isn't producing bias / wrong length.
func TestAES256(t *testing.T) {
	want := regexp.MustCompile(`^[A-Za-z0-9_-]{43}=$`)
	seen := map[string]struct{}{}
	for i := 0; i < 200; i++ {
		p, err := Generate(AES256, 0) // default = 32
		if err != nil {
			t.Fatalf("aes256: %v", err)
		}
		if len(p) != 44 {
			t.Fatalf("aes256: len got %d want 44 (%q)", len(p), p)
		}
		if !want.MatchString(p) {
			t.Fatalf("aes256: format mismatch %q (want urlsafe-base64 with `=` padding)", p)
		}
		raw, derr := base64.URLEncoding.DecodeString(p)
		if derr != nil {
			t.Fatalf("aes256: not valid urlsafe-base64: %q (%v)", p, derr)
		}
		if len(raw) != 32 {
			t.Fatalf("aes256: decoded len got %d want 32", len(raw))
		}
		seen[p] = struct{}{}
	}
	// Collision-free across 200 draws (probability of any collision is
	// negligible for a 256-bit space).
	if len(seen) != 200 {
		t.Fatalf("aes256: %d duplicates across 200 draws — RNG broken?", 200-len(seen))
	}
}

// Explicit -l 32 must succeed (matches the default; min=max=32).
func TestAES256ExplicitSize(t *testing.T) {
	p, err := Generate(AES256, 32)
	if err != nil {
		t.Fatalf("aes256 -l 32: %v", err)
	}
	if len(p) != 44 {
		t.Fatalf("aes256 -l 32: len got %d want 44", len(p))
	}
}

func TestGenerateDefaults(t *testing.T) {
	for _, s := range Styles() {
		p, err := Generate(s, 0) // 0 → style default
		if err != nil {
			t.Fatalf("default %s: %v", s, err)
		}
		if p == "" {
			t.Fatalf("empty default for %s", s)
		}
	}
}
