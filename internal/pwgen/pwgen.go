// Package pwgen generates random passwords with crypto/rand. Styles mirror
// Apple's "Strong Password" (alphanumeric, hyphen-grouped) plus a symbol variant,
// a word-based passphrase (EFF large wordlist), and a numeric PIN. Pure logic —
// no secrets, no network.
package pwgen

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

// Style selects a generator. Each style sizes differently (see bounds).
type Style string

const (
	Apple      Style = "apple"      // xxxxxx-…-xxxxxx, alphanumeric, sized by groups of 6
	Full       Style = "full"       // alphanumeric + symbols, sized by character count
	Passphrase Style = "passphrase" // EFF words joined by '-', sized by word count
	PIN        Style = "pin"        // digits only, sized by digit count
	AES256     Style = "aes256"     // 32 raw bytes → base64url (44 chars, trailing '='). Direct fit for AES-256 / ChaCha20 / encipherr keys.
)

const (
	lower   = "abcdefghijklmnopqrstuvwxyz"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	symbols = "!#$%&*+-=?@^_~" // shell-safe: no quotes, backslash, space, or backtick
	alnum   = lower + upper + digits
)

// bound describes a style's -l parameter.
type bound struct {
	def, min, max int
	unit          string
}

var bounds = map[Style]bound{
	Apple:      {def: 3, min: 1, max: 8, unit: "groups"},
	Full:       {def: 20, min: 8, max: 100, unit: "chars"},
	Passphrase: {def: 5, min: 3, max: 12, unit: "words"},
	PIN:        {def: 6, min: 4, max: 32, unit: "digits"},
	// AES256 is fixed at 32 bytes — anything else would produce an
	// invalid AES-256 key. -l is accepted for symmetry but only 32 is
	// allowed; min=max keeps the validation messages consistent with
	// the other styles.
	AES256: {def: 32, min: 32, max: 32, unit: "bytes"},
}

// Styles lists the supported styles in display order.
func Styles() []Style { return []Style{Apple, Full, Passphrase, PIN, AES256} }

// DefaultSize returns the default -l for a style (0 if unknown).
func DefaultSize(s Style) int { return bounds[s].def }

//go:embed wordlist.txt
var wordlistRaw string

var words = loadWords(wordlistRaw)

func loadWords(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// Generate produces one password of the given style and size. size==0 uses the
// style default; an out-of-range size or unknown style returns an error.
func Generate(s Style, size int) (string, error) {
	b, ok := bounds[s]
	if !ok {
		return "", fmt.Errorf("unknown style %q (use one of: apple, full, passphrase, pin, aes256)", s)
	}
	if size == 0 {
		size = b.def
	}
	if size < b.min || size > b.max {
		return "", fmt.Errorf("-l for %s must be %d–%d %s (got %d)", s, b.min, b.max, b.unit, size)
	}
	switch s {
	case Apple:
		return apple(size), nil
	case Full:
		return full(size), nil
	case Passphrase:
		return passphrase(size), nil
	case PIN:
		return pin(size), nil
	case AES256:
		return aes256(size), nil
	}
	// Unreachable: bounds check above guarantees s is one of the known styles.
	return "", fmt.Errorf("pwgen: unreachable: style %q passed bounds check but has no generator", s)
}

func apple(groups int) string {
	raw := fill(alnum, groups*6, []string{lower, upper, digits})
	var sb strings.Builder
	for i := 0; i < groups; i++ {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.Write(raw[i*6 : i*6+6])
	}
	return sb.String()
}

func full(length int) string {
	return string(fill(lower+upper+digits+symbols, length, []string{lower, upper, digits, symbols}))
}

// aes256 returns n raw bytes from crypto/rand encoded as URL-safe base64.
// For n=32 the result is 44 chars ending in '=' — the canonical wire form
// for AES-256 keys (matches what encipherr genkey / Fernet keygen produce).
// The encoding is URL-safe (not standard +/), so the output is safe to use
// in env vars, JSON, and shell argv without quoting headaches.
func aes256(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("pwgen: crypto/rand failure: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(b)
}

func pin(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = digits[randIndex(len(digits))]
	}
	return string(out)
}

func passphrase(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = words[randIndex(len(words))]
	}
	// Capitalize one random word and append a 2-digit number, so the result spans
	// upper/lower/digit classes (e.g. tidy-Cobra-mellow-quartz-vivid-09).
	c := randIndex(n)
	parts[c] = strings.ToUpper(parts[c][:1]) + parts[c][1:]
	return strings.Join(parts, "-") + fmt.Sprintf("-%02d", randIndex(100))
}

// fill draws n chars uniformly from pool, guaranteeing at least one char from
// each required class via rejection sampling (reject strings that miss a class,
// keep the rest — the accepted set stays uniform). For the sizes here it almost
// always succeeds on the first try.
func fill(pool string, n int, classes []string) []byte {
	for {
		out := make([]byte, n)
		for i := range out {
			out[i] = pool[randIndex(len(pool))]
		}
		if covers(out, classes) {
			return out
		}
	}
}

func covers(b []byte, classes []string) bool {
	s := string(b)
	for _, class := range classes {
		if !strings.ContainsAny(s, class) {
			return false
		}
	}
	return true
}

// randIndex returns an unbiased index in [0,n) from crypto/rand. A crypto/rand
// failure is unrecoverable, so it panics rather than returning a weak value.
func randIndex(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic("pwgen: crypto/rand failure: " + err.Error())
	}
	return int(v.Int64())
}
