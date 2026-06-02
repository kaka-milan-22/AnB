// Package strength derives coarse, non-revealing metadata about a secret's
// plaintext: a charset-based entropy estimate and a length bucket. Both are
// intentionally quantized — a vault stores this metadata in cleartext alongside
// the ciphertext, so exact length/entropy would be a side-channel about the
// secret. EstimateBits answers "roughly how strong is this" without pinning the
// value (e.g. distinguishing a 5-char "admin" from a 6-char one).
//
// The metric is charset-estimated bits: len × log2(effective charset size),
// the conventional password-strength number. Known limitation: it OVER-counts
// long structured content (a kubeconfig/YAML reads as "excellent" despite low
// real entropy). That trade-off is deliberate — the opposite metric (per-symbol
// Shannon entropy, in internal/redact) under-counts short random secrets, which
// is the worse failure for a strength signal.
package strength

import "math"

// charset class sizes, mirroring the alphabets in internal/pwgen.
const (
	classLower  = 26 // a-z
	classUpper  = 26 // A-Z
	classDigit  = 10 // 0-9
	classSymbol = 33 // printable ASCII punctuation + space (generous)
	classOther  = 128 // bytes >127 or controls: binary / multibyte content
)

// bitsCap bounds the reported estimate. Beyond this the exact number adds no
// strength signal (already "excellent") and a higher value would only leak the
// length of long content more precisely.
const bitsCap = 256

// EstimateBits returns a coarse charset-based entropy estimate in bits for s,
// rounded to the nearest 8 and capped at bitsCap. Rounding + cap keep the number
// from being inverted back to an exact length. Empty input returns 0.
func EstimateBits(s string) int {
	if s == "" {
		return 0
	}
	var lower, upper, digit, symbol, other bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		case c >= 0x20 && c <= 0x7e:
			symbol = true
		default:
			other = true
		}
	}
	charset := 0
	if lower {
		charset += classLower
	}
	if upper {
		charset += classUpper
	}
	if digit {
		charset += classDigit
	}
	if symbol {
		charset += classSymbol
	}
	if other {
		charset += classOther
	}
	if charset < 2 {
		charset = 2 // a single repeated symbol still carries ~1 bit/char
	}
	raw := float64(len(s)) * math.Log2(float64(charset))
	bits := int(math.Round(raw/8) * 8) // quantize to 8-bit rungs
	if bits > bitsCap {
		bits = bitsCap
	}
	return bits
}

// Tier maps an estimated bit count to a human-facing strength word.
func Tier(bits int) string {
	switch {
	case bits < 28:
		return "weak"
	case bits < 60:
		return "fair"
	case bits < 128:
		return "strong"
	default:
		return "excellent"
	}
}

// LenBucket maps a byte length to a coarse range label. Buckets, not exact
// counts, so the stored metadata can't pin a short secret's length.
func LenBucket(n int) string {
	switch {
	case n <= 0:
		return ""
	case n <= 8:
		return "1-8"
	case n <= 16:
		return "9-16"
	case n <= 32:
		return "17-32"
	case n <= 64:
		return "33-64"
	default:
		return "65+"
	}
}
