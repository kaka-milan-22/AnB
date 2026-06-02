// Package strength derives a coarse, non-revealing strength signal for a
// secret's plaintext: a charset-based entropy estimate, quantized to 8-bit
// rungs and capped. It is kept coarse because charset composition is NOT
// recoverable from the stored ciphertext, so an exact figure would be a small
// side-channel. (Exact length, by contrast, is already implied by the GCM
// ciphertext's length, so callers store that precisely — see localvault.)
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
