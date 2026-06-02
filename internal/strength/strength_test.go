package strength

import "testing"

func TestEstimateBitsQuantizedAndCapped(t *testing.T) {
	// Every estimate must be a multiple of 8 (coarse) and never exceed the cap.
	for _, s := range []string{"", "a", "admin", "123456", "Tr0ub4dor&3xtra!!", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		b := EstimateBits(s)
		if b%8 != 0 {
			t.Errorf("EstimateBits(%q) = %d, not a multiple of 8", s, b)
		}
		if b > bitsCap {
			t.Errorf("EstimateBits(%q) = %d, exceeds cap %d", s, b, bitsCap)
		}
	}
	if EstimateBits("") != 0 {
		t.Errorf("EstimateBits(\"\") = %d, want 0", EstimateBits(""))
	}
}

func TestEstimateBitsRepresentative(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int // expected quantized bits
		tier string
	}{
		{"short lowercase admin", "admin", 24, "weak"},
		{"6-digit pin", "123456", 16, "weak"},
		// 32 random base64url chars hit the cap (raw > 256).
		{"base64 aes256 key", "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==", 256, "excellent"},
	}
	for _, c := range cases {
		if got := EstimateBits(c.in); got != c.want {
			t.Errorf("%s: EstimateBits(%q) = %d, want %d", c.name, c.in, got, c.want)
		}
		if got := Tier(c.want); got != c.tier {
			t.Errorf("%s: Tier(%d) = %q, want %q", c.name, c.want, got, c.tier)
		}
	}
}

func TestTierBoundaries(t *testing.T) {
	cases := []struct {
		bits int
		want string
	}{
		{0, "weak"}, {27, "weak"},
		{28, "fair"}, {59, "fair"},
		{60, "strong"}, {127, "strong"},
		{128, "excellent"}, {256, "excellent"},
	}
	for _, c := range cases {
		if got := Tier(c.bits); got != c.want {
			t.Errorf("Tier(%d) = %q, want %q", c.bits, got, c.want)
		}
	}
}
