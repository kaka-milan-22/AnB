package ca

import (
	"encoding/asn1"
	"regexp"
	"testing"
)

func TestPairingOIDValue(t *testing.T) {
	want := asn1.ObjectIdentifier{2, 25, 0x7d2cba5a4b8d4e9a}
	if !PairingOID.Equal(want) {
		t.Fatalf("PairingOID = %v, want %v", PairingOID, want)
	}
}

func TestNewPairingCodeFormat(t *testing.T) {
	re := regexp.MustCompile(`^[0-9]{8}$`)
	for i := 0; i < 100; i++ {
		c, err := NewPairingCode()
		if err != nil {
			t.Fatalf("NewPairingCode: %v", err)
		}
		if !re.MatchString(c) {
			t.Fatalf("code %q not 8 digits", c)
		}
	}
}

func TestNewPairingCodeNotConstant(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 32; i++ {
		c, _ := NewPairingCode()
		seen[c] = struct{}{}
	}
	if len(seen) < 16 { // 16/32 distinct is a very loose lower bound
		t.Fatalf("NewPairingCode looks non-random: only %d distinct in 32", len(seen))
	}
}
