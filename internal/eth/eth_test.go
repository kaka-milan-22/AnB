package eth

import (
	"strings"
	"testing"

	"github.com/tyler-smith/go-bip39"
)

// BIP-39 official "all zeros" mnemonic — the canonical test vector
// every HD wallet implementation must reproduce. From
// https://github.com/trezor/python-mnemonic/blob/master/vectors.json
// (256-bit-entropy variant).
const (
	allAbandon24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	// Computed deterministically by every BIP-32/44 implementation given
	// this mnemonic at path m/44'/60'/0'/0/0. Cross-checked against
	// iancoleman.io BIP39 tool. Mismatch here = our derivation pipeline
	// disagrees with the canonical implementation.
	allAbandon24Addr0 = "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb"
)

// 12-word variant (128-bit entropy), also a well-known test vector.
const (
	allAbandon12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	// Address from m/44'/60'/0'/0/0 of that mnemonic. Cross-checked against
	// at least three independent wallets.
	allAbandon12Addr0 = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
)

// TestDeriveAddressBIP39Vector exercises the full pipeline end-to-end
// against the BIP-39 canonical test mnemonic. If this passes we're
// agreeing with every other HD wallet on the planet.
func TestDeriveAddressBIP39Vector(t *testing.T) {
	cases := []struct {
		name     string
		mnemonic string
		index    uint32
		want     string
	}{
		{"12-word abandon×11+about /0", allAbandon12, 0, allAbandon12Addr0},
		{"24-word abandon×23+art /0", allAbandon24, 0, allAbandon24Addr0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DeriveAddress(tc.mnemonic, tc.index)
			if err != nil {
				t.Fatalf("DeriveAddress: %v", err)
			}
			if got != tc.want {
				t.Fatalf("address mismatch:\n  got  %s\n  want %s", got, tc.want)
			}
		})
	}
}

// TestDeriveAddressDeterministic — same mnemonic + index must produce
// the same address across many calls. Sanity for "did we accidentally
// mix randomness into a deterministic path".
func TestDeriveAddressDeterministic(t *testing.T) {
	first, err := DeriveAddress(allAbandon12, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		got, err := DeriveAddress(allAbandon12, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got != first {
			t.Fatalf("non-deterministic at draw %d: %s vs %s", i, got, first)
		}
	}
}

// TestDeriveAddressIndexProducesDifferent — different indices on the
// same mnemonic must produce different addresses (no path-collapse
// bug). 4 indices is overkill but cheap.
func TestDeriveAddressIndexProducesDifferent(t *testing.T) {
	seen := map[string]uint32{}
	for i := uint32(0); i < 4; i++ {
		addr, err := DeriveAddress(allAbandon12, i)
		if err != nil {
			t.Fatal(err)
		}
		if other, dup := seen[addr]; dup {
			t.Fatalf("index %d and %d both produce %s — path collapse", other, i, addr)
		}
		seen[addr] = i
	}
}

// TestValidateMnemonicWhitespaceTolerant — paper backups frequently get
// pasted with double-spaces or stray newlines. We normalize.
func TestValidateMnemonicWhitespaceTolerant(t *testing.T) {
	cases := []string{
		allAbandon12,
		"  " + allAbandon12 + "  ",                                   // edge padding
		strings.ReplaceAll(allAbandon12, " ", "  "),                  // double-spaces
		strings.ReplaceAll(allAbandon12, " ", "\n"),                  // newlines
		strings.ReplaceAll(allAbandon12, " abandon ", " \tabandon "), // tabs mid-string
	}
	for _, m := range cases {
		if err := ValidateMnemonic(m); err != nil {
			t.Fatalf("validation failed on whitespace-variant %q: %v", m, err)
		}
	}
}

// TestValidateMnemonicRejectsBadChecksum — flip the last word to one
// that exists in the BIP-39 list but breaks the checksum.
func TestValidateMnemonicRejectsBadChecksum(t *testing.T) {
	// Replace "about" with another valid wordlist entry; checksum bits
	// almost certainly stop matching.
	bad := strings.Replace(allAbandon12, "about", "abandon", 1)
	if err := ValidateMnemonic(bad); err == nil {
		t.Fatal("expected checksum failure on tampered mnemonic")
	}
}

// TestValidateMnemonicRejectsUnknownWord — typo / off-by-one word.
func TestValidateMnemonicRejectsUnknownWord(t *testing.T) {
	bad := strings.Replace(allAbandon12, "abandon", "abandonn", 1) // double-n
	if err := ValidateMnemonic(bad); err == nil {
		t.Fatal("expected wordlist failure on unknown word")
	}
}

// TestGenMnemonicValid — generated mnemonics must self-validate (i.e.
// our generator and validator agree).
func TestGenMnemonicValid(t *testing.T) {
	for _, words := range []int{12, 24} {
		for i := 0; i < 5; i++ {
			m, err := GenMnemonic(words)
			if err != nil {
				t.Fatalf("GenMnemonic(%d): %v", words, err)
			}
			if got := len(strings.Fields(m)); got != words {
				t.Fatalf("GenMnemonic(%d): got %d words (%q)", words, got, m)
			}
			if err := ValidateMnemonic(m); err != nil {
				t.Fatalf("generated mnemonic failed self-validation: %v\n  %q", err, m)
			}
		}
	}
}

// TestGenMnemonicRejectsUnsupportedWordCount — 15, 18, 21 are valid in
// BIP-39 but we only accept 12 or 24 per design.
func TestGenMnemonicRejectsUnsupportedWordCount(t *testing.T) {
	for _, n := range []int{0, 11, 15, 18, 21, 25} {
		if _, err := GenMnemonic(n); err == nil {
			t.Errorf("GenMnemonic(%d) should error", n)
		}
	}
}

// EIP-55 official test vectors from the proposal text. If any of these
// fail, the checksum case math is wrong somewhere.
func TestEIP55Checksum(t *testing.T) {
	// Each pair is the canonical mixed-case form; we strip "0x", lowercase
	// it, hex-decode → 20 bytes, run EIP55Checksum, expect exact case
	// preservation.
	vectors := []string{
		// All-caps letters
		"0x52908400098527886E0F7030069857D2E4169EE7",
		"0x8617E340B3D01FA5F11F306F4090FD50E238070D",
		// All-lowercase letters
		"0xde709f2102306220921060314715629080e2fb77",
		"0x27b1fdb04752bbc536007a920d24acb045561c26",
		// Mixed-case (typical real-world output)
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	}
	for _, want := range vectors {
		t.Run(want, func(t *testing.T) {
			raw := decodeHexAddr(t, want)
			if got := EIP55Checksum(raw); got != want {
				t.Fatalf("\n  got  %s\n  want %s", got, want)
			}
		})
	}
}

// EIP55 must reject anything that isn't 20 bytes.
func TestEIP55ChecksumLengthGuard(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on non-20-byte input")
		}
	}()
	EIP55Checksum(make([]byte, 19))
}

// PrivateKeyToAddress must reject keys that aren't 32 bytes.
func TestPrivateKeyToAddressLengthGuard(t *testing.T) {
	if _, err := PrivateKeyToAddress(make([]byte, 31)); err == nil {
		t.Fatal("31-byte key should be rejected")
	}
	if _, err := PrivateKeyToAddress(make([]byte, 33)); err == nil {
		t.Fatal("33-byte key should be rejected")
	}
}

// Round-trip sanity: validate a freshly-generated mnemonic decodes
// back through bip39.MnemonicToByteArray cleanly.
func TestGeneratedMnemonicRoundTrip(t *testing.T) {
	m, err := GenMnemonic(24)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bip39.MnemonicToByteArray(m); err != nil {
		t.Fatalf("MnemonicToByteArray on generated: %v", err)
	}
}

func decodeHexAddr(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	if len(s) != 40 {
		t.Fatalf("test vector has wrong hex length: %q", s)
	}
	out := make([]byte, 20)
	for i := 0; i < 20; i++ {
		hi := hexNibble(t, s[2*i])
		lo := hexNibble(t, s[2*i+1])
		out[i] = hi<<4 | lo
	}
	return out
}

func hexNibble(t *testing.T, c byte) byte {
	t.Helper()
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	t.Fatalf("non-hex byte %q in test vector", c)
	return 0
}
