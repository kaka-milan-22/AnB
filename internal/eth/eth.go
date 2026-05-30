// Package eth implements the minimum needed to derive Ethereum addresses
// from a BIP-39 mnemonic, with no signing surface (signing is deferred to
// a later release once RLP / EIP-155 / EIP-1559 handling lands).
//
// Pipeline:
//
//	mnemonic ──BIP-39 PBKDF2──> seed (64 B)
//	seed     ──BIP-32──────────> master key
//	master   ──BIP-44 path m/44'/60'/0'/0/N──> child key (32 B priv)
//	priv     ──secp256k1·G─────> uncompressed pubkey (64 B, no 0x04 prefix)
//	pubkey   ──keccak256──────> hash (32 B), last 20 B = address
//	address  ──EIP-55──────────> mixed-case checksum form
//
// No randomness is consumed in derivation; given the same mnemonic and
// index N, the output address is exact and reproducible.
//
// Intentionally NO passphrase support on the BIP-39 step. Per the
// project's design notes the mnemonic itself is the single root of
// identity; a second secret would invite "two things to back up, one of
// which is undocumented" failure modes. Operators who genuinely need a
// passphrase layer can pre-mix it into the mnemonic externally.
package eth

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/sha3"
)

// CoinTypeETH is the BIP-44 coin type for Ether.
// See https://github.com/satoshilabs/slips/blob/master/slip-0044.md
const CoinTypeETH uint32 = 60

// hardenedOffset is the high bit that distinguishes a hardened child key
// from a normal one. BIP-44 requires the first three levels to be hardened.
const hardenedOffset uint32 = 0x80000000

// GenMnemonic produces a fresh BIP-39 mnemonic. Only 12 or 24 words are
// accepted (128 / 256 bits of entropy respectively). 24 is the default
// in `alice eth new`.
func GenMnemonic(words int) (string, error) {
	var bits int
	switch words {
	case 12:
		bits = 128
	case 24:
		bits = 256
	default:
		return "", fmt.Errorf("unsupported mnemonic word count %d (use 12 or 24)", words)
	}
	ent, err := bip39.NewEntropy(bits)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(ent)
}

// ValidateMnemonic checks that mnemonic is BIP-39 well-formed: every word is
// in the official 2048-word list AND the trailing checksum bits match.
// Leading / trailing whitespace and runs of inner whitespace are normalized.
func ValidateMnemonic(mnemonic string) error {
	if !bip39.IsMnemonicValid(NormalizeMnemonic(mnemonic)) {
		return errors.New("invalid BIP-39 mnemonic (bad word or checksum)")
	}
	return nil
}

// NormalizeMnemonic collapses internal whitespace and trims edges so an
// operator who pasted a mnemonic from a paper backup with double-spaces
// or stray newlines doesn't get a false "invalid" verdict.
func NormalizeMnemonic(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// DerivePrivateKey returns the raw 32-byte secp256k1 private key at
// m/44'/60'/0'/0/index. Caller MUST wipe the returned slice when done —
// it's the actual private key bytes that control the corresponding ETH
// address.
func DerivePrivateKey(mnemonic string, index uint32) ([]byte, error) {
	clean := NormalizeMnemonic(mnemonic)
	if !bip39.IsMnemonicValid(clean) {
		return nil, errors.New("invalid BIP-39 mnemonic (bad word or checksum)")
	}
	// No passphrase: BIP-39 spec treats an empty string as the absence
	// of a passphrase (still salted with "mnemonic" + ""). This is the
	// canonical "naked seed" used by all major wallets when the user
	// doesn't enable the optional 25th-word feature.
	seed := bip39.NewSeed(clean, "")
	defer wipe(seed)

	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("bip32 master derive: %w", err)
	}
	// BIP-44 path m / 44' / 60' / 0' / 0 / index
	steps := []uint32{
		44 | hardenedOffset,
		CoinTypeETH | hardenedOffset,
		0 | hardenedOffset,
		0, // external chain (non-hardened)
		index,
	}
	cur := master
	for _, step := range steps {
		next, err := cur.NewChildKey(step)
		if err != nil {
			return nil, fmt.Errorf("bip32 derive step %d: %w", step, err)
		}
		cur = next
	}
	// Defensive copy: the bip32.Key.Key slice is owned by the library;
	// returning a copy lets caller wipe without poking library state.
	out := make([]byte, len(cur.Key))
	copy(out, cur.Key)
	return out, nil
}

// DeriveAddress returns the EIP-55-checksummed Ethereum address at
// m/44'/60'/0'/0/index for the given mnemonic. The intermediate private
// key is wiped before return.
func DeriveAddress(mnemonic string, index uint32) (string, error) {
	priv, err := DerivePrivateKey(mnemonic, index)
	if err != nil {
		return "", err
	}
	defer wipe(priv)
	return PrivateKeyToAddress(priv)
}

// PrivateKeyToAddress computes the EIP-55-checksummed ETH address from a
// raw 32-byte secp256k1 private key. Exposed for tests and any caller
// that already has a derived key in hand.
func PrivateKeyToAddress(priv []byte) (string, error) {
	if len(priv) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes, got %d", len(priv))
	}
	_, pub := btcec.PrivKeyFromBytes(priv)
	// SerializeUncompressed returns 65 bytes: 0x04 || X (32) || Y (32).
	// Ethereum hashes only the 64 coordinate bytes, NOT the 0x04 prefix.
	uncompressed := pub.SerializeUncompressed()
	hash := keccak256(uncompressed[1:])
	addr := hash[len(hash)-20:] // last 20 bytes of the 32-byte hash
	return EIP55Checksum(addr), nil
}

// EIP55Checksum returns the canonical mixed-case representation of a
// 20-byte Ethereum address. The check is keccak256 of the lowercase
// hex (no `0x`): for each hex digit at position i, uppercase iff the
// i-th nibble of the hash is >= 8. See EIP-55.
func EIP55Checksum(addr []byte) string {
	if len(addr) != 20 {
		panic(fmt.Sprintf("EIP55Checksum: addr must be 20 bytes, got %d", len(addr)))
	}
	lower := hex.EncodeToString(addr) // 40 lowercase hex chars
	hash := keccak256([]byte(lower))

	var b strings.Builder
	b.Grow(42)
	b.WriteString("0x")
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if c >= '0' && c <= '9' {
			b.WriteByte(c)
			continue
		}
		// hash[i/2] holds two nibbles for hex digits 2i and 2i+1; the
		// high nibble is checked for even i, low nibble for odd i.
		var nibble byte
		if i%2 == 0 {
			nibble = hash[i/2] >> 4
		} else {
			nibble = hash[i/2] & 0x0f
		}
		if nibble >= 8 {
			b.WriteByte(c - 32) // a-f → A-F (ASCII)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// keccak256 returns SHA3-keccak256 of data (the pre-NIST variant
// Ethereum uses, not standard SHA3-256).
func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

// wipe overwrites b with zeros. Best-effort: Go's GC may have moved
// the backing array, but at minimum the slice the caller holds is now
// zeroed.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
