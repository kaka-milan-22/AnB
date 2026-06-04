// Package crypto holds AnB's symmetric primitives:
//
//   - AES-256-GCM sealing in the "ivHex:tagHex:ctHex" wire shape (byte-for-byte
//     compatible with agent-vault's TS vault, so ciphertext can be migrated).
//   - Argon2id key-wrapping of the master key under an operator passphrase
//     (the on-disk Envelope Bob persists).
//
// Nothing here knows about networks, files, or the daemon lifecycle — it is the
// auditable cryptographic core that both the keystore and tests build on.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	MasterKeyLen = 32 // AES-256
	gcmNonceLen  = 12
	gcmTagLen    = 16
	saltLen      = 16
)

// ErrBadPassword is returned by Unwrap when GCM authentication fails — which,
// for a key-wrap, means the supplied passphrase was wrong.
var ErrBadPassword = errors.New("incorrect master password")

// Params are the Argon2id cost parameters, persisted alongside the salt so a
// vault wrapped on one machine can be unwrapped after a parameter bump.
type Params struct {
	M uint32 `json:"m"` // memory in KiB
	T uint32 `json:"t"` // iterations
	P uint8  `json:"p"` // parallelism
}

// DefaultParams: 64 MiB, 3 passes, 1 lane — OWASP-ish interactive defaults.
func DefaultParams() Params { return Params{M: 64 * 1024, T: 3, P: 1} }

// Envelope is the on-disk wrapped master key. iv/tag/wrapped are the
// AES-256-GCM sealing of the master key under the Argon2id-derived KEK.
// ID + Created are meta added in v3 (v2.6+) so each K can be addressed
// by version within an EnvelopeFile.
type Envelope struct {
	ID      int    `json:"id,omitempty"`      // v3+: per-key version, 1..N
	Created string `json:"created,omitempty"` // v3+: RFC3339 UTC of wrap time
	KDF     string `json:"kdf"`               // "argon2id"
	Salt    string `json:"salt"`
	Params  Params `json:"params"`
	IV      string `json:"iv"`
	Tag     string `json:"tag"`
	Wrapped string `json:"wrapped"`
}

// NewMasterKey returns 32 cryptographically random bytes.
func NewMasterKey() ([]byte, error) {
	k := make([]byte, MasterKeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// DeriveKEK derives a 32-byte key-encryption-key from a passphrase.
func DeriveKEK(password string, salt []byte, p Params) []byte {
	return argon2.IDKey([]byte(password), salt, p.T, p.M, p.P, MasterKeyLen)
}

// Wrap seals masterKey under an Argon2id KEK derived from password.
func Wrap(masterKey []byte, password string) (*Envelope, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	p := DefaultParams()
	kek := DeriveKEK(password, salt, p)
	defer Wipe(kek)

	packed, err := Seal(kek, masterKey)
	if err != nil {
		return nil, err
	}
	iv, tag, ct, _ := splitPacked(packed)
	return &Envelope{
		KDF:     "argon2id",
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Params:  p,
		IV:      iv,
		Tag:     tag,
		Wrapped: ct,
	}, nil
}

// Unwrap reverses Wrap. A GCM auth failure surfaces as ErrBadPassword.
func Unwrap(env *Envelope, password string) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return nil, fmt.Errorf("bad salt: %w", err)
	}
	p := env.Params
	if p.M == 0 || p.T == 0 || p.P == 0 {
		p = DefaultParams()
	}
	kek := DeriveKEK(password, salt, p)
	defer Wipe(kek)

	key, err := Open(kek, env.IV+":"+env.Tag+":"+env.Wrapped)
	if err != nil {
		return nil, ErrBadPassword
	}
	if len(key) != MasterKeyLen {
		return nil, errors.New("unwrapped key has wrong length")
	}
	return key, nil
}

// Seal encrypts plaintext under key with NO additional authenticated data and
// returns "ivHex:tagHex:ctHex". Used for the master-key envelope, and as the
// legacy reader's counterpart during AAD migration.
func Seal(key, plaintext []byte) (string, error) { return sealAAD(key, plaintext, nil) }

// SealAAD is Seal with additional authenticated data bound into the GCM tag.
// The identical aad MUST be supplied to OpenAAD or authentication fails. Used
// to bind a secret's ciphertext to its key name so vault entries cannot be
// silently swapped (ciphertext-substitution).
func SealAAD(key, plaintext, aad []byte) (string, error) { return sealAAD(key, plaintext, aad) }

func sealAAD(key, plaintext, aad []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcmNonceLen)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, plaintext, aad) // ct || tag
	ct := sealed[:len(sealed)-gcmTagLen]
	tag := sealed[len(sealed)-gcmTagLen:]
	return hex.EncodeToString(iv) + ":" + hex.EncodeToString(tag) + ":" + hex.EncodeToString(ct), nil
}

// Open reverses Seal (no AAD). Used for the master-key envelope and by the
// AAD migration's legacy reader. Returns an error on malformed input or auth
// failure.
func Open(key []byte, packed string) ([]byte, error) { return openAAD(key, packed, nil) }

// OpenAAD reverses SealAAD. It is STRICT — the supplied aad must match exactly,
// with NO fallback to nil-aad. A vault written before AAD-binding must be
// migrated (re-sealed with aad via `bob migrate-aad`) before OpenAAD can read
// it; this is deliberate (security over backward-compat).
func OpenAAD(key []byte, packed string, aad []byte) ([]byte, error) { return openAAD(key, packed, aad) }

func openAAD(key []byte, packed string, aad []byte) ([]byte, error) {
	ivHex, tagHex, ctHex, err := splitPacked(packed)
	if err != nil {
		return nil, err
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, err
	}
	tag, err := hex.DecodeString(tagHex)
	if err != nil {
		return nil, err
	}
	ct, err := hex.DecodeString(ctHex)
	if err != nil {
		return nil, err
	}
	// Guard the nonce length BEFORE handing it to gcm.Open: Go's AEAD.Open
	// PANICS (not errors) on a nonce whose length != NonceSize(). A corrupted
	// or tampered ciphertext with a short/long IV would otherwise crash the
	// daemon (a local DoS) instead of failing cleanly. Tag length is checked
	// too for a clear error rather than a confusing auth failure.
	if len(iv) != gcmNonceLen {
		return nil, fmt.Errorf("crypto: bad nonce length %d (want %d)", len(iv), gcmNonceLen)
	}
	if len(tag) != gcmTagLen {
		return nil, fmt.Errorf("crypto: bad tag length %d (want %d)", len(tag), gcmTagLen)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, append(ct, tag...), aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func splitPacked(packed string) (iv, tag, ct string, err error) {
	parts := strings.SplitN(packed, ":", 3)
	if len(parts) != 3 {
		return "", "", "", errors.New("malformed ciphertext (want iv:tag:ct)")
	}
	return parts[0], parts[1], parts[2], nil
}

// Wipe zeroes a byte slice in place. Best-effort: Go strings cannot be wiped.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
