package keystore

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kaka-milan-22/AnB/v2/internal/crypto"
)

// Multi-K HoldMulti round-trip: Encrypt always uses current K and emits
// a versioned packed string; Decrypt returns the same plaintext.
func TestHoldMultiEncryptDecryptCurrent(t *testing.T) {
	k1, _ := crypto.NewMasterKey()
	k2, _ := crypto.NewMasterKey()
	s := New(nil)
	s.HoldMulti(map[int][]byte{1: k1, 2: k2}, 2, 0)

	packed, err := s.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(packed, "v2:") {
		t.Fatalf("Encrypt must use current K and emit v<current>: prefix, got %q", packed)
	}

	pt, rewrap, currentVer, err := s.Decrypt(packed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("hello")) {
		t.Fatalf("decrypt mismatch: %q", pt)
	}
	if rewrap != "" {
		t.Fatalf("decrypt of current-K ciphertext must not rewrap, got %q", rewrap)
	}
	if !currentVer {
		t.Fatal("currentVer should be true for current-K ciphertext")
	}
}

// Decrypting a v1 (legacy / no-prefix) ciphertext when current is v2
// returns the same plaintext PLUS a rewrapped v2 packed string —
// the heart of lazy rewrap.
func TestDecryptLazyRewrap(t *testing.T) {
	k1, _ := crypto.NewMasterKey()
	k2, _ := crypto.NewMasterKey()
	s := New(nil)
	s.HoldMulti(map[int][]byte{1: k1, 2: k2}, 2, 0)

	// Build a legacy v1 ciphertext directly (no prefix) under K1.
	rawV1, err := crypto.Seal(k1, []byte("legacy"))
	if err != nil {
		t.Fatal(err)
	}
	// Hand it to Decrypt as if it came from a pre-v2.6 vault.json.
	pt, rewrap, currentVer, err := s.Decrypt(rawV1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("legacy")) {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
	if currentVer {
		t.Fatal("currentVer should be false for legacy ciphertext under non-current K")
	}
	if !strings.HasPrefix(rewrap, "v2:") {
		t.Fatalf("rewrap must use current K's version prefix, got %q", rewrap)
	}
	// Round-trip the rewrap back through Decrypt to confirm it actually
	// decrypts to the same plaintext.
	pt2, rewrap2, cur2, err := s.Decrypt(rewrap)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt2, []byte("legacy")) || rewrap2 != "" || !cur2 {
		t.Fatalf("rewrap not decryptable under current K: %v %q %v", pt2, rewrap2, cur2)
	}
}

// Removing a non-current K: subsequent decrypts of ciphertext under that
// K return ErrUnknownVersion.
func TestRemoveKeyMakesCiphertextUnreadable(t *testing.T) {
	k1, _ := crypto.NewMasterKey()
	k2, _ := crypto.NewMasterKey()
	s := New(nil)
	s.HoldMulti(map[int][]byte{1: k1, 2: k2}, 2, 0)

	rawV1, _ := crypto.Seal(k1, []byte("doomed"))
	if err := s.RemoveKey(1); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := s.Decrypt(rawV1)
	if err != ErrUnknownVersion {
		t.Fatalf("after RemoveKey(1), legacy v1 ciphertext should be unknown, got %v", err)
	}
}

// RemoveKey refuses the current version.
func TestRemoveCurrentRefused(t *testing.T) {
	k, _ := crypto.NewMasterKey()
	s := New(nil)
	s.HoldMulti(map[int][]byte{1: k}, 1, 0)
	if err := s.RemoveKey(1); err != ErrCannotFinalizeCurrent {
		t.Fatalf("expected ErrCannotFinalizeCurrent, got %v", err)
	}
}

// Single-key Hold() backward compat: maps to {1: k}, current=1.
func TestHoldBackwardCompat(t *testing.T) {
	k, _ := crypto.NewMasterKey()
	s := New(nil)
	s.Hold(k, 0)
	cur, ok := s.CurrentVersion()
	if !ok || cur != 1 {
		t.Fatalf("Hold should set current=1, got (%d, %v)", cur, ok)
	}
	if vs := s.Versions(); len(vs) != 1 || vs[0] != 1 {
		t.Fatalf("Hold should leave one version, got %v", vs)
	}
}

// AddKey promotes the new id to current.
func TestAddKeyBumpsCurrent(t *testing.T) {
	k1, _ := crypto.NewMasterKey()
	k2, _ := crypto.NewMasterKey()
	s := New(nil)
	s.Hold(k1, 0)
	s.AddKey(2, k2)
	cur, _ := s.CurrentVersion()
	if cur != 2 {
		t.Fatalf("AddKey should bump current to 2, got %d", cur)
	}
	// And Encrypt now uses K2.
	packed, _ := s.Encrypt([]byte("x"))
	if !strings.HasPrefix(packed, "v2:") {
		t.Fatalf("Encrypt after AddKey should use new current: %q", packed)
	}
}

// Zeroize wipes every version + locks the store.
func TestZeroizeWipesAll(t *testing.T) {
	k1, _ := crypto.NewMasterKey()
	k2, _ := crypto.NewMasterKey()
	s := New(nil)
	s.HoldMulti(map[int][]byte{1: k1, 2: k2}, 2, 0)
	s.Zeroize()
	if s.Unlocked() {
		t.Fatal("Zeroize should lock the store")
	}
	if vs := s.Versions(); len(vs) != 0 {
		t.Fatalf("Zeroize should empty Versions(), got %v", vs)
	}
}
