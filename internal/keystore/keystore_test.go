package keystore

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kaka-milan-22/AnB/v3/internal/crypto"
)

// Multi-K HoldMulti round-trip: Encrypt always uses current K and emits
// a versioned packed string; Decrypt returns the same plaintext.
func TestHoldMultiEncryptDecryptCurrent(t *testing.T) {
	k1, _ := crypto.NewMasterKey()
	k2, _ := crypto.NewMasterKey()
	s := New(nil)
	s.HoldMulti(map[int][]byte{1: k1, 2: k2}, 2, 0)

	packed, err := s.Encrypt("greeting", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(packed, "v2:") {
		t.Fatalf("Encrypt must use current K and emit v<current>: prefix, got %q", packed)
	}

	pt, rewrap, currentVer, err := s.Decrypt("greeting", packed)
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

// Decrypting an AAD-bound v1 ciphertext when current is v2 returns the same
// plaintext PLUS a rewrapped v2 packed string (lazy cross-version rewrap),
// re-sealed under the same name-AAD.
func TestDecryptLazyRewrap(t *testing.T) {
	k1, _ := crypto.NewMasterKey()
	k2, _ := crypto.NewMasterKey()
	s := New(nil)
	s.HoldMulti(map[int][]byte{1: k1, 2: k2}, 2, 0)

	// A v1 ciphertext under K1, sealed with the same name-AAD Decrypt will use.
	raw, err := crypto.SealAAD(k1, []byte("legacy"), []byte("oldkey"))
	if err != nil {
		t.Fatal(err)
	}
	rawV1 := crypto.PackVersion(1, raw)

	pt, rewrap, currentVer, err := s.Decrypt("oldkey", rawV1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("legacy")) {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
	if currentVer {
		t.Fatal("currentVer should be false for ciphertext under non-current K")
	}
	if !strings.HasPrefix(rewrap, "v2:") {
		t.Fatalf("rewrap must use current K's version prefix, got %q", rewrap)
	}
	// Round-trip the rewrap back through Decrypt (same name) to confirm it
	// decrypts to the same plaintext under the current K.
	pt2, rewrap2, cur2, err := s.Decrypt("oldkey", rewrap)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt2, []byte("legacy")) || rewrap2 != "" || !cur2 {
		t.Fatalf("rewrap not decryptable under current K: %v %q %v", pt2, rewrap2, cur2)
	}
}

// A ciphertext sealed for one name must NOT decrypt under a different name —
// the AAD binding that prevents vault-entry substitution.
func TestDecryptWrongNameFails(t *testing.T) {
	k, _ := crypto.NewMasterKey()
	s := New(nil)
	s.HoldMulti(map[int][]byte{1: k}, 1, 0)

	packed, err := s.Encrypt("real-name", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.Decrypt("attacker-swapped-name", packed); err == nil {
		t.Fatal("decrypt under a different name must fail (AAD mismatch)")
	}
}

// Removing a non-current K: subsequent decrypts of ciphertext under that
// K return ErrUnknownVersion.
func TestRemoveKeyMakesCiphertextUnreadable(t *testing.T) {
	k1, _ := crypto.NewMasterKey()
	k2, _ := crypto.NewMasterKey()
	s := New(nil)
	s.HoldMulti(map[int][]byte{1: k1, 2: k2}, 2, 0)

	raw, _ := crypto.SealAAD(k1, []byte("doomed"), []byte("k"))
	rawV1 := crypto.PackVersion(1, raw)
	if err := s.RemoveKey(1); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := s.Decrypt("k", rawV1)
	if err != ErrUnknownVersion {
		t.Fatalf("after RemoveKey(1), v1 ciphertext should be unknown, got %v", err)
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
	packed, _ := s.Encrypt("k", []byte("x"))
	if !strings.HasPrefix(packed, "v2:") {
		t.Fatalf("Encrypt after AddKey should use new current: %q", packed)
	}
}

// TestHoldDefensivelyCopiesKey pins the v2.6 hardening that prevents the
// v2.0–v2.5 zero-K bug from coming back. Caller wipes its own copy
// after Hold; the store's K must survive (i.e. Encrypt/Decrypt still
// round-trip the right plaintext, NOT a zero-K ciphertext).
func TestHoldDefensivelyCopiesKey(t *testing.T) {
	mk, _ := crypto.NewMasterKey()
	s := New(nil)
	s.HoldMulti(map[int][]byte{1: mk}, 1, 0)
	crypto.Wipe(mk) // emulate the buggy v2.5- daemon pattern

	ct, err := s.Encrypt("k", []byte("hello"))
	if err != nil {
		t.Fatalf("encrypt after caller Wipe: %v", err)
	}
	pt, _, _, err := s.Decrypt("k", ct)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("round-trip after caller Wipe: pt=%q err=%v", pt, err)
	}

	// The store's K must NOT be the all-zero key. A ciphertext sealed under
	// zero externally (with the SAME name-AAD) would decrypt under the store's
	// K only if the store's K were also zero — defense against the v2.5- bug.
	zero := make([]byte, 32)
	external, _ := crypto.SealAAD(zero, []byte("attacker-controlled"), []byte("k"))
	if _, _, _, err := s.Decrypt("k", crypto.PackVersion(1, external)); err == nil {
		t.Fatal("store accepted a zero-K ciphertext — the v2.0-v2.5 zero-K bug regressed")
	}
}

// Hold (single-K convenience) also defensively copies.
func TestHoldSingleDefensivelyCopiesKey(t *testing.T) {
	mk, _ := crypto.NewMasterKey()
	s := New(nil)
	s.Hold(mk, 0)
	crypto.Wipe(mk)
	ct, err := s.Encrypt("k", []byte("hi"))
	if err != nil {
		t.Fatalf("encrypt after caller Wipe (Hold): %v", err)
	}
	pt, _, _, err := s.Decrypt("k", ct)
	if err != nil || string(pt) != "hi" {
		t.Fatalf("Hold round-trip after Wipe: pt=%q err=%v", pt, err)
	}
}

// AddKey defensively copies too.
func TestAddKeyDefensivelyCopiesKey(t *testing.T) {
	k1, _ := crypto.NewMasterKey()
	k2, _ := crypto.NewMasterKey()
	s := New(nil)
	s.HoldMulti(map[int][]byte{1: k1}, 1, 0)
	s.AddKey(2, k2)
	crypto.Wipe(k2)
	ct, err := s.Encrypt("k", []byte("hello"))
	if err != nil {
		t.Fatalf("encrypt after AddKey + caller Wipe: %v", err)
	}
	pt, _, _, err := s.Decrypt("k", ct)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("AddKey round-trip after Wipe: pt=%q err=%v", pt, err)
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
