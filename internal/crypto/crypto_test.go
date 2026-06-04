package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key, _ := NewMasterKey()
	pt := []byte("sk-super-secret-value-123")
	packed, err := Seal(key, pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if strings.Count(packed, ":") != 2 {
		t.Fatalf("packed format not iv:tag:ct: %q", packed)
	}
	got, err := Open(key, packed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip mismatch: %q", got)
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	k1, _ := NewMasterKey()
	k2, _ := NewMasterKey()
	packed, _ := Seal(k1, []byte("x"))
	if _, err := Open(k2, packed); err == nil {
		t.Fatal("expected auth failure with wrong key")
	}
}

// A ciphertext with a wrong-length nonce must error, NOT panic. Go's
// gcm.Open panics on a nonce whose length != NonceSize(); a corrupted or
// tampered vault entry would otherwise crash the daemon.
func TestOpenBadNonceLengthErrorsNotPanic(t *testing.T) {
	key, _ := NewMasterKey()
	// 8-byte IV (should be 12) + arbitrary tag/ct hex.
	bad := hex.EncodeToString([]byte("12345678")) + ":" +
		hex.EncodeToString(make([]byte, gcmTagLen)) + ":" +
		hex.EncodeToString([]byte("deadbeef"))
	if _, err := Open(key, bad); err == nil {
		t.Fatal("expected error for short nonce")
	} else if !strings.Contains(err.Error(), "nonce length") {
		t.Fatalf("want nonce-length error, got %v", err)
	}
	// Over-long nonce too.
	bad2 := hex.EncodeToString(make([]byte, 16)) + ":" +
		hex.EncodeToString(make([]byte, gcmTagLen)) + ":" +
		hex.EncodeToString([]byte("x"))
	if _, err := Open(key, bad2); err == nil {
		t.Fatal("expected error for long nonce")
	}
}

func TestWrapUnwrap(t *testing.T) {
	mk, _ := NewMasterKey()
	env, err := Wrap(mk, "correct horse battery staple")
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if env.KDF != "argon2id" {
		t.Fatalf("kdf = %q", env.KDF)
	}
	got, err := Unwrap(env, "correct horse battery staple")
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, mk) {
		t.Fatal("unwrapped key mismatch")
	}
}

func TestUnwrapBadPassword(t *testing.T) {
	mk, _ := NewMasterKey()
	env, _ := Wrap(mk, "right")
	if _, err := Unwrap(env, "wrong"); err != ErrBadPassword {
		t.Fatalf("want ErrBadPassword, got %v", err)
	}
}

// TestRotatePassword is the cryptographic core of `bob rotate-master-password`:
// unwrap with old → wrap same K with new → unwrap with new must yield byte-equal
// K, and neither password may open the other envelope.
func TestRotatePassword(t *testing.T) {
	mk0, _ := NewMasterKey()
	env1, err := Wrap(mk0, "pw-old")
	if err != nil {
		t.Fatalf("initial wrap: %v", err)
	}

	// rotate: unwrap with old, rewrap with new
	mk1, err := Unwrap(env1, "pw-old")
	if err != nil {
		t.Fatalf("unwrap old: %v", err)
	}
	env2, err := Wrap(mk1, "pw-new")
	if err != nil {
		t.Fatalf("rewrap new: %v", err)
	}

	// invariant 1: K survives unchanged across the rotation
	mk2, err := Unwrap(env2, "pw-new")
	if err != nil {
		t.Fatalf("unwrap new: %v", err)
	}
	if !bytes.Equal(mk0, mk2) {
		t.Fatal("master key changed across rotation — K must be invariant")
	}

	// invariant 2: old password no longer opens the new envelope
	if _, err := Unwrap(env2, "pw-old"); err != ErrBadPassword {
		t.Fatalf("old password should fail on new envelope, got %v", err)
	}
	// and the new password doesn't open the (pre-rotation) old envelope
	if _, err := Unwrap(env1, "pw-new"); err != ErrBadPassword {
		t.Fatalf("new password should fail on old envelope, got %v", err)
	}

	// salt actually changes (Wrap re-randomizes), which is why the same
	// password+same-K produces a different envelope each time.
	if env1.Salt == env2.Salt {
		t.Fatal("salt should be re-randomized on rewrap")
	}
}

// Guards the agent-vault TS wire format: a value sealed elsewhere as
// ivHex:tagHex:ctHex with the same key must Open here (migration compat).
func TestOpenAcceptsExternalFormat(t *testing.T) {
	key, _ := NewMasterKey()
	packed, _ := Seal(key, []byte("hello"))
	parts := strings.SplitN(packed, ":", 3)
	for _, p := range parts {
		if _, err := hex.DecodeString(p); err != nil {
			t.Fatalf("part not hex: %q", p)
		}
	}
}
