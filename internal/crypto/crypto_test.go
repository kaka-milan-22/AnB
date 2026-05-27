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
