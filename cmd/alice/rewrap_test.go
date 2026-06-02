package main

import (
	"testing"

	"github.com/kaka-milan-22/AnB/v3/internal/localvault"
)

// applyRewraps must refresh KeyEpoch from the new packed prefix while leaving
// the value-derived metadata (UpdatedAt, ValueLen, EntropyBits, CreatedAt)
// untouched — a rewrap moves the wrapping KEK forward but the plaintext is
// unchanged.
func TestApplyRewrapsBumpsKeyEpochOnly(t *testing.T) {
	dir := t.TempDir()
	s := localvault.Open(dir)
	v, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	v.Set("k", localvault.SecretEntry{
		Value:       "v1:iv:tag:ct",
		CreatedAt:   "created",
		UpdatedAt:   "updated",
		KeyEpoch:    1,
		ValueLen:    "9-16",
		EntropyBits: 80,
	})
	if err := s.Save(v); err != nil {
		t.Fatal(err)
	}

	n, err := applyRewraps(s, []string{"k"}, []string{"v3:IV:TAG:CT"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("applyRewraps updated %d entries, want 1", n)
	}

	v2, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	e, _ := v2.Get("k")
	if e.Value != "v3:IV:TAG:CT" {
		t.Errorf("Value = %q, want rewrapped ciphertext", e.Value)
	}
	if e.KeyEpoch != 3 {
		t.Errorf("KeyEpoch = %d, want 3 (parsed from new packed prefix)", e.KeyEpoch)
	}
	if e.CreatedAt != "created" || e.UpdatedAt != "updated" {
		t.Errorf("timestamps changed on rewrap: CreatedAt=%q UpdatedAt=%q", e.CreatedAt, e.UpdatedAt)
	}
	if e.ValueLen != "9-16" || e.EntropyBits != 80 {
		t.Errorf("strength metadata changed on rewrap: ValueLen=%q EntropyBits=%d", e.ValueLen, e.EntropyBits)
	}
}
