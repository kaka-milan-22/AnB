package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kaka-milan-22/AnB/v3/internal/crypto"
	"github.com/kaka-milan-22/AnB/v3/internal/localvault"
)

// End-to-end migrate-aad: a legacy (no-AAD) vault entry is re-sealed AAD-bound
// under its key name; afterwards it opens only with the correct name, the
// legacy nil-aad open fails, and a second run is a no-op.
func TestMigrateAAD(t *testing.T) {
	const pass = "test-master-pw"
	bobDir := t.TempDir()
	aliceDir := t.TempDir()

	// envelope.json: wrap a fresh master key under the test password.
	mk, _ := crypto.NewMasterKey()
	env, err := crypto.Wrap(mk, pass)
	if err != nil {
		t.Fatal(err)
	}
	env.ID = 1
	ef := &crypto.EnvelopeFile{Version: 3, Keys: []crypto.Envelope{*env}, Current: 1}
	efJSON, _ := crypto.MarshalEnvelopeFile(ef)
	if err := os.WriteFile(filepath.Join(bobDir, "envelope.json"), efJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	// A legacy (no-AAD) v1 vault entry, sealed under the same master key.
	store := localvault.Open(aliceDir)
	body, _ := crypto.Seal(mk, []byte("the-secret"))
	v, _ := store.Load()
	v.Set("my-secret", localvault.SecretEntry{Value: crypto.PackVersion(1, body)})
	if err := store.Save(v); err != nil {
		t.Fatal(err)
	}

	// Run migrate-aad (password via env, no TTY).
	t.Setenv("ANB_BOB_PASSWORD", pass)
	if err := cmdMigrateAAD([]string{"-dir", bobDir, "-vault-dir", aliceDir}); err != nil {
		t.Fatalf("migrate-aad: %v", err)
	}

	// The entry is now AAD-bound under its name.
	v2, _ := store.Load()
	e, ok := v2.Get("my-secret")
	if !ok {
		t.Fatal("entry vanished after migration")
	}
	_, raw, _ := crypto.ParseVersion(e.Value)
	if pt, err := crypto.OpenAAD(mk, raw, []byte("my-secret")); err != nil || string(pt) != "the-secret" {
		t.Fatalf("post-migration OpenAAD: pt=%q err=%v", pt, err)
	}
	if _, err := crypto.OpenAAD(mk, raw, []byte("other-name")); err == nil {
		t.Fatal("post-migration: wrong-name open must fail (substitution prevented)")
	}
	if _, err := crypto.Open(mk, raw); err == nil {
		t.Fatal("post-migration: legacy nil-aad Open should now fail (entry is aad-bound)")
	}

	// Idempotent: a second run succeeds and changes nothing.
	t.Setenv("ANB_BOB_PASSWORD", pass) // loadAndUnwrapEnvelope unset it on the first run
	if err := cmdMigrateAAD([]string{"-dir", bobDir, "-vault-dir", aliceDir}); err != nil {
		t.Fatalf("idempotent re-run: %v", err)
	}
}
