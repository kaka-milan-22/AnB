// Package e2e drives the whole stack at the library level: a real Bob oracle
// over loopback mTLS, a real Alice client, the local vault, and the redaction
// engine — exercising set / read / write / presence / locked exactly as the
// CLI does, minus the TTY plumbing. It is the authoritative correctness proof
// of the Alice↔Bob system.
package e2e

import (
	"crypto/tls"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kaka-milan-22/AnB/internal/authz"
	"github.com/kaka-milan-22/AnB/internal/ca"
	"github.com/kaka-milan-22/AnB/internal/client"
	"github.com/kaka-milan-22/AnB/internal/crypto"
	"github.com/kaka-milan-22/AnB/internal/keystore"
	"github.com/kaka-milan-22/AnB/internal/localvault"
	"github.com/kaka-milan-22/AnB/internal/mtls"
	"github.com/kaka-milan-22/AnB/internal/redact"
	"github.com/kaka-milan-22/AnB/internal/server"
)

type bob struct {
	authority *ca.CA
	addr      string
}

func startBob(t *testing.T, store *keystore.Store, policy *authz.Policy) *bob {
	t.Helper()
	authority, err := ca.NewCA("e2e-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, _ := authority.IssueServer([]string{"localhost", "127.0.0.1"}, time.Hour)
	sc, _ := mtls.ServerConfig(srvCert, srvKey, authority.CertPEM)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", sc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := server.New(store, policy, log.New(io.Discard, "", 0))
	go srv.Serve(ln)
	return &bob{authority: authority, addr: ln.Addr().String()}
}

// aliceClient enrolls an identity by minting a client cert (the CSR→sign flow,
// compressed) and returns a connected client.
func (b *bob) aliceClient(t *testing.T, identity string) *client.Client {
	t.Helper()
	csr, key, err := ca.GenerateCSR(identity)
	if err != nil {
		t.Fatal(err)
	}
	cert, gotID, err := b.authority.SignCSR(csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != identity {
		t.Fatalf("identity mismatch %q", gotID)
	}
	cl, err := client.New(b.addr, "localhost", cert, key, b.authority.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

func unlockedStore(t *testing.T) *keystore.Store {
	mk, _ := crypto.NewMasterKey()
	s := keystore.New(nil)
	s.Hold(mk, 0)
	return s
}

// TestFullFlow walks set → read (redact) → write (restore) through real mTLS.
func TestFullFlow(t *testing.T) {
	b := startBob(t, unlockedStore(t), &authz.Policy{DefaultAllow: true})
	cl := b.aliceClient(t, "alice")
	store := localvault.Open(t.TempDir())

	// set: Bob encrypts, Alice stores ciphertext.
	const secret = "sk-live-abcdefghijklmnop0123456789"
	packed, err := cl.Encrypt("stripe-key", secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	v, _ := store.Load()
	v.Set("stripe-key", localvault.SecretEntry{Value: packed, CreatedAt: "now"})
	if err := store.Save(v); err != nil {
		t.Fatal(err)
	}

	// read: decrypt all via Bob, redact a file mentioning the secret.
	file := filepath.Join(store.Dir, "config.env")
	os.WriteFile(file, []byte("STRIPE="+secret+"\n"), 0o644)

	v, _ = store.Load()
	vals := decryptAll(t, cl, v)
	redacted := redact.Redact(readFile(t, file), vals)
	if strings.Contains(redacted, secret) {
		t.Fatalf("secret leaked through redaction: %q", redacted)
	}
	if !strings.Contains(redacted, "<agent-vault:stripe-key>") {
		t.Fatalf("expected placeholder, got %q", redacted)
	}

	// write: restore the placeholder back to the real value.
	res := redact.Restore("STRIPE=<agent-vault:stripe-key>\n", func(k string) (string, bool) {
		e, ok := v.Get(k)
		if !ok {
			return "", false
		}
		pt, derr := cl.Decrypt(k, e.Value, e.RequirePresence)
		if derr != nil {
			t.Fatalf("decrypt %s: %v", k, derr)
		}
		return pt, true
	})
	if len(res.Missing) != 0 || !strings.Contains(res.Content, secret) {
		t.Fatalf("restore failed: %+v", res)
	}
}

func TestPresenceGatedDecrypt(t *testing.T) {
	policy := &authz.Policy{Rules: map[string][]string{"alice": {"*"}, "agent": {"*"}}}
	policy.Presence.Allow = []string{"alice"}
	b := startBob(t, unlockedStore(t), policy)

	// alice stores a gated secret.
	alice := b.aliceClient(t, "alice")
	packed, _ := alice.Encrypt("gated", "top-secret")

	// agent is authorized for the key but not on the presence allowlist.
	agent := b.aliceClient(t, "agent")
	if _, err := agent.Decrypt("gated", packed, true); err != client.ErrPresenceDenied {
		t.Fatalf("want ErrPresenceDenied for agent, got %v", err)
	}
	// alice may decrypt the gated key.
	pt, err := alice.Decrypt("gated", packed, true)
	if err != nil || pt != "top-secret" {
		t.Fatalf("alice gated decrypt: pt=%q err=%v", pt, err)
	}
}

func TestLockedBobRefuses(t *testing.T) {
	b := startBob(t, keystore.New(nil), &authz.Policy{DefaultAllow: true}) // never unlocked
	cl := b.aliceClient(t, "alice")
	if _, err := cl.Encrypt("k", "v"); err != client.ErrLocked {
		t.Fatalf("want ErrLocked, got %v", err)
	}
}

// --- helpers ---

func decryptAll(t *testing.T, cl *client.Client, v *localvault.Vault) map[string]string {
	t.Helper()
	var keys, packed []string
	gated := false
	for k, e := range v.Secrets {
		keys = append(keys, k)
		packed = append(packed, e.Value)
		gated = gated || e.RequirePresence
	}
	pts, err := cl.DecryptMany(keys, packed, gated)
	if err != nil {
		t.Fatalf("decryptMany: %v", err)
	}
	m := map[string]string{}
	for i := range keys {
		m[pts[i]] = keys[i]
	}
	return m
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
