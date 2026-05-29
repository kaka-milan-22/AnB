// Package e2e drives the whole stack at the library level: a real Bob oracle
// over loopback mTLS, a real Alice client, the local vault, and the redaction
// engine — exercising set / read / write / locked exactly as the
// CLI does, minus the TTY plumbing. It is the authoritative correctness proof
// of the Alice↔Bob system.
package e2e

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kaka-milan-22/AnB/v2/internal/authz"
	"github.com/kaka-milan-22/AnB/v2/internal/ca"
	"github.com/kaka-milan-22/AnB/v2/internal/client"
	"github.com/kaka-milan-22/AnB/v2/internal/crypto"
	"github.com/kaka-milan-22/AnB/v2/internal/keystore"
	"github.com/kaka-milan-22/AnB/v2/internal/localvault"
	"github.com/kaka-milan-22/AnB/v2/internal/mtls"
	"github.com/kaka-milan-22/AnB/v2/internal/redact"
	"github.com/kaka-milan-22/AnB/v2/internal/server"
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
		pt, derr := cl.Decrypt(k, e.Value)
		if derr != nil {
			t.Fatalf("decrypt %s: %v", k, derr)
		}
		return pt, true
	})
	if len(res.Missing) != 0 || !strings.Contains(res.Content, secret) {
		t.Fatalf("restore failed: %+v", res)
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
	for k, e := range v.Secrets {
		keys = append(keys, k)
		packed = append(packed, e.Value)
	}
	pts, err := cl.DecryptMany(keys, packed)
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

func TestPairingEnrollEndToEnd(t *testing.T) {
	// Stand up a fresh CA (mirrors what `bob ca init` writes to disk).
	authority, err := ca.NewCA("e2e-ca", time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	// Alice side: generate keypair + CSR.
	csrPEM, _, err := ca.GenerateCSR("e2e-alice")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}

	// Bob side: derive the pubkey fingerprint from the CSR, mint a code,
	// commit, and sign.
	code, err := ca.NewPairingCode()
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	commit := ca.PairingCommit(code, fp[:])
	certPEM, ident, err := authority.SignCSRWithPairing(csrPEM, time.Hour, ca.Pairing{
		Commit:    commit,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("SignCSRWithPairing: %v", err)
	}
	if ident != "e2e-alice" {
		t.Fatalf("identity: got %q want %q", ident, "e2e-alice")
	}

	// Alice side: parse cert, verify pairing with the right code, wrong code,
	// and expired window.
	certBlk, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.VerifyPairing(cert, code, time.Now()); err != nil {
		t.Fatalf("happy path: %v", err)
	}
	if err := ca.VerifyPairing(cert, "00000000", time.Now()); !errors.Is(err, ca.ErrPairingMismatch) {
		t.Fatalf("wrong code: got %v want ErrPairingMismatch", err)
	}
	future := time.Now().Add(11 * time.Minute)
	if err := ca.VerifyPairing(cert, code, future); !errors.Is(err, ca.ErrPairingExpired) {
		t.Fatalf("expired: got %v want ErrPairingExpired", err)
	}
}

// --- alice exec e2e (subprocess) ---

// execHarness holds everything the alice exec subprocess tests need: a running
// Bob, the alice state directory seeded with cert/key/CA/config, and the path
// to a freshly-built alice binary. Subprocess invocation is required because
// cmdExec terminates via syscall.Exec — calling it in-process would kill the
// test runner.
type execHarness struct {
	tmpDir    string
	aliceDir  string
	alicePath string
	cl        *client.Client
	vault     *localvault.Store
	caPEM     []byte
	bobAddr   string
}

// newExecHarness spins up Bob, mints an Alice identity, writes all disk state
// the alice subprocess needs, and builds the alice binary. The caller must
// defer h.cleanup() (but t.Cleanup also covers Bob's listener).
func newExecHarness(t *testing.T) *execHarness {
	t.Helper()

	store := unlockedStore(t)
	b := startBob(t, store, &authz.Policy{DefaultAllow: true})

	tmpDir := t.TempDir()
	aliceDir := filepath.Join(tmpDir, "alice-state")
	if err := os.MkdirAll(aliceDir, 0o700); err != nil {
		t.Fatalf("mkdir aliceDir: %v", err)
	}

	// Mint a client cert directly via the test CA (no CSR round-trip needed).
	csrPEM, keyPEM, err := ca.GenerateCSR("e2e-exec-alice")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	certPEM, _, err := b.authority.SignCSR(csrPEM, time.Hour)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}

	// Write the disk state that loadClient expects.
	lv := localvault.Open(aliceDir)
	if err := os.WriteFile(lv.ClientCertPath(), certPEM, 0o600); err != nil {
		t.Fatalf("write client.crt: %v", err)
	}
	if err := os.WriteFile(lv.ClientKeyPath(), keyPEM, 0o600); err != nil {
		t.Fatalf("write client.key: %v", err)
	}
	if err := os.WriteFile(lv.CAPath(), b.authority.CertPEM, 0o600); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	cfg := localvault.Config{
		BobAddr:    b.addr,
		ServerName: "localhost",
		Identity:   "e2e-exec-alice",
	}
	cfgBytes, _ := json.Marshal(cfg)
	if err := os.WriteFile(lv.ConfigPath(), cfgBytes, 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	// Build an in-process client to seed secrets.
	cl, err := client.New(b.addr, "localhost", certPEM, keyPEM, b.authority.CertPEM)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	// Build the alice binary.
	alicePath := buildAlice(t, tmpDir)

	return &execHarness{
		tmpDir:    tmpDir,
		aliceDir:  aliceDir,
		alicePath: alicePath,
		cl:        cl,
		vault:     lv,
		caPEM:     b.authority.CertPEM,
		bobAddr:   b.addr,
	}
}

// seedSecret encrypts plaintext via Bob and stores the ciphertext in Alice's
// vault, mirroring what `alice set` does.
func (h *execHarness) seedSecret(t *testing.T, key, plaintext string) {
	t.Helper()
	packed, err := h.cl.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt %q: %v", key, err)
	}
	v, _ := h.vault.Load()
	v.Set(key, localvault.SecretEntry{Value: packed, CreatedAt: "now"})
	if err := h.vault.Save(v); err != nil {
		t.Fatalf("vault.Save: %v", err)
	}
}

// cleanup is a no-op (t.TempDir already registers cleanup with t.Cleanup).
func (h *execHarness) cleanup() {}

// seedAllowlist writes exec-allowlist.json under h.aliceDir with the given
// entries (each a JSON-formatted entry body — caller is responsible for
// shape). Overwrites any existing file (including the scaffold).
func (h *execHarness) seedAllowlist(t *testing.T, entries ...string) {
	t.Helper()
	body := `{"allow":[` + strings.Join(entries, ",") + `]}`
	if err := os.WriteFile(filepath.Join(h.aliceDir, "exec-allowlist.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// buildAlice compiles cmd/alice into dstDir and returns the binary path.
func buildAlice(t *testing.T, dstDir string) string {
	t.Helper()
	// Locate the repo root from this test file's path at compile time.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..")

	alicePath := filepath.Join(dstDir, "alice")
	cmd := exec.Command("go", "build", "-o", alicePath, "./cmd/alice")
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build alice: %v", err)
	}
	return alicePath
}

func TestAliceExecHappyPath(t *testing.T) {
	h := newExecHarness(t)
	defer h.cleanup()

	h.seedSecret(t, "smoke-key", "the-secret-value")

	outFile := filepath.Join(h.tmpDir, "exec-out.txt")
	h.seedAllowlist(t, fmt.Sprintf(`{
		"cmd":  "/bin/sh",
		"args": ["-c", "printf '%%s' \"$FOO\" > \"$1\"", "_", %q],
		"env":  ["FOO"]
	}`, outFile))
	cmd := exec.Command(h.alicePath,
		"exec",
		"--env", "FOO=<agent-vault:smoke-key>",
		"--",
		"/bin/sh", "-c", `printf '%s' "$FOO" > "$1"`, "_", outFile,
	)
	cmd.Env = append(os.Environ(), "ANB_ALICE_DIR="+h.aliceDir)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("alice exec: %v", err)
	}
	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read outfile: %v", err)
	}
	if string(got) != "the-secret-value" {
		t.Fatalf("outfile = %q, want %q", string(got), "the-secret-value")
	}
}

func TestAliceExecFailClosedOnMissingKey(t *testing.T) {
	h := newExecHarness(t)
	defer h.cleanup()

	// Do NOT seed the key — alice exec must fail before running the child.
	// Seed an allowlist that matches this invocation so the gate passes and
	// the test genuinely exercises the vault-missing-key path.
	outFile := filepath.Join(h.tmpDir, "should-not-exist.txt")
	h.seedAllowlist(t, fmt.Sprintf(`{
		"cmd":  "/bin/sh",
		"args": ["-c", "printf '%%s' \"$FOO\" > \"$1\"", "_", %q],
		"env":  ["FOO"]
	}`, outFile))
	cmd := exec.Command(h.alicePath,
		"exec",
		"--env", "FOO=<agent-vault:nonexistent-key>",
		"--",
		"/bin/sh", "-c", `printf '%s' "$FOO" > "$1"`, "_", outFile,
	)
	cmd.Env = append(os.Environ(), "ANB_ALICE_DIR="+h.aliceDir)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected alice exec to fail when --env references a missing key")
	}
	// Confirm the child never ran — outfile must not exist.
	if _, statErr := os.Stat(outFile); !os.IsNotExist(statErr) {
		t.Fatalf("child should NOT have run; outFile exists or stat error: statErr=%v", statErr)
	}
	// Sanity-check: stderr should mention the missing key.
	if !strings.Contains(stderr.String(), "vault has no key") {
		t.Logf("stderr was: %s", stderr.String())
		// Don't Fatal — exit code + missing outfile are the real assertions.
	}
}

func TestAliceEnrollScaffoldsAllowlist(t *testing.T) {
	h := newExecHarness(t)
	defer h.cleanup()

	// newExecHarness sets up Alice's state dir by writing files directly
	// (no cmdEnroll call). We need a FRESH state dir to test the scaffold
	// side-effect of alice enroll.
	freshDir := filepath.Join(h.tmpDir, "fresh-enroll")
	if err := os.MkdirAll(freshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(h.tmpDir, "enroll-ca.crt")
	if err := os.WriteFile(caPath, h.caPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(h.alicePath,
		"enroll",
		"--dir", freshDir,
		"--identity", "scaffold-test",
		"--bob", h.bobAddr,
		"--server-name", "localhost",
		"--ca", caPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("alice enroll: %v\noutput: %s", err, out)
	}

	allow := filepath.Join(freshDir, "exec-allowlist.json")
	st, err := os.Stat(allow)
	if err != nil {
		t.Fatalf("exec-allowlist.json should exist after enroll: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("exec-allowlist.json mode = %o, want 0o600", st.Mode().Perm())
	}
	b, err := os.ReadFile(allow)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != `{"allow":[]}` {
		t.Fatalf("scaffold content = %q, want {\"allow\":[]}", string(b))
	}
}

func TestAliceExecDeniedWhenAllowlistMissing(t *testing.T) {
	h := newExecHarness(t)
	defer h.cleanup()

	// IMPORTANT: do NOT seed an allowlist. The harness does not call
	// cmdEnroll's scaffold path, so the file doesn't exist by default —
	// but be defensive and remove it in case the harness changes.
	_ = os.Remove(filepath.Join(h.aliceDir, "exec-allowlist.json"))

	outFile := filepath.Join(h.tmpDir, "should-not-exist.txt")
	cmd := exec.Command(h.alicePath,
		"exec",
		"--env", "FOO=<agent-vault:any>",
		"--",
		"/bin/sh", "-c", `printf '%s' "$FOO" > "$1"`, "_", outFile,
	)
	cmd.Env = append(os.Environ(), "ANB_ALICE_DIR="+h.aliceDir)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected alice exec to fail without an allowlist file")
	}
	if !strings.Contains(stderr.String(), "exec-allowlist.json not found") {
		t.Logf("stderr was: %s", stderr.String())
		t.Fatal("expected 'exec-allowlist.json not found' in stderr")
	}
	if _, err := os.Stat(outFile); !os.IsNotExist(err) {
		t.Fatal("child should NOT have run; outFile exists")
	}
}

func TestAliceExecDeniedWhenNoMatch(t *testing.T) {
	h := newExecHarness(t)
	defer h.cleanup()

	// Seed an allowlist with an entry that does NOT match what we'll
	// invoke (different cmd, args, and env).
	h.seedAllowlist(t, `{
		"cmd":  "/usr/bin/true",
		"args": [],
		"env":  []
	}`)

	outFile := filepath.Join(h.tmpDir, "should-not-exist.txt")
	cmd := exec.Command(h.alicePath,
		"exec",
		"--env", "FOO=<agent-vault:any>",
		"--",
		"/bin/sh", "-c", `printf '%s' "$FOO" > "$1"`, "_", outFile,
	)
	cmd.Env = append(os.Environ(), "ANB_ALICE_DIR="+h.aliceDir)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected alice exec to fail with no-match")
	}
	out := stderr.String()
	if !strings.Contains(out, "invocation not in allowlist") {
		t.Logf("stderr was: %s", out)
		t.Fatal("expected 'invocation not in allowlist' in stderr")
	}
	// Confirm the copy-paste JSON snippet is included.
	if !strings.Contains(out, `"cmd":  "/bin/sh"`) {
		t.Logf("stderr was: %s", out)
		t.Fatal("expected suggested JSON entry with /bin/sh to be in stderr")
	}
	if _, err := os.Stat(outFile); !os.IsNotExist(err) {
		t.Fatal("child should NOT have run; outFile exists")
	}
}
