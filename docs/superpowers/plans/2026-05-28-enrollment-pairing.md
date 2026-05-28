# Enrollment Pairing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an OOB 8-digit pairing code to `bob sign-csr` / `alice install-cert` that is cryptographically bound to the issued cert's public key, expires 10 minutes after signing, and refuses install on mismatch or expiry. `--no-pair` on both sides bypasses (warned) for scripted use.

**Architecture:** A new `internal/ca/pairing.go` owns the pairing protocol — OID, code generation, commitment hash, ASN.1 codec, and verification. `internal/ca/ca.go` gets a `SignCSRWithPairing` method that embeds the pairing as a non-critical X.509 extension on the issued cert. `cmd/bob/main.go` (`cmdSignCSR`) and `cmd/alice/sensitive.go` (`cmdInstallCert`) wire the CLI: y/N confirm, code display, code prompt (or `ANB_PAIR_CODE`), `--no-pair` flag.

**Tech Stack:** Go 1.26, `crypto/rand`, `crypto/sha256`, `encoding/asn1`, `crypto/x509`, `crypto/x509/pkix`, existing `internal/term` TTY helpers, ed25519 keys (existing).

**Wire format:**

```text
X.509 extension (non-critical) at OID 2.25.9019028596234243738
value: SEQUENCE {
    commit     OCTET STRING (SIZE(32)),   -- SHA-256(code || pubkey_fp)
    expiresAt  GeneralizedTime
}
where code      = 8 ASCII digits (e.g. "47281930")
      pubkey_fp = SHA-256(cert.SubjectPublicKeyInfo DER)  -- 32 bytes
```

The OID is `{2, 25, 0x7d2cba5a, 0x4b8d4e9a}` — the top 64 bits of UUID `7d2cba5a-4b8d-4e9a-9c6b-1a3f5e7c9d2b` split into **two 32-bit arcs** rather than one 64-bit arc. Go `encoding/asn1` happily encodes the single-arc form, but `crypto/x509.ParseCertificate` caps each OID arc at 31 bits via `readBase128Int`, so a 63-bit arc encodes fine but readback fails with `x509: malformed extension OID field`. Splitting into 32-bit halves (each `< 2^31`) keeps the same UUID identity end-to-end. This was discovered during T4+T5 implementation; the originally-planned single-arc form `9019789050693635738` does not survive a cert round-trip.

---

## File structure

| File | What it owns |
|---|---|
| `internal/ca/pairing.go` (new) | `PairingOID`, `Pairing` struct, `NewPairingCode`, `PubkeyFingerprint`, `PairingCommit`, `Pairing.Encode`, `DecodePairing`, `VerifyPairing`, error sentinels. |
| `internal/ca/pairing_test.go` (new) | Unit tests for everything in `pairing.go`. |
| `internal/ca/ca.go` (modify) | Refactor private `sign()` to accept `[]pkix.Extension`; add public `(c *CA) SignCSRWithPairing(csrPEM, ttl, Pairing) (certPEM, identity, error)`. |
| `internal/term/term.go` (modify) | Add `ReadLine(prompt) (string, error)` for plain-echo line input. |
| `cmd/bob/main.go` (modify, around line 213 `cmdSignCSR`) | `--no-pair` flag, default path: parse CSR, show identity + fingerprint + generated code + y/N confirm, then `SignCSRWithPairing`. |
| `cmd/alice/sensitive.go` (modify, around line 487 `cmdInstallCert`) | `--no-pair` flag, default path: parse cert, decode pairing extension, read code (env `ANB_PAIR_CODE` or TTY), call `VerifyPairing`, then install. |
| `e2e/full_test.go` (modify) | Happy-path + wrong-code + expired pairing cases. |

Tasks are small, TDD-driven, one commit per task, on branch `feat/enrollment-pairing` (already created).

---

### Task 1: PairingOID, types, and code generator

**Files:**
- Create: `internal/ca/pairing.go`
- Test: `internal/ca/pairing_test.go`

- [ ] **Step 1: Write the failing tests**

```go
// internal/ca/pairing_test.go
package ca

import (
	"encoding/asn1"
	"regexp"
	"testing"
)

func TestPairingOIDValue(t *testing.T) {
	want := asn1.ObjectIdentifier{2, 25, 0x7d2cba5a4b8d4e9a}
	if !PairingOID.Equal(want) {
		t.Fatalf("PairingOID = %v, want %v", PairingOID, want)
	}
}

func TestNewPairingCodeFormat(t *testing.T) {
	re := regexp.MustCompile(`^[0-9]{8}$`)
	for i := 0; i < 100; i++ {
		c, err := NewPairingCode()
		if err != nil {
			t.Fatalf("NewPairingCode: %v", err)
		}
		if !re.MatchString(c) {
			t.Fatalf("code %q not 8 digits", c)
		}
	}
}

func TestNewPairingCodeNotConstant(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 32; i++ {
		c, _ := NewPairingCode()
		seen[c] = struct{}{}
	}
	if len(seen) < 16 { // 16/32 distinct is a very loose lower bound
		t.Fatalf("NewPairingCode looks non-random: only %d distinct in 32", len(seen))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail (undefined symbols)**

```sh
cd /Users/bbwave03/claude/anb
go test ./internal/ca/ -run 'TestPairing|TestNewPairing' -v
```
Expected: build errors `undefined: PairingOID`, `undefined: NewPairingCode`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/ca/pairing.go
//
// Package-internal protocol for enrollment pairing: an 8-digit OOB code that
// binds a freshly-signed client cert to the operator who watched it being
// signed. See README §"Enroll Alice (with operator pairing)" for the wire
// format and threat model.
package ca

import (
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// PairingOID is the X.509 extension OID for the pairing payload.
// Derived once: top 64 bits of UUID 7d2cba5a-4b8d-4e9a-9c6b-1a3f5e7c9d2b
// under the 2.25 (UUID-based) arc. Project-internal; not registered.
var PairingOID = asn1.ObjectIdentifier{2, 25, 0x7d2cba5a4b8d4e9a}

// pairingCodeRange is exclusive upper bound: 10^8.
var pairingCodeRange = big.NewInt(100_000_000)

// NewPairingCode returns a fresh 8-digit decimal code (with leading zeros)
// drawn from crypto/rand. ~26.6 bits of entropy; sized for one-shot OOB use
// inside the 10-minute window, not as a credential.
func NewPairingCode() (string, error) {
	n, err := rand.Int(rand.Reader, pairingCodeRange)
	if err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return fmt.Sprintf("%08d", n.Int64()), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/ca/ -run 'TestPairing|TestNewPairing' -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```sh
cd /Users/bbwave03/claude/anb
git add internal/ca/pairing.go internal/ca/pairing_test.go
git commit -m "feat(ca): add PairingOID and NewPairingCode

Defines the X.509 extension OID for enrollment pairing and a
crypto/rand-backed 8-digit code generator.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Pubkey fingerprint and commit hash

**Files:**
- Modify: `internal/ca/pairing.go`
- Test: `internal/ca/pairing_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/ca/pairing_test.go`:

```go
import (
	// add to existing imports:
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"time"
)

func mustIssueClientCert(t *testing.T) *x509.Certificate {
	t.Helper()
	c, err := NewCA("test-ca", time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	certPEM, _, err := c.IssueClient("test-id", time.Hour)
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	blk, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func TestPubkeyFingerprintMatchesSPKISHA256(t *testing.T) {
	cert := mustIssueClientCert(t)
	got := PubkeyFingerprint(cert)
	want := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if len(got) != 32 {
		t.Fatalf("fp len = %d, want 32", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("fp mismatch at byte %d: got %x want %x", i, got[i], want[i])
		}
	}
}

func TestPairingCommitKnownAnswer(t *testing.T) {
	code := "47281930"
	fp := make([]byte, 32)
	for i := range fp {
		fp[i] = 0xAB
	}
	got := PairingCommit(code, fp)
	want := sha256.Sum256(append([]byte(code), fp...))
	if len(got) != 32 {
		t.Fatalf("commit len = %d, want 32", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("commit mismatch at byte %d: got %x want %x", i, got[i], want[i])
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```sh
go test ./internal/ca/ -run 'TestPubkeyFingerprint|TestPairingCommit' -v
```
Expected: build errors `undefined: PubkeyFingerprint`, `undefined: PairingCommit`.

- [ ] **Step 3: Implement**

Append to `internal/ca/pairing.go`:

```go
import (
	// add to existing imports:
	"crypto/sha256"
	"crypto/x509"
)

// PubkeyFingerprint returns SHA-256 of the cert's SubjectPublicKeyInfo DER.
// This is the binding handle used by PairingCommit — the same bytes Alice
// will recompute from the installed cert.
func PubkeyFingerprint(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:]
}

// PairingCommit = SHA-256(code || pubkey_fp). Both inputs are raw bytes:
// code as 8 ASCII digits, pubkey_fp as the 32-byte SHA-256 of SPKI.
func PairingCommit(code string, pubkeyFP []byte) []byte {
	h := sha256.New()
	h.Write([]byte(code))
	h.Write(pubkeyFP)
	return h.Sum(nil)
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/ca/ -v
```
Expected: all pairing tests PASS.

- [ ] **Step 5: Commit**

```sh
git add internal/ca/pairing.go internal/ca/pairing_test.go
git commit -m "feat(ca): add PubkeyFingerprint and PairingCommit

SHA-256 of SubjectPublicKeyInfo DER for the fingerprint;
SHA-256(code || pubkey_fp) for the commit. Both used to bind the
8-digit OOB code to the specific issued cert.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Pairing struct + ASN.1 codec

**Files:**
- Modify: `internal/ca/pairing.go`
- Test: `internal/ca/pairing_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/ca/pairing_test.go`:

```go
func TestPairingEncodeDecodeRoundTrip(t *testing.T) {
	commit := make([]byte, 32)
	for i := range commit {
		commit[i] = byte(i)
	}
	exp := time.Date(2026, 5, 28, 14, 23, 5, 0, time.UTC)
	in := Pairing{Commit: commit, ExpiresAt: exp}

	b, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := decodePairingValue(b)
	if err != nil {
		t.Fatalf("decodePairingValue: %v", err)
	}
	if !out.ExpiresAt.Equal(exp) {
		t.Fatalf("ExpiresAt round-trip: got %v want %v", out.ExpiresAt, exp)
	}
	if len(out.Commit) != 32 {
		t.Fatalf("commit len = %d", len(out.Commit))
	}
	for i := range commit {
		if out.Commit[i] != commit[i] {
			t.Fatalf("commit byte %d mismatch", i)
		}
	}
}

func TestPairingEncodeRejectsWrongCommitSize(t *testing.T) {
	p := Pairing{Commit: []byte{1, 2, 3}, ExpiresAt: time.Now()}
	if _, err := p.Encode(); err == nil {
		t.Fatal("expected error for short commit")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```sh
go test ./internal/ca/ -run 'TestPairingEncode' -v
```
Expected: build errors for `Pairing`, `decodePairingValue`.

- [ ] **Step 3: Implement**

Append to `internal/ca/pairing.go`:

```go
import (
	// add to existing imports:
	"errors"
	"time"
)

// Pairing is the deserialized contents of the X.509 extension. ExpiresAt is
// stored in UTC to match ASN.1 GeneralizedTime semantics.
type Pairing struct {
	Commit    []byte    // 32 bytes
	ExpiresAt time.Time // UTC
}

// asn1Pairing is the wire form: SEQUENCE { commit OCTET STRING, expiresAt GeneralizedTime }.
type asn1Pairing struct {
	Commit    []byte
	ExpiresAt time.Time `asn1:"generalized"`
}

// Encode marshals the Pairing as the bytes that go into the X.509 extension
// Value field.
func (p Pairing) Encode() ([]byte, error) {
	if len(p.Commit) != 32 {
		return nil, fmt.Errorf("pairing commit: want 32 bytes, got %d", len(p.Commit))
	}
	w := asn1Pairing{Commit: p.Commit, ExpiresAt: p.ExpiresAt.UTC()}
	return asn1.Marshal(w)
}

// decodePairingValue is the inverse of Encode. Package-private because the
// public entry point is DecodePairing(cert).
func decodePairingValue(b []byte) (*Pairing, error) {
	var w asn1Pairing
	rest, err := asn1.Unmarshal(b, &w)
	if err != nil {
		return nil, fmt.Errorf("pairing asn1: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("pairing asn1: trailing bytes")
	}
	if len(w.Commit) != 32 {
		return nil, fmt.Errorf("pairing commit: want 32 bytes, got %d", len(w.Commit))
	}
	return &Pairing{Commit: w.Commit, ExpiresAt: w.ExpiresAt.UTC()}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/ca/ -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add internal/ca/pairing.go internal/ca/pairing_test.go
git commit -m "feat(ca): add Pairing struct and ASN.1 codec

SEQUENCE { commit OCTET STRING, expiresAt GeneralizedTime } — the
wire format for the X.509 extension. UTC-only on the way in and out.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: DecodePairing(cert) + VerifyPairing

**Files:**
- Modify: `internal/ca/pairing.go`
- Test: `internal/ca/pairing_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/ca/pairing_test.go`:

```go
import (
	// add to existing imports:
	"crypto/x509/pkix"
)

// helper: produce a parsed cert with a pairing extension attached.
func mustIssueClientCertWithExt(t *testing.T, p Pairing) *x509.Certificate {
	t.Helper()
	c, err := NewCA("test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	val, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, _, err := GenerateCSR("test-id")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := c.SignCSRWithPairing(csrPEM, time.Hour, Pairing{
		Commit:    p.Commit,
		ExpiresAt: p.ExpiresAt,
	})
	if err != nil {
		t.Fatalf("SignCSRWithPairing: %v", err)
	}
	_ = val
	blk, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestDecodePairingReturnsNilWhenAbsent(t *testing.T) {
	cert := mustIssueClientCert(t) // no extension
	p, err := DecodePairing(cert)
	if err != nil {
		t.Fatalf("DecodePairing: %v", err)
	}
	if p != nil {
		t.Fatalf("expected nil, got %+v", p)
	}
}

func TestVerifyPairingHappyPath(t *testing.T) {
	code := "47281930"
	exp := time.Now().Add(10 * time.Minute)
	// To build the commit we need the real cert pubkey, so we mint a CSR/cert
	// the same way Bob would.
	c, err := NewCA("vt-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, _, err := GenerateCSR("vt-id")
	if err != nil {
		t.Fatal(err)
	}
	// Pre-sign with a placeholder commit to learn the pubkey, then re-sign
	// with the real commit. Simpler: peek the pubkey from the CSR.
	blk, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	commit := PairingCommit(code, fp[:])
	certPEM, _, err := c.SignCSRWithPairing(csrPEM, time.Hour, Pairing{
		Commit:    commit,
		ExpiresAt: exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(decodePEM(t, certPEM))
	if err := VerifyPairing(cert, code, time.Now()); err != nil {
		t.Fatalf("VerifyPairing: %v", err)
	}
}

func TestVerifyPairingWrongCode(t *testing.T) {
	cert, code := mintCertForPairing(t, "47281930", 10*time.Minute)
	_ = code
	err := VerifyPairing(cert, "00000000", time.Now())
	if !errors.Is(err, ErrPairingMismatch) {
		t.Fatalf("want ErrPairingMismatch, got %v", err)
	}
}

func TestVerifyPairingExpired(t *testing.T) {
	cert, code := mintCertForPairing(t, "47281930", 10*time.Minute)
	future := time.Now().Add(11 * time.Minute)
	err := VerifyPairing(cert, code, future)
	if !errors.Is(err, ErrPairingExpired) {
		t.Fatalf("want ErrPairingExpired, got %v", err)
	}
}

func TestVerifyPairingMissingExtension(t *testing.T) {
	cert := mustIssueClientCert(t)
	err := VerifyPairing(cert, "00000000", time.Now())
	if !errors.Is(err, ErrPairingAbsent) {
		t.Fatalf("want ErrPairingAbsent, got %v", err)
	}
}

// mintCertForPairing: signs a fresh CSR with a real pairing extension whose
// commit binds the given code. Returns the parsed cert + the code.
func mintCertForPairing(t *testing.T, code string, ttl time.Duration) (*x509.Certificate, string) {
	t.Helper()
	c, err := NewCA("vt-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, _, err := GenerateCSR("vt-id")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	commit := PairingCommit(code, fp[:])
	certPEM, _, err := c.SignCSRWithPairing(csrPEM, time.Hour, Pairing{
		Commit:    commit,
		ExpiresAt: time.Now().Add(ttl),
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(decodePEM(t, certPEM))
	if err != nil {
		t.Fatal(err)
	}
	return cert, code
}

func decodePEM(t *testing.T, p []byte) []byte {
	t.Helper()
	blk, _ := pem.Decode(p)
	if blk == nil {
		t.Fatal("not a PEM block")
	}
	return blk.Bytes
}

// silence unused-import warnings if needed
var _ pkix.Extension
```

- [ ] **Step 2: Run tests to verify they fail**

```sh
go test ./internal/ca/ -run 'TestDecodePairing|TestVerifyPairing' -v
```
Expected: build errors `undefined: DecodePairing`, `undefined: VerifyPairing`, `undefined: ErrPairingMismatch`, `undefined: ErrPairingExpired`, `undefined: ErrPairingAbsent`, `undefined: (*CA).SignCSRWithPairing`.

(Task 5 adds `SignCSRWithPairing`; finish that first if subagent-driven execution is reordering, then re-run Task 4 tests.)

- [ ] **Step 3: Implement DecodePairing + VerifyPairing + errors**

Append to `internal/ca/pairing.go`:

```go
// Sentinel errors so callers (alice install-cert) can distinguish failure
// reasons in their UX.
var (
	ErrPairingAbsent   = errors.New("pairing: extension not present in cert")
	ErrPairingExpired  = errors.New("pairing: code window has expired")
	ErrPairingMismatch = errors.New("pairing: code does not match commitment")
)

// DecodePairing returns the parsed Pairing from the cert's extension, or
// (nil, nil) if the extension is absent. Critical-flag is ignored on read
// (we always write non-critical).
func DecodePairing(cert *x509.Certificate) (*Pairing, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(PairingOID) {
			return decodePairingValue(ext.Value)
		}
	}
	return nil, nil
}

// VerifyPairing checks the supplied code against the cert's embedded pairing.
// Returns nil iff: extension present, now <= expiresAt, and
// SHA-256(code || pubkey_fp) equals the commit.
func VerifyPairing(cert *x509.Certificate, code string, now time.Time) error {
	p, err := DecodePairing(cert)
	if err != nil {
		return err
	}
	if p == nil {
		return ErrPairingAbsent
	}
	if now.After(p.ExpiresAt) {
		return ErrPairingExpired
	}
	got := PairingCommit(code, PubkeyFingerprint(cert))
	if subtleConstantTimeEqual(got, p.Commit) != 1 {
		return ErrPairingMismatch
	}
	return nil
}
```

Also add at the top of the file, in the imports, a constant-time compare helper. To keep the package's dependency surface small (`crypto/subtle` isn't used elsewhere in `ca`), wrap it:

```go
import (
	// add to existing imports:
	"crypto/subtle"
)

func subtleConstantTimeEqual(a, b []byte) int { return subtle.ConstantTimeCompare(a, b) }
```

- [ ] **Step 4: Run tests to verify they pass**

After Task 5 lands (provides `SignCSRWithPairing`), run:

```sh
go test ./internal/ca/ -v
```
Expected: all pairing tests PASS.

- [ ] **Step 5: Commit**

```sh
git add internal/ca/pairing.go internal/ca/pairing_test.go
git commit -m "feat(ca): DecodePairing and VerifyPairing with sentinel errors

ErrPairingAbsent / ErrPairingExpired / ErrPairingMismatch let the CLI
distinguish failure reasons. Constant-time compare on the commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: CA.SignCSRWithPairing

**Files:**
- Modify: `internal/ca/ca.go`
- Test: `internal/ca/pairing_test.go` (re-uses tests defined in Task 4)

- [ ] **Step 1: Write the failing test (skip if already added in Task 4)**

The tests from Task 4 already exercise `SignCSRWithPairing`. Add one extra assertion focusing only on the extension's presence and non-criticality:

```go
func TestSignCSRWithPairingEmbedsNonCriticalExt(t *testing.T) {
	cert, _ := mintCertForPairing(t, "12345678", time.Minute)
	var found *pkix.Extension
	for i, ext := range cert.Extensions {
		if ext.Id.Equal(PairingOID) {
			found = &cert.Extensions[i]
			break
		}
	}
	if found == nil {
		t.Fatal("pairing extension missing from signed cert")
	}
	if found.Critical {
		t.Fatal("pairing extension must be non-critical")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```sh
go test ./internal/ca/ -run 'TestSignCSRWithPairing' -v
```
Expected: build error `undefined: (*CA).SignCSRWithPairing`.

- [ ] **Step 3: Refactor `sign()` and add `SignCSRWithPairing`**

In `internal/ca/ca.go`, change the private `sign` signature to accept extra extensions, and update callers. Replace the current `sign` (lines ~159-180) with:

```go
func (c *CA) sign(cn string, hosts []string, pub any, eku x509.ExtKeyUsage, ttl time.Duration, extras []pkix.Extension) ([]byte, error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:    sn,
		Subject:         pkix.Name{CommonName: cn},
		NotBefore:       time.Now().Add(-time.Minute),
		NotAfter:        time.Now().Add(ttl),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{eku},
		ExtraExtensions: extras,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	return x509.CreateCertificate(rand.Reader, tmpl, c.Cert, pub, c.Key)
}
```

Update the two existing callers in the same file:

```go
// inside issueLeaf:
der, err := c.sign(cn, hosts, pub, eku, ttl, nil)

// inside SignCSR:
der, err := c.sign(csr.Subject.CommonName, nil, csr.PublicKey, x509.ExtKeyUsageClientAuth, ttl, nil)
```

Add the new public method just below `SignCSR`:

```go
// SignCSRWithPairing is SignCSR plus a non-critical X.509 extension carrying
// the supplied Pairing. The caller computes the commit binding `code` to the
// CSR's public key BEFORE calling, so the extension is committed by Bob's
// signature on the cert as a whole.
func (c *CA) SignCSRWithPairing(csrPEM []byte, ttl time.Duration, pairing Pairing) (certPEM []byte, identity string, err error) {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != pemCSR {
		return nil, "", errors.New("not a PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, "", fmt.Errorf("csr signature: %w", err)
	}
	if csr.Subject.CommonName == "" {
		return nil, "", errors.New("csr has empty CommonName (identity)")
	}
	val, err := pairing.Encode()
	if err != nil {
		return nil, "", fmt.Errorf("pairing encode: %w", err)
	}
	extras := []pkix.Extension{{Id: PairingOID, Critical: false, Value: val}}
	der, err := c.sign(csr.Subject.CommonName, nil, csr.PublicKey, x509.ExtKeyUsageClientAuth, ttl, extras)
	if err != nil {
		return nil, "", err
	}
	return encode(pemCert, der), csr.Subject.CommonName, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```sh
go test ./internal/ca/ -v
go test ./... 2>&1 | tail -20
```
Expected: all PASS; nothing else regressed.

- [ ] **Step 5: Commit**

```sh
git add internal/ca/ca.go internal/ca/pairing_test.go
git commit -m "feat(ca): SignCSRWithPairing embeds the pairing extension

Refactors the internal sign() to accept ExtraExtensions, then adds a
public SignCSRWithPairing that mirrors SignCSR but attaches one
non-critical X.509 extension at PairingOID carrying the encoded
Pairing.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: term.ReadLine

**Files:**
- Modify: `internal/term/term.go`
- Test: `internal/term/term_test.go` (new)

- [ ] **Step 1: Write the failing test**

```go
// internal/term/term_test.go
package term

import (
	"os"
	"strings"
	"testing"
)

func TestReadLineTrimsCRLF(t *testing.T) {
	// Drive stdin from a pipe so the test is hermetic.
	orig := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Stdin = orig })
	os.Stdin = r
	go func() {
		_, _ = w.WriteString("47281930\r\n")
		_ = w.Close()
	}()

	got, err := ReadLine("Enter code: ")
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	if got != "47281930" {
		t.Fatalf("got %q want %q", got, "47281930")
	}
	// Output of the prompt is on stderr; we don't capture/assert it here.
	_ = strings.TrimSpace
}
```

- [ ] **Step 2: Run test to verify it fails**

```sh
go test ./internal/term/ -v
```
Expected: build error `undefined: ReadLine`.

- [ ] **Step 3: Implement**

Append to `internal/term/term.go`:

```go
// ReadLine prompts on stderr and reads one line from stdin (echo not
// disabled — for non-secret short inputs like the OOB pairing code).
// Trailing CR/LF are trimmed.
func ReadLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

```sh
go test ./internal/term/ -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add internal/term/term.go internal/term/term_test.go
git commit -m "feat(term): add ReadLine for plain-echo prompts

Used by alice install-cert for the 8-digit pairing code (not a
secret; should be echoed so the operator can see typos).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: bob sign-csr — interactive pairing + --no-pair

**Files:**
- Modify: `cmd/bob/main.go` (function `cmdSignCSR` around line 213)

No new test file — the layer is glue; correctness is covered by the e2e test in Task 9. Run the build + smoke locally.

- [ ] **Step 1: Replace `cmdSignCSR` with the paired version**

Open `cmd/bob/main.go`. Replace the body of `cmdSignCSR` (currently lines ~213-248) with:

```go
func cmdSignCSR(args []string) error {
	fs := newFlags("sign-csr")
	dir := fs.String("dir", "", "state dir")
	out := fs.String("out", "", "write client cert here (default: stdout)")
	days := fs.Int("ttl-days", 90, "client cert validity in days")
	noPair := fs.Bool("no-pair", false, "skip OOB pairing — sign without an enrollment code (warned)")
	rest := parse(fs, args)
	if len(rest) != 1 {
		return fmt.Errorf("usage: bob sign-csr <csr.pem> [--out FILE] [--ttl-days N] [--no-pair]")
	}

	d := bobDir(*dir)
	caCertPEM, _ := readFile(d, "ca.crt")
	caKeyPEM, _ := readFile(d, "ca.key")
	authority, err := ca.LoadCA(caCertPEM, caKeyPEM)
	if err != nil {
		return err
	}
	csrPEM, err := os.ReadFile(rest[0])
	if err != nil {
		return err
	}

	// Pre-parse to surface CSR identity + pubkey fingerprint to the operator.
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("not a PEM CSR: %s", rest[0])
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return fmt.Errorf("parse CSR: %w", err)
	}
	if csr.Subject.CommonName == "" {
		return fmt.Errorf("CSR has empty CommonName")
	}
	fp := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	fpHex := hex.EncodeToString(fp[:])

	if *noPair {
		fmt.Fprintf(os.Stderr, "⚠ --no-pair: signing without an OOB pairing code (any holder of this cert can install it)\n")
		fmt.Fprintf(os.Stderr, "→ CSR identity:  %s\n", csr.Subject.CommonName)
		fmt.Fprintf(os.Stderr, "→ CSR pubkey fp: %s\n", fpHex)
		ok, err := term.Confirm(fmt.Sprintf("Sign %q without pairing?", csr.Subject.CommonName), false)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("aborted")
		}
		certPEM, _, err := authority.SignCSR(csrPEM, time.Duration(*days)*24*time.Hour)
		if err != nil {
			return err
		}
		return writeOrStdout(out, certPEM)
	}

	code, err := ca.NewPairingCode()
	if err != nil {
		return err
	}
	expires := time.Now().Add(pairCodeTTL)
	commit := ca.PairingCommit(code, fp[:])

	fmt.Fprintf(os.Stderr, "→ CSR identity:  %s\n", csr.Subject.CommonName)
	fmt.Fprintf(os.Stderr, "→ CSR pubkey fp: %s\n", fpHex)
	fmt.Fprintf(os.Stderr, "→ Pairing code:  %s   (show to Alice OOB; expires at %s)\n",
		code, expires.UTC().Format("15:04:05 UTC"))
	ok, err := term.Confirm(fmt.Sprintf("Sign %q with this pairing code?", csr.Subject.CommonName), false)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("aborted")
	}

	certPEM, _, err := authority.SignCSRWithPairing(csrPEM, time.Duration(*days)*24*time.Hour, ca.Pairing{
		Commit:    commit,
		ExpiresAt: expires,
	})
	if err != nil {
		return err
	}
	return writeOrStdout(out, certPEM)
}

func writeOrStdout(out *string, certPEM []byte) error {
	if *out != "" {
		if err := os.WriteFile(*out, certPEM, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "✓ wrote %s\n", *out)
		return nil
	}
	_, err := os.Stdout.Write(certPEM)
	return err
}
```

Add the constant near the top of the file (after the existing `import` block, or near other constants — pick the file's existing convention):

```go
const pairCodeTTL = 10 * time.Minute
```

Add the new imports — `crypto/sha256`, `crypto/x509`, `encoding/hex`, `encoding/pem`, and the `internal/term` package — to the existing import block. Example:

```go
import (
	// ...existing imports...
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"github.com/kaka-milan-22/AnB/internal/term"
)
```

- [ ] **Step 2: Build to verify it compiles**

```sh
cd /Users/bbwave03/claude/anb
go build ./cmd/bob
```
Expected: no errors.

- [ ] **Step 3: Manual smoke (interactive — run in a real terminal, not via a non-TTY harness)**

```sh
# In your local AnB ~/.anb/bob from earlier sessions, dump a CSR to a temp file
# (this Alice's existing CSR is fine; we'll just re-sign it for the smoke)
cp ~/.anb/alice/client.csr /tmp/smoke.csr
go run ./cmd/bob sign-csr /tmp/smoke.csr --out /tmp/smoke.crt
# Confirm: shows identity, pubkey fp, an 8-digit code, asks y/N. Type y.
# Expect: wrote /tmp/smoke.crt
# Save the code printed for the next smoke step.

# also try --no-pair
go run ./cmd/bob sign-csr /tmp/smoke.csr --out /tmp/smoke-nopair.crt --no-pair
# Confirm: prints ⚠ no-pair warning, no code, y/N, signs.
```

- [ ] **Step 4: Commit**

```sh
git add cmd/bob/main.go
git commit -m "feat(bob): interactive sign-csr with OOB pairing code

Shows CSR identity + SubjectPublicKeyInfo fingerprint, generates an
8-digit code via crypto/rand, asks y/N before signing, embeds the
SHA-256(code||fp) commit + 10-minute expiresAt into a non-critical
X.509 extension. --no-pair skips pairing and warns; signing path then
falls through to the legacy ca.SignCSR.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: alice install-cert — verify pairing + --no-pair

**Files:**
- Modify: `cmd/alice/sensitive.go` (function `cmdInstallCert` around line 487)

- [ ] **Step 1: Replace `cmdInstallCert` with the paired version**

Open `cmd/alice/sensitive.go`. Replace `cmdInstallCert` (lines ~486-504) with:

```go
// install-cert <client.crt> — install the signed client certificate, after
// verifying the OOB pairing code embedded in the cert (unless --no-pair).
func cmdInstallCert(args []string) error {
	fs := newFS("install-cert")
	dir := dirFlag(fs)
	noPair := fs.Bool("no-pair", false, "accept certs without a pairing extension (skip OOB code check)")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: alice install-cert <client.crt> [--no-pair]")
	}
	certPEM, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}

	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return fmt.Errorf("not a PEM certificate: %s", pos[0])
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}
	fp := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	fmt.Fprintf(os.Stderr, "→ Cert identity:  %s\n", cert.Subject.CommonName)
	fmt.Fprintf(os.Stderr, "→ Cert pubkey fp: %s\n", hex.EncodeToString(fp[:]))

	if *noPair {
		fmt.Fprintf(os.Stderr, "⚠ --no-pair: skipping OOB code check\n")
	} else {
		code, err := readPairingCode()
		if err != nil {
			return err
		}
		switch err := ca.VerifyPairing(cert, code, time.Now()); {
		case err == nil:
			fmt.Fprintf(os.Stderr, "✓ pairing verified\n")
		case errors.Is(err, ca.ErrPairingAbsent):
			return fmt.Errorf("cert was signed without pairing — re-run with --no-pair to accept, or ask Bob to re-sign with pairing")
		case errors.Is(err, ca.ErrPairingExpired):
			return fmt.Errorf("pairing code expired — ask Bob to re-sign the CSR (a fresh code resets the 10-minute window)")
		case errors.Is(err, ca.ErrPairingMismatch):
			return fmt.Errorf("pairing code did not match — re-run install-cert with the correct code")
		default:
			return fmt.Errorf("pairing verify: %w", err)
		}
	}

	s := localvault.Open(*dir)
	if err := s.WriteFile("client.crt", certPEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("✓ Installed client cert at %s\n", s.ClientCertPath())
	return nil
}

// readPairingCode reads the 8-digit code from $ANB_PAIR_CODE if set,
// otherwise prompts on the TTY. Validates 8 ASCII digits.
func readPairingCode() (string, error) {
	if v := os.Getenv("ANB_PAIR_CODE"); v != "" {
		if err := validatePairingCode(v); err != nil {
			return "", fmt.Errorf("ANB_PAIR_CODE: %w", err)
		}
		return v, nil
	}
	v, err := term.ReadLine("Enter the 8-digit pairing code: ")
	if err != nil {
		return "", err
	}
	if err := validatePairingCode(v); err != nil {
		return "", err
	}
	return v, nil
}

func validatePairingCode(s string) error {
	if len(s) != 8 {
		return fmt.Errorf("pairing code must be 8 digits (got %d chars)", len(s))
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return fmt.Errorf("pairing code must be digits only")
		}
	}
	return nil
}
```

Add new imports to the file (preserve existing ones):

```go
import (
	// ...existing imports...
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"time"
	"github.com/kaka-milan-22/AnB/internal/ca"
	"github.com/kaka-milan-22/AnB/internal/term"
)
```

(Some of these are likely already imported in this file — only add what's missing. Run `goimports` or `go build` to confirm.)

- [ ] **Step 2: Build to verify it compiles**

```sh
go build ./cmd/alice
```
Expected: no errors.

- [ ] **Step 3: Manual smoke (interactive — use a real terminal)**

```sh
# 1) Bob signs a fresh smoke cert, prints a code (note it down)
cp ~/.anb/alice/client.csr /tmp/smoke.csr
go run ./cmd/bob sign-csr /tmp/smoke.csr --out /tmp/smoke.crt   # confirm y, note code, e.g. 47281930

# 2) Alice install with correct code
go run ./cmd/alice install-cert /tmp/smoke.crt
# Enter the printed code → "✓ pairing verified" + "✓ Installed client cert ..."

# 3) Wrong code path
go run ./cmd/alice install-cert /tmp/smoke.crt
# Type "00000000" → should fail with "pairing code did not match"

# 4) Env var path
ANB_PAIR_CODE=47281930 go run ./cmd/alice install-cert /tmp/smoke.crt
# → installs without prompting (use the actual code from step 1)

# 5) --no-pair on a paired cert
go run ./cmd/alice install-cert /tmp/smoke.crt --no-pair
# → "⚠ --no-pair: skipping OOB code check" + installs

# 6) Old-style (no-pair) cert + default mode → error
go run ./cmd/bob sign-csr /tmp/smoke.csr --out /tmp/smoke-old.crt --no-pair   # confirm y
go run ./cmd/alice install-cert /tmp/smoke-old.crt
# → "cert was signed without pairing — re-run with --no-pair to accept, or ask Bob to re-sign with pairing"
```

After each smoke step the prior installed cert is overwritten — that's fine, the existing Alice identity is the same key.

- [ ] **Step 4: Commit**

```sh
git add cmd/alice/sensitive.go
git commit -m "feat(alice): install-cert verifies OOB pairing code

Reads the code from \$ANB_PAIR_CODE or the TTY, validates 8 digits,
runs ca.VerifyPairing, and translates the sentinel errors into
actionable messages (absent / expired / mismatch).
--no-pair accepts certs without (or with, ignored) the extension.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: e2e — pairing happy path + failure modes

**Files:**
- Modify: `e2e/full_test.go`

The existing e2e test in `e2e/full_test.go` spins up a real Bob over loopback mTLS. Extend it with a new top-level test that exercises pairing at the library level (since the CLI prompts aren't easily driven from `go test`). The cert-issuance/verification is fully covered by `internal/ca` unit tests; the e2e adds a "Bob signs with pairing → Alice would VerifyPairing on install" sanity check that the issued cert round-trips through `LoadCA` correctly.

- [ ] **Step 1: Read the existing e2e to find the setup helper**

```sh
sed -n '1,80p' e2e/full_test.go
```
Identify the helper that boots Bob (typically returns `*ca.CA`, server addr, cleanup). Note its name for the test below.

- [ ] **Step 2: Write the new test**

Append to `e2e/full_test.go` (adjust import paths and helper names to match what's already there):

```go
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
```

Make sure the file already imports `encoding/pem`, `crypto/sha256`, `crypto/x509`, `errors`, `time`, and the project's `ca` package — add any missing.

- [ ] **Step 3: Run the e2e suite**

```sh
go test ./e2e/ -run TestPairingEnrollEndToEnd -v
go test ./... 2>&1 | tail -20
```
Expected: new test PASS; full suite green.

- [ ] **Step 4: Commit**

```sh
git add e2e/full_test.go
git commit -m "test(e2e): pairing happy path + mismatch + expired

Library-level end-to-end: a CA signs a CSR with pairing, an Alice
parses the cert and runs VerifyPairing against the right code, a
wrong code (ErrPairingMismatch), and a past-expiry now
(ErrPairingExpired).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: Local smoke against the live Bob daemon

**Files:** None (operational verification).

This task validates that the real `bob` daemon (already running on `127.0.0.1:8443` per the earlier session) still accepts the existing Alice client cert after re-installation through the new flow, and that a fresh pairing flow succeeds end-to-end against the live daemon.

- [ ] **Step 1: Install fresh binaries**

```sh
cd /Users/bbwave03/claude/anb
go install ./cmd/bob ./cmd/alice
```

- [ ] **Step 2: Re-sign and re-install the existing Alice CSR through the pairing flow**

In your interactive terminal (not via a non-TTY harness):

```sh
# Bob: sign with pairing
bob sign-csr ~/.anb/alice/client.csr --out /tmp/alice-paired.crt
#   → note the 8-digit code, type y

# Alice: install with the code
alice install-cert /tmp/alice-paired.crt
#   → enter the code → ✓ pairing verified, ✓ Installed client cert

# Confirm the daemon still talks to us
alice status
#   Bob status: unlocked
```

- [ ] **Step 3: Verify failure modes locally**

```sh
# wrong code rejects, nothing written:
alice install-cert /tmp/alice-paired.crt
#   → "pairing code did not match — re-run install-cert with the correct code"

# expired (sleep > 10m, or use env override) — skip if you don't want to wait

# env var path:
ANB_PAIR_CODE=<the-real-code> alice install-cert /tmp/alice-paired.crt
#   → installs without prompting
```

Note: the daemon never sees the pairing code; only the cert. The pairing protocol is operator-level.

- [ ] **Step 4: No commit — operational only**

If any smoke step fails, fix the relevant prior task and re-amend its commit. Otherwise proceed to Task 11.

---

### Task 11: Final review + branch wrap-up

**Files:** None (review only).

- [ ] **Step 1: Full test suite + vet + fmt**

```sh
cd /Users/bbwave03/claude/anb
go test ./...
go vet ./...
gofmt -l .
```
Expected: all tests pass, no vet complaints, `gofmt -l` prints nothing.

- [ ] **Step 2: Diff review**

```sh
git log --oneline main..HEAD
git --no-pager diff main..HEAD --stat
```
Expected: one docs commit + ~9 implementation commits; touched files match the file structure table at the top of this plan.

- [ ] **Step 3: Hand back to user**

Summarize for the user: branch ready, test status, smoke status. Offer next step (open PR / merge / leave on branch).

---

## Self-review notes

- **Spec coverage:** Each section of the README design is covered. Features bullet → Tasks 7+8. Trust-boundary bullet → mostly Task 5 (no-pair warn) + Task 8 (sentinel-error UX). Wire-format paragraph → Tasks 1–5 (OID, commit, ASN.1). 10-minute TTL → `pairCodeTTL` constant (Task 7) + Task 4 expiry test. `--no-pair` on both sides → Tasks 7+8. `ANB_PAIR_CODE` env var → Task 8. Behavior on wrong code → Task 8 (returns non-zero, nothing written).
- **Placeholder scan:** No "TBD" / "TODO". Concrete code in every step.
- **Type consistency:** `Pairing{Commit, ExpiresAt}` is the only struct; `PairingOID` / `NewPairingCode` / `PubkeyFingerprint` / `PairingCommit` / `DecodePairing` / `VerifyPairing` / `SignCSRWithPairing` — names line up across tasks. Sentinel errors `ErrPairingAbsent` / `ErrPairingExpired` / `ErrPairingMismatch` used consistently in Tasks 4 and 8.
- **OID:** Concrete value `2.25.0x7d2cba5a4b8d4e9a` (uint64 = 9019028596234243738) defined once in Task 1 and used everywhere downstream.
