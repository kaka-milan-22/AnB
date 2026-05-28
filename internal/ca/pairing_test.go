package ca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"regexp"
	"testing"
	"time"
)

func TestPairingOIDValue(t *testing.T) {
	// Two arcs encode the UUID top-64-bits as 32-bit halves; each arc must fit
	// within Go crypto/x509's 31-bit OID component limit (readBase128Int cap).
	want := asn1.ObjectIdentifier{2, 25, 0x7d2cba5a, 0x4b8d4e9a}
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
		c, err := NewPairingCode()
		if err != nil {
			t.Fatalf("NewPairingCode: %v", err)
		}
		seen[c] = struct{}{}
	}
	if len(seen) < 16 { // 16/32 distinct is a very loose lower bound
		t.Fatalf("NewPairingCode looks non-random: only %d distinct in 32", len(seen))
	}
}

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
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("fp mismatch:\n got %x\n want %x", got, want)
	}
}

// TestPairingCommitKnownAnswer locks in the byte order of the construction
// SHA-256(code || pubkey_fp). The expected digest was pre-computed externally
// (Python hashlib) so swapping the concat order inside PairingCommit cannot
// silently keep this test green:
//
//	python3 -c "import hashlib; print(hashlib.sha256(b'47281930' + bytes([0xAB]*32)).hexdigest())"
//	-> 71155bdd6124802b3dd9d9d5b00a6b5d533a03367b5546f2159d3c49fd7323d5
func TestPairingCommitKnownAnswer(t *testing.T) {
	code := "47281930"
	fp := make([]byte, 32)
	for i := range fp {
		fp[i] = 0xAB
	}
	want, err := hex.DecodeString("71155bdd6124802b3dd9d9d5b00a6b5d533a03367b5546f2159d3c49fd7323d5")
	if err != nil {
		t.Fatalf("decode want: %v", err)
	}
	got := PairingCommit(code, fp)
	if !bytes.Equal(got, want) {
		t.Fatalf("commit mismatch:\n got %x\n want %x", got, want)
	}
}

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
	if !bytes.Equal(out.Commit, commit) {
		t.Fatalf("commit round-trip mismatch:\n got %x\n want %x", out.Commit, commit)
	}
}

func TestPairingEncodeRejectsWrongCommitSize(t *testing.T) {
	p := Pairing{Commit: []byte{1, 2, 3}, ExpiresAt: time.Now()}
	if _, err := p.Encode(); err == nil {
		t.Fatal("expected error for short commit")
	}
}

// TestPairingEncodeTruncatesSubSecond pins the API contract: ExpiresAt
// passes through Encode/decode at second precision, even if the caller
// supplied nanoseconds. Without truncation in Encode a `time.Now().Add(ttl)`
// would silently lose its nanoseconds and round-trip as "valid <1s ago".
func TestPairingEncodeTruncatesSubSecond(t *testing.T) {
	commit := make([]byte, 32)
	exp := time.Date(2026, 5, 28, 14, 23, 5, 123_456_789, time.UTC)
	b, err := Pairing{Commit: commit, ExpiresAt: exp}.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := decodePairingValue(b)
	if err != nil {
		t.Fatalf("decodePairingValue: %v", err)
	}
	want := exp.Truncate(time.Second)
	if !out.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt: got %v want %v (input had nanos %d)", out.ExpiresAt, want, exp.Nanosecond())
	}
	if out.ExpiresAt.Nanosecond() != 0 {
		t.Fatalf("expected 0 nanos after round-trip, got %d", out.ExpiresAt.Nanosecond())
	}
}

// mintCertForPairing mints a fresh client cert with a real pairing extension
// whose commit binds the given code. Returns the parsed cert + the code.
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
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		t.Fatal("not a PEM cert")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, code
}

func TestDecodePairingReturnsNilWhenAbsent(t *testing.T) {
	cert := mustIssueClientCert(t) // no pairing extension
	p, err := DecodePairing(cert)
	if err != nil {
		t.Fatalf("DecodePairing: %v", err)
	}
	if p != nil {
		t.Fatalf("expected nil, got %+v", p)
	}
}

func TestVerifyPairingHappyPath(t *testing.T) {
	cert, code := mintCertForPairing(t, "47281930", 10*time.Minute)
	if err := VerifyPairing(cert, code, time.Now()); err != nil {
		t.Fatalf("VerifyPairing: %v", err)
	}
}

func TestVerifyPairingWrongCode(t *testing.T) {
	cert, _ := mintCertForPairing(t, "47281930", 10*time.Minute)
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
