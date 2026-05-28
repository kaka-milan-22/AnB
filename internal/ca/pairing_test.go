package ca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"regexp"
	"testing"
	"time"
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
