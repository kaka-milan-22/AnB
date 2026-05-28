package ca

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
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
