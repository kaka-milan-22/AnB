// Package-internal protocol for enrollment pairing: an 8-digit OOB code that
// binds a freshly-signed client cert to the operator who watched it being
// signed. See README §"Enroll Alice (with operator pairing)" for the wire
// format and threat model.
package ca

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// PairingOID is the X.509 extension OID for the pairing payload.
// Derived once: top 64 bits of UUID 7d2cba5a-4b8d-4e9a-9c6b-1a3f5e7c9d2b
// under the 2.25 (UUID-based) arc. Project-internal; not registered.
var PairingOID = asn1.ObjectIdentifier{2, 25, 0x7d2cba5a4b8d4e9a}

// pairingCodeRange is the exclusive upper bound passed to crypto/rand.Int.
// Allocated per call — keeping a package-level *big.Int would be a footgun
// because big.Int is mutable.
func pairingCodeRange() *big.Int { return big.NewInt(100_000_000) }

// NewPairingCode returns a fresh 8-digit decimal code (with leading zeros)
// drawn from crypto/rand. ~26.6 bits of entropy; sized for one-shot OOB use
// inside the 10-minute window, not as a credential.
func NewPairingCode() (string, error) {
	n, err := rand.Int(rand.Reader, pairingCodeRange())
	if err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return fmt.Sprintf("%08d", n.Int64()), nil
}

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
