// Package-internal protocol for enrollment pairing: an 8-digit OOB code that
// binds a freshly-signed client cert to the operator who watched it being
// signed. See README §"Enroll Alice (with operator pairing)" for the wire
// format and threat model.
package ca

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// PairingOID is the X.509 extension OID for the pairing payload.
// Derived from UUID 7d2cba5a-4b8d-4e9a-9c6b-1a3f5e7c9d2b under the 2.25
// (UUID-based) arc. The two arcs encode the top 64 bits as two 32-bit halves
// (0x7d2cba5a, 0x4b8d4e9a) so each component fits within Go crypto/x509's
// 31-bit OID arc limit. Project-internal; not registered with IANA.
var PairingOID = asn1.ObjectIdentifier{2, 25, 0x7d2cba5a, 0x4b8d4e9a}

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

// PairingCommit computes SHA-256(code || pubkey_fp) to bind the OOB code
// to a specific issued cert. `code` is the 8 ASCII-digit pairing code;
// `pubkeyFP` is the 32-byte output of PubkeyFingerprint.
func PairingCommit(code string, pubkeyFP []byte) []byte {
	h := sha256.New()
	h.Write([]byte(code))
	h.Write(pubkeyFP)
	return h.Sum(nil)
}

// Pairing is the deserialized contents of the X.509 extension. ExpiresAt is
// stored in UTC and at second precision — Encode truncates sub-second nanos
// because ASN.1 GeneralizedTime serialises to whole seconds and a lossy
// round-trip would otherwise turn a "valid now" code into "valid <1s ago"
// on the verify side.
type Pairing struct {
	Commit    []byte    // 32 bytes
	ExpiresAt time.Time // UTC, second precision
}

// asn1Pairing is the wire form: SEQUENCE { commit OCTET STRING, expiresAt GeneralizedTime }.
type asn1Pairing struct {
	Commit    []byte
	ExpiresAt time.Time `asn1:"generalized"`
}

// Encode marshals the Pairing as the bytes that go into the X.509 extension
// Value field. ExpiresAt is normalised to UTC and truncated to whole seconds
// (GeneralizedTime cannot carry sub-second precision).
func (p Pairing) Encode() ([]byte, error) {
	if len(p.Commit) != 32 {
		return nil, fmt.Errorf("pairing commit: want 32 bytes, got %d", len(p.Commit))
	}
	w := asn1Pairing{
		Commit:    p.Commit,
		ExpiresAt: p.ExpiresAt.UTC().Truncate(time.Second),
	}
	return asn1.Marshal(w)
}

// decodePairingValue is the inverse of Encode. Package-private; higher-level
// callers (DecodePairing) extract the extension from a cert first
// and then route the raw value here.
func decodePairingValue(b []byte) (*Pairing, error) {
	var w asn1Pairing
	rest, err := asn1.Unmarshal(b, &w)
	if err != nil {
		return nil, fmt.Errorf("pairing asn1: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("pairing asn1: %d trailing bytes", len(rest))
	}
	if len(w.Commit) != 32 {
		return nil, fmt.Errorf("pairing commit: want 32 bytes, got %d", len(w.Commit))
	}
	return &Pairing{Commit: w.Commit, ExpiresAt: w.ExpiresAt.UTC()}, nil
}

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
// SHA-256(code || pubkey_fp) equals the commit. Constant-time compare on the
// commit prevents code recovery via timing.
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
	if subtle.ConstantTimeCompare(got, p.Commit) != 1 {
		return ErrPairingMismatch
	}
	return nil
}
