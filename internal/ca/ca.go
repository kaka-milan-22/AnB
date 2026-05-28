// Package ca is AnB's self-contained private CA — the trust root for the
// mutual-TLS channel between Alice and Bob. There is no public CA in the loop:
// Bob mints its own CA (`bob ca init`), issues its server cert, and signs each
// Alice's client cert (`bob sign-csr`). Both ends trust only this CA, and a
// client cert's CommonName is the identity Bob authorizes against.
//
// All keys are ed25519 (small, modern, no curve parameters); certs are short
// PEM blobs. This mirrors how Kubernetes uses a cluster CA + client certs.
package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

const (
	pemCert = "CERTIFICATE"
	pemKey  = "PRIVATE KEY" // PKCS#8
	pemCSR  = "CERTIFICATE REQUEST"
)

// CA is a loaded certificate authority capable of issuing leaf certificates.
type CA struct {
	Cert    *x509.Certificate
	Key     ed25519.PrivateKey
	CertPEM []byte // the CA cert, for distribution as the trust anchor
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// NewCA generates a fresh self-signed CA valid for the given duration.
func NewCA(commonName string, ttl time.Duration) (*CA, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: priv, CertPEM: encode(pemCert, der)}, nil
}

// MarshalKey returns the CA private key as a PKCS#8 PEM (store it 0600).
func (c *CA) MarshalKey() ([]byte, error) { return marshalKey(c.Key) }

// LoadCA rehydrates a CA from its cert+key PEM (as written by bob ca init).
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, fmt.Errorf("ca cert: %w", err)
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("ca key: %w", err)
	}
	return &CA{Cert: cert, Key: key, CertPEM: certPEM}, nil
}

// IssueServer mints a server-auth cert for the given hostnames/IPs.
func (c *CA) IssueServer(hosts []string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	return c.issueLeaf(hosts[0], hosts, x509.ExtKeyUsageServerAuth, ttl)
}

// IssueClient mints a client-auth cert whose CommonName is the identity.
func (c *CA) IssueClient(identity string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	return c.issueLeaf(identity, nil, x509.ExtKeyUsageClientAuth, ttl)
}

func (c *CA) issueLeaf(cn string, hosts []string, eku x509.ExtKeyUsage, ttl time.Duration) ([]byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := c.sign(cn, hosts, pub, eku, ttl, nil)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := marshalKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return encode(pemCert, der), keyPEM, nil
}

// GenerateCSR (Alice side) makes a keypair + CSR for the given identity. Alice
// keeps keyPEM private (0600) and sends csrPEM to Bob for signing.
func GenerateCSR(identity string) (csrPEM, keyPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	_ = pub
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: identity}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = marshalKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return encode(pemCSR, der), keyPEM, nil
}

// SignCSR (Bob side, operator-run) verifies a CSR and issues a client cert
// using the CSR's public key and CommonName. The operator reviews the CN
// out-of-band before running this — that human check is the enrollment gate.
func (c *CA) SignCSR(csrPEM []byte, ttl time.Duration) (certPEM []byte, identity string, err error) {
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
	der, err := c.sign(csr.Subject.CommonName, nil, csr.PublicKey, x509.ExtKeyUsageClientAuth, ttl, nil)
	if err != nil {
		return nil, "", err
	}
	return encode(pemCert, der), csr.Subject.CommonName, nil
}

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

// --- PEM helpers ---

func encode(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func marshalKey(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return encode(pemKey, der), nil
}

func parseCert(p []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(p)
	if blk == nil || blk.Type != pemCert {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func parseKey(p []byte) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, errors.New("not a PEM key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("key is not ed25519")
	}
	return ed, nil
}
