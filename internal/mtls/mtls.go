// Package mtls builds the tls.Config for both ends of the Alice↔Bob channel.
// Both sides trust ONLY the private CA; Bob additionally requires and verifies
// a client certificate, so the connection itself proves Alice's identity.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

func caPool(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("failed to parse CA PEM")
	}
	return pool, nil
}

// ServerConfig is Bob's side: present serverCert, require+verify a client cert
// signed by the CA. TLS 1.3 only — we control both ends, so no legacy floor.
func ServerConfig(serverCertPEM, serverKeyPEM, caPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, err
	}
	pool, err := caPool(caPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientConfig is Alice's side: present clientCert, verify Bob's server cert
// against the CA. serverName must match a SAN on Bob's server cert.
func ClientConfig(clientCertPEM, clientKeyPEM, caPEM []byte, serverName string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, err
	}
	pool, err := caPool(caPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
