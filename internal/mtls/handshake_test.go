package mtls_test

import (
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/kaka-milan-22/AnB/internal/ca"
	"github.com/kaka-milan-22/AnB/internal/mtls"
)

// startServer returns the listener addr and a channel delivering the verified
// client CommonName (or an error) from the first accepted connection.
func startServer(t *testing.T, sc *tls.Config) (string, <-chan string, <-chan error) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", sc)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	cn := make(chan string, 1)
	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer conn.Close()
		tc := conn.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			errc <- err
			return
		}
		st := tc.ConnectionState()
		if len(st.PeerCertificates) == 0 {
			errc <- errors.New("no peer cert")
			return
		}
		cn <- st.PeerCertificates[0].Subject.CommonName
	}()
	return ln.Addr().String(), cn, errc
}

func TestMutualHandshakeCarriesIdentity(t *testing.T) {
	authority, err := ca.NewCA("AnB-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, err := authority.IssueServer([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cliCert, cliKey, err := authority.IssueClient("alice-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := mtls.ServerConfig(srvCert, srvKey, authority.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := mtls.ClientConfig(cliCert, cliKey, authority.CertPEM, "localhost")
	if err != nil {
		t.Fatal(err)
	}

	addr, cnCh, errc := startServer(t, sc)
	conn, err := tls.Dial("tcp", addr, cc)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	conn.Close()

	select {
	case cn := <-cnCh:
		if cn != "alice-1" {
			t.Fatalf("server saw identity %q, want alice-1", cn)
		}
	case err := <-errc:
		t.Fatalf("server handshake: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("handshake timeout")
	}
}

func TestRejectsForeignClientCert(t *testing.T) {
	authority, _ := ca.NewCA("real-ca", time.Hour)
	srvCert, srvKey, _ := authority.IssueServer([]string{"localhost"}, time.Hour)
	sc, _ := mtls.ServerConfig(srvCert, srvKey, authority.CertPEM)

	foreign, _ := ca.NewCA("evil-ca", time.Hour)
	fCert, fKey, _ := foreign.IssueClient("mallory", time.Hour)
	// Client trusts the real CA for the server, but presents a foreign client cert.
	cc, _ := mtls.ClientConfig(fCert, fKey, authority.CertPEM, "localhost")

	addr, cnCh, errc := startServer(t, sc)
	// Under TLS 1.3 the client's Dial can return before the server validates the
	// client cert; force I/O so any rejection alert surfaces, then assert the
	// server (the authority on client-cert verification) refused the handshake.
	if conn, err := tls.Dial("tcp", addr, cc); err == nil {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var b [1]byte
		_, _ = conn.Read(b[:])
		conn.Close()
	}
	select {
	case cn := <-cnCh:
		t.Fatalf("server accepted foreign client identity %q; should have rejected", cn)
	case <-errc:
		// expected: server rejected the untrusted client cert
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server to reject foreign client cert")
	}
}

func TestSignCSRYieldsUsableClient(t *testing.T) {
	authority, _ := ca.NewCA("real-ca", time.Hour)
	csrPEM, keyPEM, err := ca.GenerateCSR("alice-2")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, identity, err := authority.SignCSR(csrPEM, time.Hour)
	if err != nil {
		t.Fatalf("sign csr: %v", err)
	}
	if identity != "alice-2" {
		t.Fatalf("identity = %q", identity)
	}
	if _, err := mtls.ClientConfig(certPEM, keyPEM, authority.CertPEM, "localhost"); err != nil {
		t.Fatalf("signed cert + key not a valid client config: %v", err)
	}
}
