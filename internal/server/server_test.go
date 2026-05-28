package server_test

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/kaka-milan-22/AnB/internal/authz"
	"github.com/kaka-milan-22/AnB/internal/ca"
	"github.com/kaka-milan-22/AnB/internal/crypto"
	"github.com/kaka-milan-22/AnB/internal/keystore"
	"github.com/kaka-milan-22/AnB/internal/mtls"
	"github.com/kaka-milan-22/AnB/internal/proto"
	"github.com/kaka-milan-22/AnB/internal/server"
)

type harness struct {
	authority *ca.CA
	addr      string
}

// newHarness starts a Bob oracle on loopback mTLS with the given store+policy.
func newHarness(t *testing.T, store *keystore.Store, policy *authz.Policy) *harness {
	t.Helper()
	authority, err := ca.NewCA("test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, err := authority.IssueServer([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := mtls.ServerConfig(srvCert, srvKey, authority.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", sc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := server.New(store, policy, log.New(io.Discard, "", 0))
	go srv.Serve(ln)
	return &harness{authority: authority, addr: ln.Addr().String()}
}

type client struct {
	conn net.Conn
	r    *bufio.Reader
}

func (h *harness) dial(t *testing.T, identity string) *client {
	t.Helper()
	cert, key, err := h.authority.IssueClient(identity, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := mtls.ClientConfig(cert, key, h.authority.CertPEM, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", h.addr, cc)
	if err != nil {
		t.Fatalf("dial as %s: %v", identity, err)
	}
	t.Cleanup(func() { conn.Close() })
	return &client{conn: conn, r: bufio.NewReader(conn)}
}

func (c *client) call(t *testing.T, req proto.Request) proto.Response {
	t.Helper()
	b, _ := json.Marshal(req)
	if _, err := c.conn.Write(append(b, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp proto.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return resp
}

func unlockedStore(t *testing.T) *keystore.Store {
	mk, _ := crypto.NewMasterKey()
	s := keystore.New(nil)
	s.Hold(mk, 0)
	return s
}

func allowAll() *authz.Policy { return &authz.Policy{DefaultAllow: true} }

func TestEncryptDecryptRoundTrip(t *testing.T) {
	h := newHarness(t, unlockedStore(t), allowAll())
	c := h.dial(t, "alice")
	enc := c.call(t, proto.Request{Op: proto.OpEncrypt, Key: "foo", Plaintext: "s3cret"})
	if !enc.OK || enc.Packed == "" {
		t.Fatalf("encrypt: %+v", enc)
	}
	dec := c.call(t, proto.Request{Op: proto.OpDecrypt, Key: "foo", Packed: enc.Packed})
	if !dec.OK || dec.Plaintext != "s3cret" {
		t.Fatalf("decrypt: %+v", dec)
	}
}

func TestDecryptMany(t *testing.T) {
	h := newHarness(t, unlockedStore(t), allowAll())
	c := h.dial(t, "alice")
	p1 := c.call(t, proto.Request{Op: proto.OpEncrypt, Key: "a", Plaintext: "AA"}).Packed
	p2 := c.call(t, proto.Request{Op: proto.OpEncrypt, Key: "b", Plaintext: "BB"}).Packed
	resp := c.call(t, proto.Request{Op: proto.OpDecryptMany, Keys: []string{"a", "b"}, PackedMany: []string{p1, p2}})
	if !resp.OK || len(resp.PlaintextMany) != 2 || resp.PlaintextMany[0] != "AA" || resp.PlaintextMany[1] != "BB" {
		t.Fatalf("decryptMany: %+v", resp)
	}
}

func TestAuthorizationByIdentity(t *testing.T) {
	policy := &authz.Policy{Rules: map[string][]string{
		"alice": {"*"},
		"ci":    {"ci-"},
	}}
	h := newHarness(t, unlockedStore(t), policy)

	// alice may store anything
	foo := h.dial(t, "alice").call(t, proto.Request{Op: proto.OpEncrypt, Key: "foo", Plaintext: "x"})
	if !foo.OK {
		t.Fatalf("alice encrypt foo: %+v", foo)
	}
	// ci may not touch "foo"
	ci := h.dial(t, "ci")
	denied := ci.call(t, proto.Request{Op: proto.OpEncrypt, Key: "foo", Plaintext: "x"})
	if denied.OK || denied.Code != proto.CodeUnauthorized {
		t.Fatalf("expected unauthorized, got %+v", denied)
	}
	// ci may touch "ci-token"
	ok := ci.call(t, proto.Request{Op: proto.OpEncrypt, Key: "ci-token", Plaintext: "x"})
	if !ok.OK {
		t.Fatalf("ci encrypt ci-token: %+v", ok)
	}
}

func TestLockedStoreRefuses(t *testing.T) {
	locked := keystore.New(nil) // never Hold → locked
	h := newHarness(t, locked, allowAll())
	got := h.dial(t, "alice").call(t, proto.Request{Op: proto.OpEncrypt, Key: "k", Plaintext: "v"})
	if got.OK || got.Code != proto.CodeLocked {
		t.Fatalf("expected locked, got %+v", got)
	}
}
