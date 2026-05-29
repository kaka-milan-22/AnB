package server_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kaka-milan-22/AnB/v2/internal/authz"
	"github.com/kaka-milan-22/AnB/v2/internal/ca"
	"github.com/kaka-milan-22/AnB/v2/internal/crypto"
	"github.com/kaka-milan-22/AnB/v2/internal/keystore"
	"github.com/kaka-milan-22/AnB/v2/internal/mtls"
	"github.com/kaka-milan-22/AnB/v2/internal/proto"
	"github.com/kaka-milan-22/AnB/v2/internal/server"
)

// syncBuffer is a goroutine-safe bytes.Buffer wrapper. log.Logger already
// serializes its own writes, but reading the buffer in the test goroutine
// concurrently with the server goroutine's writes is a separate race —
// this gives us a clean read side.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type harness struct {
	authority *ca.CA
	addr      string
	audit     *syncBuffer // populated by newHarness; nil-ish (unused) for tests that don't read it
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
	audit := &syncBuffer{}
	srv := server.New(store, policy, log.New(audit, "", 0))
	go srv.Serve(ln)
	return &harness{authority: authority, addr: ln.Addr().String(), audit: audit}
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

// TestOversizedRequestDropped verifies that a single line exceeding maxReqBytes
// (1 MiB) causes the server to respond with CodeBadRequest and close the conn.
func TestOversizedRequestDropped(t *testing.T) {
	h := newHarness(t, unlockedStore(t), allowAll())
	c := h.dial(t, "alice")

	// Send 2 MiB of 'x' without a newline — the bufio reader fills up before
	// seeing '\n', triggering ErrBufferFull on the server side.
	huge := make([]byte, 2<<20)
	for i := range huge {
		huge[i] = 'x'
	}
	// The write may fail partway through because the server closes the conn
	// after sending the error response; that's fine — we just need to read
	// whatever the server sends back.
	_, _ = c.conn.Write(huge)

	// Server should respond with CodeBadRequest then close.
	line, err := c.r.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		// conn closed before a full response — acceptable: server dropped the
		// conn; the absence of an OK response is the correct outcome.
		return
	}
	var resp proto.Response
	if jErr := json.Unmarshal(line, &resp); jErr != nil {
		t.Fatalf("unmarshal response: %v", jErr)
	}
	if resp.OK || resp.Code != proto.CodeBadRequest {
		t.Fatalf("expected CodeBadRequest for oversized request, got %+v", resp)
	}
}

// TestAuditAllowWithReason: a request with Reason set lands in the ALLOW
// line as reason="...". This is the new v2.4 wire field.
func TestAuditAllowWithReason(t *testing.T) {
	h := newHarness(t, unlockedStore(t), allowAll())
	resp := h.dial(t, "alice").call(t, proto.Request{
		Op: proto.OpEncrypt, Key: "k", Plaintext: "v",
		Reason: "manual review",
	})
	if !resp.OK {
		t.Fatalf("encrypt: %+v", resp)
	}
	got := h.audit.String()
	for _, want := range []string{"ALLOW", `identity="alice"`, "op=encrypt", `reason="manual review"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("audit line missing %q: %q", want, got)
		}
	}
}

// TestAuditAllowWithoutReason: backward compat — an old client that doesn't
// send Reason gets the legacy ALLOW line with no reason= token at all.
func TestAuditAllowWithoutReason(t *testing.T) {
	h := newHarness(t, unlockedStore(t), allowAll())
	h.dial(t, "alice").call(t, proto.Request{Op: proto.OpEncrypt, Key: "k", Plaintext: "v"})
	got := h.audit.String()
	if !strings.Contains(got, "ALLOW") {
		t.Fatalf("want ALLOW in audit: %q", got)
	}
	if strings.Contains(got, "reason=") {
		t.Fatalf("ALLOW without Reason should not contain reason= token: %q", got)
	}
}

// TestAuditDenyUsesCause: DENY lines moved from `reason=unauthorized` to
// `cause=unauthorized`; `reason=` is now exclusively operator-supplied.
func TestAuditDenyUsesCause(t *testing.T) {
	policy := &authz.Policy{Rules: map[string][]string{"alice": {"ok-"}}}
	h := newHarness(t, unlockedStore(t), policy)
	resp := h.dial(t, "alice").call(t, proto.Request{Op: proto.OpEncrypt, Key: "denied-key", Plaintext: "v"})
	if resp.OK || resp.Code != proto.CodeUnauthorized {
		t.Fatalf("expected unauthorized response, got %+v", resp)
	}
	got := h.audit.String()
	if !strings.Contains(got, "DENY") || !strings.Contains(got, "cause=unauthorized") {
		t.Fatalf("want DENY + cause=unauthorized, got %q", got)
	}
	if strings.Contains(got, "reason=unauthorized") {
		t.Fatalf("old DENY format `reason=unauthorized` must be gone, got %q", got)
	}
}
