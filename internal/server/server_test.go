package server_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kaka-milan-22/AnB/v3/internal/authz"
	"github.com/kaka-milan-22/AnB/v3/internal/ca"
	"github.com/kaka-milan-22/AnB/v3/internal/crypto"
	"github.com/kaka-milan-22/AnB/v3/internal/keystore"
	"github.com/kaka-milan-22/AnB/v3/internal/mtls"
	"github.com/kaka-milan-22/AnB/v3/internal/proto"
	"github.com/kaka-milan-22/AnB/v3/internal/server"
)

// syncBuffer is a goroutine-safe byte buffer used to capture audit JSON
// emitted concurrently by the server's connection-handling goroutines.
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
	audit     *syncBuffer
}

// newHarness starts a Bob oracle on loopback mTLS with the given store+policy.
// The audit Emitter writes one JSON object per line to harness.audit; tests
// parse those lines and assert structured fields (mirrors v2.5 prod format).
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
	srv := server.New(store, policy, jsonEmitter(audit))
	go srv.Serve(ln)
	return &harness{authority: authority, addr: ln.Addr().String(), audit: audit}
}

// jsonEmitter is a tiny in-test mirror of cmd/bob's newJSONEmitter so the
// server_test asserts the same wire format the daemon emits.
func jsonEmitter(w *syncBuffer) server.Emitter {
	return func(kind string, kv ...any) {
		obj := map[string]any{
			"ts":   time.Now().UTC().Format(time.RFC3339Nano),
			"kind": kind,
		}
		for i := 0; i+1 < len(kv); i += 2 {
			k, ok := kv[i].(string)
			if !ok {
				continue
			}
			obj[k] = kv[i+1]
		}
		b, _ := json.Marshal(obj)
		_, _ = w.Write(append(b, '\n'))
	}
}

// auditLines parses harness.audit into a slice of {kind, fields...} maps.
// Empty/blank lines are skipped. Each map carries all JSON fields including ts/kind.
func auditLines(t *testing.T, h *harness) []map[string]any {
	t.Helper()
	out := []map[string]any{}
	for _, line := range strings.Split(h.audit.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("audit line not JSON: %q (%v)", line, err)
		}
		out = append(out, m)
	}
	return out
}

func lastOfKind(t *testing.T, h *harness, kind string) map[string]any {
	t.Helper()
	for i := len(auditLines(t, h)) - 1; i >= 0; i-- {
		ev := auditLines(t, h)[i]
		if ev["kind"] == kind {
			return ev
		}
	}
	t.Fatalf("no audit event of kind %q in:\n%s", kind, h.audit.String())
	return nil
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

	foo := h.dial(t, "alice").call(t, proto.Request{Op: proto.OpEncrypt, Key: "foo", Plaintext: "x"})
	if !foo.OK {
		t.Fatalf("alice encrypt foo: %+v", foo)
	}
	ci := h.dial(t, "ci")
	denied := ci.call(t, proto.Request{Op: proto.OpEncrypt, Key: "foo", Plaintext: "x"})
	if denied.OK || denied.Code != proto.CodeUnauthorized {
		t.Fatalf("expected unauthorized, got %+v", denied)
	}
	ok := ci.call(t, proto.Request{Op: proto.OpEncrypt, Key: "ci-token", Plaintext: "x"})
	if !ok.OK {
		t.Fatalf("ci encrypt ci-token: %+v", ok)
	}
}

func TestLockedStoreRefuses(t *testing.T) {
	locked := keystore.New(nil)
	h := newHarness(t, locked, allowAll())
	got := h.dial(t, "alice").call(t, proto.Request{Op: proto.OpEncrypt, Key: "k", Plaintext: "v"})
	if got.OK || got.Code != proto.CodeLocked {
		t.Fatalf("expected locked, got %+v", got)
	}
}

func TestOversizedRequestDropped(t *testing.T) {
	h := newHarness(t, unlockedStore(t), allowAll())
	c := h.dial(t, "alice")
	huge := make([]byte, 2<<20)
	for i := range huge {
		huge[i] = 'x'
	}
	_, _ = c.conn.Write(huge)

	line, err := c.r.ReadBytes('\n')
	if err != nil && len(line) == 0 {
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

// --- v2.5 audit-format invariants (JSON one-event-per-line) -----------------

// TestAuditAllowWithReason: ALLOW carries identity + op + keys + reason.
func TestAuditAllowWithReason(t *testing.T) {
	h := newHarness(t, unlockedStore(t), allowAll())
	resp := h.dial(t, "alice").call(t, proto.Request{
		Op: proto.OpEncrypt, Key: "k", Plaintext: "v", Reason: "manual review",
	})
	if !resp.OK {
		t.Fatalf("encrypt: %+v", resp)
	}
	ev := lastOfKind(t, h, "ALLOW")
	if ev["identity"] != "alice" || ev["op"] != "encrypt" || ev["reason"] != "manual review" {
		t.Fatalf("unexpected ALLOW shape: %+v", ev)
	}
	keys, ok := ev["keys"].([]any)
	if !ok || len(keys) != 1 || keys[0] != "k" {
		t.Fatalf("ALLOW keys field: %+v", ev["keys"])
	}
}

// TestAuditAllowWithoutReason: ALLOW without operator reason has no `reason`
// field on the wire (backward-compat with pre-v2.4 clients).
func TestAuditAllowWithoutReason(t *testing.T) {
	h := newHarness(t, unlockedStore(t), allowAll())
	h.dial(t, "alice").call(t, proto.Request{Op: proto.OpEncrypt, Key: "k", Plaintext: "v"})
	ev := lastOfKind(t, h, "ALLOW")
	if _, present := ev["reason"]; present {
		t.Fatalf("ALLOW without reason should omit `reason` field: %+v", ev)
	}
}

// TestAuditDenyUsesCause: DENY uses cause=, never reason=. `reason` is
// exclusively for operator-supplied audit text.
func TestAuditDenyUsesCause(t *testing.T) {
	policy := &authz.Policy{Rules: map[string][]string{"alice": {"ok-"}}}
	h := newHarness(t, unlockedStore(t), policy)
	resp := h.dial(t, "alice").call(t, proto.Request{Op: proto.OpEncrypt, Key: "denied", Plaintext: "v"})
	if resp.OK || resp.Code != proto.CodeUnauthorized {
		t.Fatalf("want CodeUnauthorized, got %+v", resp)
	}
	ev := lastOfKind(t, h, "DENY")
	if ev["cause"] != "unauthorized" {
		t.Fatalf("DENY missing cause=unauthorized: %+v", ev)
	}
	if _, present := ev["reason"]; present {
		t.Fatalf("DENY must not have reason field: %+v", ev)
	}
}

// --- v2.5 rate-limit invariants ---------------------------------------------

// TestRateLimitEnforcedDecrypt: with a tiny per-identity cap, the bucket
// exhausts on the (cap+1)th call and we get CodeRateLimit + a RATELIMIT audit
// event. Encrypt is NOT limited.
func TestRateLimitEnforcedDecrypt(t *testing.T) {
	policy := &authz.Policy{
		Rules:      map[string][]string{"alice": {"*"}},
		RateLimits: map[string]int{"alice": 3},
	}
	h := newHarness(t, unlockedStore(t), policy)
	c := h.dial(t, "alice")

	// Stash one ciphertext we'll re-decrypt repeatedly. Encrypt is unlimited.
	enc := c.call(t, proto.Request{Op: proto.OpEncrypt, Key: "k", Plaintext: "v"})
	if !enc.OK {
		t.Fatalf("setup encrypt: %+v", enc)
	}

	// First 3 decrypts: all succeed (capacity = 3, refill is too slow to matter).
	for i := 0; i < 3; i++ {
		resp := c.call(t, proto.Request{Op: proto.OpDecrypt, Key: "k", Packed: enc.Packed})
		if !resp.OK {
			t.Fatalf("call %d under cap: %+v", i+1, resp)
		}
	}
	// 4th decrypt: bucket empty → rate-limited.
	resp := c.call(t, proto.Request{Op: proto.OpDecrypt, Key: "k", Packed: enc.Packed})
	if resp.OK || resp.Code != proto.CodeRateLimit {
		t.Fatalf("expected CodeRateLimit on 4th decrypt, got %+v", resp)
	}
	ev := lastOfKind(t, h, "RATELIMIT")
	if ev["identity"] != "alice" || ev["op"] != "decrypt" || ev["cause"] != "limit-exceeded" {
		t.Fatalf("RATELIMIT shape: %+v", ev)
	}

	// Encrypt should still go through — limit is decrypt-only.
	if resp := c.call(t, proto.Request{Op: proto.OpEncrypt, Key: "x", Plaintext: "y"}); !resp.OK {
		t.Fatalf("encrypt should not be rate-limited: %+v", resp)
	}
}

// --- v2.6 lazy-rewrap invariants ---------------------------------------------

// TestDecryptReturnsRewrapForLegacyV1: when Bob holds K1+K2 with current=K2
// and a client sends a legacy (no-prefix / v1) ciphertext, the response
// must include Plaintext + RewrappedPacked re-sealed under K2, and the
// audit log gets a KEY_REWRAP event.
func TestDecryptReturnsRewrapForLegacyV1(t *testing.T) {
	k1, _ := crypto.NewMasterKey()
	k2, _ := crypto.NewMasterKey()
	store := keystore.New(nil)
	store.HoldMulti(map[int][]byte{1: k1, 2: k2}, 2, 0)
	h := newHarness(t, store, allowAll())

	rawV1, err := crypto.SealAAD(k1, []byte("legacy-secret"), []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	resp := h.dial(t, "alice").call(t, proto.Request{Op: proto.OpDecrypt, Key: "k", Packed: rawV1})
	if !resp.OK || resp.Plaintext != "legacy-secret" {
		t.Fatalf("decrypt legacy: %+v", resp)
	}
	if !strings.HasPrefix(resp.RewrappedPacked, "v2:") {
		t.Fatalf("rewrap must use current K's v2: prefix, got %q", resp.RewrappedPacked)
	}
	ev := lastOfKind(t, h, "KEY_REWRAP")
	if ev["identity"] != "alice" || ev["op"] != "decrypt" {
		t.Fatalf("KEY_REWRAP shape: %+v", ev)
	}
}

// TestDecryptManyMixesRewrapsByPosition: a DecryptMany batch with mixed
// versions (some legacy v1, some already on current K2) returns
// RewrappedPackedMany aligned by position — non-current slots filled,
// current slots empty string.
func TestDecryptManyMixesRewrapsByPosition(t *testing.T) {
	k1, _ := crypto.NewMasterKey()
	k2, _ := crypto.NewMasterKey()
	store := keystore.New(nil)
	store.HoldMulti(map[int][]byte{1: k1, 2: k2}, 2, 0)
	h := newHarness(t, store, allowAll())
	c := h.dial(t, "alice")

	// Build one v1 (name "a") and one current v2 (name "b") ciphertext, each
	// AAD-bound to the name the request will use.
	rawV1, _ := crypto.SealAAD(k1, []byte("old"), []byte("a"))
	rawV2Body, _ := crypto.SealAAD(k2, []byte("new"), []byte("b"))
	v2Packed := crypto.PackVersion(2, rawV2Body)

	resp := c.call(t, proto.Request{
		Op:         proto.OpDecryptMany,
		Keys:       []string{"a", "b"},
		PackedMany: []string{rawV1, v2Packed},
	})
	if !resp.OK || len(resp.PlaintextMany) != 2 {
		t.Fatalf("decryptMany: %+v", resp)
	}
	if resp.PlaintextMany[0] != "old" || resp.PlaintextMany[1] != "new" {
		t.Fatalf("plaintext mismatch: %v", resp.PlaintextMany)
	}
	if len(resp.RewrappedPackedMany) != 2 {
		t.Fatalf("rewrappedMany should have len 2 to align with keys, got %v", resp.RewrappedPackedMany)
	}
	if !strings.HasPrefix(resp.RewrappedPackedMany[0], "v2:") {
		t.Fatalf("position 0 (legacy) should be rewrapped, got %q", resp.RewrappedPackedMany[0])
	}
	if resp.RewrappedPackedMany[1] != "" {
		t.Fatalf("position 1 (already current) should be empty, got %q", resp.RewrappedPackedMany[1])
	}
}

// TestDecryptManyNoRewrapWhenAllCurrent: when every entry is already on
// the current K, the server omits RewrappedPackedMany entirely (no audit
// noise either).
func TestDecryptManyNoRewrapWhenAllCurrent(t *testing.T) {
	mk, _ := crypto.NewMasterKey()
	store := keystore.New(nil)
	store.HoldMulti(map[int][]byte{1: mk}, 1, 0)
	h := newHarness(t, store, allowAll())
	c := h.dial(t, "alice")

	// Encrypt + decrypt — both under v1 = current.
	p := c.call(t, proto.Request{Op: proto.OpEncrypt, Key: "k", Plaintext: "x"})
	resp := c.call(t, proto.Request{Op: proto.OpDecryptMany, Keys: []string{"k"}, PackedMany: []string{p.Packed}})
	if !resp.OK || resp.PlaintextMany[0] != "x" {
		t.Fatalf("decrypt: %+v", resp)
	}
	if resp.RewrappedPackedMany != nil {
		t.Fatalf("RewrappedPackedMany should be nil when all current, got %v", resp.RewrappedPackedMany)
	}
	// No KEY_REWRAP event in audit.
	for _, ev := range auditLines(t, h) {
		if ev["kind"] == "KEY_REWRAP" {
			t.Fatalf("unexpected KEY_REWRAP when all on current: %+v", ev)
		}
	}
}

// TestRateLimitPerIdentityIsolated: two identities have independent buckets.
func TestRateLimitPerIdentityIsolated(t *testing.T) {
	policy := &authz.Policy{
		Rules:      map[string][]string{"a": {"*"}, "b": {"*"}},
		RateLimits: map[string]int{"a": 1, "b": 1},
	}
	h := newHarness(t, unlockedStore(t), policy)
	a := h.dial(t, "a")
	b := h.dial(t, "b")
	enc := a.call(t, proto.Request{Op: proto.OpEncrypt, Key: "k", Plaintext: "v"})

	// a uses its single token
	if !a.call(t, proto.Request{Op: proto.OpDecrypt, Key: "k", Packed: enc.Packed}).OK {
		t.Fatal("a first decrypt should succeed")
	}
	// b still has its full bucket
	if !b.call(t, proto.Request{Op: proto.OpDecrypt, Key: "k", Packed: enc.Packed}).OK {
		t.Fatal("b decrypt should succeed independently of a")
	}
	// a is now empty
	if a.call(t, proto.Request{Op: proto.OpDecrypt, Key: "k", Packed: enc.Packed}).Code != proto.CodeRateLimit {
		t.Fatal("a second decrypt should be rate-limited")
	}
}
