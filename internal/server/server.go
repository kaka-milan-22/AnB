// Package server is Bob's mTLS oracle: it accepts authenticated connections,
// derives the caller's identity from the verified client certificate, checks
// authorization per request, and performs encrypt/decrypt against the held
// master key. The key never leaves the keystore — only ciphertext and the
// plaintext the caller is authorized to see cross the wire.
package server

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"runtime/debug"
	"time"

	"github.com/kaka-milan-22/AnB/v3/internal/authz"
	"github.com/kaka-milan-22/AnB/v3/internal/keystore"
	"github.com/kaka-milan-22/AnB/v3/internal/proto"
)

const (
	connMaxLifetime = 5 * time.Minute // absolute deadline — kills slowloris and idle conns
	maxReqBytes     = 1 << 20         // 1 MiB per JSON request (newline-delimited)
)

// Emitter writes one structured audit event. kv is a flat key,value,... list.
// Implementations choose the on-wire format (v2.5 uses JSON lines).
//
// Conventions for `kind`:
//
//	ALLOW, DENY, RATELIMIT  — per-request gates (this package emits)
//	HANDSHAKE_FAIL, DROP, PANIC — connection-level events (this package emits)
//	SERVING, SHUTDOWN, AUTOLOCK, WARN_ALLOW_ALL — bob lifecycle (cmd/bob emits)
type Emitter func(kind string, kv ...any)

type Server struct {
	store   *keystore.Store
	policy  *authz.Policy
	audit   Emitter
	limiter *rateLimiter
}

func New(store *keystore.Store, policy *authz.Policy, audit Emitter) *Server {
	return &Server{
		store:   store,
		policy:  policy,
		audit:   audit,
		limiter: newRateLimiter(policy.Limit),
	}
}

// Serve accepts connections until the listener closes.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					s.audit("PANIC", "err", asString(r), "stack", string(debug.Stack()))
				}
			}()
			s.handleConn(c)
		}(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	if err := tc.Handshake(); err != nil {
		// Failed mTLS (missing/foreign/expired client cert). Never reached
		// dispatch, but audit-log the remote + error class so a probe leaves a trace.
		s.audit("HANDSHAKE_FAIL", "remote", conn.RemoteAddr().String(), "err", err.Error())
		return
	}
	identity := peerIdentity(tc)
	if identity == "" {
		return
	}

	// Absolute connection lifetime — kills slowloris and idle conns regardless of
	// per-read activity. The KMS workload is request-response in <1s; 5 min is
	// plenty of headroom for any legitimate batch.
	_ = conn.SetDeadline(time.Now().Add(connMaxLifetime))

	// Cap each newline-delimited request at maxReqBytes via ReadSlice on a
	// fixed-size bufio reader. Without this an authenticated client could send
	// an unbounded line and OOM Bob.
	r := bufio.NewReaderSize(conn, maxReqBytes)
	enc := json.NewEncoder(conn) // Encode appends '\n' → newline-delimited
	for {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			s.audit("DROP", "identity", identity, "cause", "request-too-large")
			_ = enc.Encode(proto.Response{OK: false, Code: proto.CodeBadRequest, Error: "request exceeds 1 MiB"})
			return
		}
		if len(line) > 0 {
			var req proto.Request
			if jErr := json.Unmarshal(line, &req); jErr != nil {
				_ = enc.Encode(proto.Response{OK: false, Code: proto.CodeBadRequest, Error: "malformed request"})
			} else {
				_ = enc.Encode(s.dispatch(identity, req))
			}
		}
		if err != nil {
			// EOF, deadline exceeded, or other read error — just close.
			return
		}
	}
}

func peerIdentity(tc *tls.Conn) string {
	st := tc.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return ""
	}
	return st.PeerCertificates[0].Subject.CommonName
}

func (s *Server) dispatch(identity string, req proto.Request) proto.Response {
	switch req.Op {
	case proto.OpStatus:
		return proto.Response{
			OK:           true,
			Unlocked:     s.store.Unlocked(),
			TTLRemaining: int(s.store.TTLRemaining().Seconds()),
		}

	case proto.OpEncrypt:
		if resp, ok := s.guard(identity, []string{req.Key}, "encrypt", req.Reason); !ok {
			return resp
		}
		packed, err := s.store.Encrypt([]byte(req.Plaintext))
		if err != nil {
			return cryptoErr(err)
		}
		return proto.Response{OK: true, Packed: packed}

	case proto.OpDecrypt:
		if resp, ok := s.rateLimit(identity, "decrypt"); !ok {
			return resp
		}
		if resp, ok := s.guard(identity, []string{req.Key}, "decrypt", req.Reason); !ok {
			return resp
		}
		pt, rewrapped, _, err := s.store.Decrypt(req.Packed)
		if err != nil {
			return cryptoErr(err)
		}
		if rewrapped != "" {
			s.audit("KEY_REWRAP", "identity", identity, "op", "decrypt", "key", req.Key, "count", 1)
		}
		return proto.Response{OK: true, Plaintext: string(pt), RewrappedPacked: rewrapped}

	case proto.OpDecryptMany:
		if resp, ok := s.rateLimit(identity, "decryptMany"); !ok {
			return resp
		}
		if resp, ok := s.guard(identity, req.Keys, "decryptMany", req.Reason); !ok {
			return resp
		}
		pts := make([]string, 0, len(req.PackedMany))
		rewraps := make([]string, len(req.PackedMany))
		rewrapCount := 0
		for i, p := range req.PackedMany {
			pt, rewrapped, _, err := s.store.Decrypt(p)
			if err != nil {
				return cryptoErr(err)
			}
			pts = append(pts, string(pt))
			rewraps[i] = rewrapped
			if rewrapped != "" {
				rewrapCount++
			}
		}
		if rewrapCount > 0 {
			s.audit("KEY_REWRAP", "identity", identity, "op", "decryptMany", "keys", req.Keys, "count", rewrapCount)
		} else {
			// All on current; suppress the rewrap-many field entirely (omitempty).
			rewraps = nil
		}
		return proto.Response{OK: true, PlaintextMany: pts, RewrappedPackedMany: rewraps}

	default:
		return proto.Response{OK: false, Code: proto.CodeBadRequest, Error: "unknown op: " + req.Op}
	}
}

// rateLimit consumes one token from identity's bucket. On exhaustion it emits
// a RATELIMIT audit event and returns a CodeRateLimit response. Decrypt-class
// ops only; encrypt is operator-driven (TTY) and not subject to the limit.
func (s *Server) rateLimit(identity, op string) (proto.Response, bool) {
	if s.limiter.allow(identity) {
		return proto.Response{}, true
	}
	s.audit("RATELIMIT", "identity", identity, "op", op, "cause", "limit-exceeded")
	return proto.Response{OK: false, Code: proto.CodeRateLimit, Error: "rate limit exceeded"}, false
}

// guard runs authorization + audit. Returns (resp,false) when the request must
// be denied; (zero,true) when it may proceed.
//
// Audit kinds:
//   - DENY emits cause=<denial reason> — Bob's explanation for why it refused.
//   - ALLOW emits reason=<operator text> when present — the caller's "why".
//     Bob never authorizes on reason; it's an audit-only field.
func (s *Server) guard(identity string, keys []string, op, reason string) (proto.Response, bool) {
	for _, k := range keys {
		if !s.policy.Allowed(identity, k) {
			s.audit("DENY", "identity", identity, "op", op, "key", k, "cause", "unauthorized")
			return proto.Response{OK: false, Code: proto.CodeUnauthorized, Error: "not authorized for key " + k}, false
		}
	}
	kv := []any{"identity", identity, "op", op, "keys", keys}
	if reason != "" {
		kv = append(kv, "reason", reason)
	}
	s.audit("ALLOW", kv...)
	return proto.Response{}, true
}

func cryptoErr(err error) proto.Response {
	if errors.Is(err, keystore.ErrLocked) {
		return proto.Response{OK: false, Code: proto.CodeLocked, Error: "vault is locked"}
	}
	if errors.Is(err, keystore.ErrUnknownVersion) {
		return proto.Response{OK: false, Code: proto.CodeUnknownKeyVersion, Error: "ciphertext references a finalized key version"}
	}
	return proto.Response{OK: false, Code: proto.CodeDecryptFailed, Error: "operation failed"}
}

// asString formats a panic value safely for audit logging.
func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case error:
		return x.Error()
	default:
		// %v is fine for arbitrary values; we don't need full %+v stacks
		// because debug.Stack() is emitted alongside.
		return jsonish(x)
	}
}

func jsonish(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "<unmarshalable panic value>"
	}
	return string(b)
}
