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
	"log"
	"net"
	"runtime/debug"
	"time"

	"github.com/kaka-milan-22/AnB/internal/authz"
	"github.com/kaka-milan-22/AnB/internal/keystore"
	"github.com/kaka-milan-22/AnB/internal/proto"
)

const (
	connMaxLifetime = 5 * time.Minute // absolute deadline — kills slowloris and idle conns
	maxReqBytes     = 1 << 20         // 1 MiB per JSON request (newline-delimited)
)

type Server struct {
	store  *keystore.Store
	policy *authz.Policy
	audit  *log.Logger
}

func New(store *keystore.Store, policy *authz.Policy, audit *log.Logger) *Server {
	return &Server{store: store, policy: policy, audit: audit}
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
					s.audit.Printf("PANIC handler: %v\n%s", r, debug.Stack())
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
		s.audit.Printf("HANDSHAKE_FAIL remote=%s err=%v", conn.RemoteAddr(), err)
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
			s.audit.Printf("DROP identity=%q reason=request-too-large", identity)
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
		if resp, ok := s.guard(identity, []string{req.Key}, "encrypt"); !ok {
			return resp
		}
		packed, err := s.store.Encrypt([]byte(req.Plaintext))
		if err != nil {
			return cryptoErr(err)
		}
		return proto.Response{OK: true, Packed: packed}

	case proto.OpDecrypt:
		if resp, ok := s.guard(identity, []string{req.Key}, "decrypt"); !ok {
			return resp
		}
		pt, err := s.store.Decrypt(req.Packed)
		if err != nil {
			return cryptoErr(err)
		}
		return proto.Response{OK: true, Plaintext: string(pt)}

	case proto.OpDecryptMany:
		if resp, ok := s.guard(identity, req.Keys, "decryptMany"); !ok {
			return resp
		}
		out := make([]string, 0, len(req.PackedMany))
		for _, p := range req.PackedMany {
			pt, err := s.store.Decrypt(p)
			if err != nil {
				return cryptoErr(err)
			}
			out = append(out, string(pt))
		}
		return proto.Response{OK: true, PlaintextMany: out}

	default:
		return proto.Response{OK: false, Code: proto.CodeBadRequest, Error: "unknown op: " + req.Op}
	}
}

// guard runs authorization + audit. Returns (resp,false) when the request must
// be denied; (zero,true) when it may proceed.
func (s *Server) guard(identity string, keys []string, op string) (proto.Response, bool) {
	for _, k := range keys {
		if !s.policy.Allowed(identity, k) {
			s.audit.Printf("DENY  identity=%q op=%s key=%q reason=unauthorized", identity, op, k)
			return proto.Response{OK: false, Code: proto.CodeUnauthorized, Error: "not authorized for key " + k}, false
		}
	}
	s.audit.Printf("ALLOW identity=%q op=%s keys=%v", identity, op, keys)
	return proto.Response{}, true
}

func cryptoErr(err error) proto.Response {
	if errors.Is(err, keystore.ErrLocked) {
		return proto.Response{OK: false, Code: proto.CodeLocked, Error: "vault is locked"}
	}
	return proto.Response{OK: false, Code: proto.CodeDecryptFailed, Error: "operation failed"}
}
