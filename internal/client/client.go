// Package client is Alice's side of the oracle: a thin mTLS RPC to Bob. Each
// call opens a fresh TLS connection, sends one newline-JSON request, reads one
// response, and closes. Daemon failure codes are mapped to typed errors so the
// CLI can render distinct UX (locked vs unauthorized vs unreachable).
package client

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/kaka-milan-22/AnB/v3/internal/mtls"
	"github.com/kaka-milan-22/AnB/v3/internal/proto"
)

var (
	ErrUnreachable       = errors.New("cannot reach Bob (is the daemon up / network ok?)")
	ErrLocked            = errors.New("Bob is locked (operator has not unlocked the master key)")
	ErrUnauthorized      = errors.New("not authorized for this key")
	ErrDecryptFailed     = errors.New("decrypt failed (wrong vault / corrupted ciphertext)")
	ErrRateLimited       = errors.New("rate-limited by Bob (too many decrypts per minute)")
	ErrUnknownKeyVersion = errors.New("ciphertext references a finalized master-key version")
	ErrProtocol          = errors.New("unexpected response from Bob")
)

type Client struct {
	addr   string
	tlsCfg *tls.Config
	dialTO time.Duration
	// reason is attached to every outbound proto.Request. Operator-supplied
	// free text; logged by Bob in the ALLOW audit line, not authorized on.
	// SetReason once per logical alice invocation.
	reason string
}

// SetReason stamps every subsequent outbound request with reason. Bob will
// log it in the ALLOW audit line. Pass "" to clear.
func (c *Client) SetReason(reason string) { c.reason = reason }

// New builds a client from Alice's cert/key, the CA trust anchor, Bob's address
// and the server name (SAN) to verify.
func New(addr, serverName string, clientCertPEM, clientKeyPEM, caPEM []byte) (*Client, error) {
	cfg, err := mtls.ClientConfig(clientCertPEM, clientKeyPEM, caPEM, serverName)
	if err != nil {
		return nil, err
	}
	return &Client{addr: addr, tlsCfg: cfg, dialTO: 8 * time.Second}, nil
}

func (c *Client) call(req proto.Request) (proto.Response, error) {
	req.Reason = c.reason
	d := &net.Dialer{Timeout: c.dialTO}
	conn, err := tls.DialWithDialer(d, "tcp", c.addr, c.tlsCfg)
	if err != nil {
		return proto.Response{}, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	b, _ := json.Marshal(req)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return proto.Response{}, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return proto.Response{}, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	var resp proto.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return proto.Response{}, ErrProtocol
	}
	return resp, nil
}

func mapErr(resp proto.Response) error {
	switch resp.Code {
	case proto.CodeLocked:
		return ErrLocked
	case proto.CodeUnauthorized:
		return ErrUnauthorized
	case proto.CodeDecryptFailed:
		return ErrDecryptFailed
	case proto.CodeRateLimit:
		return ErrRateLimited
	case proto.CodeUnknownKeyVersion:
		return ErrUnknownKeyVersion
	default:
		if resp.Error != "" {
			return errors.New(resp.Error)
		}
		return ErrProtocol
	}
}

// Encrypt asks Bob to encrypt plaintext under the master key (for `set`).
func (c *Client) Encrypt(key, plaintext string) (string, error) {
	resp, err := c.call(proto.Request{Op: proto.OpEncrypt, Key: key, Plaintext: plaintext})
	if err != nil {
		return "", err
	}
	if !resp.OK {
		return "", mapErr(resp)
	}
	return resp.Packed, nil
}

// Decrypt asks Bob to decrypt one ciphertext. Returns (plaintext,
// rewrappedPacked). rewrappedPacked is non-empty when Bob's CURRENT
// master key version differs from the version embedded in `packed` —
// the same plaintext re-sealed under the current K, ready for the
// caller to write back to vault.json (opportunistic migration; v2.6+).
func (c *Client) Decrypt(key, packed string) (plaintext, rewrappedPacked string, err error) {
	resp, err := c.call(proto.Request{Op: proto.OpDecrypt, Key: key, Packed: packed})
	if err != nil {
		return "", "", err
	}
	if !resp.OK {
		return "", "", mapErr(resp)
	}
	return resp.Plaintext, resp.RewrappedPacked, nil
}

// DecryptMany decrypts a batch in one round-trip (for `read` / `scan`).
// keys is parallel to packed and used for per-key authorization.
// rewrappedMany is parallel to keys: each element is either the empty
// string (already on current K) or the re-sealed packed string under
// the current K (caller should write back). nil when nothing needs
// rewrapping.
func (c *Client) DecryptMany(keys, packed []string) (plaintexts, rewrappedMany []string, err error) {
	if len(packed) == 0 {
		return nil, nil, nil
	}
	resp, err := c.call(proto.Request{Op: proto.OpDecryptMany, Keys: keys, PackedMany: packed})
	if err != nil {
		return nil, nil, err
	}
	if !resp.OK {
		return nil, nil, mapErr(resp)
	}
	return resp.PlaintextMany, resp.RewrappedPackedMany, nil
}

// Status reports whether Bob is reachable and unlocked.
func (c *Client) Status() (unlocked bool, ttlRemaining int, err error) {
	resp, err := c.call(proto.Request{Op: proto.OpStatus})
	if err != nil {
		return false, 0, err
	}
	return resp.Unlocked, resp.TTLRemaining, nil
}
