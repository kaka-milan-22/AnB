// Package proto is the newline-delimited JSON wire protocol spoken over the
// Alice↔Bob mutual-TLS connection. One Request per line, one Response per line;
// a connection may carry many request/response pairs (e.g. a `read` issues a
// single decryptMany). Bob authorizes every request against the client-cert
// identity, so each request names the logical secret Key(s) it touches.
package proto

const (
	OpEncrypt     = "encrypt"     // Plaintext + Key  -> Packed
	OpDecrypt     = "decrypt"     // Packed + Key      -> Plaintext
	OpDecryptMany = "decryptMany" // PackedMany + Keys -> PlaintextMany
	OpStatus      = "status"      // -> Unlocked, TTLRemaining
)

// Failure codes (Response.Code) — machine-readable so Alice can map them to
// distinct UX / exit behavior.
const (
	CodeLocked            = "locked"         // Bob holds no key (operator hasn't unlocked)
	CodeUnauthorized      = "unauthorized"   // identity not allowed this key
	CodeDecryptFailed     = "decrypt-failed" // ciphertext malformed / auth failure
	CodeBadRequest        = "bad-request"
	CodeInternal          = "internal"
	CodeRateLimit         = "rate-limit"          // per-identity decrypt rate exceeded (v2.5+)
	CodeUnknownKeyVersion = "unknown-key-version" // ciphertext refers to a finalized K (v2.6+)
)

// Request is one operation. Key/Keys are the logical vault key names (NOT the
// ciphertext), used for authorization.
//
// Reason is operator-supplied free-text that Bob logs in the ALLOW audit
// line. It does NOT participate in authorization — a compromised agent can
// forge any reason it likes — but it gives the operator a "why" column when
// auditing. Empty Reason is omitted from the wire and the audit line.
type Request struct {
	Op         string   `json:"op"`
	Key        string   `json:"key,omitempty"`
	Keys       []string `json:"keys,omitempty"`
	Plaintext  string   `json:"plaintext,omitempty"`
	Packed     string   `json:"packed,omitempty"`
	PackedMany []string `json:"packedMany,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

// Response is one result. OK gates the payload fields; on failure Code/Error
// are set.
//
// RewrappedPacked / RewrappedPackedMany (v2.6+) carry the same plaintext
// re-sealed under Bob's CURRENT master key, returned when the request's
// ciphertext was under an older K version. Alice should write it back to
// vault.json for opportunistic migration. Empty / nil = no rewrap needed
// (already on current). Pre-v2.6 alices ignore these fields.
type Response struct {
	OK                  bool     `json:"ok"`
	Error               string   `json:"error,omitempty"`
	Code                string   `json:"code,omitempty"`
	Packed              string   `json:"packed,omitempty"`
	Plaintext           string   `json:"plaintext,omitempty"`
	PlaintextMany       []string `json:"plaintextMany,omitempty"`
	RewrappedPacked     string   `json:"rewrappedPacked,omitempty"`
	RewrappedPackedMany []string `json:"rewrappedPackedMany,omitempty"`
	Unlocked            bool     `json:"unlocked,omitempty"`
	TTLRemaining        int      `json:"ttlRemaining,omitempty"`
}
