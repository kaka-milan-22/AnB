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
	CodeLocked        = "locked"         // Bob holds no key (operator hasn't unlocked)
	CodeUnauthorized  = "unauthorized"   // identity not allowed this key
	CodeDecryptFailed = "decrypt-failed" // ciphertext malformed / auth failure
	CodeBadRequest    = "bad-request"
	CodeInternal      = "internal"
)

// Request is one operation. Key/Keys are the logical vault key names (NOT the
// ciphertext), used for authorization.
type Request struct {
	Op         string   `json:"op"`
	Key        string   `json:"key,omitempty"`
	Keys       []string `json:"keys,omitempty"`
	Plaintext  string   `json:"plaintext,omitempty"`
	Packed     string   `json:"packed,omitempty"`
	PackedMany []string `json:"packedMany,omitempty"`
}

// Response is one result. OK gates the payload fields; on failure Code/Error
// are set.
type Response struct {
	OK            bool     `json:"ok"`
	Error         string   `json:"error,omitempty"`
	Code          string   `json:"code,omitempty"`
	Packed        string   `json:"packed,omitempty"`
	Plaintext     string   `json:"plaintext,omitempty"`
	PlaintextMany []string `json:"plaintextMany,omitempty"`
	Unlocked      bool     `json:"unlocked,omitempty"`
	TTLRemaining  int      `json:"ttlRemaining,omitempty"`
}
