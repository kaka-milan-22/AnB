// Package authz maps an mTLS client identity (the cert CommonName) to the set
// of vault keys it may operate on, plus an optional presence allowlist for
// gated keys. It is Bob's authorization layer — the thing that makes "which
// Alice" meaningful beyond "some valid cert".
//
// Policy is a small JSON file in Bob's state dir:
//
//	{
//	  "rules":   { "alice-laptop": ["*"], "agent-ci": ["ci-", "deploy-"] },
//	  "presence":{ "allow": ["alice-laptop"] }
//	}
//
// A rule value of "*" allows all keys; otherwise each entry is a key-name
// prefix. If no policy file exists, OpenOrDefault returns an allow-all policy
// (DefaultAllow=true) so first-run dev works — Bob logs a warning in that case.
package authz

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
)

type Policy struct {
	Rules    map[string][]string `json:"rules"`
	Presence struct {
		Allow []string `json:"allow"`
	} `json:"presence"`

	// DefaultAllow is true only for the implicit first-run policy (no file).
	DefaultAllow bool `json:"-"`
}

// OpenOrDefault loads policy from path, or returns an allow-all policy if the
// file does not exist. A malformed file is a hard error (fail closed).
func OpenOrDefault(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Policy{DefaultAllow: true}, nil
	}
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Allowed reports whether identity may operate on key.
func (p *Policy) Allowed(identity, key string) bool {
	if p.DefaultAllow {
		return true
	}
	prefixes, ok := p.Rules[identity]
	if !ok {
		return false
	}
	for _, pre := range prefixes {
		if pre == "*" || strings.HasPrefix(key, pre) {
			return true
		}
	}
	return false
}

// PresenceAllowed reports whether identity may decrypt a presence-gated key.
// With DefaultAllow (no policy file) or an empty allowlist, gated keys are
// permitted but the caller is expected to AUDIT the access prominently.
func (p *Policy) PresenceAllowed(identity string) bool {
	if p.DefaultAllow || len(p.Presence.Allow) == 0 {
		return true
	}
	for _, id := range p.Presence.Allow {
		if id == identity {
			return true
		}
	}
	return false
}
