// Package authz maps an mTLS client identity (the cert CommonName) to the set
// of vault keys it may operate on. It is Bob's authorization layer — the thing
// that makes "which Alice" meaningful beyond "some valid cert".
//
// Policy is a small JSON file in Bob's state dir:
//
//	{
//	  "rules": { "alice-laptop": ["*"], "agent-ci": ["ci-", "deploy-"] },
//	  "rate_limits": { "default": 100, "alice-laptop": 500, "agent-ci": 20 }
//	}
//
// A rule value of "*" allows all keys; otherwise each entry is a key-name
// prefix. If no policy file exists, OpenOrDefault returns an allow-all policy
// (DefaultAllow=true) so first-run dev works — Bob logs a warning in that case.
//
// rate_limits caps per-identity decrypt operations per minute. The lookup is:
// explicit per-identity entry > rate_limits["default"] > the built-in
// DefaultRateLimit (100/min, defined in v2.5).
package authz

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// DefaultRateLimit is the built-in per-minute decrypt cap used when the
// policy file is absent or doesn't override it.
const DefaultRateLimit = 100

type Policy struct {
	Rules      map[string][]string `json:"rules"`
	RateLimits map[string]int      `json:"rate_limits,omitempty"`

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
	for id, n := range p.RateLimits {
		if n <= 0 {
			return nil, fmt.Errorf("authz: rate_limits[%q] = %d; must be positive", id, n)
		}
	}
	return &p, nil
}

// Limit returns the per-minute decrypt cap for identity. Resolution order:
// explicit entry > "default" entry > DefaultRateLimit (100).
func (p *Policy) Limit(identity string) int {
	if v, ok := p.RateLimits[identity]; ok {
		return v
	}
	if v, ok := p.RateLimits["default"]; ok {
		return v
	}
	return DefaultRateLimit
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
