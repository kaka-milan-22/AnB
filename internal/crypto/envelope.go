package crypto

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// EnvelopeSchemaVersion is the on-disk schema version. v3 introduced
// multi-key envelopes (v2.6+); pre-v2.6 was a single Envelope object
// at the top level with no `version` field. LoadEnvelopeFile detects
// and migrates that legacy shape into the v3 in-memory form.
const EnvelopeSchemaVersion = 3

// EnvelopeFile is the on-disk container for one OR MORE wrapped master
// keys. Each KeyEnvelope (`crypto.Envelope` with ID + Created set) holds
// one K version; Current names which version Encrypt should use.
type EnvelopeFile struct {
	Version int        `json:"version"`
	Keys    []Envelope `json:"keys"`
	Current int        `json:"current"`
}

// versionPrefixRE matches "v<N>:" at the start of a packed ciphertext.
// Group 1 is the version digits. The colon is consumed; group 2 is the
// remainder (the legacy "iv:tag:ct" body).
var versionPrefixRE = regexp.MustCompile(`^v([0-9]+):(.*)$`)

// PackVersion prepends a "v<N>:" tag to a legacy iv:tag:ct ciphertext.
// Bob always emits packed strings with this prefix in v2.6+; readers
// that see a string without the prefix treat it as version 1.
func PackVersion(version int, raw string) string {
	return "v" + strconv.Itoa(version) + ":" + raw
}

// ParseVersion splits "v<N>:rest" into (N, rest). A bare iv:tag:ct
// (no prefix) is implicitly version 1 — preserves backward compat with
// vault.json written by v2.5- alices.
func ParseVersion(s string) (int, string, error) {
	if s == "" {
		return 0, "", fmt.Errorf("crypto: empty packed value")
	}
	m := versionPrefixRE.FindStringSubmatch(s)
	if m == nil {
		// No prefix → legacy v1.
		return 1, s, nil
	}
	v, err := strconv.Atoi(m[1])
	if err != nil || v < 1 {
		return 0, "", fmt.Errorf("crypto: bad version prefix in %q", firstSegment(s))
	}
	return v, m[2], nil
}

// firstSegment returns the substring before the first ':' for use in
// error messages — avoids leaking the rest of (potentially large)
// ciphertexts when complaining about a bad prefix.
func firstSegment(s string) string {
	if i := strings.IndexByte(s, ':'); i > 0 {
		return s[:i+1]
	}
	return s
}

// LoadEnvelopeFile decodes the on-disk JSON. If it's a legacy v2 shape
// (a bare Envelope object without `version`/`keys`), wrap it in-memory
// as a single-key v3 file with id=1. Either way the returned struct is
// always in v3 shape, ready for Wrap/Unwrap operations.
//
// Disk file is NOT touched here — migration is in memory. The first
// rotate-* command will rewrite the file in v3 form.
func LoadEnvelopeFile(data []byte) (*EnvelopeFile, error) {
	// Probe: a v3 file has a top-level `keys` array.
	var probe struct {
		Keys json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	if len(probe.Keys) > 0 {
		var f EnvelopeFile
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("envelope: %w", err)
		}
		if len(f.Keys) == 0 {
			return nil, fmt.Errorf("envelope: v3 file has empty keys[]")
		}
		if f.Current == 0 {
			// Tolerate missing `current`: pick the highest id present.
			for _, k := range f.Keys {
				if k.ID > f.Current {
					f.Current = k.ID
				}
			}
		}
		return &f, nil
	}
	// Legacy v2 single-key shape.
	var legacy Envelope
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, fmt.Errorf("envelope (legacy v2): %w", err)
	}
	legacy.ID = 1
	if legacy.Created == "" {
		legacy.Created = time.Now().UTC().Format(time.RFC3339)
	}
	return &EnvelopeFile{
		Version: EnvelopeSchemaVersion,
		Keys:    []Envelope{legacy},
		Current: 1,
	}, nil
}

// MarshalEnvelopeFile produces v3 JSON for on-disk storage.
func MarshalEnvelopeFile(f *EnvelopeFile) ([]byte, error) {
	f.Version = EnvelopeSchemaVersion
	return json.MarshalIndent(f, "", "  ")
}

// FindKey returns a pointer to the KeyEnvelope with the given id, or
// nil if not present.
func (f *EnvelopeFile) FindKey(id int) *Envelope {
	for i := range f.Keys {
		if f.Keys[i].ID == id {
			return &f.Keys[i]
		}
	}
	return nil
}

// NextID returns the smallest id that isn't already in use. Used when
// adding a fresh K during rotation.
func (f *EnvelopeFile) NextID() int {
	max := 0
	for _, k := range f.Keys {
		if k.ID > max {
			max = k.ID
		}
	}
	return max + 1
}

// RemoveKey deletes the KeyEnvelope with the given id. Refuses to
// remove the current version (caller's responsibility to first add a
// new K and bump current).
func (f *EnvelopeFile) RemoveKey(id int) error {
	if id == f.Current {
		return fmt.Errorf("envelope: cannot remove current key version %d (rotate first)", id)
	}
	for i := range f.Keys {
		if f.Keys[i].ID == id {
			f.Keys = append(f.Keys[:i], f.Keys[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("envelope: no key with id %d", id)
}
