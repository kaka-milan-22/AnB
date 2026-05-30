// Package keystore is Bob's in-memory custody of the master key(s).
//
// Since v2.6 the store holds a MAP of key versions → 32-byte master keys,
// not a single key. All versions live in mlock'd buffers; the idle timer
// auto-zeroizes the whole set. The "current" version is what Encrypt uses;
// Decrypt accepts any held version and (when the cipher's version isn't
// current) returns a freshly-rewrapped value alongside the plaintext so
// alice can lazily migrate vault.json off retired versions.
//
// It deliberately does NOT decide process lifecycle — an optional onLock
// callback lets the daemon log or exit; the keystore only wipes memory.
package keystore

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/kaka-milan-22/AnB/v3/internal/crypto"
)

var (
	// ErrLocked is returned when no key is currently held.
	ErrLocked = errors.New("vault locked")
	// ErrUnknownVersion is returned when a ciphertext names a K
	// version the store doesn't have (e.g. it was finalized).
	ErrUnknownVersion = errors.New("unknown key version in ciphertext")
	// ErrCannotFinalizeCurrent guards RemoveKey: the in-use version
	// can't be retired (rotate first to promote a new current).
	ErrCannotFinalizeCurrent = errors.New("cannot finalize the current key version")
)

// Store holds one or more master key versions. All methods are safe
// for concurrent use.
type Store struct {
	mu        sync.Mutex
	keys      map[int][]byte // version → raw 32-byte K (mlock'd)
	current   int            // which version Encrypt uses; 0 = locked
	ttl       time.Duration
	expiresAt time.Time
	timer     *time.Timer
	onLock    func() // invoked after an idle-TTL auto-lock (not on explicit Zeroize)
}

// New returns an empty (locked) store. onLock may be nil.
func New(onLock func()) *Store { return &Store{onLock: onLock} }

// Hold is the single-key convenience that maps to HoldMulti with one
// entry at version 1. Kept for tests and any caller that only manages
// a single K; production bob serve uses HoldMulti directly.
func (s *Store) Hold(key []byte, ttl time.Duration) {
	s.HoldMulti(map[int][]byte{1: key}, 1, ttl)
}

// HoldMulti takes ownership of all keys, mlocks each, and (re)arms
// the idle timer. ttl <= 0 means "no expiry". HoldMulti replaces any
// previously held keys.
//
// IMPORTANT — HARDENING NOTE (v2.6+): the store makes a defensive
// COPY of every caller-supplied key before mlock'ing. This breaks the
// old aliasing footgun (v2.0–v2.5 had `store.Hold(mk); crypto.Wipe(mk)`
// which zeroed the store's view because both ends shared the same
// underlying byte array; the daemon then encrypted/decrypted under an
// all-zero AES-256 key with no warning). After HoldMulti returns the
// caller is free to Wipe its own buffers — the store's K is unaffected.
func (s *Store) HoldMulti(keys map[int][]byte, current int, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zeroizeLocked()
	if keys == nil || len(keys) == 0 {
		return
	}
	if _, ok := keys[current]; !ok {
		// Caller bug — current must exist among keys. Refuse to land
		// in a half-initialized state.
		return
	}
	owned := make(map[int][]byte, len(keys))
	for id, k := range keys {
		c := make([]byte, len(k))
		copy(c, k)
		lockMemory(c)
		owned[id] = c
	}
	s.keys = owned
	s.current = current
	s.ttl = ttl
	s.armLocked(false)
}

// AddKey installs an additional K under the given version and bumps
// current to it. Used by bob rotate-master-{password,key}. Like
// HoldMulti it defensively COPIES the key — caller is free to Wipe.
func (s *Store) AddKey(id int, key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys == nil {
		s.keys = make(map[int][]byte)
	}
	c := make([]byte, len(key))
	copy(c, key)
	lockMemory(c)
	s.keys[id] = c
	s.current = id
	s.armLocked(false)
}

// RemoveKey wipes K_<id> from memory. Refuses to remove the current
// version. Used by bob rotate-master-key --finalize.
func (s *Store) RemoveKey(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == s.current {
		return ErrCannotFinalizeCurrent
	}
	k, ok := s.keys[id]
	if !ok {
		return ErrUnknownVersion
	}
	crypto.Wipe(k)
	unlockMemory(k)
	delete(s.keys, id)
	return nil
}

// Unlocked reports whether the store holds at least one key.
func (s *Store) Unlocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current != 0
}

// CurrentVersion returns the version Encrypt would use, and whether
// the store is unlocked.
func (s *Store) CurrentVersion() (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current, s.current != 0
}

// Versions returns held key versions in ascending order.
func (s *Store) Versions() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int, 0, len(s.keys))
	for v := range s.keys {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// TTLRemaining returns the time until idle-lock, or 0 if locked / no expiry.
func (s *Store) TTLRemaining() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == 0 || s.ttl <= 0 {
		return 0
	}
	d := time.Until(s.expiresAt)
	if d < 0 {
		return 0
	}
	return d
}

// Encrypt seals plaintext under the current K and returns a versioned
// packed string ("v<current>:iv:tag:ct"). Refreshes the idle timer.
func (s *Store) Encrypt(plaintext []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == 0 {
		return "", ErrLocked
	}
	k := s.keys[s.current]
	if k == nil {
		return "", ErrLocked
	}
	raw, err := crypto.Seal(k, plaintext)
	if err != nil {
		return "", err
	}
	s.armLocked(false)
	return crypto.PackVersion(s.current, raw), nil
}

// Decrypt opens packed and returns (plaintext, rewrapped, currentVer, err).
//
// rewrapped: non-empty only when the cipher's version != current; it is the
// same plaintext re-sealed under the current K (versioned). Callers should
// write it back to their secret store for opportunistic migration.
//
// currentVer: true iff the ciphertext was already on the current K.
//
// A ciphertext without a "v<N>:" prefix is treated as legacy version 1.
func (s *Store) Decrypt(packed string) (plaintext []byte, rewrapped string, currentVer bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == 0 {
		return nil, "", false, ErrLocked
	}

	ver, raw, perr := crypto.ParseVersion(packed)
	if perr != nil {
		return nil, "", false, perr
	}
	k, ok := s.keys[ver]
	if !ok {
		return nil, "", false, ErrUnknownVersion
	}
	pt, oerr := crypto.Open(k, raw)
	if oerr != nil {
		return nil, "", false, oerr
	}
	if ver == s.current {
		s.armLocked(false)
		return pt, "", true, nil
	}
	// Rewrap under current K so the caller can migrate lazily.
	cur := s.keys[s.current]
	sealed, serr := crypto.Seal(cur, pt)
	if serr != nil {
		// Got plaintext, can't rewrap — propagate; caller can retry.
		return pt, "", false, serr
	}
	s.armLocked(false)
	return pt, crypto.PackVersion(s.current, sealed), false, nil
}

// Zeroize wipes all keys immediately (explicit lock). Does not fire onLock.
func (s *Store) Zeroize() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zeroizeLocked()
}

// armLocked refreshes the idle timer. Caller holds mu.
func (s *Store) armLocked(_ bool) {
	if s.ttl <= 0 {
		return
	}
	s.expiresAt = time.Now().Add(s.ttl)
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(s.ttl, func() {
		s.mu.Lock()
		had := s.current != 0
		s.zeroizeLocked()
		cb := s.onLock
		s.mu.Unlock()
		if had && cb != nil {
			cb()
		}
	})
}

// zeroizeLocked wipes + unlocks every key and stops the timer. Caller holds mu.
func (s *Store) zeroizeLocked() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	for v, k := range s.keys {
		crypto.Wipe(k)
		unlockMemory(k)
		delete(s.keys, v)
	}
	s.keys = nil
	s.current = 0
}
