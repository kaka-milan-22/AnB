// Package keystore is Bob's in-memory custody of the master key.
//
// The key is held in an mlock'd buffer (best-effort kept out of swap), used
// only to encrypt/decrypt via the crypto package, and zeroized either on an
// explicit lock or after an idle TTL with no crypto activity. It deliberately
// does NOT decide process lifecycle — an optional onLock callback lets the
// daemon log or exit; the keystore itself only wipes memory.
package keystore

import (
	"errors"
	"sync"
	"time"

	"github.com/kaka-milan-22/AnB/internal/crypto"
)

// ErrLocked is returned by Encrypt/Decrypt when no key is currently held.
var ErrLocked = errors.New("vault locked")

// Store holds at most one master key. All methods are safe for concurrent use.
type Store struct {
	mu        sync.Mutex
	key       []byte
	ttl       time.Duration
	expiresAt time.Time
	timer     *time.Timer
	onLock    func() // invoked after an idle-TTL auto-lock (not on explicit Zeroize)
}

// New returns an empty (locked) store. onLock may be nil.
func New(onLock func()) *Store { return &Store{onLock: onLock} }

// Hold takes ownership of key, locks its pages, and (re)arms the idle timer.
// A ttl <= 0 means "no expiry". Hold replaces any previously held key.
func (s *Store) Hold(key []byte, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zeroizeLocked()
	lockMemory(key)
	s.key = key
	s.ttl = ttl
	s.armLocked(false)
}

// Unlocked reports whether a key is currently held.
func (s *Store) Unlocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.key != nil
}

// TTLRemaining returns the time until idle-lock, or 0 if locked / no expiry.
func (s *Store) TTLRemaining() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil || s.ttl <= 0 {
		return 0
	}
	d := time.Until(s.expiresAt)
	if d < 0 {
		return 0
	}
	return d
}

// Encrypt seals plaintext under the held key, refreshing the idle timer.
func (s *Store) Encrypt(plaintext []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return "", ErrLocked
	}
	packed, err := crypto.Seal(s.key, plaintext)
	if err != nil {
		return "", err
	}
	s.armLocked(false)
	return packed, nil
}

// Decrypt opens packed with the held key, refreshing the idle timer.
func (s *Store) Decrypt(packed string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return nil, ErrLocked
	}
	pt, err := crypto.Open(s.key, packed)
	if err != nil {
		return nil, err
	}
	s.armLocked(false)
	return pt, nil
}

// Zeroize wipes the key immediately (explicit lock). Does not fire onLock.
func (s *Store) Zeroize() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zeroizeLocked()
}

// armLocked refreshes the idle timer. Caller holds mu. If fromExpiry, onLock
// has already been responsible for cleanup, so we only (re)create the timer.
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
		had := s.key != nil
		s.zeroizeLocked()
		cb := s.onLock
		s.mu.Unlock()
		if had && cb != nil {
			cb()
		}
	})
}

// zeroizeLocked wipes + unlocks the key and stops the timer. Caller holds mu.
func (s *Store) zeroizeLocked() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	if s.key != nil {
		crypto.Wipe(s.key)
		unlockMemory(s.key)
		s.key = nil
	}
}
