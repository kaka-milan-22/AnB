// Package localvault is Alice's on-disk state: the vault.json holding
// ciphertext secret values + metadata (NO master key — that lives in Bob), the
// connection config (where Bob is, Alice's identity), and the paths of Alice's
// mTLS client cert/key + CA trust anchor. Plaintext never lands here.
package localvault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

const Version = 1

// SecretEntry mirrors agent-vault's shape; Value is Bob-produced ciphertext.
// Fields after CreatedAt are additive (omitempty) so vault.json written by
// older alices still loads and re-marshals cleanly; they populate on the next
// set or rewrap.
type SecretEntry struct {
	Value     string `json:"value"` // iv:tag:ct from Bob
	Desc      string `json:"desc,omitempty"`
	CreatedAt string `json:"createdAt"`
	// UpdatedAt is the last time the VALUE changed (RFC3339 UTC). Empty means
	// the value hasn't changed since CreatedAt. Rewraps do NOT bump it — the
	// plaintext is unchanged, only the wrapping KEK.
	UpdatedAt string `json:"updatedAt,omitempty"`
	// KeyEpoch is the KEK generation that wrapped Value, parsed from its
	// "v<N>:" prefix. Lets `list` surface entries lagging the current KEK.
	KeyEpoch int `json:"keyEpoch,omitempty"`
	// LenBytes is the exact plaintext byte length. Not a side-channel: the
	// AES-GCM ciphertext in Value already reveals it (GCM adds no padding, so
	// len(ct) == len(plaintext)), so bucketing it would hide nothing. EntropyBits
	// is a charset-estimated, 8-bit-quantized strength figure — kept coarse
	// because charset composition is NOT recoverable from the ciphertext.
	LenBytes    int `json:"lenBytes,omitempty"`
	EntropyBits int `json:"entropyBits,omitempty"`
}

type Vault struct {
	Version int                    `json:"version"`
	Secrets map[string]SecretEntry `json:"secrets"`
}

// Config is Alice's connection profile to Bob.
type Config struct {
	BobAddr    string `json:"bobAddr"`    // host:port
	ServerName string `json:"serverName"` // SAN to verify on Bob's cert
	Identity   string `json:"identity"`   // CN baked into the client cert
}

type Store struct{ Dir string }

// DefaultDir is ~/.anb/alice, overridable via $ANB_ALICE_DIR.
func DefaultDir() string {
	if d := os.Getenv("ANB_ALICE_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".anb", "alice")
}

func Open(dir string) *Store {
	if dir == "" {
		dir = DefaultDir()
	}
	return &Store{Dir: dir}
}

func (s *Store) VaultPath() string      { return filepath.Join(s.Dir, "vault.json") }
func (s *Store) ConfigPath() string     { return filepath.Join(s.Dir, "config.json") }
func (s *Store) ClientCertPath() string { return filepath.Join(s.Dir, "client.crt") }
func (s *Store) ClientKeyPath() string  { return filepath.Join(s.Dir, "client.key") }
func (s *Store) CSRPath() string        { return filepath.Join(s.Dir, "client.csr") }
func (s *Store) CAPath() string         { return filepath.Join(s.Dir, "ca.crt") }

func (s *Store) VaultExists() bool {
	_, err := os.Stat(s.VaultPath())
	return err == nil
}

// Load reads vault.json, or returns an empty vault if none exists.
func (s *Store) Load() (*Vault, error) {
	b, err := os.ReadFile(s.VaultPath())
	if os.IsNotExist(err) {
		return &Vault{Version: Version, Secrets: map[string]SecretEntry{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var v Vault
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	if v.Secrets == nil {
		v.Secrets = map[string]SecretEntry{}
	}
	return &v, nil
}

// Save atomically writes vault.json (0600) via temp file + rename.
func (s *Store) Save(v *Vault) error {
	v.Version = Version
	return s.writeAtomic(s.VaultPath(), mustJSON(v), 0o600)
}

func (s *Store) LoadConfig() (*Config, error) {
	b, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) SaveConfig(c *Config) error {
	return s.writeAtomic(s.ConfigPath(), mustJSON(c), 0o600)
}

func (s *Store) WriteFile(name string, data []byte, mode os.FileMode) error {
	return s.writeAtomic(filepath.Join(s.Dir, name), data, mode)
}

func (s *Store) writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	// Manual open+write+fsync+close+rename, not os.WriteFile, so the
	// bytes hit disk BEFORE rename — without fsync a crash between
	// rename and the kernel's writeback would leave a zero-byte (or
	// torn) file at `path` even though rename(2) itself is atomic on
	// POSIX filesystems. APFS / ext4 / xfs / btrfs all guarantee
	// rename atomicity but NOT that file contents are durable at the
	// time of rename.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

// --- Vault helpers ---

type Listing struct {
	Key         string `json:"key"`
	Desc        string `json:"desc,omitempty"`
	KeyEpoch    int    `json:"keyEpoch,omitempty"`
	LenBytes    int    `json:"lenBytes,omitempty"`
	EntropyBits int    `json:"entropyBits,omitempty"`
}

func (v *Vault) Has(key string) bool { _, ok := v.Secrets[key]; return ok }

func (v *Vault) Get(key string) (SecretEntry, bool) { e, ok := v.Secrets[key]; return e, ok }

func (v *Vault) Set(key string, e SecretEntry) { v.Secrets[key] = e }

func (v *Vault) Remove(key string) bool {
	if _, ok := v.Secrets[key]; !ok {
		return false
	}
	delete(v.Secrets, key)
	return true
}

// List returns key listings sorted by name.
func (v *Vault) List() []Listing {
	out := make([]Listing, 0, len(v.Secrets))
	for k, e := range v.Secrets {
		out = append(out, Listing{Key: k, Desc: e.Desc, KeyEpoch: e.KeyEpoch, LenBytes: e.LenBytes, EntropyBits: e.EntropyBits})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
