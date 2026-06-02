package main

import (
	"fmt"
	"os"

	"github.com/kaka-milan-22/AnB/v3/internal/crypto"
	"github.com/kaka-milan-22/AnB/v3/internal/localvault"
	"github.com/kaka-milan-22/AnB/v3/internal/strength"
)

// backfill-meta — populate the per-entry metadata (lenBytes, entropyBits,
// keyEpoch) for secrets stored before those fields existed. Bob decrypts every
// entry so Alice can MEASURE the plaintext (byte length + charset entropy); the
// plaintext is never printed and only lives in memory for the measurement.
//
// CreatedAt and UpdatedAt are left untouched — the value isn't changing, we're
// only describing what's already there. Any lazy rewrap Bob returns (because an
// entry lagged the current KEK) is applied while we're here, so this doubles as
// a KEK migration. Idempotent: re-running only rewrites entries whose computed
// metadata differs from what's stored.
//
// Bob must be reachable + unlocked, and the identity must have decrypt authz on
// every key. No TTY gate: it never exposes a secret value, so it's safe as a
// non-interactive maintenance step.
func cmdBackfillMeta(args []string) error {
	fs := newFS("backfill-meta")
	dir := dirFlag(fs)
	reason := fs.String("reason", "[backfill-meta]", `audit-only "why" string; logged in Bob's ALLOW line`)
	parse(fs, args)

	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}
	if len(v.Secrets) == 0 {
		fmt.Println("Vault is empty — nothing to backfill.")
		return nil
	}

	keys := make([]string, 0, len(v.Secrets))
	packed := make([]string, 0, len(v.Secrets))
	for k, e := range v.Secrets {
		keys = append(keys, k)
		packed = append(packed, e.Value)
	}

	cl, _, err := loadClient(s)
	if err != nil {
		return err
	}
	cl.SetReason(*reason)
	plaintexts, rewraps, derr := cl.DecryptMany(keys, packed)
	if derr != nil {
		return derr
	}

	updated, already := 0, 0
	for i, k := range keys {
		e, ok := v.Get(k)
		if !ok {
			continue // race: removed between load and write
		}
		// Bob omits RewrappedPackedMany entirely (nil) when nothing was
		// rewrapped, so it's only parallel to keys when non-empty.
		rewrap := ""
		if len(rewraps) == len(keys) {
			rewrap = rewraps[i]
		}
		// Apply any lazy rewrap (KEK moved forward) before reading the epoch.
		effective := e.Value
		if rewrap != "" {
			e.Value = rewrap
			effective = rewrap
		}
		epoch, _, _ := crypto.ParseVersion(effective)
		lenBytes := len(plaintexts[i])
		entropyBits := strength.EstimateBits(plaintexts[i])

		if rewrap == "" && e.LenBytes == lenBytes && e.EntropyBits == entropyBits && e.KeyEpoch == epoch {
			already++
			continue
		}
		e.LenBytes = lenBytes
		e.EntropyBits = entropyBits
		e.KeyEpoch = epoch
		v.Set(k, e)
		updated++
	}

	if err := s.Save(v); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ Backfilled metadata: %d entr%s updated, %d already complete (of %d).\n",
		updated, plural2(updated, "y", "ies"), already, len(keys))
	return nil
}
