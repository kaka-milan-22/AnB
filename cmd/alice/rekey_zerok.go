package main

import (
	"fmt"
	"os"

	"github.com/kaka-milan-22/AnB/v2/internal/crypto"
	"github.com/kaka-milan-22/AnB/v2/internal/localvault"
)

// rekey-from-zero — one-shot migration for vaults encrypted under the
// all-zero master key by buggy v2.0–v2.5 Bob daemons.
//
// Background: those Bob versions called `store.Hold(mk); crypto.Wipe(mk)`
// in `cmd/bob/main.go::cmdServe`. Hold stored the slice by reference;
// Wipe zeroed the underlying array, leaving the daemon's in-memory K as
// 32 bytes of zeros. Every Encrypt / Decrypt the daemon did therefore
// used a zero key. v2.6 fixes the bug, but vault.json entries written
// under the buggy daemons can no longer be decrypted by Bob with the
// real K — they need to be re-encrypted under the real K once.
//
// Mechanism: for each vault entry, locally attempt AES-256-GCM Open with
// the zero key. If the GCM tag verifies, the entry was a zero-K
// ciphertext — send the plaintext to Bob to re-encrypt under the
// current real K, and write the new ciphertext back to vault.json.
// Entries that don't decrypt under zero K (already on real K, or
// genuinely corrupt) are skipped.
//
// Idempotent: safe to run repeatedly. Plaintext stays in local memory
// for the duration of the Encrypt round-trip and is then wiped.
func cmdRekeyFromZero(args []string) error {
	fs := newFS("rekey-from-zero")
	dir := dirFlag(fs)
	dryRun := fs.Bool("dry-run", false, "scan only; report which keys would migrate, don't touch the vault")
	reason := fs.String("reason", "[rekey-from-zero v2.0-v2.5 fix]", `audit "why" string; logged in Bob's ALLOW line`)
	parse(fs, args)
	requireTTY("alice rekey-from-zero")

	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}
	if len(v.Secrets) == 0 {
		fmt.Println("Vault is empty — nothing to migrate.")
		return nil
	}

	zero := make([]byte, 32) // 32-byte AES-256 all-zero key

	type todo struct {
		key       string
		plaintext []byte
	}
	var pending []todo
	var skipped []string

	for name, entry := range v.Secrets {
		_, raw, perr := crypto.ParseVersion(entry.Value)
		if perr != nil {
			skipped = append(skipped, name+" (parse error: "+perr.Error()+")")
			continue
		}
		pt, oerr := crypto.Open(zero, raw)
		if oerr != nil {
			// Entry is already on the real K (or genuinely corrupt). Skip.
			skipped = append(skipped, name)
			continue
		}
		pending = append(pending, todo{key: name, plaintext: pt})
	}

	if len(pending) == 0 {
		fmt.Println("✓ No entries decrypt under the legacy zero K. Vault is clean.")
		if len(skipped) > 0 {
			fmt.Fprintf(os.Stderr, "  (%d entries already on real K or unrecoverable)\n", len(skipped))
		}
		return nil
	}

	if *dryRun {
		fmt.Fprintf(os.Stderr, "Would migrate %d zero-K entries:\n", len(pending))
		for _, t := range pending {
			fmt.Fprintf(os.Stderr, "  %s\n", t.key)
		}
		if len(skipped) > 0 {
			fmt.Fprintf(os.Stderr, "Skipping %d (already on real K or unrecoverable):\n", len(skipped))
			for _, k := range skipped {
				fmt.Fprintf(os.Stderr, "  %s\n", k)
			}
		}
		fmt.Fprintln(os.Stderr, "Re-run without --dry-run to actually migrate.")
		// Wipe locally-decrypted plaintext before returning.
		for i := range pending {
			for j := range pending[i].plaintext {
				pending[i].plaintext[j] = 0
			}
		}
		return nil
	}

	// Phase 2: re-encrypt each plaintext via Bob under the real current K.
	cl, _, err := loadClient(s)
	if err != nil {
		return err
	}
	cl.SetReason(*reason)

	migrated := 0
	var failed []string
	for i := range pending {
		t := &pending[i]
		packed, eerr := cl.Encrypt(t.key, string(t.plaintext))
		// Wipe plaintext immediately whether encrypt succeeded or not.
		for j := range t.plaintext {
			t.plaintext[j] = 0
		}
		if eerr != nil {
			failed = append(failed, t.key+": "+eerr.Error())
			continue
		}
		e, ok := v.Get(t.key)
		if !ok {
			failed = append(failed, t.key+": vanished from vault mid-migration")
			continue
		}
		e.Value = packed
		v.Set(t.key, e)
		migrated++
	}

	if err := s.Save(v); err != nil {
		return fmt.Errorf("save vault.json: %w (re-encrypted %d entries in memory but not persisted; re-run is safe)", err, migrated)
	}

	fmt.Fprintf(os.Stderr, "✓ Migrated %d entries from zero-K to the current real K.\n", migrated)
	if len(skipped) > 0 {
		fmt.Fprintf(os.Stderr, "  Skipped %d (already on real K or unrecoverable).\n", len(skipped))
	}
	if len(failed) > 0 {
		fmt.Fprintf(os.Stderr, "  Failed:\n")
		for _, f := range failed {
			fmt.Fprintf(os.Stderr, "    %s\n", f)
		}
		return fmt.Errorf("%d entries failed to migrate", len(failed))
	}
	return nil
}
