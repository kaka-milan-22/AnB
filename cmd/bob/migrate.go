package main

import (
	"fmt"
	"os"
	"time"

	"github.com/kaka-milan-22/AnB/v3/internal/crypto"
	"github.com/kaka-milan-22/AnB/v3/internal/localvault"
)

// cmdMigrateAAD re-seals every vault entry so its ciphertext is bound to its
// key name via AES-GCM AAD (see internal/crypto). It reads each legacy (no-AAD)
// ciphertext, re-encrypts it under the current K with the name as AAD, and
// writes the vault back atomically after a timestamped .bak backup.
//
// Offline, operator-run, one-shot. The legacy no-AAD read path lives ONLY here;
// it is never exposed over the mTLS oracle (serve is strict-AAD only).
// Idempotent: entries already AAD-bound are detected and left untouched, and
// the vault is only rewritten if at least one entry changed. On any per-entry
// error it aborts WITHOUT writing — the original vault (and the .bak) are intact.
func cmdMigrateAAD(args []string) error {
	fs := newFlags("migrate-aad")
	dir := fs.String("dir", "", "bob state dir (envelope.json); default ~/.anb/bob or $ANB_BOB_DIR")
	vaultDir := fs.String("vault-dir", "", "alice vault dir (vault.json); default ~/.anb/alice")
	parse(fs, args)

	d := bobDir(*dir)
	envFile, pass, err := loadAndUnwrapEnvelope(d, "Bob master password: ")
	if err != nil {
		return err
	}
	mks, err := unwrapAll(envFile, pass)
	if err != nil {
		return err
	}
	defer func() {
		for _, k := range mks {
			crypto.Wipe(k)
		}
	}()
	curK, ok := mks[envFile.Current]
	if !ok {
		return fmt.Errorf("current key version %d not unwrapped", envFile.Current)
	}

	vdir := *vaultDir
	if vdir == "" {
		vdir = localvault.DefaultDir()
	}
	store := localvault.Open(vdir)
	v, err := store.Load()
	if err != nil {
		return fmt.Errorf("load vault %s: %w", store.VaultPath(), err)
	}
	if len(v.Secrets) == 0 {
		fmt.Printf("vault %s has no secrets; nothing to migrate\n", store.VaultPath())
		return nil
	}

	// Backup the vault file BEFORE touching it.
	bak := store.VaultPath() + ".pre-aad-" + time.Now().UTC().Format("20060102T150405Z")
	raw0, err := os.ReadFile(store.VaultPath())
	if err != nil {
		return fmt.Errorf("read vault for backup: %w", err)
	}
	if err := os.WriteFile(bak, raw0, 0o600); err != nil {
		return fmt.Errorf("write backup %s: %w", bak, err)
	}

	migrated, already := 0, 0
	for name, e := range v.Secrets {
		ver, body, perr := crypto.ParseVersion(e.Value)
		if perr != nil {
			return fmt.Errorf("entry %q: %w (vault unchanged; backup at %s)", name, perr, bak)
		}
		k, ok := mks[ver]
		if !ok {
			return fmt.Errorf("entry %q references key version %d not in envelope (retired?); vault unchanged, backup at %s", name, ver, bak)
		}
		// Already AAD-bound under this name? (idempotent re-run / partial prior run)
		if _, oerr := crypto.OpenAAD(k, body, []byte(name)); oerr == nil {
			already++
			continue
		}
		// Legacy no-AAD read.
		pt, lerr := crypto.Open(k, body)
		if lerr != nil {
			return fmt.Errorf("entry %q: not decryptable as legacy or AAD-bound; vault unchanged, backup at %s: %w", name, bak, lerr)
		}
		sealed, serr := crypto.SealAAD(curK, pt, []byte(name))
		crypto.Wipe(pt)
		if serr != nil {
			return fmt.Errorf("entry %q reseal: %w", name, serr)
		}
		e.Value = crypto.PackVersion(envFile.Current, sealed)
		v.Set(name, e)
		migrated++
	}

	if migrated == 0 {
		fmt.Printf("all %d entries already AAD-bound; nothing to do\n", already)
		_ = os.Remove(bak) // backup not needed — nothing changed
		return nil
	}
	if err := store.Save(v); err != nil {
		return fmt.Errorf("save vault (backup at %s): %w", bak, err)
	}
	fmt.Printf("✓ migrated %d entries to AAD-binding (%d already bound).\n  vault:  %s\n  backup: %s\n",
		migrated, already, store.VaultPath(), bak)
	return nil
}
