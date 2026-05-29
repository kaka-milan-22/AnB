package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kaka-milan-22/AnB/v2/internal/crypto"
	"github.com/kaka-milan-22/AnB/v2/internal/term"
)

// rotate-master-password — re-wrap the existing master key K under a new
// passphrase. K itself doesn't change, so vault.json ciphertext on alice's
// side is untouched and a currently-serving Bob keeps running with the
// same in-memory K. Only the next `bob serve` startup will need the new
// password.
//
// Failure modes are atomic: we unwrap with the old password first (and
// bail on error), then wrap with the new one, then write — so wrong old
// password / wrong new password confirmation leaves envelope.json byte
// for byte identical to what it was before.
func cmdRotateMasterPassword(args []string) error {
	fs := newFlags("rotate-master-password")
	dir := fs.String("dir", "", "state dir")
	parse(fs, args)

	d := bobDir(*dir)
	if !exists(d, "envelope.json") {
		return fmt.Errorf("no envelope.json in %s — run `bob init` first", d)
	}
	envJSON, err := readFile(d, "envelope.json")
	if err != nil {
		return fmt.Errorf("read envelope.json: %w", err)
	}
	var env crypto.Envelope
	if err := json.Unmarshal(envJSON, &env); err != nil {
		return fmt.Errorf("envelope.json: %w", err)
	}

	// --- old password (env override > TTY) ---
	oldPass := os.Getenv("ANB_BOB_PASSWORD")
	if oldPass == "" {
		if !term.StdinIsTTY() {
			return fmt.Errorf("rotate-master-password needs the current password: run on a TTY or set ANB_BOB_PASSWORD")
		}
		if oldPass, err = term.ReadPassword("Current master password: "); err != nil {
			return err
		}
	}

	mk, err := crypto.Unwrap(&env, oldPass)
	if err != nil {
		return err // surfaces "incorrect master password" verbatim
	}
	defer crypto.Wipe(mk)

	// --- new password (env override > TTY-confirmed) ---
	newPass := os.Getenv("ANB_BOB_NEW_PASSWORD")
	if newPass == "" {
		if !term.StdinIsTTY() {
			return fmt.Errorf("rotate-master-password needs the new password: run on a TTY or set ANB_BOB_NEW_PASSWORD")
		}
		if newPass, err = term.ReadNewPassword("New master password: "); err != nil {
			return err
		}
	}
	if newPass == oldPass {
		return fmt.Errorf("new password is identical to the current one — nothing to do")
	}

	newEnv, err := crypto.Wrap(mk, newPass)
	if err != nil {
		return fmt.Errorf("rewrap: %w", err)
	}
	newJSON, err := json.MarshalIndent(newEnv, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFile(d, "envelope.json", newJSON, 0o600); err != nil {
		return fmt.Errorf("write envelope.json: %w", err)
	}

	fmt.Println("✓ Master password rotated.")
	fmt.Println("  • The master key K is unchanged — vault.json on every alice is unaffected.")
	fmt.Println("  • A currently-serving bob keeps running with K already in memory.")
	fmt.Println("  • The new password is required at the next `bob serve` startup.")
	fmt.Println("  • If you have a launchd/systemd wrapper supplying $ANB_BOB_PASSWORD,")
	fmt.Println("    update it before restarting the daemon.")
	return nil
}
