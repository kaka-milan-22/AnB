package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kaka-milan-22/AnB/v3/internal/crypto"
	"github.com/kaka-milan-22/AnB/v3/internal/term"
)

// rotate-master-password — by default re-wraps the existing master keys
// under a new passphrase AND adds a fresh K (bumping current), so callers
// who decrypt old-K ciphertext get a lazy-rewrap response. Pass
// `--keep-key` to retain v2.3 semantics (just change the password, K
// unchanged).
//
// Failure modes are atomic: if any unwrap fails, envelope.json stays
// byte-for-byte unchanged.
func cmdRotateMasterPassword(args []string) error {
	fs := newFlags("rotate-master-password")
	dir := fs.String("dir", "", "state dir")
	keepKey := fs.Bool("keep-key", false, "do NOT add a fresh K (v2.3 behavior: change password only)")
	parse(fs, args)

	d := bobDir(*dir)
	envFile, oldPass, err := loadAndUnwrapEnvelope(d, "Current master password: ")
	if err != nil {
		return err
	}
	// oldPass is the password we just used to unwrap. Now ask for the new one.
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

	// Unwrap every held K with the OLD password (we already validated current,
	// but every version may be wrapped under different salts; need fresh KDF
	// per entry). Then re-wrap each under the NEW password.
	mks, err := unwrapAll(envFile, oldPass)
	if err != nil {
		return err
	}
	defer func() {
		for _, k := range mks {
			crypto.Wipe(k)
		}
	}()

	if !*keepKey {
		// Add a fresh K_<NextID>.
		fresh, err := crypto.NewMasterKey()
		if err != nil {
			return err
		}
		newID := envFile.NextID()
		mks[newID] = fresh
		envFile.Current = newID
	}

	if err := rewrapAll(envFile, mks, newPass); err != nil {
		return err
	}

	if err := writeEnvelope(d, envFile); err != nil {
		return err
	}

	if *keepKey {
		fmt.Println("✓ Master password rotated (--keep-key: K versions unchanged).")
	} else {
		fmt.Printf("✓ Master password rotated; added K_%d as current.\n", envFile.Current)
		fmt.Println("  • Old vault.json ciphertext still decrypts; lazy rewrap migrates entries")
		fmt.Println("    on the next alice access (or run `alice rekey` to force-migrate now).")
		fmt.Println("  • When `alice rekey-status` shows zero for an old version on every alice,")
		fmt.Println("    run `bob rotate-master-key --finalize <id>` to retire it.")
	}
	fmt.Println("  • The new password is required at the next `bob serve` startup.")
	fmt.Println("  • Currently-serving bob keeps running with K already in memory.")
	return nil
}

// rotate-master-key — add a fresh K under the SAME password (no password
// change). Used when you want a key rotation without touching the
// passphrase. With `--finalize <id>` it instead REMOVES the named K.
func cmdRotateMasterKey(args []string) error {
	fs := newFlags("rotate-master-key")
	dir := fs.String("dir", "", "state dir")
	finalize := fs.Int("finalize", 0, "retire key version <id> (cannot be the current one)")
	yes := fs.Bool("yes", false, "skip the interactive confirmation for --finalize")
	parse(fs, args)

	d := bobDir(*dir)
	envFile, pass, err := loadAndUnwrapEnvelope(d, "Master password: ")
	if err != nil {
		return err
	}

	if *finalize > 0 {
		return doFinalize(d, envFile, pass, *finalize, *yes)
	}

	// Add a fresh K under the same password.
	mks, err := unwrapAll(envFile, pass)
	if err != nil {
		return err
	}
	defer func() {
		for _, k := range mks {
			crypto.Wipe(k)
		}
	}()

	fresh, err := crypto.NewMasterKey()
	if err != nil {
		return err
	}
	newID := envFile.NextID()
	mks[newID] = fresh
	envFile.Current = newID

	if err := rewrapAll(envFile, mks, pass); err != nil {
		return err
	}
	if err := writeEnvelope(d, envFile); err != nil {
		return err
	}

	fmt.Printf("✓ Added K_%d as current. Existing K versions retained for backward decrypt.\n", newID)
	fmt.Println("  • Restart `bob serve` to load the new K into memory.")
	fmt.Println("  • Run `alice rekey` on each alice when ready to migrate vault.json.")
	return nil
}

func doFinalize(dir string, envFile *crypto.EnvelopeFile, pass string, id int, yes bool) error {
	if envFile.FindKey(id) == nil {
		return fmt.Errorf("--finalize: no K_%d in envelope.json", id)
	}
	if id == envFile.Current {
		return fmt.Errorf("--finalize: cannot retire the current key version %d (rotate first)", id)
	}
	if !yes {
		fmt.Printf("This irrevocably destroys K_%d.\n", id)
		fmt.Println("Any vault.json entry still encrypted under it will become unreadable.")
		fmt.Println("Have you run `alice rekey-status` on every enrolled identity and confirmed zero?")
		fmt.Print("Type 'yes' to confirm: ")
		r := bufio.NewReader(os.Stdin)
		line, _ := r.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("Cancelled — no changes written.")
			return nil
		}
	}
	if err := envFile.RemoveKey(id); err != nil {
		return err
	}
	// Re-wrap remaining keys under the same password (preserves salt
	// rotation hygiene — fresh KDF cost per write).
	mks, err := unwrapAll(envFile, pass)
	if err != nil {
		return err
	}
	defer func() {
		for _, k := range mks {
			crypto.Wipe(k)
		}
	}()
	if err := rewrapAll(envFile, mks, pass); err != nil {
		return err
	}
	if err := writeEnvelope(dir, envFile); err != nil {
		return err
	}
	fmt.Printf("✓ Finalized K_%d (removed from envelope.json).\n", id)
	fmt.Println("  • Restart `bob serve` so the daemon drops K from memory too.")
	fmt.Printf("  • Any vault.json entry that still referenced K_%d is now permanently unreadable.\n", id)
	return nil
}

// list-keys — show the envelope's K versions (no password needed; reads
// metadata only).
func cmdListKeys(args []string) error {
	fs := newFlags("list-keys")
	dir := fs.String("dir", "", "state dir")
	parse(fs, args)

	d := bobDir(*dir)
	if !exists(d, "envelope.json") {
		return fmt.Errorf("no envelope.json in %s — run `bob init` first", d)
	}
	envJSON, err := readFile(d, "envelope.json")
	if err != nil {
		return err
	}
	envFile, err := crypto.LoadEnvelopeFile(envJSON)
	if err != nil {
		return fmt.Errorf("envelope.json: %w", err)
	}
	fmt.Printf("%-4s  %-25s  %-9s  %-20s  %s\n", "ID", "CREATED", "KDF", "PARAMS", "CURRENT")
	for _, k := range envFile.Keys {
		mark := ""
		if k.ID == envFile.Current {
			mark = "←"
		}
		p := fmt.Sprintf("m=%d t=%d p=%d", k.Params.M, k.Params.T, k.Params.P)
		fmt.Printf("%-4d  %-25s  %-9s  %-20s  %s\n", k.ID, k.Created, k.KDF, p, mark)
	}
	return nil
}

// --- internal helpers ---

// loadAndUnwrapEnvelope reads envelope.json from dir, prompts (or reads
// env) for the master password, validates it against the CURRENT K, and
// returns (envFile, password) ready for further unwrap. Atomic: if the
// password is wrong, returns an error before any disk write.
func loadAndUnwrapEnvelope(dir, prompt string) (*crypto.EnvelopeFile, string, error) {
	if !exists(dir, "envelope.json") {
		return nil, "", fmt.Errorf("no envelope.json in %s — run `bob init` first", dir)
	}
	envJSON, err := readFile(dir, "envelope.json")
	if err != nil {
		return nil, "", fmt.Errorf("read envelope.json: %w", err)
	}
	envFile, err := crypto.LoadEnvelopeFile(envJSON)
	if err != nil {
		return nil, "", fmt.Errorf("envelope.json: %w", err)
	}

	pass := os.Getenv("ANB_BOB_PASSWORD")
	if pass != "" {
		// Prune the env immediately so any further fork/exec we do doesn't
		// inherit the password. See cmdServe for the full caveat re:
		// /proc/PID/environ.
		_ = os.Unsetenv("ANB_BOB_PASSWORD")
	}
	if pass == "" {
		if !term.StdinIsTTY() {
			return nil, "", fmt.Errorf("needs the master password: run on a TTY or set ANB_BOB_PASSWORD")
		}
		if pass, err = term.ReadPassword(prompt); err != nil {
			return nil, "", err
		}
	}
	// Validate against the current K.
	cur := envFile.FindKey(envFile.Current)
	if cur == nil {
		return nil, "", fmt.Errorf("envelope.json: current=%d but no such key", envFile.Current)
	}
	mk, err := crypto.Unwrap(cur, pass)
	if err != nil {
		return nil, "", err
	}
	crypto.Wipe(mk)
	return envFile, pass, nil
}

// unwrapAll opens every K version in envFile under password. Returns a
// fresh map[id]K_bytes. Caller is responsible for Wiping every entry.
func unwrapAll(envFile *crypto.EnvelopeFile, password string) (map[int][]byte, error) {
	out := make(map[int][]byte, len(envFile.Keys))
	for i := range envFile.Keys {
		k, err := crypto.Unwrap(&envFile.Keys[i], password)
		if err != nil {
			for _, w := range out {
				crypto.Wipe(w)
			}
			return nil, fmt.Errorf("unwrap K_%d: %w", envFile.Keys[i].ID, err)
		}
		out[envFile.Keys[i].ID] = k
	}
	return out, nil
}

// rewrapAll re-wraps each K_id in mks under password and writes the
// fresh KeyEnvelope back into envFile.Keys (preserving order by ID).
// Salts are re-randomized per entry (free Argon2 cost refresh).
func rewrapAll(envFile *crypto.EnvelopeFile, mks map[int][]byte, password string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	// Preserve Created timestamps for existing keys; only set new keys
	// to "now".
	created := make(map[int]string, len(envFile.Keys))
	for _, k := range envFile.Keys {
		created[k.ID] = k.Created
	}
	newKeys := make([]crypto.Envelope, 0, len(mks))
	for id, k := range mks {
		ne, err := crypto.Wrap(k, password)
		if err != nil {
			return fmt.Errorf("rewrap K_%d: %w", id, err)
		}
		ne.ID = id
		if c, ok := created[id]; ok && c != "" {
			ne.Created = c
		} else {
			ne.Created = now
		}
		newKeys = append(newKeys, *ne)
	}
	// Sort by ID for deterministic on-disk order.
	for i := 0; i < len(newKeys); i++ {
		for j := i + 1; j < len(newKeys); j++ {
			if newKeys[j].ID < newKeys[i].ID {
				newKeys[i], newKeys[j] = newKeys[j], newKeys[i]
			}
		}
	}
	envFile.Keys = newKeys
	return nil
}

func writeEnvelope(dir string, envFile *crypto.EnvelopeFile) error {
	body, err := crypto.MarshalEnvelopeFile(envFile)
	if err != nil {
		return err
	}
	return writeFile(dir, "envelope.json", body, 0o600)
}

// ParseFinalizeID is exposed for testing; converts a "<id>" string to an int.
func parseFinalizeID(s string) (int, error) { return strconv.Atoi(s) }
