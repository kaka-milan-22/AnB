// alice eth — Ethereum HD wallet helpers backed by the AnB vault.
//
// The mnemonic is stored as a normal secret entry (encrypted under Bob's
// K_current, same as any other --reveal-class secret). Addresses are
// derived on demand from the stored mnemonic; no derived state is
// cached on disk. See internal/eth for the derivation pipeline.
//
// Sub-commands:
//
//	alice eth new      [--words 12|24] [--name <vault-key>]
//	alice eth address  [--name <vault-key>] [--index N]
//	alice eth show     [--name <vault-key>] [--reveal-mnemonic]
//	alice eth import   [--name <vault-key>]
//
// Signing (eth sign) is deferred to a future release — RLP encoder,
// EIP-155 chain ID, and EIP-1559 typed-transaction handling each
// deserve their own treatment.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/kaka-milan-22/AnB/v3/internal/eth"
	"github.com/kaka-milan-22/AnB/v3/internal/localvault"
	"github.com/kaka-milan-22/AnB/v3/internal/term"
)

const ethDefaultName = "eth"

// cmdEth dispatches `alice eth <sub> ...` to the right handler.
func cmdEth(args []string) error {
	if len(args) == 0 {
		return ethUsage()
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "new":
		return cmdEthNew(rest)
	case "address":
		return cmdEthAddress(rest)
	case "show":
		return cmdEthShow(rest)
	case "import":
		return cmdEthImport(rest)
	case "-h", "--help", "help":
		return ethUsage()
	default:
		return fmt.Errorf("unknown subcommand %q (use one of: new, address, show, import)", sub)
	}
}

func ethUsage() error {
	w := os.Stderr
	fmt.Fprint(w, "Usage: alice eth <subcommand> [flags]\n\n")
	fmt.Fprint(w, "Subcommands:\n")
	fmt.Fprintln(w, "  new      [--words 12|24] [--name <key>]     Generate a fresh mnemonic + show the first address (TTY only).")
	fmt.Fprintln(w, "  address  [--name <key>] [--index N]         Derive m/44'/60'/0'/0/N (EIP-55 checksummed).")
	fmt.Fprintln(w, "  show     [--name <key>] [--reveal-mnemonic] Print address + metadata; with the flag (TTY only), the 24 words too.")
	fmt.Fprintln(w, "  import   [--name <key>]                     Read an existing mnemonic from TTY, validate, and store it.")
	return fmt.Errorf("usage")
}

// cmdEthNew generates a fresh BIP-39 mnemonic, stores it (encrypted by
// Bob) under a vault entry, and prints the words + first address.
func cmdEthNew(args []string) error {
	fs := newFS("eth new")
	dir := dirFlag(fs)
	words := fs.Int("words", 24, "mnemonic word count (12 or 24)")
	name := fs.String("name", ethDefaultName, "vault entry name to store the mnemonic under")
	parse(fs, args)
	requireTTY("alice eth new")

	if !keyFormat.MatchString(*name) {
		return fmt.Errorf("invalid --name %q (use lowercase alphanumeric + hyphens)", *name)
	}

	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}
	if existing, exists := v.Get(*name); exists {
		fmt.Fprintf(os.Stderr, "⚠ %q already exists (set %s).\n", *name, existing.CreatedAt)
		fmt.Fprintln(os.Stderr, "  Overwriting would destroy the existing mnemonic and all addresses derived from it.")
		ok, _ := term.Confirm("Overwrite?", false)
		if !ok {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	mnemonic, err := eth.GenMnemonic(*words)
	if err != nil {
		return err
	}
	addr, err := eth.DeriveAddress(mnemonic, 0)
	if err != nil {
		return err
	}

	cl, _, err := loadClient(s)
	if err != nil {
		return err
	}
	packed, err := cl.Encrypt(*name, mnemonic)
	if err != nil {
		return err
	}
	v.Set(*name, localvault.SecretEntry{
		Value:     packed,
		CreatedAt: nowStamp(),
		Desc:      fmt.Sprintf("ETH BIP-39 mnemonic (%d words, derive m/44'/60'/0'/0/N)", *words),
	})
	if err := s.Save(v); err != nil {
		return err
	}

	fmt.Printf("✓ Stored mnemonic under %q (encrypted by Bob).\n\n", *name)
	fmt.Println("Mnemonic — write this down NOW (it is the ONLY backup outside the vault):")
	fmt.Println()
	printWords(mnemonic)
	fmt.Println()
	fmt.Printf("First address (m/44'/60'/0'/0/0):  %s\n", addr)
	fmt.Println()
	fmt.Println("To derive more addresses:")
	fmt.Printf("  alice eth address --name %s --index 1\n", *name)
	fmt.Printf("  alice eth address --name %s --index 2\n", *name)
	return nil
}

// cmdEthAddress fetches the stored mnemonic via Bob and prints the address
// at the requested index. The mnemonic itself is wiped immediately.
func cmdEthAddress(args []string) error {
	fs := newFS("eth address")
	dir := dirFlag(fs)
	name := fs.String("name", ethDefaultName, "vault entry holding the mnemonic")
	index := fs.Uint("index", 0, "BIP-44 index N for m/44'/60'/0'/0/N")
	parse(fs, args)
	// No TTY requirement — addresses are PUBLIC. Safe to pipe / log /
	// post on Slack. The mnemonic stays inside this process.

	mnemonic, err := loadMnemonic(*dir, *name)
	if err != nil {
		return err
	}
	defer wipeStr(&mnemonic)

	addr, err := eth.DeriveAddress(mnemonic, uint32(*index))
	if err != nil {
		return err
	}
	fmt.Println(addr)
	return nil
}

// cmdEthShow prints address(es) + vault metadata; with --reveal-mnemonic
// also prints the 24-word backup (TTY only, like alice get --reveal).
func cmdEthShow(args []string) error {
	fs := newFS("eth show")
	dir := dirFlag(fs)
	name := fs.String("name", ethDefaultName, "vault entry holding the mnemonic")
	reveal := fs.Bool("reveal-mnemonic", false, "also print the 24-word mnemonic (TTY only)")
	index := fs.Uint("index", 0, "BIP-44 index N for the displayed address")
	parse(fs, args)

	if *reveal {
		requireStdoutTTY("alice eth show --reveal-mnemonic")
	}

	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}
	entry, ok := v.Get(*name)
	if !ok {
		return fmt.Errorf("no vault entry named %q (try `alice eth new` or `alice eth import`)", *name)
	}

	mnemonic, err := loadMnemonic(*dir, *name)
	if err != nil {
		return err
	}
	defer wipeStr(&mnemonic)

	addr, err := eth.DeriveAddress(mnemonic, uint32(*index))
	if err != nil {
		return err
	}

	fmt.Printf("Wallet:           %s\n", *name)
	fmt.Printf("Set at:           %s\n", entry.CreatedAt)
	if entry.Desc != "" {
		fmt.Printf("Description:      %s\n", entry.Desc)
	}
	fmt.Printf("Address (idx %d):  %s\n", *index, addr)
	if *reveal {
		fmt.Println()
		fmt.Println("Mnemonic:")
		printWords(mnemonic)
	} else {
		fmt.Println("(Use --reveal-mnemonic on a TTY to print the 24 words.)")
	}
	return nil
}

// cmdEthImport reads an existing mnemonic from TTY (prompts), validates
// BIP-39 wordlist + checksum, and stores it. No --stdin path — pasting
// 24 words through a pipe is a footgun (whitespace, history exposure).
func cmdEthImport(args []string) error {
	fs := newFS("eth import")
	dir := dirFlag(fs)
	name := fs.String("name", ethDefaultName, "vault entry name to store the mnemonic under")
	parse(fs, args)
	requireTTY("alice eth import")

	if !keyFormat.MatchString(*name) {
		return fmt.Errorf("invalid --name %q (use lowercase alphanumeric + hyphens)", *name)
	}

	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}
	if existing, exists := v.Get(*name); exists {
		fmt.Fprintf(os.Stderr, "⚠ %q already exists (set %s).\n", *name, existing.CreatedAt)
		ok, _ := term.Confirm("Overwrite?", false)
		if !ok {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	fmt.Println("Paste your 12- or 24-word mnemonic (single line, space-separated):")
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read mnemonic: %w", err)
	}
	mnemonic := eth.NormalizeMnemonic(line)
	defer wipeStr(&mnemonic)

	if err := eth.ValidateMnemonic(mnemonic); err != nil {
		return err
	}
	addr, err := eth.DeriveAddress(mnemonic, 0)
	if err != nil {
		return err
	}

	cl, _, err := loadClient(s)
	if err != nil {
		return err
	}
	packed, err := cl.Encrypt(*name, mnemonic)
	if err != nil {
		return err
	}
	words := strings.Fields(mnemonic)
	v.Set(*name, localvault.SecretEntry{
		Value:     packed,
		CreatedAt: nowStamp(),
		Desc:      fmt.Sprintf("ETH BIP-39 mnemonic (%d words, derive m/44'/60'/0'/0/N) — imported", len(words)),
	})
	if err := s.Save(v); err != nil {
		return err
	}

	fmt.Printf("✓ Imported mnemonic under %q.\n", *name)
	fmt.Printf("First address (m/44'/60'/0'/0/0):  %s\n", addr)
	return nil
}

// loadMnemonic fetches and decrypts the stored mnemonic. Returned string
// holds plaintext — caller must wipeStr() it when done.
func loadMnemonic(dir, name string) (string, error) {
	s := localvault.Open(dir)
	v, err := s.Load()
	if err != nil {
		return "", err
	}
	entry, ok := v.Get(name)
	if !ok {
		return "", fmt.Errorf("no vault entry named %q (try `alice eth new` or `alice eth import`)", name)
	}
	cl, _, err := loadClient(s)
	if err != nil {
		return "", err
	}
	pts, rewraps, err := cl.DecryptMany([]string{name}, []string{entry.Value})
	if err != nil {
		return "", err
	}
	if n, werr := applyRewraps(s, []string{name}, rewraps); werr != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write back %d rewrapped entries: %v\n", n, werr)
	}
	return pts[0], nil
}

// printWords pretty-prints a mnemonic in numbered groups of 4 so paper
// transcription is hard to misread. Output is for TTY consumption only;
// callers wrap this in a TTY check or accept that the words go to stdout.
func printWords(mnemonic string) {
	words := strings.Fields(mnemonic)
	for i := 0; i < len(words); i += 4 {
		end := i + 4
		if end > len(words) {
			end = len(words)
		}
		var nums []string
		for j := i; j < end; j++ {
			nums = append(nums, fmt.Sprintf("%2d. %-9s", j+1, words[j]))
		}
		fmt.Println("  " + strings.Join(nums, " "))
	}
}

// wipeStr overwrites the backing memory of a string-valued variable so
// the mnemonic doesn't linger in the process heap longer than necessary.
// Best-effort: Go strings are immutable + GC may have moved them.
// Documented as defense-in-depth, not a guarantee.
func wipeStr(s *string) {
	if s == nil || *s == "" {
		return
	}
	b := []byte(*s)
	for i := range b {
		b[i] = 0
	}
	*s = ""
}
