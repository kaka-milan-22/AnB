package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kaka-milan-22/AnB/v3/internal/ca"
	"github.com/kaka-milan-22/AnB/v3/internal/localvault"
	"github.com/kaka-milan-22/AnB/v3/internal/pwgen"
	"github.com/kaka-milan-22/AnB/v3/internal/redact"
	"github.com/kaka-milan-22/AnB/v3/internal/term"
)

func nowStamp() string { return time.Now().UTC().Format(time.RFC3339) }

// set <key> — store a secret (human only). Value is encrypted by Bob.
func cmdSet(args []string) error {
	fs := newFS("set")
	dir := dirFlag(fs)
	desc := fs.String("desc", "", "description")
	fromEnv := fs.String("from-env", "", "read value from environment variable")
	stdin := fs.Bool("stdin", false, "read value from stdin pipe")
	force := fs.Bool("force", false, "overwrite an existing key without the confirm prompt")
	generate := fs.Bool("generate", false, "generate the value instead of entering it")
	genStyle := fs.String("style", "apple", "generator style with --generate: apple | full | passphrase | pin | aes256")
	var genLen int
	fs.IntVar(&genLen, "l", 0, "generator size with --generate (0 = style default)")
	fs.IntVar(&genLen, "length", 0, "alias for -l")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: alice set <key> [flags]")
	}
	key := pos[0]

	// --stdin reads the value from a pipe; stdout only carries the "✓ Saved"
	// confirmation, NOT the secret. No TTY required — scripts and CI can
	// drive `alice set --stdin --force <key>` programmatically. Other paths
	// (interactive prompt, --generate, --from-env) still need a full TTY
	// either to read the value (prompt) or to handle the overwrite confirm.
	// Non-interactive callers (agents/CI) need an explicit value source — we
	// can't prompt without a TTY. Authorization is still enforced by Bob's
	// encrypt authz; overwrites need --force when there's no TTY to confirm.
	if !term.StdinIsTTY() && !*stdin && !*generate && *fromEnv == "" {
		return fmt.Errorf("non-interactive: provide a value via --from-env, --stdin, or --generate")
	}
	if !keyFormat.MatchString(key) {
		return fmt.Errorf("invalid key format (use lowercase alphanumeric + hyphens, e.g. my-api-key)")
	}
	if *generate && (*fromEnv != "" || *stdin) {
		return fmt.Errorf("--generate cannot be combined with --from-env or --stdin")
	}

	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}
	existing, already := v.Get(key)

	var value string
	switch {
	case *generate:
		if already {
			ok, oerr := confirmOverwrite(key, existing, *force)
			if oerr != nil {
				return oerr
			}
			if !ok {
				fmt.Println("Cancelled")
				return nil
			}
		}
		gen, gerr := pwgen.Generate(pwgen.Style(*genStyle), genLen)
		if gerr != nil {
			return gerr
		}
		value = gen
	case *fromEnv != "":
		value = os.Getenv(*fromEnv)
		if value == "" {
			return fmt.Errorf("environment variable $%s is not set or empty", *fromEnv)
		}
		if already {
			ok, oerr := confirmOverwrite(key, existing, *force)
			if oerr != nil {
				return oerr
			}
			if !ok {
				fmt.Println("Cancelled")
				return nil
			}
		}
	case *stdin:
		if already && !*force {
			return fmt.Errorf("refusing to overwrite %q via --stdin without --force", key)
		}
		b, _ := io.ReadAll(os.Stdin)
		value = strings.TrimSpace(string(b))
		if value == "" {
			return fmt.Errorf("no input received from stdin")
		}
	default:
		if already {
			ok, oerr := confirmOverwrite(key, existing, *force)
			if oerr != nil {
				return oerr
			}
			if !ok {
				fmt.Println("Cancelled")
				return nil
			}
		}
		if value, err = term.ReadPassword(fmt.Sprintf("Enter value for %q: ", key)); err != nil {
			return err
		}
		if value == "" {
			return fmt.Errorf("empty value, nothing saved")
		}
	}

	cl, _, err := loadClient(s)
	if err != nil {
		return err
	}
	packed, err := cl.Encrypt(key, value)
	if err != nil {
		return err
	}
	entry := localvault.SecretEntry{Value: packed, CreatedAt: nowStamp(), Desc: *desc}
	v.Set(key, entry)
	if err := s.Save(v); err != nil {
		return err
	}
	suffix := ""
	if *generate {
		suffix = fmt.Sprintf(" [generated: %s]", *genStyle)
	}
	fmt.Printf("✓ Saved %q%s\n", key, suffix)
	return nil
}

// confirmOverwrite decides whether to overwrite an existing key. --force skips
// the prompt; without a TTY and without --force it refuses (rather than
// silently cancelling) so non-interactive callers get a clear error.
func confirmOverwrite(key string, e localvault.SecretEntry, force bool) (bool, error) {
	if force {
		return true, nil
	}
	if !term.StdinIsTTY() {
		return false, fmt.Errorf("%q already exists; pass --force to overwrite non-interactively", key)
	}
	fmt.Fprintf(os.Stderr, "⚠ %q already exists (set %s)\n", key, e.CreatedAt)
	ok, _ := term.Confirm("Overwrite?", false)
	return ok, nil
}

// get <key> [--reveal] [--reason "..."] — metadata, or the value (human only,
// stdout TTY). --reason is logged in Bob's ALLOW audit line; audit-only, not
// authorized on.
func cmdGet(args []string) error {
	fs := newFS("get")
	dir := dirFlag(fs)
	reveal := fs.Bool("reveal", false, "show the actual secret value")
	reason := fs.String("reason", "", `audit-only "why" string; logged in Bob's ALLOW line`)
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: alice get <key> [--reveal] [--reason R]")
	}
	key := pos[0]
	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}
	e, ok := v.Get(key)
	if !ok {
		return fmt.Errorf("secret %q not found", key)
	}
	if *reveal {
		requireStdoutTTY("alice get --reveal")
		cl, _, err := loadClient(s)
		if err != nil {
			return err
		}
		cl.SetReason(*reason)
		pt, rewrapped, err := cl.Decrypt(key, e.Value)
		if err != nil {
			return err
		}
		if rewrapped != "" {
			if _, werr := applyRewraps(s, []string{key}, []string{rewrapped}); werr != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to write back rewrapped entry %q: %v\n", key, werr)
			}
		}
		fmt.Println(pt)
		return nil
	}
	fmt.Printf("Key:      %s\n", key)
	if e.Desc != "" {
		fmt.Printf("Desc:     %s\n", e.Desc)
	}
	fmt.Printf("Set at:   %s\n", e.CreatedAt)
	return nil
}

// rm <key> — remove a secret (human only).
func cmdRm(args []string) error {
	fs := newFS("rm")
	dir := dirFlag(fs)
	yes := fs.Bool("yes", false, "skip the confirm prompt (required when non-interactive)")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: alice rm <key> [--yes]")
	}
	key := pos[0]
	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}
	if !v.Has(key) {
		return fmt.Errorf("secret %q not found", key)
	}
	if !*yes {
		if !term.StdinIsTTY() {
			return fmt.Errorf("refusing to remove %q non-interactively without --yes", key)
		}
		if ok, _ := term.Confirm(fmt.Sprintf("Remove %q?", key), false); !ok {
			fmt.Println("Cancelled")
			return nil
		}
	}
	v.Remove(key)
	if err := s.Save(v); err != nil {
		return err
	}
	fmt.Printf("✓ Removed %q\n", key)
	return nil
}

// init — initialize an empty local vault (human only).
func cmdInit(args []string) error {
	fs := newFS("init")
	dir := dirFlag(fs)
	parse(fs, args)
	s := localvault.Open(*dir)
	if s.VaultExists() {
		fmt.Printf("Vault already exists at %s\n", s.VaultPath())
		return nil
	}
	v, _ := s.Load()
	if err := s.Save(v); err != nil {
		return err
	}
	fmt.Printf("✓ Initialized vault at %s\n", s.VaultPath())
	return nil
}

// import <file> — bulk-import a .env file (human only).
func cmdImport(args []string) error {
	fs := newFS("import")
	dir := dirFlag(fs)
	minLen := fs.Int("min-length", 8, "minimum value length to import")
	yes := fs.Bool("yes", false, "skip the confirm prompt (required when non-interactive)")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: alice import <file> [--yes]")
	}
	raw, err := os.ReadFile(pos[0])
	if err != nil {
		return fmt.Errorf("file not found: %s", pos[0])
	}
	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}

	type cand struct{ envKey, vaultKey, value, skip string }
	common := map[string]bool{"true": true, "false": true, "null": true, "undefined": true,
		"localhost": true, "0.0.0.0": true, "127.0.0.1": true, "development": true,
		"production": true, "staging": true, "test": true}
	var cands []cand
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		eq := strings.IndexByte(t, '=')
		if eq <= 0 {
			continue
		}
		envKey := strings.TrimSpace(t[:eq])
		if !envKeyRE.MatchString(envKey) {
			continue
		}
		value := strings.Trim(strings.TrimSpace(t[eq+1:]), `"'`)
		vaultKey := strings.ToLower(strings.ReplaceAll(envKey, "_", "-"))
		c := cand{envKey: envKey, vaultKey: vaultKey, value: value}
		switch {
		case len(value) < *minLen:
			c.skip = fmt.Sprintf("too short (%d chars)", len(value))
		case common[strings.ToLower(value)]:
			c.skip = "common value"
		}
		cands = append(cands, c)
	}
	var toImport []cand
	for _, c := range cands {
		if c.skip == "" {
			toImport = append(toImport, c)
		}
	}
	if len(cands) == 0 {
		fmt.Println("No entries found in file")
		return nil
	}
	fmt.Printf("Found %d entries:\n", len(cands))
	for _, c := range cands {
		if c.skip != "" {
			fmt.Printf("  %s → (skip: %s)\n", c.envKey, c.skip)
		} else {
			ow := ""
			if v.Has(c.vaultKey) {
				ow = " (overwrite)"
			}
			fmt.Printf("  %s → %s%s\n", c.envKey, c.vaultKey, ow)
		}
	}
	if len(toImport) == 0 {
		fmt.Println("Nothing to import (all entries skipped)")
		return nil
	}
	if !*yes {
		if !term.StdinIsTTY() {
			return fmt.Errorf("refusing to import %d secret(s) non-interactively without --yes", len(toImport))
		}
		if ok, _ := term.Confirm(fmt.Sprintf("Import %d secret%s?", len(toImport), plural(len(toImport))), true); !ok {
			fmt.Println("Cancelled")
			return nil
		}
	}
	cl, _, err := loadClient(s)
	if err != nil {
		return err
	}
	for _, c := range toImport {
		packed, err := cl.Encrypt(c.vaultKey, c.value)
		if err != nil {
			return err
		}
		v.Set(c.vaultKey, localvault.SecretEntry{Value: packed, CreatedAt: nowStamp()})
	}
	if err := s.Save(v); err != nil {
		return err
	}
	fmt.Printf("✓ Imported %d secret%s\n", len(toImport), plural(len(toImport)))
	return nil
}

// scan <file> — audit a file for vaulted + unvaulted-suspect secrets (human).
func cmdScan(args []string) error {
	fs := newFS("scan")
	dir := dirFlag(fs)
	asJSON := fs.Bool("json", false, "output as JSON")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: alice scan <file>")
	}
	raw, err := os.ReadFile(pos[0])
	if err != nil {
		return fmt.Errorf("file not found: %s", pos[0])
	}
	s := localvault.Open(*dir)
	vals := map[string]string{}
	if s.VaultExists() {
		if vals, err = decryptAllValues(s); err != nil {
			return err
		}
	}
	lines := strings.Split(string(raw), "\n")
	type hit struct {
		Line int    `json:"line"`
		Key  string `json:"key"`
	}
	var vaulted, suspects []hit
	for i, line := range lines {
		for val, key := range vals {
			if val != "" && strings.Contains(line, val) {
				vaulted = append(vaulted, hit{i + 1, key})
			}
		}
	}
	for i, line := range strings.Split(redact.Redact(string(raw), vals), "\n") {
		for _, m := range unvaultedMarker.FindAllString(line, -1) {
			suspects = append(suspects, hit{i + 1, strings.TrimSuffix(strings.TrimPrefix(m, "<agent-vault:"), ">")})
		}
	}
	if *asJSON {
		b, _ := json.MarshalIndent(map[string]any{"file": pos[0], "vaulted": vaulted, "unvaulted_suspects": suspects}, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Printf("Vaulted (%d):\n", len(vaulted))
	if len(vaulted) == 0 {
		fmt.Println("  (none)")
	}
	for _, h := range vaulted {
		fmt.Printf("  line %d: matches %q\n", h.Line, h.Key)
	}
	fmt.Printf("Unvaulted suspects (%d):\n", len(suspects))
	if len(suspects) == 0 {
		fmt.Println("  (none)")
	}
	for _, h := range suspects {
		fmt.Printf("  line %d: %s\n  → Run: alice set <key-name>\n", h.Line, h.Key)
	}
	return nil
}

// enroll — generate a keypair + CSR, install the CA trust anchor, save config.
func cmdEnroll(args []string) error {
	fs := newFS("enroll")
	dir := dirFlag(fs)
	identity := fs.String("identity", "", "client identity (cert CommonName)")
	bob := fs.String("bob", "", "Bob address host:port")
	serverName := fs.String("server-name", "", "SAN to verify on Bob's server cert")
	caPath := fs.String("ca", "", "path to Bob's ca.crt (trust anchor)")
	parse(fs, args)
	if *identity == "" || *bob == "" || *caPath == "" {
		return fmt.Errorf("usage: alice enroll --identity NAME --bob HOST:PORT --ca ca.crt [--server-name SAN]")
	}
	sn := *serverName
	if sn == "" {
		sn = hostOnly(*bob)
	}
	caPEM, err := os.ReadFile(*caPath)
	if err != nil {
		return fmt.Errorf("reading CA: %w", err)
	}
	csrPEM, keyPEM, err := ca.GenerateCSR(*identity)
	if err != nil {
		return err
	}
	s := localvault.Open(*dir)
	if err := s.WriteFile("client.key", keyPEM, 0o600); err != nil {
		return err
	}
	if err := s.WriteFile("client.csr", csrPEM, 0o644); err != nil {
		return err
	}
	if err := s.WriteFile("ca.crt", caPEM, 0o644); err != nil {
		return err
	}
	if err := s.SaveConfig(&localvault.Config{BobAddr: *bob, ServerName: sn, Identity: *identity}); err != nil {
		return err
	}
	// v3.0+: scaffold exec-allowlist.rules so the first alice exec call gets a
	// "not in allowlist" deny (with TTY bless-prompt) rather than a
	// "file not found" error. Idempotent: never clobbers an existing file.
	if err := scaffoldRulesFile(s.Dir); err != nil {
		return err
	}
	fmt.Printf("✓ Enrolled as %q. CSR written to %s\n", *identity, s.CSRPath())
	fmt.Println("  Next: have the Bob operator run `bob sign-csr client.csr`, then `alice install-cert <client.crt>`")
	return nil
}

// scaffoldRulesFile creates exec-allowlist.rules with a header comment
// if absent. Idempotent — never overwrites an existing file.
func scaffoldRulesFile(dir string) error {
	path := filepath.Join(dir, "exec-allowlist.rules")
	if _, err := os.Stat(path); err == nil {
		return nil // already exists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	header := `# AnB exec-allowlist rules.
# One rule per line: <regex>\t<env-csv>\t#<label>.
# Implicit ^...$ anchor.
# Default deny: unmatched invocations are rejected (TTY callers see
# an auto-bless prompt; non-TTY callers hard-deny).
# Run 'alice exec --show-match-string -- cmd args...' to see exactly
# what string your regex needs to match.

`
	return os.WriteFile(path, []byte(header), 0o600)
}

// install-cert <client.crt> — install the signed client certificate, after
// verifying the OOB pairing code embedded in the cert (unless --no-pair).
func cmdInstallCert(args []string) error {
	fs := newFS("install-cert")
	dir := dirFlag(fs)
	noPair := fs.Bool("no-pair", false, "accept certs without a pairing extension (skip OOB code check)")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: alice install-cert <client.crt> [--no-pair]")
	}
	certPEM, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}

	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return fmt.Errorf("not a PEM certificate: %s", pos[0])
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}
	fp := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	fmt.Fprintf(os.Stderr, "→ Cert identity:  %s\n", cert.Subject.CommonName)
	fmt.Fprintf(os.Stderr, "→ Cert pubkey fp: %s\n", hex.EncodeToString(fp[:]))

	if *noPair {
		fmt.Fprintf(os.Stderr, "⚠ --no-pair: skipping OOB code check\n")
	} else {
		code, err := readPairingCode()
		if err != nil {
			return err
		}
		switch err := ca.VerifyPairing(cert, code, time.Now()); {
		case err == nil:
			fmt.Fprintf(os.Stderr, "✓ pairing verified\n")
		case errors.Is(err, ca.ErrPairingAbsent):
			return fmt.Errorf("cert was signed without pairing — re-run with --no-pair to accept, or ask Bob to re-sign with pairing")
		case errors.Is(err, ca.ErrPairingExpired):
			return fmt.Errorf("pairing code expired — ask Bob to re-sign the CSR (a fresh code resets the 10-minute window)")
		case errors.Is(err, ca.ErrPairingMismatch):
			return fmt.Errorf("pairing code did not match — re-run install-cert with the correct code")
		default:
			return fmt.Errorf("pairing verify: %w", err)
		}
	}

	s := localvault.Open(*dir)
	if err := s.WriteFile("client.crt", certPEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("✓ Installed client cert at %s\n", s.ClientCertPath())
	return nil
}

// readPairingCode reads the 8-digit code from $ANB_PAIR_CODE if set,
// otherwise prompts on the TTY. Validates 8 ASCII digits in either case.
func readPairingCode() (string, error) {
	if v := os.Getenv("ANB_PAIR_CODE"); v != "" {
		if err := validatePairingCode(v); err != nil {
			return "", fmt.Errorf("ANB_PAIR_CODE: %w", err)
		}
		return v, nil
	}
	v, err := term.ReadLine("Enter the 8-digit pairing code: ")
	if err != nil {
		return "", err
	}
	if err := validatePairingCode(v); err != nil {
		return "", err
	}
	return v, nil
}

func validatePairingCode(s string) error {
	if len(s) != 8 {
		return fmt.Errorf("pairing code must be 8 digits (got %d chars)", len(s))
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return fmt.Errorf("pairing code must be digits only")
		}
	}
	return nil
}

func hostOnly(addr string) string {
	if i := strings.LastIndexByte(addr, ':'); i > 0 {
		return addr[:i]
	}
	return addr
}
