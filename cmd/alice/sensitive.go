package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kaka-milan-22/AnB/internal/ca"
	"github.com/kaka-milan-22/AnB/internal/localvault"
	"github.com/kaka-milan-22/AnB/internal/pwgen"
	"github.com/kaka-milan-22/AnB/internal/redact"
	"github.com/kaka-milan-22/AnB/internal/term"
)

func nowStamp() string { return time.Now().UTC().Format(time.RFC3339) }

// set <key> — store a secret (human only). Value is encrypted by Bob.
func cmdSet(args []string) error {
	fs := newFS("set")
	dir := dirFlag(fs)
	desc := fs.String("desc", "", "description")
	fromEnv := fs.String("from-env", "", "read value from environment variable")
	stdin := fs.Bool("stdin", false, "read value from stdin pipe")
	force := fs.Bool("force", false, "overwrite without prompt (only with --stdin)")
	reqPresence := fs.Bool("require-presence", false, "gate decrypt behind Bob presence policy")
	reason := fs.String("reason", "", "presence reason (with --require-presence)")
	generate := fs.Bool("generate", false, "generate the value instead of entering it")
	genStyle := fs.String("style", "apple", "generator style with --generate: apple | full | passphrase | pin")
	var genLen int
	fs.IntVar(&genLen, "l", 0, "generator size with --generate (0 = style default)")
	fs.IntVar(&genLen, "length", 0, "alias for -l")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: alice set <key> [flags]")
	}
	key := pos[0]

	if *stdin {
		requireStdoutTTY("alice set")
	} else {
		requireTTY("alice set")
	}
	if !keyFormat.MatchString(key) {
		return fmt.Errorf("invalid key format (use lowercase alphanumeric + hyphens, e.g. my-api-key)")
	}
	if *reason != "" && !*reqPresence {
		return fmt.Errorf("--reason can only be used with --require-presence")
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
		if already && !confirmOverwrite(key, existing) {
			fmt.Println("Cancelled")
			return nil
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
		if already && !confirmOverwrite(key, existing) {
			fmt.Println("Cancelled")
			return nil
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
		if already && !confirmOverwrite(key, existing) {
			fmt.Println("Cancelled")
			return nil
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
	if *reqPresence {
		entry.RequirePresence = true
		entry.PresenceReason = *reason
	}
	v.Set(key, entry)
	if err := s.Save(v); err != nil {
		return err
	}
	gate := ""
	if *reqPresence {
		gate = " (presence-gated)"
	}
	if *generate {
		gate += fmt.Sprintf(" [generated: %s]", *genStyle)
	}
	fmt.Printf("✓ Saved %q%s\n", key, gate)
	return nil
}

func confirmOverwrite(key string, e localvault.SecretEntry) bool {
	gate := ""
	if e.RequirePresence {
		gate = " [presence]"
	}
	fmt.Fprintf(os.Stderr, "⚠ %q%s already exists (set %s)\n", key, gate, e.CreatedAt)
	ok, _ := term.Confirm("Overwrite?", false)
	return ok
}

// get <key> [--reveal] — metadata, or the value (human only, stdout TTY).
func cmdGet(args []string) error {
	fs := newFS("get")
	dir := dirFlag(fs)
	reveal := fs.Bool("reveal", false, "show the actual secret value")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: alice get <key> [--reveal]")
	}
	requireTTY("alice get")
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
		pt, err := cl.Decrypt(key, e.Value, e.RequirePresence)
		if err != nil {
			return err
		}
		fmt.Println(pt)
		return nil
	}
	fmt.Printf("Key:      %s\n", key)
	if e.Desc != "" {
		fmt.Printf("Desc:     %s\n", e.Desc)
	}
	fmt.Printf("Set at:   %s\n", e.CreatedAt)
	if e.RequirePresence {
		fmt.Println("Presence: required (Bob policy)")
		if e.PresenceReason != "" {
			fmt.Printf("Reason:   %s\n", e.PresenceReason)
		}
	}
	return nil
}

// rm <key> — remove a secret (human only).
func cmdRm(args []string) error {
	fs := newFS("rm")
	dir := dirFlag(fs)
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: alice rm <key>")
	}
	requireTTY("alice rm")
	key := pos[0]
	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}
	if !v.Has(key) {
		return fmt.Errorf("secret %q not found", key)
	}
	if ok, _ := term.Confirm(fmt.Sprintf("Remove %q?", key), false); !ok {
		fmt.Println("Cancelled")
		return nil
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
	requireTTY("alice init")
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

// require-presence <key> --on|--off — toggle presence policy on a key.
func cmdRequirePresence(args []string) error {
	fs := newFS("require-presence")
	dir := dirFlag(fs)
	on := fs.Bool("on", false, "enable the gate")
	off := fs.Bool("off", false, "disable the gate")
	reason := fs.String("reason", "", "presence reason (with --on)")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: alice require-presence <key> --on|--off")
	}
	requireTTY("alice require-presence")
	if *on == *off {
		return fmt.Errorf("specify exactly one of --on or --off")
	}
	if *reason != "" && *off {
		return fmt.Errorf("--reason is only meaningful with --on")
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
	if e.RequirePresence == *on {
		fmt.Printf("%q already %s presence; nothing to do.\n", key, ternary(*on, "requires", "does not require"))
		return nil
	}
	e.RequirePresence = *on
	if *on {
		e.PresenceReason = *reason
	} else {
		e.PresenceReason = ""
	}
	v.Set(key, e)
	if err := s.Save(v); err != nil {
		return err
	}
	fmt.Printf("✓ %q %s\n", key, ternary(*on, "now requires presence", "no longer requires presence"))
	return nil
}

// import <file> — bulk-import a .env file (human only).
func cmdImport(args []string) error {
	fs := newFS("import")
	dir := dirFlag(fs)
	minLen := fs.Int("min-length", 8, "minimum value length to import")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: alice import <file>")
	}
	requireTTY("alice import")
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
	if ok, _ := term.Confirm(fmt.Sprintf("Import %d secret%s?", len(toImport), plural(len(toImport))), true); !ok {
		fmt.Println("Cancelled")
		return nil
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
	requireTTY("alice scan")
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
	fmt.Printf("✓ Enrolled as %q. CSR written to %s\n", *identity, s.CSRPath())
	fmt.Println("  Next: have the Bob operator run `bob sign-csr client.csr`, then `alice install-cert <client.crt>`")
	return nil
}

// install-cert <client.crt> — install the signed client certificate.
func cmdInstallCert(args []string) error {
	fs := newFS("install-cert")
	dir := dirFlag(fs)
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: alice install-cert <client.crt>")
	}
	certPEM, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	s := localvault.Open(*dir)
	if err := s.WriteFile("client.crt", certPEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("✓ Installed client cert at %s\n", s.ClientCertPath())
	return nil
}

func ternary(b bool, a, c string) string {
	if b {
		return a
	}
	return c
}

func hostOnly(addr string) string {
	if i := strings.LastIndexByte(addr, ':'); i > 0 {
		return addr[:i]
	}
	return addr
}
