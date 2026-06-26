package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/kaka-milan-22/AnB/v3/internal/localvault"
	"github.com/kaka-milan-22/AnB/v3/internal/redact"
	"github.com/kaka-milan-22/AnB/v3/internal/strength"
)

var unvaultedMarker = regexp.MustCompile(`<agent-vault:UNVAULTED:sha256:[a-f0-9]{8,16}>`)

// read <file> — print the file with secrets redacted (safe for agents).
func cmdRead(args []string) error {
	fs := newFS("read")
	dir := dirFlag(fs)
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: alice read <file>")
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
	printCatN(redact.Redact(string(raw), vals), string(raw))
	return nil
}

// redact — stdin redaction filter (safe for agents). Reads stdin, replaces
// known secret values and high-entropy unvaulted tokens with <agent-vault:key>
// placeholders, and writes the redacted result to stdout. Same engine as
// `read`, but stream-oriented: lets a caller (e.g. the AnB-MCP server) scrub
// captured command output without ever writing the plaintext to disk. Never
// reveals a value.
func cmdRedact(args []string) error {
	fs := newFS("redact")
	dir := dirFlag(fs)
	parse(fs, args)
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	s := localvault.Open(*dir)
	vals := map[string]string{}
	if s.VaultExists() {
		if vals, err = decryptAllValues(s); err != nil {
			return err
		}
	}
	fmt.Print(redact.Redact(string(raw), vals))
	return nil
}

func printCatN(redacted, raw string) {
	lines := strings.Split(redacted, "\n")
	if strings.HasSuffix(raw, "\n") && len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	width := len(strconv.Itoa(len(lines)))
	if width < 6 {
		width = 6
	}
	for i, l := range lines {
		fmt.Printf("%*d\t%s\n", width, i+1, l)
	}
}

// write <file> — restore <agent-vault:key> placeholders (safe for agents).
func cmdWrite(args []string) error {
	fs := newFS("write")
	dir := dirFlag(fs)
	contentFlag := fs.String("content", "", "file content with <agent-vault:key> placeholders")
	quiet := fs.Bool("quiet", false, "suppress status lines on stderr; restored content still goes to stdout/target")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: alice write <file> [--content C]")
	}
	filePath := pos[0]

	var content string
	if isSet(fs, "content") {
		content = *contentFlag
	} else {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		content = string(b)
	}

	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}

	// Resolve referenced placeholders via Bob in a single batch.
	var keys, packed []string
	for _, k := range redact.ExtractPlaceholders(content) {
		if e, ok := v.Get(k); ok {
			keys = append(keys, k)
			packed = append(packed, e.Value)
		}
	}
	resolved := map[string]string{}
	if len(packed) > 0 {
		cl, _, err := loadClient(s)
		if err != nil {
			return err
		}
		pts, rewraps, err := cl.DecryptMany(keys, packed)
		if err != nil {
			return err
		}
		if _, werr := applyRewraps(s, keys, rewraps); werr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to write back rewrapped entries: %v\n", werr)
		}
		for i := range keys {
			resolved[keys[i]] = pts[i]
		}
	}

	res := redact.Restore(content, func(k string) (string, bool) { v, ok := resolved[k]; return v, ok })
	if len(res.Missing) > 0 {
		fmt.Fprintf(os.Stderr, "✗ Secret %q not found in vault\n  Add it: alice set %s\n", res.Missing[0], res.Missing[0])
		for _, k := range res.Missing[1:] {
			fmt.Fprintf(os.Stderr, "  Also missing: %q → alice set %s\n", k, k)
		}
		os.Exit(1)
	}

	final := res.Content
	unvaultedCount := 0
	if unvaultedMarker.MatchString(final) {
		existing, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("content has UNVAULTED placeholders but %s does not exist yet; vault those secrets first", filePath)
		}
		var unmatched []string
		final, unvaultedCount, unmatched = redact.RestoreUnvaulted(final, string(existing))
		if len(unmatched) > 0 {
			return fmt.Errorf("could not restore %d UNVAULTED placeholder(s) — no matching value in existing file", len(unmatched))
		}
	}

	if err := os.WriteFile(filePath, []byte(final), 0o644); err != nil {
		return err
	}
	count := len(res.Restored) + unvaultedCount
	if !*quiet {
		fmt.Fprintf(os.Stderr, "✓ Written %s (%d secret%s restored)\n", filePath, count, plural(count))
		if unvaultedCount > 0 {
			fmt.Fprintf(os.Stderr, "⚠ %d unvaulted secret(s) restored from existing file — consider: alice import\n", unvaultedCount)
		}
	}
	return nil
}

// has <keys...> — check existence (local metadata, never touches Bob).
func cmdHas(args []string) error {
	fs := newFS("has")
	dir := dirFlag(fs)
	asJSON := fs.Bool("json", false, "output as JSON")
	pos := parse(fs, args)
	if len(pos) == 0 {
		return fmt.Errorf("usage: alice has <keys...>")
	}
	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}
	if *asJSON {
		res := map[string]bool{}
		all := true
		for _, k := range pos {
			res[k] = v.Has(k)
			all = all && res[k]
		}
		b, _ := json.Marshal(res)
		fmt.Println(string(b))
		if !all {
			os.Exit(1)
		}
		return nil
	}
	all := true
	for _, k := range pos {
		ok := v.Has(k)
		if len(pos) > 1 {
			fmt.Printf("%s: %t\n", k, ok)
		} else {
			fmt.Println(ok)
		}
		all = all && ok
	}
	if !all {
		os.Exit(1)
	}
	return nil
}

// list — list key names (local metadata). -l/--long adds the stored
// per-entry metadata columns (length, strength, master-key version) without decrypting.
func cmdList(args []string) error {
	fs := newFS("list")
	dir := dirFlag(fs)
	asJSON := fs.Bool("json", false, "output as JSON")
	var long bool
	fs.BoolVar(&long, "l", false, "long format: show length, strength, and master-key version columns")
	fs.BoolVar(&long, "long", false, "alias for -l")
	pos := parse(fs, args)
	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}
	listing := v.List()
	// Optional shell-style glob filter: `alice list 'test-*'`.
	if len(pos) > 0 {
		var f []localvault.Listing
		for _, l := range listing {
			if ok, merr := filepath.Match(pos[0], l.Key); merr == nil && ok {
				f = append(f, l)
			}
		}
		listing = f
	}
	if *asJSON {
		b, _ := json.MarshalIndent(map[string]any{"keys": listing}, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	if !long {
		for _, l := range listing {
			fmt.Println(l.Key)
		}
		return nil
	}
	// Long format. Metadata shows "—" for entries predating it (run
	// `alice backfill-meta` to populate them).
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "KEY\tLENGTH\tSTRENGTH\tMK\tDESC")
	for _, l := range listing {
		length, strg, mkver := "—", "—", "—"
		if l.LenBytes != 0 {
			length = fmt.Sprintf("%d", l.LenBytes)
		}
		if l.EntropyBits != 0 {
			strg = fmt.Sprintf("~%d (%s)", l.EntropyBits, strength.Tier(l.EntropyBits))
		}
		if l.KeyEpoch != 0 {
			mkver = fmt.Sprintf("v%d", l.KeyEpoch) // master-key version (v<N> prefix), not the envelope KEK
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", l.Key, length, strg, mkver, l.Desc)
	}
	return tw.Flush()
}

// status — enrollment + Bob reachability/unlock state.
func cmdStatus(args []string) error {
	fs := newFS("status")
	dir := dirFlag(fs)
	asJSON := fs.Bool("json", false, "output as JSON")
	parse(fs, args)
	s := localvault.Open(*dir)

	if *asJSON {
		b, _ := json.MarshalIndent(gatherStatus(s), "", "  ")
		fmt.Println(string(b))
		return nil
	}

	cfg, err := s.LoadConfig()
	if err != nil {
		fmt.Println("Enrolled: no (run `alice enroll`)")
		return nil
	}
	fmt.Printf("Identity:   %s\n", cfg.Identity)
	fmt.Printf("Bob:        %s (server-name %s)\n", cfg.BobAddr, cfg.ServerName)
	if _, e := os.Stat(s.ClientCertPath()); e != nil {
		fmt.Println("Client cert: missing (have Bob sign the CSR, then `alice install-cert`)")
		return nil
	}
	cl, _, err := loadClient(s)
	if err != nil {
		fmt.Printf("Bob status: error — %v\n", err)
		return nil
	}
	unlocked, ttl, err := cl.Status()
	if err != nil {
		fmt.Printf("Bob status: unreachable — %v\n", err)
		return nil
	}
	if unlocked {
		if ttl > 0 {
			fmt.Printf("Bob status: unlocked (idle TTL %ds)\n", ttl)
		} else {
			fmt.Println("Bob status: unlocked")
		}
	} else {
		fmt.Println("Bob status: locked")
	}
	return nil
}

// statusInfo is the structured form of `alice status`, emitted by --json.
type statusInfo struct {
	Enrolled     bool   `json:"enrolled"`
	Identity     string `json:"identity,omitempty"`
	BobAddr      string `json:"bob_addr,omitempty"`
	ServerName   string `json:"server_name,omitempty"`
	ClientCert   bool   `json:"client_cert"`
	BobReachable bool   `json:"bob_reachable"`
	BobUnlocked  bool   `json:"bob_unlocked"`
	IdleTTLSec   int    `json:"idle_ttl_seconds,omitempty"`
	Error        string `json:"error,omitempty"`
}

// gatherStatus collects the same state cmdStatus prints, into a struct for the
// --json path. Mirrors the text path's staged early-returns so json and text
// report the same thing at every stage (not enrolled / no cert / unreachable).
func gatherStatus(s *localvault.Store) statusInfo {
	var info statusInfo
	cfg, err := s.LoadConfig()
	if err != nil {
		return info // enrolled=false
	}
	info.Enrolled = true
	info.Identity = cfg.Identity
	info.BobAddr = cfg.BobAddr
	info.ServerName = cfg.ServerName
	if _, e := os.Stat(s.ClientCertPath()); e != nil {
		return info // client_cert=false
	}
	info.ClientCert = true
	cl, _, err := loadClient(s)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	unlocked, ttl, err := cl.Status()
	if err != nil {
		info.Error = err.Error()
		return info // bob_reachable=false
	}
	info.BobReachable = true
	info.BobUnlocked = unlocked
	if unlocked && ttl > 0 {
		info.IdleTTLSec = int(ttl)
	}
	return info
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func isSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
