package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/kaka-milan-22/AnB/internal/localvault"
	"github.com/kaka-milan-22/AnB/internal/redact"
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
		pts, err := cl.DecryptMany(keys, packed)
		if err != nil {
			return err
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
	fmt.Printf("✓ Written %s (%d secret%s restored)\n", filePath, count, plural(count))
	if unvaultedCount > 0 {
		fmt.Fprintf(os.Stderr, "⚠ %d unvaulted secret(s) restored from existing file — consider: alice import\n", unvaultedCount)
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

// list — list key names (local metadata).
func cmdList(args []string) error {
	fs := newFS("list")
	dir := dirFlag(fs)
	asJSON := fs.Bool("json", false, "output as JSON")
	parse(fs, args)
	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}
	listing := v.List()
	if *asJSON {
		b, _ := json.MarshalIndent(map[string]any{"keys": listing}, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	for _, l := range listing {
		fmt.Println(l.Key)
	}
	return nil
}

// status — enrollment + Bob reachability/unlock state.
func cmdStatus(args []string) error {
	fs := newFS("status")
	dir := dirFlag(fs)
	parse(fs, args)
	s := localvault.Open(*dir)

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
