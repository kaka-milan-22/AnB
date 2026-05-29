// Command alice is AnB's client CLI — the agent-facing tool. It keeps only
// ciphertext locally, runs the redaction engine, and asks Bob (over mTLS) to
// encrypt/decrypt. Command surface mirrors agent-vault 0.5, including the
// safe/sensitive TTY split that structurally keeps agents out of plaintext.
//
//	safe (agent + human):     read  write  has  list  status  exec
//	sensitive (human, TTY):   set  get  rm  import  init  scan
//	setup:                    enroll  install-cert
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/kaka-milan-22/AnB/v2/internal/client"
	"github.com/kaka-milan-22/AnB/v2/internal/localvault"
	"github.com/kaka-milan-22/AnB/v2/internal/term"
	"github.com/kaka-milan-22/AnB/v2/internal/version"
)

var (
	keyFormat = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	envKeyRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "version", "--version", "-V":
		version.Print(os.Stdout, "alice")
		return
	}
	cmds := map[string]func([]string) error{
		"read": cmdRead, "write": cmdWrite, "has": cmdHas, "list": cmdList, "status": cmdStatus, "exec": cmdExec,
		"set": cmdSet, "get": cmdGet, "rm": cmdRm, "import": cmdImport, "gen": cmdGen,
		"init": cmdInit, "scan": cmdScan, "template": cmdTemplate, "shell": cmdShell,
		"enroll": cmdEnroll, "install-cert": cmdInstallCert,
	}
	fn, ok := cmds[os.Args[1]]
	if !ok {
		if os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
			usage()
		}
		fmt.Fprintf(os.Stderr, "alice: unknown command %q\n", os.Args[1])
		usage()
	}
	if err := fn(os.Args[2:]); err != nil {
		// errExecDenied: caller (cmdExec TTY-confirm path) already
		// printed the deny output before reading the prompt. Exit
		// non-zero silently — no second print.
		// "✓ " prefix: intentional non-zero exit with a success-marker
		// (alice exec auto-append asks the operator to re-run). Print
		// without the ✗ wrapping but keep the non-zero exit so script
		// chains do not proceed as if the child ran.
		switch {
		case errors.Is(err, errExecDenied):
			// silent
		case strings.HasPrefix(err.Error(), "✓ "):
			fmt.Fprintln(os.Stderr, err.Error())
		default:
			fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		}
		os.Exit(1)
	}
}

func usage() {
	const row = "  %-36s%s\n" // 2-space indent + aligned command column + description
	w := os.Stderr
	fmt.Fprint(w, "Usage: alice [options] <command>\n\n")
	fmt.Fprint(w, "Keep your secrets hidden from AI agents.\n")
	fmt.Fprint(w, "https://github.com/kaka-milan-22/AnB\n\n")

	fmt.Fprint(w, "Options:\n")
	fmt.Fprintf(w, row, "-h, --help", "display help for command")
	fmt.Fprintf(w, row, "-V, --version", "print version and exit")

	fmt.Fprint(w, "\nCommands:\n")
	fmt.Fprintf(w, row, "read <file>", "Read a file with secrets redacted (safe for agents)")
	fmt.Fprintf(w, row, "write [options] <file>", "Write a file, restoring <agent-vault:key> placeholders (safe for agents)")
	fmt.Fprintf(w, row, "has <keys...>", "Check if secrets exist in the vault (safe for agents)")
	fmt.Fprintf(w, row, "list [options]", "List all stored secret key names (safe for agents)")
	fmt.Fprintf(w, row, "status", "Show enrollment and Bob reachability/unlock state (safe for agents)")
	fmt.Fprintf(w, row, "exec [--env KEY=V]... -- <cmd>", "Resolve <agent-vault:k> in --env values, syscall.Exec the child (safe for agents)")
	fmt.Fprintf(w, row, "set [options] <key>", "Store a secret value, or --generate one (interactive, human only)")
	fmt.Fprintf(w, row, "get [options] <key>", "View secret metadata or value (human only)")
	fmt.Fprintf(w, row, "rm <key>", "Remove a secret from the vault (human only)")
	fmt.Fprintf(w, row, "import [options] <file>", "Import secrets from a .env file (human only)")
	fmt.Fprintf(w, row, "gen [options]", "Generate random passwords: --style apple|full|passphrase|pin (human only)")
	fmt.Fprintf(w, row, "init", "Initialize a new vault (human only)")
	fmt.Fprintf(w, row, "scan [options] <file>", "Audit a file for secrets (human only)")
	fmt.Fprintf(w, row, "template [opts] <src> <dst>", "Render <src>'s placeholders into <dst> with mode/owner (human only)")
	fmt.Fprintf(w, row, "shell [--env K=V]... [-- shell]", "Sub-shell with --env injected; TTY-only (human only)")
	fmt.Fprintf(w, row, "enroll [options]", "Generate a keypair + CSR, install the CA, save the profile (setup)")
	fmt.Fprintf(w, row, "install-cert <client.crt>", "Install the signed client certificate (setup)")

	fmt.Fprint(w, "\nCommon: --dir DIR   state dir (default ~/.anb/alice or $ANB_ALICE_DIR)\n")
	os.Exit(2)
}

// dirFlag registers --dir on fs and returns a pointer resolved at use time.
func dirFlag(fs *flag.FlagSet) *string { return fs.String("dir", "", "alice state dir") }

func newFS(name string) *flag.FlagSet { return flag.NewFlagSet(name, flag.ExitOnError) }

// parse handles flags interspersed with positionals (stdlib flag stops at the
// first non-flag arg). It repeatedly parses, collecting positionals in order,
// so `set api-key --from-env X` and `set --from-env X api-key` both work.
func parse(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		_ = fs.Parse(args)
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	return pos
}

// loadClient builds an mTLS client from Alice's enrolled state.
func loadClient(s *localvault.Store) (*client.Client, *localvault.Config, error) {
	cfg, err := s.LoadConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("not enrolled (no config.json) — run `alice enroll`")
	}
	cert, err := os.ReadFile(s.ClientCertPath())
	if err != nil {
		return nil, cfg, fmt.Errorf("no client cert — run `alice enroll`, have Bob sign the CSR, then `alice install-cert`")
	}
	key, err := os.ReadFile(s.ClientKeyPath())
	if err != nil {
		return nil, cfg, fmt.Errorf("no client key in %s — re-run `alice enroll`", s.Dir)
	}
	ca, err := os.ReadFile(s.CAPath())
	if err != nil {
		return nil, cfg, fmt.Errorf("no CA trust anchor (ca.crt) — provide it via `alice enroll --ca`")
	}
	cl, err := client.New(cfg.BobAddr, cfg.ServerName, cert, key, ca)
	if err != nil {
		return nil, cfg, err
	}
	return cl, cfg, nil
}

func requireTTY(cmd string) {
	if !term.StdinIsTTY() {
		fmt.Fprintf(os.Stderr, "✗ %q requires an interactive terminal (TTY).\n  It handles secret values and cannot be run programmatically.\n", cmd)
		os.Exit(1)
	}
}

func requireStdoutTTY(cmd string) {
	if !term.StdoutIsTTY() {
		fmt.Fprintf(os.Stderr, "✗ %q requires an interactive terminal (stdout TTY).\n  Cannot pipe or redirect secret values.\n", cmd)
		os.Exit(1)
	}
}

// decryptAllValues returns a map of plaintext→keyName for every secret, asking
// Bob to decrypt the whole batch in one round-trip. Empty if the vault is empty.
func decryptAllValues(s *localvault.Store) (map[string]string, error) {
	v, err := s.Load()
	if err != nil {
		return nil, err
	}
	if len(v.Secrets) == 0 {
		return map[string]string{}, nil
	}
	keys := make([]string, 0, len(v.Secrets))
	packed := make([]string, 0, len(v.Secrets))
	for k, e := range v.Secrets {
		keys = append(keys, k)
		packed = append(packed, e.Value)
	}
	cl, _, err := loadClient(s)
	if err != nil {
		return nil, err
	}
	pts, err := cl.DecryptMany(keys, packed)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(keys))
	for i := range keys {
		m[pts[i]] = keys[i]
	}
	return m, nil
}
