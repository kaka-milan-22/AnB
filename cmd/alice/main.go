// Command alice is AnB's client CLI — the agent-facing tool. It keeps only
// ciphertext locally, runs the redaction engine, and asks Bob (over mTLS) to
// encrypt/decrypt. Command surface mirrors agent-vault 0.5, including the
// safe/sensitive TTY split that structurally keeps agents out of plaintext.
//
//	safe (agent + human):     read  write  has  list  status
//	sensitive (human, TTY):   set  get  rm  import  init  scan  require-presence
//	setup:                    enroll  install-cert
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/kaka-milan-22/AnB/internal/client"
	"github.com/kaka-milan-22/AnB/internal/localvault"
	"github.com/kaka-milan-22/AnB/internal/term"
)

var (
	keyFormat = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	envKeyRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmds := map[string]func([]string) error{
		"read": cmdRead, "write": cmdWrite, "has": cmdHas, "list": cmdList, "status": cmdStatus,
		"set": cmdSet, "get": cmdGet, "rm": cmdRm, "import": cmdImport,
		"init": cmdInit, "scan": cmdScan, "require-presence": cmdRequirePresence,
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
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `alice — AnB client
  safe:       read <file> | write <file> [--content C] | has <keys...> | list | status
  sensitive:  set <key> | get <key> [--reveal] | rm <key> | import <file> | init | scan <file>
              require-presence <key> --on|--off [--reason R]
  setup:      enroll --identity N --bob HOST:PORT --server-name SAN --ca ca.crt
              install-cert <client.crt>
common flag:  --dir DIR  (default ~/.anb/alice or $ANB_ALICE_DIR)
`)
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
	gated := false
	for k, e := range v.Secrets {
		keys = append(keys, k)
		packed = append(packed, e.Value)
		if e.RequirePresence {
			gated = true
		}
	}
	cl, _, err := loadClient(s)
	if err != nil {
		return nil, err
	}
	pts, err := cl.DecryptMany(keys, packed, gated)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(keys))
	for i := range keys {
		m[pts[i]] = keys[i]
	}
	return m, nil
}
