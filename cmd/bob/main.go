// Command bob is AnB's KMS daemon (operator-run).
//
//	bob ca init [--cn NAME] [--ttl-years N]      generate the private CA
//	bob init [--host h1,h2,...]                  create+wrap master key, mint server cert
//	bob sign-csr <csr.pem> [--out f] [--ttl-days N]   sign an Alice CSR → client cert
//	bob serve [--addr :8443]                     unlock (operator password) + mTLS oracle
//
// State lives in --dir (default ~/.anb/bob or $ANB_BOB_DIR):
// ca.crt/ca.key, server.crt/server.key, envelope.json, authz.json.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kaka-milan-22/AnB/internal/authz"
	"github.com/kaka-milan-22/AnB/internal/ca"
	"github.com/kaka-milan-22/AnB/internal/crypto"
	"github.com/kaka-milan-22/AnB/internal/keystore"
	"github.com/kaka-milan-22/AnB/internal/mtls"
	"github.com/kaka-milan-22/AnB/internal/server"
	"github.com/kaka-milan-22/AnB/internal/term"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "ca":
		err = cmdCA(os.Args[2:])
	case "init":
		err = cmdInit(os.Args[2:])
	case "sign-csr":
		err = cmdSignCSR(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "bob: unknown command %q\n", os.Args[1])
		usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `bob — AnB KMS daemon
  bob ca init [--cn NAME] [--ttl-years N]
  bob init [--host h1,h2,...]
  bob sign-csr <csr.pem> [--out FILE] [--ttl-days N]
  bob serve [--addr :8443] [--ttl SECONDS]
`)
	os.Exit(2)
}

// --- state dir & file helpers ---

func bobDir(flagDir string) string {
	if flagDir != "" {
		return flagDir
	}
	if d := os.Getenv("ANB_BOB_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".anb", "bob")
}

func writeFile(dir, name string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), data, mode)
}

func readFile(dir, name string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, name)) }

func exists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

// --- bob ca init ---

func cmdCA(args []string) error {
	if len(args) == 0 || args[0] != "init" {
		return fmt.Errorf("usage: bob ca init [--cn NAME] [--ttl-years N]")
	}
	fs := newFlags("ca init")
	dir := fs.String("dir", "", "state dir")
	cn := fs.String("cn", "AnB-ca", "CA common name")
	years := fs.Int("ttl-years", 10, "CA validity in years")
	force := fs.Bool("force", false, "overwrite an existing CA")
	parse(fs, args[1:])

	d := bobDir(*dir)
	if exists(d, "ca.key") && !*force {
		return fmt.Errorf("CA already exists in %s (use --force to overwrite)", d)
	}
	authority, err := ca.NewCA(*cn, time.Duration(*years)*365*24*time.Hour)
	if err != nil {
		return err
	}
	keyPEM, err := authority.MarshalKey()
	if err != nil {
		return err
	}
	if err := writeFile(d, "ca.crt", authority.CertPEM, 0o644); err != nil {
		return err
	}
	if err := writeFile(d, "ca.key", keyPEM, 0o600); err != nil {
		return err
	}
	fmt.Printf("✓ CA created in %s (ca.crt, ca.key)\n", d)
	fmt.Println("  Distribute ca.crt to each Alice as the trust anchor.")
	return nil
}

// --- bob init ---

func cmdInit(args []string) error {
	fs := newFlags("init")
	dir := fs.String("dir", "", "state dir")
	hosts := fs.String("host", "localhost,127.0.0.1", "comma-separated server hostnames/IPs (SANs)")
	force := fs.Bool("force", false, "overwrite an existing master key / server cert")
	parse(fs, args)

	d := bobDir(*dir)
	if !exists(d, "ca.key") {
		return fmt.Errorf("no CA in %s — run `bob ca init` first", d)
	}
	if exists(d, "envelope.json") && !*force {
		return fmt.Errorf("master key already initialized in %s (use --force)", d)
	}

	caCertPEM, _ := readFile(d, "ca.crt")
	caKeyPEM, _ := readFile(d, "ca.key")
	authority, err := ca.LoadCA(caCertPEM, caKeyPEM)
	if err != nil {
		return err
	}

	// Master password from a TTY (interactive, the norm) or $ANB_BOB_PASSWORD
	// (automated deploys / CI). Either way it never touches disk in plaintext.
	password := os.Getenv("ANB_BOB_PASSWORD")
	if password == "" {
		if !term.StdinIsTTY() {
			return fmt.Errorf("init needs a master password: run on a TTY or set ANB_BOB_PASSWORD")
		}
		var perr error
		if password, perr = term.ReadNewPassword("Set Bob master password: "); perr != nil {
			return perr
		}
	}

	mk, err := crypto.NewMasterKey()
	if err != nil {
		return err
	}
	defer crypto.Wipe(mk)
	env, err := crypto.Wrap(mk, password)
	if err != nil {
		return err
	}
	envJSON, _ := json.MarshalIndent(env, "", "  ")
	if err := writeFile(d, "envelope.json", envJSON, 0o600); err != nil {
		return err
	}

	hostList := splitCSV(*hosts)
	srvCert, srvKey, err := authority.IssueServer(hostList, 825*24*time.Hour)
	if err != nil {
		return err
	}
	if err := writeFile(d, "server.crt", srvCert, 0o644); err != nil {
		return err
	}
	if err := writeFile(d, "server.key", srvKey, 0o600); err != nil {
		return err
	}
	fmt.Printf("✓ Master key wrapped (envelope.json) and server cert minted for %v\n", hostList)
	return nil
}

// --- bob sign-csr ---

func cmdSignCSR(args []string) error {
	fs := newFlags("sign-csr")
	dir := fs.String("dir", "", "state dir")
	out := fs.String("out", "", "write client cert here (default: stdout)")
	days := fs.Int("ttl-days", 90, "client cert validity in days")
	rest := parse(fs, args)
	if len(rest) != 1 {
		return fmt.Errorf("usage: bob sign-csr <csr.pem> [--out FILE] [--ttl-days N]")
	}

	d := bobDir(*dir)
	caCertPEM, _ := readFile(d, "ca.crt")
	caKeyPEM, _ := readFile(d, "ca.key")
	authority, err := ca.LoadCA(caCertPEM, caKeyPEM)
	if err != nil {
		return err
	}
	csrPEM, err := os.ReadFile(rest[0])
	if err != nil {
		return err
	}
	certPEM, identity, err := authority.SignCSR(csrPEM, time.Duration(*days)*24*time.Hour)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "→ signing client cert for identity %q (review before distributing)\n", identity)
	if *out != "" {
		if err := os.WriteFile(*out, certPEM, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "✓ wrote %s\n", *out)
		return nil
	}
	os.Stdout.Write(certPEM)
	return nil
}

// --- bob serve ---

func cmdServe(args []string) error {
	fs := newFlags("serve")
	dir := fs.String("dir", "", "state dir")
	addr := fs.String("addr", ":8443", "listen address")
	ttl := fs.Int("ttl", 0, "idle seconds before auto-relock (0 = hold until exit)")
	parse(fs, args)

	d := bobDir(*dir)
	for _, f := range []string{"ca.crt", "server.crt", "server.key", "envelope.json"} {
		if !exists(d, f) {
			return fmt.Errorf("missing %s in %s — run `bob ca init` and `bob init` first", f, d)
		}
	}
	caCertPEM, _ := readFile(d, "ca.crt")
	srvCert, _ := readFile(d, "server.crt")
	srvKey, _ := readFile(d, "server.key")
	envJSON, _ := readFile(d, "envelope.json")

	var env crypto.Envelope
	if err := json.Unmarshal(envJSON, &env); err != nil {
		return fmt.Errorf("envelope.json: %w", err)
	}

	// Unlock: operator password (TTY) or $ANB_BOB_PASSWORD for automation.
	password := os.Getenv("ANB_BOB_PASSWORD")
	if password == "" {
		if !term.StdinIsTTY() {
			return fmt.Errorf("serve needs the master password: run on a TTY or set ANB_BOB_PASSWORD")
		}
		var err error
		if password, err = term.ReadPassword("Bob master password: "); err != nil {
			return err
		}
	}
	mk, err := crypto.Unwrap(&env, password)
	if err != nil {
		return err
	}

	policy, err := authz.OpenOrDefault(filepath.Join(d, "authz.json"))
	if err != nil {
		return fmt.Errorf("authz.json: %w", err)
	}
	if policy.DefaultAllow {
		log.Println("⚠ no authz.json — running ALLOW-ALL (every authenticated client may access every key)")
	}

	store := keystore.New(func() { log.Println("⚠ master key auto-locked (idle TTL); restart serve to unlock") })
	store.Hold(mk, time.Duration(*ttl)*time.Second) // store mlocks + owns mk now
	crypto.Wipe(mk)

	tlsCfg, err := mtls.ServerConfig(srvCert, srvKey, caCertPEM)
	if err != nil {
		return err
	}
	ln, err := tlsListen(*addr, tlsCfg)
	if err != nil {
		return err
	}
	defer ln.Close()

	audit := log.New(os.Stderr, "audit ", log.LstdFlags|log.LUTC)
	srv := server.New(store, policy, audit)

	// Clean shutdown: zeroize the key on signal.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		log.Println("shutting down, zeroizing key")
		store.Zeroize()
		ln.Close()
	}()

	log.Printf("bob serving mTLS on %s (state %s)", *addr, d)
	if err := srv.Serve(ln); err != nil {
		// listener closed on shutdown is expected
		if !strings.Contains(err.Error(), "use of closed") {
			return err
		}
	}
	return nil
}
