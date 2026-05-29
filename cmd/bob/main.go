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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kaka-milan-22/AnB/v2/internal/authz"
	"github.com/kaka-milan-22/AnB/v2/internal/ca"
	"github.com/kaka-milan-22/AnB/v2/internal/crypto"
	"github.com/kaka-milan-22/AnB/v2/internal/keystore"
	"github.com/kaka-milan-22/AnB/v2/internal/mtls"
	"github.com/kaka-milan-22/AnB/v2/internal/server"
	"github.com/kaka-milan-22/AnB/v2/internal/term"
	"github.com/kaka-milan-22/AnB/v2/internal/version"
)

const pairCodeTTL = 10 * time.Minute

const authzExampleJSON = `{
  "rules": {
    "alice-laptop": ["*"],
    "agent-ci":     ["ci-", "deploy-"]
  }
}
`

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
	case "rotate-master-password":
		err = cmdRotateMasterPassword(os.Args[2:])
	case "version", "--version", "-V":
		version.Print(os.Stdout, "bob")
		return
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
	const row = "  %-36s%s\n" // 2-space indent + aligned command column + description
	w := os.Stderr
	fmt.Fprint(w, "Usage: bob [options] <command>\n\n")
	fmt.Fprint(w, "Keep your secrets hidden from AI agents.\n")
	fmt.Fprint(w, "https://github.com/kaka-milan-22/AnB\n\n")

	fmt.Fprint(w, "Options:\n")
	fmt.Fprintf(w, row, "-h, --help", "display help for command")
	fmt.Fprintf(w, row, "-V, --version", "print version and exit")

	fmt.Fprint(w, "\nCommands:\n")
	fmt.Fprintf(w, row, "ca init [options]", "Create the private CA — the trust root for everyone")
	fmt.Fprintf(w, row, "init [options]", "Generate + wrap the master key, mint the server cert")
	fmt.Fprintf(w, row, "sign-csr [options] <csr.pem>", "Sign an Alice CSR → client certificate")
	fmt.Fprintf(w, row, "serve [options]", "Unlock the master key and run the mTLS oracle (-D to daemonize)")
	fmt.Fprintf(w, row, "rotate-master-password", "Re-wrap the master key under a new password (K unchanged; vault.json untouched)")

	fmt.Fprint(w, "\nCommon: --dir DIR        state dir (default ~/.anb/bob or $ANB_BOB_DIR)\n")
	fmt.Fprint(w, "        $ANB_BOB_PASSWORD master password for init/serve (else prompted on a TTY)\n")
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

// writeFile writes data to dir/name atomically: tmp file + rename. Prevents a
// SIGKILL / power loss mid-write from truncating critical files like
// envelope.json or ca.key. mode is applied to the temp file (rename preserves).
func writeFile(dir, name string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
	if err := writeFile(d, "authz.json.example", []byte(authzExampleJSON), 0o644); err != nil {
		return err
	}
	fmt.Printf("✓ Master key wrapped (envelope.json) and server cert minted for %v\n", hostList)
	fmt.Println("✓ Wrote authz.json.example — copy to authz.json and edit before serving in production")
	fmt.Println("  (without authz.json, Bob runs ALLOW-ALL: every authenticated client can access every key)")
	return nil
}

// --- bob sign-csr ---

func cmdSignCSR(args []string) error {
	fs := newFlags("sign-csr")
	dir := fs.String("dir", "", "state dir")
	out := fs.String("out", "", "write client cert here (default: stdout)")
	days := fs.Int("ttl-days", 90, "client cert validity in days")
	noPair := fs.Bool("no-pair", false, "skip OOB pairing — sign without an enrollment code (warned)")
	rest := parse(fs, args)
	if len(rest) != 1 {
		return fmt.Errorf("usage: bob sign-csr <csr.pem> [--out FILE] [--ttl-days N] [--no-pair]")
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

	// Pre-parse to surface CSR identity + pubkey fingerprint to the operator.
	// CRITICAL: verify the CSR's self-signature BEFORE displaying anything.
	// Otherwise an attacker could craft a CSR with a forged CommonName + an
	// invalid signature; the operator would see the fake identity, confirm,
	// and have already transmitted the pairing code OOB by the time the later
	// SignCSR{,WithPairing} call rejected the bad signature.
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("not a PEM CSR: %s", rest[0])
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("CSR signature invalid: %w", err)
	}
	if csr.Subject.CommonName == "" {
		return fmt.Errorf("CSR has empty CommonName")
	}
	fp := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	fpHex := hex.EncodeToString(fp[:])

	if *noPair {
		fmt.Fprintf(os.Stderr, "⚠ --no-pair: signing without an OOB pairing code (any holder of this cert can install it)\n")
		fmt.Fprintf(os.Stderr, "→ CSR identity:  %s\n", csr.Subject.CommonName)
		fmt.Fprintf(os.Stderr, "→ CSR pubkey fp: %s\n", fpHex)
		ok, err := term.Confirm(fmt.Sprintf("Sign %q without pairing?", csr.Subject.CommonName), false)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("aborted")
		}
		certPEM, _, err := authority.SignCSR(csrPEM, time.Duration(*days)*24*time.Hour)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "✓ signed cert for identity %q\n", csr.Subject.CommonName)
		return writeOrStdout(out, certPEM)
	}

	code, err := ca.NewPairingCode()
	if err != nil {
		return err
	}
	expires := time.Now().Add(pairCodeTTL)
	commit := ca.PairingCommit(code, fp[:])

	fmt.Fprintf(os.Stderr, "→ CSR identity:  %s\n", csr.Subject.CommonName)
	fmt.Fprintf(os.Stderr, "→ CSR pubkey fp: %s\n", fpHex)
	fmt.Fprintf(os.Stderr, "→ Pairing code:  %s   (show to Alice OOB; expires at %s)\n",
		code, expires.UTC().Format("15:04:05 UTC"))
	ok, err := term.Confirm(fmt.Sprintf("Sign %q with this pairing code?", csr.Subject.CommonName), false)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("aborted")
	}

	certPEM, _, err := authority.SignCSRWithPairing(csrPEM, time.Duration(*days)*24*time.Hour, ca.Pairing{
		Commit:    commit,
		ExpiresAt: expires,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ signed cert for identity %q (pairing code expires at %s)\n",
		csr.Subject.CommonName, expires.UTC().Format("15:04:05 UTC"))
	return writeOrStdout(out, certPEM)
}

// writeOrStdout writes the cert PEM to *out (a file path) when non-empty,
// else to os.Stdout. Always uses 0o644 for the file path.
func writeOrStdout(out *string, certPEM []byte) error {
	if *out != "" {
		if err := os.WriteFile(*out, certPEM, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "✓ wrote %s\n", *out)
		return nil
	}
	_, err := os.Stdout.Write(certPEM)
	return err
}

// --- bob serve ---

func cmdServe(args []string) error {
	fs := newFlags("serve")
	dir := fs.String("dir", "", "state dir")
	addr := fs.String("addr", ":8443", "listen address")
	ttl := fs.Int("ttl", 0, "idle seconds before auto-relock (0 = hold until exit)")
	daemon := fs.Bool("D", false, "daemonize: read the password on the TTY, then detach into the background")
	logPath := fs.String("log", "", "log file in daemon mode (default <dir>/bob.log)")
	parse(fs, args)

	// _ANB_DAEMON_CHILD marks the detached child re-exec'd by -D; it reads the
	// master password from its stdin pipe (handed over by the parent) instead of
	// prompting, since it has no controlling terminal.
	isChild := os.Getenv("_ANB_DAEMON_CHILD") == "1"

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

	// Unlock secret: $ANB_BOB_PASSWORD (automation) > parent's stdin pipe (daemon
	// child) > interactive TTY prompt. It never touches env (unless the operator
	// set it) or disk.
	password := os.Getenv("ANB_BOB_PASSWORD")
	if password == "" {
		switch {
		case isChild:
			// Read the password from the parent's pipe via term.ReadLine, which uses
			// byte-by-byte stdin reads instead of bufio — avoids the same latent
			// read-ahead drain footgun the term package was refactored to escape.
			pw, _ := term.ReadLine("")
			password = pw
			if password == "" {
				return fmt.Errorf("daemon: no master password received from parent")
			}
		case term.StdinIsTTY():
			var err error
			if password, err = term.ReadPassword("Bob master password: "); err != nil {
				return err
			}
		default:
			return fmt.Errorf("serve needs the master password: run on a TTY (optionally with -D) or set ANB_BOB_PASSWORD")
		}
	}

	// -D in the foreground process: validate the password here (so a wrong one
	// fails immediately, not silently in the background), then re-exec a detached
	// child and hand it the password over a pipe.
	if *daemon && !isChild {
		mk, err := crypto.Unwrap(&env, password) // validate before detaching
		if err != nil {
			return err
		}
		crypto.Wipe(mk)
		return daemonize(d, *logPath, password)
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

// daemonize re-execs bob as a detached background process (new session, stdio →
// log file) and hands it the master password over an anonymous pipe, so the key
// material stays off env and disk. The foreground parent prints the child PID
// and returns; the child re-enters cmdServe and reads the password from stdin.
func daemonize(dir, logPath, password string) error {
	if logPath == "" {
		logPath = filepath.Join(dir, "bob.log")
	}
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("opening log %s: %w", logPath, err)
	}
	defer logf.Close()

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}

	cmd := exec.Command(exe, os.Args[1:]...) // same args (incl. -D); child opts out via the env marker
	cmd.Env = append(os.Environ(), "_ANB_DAEMON_CHILD=1")
	cmd.Stdin = pr
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // detach from the controlling terminal
	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return err
	}
	pr.Close()
	io.WriteString(pw, password+"\n")
	pw.Close()

	pid := cmd.Process.Pid
	_ = writeFile(dir, "bob.pid", []byte(fmt.Sprintf("%d\n", pid)), 0o600)
	_ = cmd.Process.Release() // fire-and-forget; let init reap it
	fmt.Printf("✓ bob daemonized (pid %d) → %s\n", pid, logPath)
	fmt.Printf("  stop: kill %d   (master key zeroized on SIGTERM)\n", pid)
	return nil
}
