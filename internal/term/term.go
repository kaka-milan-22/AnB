// Package term centralizes interactive-terminal handling: TTY detection (the
// structural gate that keeps agents out of sensitive commands) and masked
// password entry. Prompts go to stderr so stdout stays clean for piping.
package term

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	xterm "golang.org/x/term"
)

// IsTTY reports whether the file descriptor is an interactive terminal.
func IsTTY(f *os.File) bool { return xterm.IsTerminal(int(f.Fd())) }

// StdinIsTTY / StdoutIsTTY are the two signals sensitive commands gate on.
func StdinIsTTY() bool  { return IsTTY(os.Stdin) }
func StdoutIsTTY() bool { return IsTTY(os.Stdout) }

// ReadPassword reads a line from stdin with echo disabled.
func ReadPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := xterm.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ReadNewPassword prompts twice and requires a non-empty match. Used when
// setting a brand-new secret (operator master password, or a vaulted value).
func ReadNewPassword(prompt string) (string, error) {
	p1, err := ReadPassword(prompt)
	if err != nil {
		return "", err
	}
	if p1 == "" {
		return "", errors.New("empty value")
	}
	p2, err := ReadPassword("Confirm: ")
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", errors.New("entries did not match")
	}
	return p1, nil
}

// Confirm asks a y/N question on stderr and reads stdin.
func Confirm(prompt string, defaultYes bool) (bool, error) {
	hint := "[y/N]"
	if defaultYes {
		hint = "[Y/n]"
	}
	fmt.Fprintf(os.Stderr, "%s %s ", prompt, hint)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return false, err
	}
	a := strings.ToLower(strings.TrimSpace(line))
	if a == "" {
		return defaultYes, nil
	}
	return a == "y" || a == "yes", nil
}
