// Package aclrules implements alice's regex-based execution allowlist.
//
// An allowlist file is plain text. Each non-empty, non-comment line is a
// rule consisting of up to three tab-separated fields: a Go RE2 regex
// (implicitly anchored), a comma-separated set of allowed env-var names,
// and an optional "#"-prefixed label for audit attribution.
//
// alice canonicalises each "alice exec" invocation as
//
//	shellescape(cmd) + " " + shellescape(arg1) + " " + ... + shellescape(argN)
//
// and tests it top-to-bottom against the rules' regexes. The first match
// wins; the operator's --env names must be a subset of the matched rule's
// allowed env set; no match means hard-deny.
package aclrules

import (
	"strings"
)

// shellSafe matches every char that does not need shell quoting.
// Keep this conservative — POSIX sh treats more chars as special than
// most operators expect (notably !, ~, *, ?, $, etc.).
const shellSafeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:=@,"

func isShellSafe(s string) bool {
	if s == "" {
		return false // empty arg needs '' wrapping
	}
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(shellSafeChars, rune(s[i])) {
			return false
		}
	}
	return true
}

func shellescape(s string) string {
	if isShellSafe(s) {
		return s
	}
	// POSIX single-quote: wrap in ' ... '. Embedded ' becomes '\''.
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Canonicalize joins cmd and args into the match string used by Rule.Matches.
// Pure function — no I/O, no side effects.
func Canonicalize(cmd string, args []string) string {
	var sb strings.Builder
	sb.WriteString(shellescape(cmd))
	for _, a := range args {
		sb.WriteByte(' ')
		sb.WriteString(shellescape(a))
	}
	return sb.String()
}
