package main

import "github.com/kaka-milan-22/AnB/v3/internal/term"

// red wraps s in an ANSI red SGR sequence, but only when stdout is a real
// terminal — so piped/redirected output stays clean for parsing.
func red(s string) string {
	if !term.StdoutIsTTY() {
		return s
	}
	return "\x1b[31m" + s + "\x1b[0m"
}
