package main

import (
	"fmt"

	"github.com/kaka-milan-22/AnB/v3/internal/pwgen"
)

// gen — generate random password candidates and print them. Pipe-friendly:
// the output is one candidate per line on stdout (no banner, no labels), so
// `alice gen | alice set --stdin --force <key>` is the natural compose flow.
// Generation is purely local (no Bob, no vault touch); the produced bytes
// are fresh entropy, not an existing secret, so there's no exfil risk to
// gate on TTY presence.
func cmdGen(args []string) error {
	fs := newFS("gen")
	style := fs.String("style", "apple", "apple | full | passphrase | pin")
	var length, count int
	fs.IntVar(&length, "l", 0, "size: apple=groups(1-8) full=chars(8-100) passphrase=words(3-12) pin=digits(4-32); 0=default")
	fs.IntVar(&length, "length", 0, "alias for -l")
	fs.IntVar(&count, "n", 1, "how many to generate (1-10)")
	fs.IntVar(&count, "count", 1, "alias for -n")
	parse(fs, args)

	if count < 1 || count > 10 {
		return fmt.Errorf("-n must be 1-10 (got %d)", count)
	}
	s := pwgen.Style(*style)
	for i := 0; i < count; i++ {
		p, err := pwgen.Generate(s, length) // first iteration validates style/size before any output
		if err != nil {
			return err
		}
		fmt.Println(p)
	}
	return nil
}
