package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kaka-milan-22/AnB/v3/internal/aclrules"
	"github.com/kaka-milan-22/AnB/v3/internal/localvault"
)

// cmdAllowlistCheck — lint pass over exec-allowlist.rules. Reports
// parse errors + lint findings with severity. Exit codes:
//
//	0  no findings, no parse errors
//	1  parse errors OR DANGER findings present
//	2  only WARNINGs present AND --strict flag set
func cmdAllowlistCheck(args []string) error {
	fs := newFS("allowlist-check")
	fileFlag := fs.String("file", "", "rules file to check (default: <state>/exec-allowlist.rules)")
	strictFlag := fs.Bool("strict", false, "exit non-zero on WARNINGs as well as DANGERs")
	dir := dirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := *fileFlag
	if path == "" {
		s := localvault.Open(*dir)
		path = filepath.Join(s.Dir, "exec-allowlist.rules")
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	rules, parseErrs := aclrules.Parse(f)
	findings := aclrules.Lint(rules)

	fmt.Printf("Checking %s\n", path)
	fmt.Printf("%d rules loaded, %d findings.\n\n", len(rules), len(findings)+len(parseErrs))

	// Parse errors first (operator must fix these before findings matter).
	for _, e := range parseErrs {
		fmt.Printf("❌ ERROR: %v\n\n", e)
	}

	// Lint findings.
	for _, fnd := range findings {
		emoji := severityEmoji(fnd.Severity)
		fmt.Printf("%s line %d: %s (%s)\n  %s\n  Hint: %s\n\n",
			emoji, fnd.LineNo, fnd.ID, fnd.Severity, fnd.Rule, fnd.Hint)
	}

	// Summary.
	var danger, warning, info int
	for _, fnd := range findings {
		switch fnd.Severity {
		case aclrules.SeverityDanger:
			danger++
		case aclrules.SeverityWarning:
			warning++
		case aclrules.SeverityInfo:
			info++
		}
	}
	fmt.Printf("Summary: %d rules, %d danger, %d warnings, %d info\n",
		len(rules), danger, warning, info)

	// Exit code.
	if len(parseErrs) > 0 || danger > 0 {
		os.Exit(1)
	}
	if *strictFlag && warning > 0 {
		os.Exit(2)
	}
	return nil
}

func severityEmoji(s aclrules.Severity) string {
	switch s {
	case aclrules.SeverityDanger:
		return "🚨"
	case aclrules.SeverityWarning:
		return "⚠"
	case aclrules.SeverityInfo:
		return "ℹ"
	}
	return "?"
}
