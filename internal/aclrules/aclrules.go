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
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
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

// envNameRE validates env-var names: POSIX KEY syntax.
var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Rule is one parsed allowlist entry.
type Rule struct {
	Regex    *regexp.Regexp // implicitly anchored ^(?:...)$
	EnvAllow []string       // env names allowed (empty -> no --env; order preserved from source)
	EnvAny   bool           // env column was "*" -> any env name allowed
	Label    string         // audit label from field 3 (empty if no label)
	LineNo   int            // 1-based line number in source file
	Raw      string         // original line, for error context
}

// Parse reads rule lines from r and returns the parsed rules plus any
// per-line errors. Errors are non-fatal at the line level — Parse
// returns all valid rules it could parse plus a list of errors for
// lines that failed. Callers may decide whether to refuse the whole
// file (LoadFile does) or use the partial result.
func Parse(r io.Reader) ([]Rule, []error) {
	var rules []Rule
	var errs []error
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4*1024), 4*1024) // 4 KB per line max
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		rule, err := parseLine(line, lineNo)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rules = append(rules, rule)
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, fmt.Errorf("scan: %w", err))
	}
	return rules, errs
}

func parseLine(line string, lineNo int) (Rule, error) {
	fields := strings.Split(line, "\t")
	if len(fields) > 3 {
		return Rule{}, fmt.Errorf("line %d: %d tab-separated fields, max 3 (got %q)", lineNo, len(fields), line)
	}

	// rxRaw is kept verbatim — leading/trailing whitespace is significant
	// (it's a regex; a literal space at the start is a literal space match).
	// Operators with mis-paste'd trailing space at end of line get to see
	// their regex actually contains that space; better than a silent trim
	// that wouldn't match invocations the way the file visually suggested.
	rxRaw := fields[0]
	envCol := ""
	labelCol := ""
	if len(fields) >= 2 {
		envCol = fields[1]
	}
	if len(fields) >= 3 {
		labelCol = fields[2]
	}

	// Anchor implicitly. Operator may add their own ^ / $ — harmless
	// (RE2 collapses ^^ to ^ and $$ to $; escaped \$ stays literal and
	// the outer $ remains the anchor).
	anchored := "^(?:" + rxRaw + ")$"
	rx, err := regexp.Compile(anchored)
	if err != nil {
		return Rule{}, fmt.Errorf("line %d: invalid regex %q: %w", lineNo, rxRaw, err)
	}

	envAllow, envAny, err := parseEnvColumn(envCol, lineNo)
	if err != nil {
		return Rule{}, err
	}

	label, err := parseLabelColumn(labelCol, lineNo)
	if err != nil {
		return Rule{}, err
	}

	return Rule{
		Regex:    rx,
		EnvAllow: envAllow,
		EnvAny:   envAny,
		Label:    label,
		LineNo:   lineNo,
		Raw:      line,
	}, nil
}

func parseEnvColumn(col string, lineNo int) ([]string, bool, error) {
	col = strings.TrimSpace(col)
	if col == "" {
		return nil, false, nil
	}
	if col == "*" {
		return nil, true, nil
	}
	parts := strings.Split(col, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		name := strings.TrimSpace(p)
		if name == "" {
			return nil, false, fmt.Errorf("line %d: empty env name in csv %q", lineNo, col)
		}
		if !envNameRE.MatchString(name) {
			return nil, false, fmt.Errorf("line %d: invalid env name %q (must match %s)", lineNo, name, envNameRE.String())
		}
		out = append(out, name)
	}
	return out, false, nil
}

func parseLabelColumn(col string, lineNo int) (string, error) {
	if col == "" {
		return "", nil
	}
	if !strings.HasPrefix(col, "#") {
		return "", fmt.Errorf("line %d: field 3 must start with '#'; got %q", lineNo, col)
	}
	return strings.TrimSpace(strings.TrimPrefix(col, "#")), nil
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

// Matches reports whether this rule allows the given canonical match
// string and operator-supplied env-var name set. Both regex anchor
// (compiled in at parse time) and env subset check must pass.
func (r *Rule) Matches(matchStr string, envKeys []string) bool {
	if !r.Regex.MatchString(matchStr) {
		return false
	}
	return r.envAllowed(envKeys)
}

// ErrRulesMissing is returned by LoadFile when the rules file does
// not exist. cmdExec catches this to print the dedicated init hint.
var ErrRulesMissing = errors.New("exec-allowlist.rules not found")

// LoadFile reads and parses an allowlist rules file. Refuses to load
// if any line failed to parse or if any rule trivially matches every
// possible invocation. Returns ErrRulesMissing if the file does not
// exist (callers may scaffold or hard-deny on this).
func LoadFile(path string) ([]Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrRulesMissing
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	rules, errs := Parse(f)
	if len(errs) > 0 {
		// Refuse the whole file on any per-line error — partial loading
		// would silently drop rules the operator thought they had.
		// Surface ALL parse errors at once (errors.Join preserves the
		// errors.Is chain for each constituent) so a 10-line file with
		// errors on lines 3 and 8 doesn't force a fix-one-rerun cycle.
		return nil, fmt.Errorf("parse %s: %w", path, errors.Join(errs...))
	}

	for _, r := range rules {
		if isTrivialMatchEverything(r.Regex) {
			return nil, fmt.Errorf("%s line %d: rule matches every possible invocation (%q); refuse to load",
				path, r.LineNo, r.Raw)
		}
	}
	return rules, nil
}

// isTrivialMatchEverything heuristically detects rules that accept
// any string. Three sentinel inputs that should never simultaneously
// match a reasonable allowlist rule: empty string, "/", and a
// path-traversal-looking adversarial string.
func isTrivialMatchEverything(rx *regexp.Regexp) bool {
	return rx.MatchString("") &&
		rx.MatchString("/") &&
		rx.MatchString("../../etc/passwd")
}

// LiteralRule returns a fully-escaped, anchored rule line for the
// given invocation. Used by alice's auto-bless flow: when operator
// types 'yes' at the deny prompt, alice appends this line to
// exec-allowlist.rules. The generated regex matches *exactly* the
// original (cmd, args); operator can hand-edit later to widen it.
//
// Env names are sorted so identical invocations produce byte-identical
// lines (deterministic for tests and stable diffs).
func LiteralRule(cmd string, args []string, envKeys []string, label string) string {
	match := Canonicalize(cmd, args)
	rxBody := regexp.QuoteMeta(match)

	envSorted := append([]string(nil), envKeys...)
	sort.Strings(envSorted)

	var sb strings.Builder
	sb.WriteByte('^')
	sb.WriteString(rxBody)
	sb.WriteByte('$')
	if len(envSorted) > 0 || label != "" {
		sb.WriteByte('\t')
		sb.WriteString(strings.Join(envSorted, ","))
	}
	if label != "" {
		sb.WriteByte('\t')
		sb.WriteString("# ")
		sb.WriteString(label)
	}
	return sb.String()
}

func (r *Rule) envAllowed(envKeys []string) bool {
	if r.EnvAny {
		return true
	}
	if len(envKeys) == 0 {
		return true // empty subset is always allowed
	}
	if len(r.EnvAllow) == 0 {
		return false // no env keys allowed, but operator passed some
	}
	allowed := make(map[string]struct{}, len(r.EnvAllow))
	for _, k := range r.EnvAllow {
		allowed[k] = struct{}{}
	}
	for _, k := range envKeys {
		if _, ok := allowed[k]; !ok {
			return false
		}
	}
	return true
}
