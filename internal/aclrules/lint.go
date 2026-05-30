package aclrules

// Severity is the lint-finding severity level. String values are
// operator-visible (appear in alice allowlist-check output and in
// CI log scraping).
type Severity string

const (
	SeverityDanger  Severity = "DANGER"
	SeverityWarning Severity = "WARNING"
	SeverityInfo    Severity = "INFO"
)

// Finding is one lint hit on one rule.
type Finding struct {
	ID       string
	Severity Severity
	LineNo   int
	Rule     string
	Message  string
	Hint     string
}

// lintCheck is the signature each individual check must satisfy.
type lintCheck func(r Rule) *Finding

// lintChecks is the registry of all enabled checks. Tasks L2-L6
// append one entry each.
var lintChecks = []lintCheck{
	lintTrivialMatch,
	lintScriptHost,
	lintEnvWildcard,
	lintUnescapedDot,
	lintNoLabel,
}

// trivialMatchSentinels — inputs no realistic allowlist rule should
// accept simultaneously. We use two sets: one including the empty string
// (catches ^.*$ and ^.{0,N}$) and one without (catches ^.+$ which requires
// at least one char). If the non-empty set all matches, the rule is
// trivially permissive over all non-empty strings — still DANGER.
var trivialMatchSentinelsAll = []string{
	"",
	"/",
	"/bin/sh",
	"../../etc/passwd",
	"a",
	"some random string",
}

var trivialMatchSentinelsNonEmpty = []string{
	"/",
	"/bin/sh",
	"../../etc/passwd",
	"a",
	"some random string",
}

func lintTrivialMatch(r Rule) *Finding {
	// Check full set (including empty string) first.
	allMatch := true
	for _, s := range trivialMatchSentinelsAll {
		if !r.Regex.MatchString(s) {
			allMatch = false
			break
		}
	}
	if allMatch {
		return &Finding{
			ID:       "trivial-match",
			Severity: SeverityDanger,
			LineNo:   r.LineNo,
			Rule:     r.Raw,
			Message:  "regex matches every input string (trivial-match-everything)",
			Hint:     "narrow with a literal prefix; run `alice exec --show-match-string -- <cmd> <args>` to see exactly what string your regex must match",
		}
	}
	// Check non-empty set: catches ^.+$ and ^.{1,N}$ style patterns.
	for _, s := range trivialMatchSentinelsNonEmpty {
		if !r.Regex.MatchString(s) {
			return nil
		}
	}
	// Also verify it does NOT match empty (distinguishes from allMatch case already
	// handled above) AND that it rejects a realistic narrow command prefix.
	if r.Regex.MatchString("/bin/echo hello") && r.Regex.MatchString("curl https://example.com") {
		return &Finding{
			ID:       "trivial-match",
			Severity: SeverityDanger,
			LineNo:   r.LineNo,
			Rule:     r.Raw,
			Message:  "regex matches every non-empty input string (trivial-match-everything)",
			Hint:     "narrow with a literal prefix; run `alice exec --show-match-string -- <cmd> <args>` to see exactly what string your regex must match",
		}
	}
	return nil
}

var scriptHosts = []string{
	"/bin/sh",
	"/bin/bash",
	"/bin/zsh",
	"/bin/dash",
	"/bin/ksh",
	"/usr/bin/python",
	"/usr/bin/python3",
	"/opt/homebrew/bin/python3",
	"/usr/bin/perl",
	"/opt/homebrew/bin/perl",
	"/usr/bin/awk",
	"/usr/bin/gawk",
	"/opt/homebrew/bin/awk",
}

var jqHosts = []string{
	"/usr/bin/jq",
	"/opt/homebrew/bin/jq",
}

func lintScriptHost(r Rule) *Finding {
	for _, host := range scriptHosts {
		probes := []string{
			host + " -c x",
			host + " -c 'echo evil'",
			host + " -c any-thing-here",
		}
		hit := true
		for _, p := range probes {
			if !r.Regex.MatchString(p) {
				hit = false
				break
			}
		}
		if hit {
			return &Finding{
				ID:       "script-host",
				Severity: SeverityDanger,
				LineNo:   r.LineNo,
				Rule:     r.Raw,
				Message:  "regex matches script-host " + host + " with arbitrary -c argument (arbitrary code execution)",
				Hint:     "remove this rule, OR allowlist a specific script file path (e.g. ^" + host + ` /Users/me/safe\.py$\tKEY) instead of '-c'`,
			}
		}
	}
	for _, host := range jqHosts {
		probes := []string{
			host + " -r .",
			host + " -r '.foo'",
			host + " -r any-expression",
		}
		hit := true
		for _, p := range probes {
			if !r.Regex.MatchString(p) {
				hit = false
				break
			}
		}
		if hit {
			return &Finding{
				ID:       "script-host",
				Severity: SeverityDanger,
				LineNo:   r.LineNo,
				Rule:     r.Raw,
				Message:  "regex matches " + host + " -r with arbitrary expression (jq expression language is code-exec class)",
				Hint:     "constrain the expression with a literal pattern, or remove this rule",
			}
		}
	}
	return nil
}

func lintEnvWildcard(r Rule) *Finding {
	if !r.EnvAny {
		return nil
	}
	return &Finding{
		ID:       "env-wildcard",
		Severity: SeverityWarning,
		LineNo:   r.LineNo,
		Rule:     r.Raw,
		Message:  "env column is '*' — any env-var name accepted",
		Hint:     "list specific env names (e.g. AUTH_TOKEN) unless the binary truly needs unrestricted env. '*' is safe only for binaries that don't leak env content via output",
	}
}

// lintUnescapedDot — heuristic: literal `.` in regex column, flanked
// by `/` within ~30 chars, not preceded by `\`. Best-effort, returns
// WARNING not DANGER.
func lintUnescapedDot(r Rule) *Finding {
	regexCol := r.Raw
	if i := indexOfByte(regexCol, '\t'); i >= 0 {
		regexCol = regexCol[:i]
	}

	for i := 0; i < len(regexCol); i++ {
		if regexCol[i] != '.' {
			continue
		}
		if i > 0 && regexCol[i-1] == '\\' {
			continue
		}
		left := false
		for j := i - 1; j >= 0 && j >= i-30; j-- {
			if regexCol[j] == '/' {
				left = true
				break
			}
			if regexCol[j] == ' ' || regexCol[j] == '\t' {
				break
			}
		}
		right := false
		for j := i + 1; j < len(regexCol) && j <= i+30; j++ {
			if regexCol[j] == '/' {
				right = true
				break
			}
			if regexCol[j] == ' ' || regexCol[j] == '\t' || regexCol[j] == '$' {
				break
			}
		}
		if left && right {
			return &Finding{
				ID:       "unescaped-dot",
				Severity: SeverityWarning,
				LineNo:   r.LineNo,
				Rule:     r.Raw,
				Message:  "regex contains unescaped `.` in a path component (matches any char, not just literal dot)",
				Hint:     "use `\\.` for literal dot; auto-blessed rules already escape correctly. e.g. /Users/me/.local → /Users/me/\\.local",
			}
		}
	}
	return nil
}

func indexOfByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func lintNoLabel(r Rule) *Finding {
	if r.Label != "" {
		return nil
	}
	return &Finding{
		ID:       "no-label",
		Severity: SeverityInfo,
		LineNo:   r.LineNo,
		Rule:     r.Raw,
		Message:  "rule has no label",
		Hint:     "add `\\t# <label>` as third column. Without a label, audit-line stderr shows `rule=line:N` (less searchable than `rule=[name]`)",
	}
}

// Lint runs every registered check against every rule. Findings
// returned in (line, check-registration) order.
func Lint(rules []Rule) []Finding {
	var out []Finding
	for _, r := range rules {
		for _, check := range lintChecks {
			if f := check(r); f != nil {
				out = append(out, *f)
			}
		}
	}
	return out
}
