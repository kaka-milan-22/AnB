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
