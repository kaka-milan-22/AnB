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
	// Tasks L2-L6 add entries here.
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
