package aclrules

import (
	"strings"
	"testing"
)

// A rule with no 4th field defaults to cli-only. This keeps every existing
// rule invisible to the mcp surface — default-deny for agents.
func TestParseScopeDefaultCLI(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo hi$\tKEY\t# label")
	if len(r.Scope) != 1 || r.Scope[0] != "cli" {
		t.Errorf("default scope: got %v want [cli]", r.Scope)
	}
}

func TestParseScopeRegexOnlyDefaultsCLI(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo hi$")
	if len(r.Scope) != 1 || r.Scope[0] != "cli" {
		t.Errorf("regex-only default scope: got %v want [cli]", r.Scope)
	}
}

func TestParseScopeMCP(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo hi$\tKEY\t# label\tmcp")
	if len(r.Scope) != 1 || r.Scope[0] != "mcp" {
		t.Errorf("scope: got %v want [mcp]", r.Scope)
	}
}

func TestParseScopeCSV(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo hi$\tKEY\t# label\tcli,mcp")
	if len(r.Scope) != 2 || r.Scope[0] != "cli" || r.Scope[1] != "mcp" {
		t.Errorf("scope: got %v want [cli mcp]", r.Scope)
	}
}

// scope without a label: empty 3rd field, scope in the 4th.
func TestParseScopeWithoutLabel(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo hi$\tKEY\t\tmcp")
	if r.Label != "" {
		t.Errorf("label should be empty; got %q", r.Label)
	}
	if len(r.Scope) != 1 || r.Scope[0] != "mcp" {
		t.Errorf("scope: got %v want [mcp]", r.Scope)
	}
}

func TestParseScopeUnknownSurface(t *testing.T) {
	_, errs := Parse(strings.NewReader("^/bin/foo$\tKEY\t# l\tbogus\n"))
	if len(errs) == 0 {
		t.Error("expected parse error for unknown surface 'bogus'")
	}
}

func TestParseScopeEmptyMemberRejected(t *testing.T) {
	_, errs := Parse(strings.NewReader("^/bin/foo$\tKEY\t# l\tcli,\n"))
	if len(errs) == 0 {
		t.Error("expected parse error for empty scope member in 'cli,'")
	}
}

func TestFilterBySurface(t *testing.T) {
	rules := []Rule{
		mustParseOne(t, "^/bin/a$\tK\t# a"),          // cli (default)
		mustParseOne(t, "^/bin/b$\tK\t# b\tmcp"),     // mcp only
		mustParseOne(t, "^/bin/c$\tK\t# c\tcli,mcp"), // both
	}
	cli := FilterBySurface(rules, "cli")
	if len(cli) != 2 { // a, c
		t.Errorf("cli surface: got %d rules want 2", len(cli))
	}
	mcp := FilterBySurface(rules, "mcp")
	if len(mcp) != 2 { // b, c
		t.Errorf("mcp surface: got %d rules want 2", len(mcp))
	}
	// the cli-only rule (rules[0]) must NOT leak into the mcp set
	for _, r := range mcp {
		if r.Raw == rules[0].Raw {
			t.Error("cli-only rule leaked into mcp surface")
		}
	}
}

func TestIsKnownSurface(t *testing.T) {
	if !IsKnownSurface("cli") || !IsKnownSurface("mcp") {
		t.Error("cli and mcp should be known surfaces")
	}
	if IsKnownSurface("bogus") || IsKnownSurface("") {
		t.Error("unknown/empty surface should be rejected")
	}
}

func TestAppliesTo(t *testing.T) {
	cli := mustParseOne(t, "^/bin/x$\tKEY\t# l") // default cli
	if !cli.AppliesTo("cli") {
		t.Error("default rule should apply to cli")
	}
	if cli.AppliesTo("mcp") {
		t.Error("default (cli) rule must NOT apply to mcp")
	}

	both := mustParseOne(t, "^/bin/x$\tKEY\t# l\tcli,mcp")
	if !both.AppliesTo("cli") || !both.AppliesTo("mcp") {
		t.Error("cli,mcp rule should apply to both surfaces")
	}

	mcp := mustParseOne(t, "^/bin/x$\tKEY\t# l\tmcp")
	if mcp.AppliesTo("cli") {
		t.Error("mcp-only rule must NOT apply to cli")
	}
	if !mcp.AppliesTo("mcp") {
		t.Error("mcp rule should apply to mcp")
	}
}
