package aclrules

import (
	"strings"
	"testing"
)

func TestLintEmpty(t *testing.T) {
	findings := Lint(nil)
	if len(findings) != 0 {
		t.Errorf("Lint(nil) = %v, want []", findings)
	}
}

func TestLintEmptyRulesSlice(t *testing.T) {
	findings := Lint([]Rule{})
	if len(findings) != 0 {
		t.Errorf("Lint([]Rule{}) = %v, want []", findings)
	}
}

func TestSeverityConstants(t *testing.T) {
	if string(SeverityDanger) != "DANGER" {
		t.Errorf("SeverityDanger = %q, want %q", SeverityDanger, "DANGER")
	}
	if string(SeverityWarning) != "WARNING" {
		t.Errorf("SeverityWarning = %q, want %q", SeverityWarning, "WARNING")
	}
	if string(SeverityInfo) != "INFO" {
		t.Errorf("SeverityInfo = %q, want %q", SeverityInfo, "INFO")
	}
}

func TestFindingFieldsAccessible(t *testing.T) {
	f := Finding{
		ID:       "test",
		Severity: SeverityDanger,
		LineNo:   1,
		Rule:     "raw",
		Message:  "msg",
		Hint:     "hint",
	}
	if f.ID != "test" || f.LineNo != 1 {
		t.Error("Finding fields not assignable")
	}
}

func TestLintBenignRuleProducesNoFindings(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo hello$\tKEY\t# echo hello")
	findings := Lint([]Rule{r})
	if len(findings) != 0 {
		t.Errorf("expected zero findings from skeleton; got %v", findings)
	}
}

var _ = strings.Contains

func TestLintTrivialMatchStar(t *testing.T) {
	r := mustParseOne(t, "^.*$\t*\t# trivially permissive")
	findings := Lint([]Rule{r})
	if len(findings) != 1 || findings[0].ID != "trivial-match" {
		t.Fatalf("expected 1 trivial-match finding; got %v", findings)
	}
	if findings[0].Severity != SeverityDanger {
		t.Errorf("Severity = %q, want DANGER", findings[0].Severity)
	}
	if findings[0].LineNo != 1 {
		t.Errorf("LineNo = %d, want 1", findings[0].LineNo)
	}
}

func TestLintTrivialMatchPlus(t *testing.T) {
	r := mustParseOne(t, "^.+$\tKEY\t# plus-permissive")
	findings := Lint([]Rule{r})
	if len(findings) != 1 || findings[0].ID != "trivial-match" {
		t.Fatalf("expected trivial-match finding; got %v", findings)
	}
}

func TestLintTrivialMatchRangeQuantifier(t *testing.T) {
	r := mustParseOne(t, "^.{0,1000}$\tKEY\t# range")
	findings := Lint([]Rule{r})
	if len(findings) != 1 || findings[0].ID != "trivial-match" {
		t.Fatalf("expected trivial-match finding; got %v", findings)
	}
}

func TestLintTrivialMatchNarrowDoesNotFire(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo .+$\tKEY\t# echo with arg")
	findings := Lint([]Rule{r})
	for _, f := range findings {
		if f.ID == "trivial-match" {
			t.Errorf("narrow regex incorrectly flagged as trivial-match: %v", f)
		}
	}
}
