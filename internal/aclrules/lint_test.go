package aclrules

import (
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

func TestLintTrivialMatchStar(t *testing.T) {
	r := mustParseOne(t, "^.*$\t*\t# trivially permissive")
	findings := Lint([]Rule{r})
	got := findID(findings, "trivial-match")
	if got == nil {
		t.Fatalf("expected trivial-match finding; got %v", findings)
	}
	if got.Severity != SeverityDanger {
		t.Errorf("Severity = %q, want DANGER", got.Severity)
	}
	if got.LineNo != 1 {
		t.Errorf("LineNo = %d, want 1", got.LineNo)
	}
}

func TestLintTrivialMatchPlus(t *testing.T) {
	r := mustParseOne(t, "^.+$\tKEY\t# plus-permissive")
	findings := Lint([]Rule{r})
	if got := findID(findings, "trivial-match"); got == nil {
		t.Fatalf("expected trivial-match finding; got %v", findings)
	}
}

func TestLintTrivialMatchRangeQuantifier(t *testing.T) {
	r := mustParseOne(t, "^.{0,1000}$\tKEY\t# range")
	findings := Lint([]Rule{r})
	if got := findID(findings, "trivial-match"); got == nil {
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

func TestLintScriptHostSh(t *testing.T) {
	r := mustParseOne(t, "^/bin/sh -c .+$\t*\t# debug shell")
	findings := Lint([]Rule{r})
	got := findID(findings, "script-host")
	if got == nil {
		t.Fatalf("expected script-host finding; got %v", findings)
	}
	if got.Severity != SeverityDanger {
		t.Errorf("Severity = %q, want DANGER", got.Severity)
	}
}

func TestLintScriptHostPython(t *testing.T) {
	r := mustParseOne(t, "^/usr/bin/python3 -c .+$\tK")
	if got := findID(Lint([]Rule{r}), "script-host"); got == nil {
		t.Errorf("expected script-host finding for python3")
	}
}

func TestLintScriptHostBash(t *testing.T) {
	r := mustParseOne(t, "^/bin/bash -c .+$\tK")
	if got := findID(Lint([]Rule{r}), "script-host"); got == nil {
		t.Errorf("expected script-host finding for bash")
	}
}

func TestLintScriptHostJqRaw(t *testing.T) {
	r := mustParseOne(t, "^/opt/homebrew/bin/jq -r .+$\tK")
	if got := findID(Lint([]Rule{r}), "script-host"); got == nil {
		t.Errorf("expected script-host finding for jq -r")
	}
}

func TestLintNonScriptHostDoesNotFire(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo .+$\tK")
	if got := findID(Lint([]Rule{r}), "script-host"); got != nil {
		t.Errorf("echo should not trip script-host; got %v", got)
	}
}

func TestLintScriptHostBlockedSpecificScript(t *testing.T) {
	r := mustParseOne(t, `^/usr/bin/python3 /Users/me/safe\.py( [^ ]+)*$`+"\tK")
	if got := findID(Lint([]Rule{r}), "script-host"); got != nil {
		t.Errorf("specific script path should not trip script-host; got %v", got)
	}
}

func TestLintUnescapedDotInPath(t *testing.T) {
	r := mustParseOne(t, "^/Users/me/.local/bin/foo .+$\tK")
	got := findID(Lint([]Rule{r}), "unescaped-dot")
	if got == nil {
		t.Fatalf("expected unescaped-dot finding; got %v", Lint([]Rule{r}))
	}
	if got.Severity != SeverityWarning {
		t.Errorf("Severity = %q, want WARNING", got.Severity)
	}
}

func TestLintEscapedDotDoesNotFire(t *testing.T) {
	r := mustParseOne(t, `^/Users/me/\.local/bin/foo .+$`+"\tK")
	if got := findID(Lint([]Rule{r}), "unescaped-dot"); got != nil {
		t.Errorf("escaped dot should not trip unescaped-dot; got %v", got)
	}
}

func TestLintNoDotDoesNotFire(t *testing.T) {
	r := mustParseOne(t, "^/usr/bin/echo .+$\tK")
	if got := findID(Lint([]Rule{r}), "unescaped-dot"); got != nil {
		t.Errorf("regex without literal dot should not trip; got %v", got)
	}
}

func TestLintDotInQuantifierDoesNotFire(t *testing.T) {
	r := mustParseOne(t, "^/bin/cat .+$\tK")
	if got := findID(Lint([]Rule{r}), "unescaped-dot"); got != nil {
		t.Errorf("trailing .+ should not trip unescaped-dot; got %v", got)
	}
}

func TestLintMultipleUnescapedDots(t *testing.T) {
	r := mustParseOne(t, "^/Users/me/.foo/.bar/baz$\tK")
	findings := Lint([]Rule{r})
	count := 0
	for _, f := range findings {
		if f.ID == "unescaped-dot" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 unescaped-dot finding (lint reports first hit per rule, not one per dot); got %d", count)
	}
}

func TestLintNoLabel(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo$\tK")
	got := findID(Lint([]Rule{r}), "no-label")
	if got == nil {
		t.Fatalf("expected no-label finding; got %v", Lint([]Rule{r}))
	}
	if got.Severity != SeverityInfo {
		t.Errorf("Severity = %q, want INFO", got.Severity)
	}
}

func TestLintLabelPresentDoesNotFire(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo$\tK\t# echo")
	if got := findID(Lint([]Rule{r}), "no-label"); got != nil {
		t.Errorf("rule with label should not trip no-label; got %v", got)
	}
}

func TestLintMultipleFindingsPerRule(t *testing.T) {
	r := mustParseOne(t, "^.+$\t*")
	findings := Lint([]Rule{r})
	wantIDs := map[string]bool{"trivial-match": false, "env-wildcard": false, "no-label": false}
	for _, f := range findings {
		if _, ok := wantIDs[f.ID]; ok {
			wantIDs[f.ID] = true
		}
	}
	for id, found := range wantIDs {
		if !found {
			t.Errorf("expected finding %q; got %v", id, findings)
		}
	}
}

func TestLintMultipleRulesIndependent(t *testing.T) {
	r1 := mustParseOne(t, "^/bin/echo$\tK\t# echo")
	r2 := mustParseOne(t, "^.*$\t*\t# yolo")
	findings := Lint([]Rule{r1, r2})
	for _, f := range findings {
		if f.Rule == r1.Raw {
			t.Errorf("clean rule produced finding: %v", f)
		}
	}
}

func TestLintEnvWildcard(t *testing.T) {
	r := mustParseOne(t, "^/usr/bin/curl .+$\t*\t# debug curl")
	got := findID(Lint([]Rule{r}), "env-wildcard")
	if got == nil {
		t.Fatalf("expected env-wildcard finding; got %v", Lint([]Rule{r}))
	}
	if got.Severity != SeverityWarning {
		t.Errorf("Severity = %q, want WARNING", got.Severity)
	}
}

func TestLintEnvWildcardEmptyDoesNotFire(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo$\t\t# no env")
	if got := findID(Lint([]Rule{r}), "env-wildcard"); got != nil {
		t.Errorf("empty env should not trip env-wildcard; got %v", got)
	}
}

func TestLintEnvWildcardSpecificDoesNotFire(t *testing.T) {
	r := mustParseOne(t, "^/bin/x$\tK1,K2")
	if got := findID(Lint([]Rule{r}), "env-wildcard"); got != nil {
		t.Errorf("specific env names should not trip env-wildcard; got %v", got)
	}
}

func findID(findings []Finding, id string) *Finding {
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i]
		}
	}
	return nil
}
