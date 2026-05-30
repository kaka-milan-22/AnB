package aclrules

import (
	"strings"
	"testing"
)

func TestCanonicalizeSafeArgs(t *testing.T) {
	got := Canonicalize("/usr/bin/echo", []string{"hello", "world"})
	want := "/usr/bin/echo hello world"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeArgWithSpace(t *testing.T) {
	got := Canonicalize("/usr/bin/echo", []string{"hello world"})
	want := "/usr/bin/echo 'hello world'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeArgWithEmbeddedQuote(t *testing.T) {
	got := Canonicalize("/usr/bin/echo", []string{"it's"})
	want := `/usr/bin/echo 'it'\''s'`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeEmptyArg(t *testing.T) {
	got := Canonicalize("/usr/bin/echo", []string{""})
	want := "/usr/bin/echo ''"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeNoArgs(t *testing.T) {
	got := Canonicalize("/usr/bin/bob", nil)
	want := "/usr/bin/bob"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeCmdWithSpecial(t *testing.T) {
	got := Canonicalize("/path with space/tool", []string{"arg"})
	want := "'/path with space/tool' arg"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeArgWithGlobChars(t *testing.T) {
	got := Canonicalize("/bin/ls", []string{"*.txt"})
	want := "/bin/ls '*.txt'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeArgWithNewline(t *testing.T) {
	got := Canonicalize("/bin/printf", []string{"line1\nline2"})
	want := "/bin/printf 'line1\nline2'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeSafeCharsBoundary(t *testing.T) {
	// The "safe set" is [A-Za-z0-9_\-./:=@,]. Test each at boundaries.
	got := Canonicalize("/x", []string{"abc_DEF-123./:=@,"})
	want := "/x abc_DEF-123./:=@,"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeArgWithDollar(t *testing.T) {
	got := Canonicalize("/bin/echo", []string{"$HOME"})
	want := "/bin/echo '$HOME'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeCombined(t *testing.T) {
	got := Canonicalize(
		"/Users/bbwave03/.local/bin/encipherr",
		[]string{"encrypt", "file", "/tmp/has space.txt"},
	)
	want := "/Users/bbwave03/.local/bin/encipherr encrypt file '/tmp/has space.txt'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseEmpty(t *testing.T) {
	rules, errs := Parse(strings.NewReader(""))
	if len(rules) != 0 {
		t.Errorf("expected zero rules, got %d", len(rules))
	}
	if len(errs) != 0 {
		t.Errorf("expected zero errors, got %v", errs)
	}
}

func TestParseComments(t *testing.T) {
	body := "# this is a comment\n   # indented comment too\n\n\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(rules) != 0 || len(errs) != 0 {
		t.Errorf("expected nothing; got rules=%v errs=%v", rules, errs)
	}
}

func TestParseSingleRule(t *testing.T) {
	body := "^/bin/echo hello$\tENCIPHERR_KEY\t# echo hello\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.Raw != "^/bin/echo hello$\tENCIPHERR_KEY\t# echo hello" {
		t.Errorf("Raw mismatch: %q", r.Raw)
	}
	if r.LineNo != 1 {
		t.Errorf("LineNo: got %d want 1", r.LineNo)
	}
	if r.Label != "echo hello" {
		t.Errorf("Label: got %q want %q", r.Label, "echo hello")
	}
	if len(r.EnvAllow) != 1 || r.EnvAllow[0] != "ENCIPHERR_KEY" {
		t.Errorf("EnvAllow: got %v", r.EnvAllow)
	}
	if r.EnvAny {
		t.Errorf("EnvAny should be false")
	}
	if r.Regex == nil {
		t.Error("Regex should be compiled")
	}
}

func TestParseRuleNoEnv(t *testing.T) {
	body := "^/bin/bob list-keys$\t\t# bob list-keys\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if len(r.EnvAllow) != 0 {
		t.Errorf("EnvAllow should be empty; got %v", r.EnvAllow)
	}
	if r.EnvAny {
		t.Errorf("EnvAny should be false for empty (not '*')")
	}
}

func TestParseRuleNoLabel(t *testing.T) {
	body := "^/bin/bob list-keys$\tKEY\n"
	rules, _ := Parse(strings.NewReader(body))
	if len(rules) != 1 || rules[0].Label != "" {
		t.Errorf("expected empty label; got %q", rules[0].Label)
	}
}

func TestParseRuleRegexOnly(t *testing.T) {
	body := "^/bin/bob list-keys$\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if len(rules[0].EnvAllow) != 0 || rules[0].EnvAny {
		t.Errorf("missing env column should be no env allowed; got allow=%v any=%v",
			rules[0].EnvAllow, rules[0].EnvAny)
	}
}

func TestParseRuleEnvCsv(t *testing.T) {
	body := "^/bin/foo$\tKEY1, KEY2 ,KEY3\t# multi\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	want := []string{"KEY1", "KEY2", "KEY3"}
	got := rules[0].EnvAllow
	if len(got) != len(want) {
		t.Fatalf("len: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("EnvAllow[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestParseRuleEnvStar(t *testing.T) {
	body := "^/bin/foo$\t*\t# any env\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if !rules[0].EnvAny {
		t.Error("EnvAny should be true when env column is '*'")
	}
	if len(rules[0].EnvAllow) != 0 {
		t.Error("EnvAllow should be empty when EnvAny is set")
	}
}

func TestParseInvalidRegex(t *testing.T) {
	body := "^/bin/[unclosed\tKEY\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) == 0 {
		t.Error("expected parse error for invalid regex")
	}
	if len(rules) != 0 {
		t.Errorf("rules should not include invalid ones; got %v", rules)
	}
}

func TestParseInvalidEnvName(t *testing.T) {
	body := "^/bin/foo$\t1BAD-ENV\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) == 0 {
		t.Error("expected parse error for invalid env name")
	}
	if len(rules) != 0 {
		t.Errorf("rules should not include invalid ones; got %v", rules)
	}
}

func TestParseTooManyFields(t *testing.T) {
	body := "^/bin/foo$\tKEY\t# label\textra\n"
	_, errs := Parse(strings.NewReader(body))
	if len(errs) == 0 {
		t.Error("expected parse error for >3 tab-separated fields")
	}
}

func TestParseLabelMustStartWithHash(t *testing.T) {
	body := "^/bin/foo$\tKEY\tnot-a-comment\n"
	_, errs := Parse(strings.NewReader(body))
	if len(errs) == 0 {
		t.Error("expected parse error: field 3 must start with #")
	}
}

func TestParseAnchorImplicit(t *testing.T) {
	body := "/bin/echo .+\tKEY\n"
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	r := rules[0]
	if !r.Regex.MatchString("/bin/echo hello") {
		t.Error("should match /bin/echo hello")
	}
	if r.Regex.MatchString("XX /bin/echo hello") {
		t.Error("must NOT match XX /bin/echo hello (anchor is implicit)")
	}
}

func TestParseMultipleRulesAndComments(t *testing.T) {
	body := `# Header comment

# encipherr ops
^/Users/me/encipherr encrypt$	K1	# encipherr encrypt

# bob list-keys
^/Users/me/bob list-keys$		# bob

`
	rules, errs := Parse(strings.NewReader(body))
	if len(errs) != 0 {
		t.Fatalf("unexpected: %v", errs)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules; got %d", len(rules))
	}
	if rules[0].LineNo != 4 {
		t.Errorf("rules[0].LineNo: got %d want 4", rules[0].LineNo)
	}
	if rules[1].LineNo != 7 {
		t.Errorf("rules[1].LineNo: got %d want 7", rules[1].LineNo)
	}
}
