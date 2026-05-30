package aclrules

import (
	"errors"
	"os"
	"path/filepath"
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

func mustParseOne(t *testing.T, line string) Rule {
	t.Helper()
	rules, errs := Parse(strings.NewReader(line + "\n"))
	if len(errs) != 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule; got %d", len(rules))
	}
	return rules[0]
}

func TestMatchesExact(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo hello$\tKEY")
	if !r.Matches("/bin/echo hello", []string{"KEY"}) {
		t.Error("expected match")
	}
	if r.Matches("/bin/echo world", []string{"KEY"}) {
		t.Error("should not match different args")
	}
}

func TestMatchesAnchored(t *testing.T) {
	r := mustParseOne(t, "/bin/echo hello\tKEY")
	if r.Matches("XXX /bin/echo hello", []string{"KEY"}) {
		t.Error("implicit anchor: must not match leading prefix")
	}
	if r.Matches("/bin/echo hello YYY", []string{"KEY"}) {
		t.Error("implicit anchor: must not match trailing suffix")
	}
}

func TestMatchesWildcard(t *testing.T) {
	r := mustParseOne(t, "^/bin/echo .+$\tKEY")
	for _, s := range []string{"/bin/echo a", "/bin/echo a b c", "/bin/echo 'hello world'"} {
		if !r.Matches(s, []string{"KEY"}) {
			t.Errorf("expected match: %q", s)
		}
	}
	if r.Matches("/bin/echo", []string{"KEY"}) {
		t.Error("'.+' requires at least one trailing char (incl. space)")
	}
}

func TestMatchesEnvSubsetExact(t *testing.T) {
	r := mustParseOne(t, "^/bin/x$\tKEY")
	if !r.Matches("/bin/x", []string{"KEY"}) {
		t.Error("--env KEY should be allowed")
	}
	if !r.Matches("/bin/x", nil) {
		t.Error("no --env should be allowed (empty subset)")
	}
	if r.Matches("/bin/x", []string{"OTHER"}) {
		t.Error("--env OTHER should NOT be allowed")
	}
	if r.Matches("/bin/x", []string{"KEY", "OTHER"}) {
		t.Error("--env KEY,OTHER should NOT be allowed (OTHER not in set)")
	}
}

func TestMatchesEnvSubsetCsv(t *testing.T) {
	r := mustParseOne(t, "^/bin/x$\tK1,K2,K3")
	cases := []struct {
		env  []string
		want bool
	}{
		{nil, true},
		{[]string{"K1"}, true},
		{[]string{"K2"}, true},
		{[]string{"K1", "K3"}, true},
		{[]string{"K1", "K2", "K3"}, true},
		{[]string{"K4"}, false},
		{[]string{"K1", "K4"}, false},
	}
	for _, c := range cases {
		got := r.Matches("/bin/x", c.env)
		if got != c.want {
			t.Errorf("env=%v: got %v want %v", c.env, got, c.want)
		}
	}
}

func TestMatchesEnvEmpty(t *testing.T) {
	r := mustParseOne(t, "^/bin/x$\t")
	if !r.Matches("/bin/x", nil) {
		t.Error("no --env should match an empty env column")
	}
	if r.Matches("/bin/x", []string{"K"}) {
		t.Error("any --env should be denied with empty env column")
	}
}

func TestMatchesEnvAny(t *testing.T) {
	r := mustParseOne(t, "^/bin/x$\t*")
	if !r.Matches("/bin/x", nil) {
		t.Error("nil --env should match * column")
	}
	if !r.Matches("/bin/x", []string{"ANYTHING", "GOES"}) {
		t.Error("any --env should match * column")
	}
}

func TestMatchesRegexNoMatch(t *testing.T) {
	r := mustParseOne(t, "^/bin/x$\tKEY")
	if r.Matches("/bin/y", []string{"KEY"}) {
		t.Error("cmd /bin/y does not match /bin/x")
	}
}

func TestLoadFileMissing(t *testing.T) {
	rules, err := LoadFile(filepath.Join(t.TempDir(), "missing.rules"))
	if !errors.Is(err, ErrRulesMissing) {
		t.Fatalf("want ErrRulesMissing, got %v", err)
	}
	if rules != nil {
		t.Errorf("expected nil rules; got %v", rules)
	}
}

func TestLoadFileEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.rules")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadFile(path)
	if err != nil {
		t.Fatalf("want no error; got %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected zero rules; got %d", len(rules))
	}
}

func TestLoadFileValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.rules")
	body := "^/bin/echo .+$\tKEY\t# echo\n^/bin/bob list-keys$\t\t# bob\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadFile(path)
	if err != nil {
		t.Fatalf("want no error; got %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 rules; got %d", len(rules))
	}
}

func TestLoadFileRefusesParseErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.rules")
	body := "^/bin/[unclosed\tKEY\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFile(path)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
	if !strings.Contains(err.Error(), "line 1") {
		t.Errorf("error should reference line 1: %v", err)
	}
}

func TestLoadFileRefusesTrivialMatchEverything(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.rules")
	// .* anchored becomes ^(?:.*)$ which matches every string.
	body := "^.*$\t*\t# everything\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFile(path)
	if err == nil {
		t.Error("expected refusal for trivial-match-everything rule")
	}
	if !strings.Contains(err.Error(), "matches every") && !strings.Contains(err.Error(), "trivial") {
		t.Errorf("error should mention trivial-match: %v", err)
	}
}

func TestLoadFileAcceptsRealisticPermissive(t *testing.T) {
	// /bin/echo .+ is permissive but bounded — operator's call.
	dir := t.TempDir()
	path := filepath.Join(dir, "x.rules")
	body := "^/bin/echo .+$\t*\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadFile(path)
	if err != nil {
		t.Errorf("realistic permissive rule should load; got %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 rule; got %d", len(rules))
	}
}
