package redact

import (
	"strings"
	"testing"
)

func TestRedactKnownValueAndRestore(t *testing.T) {
	secret := "hunter2-super-secret-token-value"
	vals := map[string]string{secret: "db-password"}
	in := "password = " + secret + "\n"
	out := Redact(in, vals)
	if strings.Contains(out, secret) {
		t.Fatalf("known secret not redacted: %q", out)
	}
	if !strings.Contains(out, "<agent-vault:db-password>") {
		t.Fatalf("missing placeholder: %q", out)
	}
	// restore brings it back
	r := Restore(out, func(k string) (string, bool) {
		if k == "db-password" {
			return secret, true
		}
		return "", false
	})
	if !strings.Contains(r.Content, secret) || len(r.Restored) != 1 {
		t.Fatalf("restore failed: %+v", r)
	}
}

func TestRestoreMissingKeyLeavesPlaceholder(t *testing.T) {
	r := Restore("x = <agent-vault:nope>\n", func(string) (string, bool) { return "", false })
	if len(r.Missing) != 1 || r.Missing[0] != "nope" {
		t.Fatalf("missing tracking: %+v", r)
	}
	if !strings.Contains(r.Content, "<agent-vault:nope>") {
		t.Fatalf("placeholder should be left intact: %q", r.Content)
	}
}

func TestUnvaultedPatternDetection(t *testing.T) {
	// An OpenAI-style key not in the vault should be flagged UNVAULTED.
	line := "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123456789\n"
	out := Redact(line, map[string]string{})
	if !strings.Contains(out, "<agent-vault:UNVAULTED:sha256:") {
		t.Fatalf("expected unvaulted detection: %q", out)
	}
}

func TestLowEntropyValueNotRedacted(t *testing.T) {
	line := "environment = production\n"
	out := Redact(line, map[string]string{})
	if strings.Contains(out, "UNVAULTED") {
		t.Fatalf("plain english value should not be flagged: %q", out)
	}
}

func TestRestoreUnvaultedRoundTrip(t *testing.T) {
	existing := "TOKEN=sk-abcdefghijklmnopqrstuvwxyz0123456789\n"
	redacted := Redact(existing, map[string]string{})
	if !strings.Contains(redacted, "UNVAULTED") {
		t.Fatalf("setup: expected redaction, got %q", redacted)
	}
	out, n, unmatched := RestoreUnvaulted(redacted, existing)
	if n != 1 || len(unmatched) != 0 {
		t.Fatalf("restoreUnvaulted: n=%d unmatched=%v", n, unmatched)
	}
	if !strings.Contains(out, "sk-abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Fatalf("value not restored from existing file: %q", out)
	}
}

func TestExtractPlaceholders(t *testing.T) {
	keys := ExtractPlaceholders("a=<agent-vault:foo> b=<agent-vault:bar> c=<agent-vault:foo>")
	if len(keys) != 2 || keys[0] != "foo" || keys[1] != "bar" {
		t.Fatalf("placeholders: %v", keys)
	}
}

func TestIsValidPlaceholder(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// Valid `<agent-vault:KEY>` references.
		{"<agent-vault:foo>", true},
		{"<agent-vault:my-api-key>", true},
		{"<agent-vault:a>", true},
		{"<agent-vault:UNVAULTED:sha256:abcdef12>", true},
		// Missing prefix — the most common typo, regression covered.
		{"<foo>", false},
		{"<my-api-key>", false},
		// Whitespace inside the body breaks the strict grammar.
		{"<agent-vault: foo>", false},
		{"<agent-vault:foo >", false},
		// Wrong charset in KEY.
		{"<agent-vault:FOO>", false},
		{"<agent-vault:foo_bar>", false},
		// Substring of a valid placeholder — IsValidPlaceholder requires the
		// entire string to be a placeholder, not just contain one.
		{"prefix<agent-vault:foo>", false},
		{"<agent-vault:foo>suffix", false},
		// Pure literals stay false.
		{"foo", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsValidPlaceholder(tc.in); got != tc.want {
			t.Errorf("IsValidPlaceholder(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestFindSuspiciousPlaceholders(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "missing agent-vault prefix is the canonical near-miss",
			in:   "<encipherr-key>",
			want: []string{"<encipherr-key>"},
		},
		{
			name: "valid placeholder is not suspicious",
			in:   "<agent-vault:encipherr-key>",
			want: nil,
		},
		{
			name: "mixed valid + invalid surfaces only the invalid one",
			in:   "<agent-vault:good> and <typo>",
			want: []string{"<typo>"},
		},
		{
			name: "pure literal with no angles passes through clean",
			in:   "LOG_LEVEL=debug",
			want: nil,
		},
		{
			name: "stray whitespace inside body — common copy-paste failure",
			in:   "<agent-vault: spaced>",
			want: []string{"<agent-vault: spaced>"},
		},
		{
			name: "empty input is clean",
			in:   "",
			want: nil,
		},
		{
			name: "multiple suspicious — all reported",
			in:   "<a> <b> <agent-vault:c>",
			want: []string{"<a>", "<b>"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FindSuspiciousPlaceholders(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("count: got %v want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("[%d]: got %q want %q (full: %v vs %v)", i, got[i], tc.want[i], got, tc.want)
				}
			}
		})
	}
}
