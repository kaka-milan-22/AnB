package version

import (
	"strings"
	"testing"
)

func TestFormatIncludesAllStdFields(t *testing.T) {
	bi := buildInfo{
		Version:  "v2.1.1",
		Revision: "a27b81a8b9cdef012345",
		Modified: false,
		GoVer:    "go1.26.3",
		OS:       "darwin",
		Arch:     "arm64",
	}
	got := format("alice", bi)

	mustContain := []string{
		"alice",
		"v2.1.1",
		"a27b81a8b9cd", // 12-char commit truncation
		"go1.26.3",
		"darwin/arm64",
		"Keep your secrets hidden from AI agents.", // Tagline
		"https://github.com/kaka-milan-22/AnB",     // URL
	}
	for _, s := range mustContain {
		if !strings.Contains(got, s) {
			t.Errorf("output missing %q\n--- output ---\n%s\n--- end ---", s, got)
		}
	}
}

func TestFormatTruncatesLongCommit(t *testing.T) {
	bi := buildInfo{
		Version:  "v2.1.1",
		Revision: "abcdef1234567890abcdef1234567890abcdef12",
		GoVer:    "go1.26.3",
		OS:       "linux",
		Arch:     "amd64",
	}
	got := format("bob", bi)
	if !strings.Contains(got, "abcdef123456") {
		t.Errorf("commit not present at expected truncation: %q", got)
	}
	if strings.Contains(got, "abcdef1234567890a") {
		t.Errorf("commit not truncated to 12 chars: %q", got)
	}
}

func TestFormatMarksDirty(t *testing.T) {
	bi := buildInfo{
		Version:  "(devel)",
		Revision: "abcdef123456",
		Modified: true,
		GoVer:    "go1.26.3",
		OS:       "darwin",
		Arch:     "arm64",
	}
	got := format("alice", bi)
	if !strings.Contains(got, "abcdef123456-dirty") {
		t.Errorf("dirty marker missing or in wrong position: %q", got)
	}
}

func TestFormatOmitsCommitWhenAbsent(t *testing.T) {
	// Binaries built outside a VCS context have no vcs.revision.
	bi := buildInfo{
		Version: "v2.1.1",
		GoVer:   "go1.26.3",
		OS:      "darwin",
		Arch:    "arm64",
	}
	got := format("alice", bi)
	if strings.Contains(got, "commit ") {
		t.Errorf("output should not contain 'commit ' when Revision empty: %q", got)
	}
	// Should still have version + go + platform.
	for _, s := range []string{"v2.1.1", "go1.26.3", "darwin/arm64"} {
		if !strings.Contains(got, s) {
			t.Errorf("output missing %q: %s", s, got)
		}
	}
}

func TestFormatDevelVersion(t *testing.T) {
	bi := buildInfo{
		Version: "(devel)",
		GoVer:   "go1.26.3",
		OS:      "darwin",
		Arch:    "arm64",
	}
	got := format("alice", bi)
	if !strings.Contains(got, "(devel)") {
		t.Errorf("expected (devel) marker: %q", got)
	}
}

func TestTaglineAndURLAreExported(t *testing.T) {
	// usage() in cmd/alice and cmd/bob reference these constants
	// directly — the test locks them so future renames are caught.
	if Tagline != "Keep your secrets hidden from AI agents." {
		t.Errorf("Tagline drifted: %q", Tagline)
	}
	if URL != "https://github.com/kaka-milan-22/AnB" {
		t.Errorf("URL drifted: %q", URL)
	}
}

func TestPrintWritesFormattedString(t *testing.T) {
	var sb strings.Builder
	Print(&sb, "alice")
	got := sb.String()
	if !strings.Contains(got, "alice ") {
		t.Errorf("Print output missing tool name: %q", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("Print should append newline; got: %q", got)
	}
}

func TestReadBuildInfoReturnsKnownDefaults(t *testing.T) {
	// In the test binary, debug.ReadBuildInfo always succeeds but
	// Main.Version is "" (test binaries have no module version stamp).
	// Verify the fallback to "(devel)" fires.
	bi := readBuildInfo()
	if bi.GoVer == "" {
		t.Error("GoVer should be set from runtime.Version()")
	}
	if bi.OS == "" || bi.Arch == "" {
		t.Errorf("OS/Arch should be set from runtime constants; got OS=%q Arch=%q", bi.OS, bi.Arch)
	}
	// Version should be either a real version (when binary was tagged),
	// "(devel)" (when locally built without tag), or "(unknown)" (when
	// ReadBuildInfo unexpectedly fails). All three are acceptable.
	switch bi.Version {
	case "", "(unknown)":
		t.Errorf("Version should fall back to (devel) when Main.Version is empty; got %q", bi.Version)
	}
}
