// Package version centralises version-string formatting for the alice
// and bob CLIs. The version, commit hash and Go-version stamps come
// from runtime/debug.ReadBuildInfo, which Go 1.18+ embeds automatically
// in every binary. No ldflags / build-time -X tricks required.
package version

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
)

// Tagline is the one-liner that follows the version block. Kept as a
// const so usage() in cmd/alice and cmd/bob render the same wording.
const Tagline = "Keep your secrets hidden from AI agents."

// URL is the project's canonical landing page.
const URL = "https://github.com/kaka-milan-22/AnB"

// Print writes the formatted version block for the named tool to w.
func Print(w io.Writer, tool string) {
	fmt.Fprintln(w, Format(tool))
}

// Format returns the formatted version block as a single string.
// Exposed so callers (and tests) can capture it without re-formatting.
func Format(tool string) string {
	return format(tool, readBuildInfo())
}

// buildInfo is a testable subset of debug.BuildInfo. All fields are
// injected through readBuildInfo (production) or hand-built (tests).
type buildInfo struct {
	Version  string // module version: "v2.1.1", "(devel)", or "(unknown)"
	Revision string // VCS commit SHA, possibly empty
	Modified bool   // VCS dirty flag (set when working tree had local edits at build time)
	GoVer    string // e.g. "go1.26.3"
	OS       string // GOOS at build time
	Arch     string // GOARCH at build time
}

func readBuildInfo() buildInfo {
	bi := buildInfo{
		Version: "(unknown)",
		GoVer:   runtime.Version(),
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return bi
	}
	if info.Main.Version != "" {
		bi.Version = info.Main.Version
	} else {
		bi.Version = "(devel)"
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			bi.Revision = s.Value
		case "vcs.modified":
			bi.Modified = s.Value == "true"
		}
	}
	return bi
}

func format(tool string, bi buildInfo) string {
	parts := []string{}
	if bi.Revision != "" {
		rev := bi.Revision
		if len(rev) > 12 {
			rev = rev[:12]
		}
		if bi.Modified {
			rev += "-dirty"
		}
		parts = append(parts, "commit "+rev)
	}
	parts = append(parts, "built with "+bi.GoVer)
	parts = append(parts, bi.OS+"/"+bi.Arch)

	var sb strings.Builder
	sb.WriteString(tool)
	sb.WriteString(" ")
	sb.WriteString(bi.Version)
	sb.WriteString(" (")
	sb.WriteString(strings.Join(parts, ", "))
	sb.WriteString(")\n\n")
	sb.WriteString(Tagline)
	sb.WriteString("\n")
	sb.WriteString(URL)
	return sb.String()
}
