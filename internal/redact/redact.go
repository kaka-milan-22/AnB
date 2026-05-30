// Package redact is a faithful Go port of agent-vault's TypeScript redaction
// engine (src/redact.ts). It keeps the exact placeholder format
// `<agent-vault:key>` and `<agent-vault:UNVAULTED:sha256:<12hex>>`, the same
// secret-pattern set, Shannon-entropy threshold, and English-bigram heuristic,
// so behavior matches the TS tool byte-for-byte where it counts.
package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"sort"
	"strings"
)

const (
	unvaultedPrefixLen   = 12
	highEntropyThreshold = 3.0
	highEntropyMinLength = 12
	englishBigramHitRate = 0.3
	placeholderPrefix    = "<agent-vault:"
)

var (
	// Key group is lowercase alnum+hyphens, so this never matches the uppercase
	// UNVAULTED placeholders — the two are disjoint.
	placeholderRE = regexp.MustCompile(`<agent-vault:([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)>`)
	unvaultedRE   = regexp.MustCompile(`<agent-vault:UNVAULTED:sha256:([a-f0-9]{8,16})>`)

	// looseAngleRE matches anything that looks like a placeholder (`<…>`
	// with a non-empty body, no embedded `>`). Used by FindSuspiciousPlaceholders
	// to spot near-misses: a value that contains `<foo>` but doesn't match
	// the strict `<agent-vault:KEY>` grammar is almost always a typo, not
	// an intentional literal.
	looseAngleRE = regexp.MustCompile(`<[^>]+>`)

	secretPatterns = compileAll([]string{
		`sk-[A-Za-z0-9_-]{20,}`,
		`sk-proj-[A-Za-z0-9_-]{20,}`,
		`sk-ant-[A-Za-z0-9_-]{20,}`,
		`gh[po]_[A-Za-z0-9_]{36,}`,
		`github_pat_[A-Za-z0-9_]{22,}`,
		`xox[bpas]-[A-Za-z0-9-]{10,}`,
		`sk_live_[A-Za-z0-9]{24,}`,
		`sk_test_[A-Za-z0-9]{24,}`,
		`pk_live_[A-Za-z0-9]{24,}`,
		`pk_test_[A-Za-z0-9]{24,}`,
		`AKIA[0-9A-Z]{16}`,
		`[0-9]{8,10}:[A-Za-z0-9_-]{35}`,
		`[0-9a-f]{40,}`,
		`[A-Za-z0-9+/]{32,}={0,2}`,
		`(?s)-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----`,
		`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`,
		`Bearer\s+[A-Za-z0-9_.-]{20,}`,
	})

	reEnvLine    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=\s*(.+)$`)
	reYamlLine   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*\s*:\s+(.+)$`)
	reJSONLine   = regexp.MustCompile(`"[^"]+"\s*:\s*"([^"]+)"`)
	reArrayObj   = regexp.MustCompile(`(?s)^\[.*\]$|^\{.*\}$`)
	reURL        = regexp.MustCompile(`(?i)^https?://`)
	reFilePath   = regexp.MustCompile(`^[~.]?/`)
	reAllUpper   = regexp.MustCompile(`^[A-Z]+$`)
	reAllDigits  = regexp.MustCompile(`^[0-9]+$`)
	reAllLetters = regexp.MustCompile(`^[a-zA-Z]+$`)
	reNonAlnum   = regexp.MustCompile(`[^a-zA-Z0-9]+`)
)

func compileAll(pats []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(pats))
	for i, p := range pats {
		out[i] = regexp.MustCompile(p)
	}
	return out
}

// Redact replaces known vault values and high-entropy unvaulted strings.
// secretValues maps plaintext value → vault key name (mirrors the TS Map).
func Redact(content string, secretValues map[string]string) string {
	result := content

	// Phase 1: replace known values, longest first (avoid partial overlaps).
	type kv struct{ val, key string }
	entries := make([]kv, 0, len(secretValues))
	for v, k := range secretValues {
		if v != "" {
			entries = append(entries, kv{v, k})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return len(entries[i].val) > len(entries[j].val) })
	for _, e := range entries {
		result = strings.ReplaceAll(result, e.val, placeholderPrefix+e.key+">")
	}

	// Phase 2: detect unvaulted high-entropy tokens.
	known := make(map[string]struct{}, len(secretValues))
	for v := range secretValues {
		known[v] = struct{}{}
	}
	return redactUnvaultedTokens(result, known)
}

func redactUnvaultedTokens(content string, known map[string]struct{}) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.Contains(line, placeholderPrefix) {
			continue
		}
		result := line
		for _, cand := range extractValueCandidates(line) {
			trimmed := stripQuotes(cand)
			if len(trimmed) < highEntropyMinLength {
				continue
			}
			if _, ok := known[trimmed]; ok {
				continue
			}
			if matchesSecretPattern(trimmed) || (isHighEntropy(trimmed) && !looksLikeNonSecret(trimmed)) {
				ph := placeholderPrefix + "UNVAULTED:sha256:" + sha256Prefix(trimmed) + ">"
				result = strings.Replace(result, cand, ph, 1)
			}
		}
		lines[i] = result
	}
	return strings.Join(lines, "\n")
}

func extractValueCandidates(line string) []string {
	var cands []string
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return cands
	}
	if m := reEnvLine.FindStringSubmatch(trimmed); m != nil {
		cands = append(cands, m[1])
	}
	if m := reYamlLine.FindStringSubmatch(trimmed); m != nil {
		cands = append(cands, m[1])
	}
	if m := reJSONLine.FindStringSubmatch(trimmed); m != nil {
		cands = append(cands, m[1])
	}
	return cands
}

// stripQuotes mirrors JS .trim().replace(/^["']|["'],?$/g, ""): strip one
// leading quote and one trailing quote (optionally followed by a comma).
func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 0 && (s[0] == '"' || s[0] == '\'') {
		s = s[1:]
	}
	if n := len(s); n >= 2 && s[n-1] == ',' && (s[n-2] == '"' || s[n-2] == '\'') {
		s = s[:n-2]
	} else if n >= 1 && (s[n-1] == '"' || s[n-1] == '\'') {
		s = s[:n-1]
	}
	return s
}

// --- Restore (for `write`) ---

type RestoreResult struct {
	Content  string
	Restored []string
	Missing  []string
}

// Restore replaces <agent-vault:key> placeholders via the get lookup. A key
// whose lookup returns ok=false is left in place and reported in Missing.
func Restore(content string, get func(key string) (string, bool)) RestoreResult {
	var restored, missing []string
	out := placeholderRE.ReplaceAllStringFunc(content, func(m string) string {
		key := placeholderRE.FindStringSubmatch(m)[1]
		val, ok := get(key)
		if !ok {
			missing = append(missing, key)
			return m
		}
		restored = append(restored, key)
		return val
	})
	return RestoreResult{Content: out, Restored: restored, Missing: missing}
}

// RestoreUnvaulted resolves UNVAULTED placeholders by matching sha256 prefixes
// against high-entropy tokens found in the existing on-disk file.
func RestoreUnvaulted(content, existingContent string) (out string, restoredCount int, unmatched []string) {
	type cand struct{ value, fullHash string }
	var candidates []cand
	seen := map[string]struct{}{}
	for _, line := range strings.Split(existingContent, "\n") {
		for _, c := range extractValueCandidates(line) {
			trimmed := stripQuotes(c)
			if len(trimmed) < highEntropyMinLength {
				continue
			}
			if _, ok := seen[trimmed]; ok {
				continue
			}
			if matchesSecretPattern(trimmed) || (isHighEntropy(trimmed) && !looksLikeNonSecret(trimmed)) {
				candidates = append(candidates, cand{trimmed, sha256Hex(trimmed)})
				seen[trimmed] = struct{}{}
			}
		}
	}
	out = unvaultedRE.ReplaceAllStringFunc(content, func(m string) string {
		hash := unvaultedRE.FindStringSubmatch(m)[1]
		for _, c := range candidates {
			if len(c.fullHash) >= len(hash) && c.fullHash[:len(hash)] == hash {
				restoredCount++
				return c.value
			}
		}
		unmatched = append(unmatched, hash)
		return m
	})
	return out, restoredCount, unmatched
}

// ExtractPlaceholders returns the distinct vault key names referenced.
func ExtractPlaceholders(content string) []string {
	var keys []string
	seen := map[string]struct{}{}
	for _, m := range placeholderRE.FindAllStringSubmatch(content, -1) {
		if _, ok := seen[m[1]]; !ok {
			seen[m[1]] = struct{}{}
			keys = append(keys, m[1])
		}
	}
	return keys
}

// IsValidPlaceholder reports whether s is a complete, well-formed
// `<agent-vault:KEY>` (or `<agent-vault:UNVAULTED:sha256:…>`) reference.
// Used by callers that need to disambiguate "this string IS a vault
// placeholder" from "this string just happens to contain `<…>`".
func IsValidPlaceholder(s string) bool {
	if s == "" {
		return false
	}
	return placeholderRE.FindString(s) == s || unvaultedRE.FindString(s) == s
}

// FindSuspiciousPlaceholders returns every `<…>` substring of content that
// is NOT a valid `<agent-vault:…>` reference. The intent is fail-closed
// safety on operator typos: `<my-key>` (missing the `agent-vault:` prefix),
// `<agent-vault: my-key>` (stray whitespace) and similar near-misses are
// otherwise indistinguishable from literal values and silently slip
// through to the child process. Callers should turn a non-empty return
// into a hard error.
//
// Pure literals with no `<…>` substring are NOT flagged — `LOG_LEVEL=debug`
// stays a valid env value.
func FindSuspiciousPlaceholders(content string) []string {
	var bad []string
	for _, m := range looseAngleRE.FindAllString(content, -1) {
		if !IsValidPlaceholder(m) {
			bad = append(bad, m)
		}
	}
	return bad
}

// --- entropy & heuristics ---

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := map[rune]int{}
	n := 0
	for _, c := range s {
		freq[c]++
		n++
	}
	var e float64
	for _, count := range freq {
		p := float64(count) / float64(n)
		e -= p * math.Log2(p)
	}
	return e
}

func isHighEntropy(s string) bool {
	if len(s) < highEntropyMinLength {
		return false
	}
	return shannonEntropy(s) >= highEntropyThreshold
}

func matchesSecretPattern(s string) bool {
	for _, p := range secretPatterns {
		if p.MatchString(s) {
			return true
		}
	}
	return false
}

func looksLikeNonSecret(s string) bool {
	if reArrayObj.MatchString(s) {
		return true
	}
	if reURL.MatchString(s) {
		return true
	}
	if reFilePath.MatchString(s) {
		return true
	}
	segs := reNonAlnum.Split(s, -1)
	nonEmpty := segs[:0]
	for _, seg := range segs {
		if seg != "" {
			nonEmpty = append(nonEmpty, seg)
		}
	}
	if len(nonEmpty) == 0 {
		return false
	}
	for _, seg := range nonEmpty {
		if !isWordLikeSegment(seg) {
			return false
		}
	}
	return true
}

func isWordLikeSegment(seg string) bool {
	if len(seg) <= 3 {
		return true
	}
	if reAllUpper.MatchString(seg) {
		return true
	}
	if reAllDigits.MatchString(seg) {
		return true
	}
	if reAllLetters.MatchString(seg) {
		return looksLikeEnglish(seg)
	}
	return false
}

func looksLikeEnglish(seg string) bool {
	s := strings.ToLower(seg)
	n := len(s) - 1
	if n <= 0 {
		return true
	}
	hits := 0
	for i := 0; i < n; i++ {
		if _, ok := commonBigrams[s[i:i+2]]; ok {
			hits++
		}
	}
	return float64(hits)/float64(n) >= englishBigramHitRate
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha256Prefix(s string) string { return sha256Hex(s)[:unvaultedPrefixLen] }

var commonBigrams = func() map[string]struct{} {
	list := []string{
		"th", "he", "in", "er", "an", "re", "on", "en", "at", "es",
		"ed", "te", "ti", "or", "st", "ar", "nd", "to", "nt", "is",
		"of", "it", "al", "as", "ha", "ng", "co", "se", "me", "de",
		"le", "ou", "no", "ne", "ea", "ri", "ro", "li", "ra", "io",
		"ic", "el", "la", "ve", "ta", "ce", "ma", "si", "om", "ur",
		"ec", "il", "ge", "lo", "ch", "so", "pr", "pe", "fo", "ca",
		"di", "be", "mo", "ag", "un", "us", "wi", "hi", "sh", "ac",
		"ad", "ol", "ab", "mi", "im", "id", "oo", "ke", "ki", "su",
		"po", "pa", "wa", "up", "do", "fi", "ho", "da", "fe", "vi",
		"ow", "am", "ut", "ni", "lu", "tr", "pl", "bl", "sp", "cr",
		"na", "ot", "ns", "ll", "ss", "wh", "ck", "gh", "ry", "ly",
		"ty", "ay", "ey",
	}
	m := make(map[string]struct{}, len(list))
	for _, b := range list {
		m[b] = struct{}{}
	}
	return m
}()
