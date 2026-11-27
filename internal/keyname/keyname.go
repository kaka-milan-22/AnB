// Package keyname defines the flat vault key used by Alice and Bob.
package keyname

import (
	"regexp"
	"strings"
)

const Default = "default"
const Component = `[a-z0-9](?:[a-z0-9-]*[a-z0-9])?`
const Pattern = Component + `(?:\.` + Component + `)?`

var valid = regexp.MustCompile("^" + Pattern + "$")
var component = regexp.MustCompile("^" + Component + "$")

func Valid(s string) bool          { return valid.MatchString(s) }
func ValidNamespace(s string) bool { return component.MatchString(s) }

// Canonical maps an explicit default qualifier to the historical storage/AAD key.
func Canonical(s string) string {
	ns, name, qualified := strings.Cut(s, ".")
	if qualified && ns == Default && !strings.Contains(name, ".") {
		return name
	}
	return s
}

func Split(s string) (namespace, name string) {
	if ns, key, ok := strings.Cut(s, "."); ok {
		return ns, key
	}
	return Default, s
}
