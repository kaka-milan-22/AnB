package authz

import "testing"

func TestNamespacePrefixes(t *testing.T) {
	p := Policy{Rules: map[string][]string{"alice": {"ci-", "kaka.api-", "stage."}, "admin": {"*"}}}
	for key, want := range map[string]bool{
		"ci-token": true, "ci-prod.token": false, "kaka.ci-token": false,
		"kaka.api-key": true, "kaka.other": false, "kaka2.api-key": false,
		"stage.eth": true, "stage": false,
	} {
		if got := p.Allowed("alice", key); got != want {
			t.Errorf("Allowed(%q) = %v, want %v", key, got, want)
		}
		if !p.Allowed("admin", key) {
			t.Errorf("wildcard denied %q", key)
		}
	}
}
