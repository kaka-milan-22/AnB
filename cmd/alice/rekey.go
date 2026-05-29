package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/kaka-milan-22/AnB/v2/internal/crypto"
	"github.com/kaka-milan-22/AnB/v2/internal/localvault"
)

// rekey-status — local inspection of vault.json's per-entry K version.
// No network call; doesn't know which K is "current" — see `bob list-keys`
// for that. Use this to confirm zero count for a K version before
// running `bob rotate-master-key --finalize <id>`.
func cmdRekeyStatus(args []string) error {
	fs := newFS("rekey-status")
	dir := dirFlag(fs)
	parse(fs, args)
	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}
	counts := map[int]int{}
	total := 0
	for _, e := range v.Secrets {
		ver, _, perr := crypto.ParseVersion(e.Value)
		if perr != nil {
			ver = -1 // malformed; bucket under -1
		}
		counts[ver]++
		total++
	}
	versions := make([]int, 0, len(counts))
	for v := range counts {
		versions = append(versions, v)
	}
	sort.Ints(versions)
	fmt.Printf("%-12s  %s\n", "K version", "Entries")
	for _, v := range versions {
		label := fmt.Sprintf("v%d", v)
		if v == -1 {
			label = "(malformed)"
		}
		fmt.Printf("%-12s  %d\n", label, counts[v])
	}
	fmt.Printf("%-12s  %d\n", "total", total)
	fmt.Println()
	fmt.Println("(Use `bob list-keys` to see Bob's current K version.)")
	return nil
}

// rekey — force-migrate every non-current vault entry to the current K.
// Implemented by simply asking Bob to decrypt every stored ciphertext;
// Bob's lazy-rewrap path returns the rewrapped value for any non-current
// entry, which we write back.
//
// Bob must be reachable + unlocked, and the identity must have authz on
// every key it tries to migrate. requireTTY so an agent doesn't trigger
// migration accidentally.
func cmdRekey(args []string) error {
	fs := newFS("rekey")
	dir := dirFlag(fs)
	reason := fs.String("reason", "[rekey]", `audit-only "why" string; logged in Bob's ALLOW line`)
	parse(fs, args)
	requireTTY("alice rekey")

	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}
	if len(v.Secrets) == 0 {
		fmt.Println("Vault is empty — nothing to rekey.")
		return nil
	}
	keys := make([]string, 0, len(v.Secrets))
	packed := make([]string, 0, len(v.Secrets))
	for k, e := range v.Secrets {
		keys = append(keys, k)
		packed = append(packed, e.Value)
	}
	cl, _, err := loadClient(s)
	if err != nil {
		return err
	}
	cl.SetReason(*reason)
	_, rewraps, derr := cl.DecryptMany(keys, packed)
	if derr != nil {
		return derr
	}
	n, werr := applyRewraps(s, keys, rewraps)
	if werr != nil {
		return werr
	}
	fmt.Fprintf(os.Stderr, "✓ Rekeyed: %d entr%s migrated to the current K (out of %d total).\n",
		n, plural2(n, "y", "ies"), len(keys))
	if n == 0 {
		fmt.Fprintln(os.Stderr, "  (everything already on current; nothing to do)")
	}
	return nil
}

// plural2 picks between two suffixes based on count. Tiny local helper
// because the existing plural() in safe.go only returns "" / "s".
func plural2(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}
