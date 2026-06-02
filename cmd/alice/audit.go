package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/kaka-milan-22/AnB/v3/internal/localvault"
	"github.com/kaka-milan-22/AnB/v3/internal/strength"
)

// audit — local hygiene scan over stored metadata. No decryption, no Bob: it
// reads only what's already in vault.json. Flags three things:
//   - weak secrets (entropy in the "weak" tier, ~<28 bit)
//   - entries lagging the newest KEK generation seen locally
//   - entries with no strength metadata yet (need `alice backfill-meta`)
//
// Staleness is inferred from the highest keyEpoch present; for the
// authoritative current K version, see `bob list-keys` / `alice rekey-status`.
// --strict exits non-zero when any issue is found (handy in CI).
func cmdAudit(args []string) error {
	fs := newFS("audit")
	dir := dirFlag(fs)
	strict := fs.Bool("strict", false, "exit non-zero if any issue is found")
	parse(fs, args)
	s := localvault.Open(*dir)
	v, err := s.Load()
	if err != nil {
		return err
	}
	listing := v.List()
	if len(listing) == 0 {
		fmt.Println("Vault is empty — nothing to audit.")
		return nil
	}

	// Newest KEK generation seen locally; entries below it lag behind.
	maxEpoch := 0
	for _, l := range listing {
		if l.KeyEpoch > maxEpoch {
			maxEpoch = l.KeyEpoch
		}
	}

	var weak, stale, missing []localvault.Listing
	for _, l := range listing {
		if l.EntropyBits == 0 {
			missing = append(missing, l)
		} else if strength.Tier(l.EntropyBits) == "weak" {
			weak = append(weak, l)
		}
		if l.KeyEpoch != 0 && l.KeyEpoch < maxEpoch {
			stale = append(stale, l)
		}
	}

	fmt.Printf("Audited %d secret%s (local metadata only).\n", len(listing), plural(len(listing)))

	fmt.Println("\nWeak secrets (entropy in the weak tier, ~<28 bit):")
	if len(weak) == 0 {
		fmt.Println("  none")
	} else {
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		for _, l := range weak {
			fmt.Fprintf(tw, "  %s\t~%d bit\t%d bytes\n", l.Key, l.EntropyBits, l.LenBytes)
		}
		tw.Flush()
	}

	fmt.Printf("\nStale KEK (below the newest generation seen, v%d):\n", maxEpoch)
	if len(stale) == 0 {
		fmt.Println("  none")
	} else {
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		for _, l := range stale {
			fmt.Fprintf(tw, "  %s\tKEK v%d\n", l.Key, l.KeyEpoch)
		}
		tw.Flush()
		fmt.Println("  → run `alice rekey` to migrate them to the current K.")
	}

	fmt.Println("\nMissing strength metadata:")
	if len(missing) == 0 {
		fmt.Println("  none")
	} else {
		for _, l := range missing {
			fmt.Printf("  %s\n", l.Key)
		}
		fmt.Println("  → run `alice backfill-meta` to populate them.")
	}

	issues := len(weak) + len(stale) + len(missing)
	fmt.Printf("\nSummary: %d weak, %d stale, %d missing metadata.\n", len(weak), len(stale), len(missing))
	if *strict && issues > 0 {
		os.Exit(1)
	}
	return nil
}
