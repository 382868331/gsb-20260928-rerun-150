package vdex

import (
	"encoding/hex"
	"fmt"
	"sort"
)

// VerifyResult reports independent verification of a data package.
type VerifyResult struct {
	Valid bool
	// Identity of the receiver's trusted target (never taken from the package).
	Dataset  string
	Version  uint64
	Root     Hash
	Expected []uint64
	// Present indices carried by the package and how many anchored to Root.
	Present []uint64
	Matched int
	Errors  []string
}

// Expectation is the receiver's trusted target for an exchange. It must be
// learned over a trusted channel (publisher identity, sealed version
// directory, or out-of-band confirmation); the package itself can never
// supply it. Dataset and Version pin the named numbered release, Root pins
// its exact content, and Indices is the exact record set the receiver asked
// for. A subset package is valid only when it carries precisely that set,
// with every proof anchored to Root.
type Expectation struct {
	Dataset string
	Version uint64
	Root    Hash
	Indices []uint64
}

// VerifyPackage checks a package without any access to the publisher store.
// The receiver pins the target through want: dataset name, version number,
// trusted Merkle root, and the exact set of expected record indices.
// Self-reported values inside the package never replace these conditions.
//
// Each violated requirement gets its own error rather than merely checking
// that the surviving entries are individually valid: dataset, version and
// root mismatches, missing expected records, extra unrequested records,
// duplicated indices, tampered records, position replay, and entries
// spliced from another root all fail explicitly.
func VerifyPackage(pkg Package, want Expectation) VerifyResult {
	r := VerifyResult{
		Dataset:  want.Dataset,
		Version:  want.Version,
		Root:     want.Root,
		Expected: sortedDedup(want.Indices),
	}
	addErr := func(format string, args ...any) {
		r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
	}

	// The receiver must name the complete trusted target. An empty root would
	// otherwise silently fall back to trusting whatever the package carries.
	rootSet := false
	for _, b := range want.Root {
		if b != 0 {
			rootSet = true
			break
		}
	}
	if want.Dataset == "" || want.Version == 0 || !rootSet {
		addErr("receiver expectation incomplete: trusted dataset, version and root are all required")
	}

	if pkg.Format != PackageFormat {
		addErr("unsupported package format %q", pkg.Format)
	}
	if err := pkg.Manifest.validate(); err != nil {
		addErr("invalid manifest: %v", err)
	}

	// Bind the package's self-reported identity to the receiver's target.
	if pkg.Manifest.Dataset != want.Dataset {
		addErr("dataset name mismatch: package self-reports %q, receiver requires %q",
			pkg.Manifest.Dataset, want.Dataset)
	}
	if pkg.Manifest.Version != want.Version {
		addErr("version mismatch: package self-reports v%d, receiver requires v%d of %q",
			pkg.Manifest.Version, want.Version, want.Dataset)
	}
	if pkg.Manifest.Root != want.Root {
		addErr("root mismatch: package self-reports root %s, receiver requires %s for %q v%d",
			hex.EncodeToString(pkg.Manifest.Root[:]), hex.EncodeToString(want.Root[:]),
			want.Dataset, want.Version)
	}

	wanted := map[uint64]bool{}
	for _, i := range r.Expected {
		wanted[i] = true
	}

	seen := map[uint64]bool{}
	if !sort.SliceIsSorted(pkg.Entries, func(a, b int) bool {
		return pkg.Entries[a].Index < pkg.Entries[b].Index
	}) {
		addErr("package entries are not sorted by index")
	}
	for i, e := range pkg.Entries {
		if e.Index != e.Proof.Index {
			addErr("entry %d: wrapper index %d disagrees with proof index %d", i, e.Index, e.Proof.Index)
		}
		if seen[e.Index] {
			addErr("entry %d: duplicated index %d in package", i, e.Index)
		}
		seen[e.Index] = true
		r.Present = append(r.Present, e.Index)
		if !wanted[e.Index] {
			addErr("entry %d: extra record not part of the requested set %v", e.Index, r.Expected)
		}
		normalized, err := compactJSON(e.Record)
		if err != nil {
			addErr("entry %d: invalid record JSON: %v", e.Index, err)
			continue
		}
		// Anchor every proof to the trusted root. The package manifest's root
		// and leaf count are never authoritative on their own.
		if err := e.Proof.Verify(want.Root, pkg.Manifest.LeafCount, normalized); err != nil {
			addErr("entry %d: %v", e.Index, err)
		} else {
			r.Matched++
		}
	}

	// Missing expected records fail on their own: an empty package, or one
	// with requested entries deleted, cannot pass merely because no invalid
	// surviving entry remains to be reported.
	for _, i := range r.Expected {
		if !seen[i] {
			addErr("missing expected record at index %d (requested set %v)", i, r.Expected)
		}
	}

	r.Valid = len(r.Errors) == 0
	return r
}

func sortedDedup(in []uint64) []uint64 {
	set := map[uint64]bool{}
	for _, i := range in {
		set[i] = true
	}
	out := make([]uint64, 0, len(set))
	for i := range set {
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}
