package vdex

import (
	"fmt"
	"sort"
)

// VerifyResult reports independent verification of a data package.
type VerifyResult struct {
	Valid     bool
	Dataset   string
	Version   uint64
	Root      Hash
	LeafCount uint64
	Entries   int
	Errors    []string
}

// VerifyPackage checks a package without any access to the publisher store.
// It detects tampered records, missing duplicates (same record at distinct
// indices), position replay, and entries spliced from other versions.
func VerifyPackage(pkg Package) VerifyResult {
	r := VerifyResult{
		Dataset:   pkg.Manifest.Dataset,
		Version:   pkg.Manifest.Version,
		Root:      pkg.Manifest.Root,
		LeafCount: pkg.Manifest.LeafCount,
		Entries:   len(pkg.Entries),
	}
	addErr := func(format string, args ...any) {
		r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
	}
	if pkg.Format != PackageFormat {
		addErr("unsupported package format %q", pkg.Format)
	}
	if err := pkg.Manifest.validate(); err != nil {
		addErr("invalid manifest: %v", err)
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
		normalized, err := compactJSON(e.Record)
		if err != nil {
			addErr("entry %d: invalid record JSON: %v", e.Index, err)
			continue
		}
		if err := e.Proof.Verify(pkg.Manifest.Root, pkg.Manifest.LeafCount, normalized); err != nil {
			addErr("entry %d: %v", e.Index, err)
		}
	}
	r.Valid = len(r.Errors) == 0
	return r
}
