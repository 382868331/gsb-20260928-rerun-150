package vdex

import (
	"errors"
	"fmt"
	"sort"
)

// Request is the receiver-side expectation a package must satisfy.
// The package's self-declared manifest never substitutes for these
// conditions: the receiver states which dataset, version and record
// set they asked for, and verification binds the package to them.
//
// Root is the trust boundary and is mandatory: without an external
// trusted root the material only proves self-consistency, so
// verification must fail rather than derive trust from the package
// itself.
type Request struct {
	Dataset string `json:"dataset"`
	Version uint64 `json:"version"`
	// Root pins the exact trusted version root. It must come from a
	// source outside the package under verification.
	Root *Hash `json:"root,omitempty"`
	// Indices is the exact set of record indices expected in the
	// package. Missing, extra and duplicated entries are all errors.
	Indices []uint64 `json:"indices"`
}

// canonical returns the request with its record set normalized
// (sorted, de-duplicated), so that requests stating the same set in
// different orders are the same requirement.
func (r Request) canonical() Request {
	set := map[uint64]bool{}
	var idx []uint64
	for _, i := range r.Indices {
		if !set[i] {
			set[i] = true
			idx = append(idx, i)
		}
	}
	sort.Slice(idx, func(a, b int) bool { return idx[a] < idx[b] })
	return Request{Dataset: r.Dataset, Version: r.Version, Root: r.Root, Indices: idx}
}

// validate checks the request itself is well-formed and carries the
// trusted basis verification depends on.
func (r Request) validate() error {
	if r.Dataset == "" {
		return errors.New("request must name the trusted dataset")
	}
	if r.Version == 0 {
		return errors.New("request must name the trusted version")
	}
	if r.Root == nil {
		return errors.New("trusted root is required: the package's self-declared root cannot vouch for itself")
	}
	if len(r.Indices) == 0 {
		return errors.New("request must state the expected record set")
	}
	return nil
}

// sameRequirement reports whether two requests fix the same record set,
// scope and trusted basis. A request modified in any of these is a new
// decision and must not inherit earlier conclusions.
func sameRequirement(a, b Request) bool {
	ca, cb := a.canonical(), b.canonical()
	if ca.Dataset != cb.Dataset || ca.Version != cb.Version || len(ca.Indices) != len(cb.Indices) {
		return false
	}
	if (ca.Root == nil) != (cb.Root == nil) {
		return false
	}
	if ca.Root != nil && *ca.Root != *cb.Root {
		return false
	}
	for i := range ca.Indices {
		if ca.Indices[i] != cb.Indices[i] {
			return false
		}
	}
	return true
}

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

// VerifyPackageAgainst checks a package against the receiver's explicit
// request, without any access to the publisher store. It detects tampered
// records, dataset/version substitution, missing requested records,
// unexpected extra or duplicated entries, position replay, and entries
// spliced from other versions.
func VerifyPackageAgainst(pkg Package, req Request) VerifyResult {
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

	if pkg.Manifest.Dataset != req.Dataset {
		addErr("dataset mismatch: requested %q but package claims %q", req.Dataset, pkg.Manifest.Dataset)
	}
	if pkg.Manifest.Version != req.Version {
		addErr("version mismatch: requested v%d but package claims v%d", req.Version, pkg.Manifest.Version)
	}
	if req.Root == nil {
		addErr("trusted root is required: the package's self-declared root cannot vouch for itself")
	} else if pkg.Manifest.Root != *req.Root {
		addErr("root mismatch: package root does not match the trusted root")
	}

	want := map[uint64]bool{}
	for _, i := range req.Indices {
		if want[i] {
			addErr("request lists index %d more than once", i)
		}
		want[i] = true
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
		if !want[e.Index] {
			addErr("entry %d: unexpected extra record at index %d (not requested)", i, e.Index)
		}
		normalized, err := compactJSON(e.Record)
		if err != nil {
			addErr("entry %d: invalid record JSON: %v", e.Index, err)
			continue
		}
		if err := e.Proof.Verify(pkg.Manifest.Root, pkg.Manifest.LeafCount, normalized); err != nil {
			addErr("entry %d: %v", e.Index, err)
		}
	}
	for i := range want {
		if !seen[i] {
			addErr("missing requested record at index %d", i)
		}
	}
	r.Valid = len(r.Errors) == 0
	return r
}
