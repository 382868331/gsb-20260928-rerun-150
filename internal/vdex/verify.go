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
type Request struct {
	Dataset string
	Version uint64
	// Root is the trusted version root, obtained from a source the
	// receiver already trusts. It is required: without it the package
	// only proves its own self-consistency, and verification must fail
	// rather than silently accept a root supplied by the material
	// under examination.
	Root *Hash
	// Indices is the exact set of record indices expected in the
	// package. Missing, extra and duplicated entries are all errors.
	Indices []uint64
}

// Fingerprint is the canonical identity of a request. Any change to the
// dataset, version, trusted root or required record set yields a new
// fingerprint, and therefore a new verification decision: a pass
// obtained under one fingerprint never carries over to another.
func (r Request) Fingerprint() Hash {
	uniq := map[uint64]bool{}
	var indices []uint64
	for _, i := range r.Indices {
		if !uniq[i] {
			uniq[i] = true
			indices = append(indices, i)
		}
	}
	sort.Slice(indices, func(a, b int) bool { return indices[a] < indices[b] })
	parts := [][]byte{[]byte(r.Dataset), u64Bytes(r.Version)}
	if r.Root != nil {
		parts = append(parts, r.Root[:])
	} else {
		parts = append(parts, []byte("no-trusted-root"))
	}
	for _, i := range indices {
		parts = append(parts, u64Bytes(i))
	}
	return hashDomain("vdex-request-v1", parts...)
}

// validateRequest enforces the trust boundary before any material is
// examined: the receiver must supply the trusted basis (dataset,
// version, root) and an unambiguous required record set.
func validateRequest(req Request) error {
	if req.Dataset == "" {
		return errors.New("request must name the trusted dataset")
	}
	if req.Version == 0 {
		return errors.New("request must name the trusted version")
	}
	if req.Root == nil {
		return errors.New("no trusted root: the package's self-declared manifest cannot vouch for itself")
	}
	seen := map[uint64]bool{}
	for _, i := range req.Indices {
		if seen[i] {
			return fmt.Errorf("request lists index %d more than once", i)
		}
		seen[i] = true
	}
	return nil
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
		addErr("no trusted root provided: the package only proves its own self-consistency")
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
