package vdex

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Entry is one record with its inclusion proof inside a data package.
type Entry struct {
	Index  uint64          `json:"index"`
	Record json.RawMessage `json:"record"`
	Proof  Proof           `json:"proof"`
}

// Package is a self-contained, transport-independent subset of a version.
type Package struct {
	Format   string   `json:"format"`
	Manifest Manifest `json:"manifest"`
	Entries  []Entry  `json:"entries"`
}

const PackageFormat = "vdex-package-v1"

// Extract builds a package containing the requested indices of a version.
// Indices may be given in any order and repeated requests are de-duplicated;
// output is sorted by index so the package is deterministic.
func (s *Store) Extract(version uint64, indices []uint64) (Package, error) {
	m, err := s.LoadManifest(version)
	if err != nil {
		return Package{}, err
	}
	want := map[uint64]bool{}
	for _, i := range indices {
		if i >= m.LeafCount {
			return Package{}, fmt.Errorf("requested index %d out of range (leaf count %d)", i, m.LeafCount)
		}
		want[i] = true
	}

	records := make(map[uint64]json.RawMessage, len(want))
	if err := s.ReadRecords(version, func(i uint64, rec []byte) error {
		if want[i] {
			normalized, err := compactJSON(rec)
			if err != nil {
				return err
			}
			records[i] = normalized
		}
		return nil
	}); err != nil {
		return Package{}, err
	}
	for i := range want {
		if _, ok := records[i]; !ok {
			return Package{}, fmt.Errorf("sealed data missing record %d", i)
		}
	}

	var leaves []Hash
	if err := s.ReadRecords(version, func(i uint64, rec []byte) error {
		leaves = append(leaves, LeafHash(i, rec))
		return nil
	}); err != nil {
		return Package{}, err
	}
	tree := NewTree(leaves)
	pkg := Package{Format: PackageFormat, Manifest: m}
	sorted := make([]uint64, 0, len(want))
	for i := range want {
		sorted = append(sorted, i)
	}
	sort.Slice(sorted, func(a, b int) bool { return sorted[a] < sorted[b] })
	for _, i := range sorted {
		p, err := tree.Proof(i)
		if err != nil {
			return Package{}, err
		}
		pkg.Entries = append(pkg.Entries, Entry{Index: i, Record: records[i], Proof: p})
	}
	return pkg, nil
}

// WritePackage writes a package as an indented JSON file (atomic replace).
func WritePackage(path string, pkg Package) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadPackage loads a package from JSON.
func ReadPackage(path string) (Package, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Package{}, err
	}
	var pkg Package
	if err := json.Unmarshal(b, &pkg); err != nil {
		return Package{}, err
	}
	return pkg, nil
}
