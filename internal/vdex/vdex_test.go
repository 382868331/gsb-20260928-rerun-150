package vdex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustJSONL(records ...string) *bytes.Buffer {
	return bytes.NewBufferString(strings.Join(records, "\n") + "\n")
}

func sealTwoVersions(t *testing.T) (string, Manifest, Manifest) {
	t.Helper()
	dir := t.TempDir()
	store := NewStore(dir)
	m1, err := store.Seal("demo", mustJSONL(`{"id":1}`, `{"id":2}`, `{"id":1}`), 0, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	m2, err := store.Seal("demo", mustJSONL(`{"id":1}`, `{"id":2}`, `{"id":1}`, `{"id":3}`), 0, time.Unix(2, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return dir, m1, m2
}

func TestSealVersionsAndChain(t *testing.T) {
	_, m1, m2 := sealTwoVersions(t)
	if m1.Version != 1 || m2.Version != 2 {
		t.Fatalf("versions = %d,%d", m1.Version, m2.Version)
	}
	if m2.Prev == nil || *m2.Prev != m1.Root {
		t.Fatal("v2 must commit to v1 root")
	}
	if m1.Root == m2.Root {
		t.Fatal("adding a record must produce a new root")
	}
	if m1.LeafCount != 3 || m2.LeafCount != 4 {
		t.Fatal("unexpected leaf counts")
	}
}

func TestDuplicateContentHasDistinctLeaves(t *testing.T) {
	rec := []byte(`{"x":1}`)
	if LeafHash(0, rec) == LeafHash(2, rec) {
		t.Fatal("identical records at different positions must have distinct leaf hashes")
	}
	tree := NewTree([]Hash{LeafHash(0, rec), LeafHash(1, rec)})
	p0, _ := tree.Proof(0)
	p1, _ := tree.Proof(1)
	if err := p0.Verify(tree.Root(), 2, rec); err != nil {
		t.Fatal(err)
	}
	if err := p1.Verify(tree.Root(), 2, rec); err != nil {
		t.Fatal(err)
	}
}

func TestProofCannotMovePosition(t *testing.T) {
	rec := []byte(`{"x":1}`)
	tree := NewTree([]Hash{LeafHash(0, rec), LeafHash(1, rec)})
	p0, _ := tree.Proof(0)
	moved := p0
	moved.Index = 1
	if err := moved.Verify(tree.Root(), 2, rec); err == nil {
		t.Fatal("proof moved to another index must fail")
	}
}

func TestExtractAndVerify(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	store := NewStore(dir)
	pkg, err := store.Extract(2, []uint64{0, 2, 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg.Entries) != 2 {
		t.Fatalf("duplicate requests should de-duplicate, got %d", len(pkg.Entries))
	}
	m2, _ := store.LoadManifest(2)
	r := VerifyPackage(pkg, Expectation{Dataset: "demo", Version: 2, Root: m2.Root, Indices: []uint64{0, 2}})
	if !r.Valid {
		t.Fatalf("package should verify: %v", r.Errors)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	dir, m1, _ := sealTwoVersions(t)
	pkg, err := NewStore(dir).Extract(1, []uint64{1})
	if err != nil {
		t.Fatal(err)
	}
	pkg.Entries[0].Record = json.RawMessage(`{"id":999}`)
	r := VerifyPackage(pkg, Expectation{Dataset: "demo", Version: 1, Root: m1.Root, Indices: []uint64{1}})
	if r.Valid {
		t.Fatal("tampered record must fail")
	}
}

func TestVerifyDetectsCrossVersionSplice(t *testing.T) {
	dir, m1, _ := sealTwoVersions(t)
	store := NewStore(dir)
	pkg1, _ := store.Extract(1, []uint64{0})
	pkg2, _ := store.Extract(2, []uint64{3})
	pkg1.Entries = append(pkg1.Entries, pkg2.Entries...)
	r := VerifyPackage(pkg1, Expectation{Dataset: "demo", Version: 1, Root: m1.Root, Indices: []uint64{0, 3}})
	if r.Valid {
		t.Fatal("cross-version splice must fail")
	}
	assertErrContains(t, r, "entry 3")
}

func TestOldProofInvalidForNewVersion(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	store := NewStore(dir)
	m2, _ := store.LoadManifest(2)
	pkg1, _ := store.Extract(1, []uint64{0})
	pkg1.Manifest = m2
	r := VerifyPackage(pkg1, Expectation{Dataset: "demo", Version: 2, Root: m2.Root, Indices: []uint64{0}})
	if r.Valid {
		t.Fatal("old proofs must not validate under a new version root")
	}
}

func TestSealKeepsOldVersionAfterBadInput(t *testing.T) {
	dir, m1, _ := sealTwoVersions(t)
	store := NewStore(dir)
	bad := "{\"ok\":true}\nnot-json\n"
	_, err := store.Seal("demo", strings.NewReader(bad), 0, time.Unix(3, 0))
	if err == nil {
		t.Fatal("sealing invalid JSONL must fail")
	}
	latest, _ := store.LatestVersion()
	if latest != 2 {
		t.Fatalf("failed seal must not advance version, got %d", latest)
	}
	got, err := store.LoadManifest(1)
	if err != nil {
		t.Fatalf("load v1: %v", err)
	}
	if got.Root != m1.Root {
		t.Fatalf("root changed: m1=%x got=%x", m1.Root, got.Root)
	}
	if _, err := os.Stat(filepath.Join(store.versionDir(3) + ".tmp")); !os.IsNotExist(err) {
		t.Fatal("interrupted seal must clean up temp directory")
	}
}

func TestPackageRoundTripFile(t *testing.T) {
	dir, _, m2 := sealTwoVersions(t)
	pkg, _ := NewStore(dir).Extract(2, []uint64{3})
	path := filepath.Join(t.TempDir(), "pkg.json")
	if err := WritePackage(path, pkg); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPackage(path)
	if err != nil {
		t.Fatal(err)
	}
	r := VerifyPackage(got, Expectation{Dataset: "demo", Version: 2, Root: m2.Root, Indices: []uint64{3}})
	if !r.Valid {
		t.Fatalf("file round trip must verify: %v", r.Errors)
	}
}

func assertErrContains(t *testing.T, r VerifyResult, want string) {
	t.Helper()
	for _, e := range r.Errors {
		if strings.Contains(e, want) {
			return
		}
	}
	t.Fatalf("expected an error containing %q, got %v", want, r.Errors)
}

// The receiver's target is the trusted anchor: rewriting the dataset name or
// version inside the package must not let it pass.
func TestVerifyRejectsRenamedDataset(t *testing.T) {
	dir, m1, _ := sealTwoVersions(t)
	pkg, _ := NewStore(dir).Extract(1, []uint64{0, 1})
	pkg.Manifest.Dataset = "other-dataset"
	r := VerifyPackage(pkg, Expectation{Dataset: "demo", Version: 1, Root: m1.Root, Indices: []uint64{0, 1}})
	if r.Valid {
		t.Fatal("renamed dataset must fail")
	}
	assertErrContains(t, r, "dataset name mismatch")
}

func TestVerifyRejectsReplacedVersion(t *testing.T) {
	dir, m1, _ := sealTwoVersions(t)
	pkg, _ := NewStore(dir).Extract(1, []uint64{0, 1})
	pkg.Manifest.Version = 7
	r := VerifyPackage(pkg, Expectation{Dataset: "demo", Version: 1, Root: m1.Root, Indices: []uint64{0, 1}})
	if r.Valid {
		t.Fatal("rewritten version number must fail even when the root is untouched")
	}
	assertErrContains(t, r, "version mismatch")
}

func TestVerifyRejectsDifferentRoot(t *testing.T) {
	dir, _, m2 := sealTwoVersions(t)
	// Package genuinely comes from v1, but the receiver trusts v2 of the same
	// dataset: the self-reported v1 root must not substitute for it.
	pkg, _ := NewStore(dir).Extract(1, []uint64{0, 1})
	r := VerifyPackage(pkg, Expectation{Dataset: "demo", Version: 2, Root: m2.Root, Indices: []uint64{0, 1}})
	if r.Valid {
		t.Fatal("package anchored to another root must fail")
	}
	assertErrContains(t, r, "root mismatch")
}

func TestVerifyRejectsAllEntriesDeleted(t *testing.T) {
	dir, m1, _ := sealTwoVersions(t)
	pkg, _ := NewStore(dir).Extract(1, []uint64{0, 1, 2})
	pkg.Entries = nil
	r := VerifyPackage(pkg, Expectation{Dataset: "demo", Version: 1, Root: m1.Root, Indices: []uint64{0, 1, 2}})
	if r.Valid {
		t.Fatal("empty package must not verify against a non-empty request")
	}
	for _, i := range []uint64{0, 1, 2} {
		assertErrContains(t, r, fmt.Sprintf("missing expected record at index %d", i))
	}
}

func TestVerifyRejectsPartiallyMissingSubset(t *testing.T) {
	dir, _, m2 := sealTwoVersions(t)
	// Receiver asked for {0,2}; the package only carries {0}.
	pkg, _ := NewStore(dir).Extract(2, []uint64{0})
	r := VerifyPackage(pkg, Expectation{Dataset: "demo", Version: 2, Root: m2.Root, Indices: []uint64{0, 2}})
	if r.Valid {
		t.Fatal("subset missing a requested record must fail")
	}
	assertErrContains(t, r, "missing expected record at index 2")
}

func TestVerifyRejectsExtraEntry(t *testing.T) {
	dir, _, m2 := sealTwoVersions(t)
	pkg, _ := NewStore(dir).Extract(2, []uint64{0, 1})
	r := VerifyPackage(pkg, Expectation{Dataset: "demo", Version: 2, Root: m2.Root, Indices: []uint64{0}})
	if r.Valid {
		t.Fatal("unrequested extra record must fail")
	}
	assertErrContains(t, r, "extra record not part of the requested set")
}

func TestVerifyRejectsDuplicatedEntry(t *testing.T) {
	dir, _, m2 := sealTwoVersions(t)
	pkg, _ := NewStore(dir).Extract(2, []uint64{0})
	pkg.Entries = append(pkg.Entries, pkg.Entries[0])
	r := VerifyPackage(pkg, Expectation{Dataset: "demo", Version: 2, Root: m2.Root, Indices: []uint64{0}})
	if r.Valid {
		t.Fatal("duplicated entry must fail")
	}
	assertErrContains(t, r, "duplicated index 0")
}

func TestVerifyLegitSubsetPasses(t *testing.T) {
	dir, _, m2 := sealTwoVersions(t)
	// Any-order request, de-duplicated: the legitimate subset still passes.
	pkg, err := NewStore(dir).Extract(2, []uint64{3, 0, 3})
	if err != nil {
		t.Fatal(err)
	}
	r := VerifyPackage(pkg, Expectation{Dataset: "demo", Version: 2, Root: m2.Root, Indices: []uint64{3, 0, 3}})
	if !r.Valid {
		t.Fatalf("legit subset must verify: %v", r.Errors)
	}
	if r.Matched != 2 {
		t.Fatalf("matched = %d, want 2", r.Matched)
	}
}

func TestVerifyRejectsEmptyExpectation(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	pkg, _ := NewStore(dir).Extract(1, []uint64{0})
	if r := VerifyPackage(pkg, Expectation{}); r.Valid {
		t.Fatal("verification without a trusted target must fail")
	}
}
