package vdex

import (
	"bytes"
	"encoding/json"
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
	req := Request{Dataset: "demo", Version: 2, Indices: []uint64{0, 2}}
	if r := VerifyPackageAgainst(pkg, req); !r.Valid {
		t.Fatalf("package should verify: %v", r.Errors)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	pkg, err := NewStore(dir).Extract(1, []uint64{1})
	if err != nil {
		t.Fatal(err)
	}
	pkg.Entries[0].Record = json.RawMessage(`{"id":999}`)
	req := Request{Dataset: "demo", Version: 1, Indices: []uint64{1}}
	if r := VerifyPackageAgainst(pkg, req); r.Valid {
		t.Fatal("tampered record must fail")
	}
}

func TestVerifyDetectsDatasetNameMismatch(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	pkg, err := NewStore(dir).Extract(1, []uint64{0})
	if err != nil {
		t.Fatal(err)
	}
	req := Request{Dataset: "other", Version: 1, Indices: []uint64{0}}
	r := VerifyPackageAgainst(pkg, req)
	if r.Valid {
		t.Fatal("dataset name mismatch must fail")
	}
	if !hasErrorContaining(r, "dataset mismatch") {
		t.Fatalf("failure must name the unmet requirement, got %v", r.Errors)
	}
}

func TestVerifyDetectsVersionSubstitution(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	store := NewStore(dir)
	pkg, err := store.Extract(1, []uint64{0})
	if err != nil {
		t.Fatal(err)
	}
	m2, err := store.LoadManifest(2)
	if err != nil {
		t.Fatal(err)
	}
	pkg.Manifest.Version = m2.Version
	pkg.Manifest.Root = m2.Root
	pkg.Manifest.LeafCount = m2.LeafCount
	req := Request{Dataset: "demo", Version: 2, Indices: []uint64{0}}
	r := VerifyPackageAgainst(pkg, req)
	if r.Valid {
		t.Fatal("v1 entries re-labelled as v2 must fail")
	}
	if !hasErrorContaining(r, "recomputed root") {
		t.Fatalf("failure must mention the root mismatch, got %v", r.Errors)
	}
}

func TestVerifyDetectsAllEntriesDeleted(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	pkg, err := NewStore(dir).Extract(1, []uint64{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	pkg.Entries = nil
	req := Request{Dataset: "demo", Version: 1, Indices: []uint64{0, 1}}
	r := VerifyPackageAgainst(pkg, req)
	if r.Valid {
		t.Fatal("deleting all entries must fail")
	}
	if !hasErrorContaining(r, "missing requested record at index 0") ||
		!hasErrorContaining(r, "missing requested record at index 1") {
		t.Fatalf("failure must list every missing record, got %v", r.Errors)
	}
}

func TestVerifyDetectsPartiallyMissing(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	pkg, err := NewStore(dir).Extract(2, []uint64{0, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	pkg.Entries = pkg.Entries[:2]
	req := Request{Dataset: "demo", Version: 2, Indices: []uint64{0, 2, 3}}
	r := VerifyPackageAgainst(pkg, req)
	if r.Valid {
		t.Fatal("a partially missing record set must fail")
	}
	if !hasErrorContaining(r, "missing requested record at index 3") {
		t.Fatalf("failure must identify the missing index, got %v", r.Errors)
	}
}

func TestVerifyDetectsExtraEntry(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	pkg, err := NewStore(dir).Extract(2, []uint64{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	req := Request{Dataset: "demo", Version: 2, Indices: []uint64{0}}
	r := VerifyPackageAgainst(pkg, req)
	if r.Valid {
		t.Fatal("unrequested extra entries must fail")
	}
	if !hasErrorContaining(r, "unexpected extra record at index 1") {
		t.Fatalf("failure must identify the extra index, got %v", r.Errors)
	}
}

func TestVerifyDetectsCrossVersionSplice(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	store := NewStore(dir)
	pkg1, _ := store.Extract(1, []uint64{0})
	pkg2, _ := store.Extract(2, []uint64{3})
	pkg1.Entries = append(pkg1.Entries, pkg2.Entries...)
	req := Request{Dataset: "demo", Version: 1, Indices: []uint64{0, 3}}
	r := VerifyPackageAgainst(pkg1, req)
	if r.Valid {
		t.Fatal("cross-version splice must fail")
	}
	if len(r.Errors) == 0 {
		t.Fatalf("spliced entry must fail its proof, got %v", r.Errors)
	}
}

func TestOldProofInvalidForNewVersion(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	store := NewStore(dir)
	m2, _ := store.LoadManifest(2)
	pkg1, _ := store.Extract(1, []uint64{0})
	pkg1.Manifest = m2
	req := Request{Dataset: "demo", Version: 2, Indices: []uint64{0}}
	if r := VerifyPackageAgainst(pkg1, req); r.Valid {
		t.Fatal("old proofs must not validate under a new version root")
	}
}

func TestVerifyDetectsRootPinMismatch(t *testing.T) {
	dir, m1, _ := sealTwoVersions(t)
	pkg, err := NewStore(dir).Extract(1, []uint64{0})
	if err != nil {
		t.Fatal(err)
	}
	other := m1.Root
	other[0] ^= 0xff
	req := Request{Dataset: "demo", Version: 1, Root: &other, Indices: []uint64{0}}
	if r := VerifyPackageAgainst(pkg, req); r.Valid {
		t.Fatal("package root differing from the trusted root must fail")
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
	dir, _, _ := sealTwoVersions(t)
	pkg, _ := NewStore(dir).Extract(2, []uint64{3})
	path := filepath.Join(t.TempDir(), "pkg.json")
	if err := WritePackage(path, pkg); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPackage(path)
	req := Request{Dataset: "demo", Version: 2, Indices: []uint64{3}}
	if err != nil || !VerifyPackageAgainst(got, req).Valid {
		t.Fatalf("file round trip must verify: %v", err)
	}
}

func hasErrorContaining(r VerifyResult, substr string) bool {
	for _, e := range r.Errors {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}
