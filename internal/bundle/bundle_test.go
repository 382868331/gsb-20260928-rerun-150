package bundle

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vdx/internal/manifest"
	"vdx/internal/merkle"
)

func fixture(t *testing.T, n int, version uint64) (manifest.Manifest, [][]byte, *merkle.Tree, merkle.Hash) {
	t.Helper()
	recs := make([][]byte, n)
	leaves := make([]merkle.Hash, n)
	for i := 0; i < n; i++ {
		recs[i] = []byte(string(rune('a' + i)))
		leaves[i] = merkle.LeafHash("ds", version, uint64(i), recs[i])
	}
	tree := merkle.Build(leaves)
	root := tree.Root()
	m := manifest.Manifest{
		Schema:      manifest.ManifestSchema,
		DatasetID:   "ds",
		Version:     version,
		VersionID:   hex.EncodeToString(root[:]),
		RecordCount: uint64(n),
	}
	return m, recs, tree, root
}

func TestValidPartialBundle(t *testing.T) {
	m, recs, tree, root := fixture(t, 5, 1)
	dir := t.TempDir()
	if _, err := Create(m, recs, tree, 1, 4, dir); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(dir, "ds", 1, root)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("expected ok, got %v", res.Errors)
	}
	if res.VerifiedRecords != 3 {
		t.Fatalf("verified %d", res.VerifiedRecords)
	}
}

func TestTamperMissingAndSplice(t *testing.T) {
	m, recs, tree, root := fixture(t, 5, 1)
	dir := t.TempDir()
	if _, err := Create(m, recs, tree, 1, 4, dir); err != nil {
		t.Fatal(err)
	}

	// 1) Tamper with a record byte.
	tampered := filepath.Join(t.TempDir(), "t")
	copyDir(t, dir, tampered)
	data, _ := os.ReadFile(filepath.Join(tampered, RecordsFile))
	data[0] = 'Z'
	os.WriteFile(filepath.Join(tampered, RecordsFile), data, 0o644)
	res, _ := Verify(tampered, "ds", 1, root)
	if res.OK || !strings.Contains(strings.Join(res.Errors, ";"), "index 1") {
		t.Fatalf("tamper not reported: %+v", res)
	}

	// 2) Delete one record line without updating proofs => missing.
	missing := filepath.Join(t.TempDir(), "m")
	copyDir(t, dir, missing)
	lines, _ := os.ReadFile(filepath.Join(missing, RecordsFile))
	os.WriteFile(filepath.Join(missing, RecordsFile), lines[:len(lines)-2], 0o644)
	res, _ = Verify(missing, "ds", 1, root)
	if res.OK || !strings.Contains(strings.Join(res.Errors, ";"), "missing or extra records") {
		t.Fatalf("missing record not reported: %+v", res)
	}

	// 3) Move a proof to another line within the same package.
	moved := filepath.Join(t.TempDir(), "p")
	copyDir(t, dir, moved)
	pf, _ := os.ReadFile(filepath.Join(moved, ProofsFile))
	parts := strings.Split(strings.TrimRight(string(pf), "\n"), "\n")
	parts[0], parts[1] = parts[1], parts[0]
	os.WriteFile(filepath.Join(moved, ProofsFile), []byte(strings.Join(parts, "\n")+"\n"), 0o644)
	res, _ = Verify(moved, "ds", 1, root)
	if res.OK || !strings.Contains(strings.Join(res.Errors, ";"), "position moved") {
		t.Fatalf("moved proof not reported: %+v", res)
	}

	// 4) Cross-version splice: verify v1 bundle against v2 root.
	m2, recs2, tree2, root2 := fixture(t, 5, 2)
	_ = m2
	_ = recs2
	_ = tree2
	res, _ = Verify(dir, "ds", 2, root2)
	if res.OK {
		t.Fatalf("v1 package accepted against v2 root: %+v", res)
	}

	// 5) Different dataset id rejected.
	res, _ = Verify(dir, "other", 1, root)
	if res.OK {
		t.Fatal("cross-dataset bundle accepted")
	}
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(dst, 0o755)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
