package merkle

import "testing"

func mustProof(t *testing.T, tr *Tree, i uint64) Proof {
	t.Helper()
	p, err := tr.ProofFor(i)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInclusionAcrossSizes(t *testing.T) {
	dataset := "ds"
	for n := 1; n <= 20; n++ {
		version := uint64(3)
		recs := make([][]byte, n)
		leaves := make([]Hash, n)
		for i := range recs {
			recs[i] = []byte{byte(i), byte(n)}
			leaves[i] = LeafHash(dataset, version, uint64(i), recs[i])
		}
		tree := Build(leaves)
		root := tree.Root()
		for i := 0; i < n; i++ {
			p := mustProof(t, tree, uint64(i))
			p.Version = version
			if err := Verify(dataset, p, recs[i], root); err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
		}
	}
}

func TestDuplicateContentsGetDistinctIdentities(t *testing.T) {
	content := []byte(`"same record"`)
	h0 := LeafHash("ds", 1, 0, content)
	h1 := LeafHash("ds", 1, 1, content)
	if h0 == h1 {
		t.Fatal("identical content at different positions must hash differently")
	}
	var leaves [2]Hash
	leaves[0] = h0
	leaves[1] = h1
	tree := Build(leaves[:])
	root := tree.Root()
	p0 := mustProof(t, tree, 0)
	p0.Version = 1
	p1 := mustProof(t, tree, 1)
	p1.Version = 1
	if err := Verify("ds", p0, content, root); err != nil {
		t.Fatal(err)
	}
	// Moving proof p1 onto slot 0 (same content!) must not pass.
	p1Moved := p1
	p1Moved.Index = 0
	if err := Verify("ds", p1Moved, content, root); err == nil {
		t.Fatal("proof replayed at another position was accepted")
	}
}

func TestVersionBinding(t *testing.T) {
	content := []byte("hello")
	l1 := LeafHash("ds", 1, 0, content)
	l2 := LeafHash("ds", 2, 0, content)
	if l1 == l2 {
		t.Fatal("same record in different versions must hash differently")
	}
	r1 := Build([]Hash{l1}).Root()
	p := Proof{Index: 0, Total: 1, Version: 2}
	if err := Verify("ds", p, content, r1); err == nil {
		t.Fatal("proof from v2 verified against v1 root")
	}
	p.Version = 1
	if err := Verify("ds", p, content, r1); err != nil {
		t.Fatal(err)
	}
}

func TestTamperedContentFails(t *testing.T) {
	leaf := LeafHash("ds", 1, 0, []byte("a"))
	root := Build([]Hash{leaf}).Root()
	p := Proof{Index: 0, Total: 1, Version: 1}
	if err := Verify("ds", p, []byte("b"), root); err == nil {
		t.Fatal("tampered record verified")
	}
}

func TestEmptyAndOddPromotion(t *testing.T) {
	e := EmptyRoot("ds", 1)
	if e == EmptyRoot("ds", 2) {
		t.Fatal("empty roots must differ across versions")
	}
	recs := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	leaves := make([]Hash, 3)
	for i, r := range recs {
		leaves[i] = LeafHash("ds", 1, uint64(i), r)
	}
	tree := Build(leaves)
	root := tree.Root()
	p := mustProof(t, tree, 2)
	p.Version = 1
	if err := Verify("ds", p, recs[2], root); err != nil {
		t.Fatalf("odd-promoted leaf: %v", err)
	}
}
