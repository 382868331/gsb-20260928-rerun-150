package vdex

import (
	"encoding/json"
	"strings"
	"testing"
)

func sessionRequest(t *testing.T, dir string, version uint64, indices ...uint64) Request {
	t.Helper()
	return Request{Dataset: "demo", Version: version, Root: rootOf(t, dir, version), Indices: indices}
}

func TestVerifyFailsWithoutTrustedRoot(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	pkg, err := NewStore(dir).Extract(2, []uint64{0})
	if err != nil {
		t.Fatal(err)
	}
	req := Request{Dataset: "demo", Version: 2, Indices: []uint64{0}}
	r := VerifyPackageAgainst(pkg, req)
	if r.Valid {
		t.Fatal("a genuine package must still fail when no trusted root is given")
	}
	if !hasErrorContaining(r, "no trusted root") {
		t.Fatalf("failure must name the missing trust basis, got %v", r.Errors)
	}
	if _, err := NewSession(req); err == nil {
		t.Fatal("NewSession must refuse a request without a trusted root")
	}
}

func TestSessionBatchedOutOfOrder(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	store := NewStore(dir)
	req := sessionRequest(t, dir, 2, 0, 2, 3)
	s, err := NewSession(req)
	if err != nil {
		t.Fatal(err)
	}
	// Batches arrive out of order: index 3 first, then 0 and 2.
	for _, batch := range [][]uint64{{3}, {0, 2}} {
		pkg, err := store.Extract(2, batch)
		if err != nil {
			t.Fatal(err)
		}
		s.Add(pkg)
	}
	st := s.Status()
	if !st.Complete {
		t.Fatalf("out-of-order batches must still complete: %+v", st)
	}
	if len(st.Verified) != 3 {
		t.Fatalf("verified = %v", st.Verified)
	}
}

func TestSessionPartialIsNotComplete(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	pkg, err := NewStore(dir).Extract(2, []uint64{0, 2})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(sessionRequest(t, dir, 2, 0, 2, 3))
	if err != nil {
		t.Fatal(err)
	}
	s.Add(pkg)
	st := s.Status()
	if st.Complete {
		t.Fatal("a partially delivered set must not complete")
	}
	if len(st.Verified) != 2 || len(st.Missing) != 1 || st.Missing[0] != 3 {
		t.Fatalf("partial progress must be exact: %+v", st)
	}
}

func TestSessionDuplicateResubmissionIsInert(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	pkg, err := NewStore(dir).Extract(2, []uint64{0, 2})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(sessionRequest(t, dir, 2, 0, 2))
	if err != nil {
		t.Fatal(err)
	}
	s.Add(pkg)
	s.Add(pkg) // identical batch delivered twice
	st := s.Status()
	if !st.Complete {
		t.Fatalf("duplicate delivery must not change the requirements: %+v", st)
	}
	if st.Duplicates != 2 {
		t.Fatalf("duplicates = %d, want 2", st.Duplicates)
	}
}

func TestSessionConflictKeepsBothSides(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	store := NewStore(dir)
	pkg, err := store.Extract(2, []uint64{0})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(sessionRequest(t, dir, 2, 0))
	if err != nil {
		t.Fatal(err)
	}
	s.Add(pkg)
	// A forged replacement fails its proof against the trusted root and
	// is kept as refused evidence.
	forged := pkg
	forged.Entries = append([]Entry(nil), pkg.Entries...)
	forged.Entries[0].Record = json.RawMessage(`{"id":999}`)
	s.Add(forged)
	st := s.Status()
	if len(st.Rejected) == 0 {
		t.Fatal("forged replacement must be kept as refused evidence")
	}
	// Under one trusted root a second valid proof for the same index
	// with different content cannot be produced, so the conflict branch
	// is exercised directly: the session must preserve both sides.
	s3, _ := NewSession(sessionRequest(t, dir, 2, 0))
	s3.verified[0] = json.RawMessage(`{"id":777}`)
	s3.Add(pkg)
	st3 := s3.Status()
	if len(st3.Conflicts) != 1 {
		t.Fatalf("conflicting content must be recorded: %+v", st3)
	}
	c := st3.Conflicts[0]
	if string(c.Accepted) != `{"id":777}` || string(c.Rejected) != `{"id":1}` {
		t.Fatalf("both sides of the conflict must be preserved: %+v", c)
	}
	if st3.Complete {
		t.Fatal("an unresolved conflict must block completion")
	}
}

func TestSessionRejectsBatchFromWrongVersion(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	store := NewStore(dir)
	s, err := NewSession(sessionRequest(t, dir, 2, 0))
	if err != nil {
		t.Fatal(err)
	}
	pkg1, err := store.Extract(1, []uint64{0})
	if err != nil {
		t.Fatal(err)
	}
	s.Add(pkg1)
	st := s.Status()
	if st.Complete || len(st.Verified) != 0 {
		t.Fatalf("material outside the pinned scope must not count: %+v", st)
	}
	if len(st.Rejected) == 0 || !strings.Contains(st.Rejected[0], "request pinned") {
		t.Fatalf("refusal must name the pinned scope: %v", st.Rejected)
	}
}

func TestSessionSnapshotResume(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	store := NewStore(dir)
	req := sessionRequest(t, dir, 2, 0, 2, 3)
	s, err := NewSession(req)
	if err != nil {
		t.Fatal(err)
	}
	pkgA, _ := store.Extract(2, []uint64{0, 2})
	s.Add(pkgA)
	if st := s.Status(); st.Complete || len(st.Verified) != 2 {
		t.Fatalf("expected partial progress: %+v", st)
	}
	snap := s.Snapshot()

	// Reopen and continue: only the missing batch is still required.
	s2, err := Resume(req, snap)
	if err != nil {
		t.Fatal(err)
	}
	pkgB, _ := store.Extract(2, []uint64{3})
	s2.Add(pkgB)
	if st := s2.Status(); !st.Complete {
		t.Fatalf("resumed session must complete: %+v", st)
	}

	// A changed request is a new decision: the old snapshot must not apply.
	changed := sessionRequest(t, dir, 2, 0, 2)
	if _, err := Resume(changed, snap); err == nil {
		t.Fatal("a snapshot must not carry progress into a different request")
	}
	changedRoot := sessionRequest(t, dir, 1, 0, 2, 3)
	if _, err := Resume(changedRoot, snap); err == nil {
		t.Fatal("changing the trusted basis must start a new decision")
	}
}
