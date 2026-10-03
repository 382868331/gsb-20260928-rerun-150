package vdex

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func sessionRequest(t *testing.T, root Hash, indices ...uint64) Request {
	t.Helper()
	return Request{Dataset: "demo", Version: 2, Root: &root, Indices: indices}
}

func TestNewSessionRequiresTrustedBasis(t *testing.T) {
	if _, err := NewSession(Request{Dataset: "demo", Version: 2, Indices: []uint64{0}}); err == nil {
		t.Fatal("a session without a trusted root must be rejected")
	} else if !strings.Contains(err.Error(), "trusted root is required") {
		t.Fatalf("error must name the missing trusted basis, got %v", err)
	}
}

func TestSessionBatchedOutOfOrder(t *testing.T) {
	dir, _, m2 := sealTwoVersions(t)
	store := NewStore(dir)
	req := sessionRequest(t, m2.Root, 0, 1, 2, 3)
	s, err := NewSession(req)
	if err != nil {
		t.Fatal(err)
	}
	// Batches arrive out of order; the requirement stays fixed.
	for _, batch := range [][]uint64{{2}, {3, 0}, {1}} {
		pkg, err := store.Extract(2, batch)
		if err != nil {
			t.Fatal(err)
		}
		s.AddPackage(pkg)
	}
	st := s.Status()
	if !st.Complete || st.Verified != 4 || len(st.Missing) != 0 {
		t.Fatalf("out-of-order batches must still complete: %+v", st)
	}
}

func TestSessionPartialIsNotComplete(t *testing.T) {
	dir, _, m2 := sealTwoVersions(t)
	store := NewStore(dir)
	req := sessionRequest(t, m2.Root, 0, 2, 3)
	s, err := NewSession(req)
	if err != nil {
		t.Fatal(err)
	}
	pkg, _ := store.Extract(2, []uint64{0, 2})
	s.AddPackage(pkg)
	st := s.Status()
	if st.Complete {
		t.Fatal("a partially delivered record set must not conclude")
	}
	if st.Verified != 2 || len(st.Missing) != 1 || st.Missing[0] != 3 {
		t.Fatalf("partial status must show verified progress and the missing index: %+v", st)
	}
}

func TestSessionDuplicateResubmission(t *testing.T) {
	dir, _, m2 := sealTwoVersions(t)
	store := NewStore(dir)
	req := sessionRequest(t, m2.Root, 0, 1)
	s, err := NewSession(req)
	if err != nil {
		t.Fatal(err)
	}
	pkg, _ := store.Extract(2, []uint64{0, 1})
	s.AddPackage(pkg)
	s.AddPackage(pkg) // exact re-delivery
	again, _ := store.Extract(2, []uint64{1})
	s.AddPackage(again) // subset re-delivery
	st := s.Status()
	if !st.Complete {
		t.Fatalf("duplicates must not break completion: %+v", st)
	}
	if st.Duplicates != 3 {
		t.Fatalf("duplicates = %d, want 3", st.Duplicates)
	}
	if len(st.Rejected) != 0 || len(st.Conflicts) != 0 {
		t.Fatalf("duplicates must not be errors or conflicts: %+v", st)
	}
}

func TestSessionConflictKeepsBothSides(t *testing.T) {
	dir, _, m2 := sealTwoVersions(t)
	store := NewStore(dir)
	req := sessionRequest(t, m2.Root, 0)
	s, err := NewSession(req)
	if err != nil {
		t.Fatal(err)
	}
	good, _ := store.Extract(2, []uint64{0})
	s.AddPackage(good)
	// A later batch contradicts the verified record: both contents
	// stay on file as evidence and the session cannot conclude.
	bad, _ := store.Extract(2, []uint64{0})
	bad.Entries[0].Record = json.RawMessage(`{"id":777}`)
	s.AddPackage(bad)
	st := s.Status()
	if st.Complete {
		t.Fatal("an open contradiction must block the overall conclusion")
	}
	if len(st.Conflicts) != 1 || st.Conflicts[0].Index != 0 {
		t.Fatalf("conflict must be recorded for index 0: %+v", st.Conflicts)
	}
	recs := st.Conflicts[0].Records
	if len(recs) != 2 {
		t.Fatalf("both sides of the contradiction must be retained, got %d", len(recs))
	}
	if string(recs[0]) != `{"id":1}` || string(recs[1]) != `{"id":777}` {
		t.Fatalf("evidence must keep both records in arrival order, got %s and %s", recs[0], recs[1])
	}
}

func TestSessionRejectsOutOfScope(t *testing.T) {
	dir, m1, m2 := sealTwoVersions(t)
	store := NewStore(dir)
	req := sessionRequest(t, m2.Root, 0)
	s, err := NewSession(req)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := store.Extract(1, []uint64{0}) // wrong version
	s.AddPackage(other)
	if len(s.Rejected) == 0 || !strings.Contains(s.Rejected[0], "outside the requested scope") {
		t.Fatalf("wrong-version package must be rejected, got %v", s.Rejected)
	}
	forged, _ := store.Extract(2, []uint64{0})
	forged.Manifest.Root = m1.Root // does not match the trusted root
	s.AddPackage(forged)
	if len(s.Rejected) != 2 || !strings.Contains(s.Rejected[1], "trusted root") {
		t.Fatalf("root-mismatched package must be rejected, got %v", s.Rejected)
	}
	extra, _ := store.Extract(2, []uint64{0, 1})
	s.AddPackage(extra)
	found := false
	for _, r := range s.Rejected {
		if strings.Contains(r, "index 1: outside the requested record set") {
			found = true
		}
	}
	if !found {
		t.Fatalf("unrequested entries must be rejected, got %v", s.Rejected)
	}
	if !s.Status().Complete {
		t.Fatal("rejections must not block completion by the valid entry")
	}
}

func TestSessionSaveAndResume(t *testing.T) {
	dir, _, m2 := sealTwoVersions(t)
	store := NewStore(dir)
	req := sessionRequest(t, m2.Root, 0, 1, 2)
	path := filepath.Join(t.TempDir(), "session.json")

	s, err := NewSession(req)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := store.Extract(2, []uint64{2})
	s.AddPackage(first)
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}

	resumed, err := LoadSession(path, req)
	if err != nil {
		t.Fatal(err)
	}
	if st := resumed.Status(); st.Complete || st.Verified != 1 {
		t.Fatalf("resumed session must keep partial progress: %+v", st)
	}
	rest, _ := store.Extract(2, []uint64{0, 1, 2})
	resumed.AddPackage(rest) // includes one duplicate of index 2
	st := resumed.Status()
	if !st.Complete || st.Duplicates != 1 {
		t.Fatalf("resumed session must complete with the remaining batches: %+v", st)
	}
}

func TestSessionRequestChangeIsNewDecision(t *testing.T) {
	dir, _, m2 := sealTwoVersions(t)
	store := NewStore(dir)
	req := sessionRequest(t, m2.Root, 0, 1)
	path := filepath.Join(t.TempDir(), "session.json")
	s, err := NewSession(req)
	if err != nil {
		t.Fatal(err)
	}
	pkg, _ := store.Extract(2, []uint64{0, 1})
	s.AddPackage(pkg)
	if !s.Status().Complete {
		t.Fatal("session should be complete before the request changes")
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	// Modifying the request afterwards must not inherit the pass state.
	changed := sessionRequest(t, m2.Root, 0, 1, 2)
	if _, err := LoadSession(path, changed); err == nil {
		t.Fatal("a changed request must not resume the old session")
	} else if !strings.Contains(err.Error(), "request changed") {
		t.Fatalf("error must explain the new decision, got %v", err)
	}
	fresh, err := NewSession(changed)
	if err != nil {
		t.Fatal(err)
	}
	if st := fresh.Status(); st.Complete || st.Verified != 0 {
		t.Fatalf("the new request starts from zero progress: %+v", st)
	}
}
