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
	if st.Complete {
		t.Fatal("a refused later arrival must block completion")
	}
	if len(st.Rejected) != 1 {
		t.Fatalf("forged replacement must be kept as refused evidence: %+v", st)
	}
	ev := st.Rejected[0]
	if string(ev.Record) != `{"id":999}` {
		t.Fatalf("the refused original content must be preserved, got %q", ev.Record)
	}
	if ev.Batch != 2 || ev.Index == nil || *ev.Index != 0 || ev.Reason == "" {
		t.Fatalf("evidence must record arrival batch, index and refusal basis: %+v", ev)
	}
	// Repeating the same forged delivery folds into one evidence entry.
	s.Add(forged)
	s.Add(forged)
	st = s.Status()
	if len(st.Rejected) != 1 || st.Rejected[0].Count != 3 {
		t.Fatalf("identical disputed material must not pile up: %+v", st.Rejected)
	}
	// Under one trusted root a second valid proof for the same index
	// with different content cannot be produced, so the conflict branch
	// is exercised directly: the session must preserve both sides.
	s3, _ := NewSession(sessionRequest(t, dir, 2, 0))
	s3.verified[0] = json.RawMessage(`{"id":777}`)
	s3.verifiedBatch[0] = 1
	s3.Add(pkg)
	st3 := s3.Status()
	if len(st3.Conflicts) != 1 {
		t.Fatalf("conflicting content must be recorded: %+v", st3)
	}
	c := st3.Conflicts[0]
	if string(c.Accepted) != `{"id":777}` || string(c.Rejected) != `{"id":1}` {
		t.Fatalf("both sides of the conflict must be preserved: %+v", c)
	}
	if c.AcceptedBatch == 0 || c.RejectedBatch == 0 || c.Reason == "" {
		t.Fatalf("conflict must record arrival batches and refusal basis: %+v", c)
	}
	if len(st3.Conflicted) != 1 || st3.Conflicted[0] != 0 {
		t.Fatalf("conflicted range must be reported exactly: %+v", st3)
	}
	if st3.Complete {
		t.Fatal("an unresolved conflict must block completion")
	}
	// The same dispute delivered again must not duplicate the evidence.
	s3.Add(pkg)
	if got := len(s3.Status().Conflicts); got != 1 {
		t.Fatalf("repeated identical conflict must fold, got %d entries", got)
	}
	if got := s3.Status().Conflicts[0].Count; got != 2 {
		t.Fatalf("folded conflict count = %d, want 2", got)
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
	if len(st.Rejected) == 0 || !strings.Contains(st.Rejected[0].Reason, "request pinned") {
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

func TestSessionResumeThenConflictStaysUndecided(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	store := NewStore(dir)
	req := sessionRequest(t, dir, 2, 0, 2)
	s, err := NewSession(req)
	if err != nil {
		t.Fatal(err)
	}
	// Partial delivery, persist, reopen and complete the set.
	pkgA, _ := store.Extract(2, []uint64{0})
	s.Add(pkgA)
	s2, err := Resume(req, s.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	pkgB, _ := store.Extract(2, []uint64{2})
	s2.Add(pkgB)
	if st := s2.Status(); !st.Complete {
		t.Fatalf("resumed session must complete: %+v", st)
	}
	// A different record for an already verified index, then its repeat.
	forged := pkgA
	forged.Entries = append([]Entry(nil), pkgA.Entries...)
	forged.Entries[0].Record = json.RawMessage(`{"id":555}`)
	s2.Add(forged)
	s2.Add(forged)
	st := s2.Status()
	if st.Complete {
		t.Fatal("disputed material must revoke the pass state")
	}
	if len(st.Verified) != 2 || len(st.Missing) != 0 {
		t.Fatalf("verified/missing ranges must stay exact: %+v", st)
	}
	if len(st.Rejected) != 1 || st.Rejected[0].Count != 2 {
		t.Fatalf("repeated dispute must fold into one evidence entry: %+v", st.Rejected)
	}
	if string(st.Rejected[0].Record) != `{"id":555}` || st.Rejected[0].Batch != 3 {
		t.Fatalf("disputed original and arrival batch must be kept: %+v", st.Rejected[0])
	}
	// Evidence survives another save/reopen cycle.
	s3, err := Resume(req, s2.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	st3 := s3.Status()
	if st3.Complete || len(st3.Rejected) != 1 || st3.Rejected[0].Count != 2 {
		t.Fatalf("evidence must survive resume: %+v", st3)
	}
}

func TestArchiveKeepsOldDecisionsQueryable(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	store := NewStore(dir)
	arch := NewArchive()

	req1 := sessionRequest(t, dir, 2, 0)
	s1, _ := NewSession(req1)
	pkg, _ := store.Extract(2, []uint64{0})
	s1.Add(pkg)
	d1 := arch.File(s1)
	if !d1.Status.Complete {
		t.Fatal("first decision should be a complete pass")
	}

	// A changed request is a new decision; the old one stays on record.
	req2 := sessionRequest(t, dir, 2, 0, 2)
	s2, _ := NewSession(req2)
	s2.Add(pkg)
	d2 := arch.File(s2)
	if d2.Status.Complete || len(d2.Status.Missing) != 1 {
		t.Fatalf("second decision must be partial: %+v", d2.Status)
	}

	old, ok := arch.Lookup(req1.Fingerprint())
	if !ok || !old.Status.Complete {
		t.Fatal("the old decision must remain queryable after the request changed")
	}
	if string(old.Snapshot.Verified[0]) != `{"id":1}` {
		t.Fatalf("old decision material must be preserved: %+v", old.Snapshot)
	}
	if got := len(arch.Decisions()); got != 2 {
		t.Fatalf("archive must hold both decisions, got %d", got)
	}
}
