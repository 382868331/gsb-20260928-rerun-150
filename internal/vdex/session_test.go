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
	if len(st.Refused) == 0 {
		t.Fatal("forged replacement must be kept as refused evidence")
	}
	ev := st.Refused[0]
	if string(ev.Record) != `{"id":999}` || ev.Batch != 2 {
		t.Fatalf("refused evidence must keep the original bytes and arrival batch: %+v", ev)
	}
	if !strings.Contains(ev.Basis, "leaf verification failed") {
		t.Fatalf("refusal basis must explain the failed leaf check, got %q", ev.Basis)
	}
	// Under one trusted root a second valid proof for the same index
	// with different content cannot be produced, so the conflict branch
	// is exercised directly: the session must preserve both sides.
	s3, _ := NewSession(sessionRequest(t, dir, 2, 0))
	s3.verified[0] = Evidence{Record: json.RawMessage(`{"id":777}`), Batch: 1, Basis: "verified against trusted root"}
	s3.batches = 1
	s3.Add(pkg)
	st3 := s3.Status()
	if len(st3.Conflicts) != 1 {
		t.Fatalf("conflicting content must be recorded: %+v", st3)
	}
	c := st3.Conflicts[0]
	if string(c.Accepted.Record) != `{"id":777}` || len(c.Disputed) != 1 || string(c.Disputed[0].Record) != `{"id":1}` {
		t.Fatalf("both sides of the conflict must be preserved: %+v", c)
	}
	if c.Disputed[0].Batch != 2 || !strings.Contains(c.Disputed[0].Basis, "contradict") {
		t.Fatalf("disputed side must carry batch and basis: %+v", c.Disputed[0])
	}
	if len(st3.Conflicted) != 1 || st3.Conflicted[0] != 0 {
		t.Fatalf("conflicted index must be partitioned out of verified/missing: %+v", st3)
	}
	if len(st3.Verified) != 0 || len(st3.Missing) != 0 {
		t.Fatalf("a conflicted index is neither verified nor missing: %+v", st3)
	}
	if st3.Complete {
		t.Fatal("an unresolved conflict must block completion")
	}

	// Repeated deliveries of the same disputed content must not pile up
	// identical evidence forever.
	s3.Add(pkg)
	s3.Add(pkg)
	st3 = s3.Status()
	if len(st3.Conflicts[0].Disputed) != 1 || st3.Conflicts[0].Repeats != 2 {
		t.Fatalf("duplicate disputed material must be counted, not stored again: %+v", st3.Conflicts[0])
	}
	if len(st3.Conflicts[0].RepeatBatches) != 2 || st3.Conflicts[0].RepeatBatches[0] != 3 || st3.Conflicts[0].RepeatBatches[1] != 4 {
		t.Fatalf("disputed repeat batches must be recorded: %+v", st3.Conflicts[0])
	}

	// The dedup boundary survives a save/resume cycle even though the
	// snapshot re-formats the JSON bytes.
	s4, err := Resume(s3.req, s3.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	s4.Add(pkg)
	st4 := s4.Status()
	if len(st4.Conflicts[0].Disputed) != 1 || st4.Conflicts[0].Repeats != 3 || len(st4.Conflicts[0].RepeatBatches) != 3 {
		t.Fatalf("disputed dedup must survive persistence: %+v", st4.Conflicts[0])
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
	if len(st.Refused) == 0 || !strings.Contains(st.Refused[0].Basis, "request pinned") {
		t.Fatalf("refusal must name the pinned scope: %v", st.Refused)
	}
	if st.Refused[0].Batch != 1 {
		t.Fatalf("whole-batch refusal must record its arrival batch: %+v", st.Refused[0])
	}
}

// Identical refused material (same index, same original bytes, same
// basis) is stored once no matter how often it arrives, including after
// a save/resume cycle; distinct content stays independent and the
// decision can never return to a full pass while any refusal exists.
func TestSessionRefusedEvidenceDedupAcrossResume(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	store := NewStore(dir)
	req := sessionRequest(t, dir, 2, 0)
	s, _ := NewSession(req)
	good, _ := store.Extract(2, []uint64{0})
	s.Add(good)

	bad := good
	bad.Entries = append([]Entry(nil), good.Entries...)
	bad.Entries[0].Record = json.RawMessage(`{"id":999}`)
	s.Add(bad)

	// Save the partial (already disputed) state and reopen it.
	s2, err := Resume(req, s.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	s2.Add(bad)
	s2.Add(bad)
	st := s2.Status()
	if st.Complete {
		t.Fatal("refused material must keep blocking the pass")
	}
	if len(st.Refused) != 1 {
		t.Fatalf("repeated identical refusals must collapse to one: %+v", st.Refused)
	}
	ev := st.Refused[0]
	if ev.Batch != 2 || string(ev.Record) != `{"id":999}` {
		t.Fatalf("first batch and trusted original must be preserved: %+v", ev)
	}
	if ev.Repeats != 2 || len(ev.RepeatBatches) != 2 || ev.RepeatBatches[0] != 3 || ev.RepeatBatches[1] != 4 {
		t.Fatalf("repeat counts and arrival batches must be exact: %+v", ev)
	}

	// Repeated wrong-version batches dedup on the batch-level basis too.
	wrong, _ := store.Extract(1, []uint64{0})
	s2.Add(wrong)
	s2.Add(wrong)
	st = s2.Status()
	batchRefusals := 0
	for _, r := range st.Refused {
		if r.Index == nil {
			batchRefusals++
			if r.Repeats != 1 {
				t.Fatalf("identical batch refusals must be counted: %+v", r)
			}
		}
	}
	if batchRefusals != 1 {
		t.Fatalf("identical whole-batch refusals must collapse to one: %+v", st.Refused)
	}

	// After another resume the dedup boundary is unchanged.
	s3, err := Resume(req, s2.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	s3.Add(bad)
	st3 := s3.Status()
	if st3.Complete || len(st3.Refused) != 2 || st3.Refused[0].Repeats != 3 {
		t.Fatalf("dedup must survive persistence and keep blocking VALID: %+v", st3)
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
