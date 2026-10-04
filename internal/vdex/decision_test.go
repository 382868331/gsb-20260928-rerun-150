package vdex

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// Partial material is saved, the session is reopened, the remainder
// completes it, and then different content plus repeated copies arrive
// for the same index. The overall result must never show a full pass,
// and repeated disputed copies must not multiply the stored evidence.
func TestSessionReopenThenContradictionAcrossBatches(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	store := NewStore(dir)
	req := sessionRequest(t, dir, 2, 0, 2, 3)

	s, err := NewSession(req)
	if err != nil {
		t.Fatal(err)
	}
	part, _ := store.Extract(2, []uint64{0, 2})
	s.Add(part)
	snap := s.Snapshot()
	if snap.Batches != 1 {
		t.Fatalf("snapshot must remember batch count, got %d", snap.Batches)
	}

	// Reopen and finish the required set.
	s2, err := Resume(req, snap)
	if err != nil {
		t.Fatal(err)
	}
	rest, _ := store.Extract(2, []uint64{3})
	s2.Add(rest)
	if st := s2.Status(); !st.Complete {
		t.Fatalf("required set should complete after reopen: %+v", st)
	}

	// Later different content for index 0: it cannot pass the leaf
	// check, but the original must still be retained as evidence.
	conflictPkg, _ := store.Extract(2, []uint64{0})
	conflictPkg.Entries[0].Record = json.RawMessage(`{"id":42}`)
	s2.Add(conflictPkg)
	s2.Add(conflictPkg)
	st := s2.Status()
	if st.Complete {
		t.Fatal("later contradiction must revoke the full-pass appearance")
	}
	if len(st.Refused) != 2 {
		t.Fatalf("both invalid arrivals must be retained with their batches: %+v", st.Refused)
	}
	for i, ev := range st.Refused {
		if string(ev.Record) != `{"id":42}` || ev.Batch != uint64(i+3) {
			t.Fatalf("disputed original and arrival batch must survive: %+v", ev)
		}
		if !strings.Contains(ev.Basis, "leaf verification failed") {
			t.Fatalf("refusal basis must name the failed leaf check: %q", ev.Basis)
		}
	}
	if len(st.Verified) != 3 {
		t.Fatalf("the verified record set stays intact and auditable: %+v", st.Verified)
	}

	// Evidence survives another save/resume cycle.
	s3, err := Resume(req, s2.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	st3 := s3.Status()
	if st3.Complete || len(st3.Refused) != 2 {
		t.Fatalf("conflict evidence must survive persistence: %+v", st3)
	}
}

// Refused material (failing leaf proof) keeps its original content and
// blocks a pass; repeat copies of the same invalid payload are stored
// once as evidence per distinct arrival... here both arrivals remain
// distinct batches but only one disputed entry exists per conflict rule.
func TestInvalidLaterMaterialIsRetainedNotLost(t *testing.T) {
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
	s.Add(bad) // repeated invalid delivery

	st := s.Status()
	if st.Complete {
		t.Fatal("invalid later material must block the pass")
	}
	if len(st.Refused) != 2 {
		t.Fatalf("each refused arrival remains auditable with its batch: %+v", st.Refused)
	}
	for i, ev := range st.Refused {
		if string(ev.Record) != `{"id":999}` || ev.Batch != uint64(i+2) {
			t.Fatalf("original and batch must be retained: %+v", ev)
		}
		if !strings.Contains(ev.Basis, "leaf verification failed") {
			t.Fatalf("basis must name the leaf failure: %q", ev.Basis)
		}
	}
}

// Changing the request forms a new decision; the old request's material
// and conclusion stay archived and queryable.
func TestDecisionStoreKeepsOldDecisions(t *testing.T) {
	dir, _, _ := sealTwoVersions(t)
	store := NewStore(dir)
	ds := NewDecisionStore(filepath.Join(t.TempDir(), "decisions"))

	req := sessionRequest(t, dir, 2, 0, 2)
	s, resumed, err := ds.Open(req)
	if err != nil || resumed {
		t.Fatalf("first open must be fresh: %v resumed=%v", err, resumed)
	}
	pkg, _ := store.Extract(2, []uint64{0, 2})
	s.Add(pkg)
	dec, err := ds.Save(s)
	if err != nil || !dec.Complete {
		t.Fatalf("first decision should be a complete pass: %+v err=%v", dec, err)
	}

	// Modified request (different record set) is a brand-new decision.
	changed := sessionRequest(t, dir, 2, 0, 2, 3)
	s2, resumed, err := ds.Open(changed)
	if err != nil || resumed {
		t.Fatalf("changed request must not inherit the old pass: %v resumed=%v", err, resumed)
	}
	if st := s2.Status(); st.Complete || len(st.Missing) != 3 {
		t.Fatalf("new decision starts without the old conclusion: %+v", st)
	}
	if _, err := ds.Save(s2); err != nil {
		t.Fatal(err)
	}

	listed, err := ds.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 {
		t.Fatalf("both decisions must remain archived, got %d", len(listed))
	}
	oldPass, newOpen := false, false
	for _, d := range listed {
		if len(d.Request.Indices) == 2 && d.Complete {
			oldPass = true
		}
		if len(d.Request.Indices) == 3 && !d.Complete && len(d.Snapshot.Verified) == 0 {
			newOpen = true
		}
	}
	if !oldPass || !newOpen {
		t.Fatalf("old conclusion VALID and new decision INCOMPLETE must both survive: %+v", listed)
	}

	// Resuming the original request returns its preserved pass.
	again, resumed, err := ds.Open(req)
	if err != nil || !resumed {
		t.Fatalf("old decision must be reopenable: %v resumed=%v", err, resumed)
	}
	if st := again.Status(); !st.Complete || len(st.Verified) != 2 {
		t.Fatalf("old pass material must remain queryable: %+v", st)
	}
}
