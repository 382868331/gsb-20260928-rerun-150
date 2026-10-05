package vdex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Evidence is one disputed piece of material for an index. Verification
// outcome and evidence retention are independent: an arrival that does
// not pass (a bad leaf proof, a proof replayed at another position, or
// content contradicting what already verified) is never accepted, but
// its original bytes are never discarded either. Batch is the 1-based
// arrival order within the session; Basis names why the material was
// refused or judged contradictory.
type Evidence struct {
	Record json.RawMessage `json:"record"`
	Batch  uint64          `json:"batch"`
	Basis  string          `json:"basis"`
}

// Conflict preserves every side of contradictory material for one
// index. Accepted is the content that verified against the trusted
// root (with the batch that first delivered it); Disputed holds each
// distinct later arrival that disagrees with it. Repeat deliveries of
// the same disputed content are counted, not stored again, so evidence
// cannot grow without bound.
type Conflict struct {
	Index    uint64     `json:"index"`
	Accepted Evidence   `json:"accepted"`
	Disputed []Evidence `json:"disputed"`
	Repeats  int        `json:"repeats"`
}

// RefusedEvidence keeps material refused at batch level (a manifest that
// contradicts the pinned request) or at entry level (wrong position,
// malformed record, failed leaf proof, unrequested index). Index is nil
// for whole-batch refusals. The original record is retained whenever an
// entry-level payload exists. Batch is the first matching arrival; later
// arrivals with the same index, record and basis increment Repeats.
type RefusedEvidence struct {
	Index   *uint64         `json:"index,omitempty"`
	Record  json.RawMessage `json:"record,omitempty"`
	Batch   uint64          `json:"batch"`
	Basis   string          `json:"basis"`
	Repeats int             `json:"repeats,omitempty"`
}

// Session accumulates material for one fixed verification request.
// The request — required record set, dataset/version scope and trusted
// root — is pinned at construction and never changes afterwards, so
// out-of-order and duplicate deliveries cannot alter what is demanded.
// A session is one decision: to change the request, build a new
// session; a pass state never transfers to a different request.
type Session struct {
	req       Request
	batches   uint64
	verified  map[uint64]Evidence
	conflicts map[uint64]*Conflict
	refused   []RefusedEvidence
	dupes     int
}

// NewSession starts a verification decision for req. The trusted basis
// must be complete: without a trusted root the material could only
// prove its own self-consistency, which is not acceptance.
func NewSession(req Request) (*Session, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	return &Session{
		req:       req,
		verified:  map[uint64]Evidence{},
		conflicts: map[uint64]*Conflict{},
	}, nil
}

// Fingerprint identifies the decision this session embodies.
func (s *Session) Fingerprint() Hash { return s.req.Fingerprint() }

// Batches reports how many arrival batches have been folded in.
func (s *Session) Batches() uint64 { return s.batches }

// Add folds one arriving batch into the session. Batches whose manifest
// contradicts the pinned request are refused wholesale and kept as
// evidence; inside an acceptable batch, entries that fail their proof,
// were never requested, or contradict already verified content are
// likewise kept as evidence together with their original bytes,
// arrival batch and refusal basis. Only entries that verify against the
// trusted root extend the verified set. Add never returns an error:
// every outcome is reflected in Status.
func (s *Session) Add(pkg Package) {
	s.batches++
	batch := s.batches
	refuseBatch := func(basis string) {
		s.addRefused(nil, nil, batch, basis)
	}
	if pkg.Format != PackageFormat {
		refuseBatch(fmt.Sprintf("batch refused: unsupported package format %q", pkg.Format))
		return
	}
	if err := pkg.Manifest.validate(); err != nil {
		refuseBatch(fmt.Sprintf("batch refused: invalid manifest: %v", err))
		return
	}
	if pkg.Manifest.Dataset != s.req.Dataset || pkg.Manifest.Version != s.req.Version {
		refuseBatch(fmt.Sprintf(
			"batch refused: claims %s v%d, request pinned to %s v%d",
			pkg.Manifest.Dataset, pkg.Manifest.Version, s.req.Dataset, s.req.Version))
		return
	}
	if pkg.Manifest.Root != *s.req.Root {
		refuseBatch("batch refused: manifest root does not match the trusted root")
		return
	}
	seen := map[uint64]bool{}
	for _, e := range pkg.Entries {
		idx := e.Index
		refuseEntry := func(record json.RawMessage, basis string) {
			s.addRefused(&idx, record, batch, basis)
		}
		if e.Index != e.Proof.Index {
			refuseEntry(e.Record, fmt.Sprintf(
				"entry refused: wrapper index %d disagrees with proof index %d", e.Index, e.Proof.Index))
			continue
		}
		if seen[e.Index] {
			refuseEntry(e.Record, "entry refused: duplicated within one batch")
			continue
		}
		seen[e.Index] = true
		if !s.wants(e.Index) {
			refuseEntry(e.Record, "entry refused: not part of the required set")
			continue
		}
		normalized, err := compactJSON(e.Record)
		if err != nil {
			// Keep the bytes exactly as they arrived; they may not be
			// valid JSON but they are still disputed evidence.
			refuseEntry(e.Record, fmt.Sprintf("entry refused: invalid record JSON: %v", err))
			continue
		}
		if err := e.Proof.Verify(*s.req.Root, pkg.Manifest.LeafCount, normalized); err != nil {
			refuseEntry(e.Record, fmt.Sprintf("entry refused: leaf verification failed: %v", err))
			continue
		}
		ev := Evidence{Record: normalized, Batch: batch, Basis: "verified against trusted root"}
		if prev, ok := s.verified[e.Index]; ok {
			if bytes.Equal(prev.Record, normalized) {
				s.dupes++
				continue
			}
			ev.Basis = "contradicts already verified content at the same index"
			s.addDispute(e.Index, prev, ev)
			continue
		}
		s.verified[e.Index] = ev
	}
}

// addRefused keeps the first arrival of each distinct index, original
// record and refusal basis. Later identical arrivals only increment
// Repeats, so repeated invalid material cannot grow without bound.
func (s *Session) addRefused(index *uint64, record json.RawMessage, batch uint64, basis string) {
	for i := range s.refused {
		if sameRefusedEvidence(s.refused[i], index, record, basis) {
			s.refused[i].Repeats++
			return
		}
	}
	s.refused = append(s.refused, RefusedEvidence{
		Index:  index,
		Record: append(json.RawMessage(nil), record...),
		Batch:  batch,
		Basis:  basis,
	})
}

func sameRefusedEvidence(ev RefusedEvidence, index *uint64, record json.RawMessage, basis string) bool {
	if (ev.Index == nil) != (index == nil) || ev.Basis != basis || !sameArrivalRecord(ev.Record, record) {
		return false
	}
	return ev.Index == nil || *ev.Index == *index
}

func sameArrivalRecord(a, b json.RawMessage) bool {
	aCompact, aErr := compactJSON(a)
	bCompact, bErr := compactJSON(b)
	if aErr != nil || bErr != nil {
		return aErr != nil && bErr != nil && bytes.Equal(a, b)
	}
	return bytes.Equal(aCompact, bCompact)
}

// addDispute records contradictory content for an index. The verified
// side stays the accepted one; each distinct later payload and basis is
// kept once, and repeated copies only bump Repeats.
func (s *Session) addDispute(index uint64, accepted Evidence, later Evidence) {
	c := s.conflicts[index]
	if c == nil {
		c = &Conflict{Index: index, Accepted: accepted}
		s.conflicts[index] = c
	}
	for i := range c.Disputed {
		if bytes.Equal(c.Disputed[i].Record, later.Record) && c.Disputed[i].Basis == later.Basis {
			c.Repeats++
			return
		}
	}
	c.Disputed = append(c.Disputed, later)
}

func (s *Session) wants(index uint64) bool {
	for _, i := range s.req.Indices {
		if i == index {
			return true
		}
	}
	return false
}

// Status is a point-in-time report of one decision. The required set is
// partitioned without overlap into Verified, Missing and Conflicted.
// Complete is true only when every required record has verified against
// the trusted root and no contradictory or refused material is on
// record; anything less is a partial result, never a pass.
type Status struct {
	Complete   bool
	Verified   []uint64
	Missing    []uint64
	Conflicted []uint64
	Duplicates int
	Conflicts  []Conflict
	Refused    []RefusedEvidence
}

// Status reports progress without mutating the session.
func (s *Session) Status() Status {
	st := Status{
		Duplicates: s.dupes,
		Refused:    append([]RefusedEvidence(nil), s.refused...),
	}
	want := map[uint64]bool{}
	for _, i := range s.req.Indices {
		want[i] = true
	}
	for i := range want {
		if c, ok := s.conflicts[i]; ok {
			st.Conflicted = append(st.Conflicted, i)
			st.Conflicts = append(st.Conflicts, *c)
			continue
		}
		if _, ok := s.verified[i]; ok {
			st.Verified = append(st.Verified, i)
		} else {
			st.Missing = append(st.Missing, i)
		}
	}
	sort.Slice(st.Verified, func(a, b int) bool { return st.Verified[a] < st.Verified[b] })
	sort.Slice(st.Missing, func(a, b int) bool { return st.Missing[a] < st.Missing[b] })
	sort.Slice(st.Conflicted, func(a, b int) bool { return st.Conflicted[a] < st.Conflicted[b] })
	sort.Slice(st.Conflicts, func(a, b int) bool { return st.Conflicts[a].Index < st.Conflicts[b].Index })
	st.Complete = len(st.Missing) == 0 && len(st.Conflicted) == 0 && len(st.Refused) == 0
	return st
}

// Snapshot is the persistable progress of a session: which records of
// the pinned request have verified, plus every piece of disputed or
// refused evidence. It is bound to the request's fingerprint so it can
// never be replayed into a different decision.
type Snapshot struct {
	Fingerprint Hash                `json:"fingerprint"`
	Batches     uint64              `json:"batches"`
	Verified    map[uint64]Evidence `json:"verified"`
	Duplicates  int                 `json:"duplicates"`
	Conflicts   []Conflict          `json:"conflicts,omitempty"`
	Refused     []RefusedEvidence   `json:"refused,omitempty"`
}

// Snapshot captures verified progress and all retained evidence so a
// receiver can persist it and resume later instead of re-receiving
// everything.
func (s *Session) Snapshot() Snapshot {
	snap := Snapshot{
		Fingerprint: s.Fingerprint(),
		Batches:     s.batches,
		Verified:    map[uint64]Evidence{},
		Duplicates:  s.dupes,
		Refused:     append([]RefusedEvidence(nil), s.refused...),
	}
	for i, ev := range s.verified {
		snap.Verified[i] = ev
	}
	for _, c := range s.conflicts {
		snap.Conflicts = append(snap.Conflicts, *c)
	}
	sort.Slice(snap.Conflicts, func(a, b int) bool { return snap.Conflicts[a].Index < snap.Conflicts[b].Index })
	return snap
}

// Resume restores a session from a snapshot. The snapshot only applies
// to the exact request it was taken under: if the request has changed
// in any way — record set, scope or trusted basis — Resume refuses and
// the caller must start a new decision with NewSession. A stale pass
// state is never carried over.
func Resume(req Request, snap Snapshot) (*Session, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	if snap.Fingerprint != req.Fingerprint() {
		return nil, errors.New("snapshot belongs to a different request: changing the request starts a new decision")
	}
	s := &Session{
		req:       req,
		batches:   snap.Batches,
		verified:  map[uint64]Evidence{},
		conflicts: map[uint64]*Conflict{},
		dupes:     snap.Duplicates,
		refused:   dedupeRefused(snap.Refused),
	}
	for i, ev := range snap.Verified {
		if !s.wants(i) {
			return nil, fmt.Errorf("snapshot contains index %d outside the required set", i)
		}
		s.verified[i] = ev
	}
	for i := range snap.Conflicts {
		c := snap.Conflicts[i]
		if !s.wants(c.Index) {
			return nil, fmt.Errorf("snapshot contains conflict at index %d outside the required set", c.Index)
		}
		c = dedupeConflict(c)
		s.conflicts[c.Index] = &c
	}
	return s, nil
}

func dedupeRefused(in []RefusedEvidence) []RefusedEvidence {
	if len(in) < 2 {
		return in
	}
	out := make([]RefusedEvidence, 0, len(in))
	for _, ev := range in {
		found := false
		for i := range out {
			if sameRefusedEvidence(out[i], ev.Index, ev.Record, ev.Basis) {
				out[i].Repeats += ev.Repeats + 1
				found = true
				break
			}
		}
		if !found {
			if ev.Index != nil {
				idx := *ev.Index
				ev.Index = &idx
			}
			if ev.Record != nil {
				ev.Record = append(json.RawMessage(nil), ev.Record...)
			}
			out = append(out, ev)
		}
	}
	return out
}

func dedupeConflict(c Conflict) Conflict {
	if len(c.Disputed) < 2 {
		return c
	}
	out := make([]Evidence, 0, len(c.Disputed))
	repeats := c.Repeats
	for _, ev := range c.Disputed {
		found := false
		for i := range out {
			if sameArrivalRecord(out[i].Record, ev.Record) && out[i].Basis == ev.Basis {
				repeats++
				found = true
				break
			}
		}
		if !found {
			ev.Record = append(json.RawMessage(nil), ev.Record...)
			out = append(out, ev)
		}
	}
	c.Disputed = out
	c.Repeats = repeats
	return c
}
