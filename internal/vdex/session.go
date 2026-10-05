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
	Index         uint64     `json:"index"`
	Accepted      Evidence   `json:"accepted"`
	Disputed      []Evidence `json:"disputed"`
	Repeats       int        `json:"repeats"`
	RepeatBatches []uint64   `json:"repeat_batches,omitempty"`
}

// RefusedEvidence keeps material refused at batch level (a manifest that
// contradicts the pinned request) or at entry level (wrong position,
// malformed record, failed leaf proof, unrequested index). Index is nil
// for whole-batch refusals. The original record is retained whenever an
// entry-level payload exists.
type RefusedEvidence struct {
	Index  *uint64         `json:"index,omitempty"`
	Record json.RawMessage `json:"record,omitempty"`
	// dedupKey is the canonical form of Record used to recognise repeat
	// arrivals across formatting changes (e.g. a snapshot round-trip);
	// it is recomputed on resume. Record keeps the first arrival's
	// original bytes while the key decides identity.
	dedupKey []byte `json:"-"`
	// Batch is the first batch that brought this exact (index, record,
	// basis) refusal; it is never overwritten by later repeats.
	Batch uint64 `json:"batch"`
	Basis string `json:"basis"`
	// Repeats counts later arrivals identical in index, original bytes
	// and refusal basis; RepeatBatches records their batches so the
	// arrival history is not lost. Distinct content always gets its own
	// RefusedEvidence entry.
	Repeats       int      `json:"repeats,omitempty"`
	RepeatBatches []uint64 `json:"repeat_batches,omitempty"`
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
		s.refuse(RefusedEvidence{Batch: batch, Basis: basis})
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
			s.refuse(RefusedEvidence{
				Index:  &idx,
				Record: append(json.RawMessage(nil), record...),
				Batch:  batch,
				Basis:  basis,
			})
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
			refuseEntry(normalized, fmt.Sprintf("entry refused: leaf verification failed: %v", err))
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

// refuse retains refused material with a fixed dedup boundary: the
// same index, identical original bytes and the same refusal basis are
// one piece of evidence no matter how often they arrive again. The
// first copy — with its original batch and trusted bytes — is kept, and
// every repeat is only counted with its arrival batch. Different
// content (or a different basis) is stored independently. Whole-batch
// refusals carry no index or record and dedup on their basis alone.
func (s *Session) refuse(in RefusedEvidence) {
	if len(in.Record) > 0 {
		if key, err := compactJSON(in.Record); err == nil {
			in.dedupKey = key
		} else {
			// Malformed JSON survives a snapshot byte-for-byte, so the
			// raw arrival bytes remain a stable identity key.
			in.dedupKey = append([]byte(nil), in.Record...)
		}
	}
	for i := range s.refused {
		r := &s.refused[i]
		if r.Basis != in.Basis || !sameRefusedIndex(r.Index, in.Index) {
			continue
		}
		if in.Index == nil || bytes.Equal(r.dedupKey, in.dedupKey) {
			r.Repeats++
			r.RepeatBatches = append(r.RepeatBatches, in.Batch)
			return
		}
	}
	s.refused = append(s.refused, in)
}

func sameRefusedIndex(a, b *uint64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// addDispute records contradictory content for an index. The verified
// side stays the accepted one; each distinct later payload is kept
// once, and repeated copies of the same payload only bump Repeats.
func (s *Session) addDispute(index uint64, accepted Evidence, later Evidence) {
	c := s.conflicts[index]
	if c == nil {
		c = &Conflict{Index: index, Accepted: accepted}
		s.conflicts[index] = c
	}
	laterKey, _ := compactJSON(later.Record)
	for i := range c.Disputed {
		existingKey, _ := compactJSON(c.Disputed[i].Record)
		if bytes.Equal(existingKey, laterKey) {
			c.Repeats++
			c.RepeatBatches = append(c.RepeatBatches, later.Batch)
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
		refused:   make([]RefusedEvidence, 0, len(snap.Refused)),
	}
	for _, r := range snap.Refused {
		if len(r.Record) > 0 {
			if key, err := compactJSON(r.Record); err == nil {
				r.dedupKey = key
			} else {
				r.dedupKey = append([]byte(nil), r.Record...)
			}
		}
		r.RepeatBatches = append([]uint64(nil), r.RepeatBatches...)
		s.refused = append(s.refused, r)
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
		c.Disputed = append([]Evidence(nil), c.Disputed...)
		c.RepeatBatches = append([]uint64(nil), c.RepeatBatches...)
		s.conflicts[c.Index] = &c
	}
	return s, nil
}
