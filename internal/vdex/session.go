package vdex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Evidence is refused material kept for audit, independent of the
// verification verdict. Whether a record passes verification and
// whether its content must be preserved are separate questions: an
// arrival that fails its proof is still kept — original content, the
// batch it arrived in, and the basis for refusal — so disputed
// material is never lost just because it was invalid. Identical
// repeat deliveries fold into Count instead of piling up copies.
type Evidence struct {
	Batch  int             `json:"batch"`
	Index  *uint64         `json:"index,omitempty"` // nil when a whole batch is refused
	Record json.RawMessage `json:"record,omitempty"`
	Reason string          `json:"reason"`
	Count  int             `json:"count"`
}

// Conflict preserves both sides of contradictory material for one
// index: the record already verified against the trusted root, and
// the later arrival that disagrees with it. Both originals are kept
// with the batch each side arrived in and the basis for rejecting
// the later one. Neither side is silently dropped; the conflict
// blocks completion until the receiver resolves it out of band (by
// starting a new decision with a corrected request). Identical
// repeat disputes fold into Count.
type Conflict struct {
	Index         uint64          `json:"index"`
	Accepted      json.RawMessage `json:"accepted"`
	AcceptedBatch int             `json:"accepted_batch"`
	Rejected      json.RawMessage `json:"rejected"`
	RejectedBatch int             `json:"rejected_batch"`
	Reason        string          `json:"reason"`
	Count         int             `json:"count"`
}

// Session accumulates material for one fixed verification request.
// The request — required record set, dataset/version scope and trusted
// root — is pinned at construction and never changes afterwards, so
// out-of-order and duplicate deliveries cannot alter what is demanded.
// A session is one decision: to change the request, build a new
// session; a pass state never transfers to a different request.
type Session struct {
	req           Request
	verified      map[uint64]json.RawMessage
	verifiedBatch map[uint64]int
	batches       int
	conflicts     []Conflict
	conflictSeen  map[string]int
	rejected      []Evidence
	rejectedSeen  map[string]int
	dupes         int
}

// NewSession starts a verification decision for req. The trusted basis
// must be complete: without a trusted root the material could only
// prove its own self-consistency, which is not acceptance.
func NewSession(req Request) (*Session, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	return &Session{
		req:           req,
		verified:      map[uint64]json.RawMessage{},
		verifiedBatch: map[uint64]int{},
		conflictSeen:  map[string]int{},
		rejectedSeen:  map[string]int{},
	}, nil
}

// Fingerprint identifies the decision this session embodies.
func (s *Session) Fingerprint() Hash { return s.req.Fingerprint() }

// refuse keeps refused material as evidence. Deliveries identical in
// index, content and refusal basis fold into the existing entry’s
// Count, so repeated junk cannot grow the evidence log without bound.
func (s *Session) refuse(ev Evidence) {
	ev.Count = 1
	key := evidenceKey(ev)
	if at, ok := s.rejectedSeen[key]; ok {
		s.rejected[at].Count++
		return
	}
	s.rejectedSeen[key] = len(s.rejected)
	s.rejected = append(s.rejected, ev)
}

func evidenceKey(ev Evidence) string {
	idx := "batch"
	if ev.Index != nil {
		idx = string(u64Bytes(*ev.Index))
	}
	return idx + "|" + string(ev.Record) + "|" + ev.Reason
}

func conflictKey(c Conflict) string {
	return string(u64Bytes(c.Index)) + "|" + string(c.Accepted) + "|" + string(c.Rejected)
}

// Add folds one arriving batch into the session. Batches whose manifest
// contradicts the pinned request are refused wholesale and kept as
// evidence; inside an acceptable batch, entries that fail their proof,
// were never requested, or contradict already verified content are
// likewise kept as evidence with their original content. Only entries
// that verify against the trusted root extend the verified set. Add
// never returns an error: every outcome is reflected in Status.
func (s *Session) Add(pkg Package) {
	s.batches++
	batch := s.batches
	refuseBatch := func(format string, args ...any) {
		s.refuse(Evidence{Batch: batch, Reason: fmt.Sprintf(format, args...)})
	}
	if pkg.Format != PackageFormat {
		refuseBatch("batch refused: unsupported package format %q", pkg.Format)
		return
	}
	if err := pkg.Manifest.validate(); err != nil {
		refuseBatch("batch refused: invalid manifest: %v", err)
		return
	}
	if pkg.Manifest.Dataset != s.req.Dataset || pkg.Manifest.Version != s.req.Version {
		refuseBatch("batch refused: claims %s v%d, request pinned to %s v%d",
			pkg.Manifest.Dataset, pkg.Manifest.Version, s.req.Dataset, s.req.Version)
		return
	}
	if pkg.Manifest.Root != *s.req.Root {
		refuseBatch("batch refused: manifest root does not match the trusted root")
		return
	}
	seen := map[uint64]bool{}
	for _, e := range pkg.Entries {
		idx := e.Index
		refuseEntry := func(format string, args ...any) {
			s.refuse(Evidence{
				Batch:  batch,
				Index:  &idx,
				Record: append(json.RawMessage(nil), e.Record...),
				Reason: fmt.Sprintf(format, args...),
			})
		}
		if e.Index != e.Proof.Index {
			refuseEntry("entry %d refused: wrapper index %d disagrees with proof index %d", e.Index, e.Index, e.Proof.Index)
			continue
		}
		if seen[e.Index] {
			refuseEntry("entry %d refused: duplicated within one batch", e.Index)
			continue
		}
		seen[e.Index] = true
		if !s.wants(e.Index) {
			refuseEntry("entry %d refused: not part of the required set", e.Index)
			continue
		}
		normalized, err := compactJSON(e.Record)
		if err != nil {
			refuseEntry("entry %d refused: invalid record JSON: %v", e.Index, err)
			continue
		}
		if err := e.Proof.Verify(*s.req.Root, pkg.Manifest.LeafCount, normalized); err != nil {
			refuseEntry("entry %d refused: %v", e.Index, err)
			continue
		}
		if prev, ok := s.verified[e.Index]; ok {
			if bytes.Equal(prev, normalized) {
				s.dupes++
				continue
			}
			c := Conflict{
				Index:         e.Index,
				Accepted:      prev,
				AcceptedBatch: s.verifiedBatch[e.Index],
				Rejected:      normalized,
				RejectedBatch: batch,
				Reason:        "later arrival verifies but contradicts the already verified record for this index",
				Count:         1,
			}
			key := conflictKey(c)
			if at, ok := s.conflictSeen[key]; ok {
				s.conflicts[at].Count++
				continue
			}
			s.conflictSeen[key] = len(s.conflicts)
			s.conflicts = append(s.conflicts, c)
			continue
		}
		s.verified[e.Index] = normalized
		s.verifiedBatch[e.Index] = batch
	}
}

func (s *Session) wants(index uint64) bool {
	for _, i := range s.req.Indices {
		if i == index {
			return true
		}
	}
	return false
}

// Status is a point-in-time report of one decision. Complete is true
// only when every required record has verified against the trusted root
// and no contradictory or refused material is on record; anything less
// is a partial result, never a pass. Verified, Missing and Conflicted
// are exact, disjoint views of the required index set.
type Status struct {
	Complete   bool       `json:"complete"`
	Verified   []uint64   `json:"verified"`
	Missing    []uint64   `json:"missing"`
	Conflicted []uint64   `json:"conflicted,omitempty"`
	Duplicates int        `json:"duplicates"`
	Conflicts  []Conflict `json:"conflicts,omitempty"`
	Rejected   []Evidence `json:"rejected,omitempty"`
}

// Status reports progress without mutating the session.
func (s *Session) Status() Status {
	st := Status{
		Duplicates: s.dupes,
		Conflicts:  append([]Conflict(nil), s.conflicts...),
		Rejected:   append([]Evidence(nil), s.rejected...),
	}
	inConflict := map[uint64]bool{}
	for _, c := range s.conflicts {
		inConflict[c.Index] = true
	}
	want := map[uint64]bool{}
	for _, i := range s.req.Indices {
		want[i] = true
	}
	for i := range want {
		if _, ok := s.verified[i]; ok {
			st.Verified = append(st.Verified, i)
		} else {
			st.Missing = append(st.Missing, i)
		}
		if inConflict[i] {
			st.Conflicted = append(st.Conflicted, i)
		}
	}
	sort.Slice(st.Verified, func(a, b int) bool { return st.Verified[a] < st.Verified[b] })
	sort.Slice(st.Missing, func(a, b int) bool { return st.Missing[a] < st.Missing[b] })
	sort.Slice(st.Conflicted, func(a, b int) bool { return st.Conflicted[a] < st.Conflicted[b] })
	st.Complete = len(st.Missing) == 0 && len(st.Conflicts) == 0 && len(st.Rejected) == 0
	return st
}

// Snapshot is the persistable progress of a session: which records of
// the pinned request have already verified, and the evidence gathered
// so far. It is bound to the request’s fingerprint so it can never be
// replayed into a different decision.
type Snapshot struct {
	Fingerprint   Hash                       `json:"fingerprint"`
	Verified      map[uint64]json.RawMessage `json:"verified"`
	VerifiedBatch map[uint64]int             `json:"verified_batch,omitempty"`
	Batches       int                        `json:"batches"`
	Duplicates    int                        `json:"duplicates"`
	Conflicts     []Conflict                 `json:"conflicts,omitempty"`
	Rejected      []Evidence                 `json:"rejected,omitempty"`
}

// Snapshot captures verified progress and preserved evidence so a
// receiver can persist it and resume later instead of re-verifying
// everything.
func (s *Session) Snapshot() Snapshot {
	snap := Snapshot{
		Fingerprint:   s.Fingerprint(),
		Verified:      map[uint64]json.RawMessage{},
		VerifiedBatch: map[uint64]int{},
		Batches:       s.batches,
		Duplicates:    s.dupes,
		Conflicts:     append([]Conflict(nil), s.conflicts...),
		Rejected:      append([]Evidence(nil), s.rejected...),
	}
	for i, rec := range s.verified {
		snap.Verified[i] = rec
	}
	for i, b := range s.verifiedBatch {
		snap.VerifiedBatch[i] = b
	}
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
		req:           req,
		verified:      map[uint64]json.RawMessage{},
		verifiedBatch: map[uint64]int{},
		batches:       snap.Batches,
		dupes:         snap.Duplicates,
		conflicts:     append([]Conflict(nil), snap.Conflicts...),
		conflictSeen:  map[string]int{},
		rejected:      append([]Evidence(nil), snap.Rejected...),
		rejectedSeen:  map[string]int{},
	}
	for i, rec := range snap.Verified {
		if !s.wants(i) {
			return nil, fmt.Errorf("snapshot contains index %d outside the required set", i)
		}
		s.verified[i] = rec
		s.verifiedBatch[i] = snap.VerifiedBatch[i]
	}
	for at, c := range s.conflicts {
		s.conflictSeen[conflictKey(c)] = at
	}
	for at, ev := range s.rejected {
		s.rejectedSeen[evidenceKey(ev)] = at
	}
	return s, nil
}
