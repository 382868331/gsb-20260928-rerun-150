package vdex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Conflict preserves both sides of contradictory material for one
// index: the record already verified against the trusted root, and the
// later arrival that disagrees with it. Neither side is silently
// dropped; the conflict blocks completion until the receiver resolves
// it out of band (by starting a new decision with a corrected request).
type Conflict struct {
	Index    uint64          `json:"index"`
	Accepted json.RawMessage `json:"accepted"`
	Rejected json.RawMessage `json:"rejected"`
}

// Session accumulates material for one fixed verification request.
// The request — required record set, dataset/version scope and trusted
// root — is pinned at construction and never changes afterwards, so
// out-of-order and duplicate deliveries cannot alter what is demanded.
// A session is one decision: to change the request, build a new
// session; a pass state never transfers to a different request.
type Session struct {
	req       Request
	verified  map[uint64]json.RawMessage
	conflicts []Conflict
	rejected  []string
	dupes     int
}

// NewSession starts a verification decision for req. The trusted basis
// must be complete: without a trusted root the material could only
// prove its own self-consistency, which is not acceptance.
func NewSession(req Request) (*Session, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	return &Session{req: req, verified: map[uint64]json.RawMessage{}}, nil
}

// Fingerprint identifies the decision this session embodies.
func (s *Session) Fingerprint() Hash { return s.req.Fingerprint() }

// Add folds one arriving batch into the session. Batches whose manifest
// contradicts the pinned request are refused wholesale and kept as
// evidence; inside an acceptable batch, entries that fail their proof,
// were never requested, or contradict already verified content are
// likewise kept as evidence. Only entries that verify against the
// trusted root extend the verified set. Add never returns an error:
// every outcome is reflected in Status.
func (s *Session) Add(pkg Package) {
	if pkg.Format != PackageFormat {
		s.rejected = append(s.rejected, fmt.Sprintf("batch refused: unsupported package format %q", pkg.Format))
		return
	}
	if err := pkg.Manifest.validate(); err != nil {
		s.rejected = append(s.rejected, fmt.Sprintf("batch refused: invalid manifest: %v", err))
		return
	}
	if pkg.Manifest.Dataset != s.req.Dataset || pkg.Manifest.Version != s.req.Version {
		s.rejected = append(s.rejected, fmt.Sprintf(
			"batch refused: claims %s v%d, request pinned to %s v%d",
			pkg.Manifest.Dataset, pkg.Manifest.Version, s.req.Dataset, s.req.Version))
		return
	}
	if pkg.Manifest.Root != *s.req.Root {
		s.rejected = append(s.rejected, "batch refused: manifest root does not match the trusted root")
		return
	}
	seen := map[uint64]bool{}
	for _, e := range pkg.Entries {
		if e.Index != e.Proof.Index {
			s.rejected = append(s.rejected, fmt.Sprintf(
				"entry %d refused: wrapper index %d disagrees with proof index %d", e.Index, e.Index, e.Proof.Index))
			continue
		}
		if seen[e.Index] {
			s.rejected = append(s.rejected, fmt.Sprintf("entry %d refused: duplicated within one batch", e.Index))
			continue
		}
		seen[e.Index] = true
		if !s.wants(e.Index) {
			s.rejected = append(s.rejected, fmt.Sprintf("entry %d refused: not part of the required set", e.Index))
			continue
		}
		normalized, err := compactJSON(e.Record)
		if err != nil {
			s.rejected = append(s.rejected, fmt.Sprintf("entry %d refused: invalid record JSON: %v", e.Index, err))
			continue
		}
		if err := e.Proof.Verify(*s.req.Root, pkg.Manifest.LeafCount, normalized); err != nil {
			s.rejected = append(s.rejected, fmt.Sprintf("entry %d refused: %v", e.Index, err))
			continue
		}
		if prev, ok := s.verified[e.Index]; ok {
			if bytes.Equal(prev, normalized) {
				s.dupes++
				continue
			}
			s.conflicts = append(s.conflicts, Conflict{
				Index:    e.Index,
				Accepted: prev,
				Rejected: normalized,
			})
			continue
		}
		s.verified[e.Index] = normalized
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
// is a partial result, never a pass.
type Status struct {
	Complete   bool
	Verified   []uint64
	Missing    []uint64
	Duplicates int
	Conflicts  []Conflict
	Rejected   []string
}

// Status reports progress without mutating the session.
func (s *Session) Status() Status {
	st := Status{
		Duplicates: s.dupes,
		Conflicts:  append([]Conflict(nil), s.conflicts...),
		Rejected:   append([]string(nil), s.rejected...),
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
	}
	sort.Slice(st.Verified, func(a, b int) bool { return st.Verified[a] < st.Verified[b] })
	sort.Slice(st.Missing, func(a, b int) bool { return st.Missing[a] < st.Missing[b] })
	st.Complete = len(st.Missing) == 0 && len(st.Conflicts) == 0 && len(st.Rejected) == 0
	return st
}

// Snapshot is the persistable progress of a session: which records of
// the pinned request have already verified. It is bound to the
// request's fingerprint so it can never be replayed into a different
// decision.
type Snapshot struct {
	Fingerprint Hash                       `json:"fingerprint"`
	Verified    map[uint64]json.RawMessage `json:"verified"`
	Duplicates  int                        `json:"duplicates"`
	Conflicts   []Conflict                 `json:"conflicts,omitempty"`
	Rejected    []string                   `json:"rejected,omitempty"`
}

// Snapshot captures verified progress so a receiver can persist it and
// resume later instead of re-verifying everything.
func (s *Session) Snapshot() Snapshot {
	snap := Snapshot{
		Fingerprint: s.Fingerprint(),
		Verified:    map[uint64]json.RawMessage{},
		Duplicates:  s.dupes,
		Conflicts:   append([]Conflict(nil), s.conflicts...),
		Rejected:    append([]string(nil), s.rejected...),
	}
	for i, rec := range s.verified {
		snap.Verified[i] = rec
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
		req:       req,
		verified:  map[uint64]json.RawMessage{},
		dupes:     snap.Duplicates,
		conflicts: append([]Conflict(nil), snap.Conflicts...),
		rejected:  append([]string(nil), snap.Rejected...),
	}
	for i, rec := range snap.Verified {
		if !s.wants(i) {
			return nil, fmt.Errorf("snapshot contains index %d outside the required set", i)
		}
		s.verified[i] = rec
	}
	return s, nil
}
