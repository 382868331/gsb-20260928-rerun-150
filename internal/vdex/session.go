package vdex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Session is a resumable, multi-batch verification of one fixed
// request. The request pins the required record set, the scope
// (dataset and version) and the trusted basis (root) up front;
// packages may then arrive in any order and any number of batches.
// Out-of-order and duplicate arrivals never change the requirement,
// and a conclusion of complete is only reached once every required
// record is verified against the trusted root.
type Session struct {
	Request Request `json:"request"`
	// Verified holds the entries that proved inclusion under the
	// trusted root, sorted by index.
	Verified []Entry `json:"verified"`
	// Conflicts retains both sides of contradictory material: every
	// distinct record content observed for the same index.
	Conflicts []Conflict `json:"conflicts,omitempty"`
	// Rejected records arrivals that failed verification or fell
	// outside the requested scope, with reasons.
	Rejected []string `json:"rejected,omitempty"`
	// Duplicates counts exact re-deliveries of already verified
	// records; they are accepted but change nothing.
	Duplicates int `json:"duplicates"`
}

// NewSession opens a verification session for a fixed request. The
// request must carry the trusted basis; without it no material can
// ever be accepted.
func NewSession(req Request) (*Session, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	return &Session{Request: req.canonical()}, nil
}

// Conflict is the retained evidence of contradictory records
// delivered for one index, in arrival order.
type Conflict struct {
	Index   uint64            `json:"index"`
	Records []json.RawMessage `json:"records"`
}

// SessionStatus is a point-in-time report. Complete is only true when
// every required record is verified and no contradiction is open;
// anything less is partial progress, never a conclusion.
type SessionStatus struct {
	Complete   bool
	Required   int
	Verified   int
	Missing    []uint64
	Duplicates int
	Conflicts  []Conflict
	Rejected   []string
}

func (s *Session) verifiedIndex() map[uint64]int {
	m := make(map[uint64]int, len(s.Verified))
	for i, e := range s.Verified {
		m[e.Index] = i
	}
	return m
}

func (s *Session) conflictIndex() map[uint64]int {
	m := make(map[uint64]int, len(s.Conflicts))
	for i, c := range s.Conflicts {
		m[c.Index] = i
	}
	return m
}

func (s *Session) reject(format string, args ...any) {
	s.Rejected = append(s.Rejected, fmt.Sprintf(format, args...))
}

// AddPackage folds one arriving batch into the session. The package
// manifest must match the session's fixed scope and trusted root;
// each entry is then verified on its own. Identical re-deliveries are
// duplicates, contradictory content for an index is kept as conflict
// evidence, and out-of-scope or unprovable entries are rejected.
func (s *Session) AddPackage(pkg Package) {
	req := s.Request
	if pkg.Format != PackageFormat {
		s.reject("package format %q is not supported", pkg.Format)
		return
	}
	if err := pkg.Manifest.validate(); err != nil {
		s.reject("invalid manifest: %v", err)
		return
	}
	if pkg.Manifest.Dataset != req.Dataset || pkg.Manifest.Version != req.Version {
		s.reject("package claims %s v%d, outside the requested scope %s v%d",
			pkg.Manifest.Dataset, pkg.Manifest.Version, req.Dataset, req.Version)
		return
	}
	if pkg.Manifest.Root != *req.Root {
		s.reject("package root does not match the trusted root")
		return
	}

	want := map[uint64]bool{}
	for _, i := range req.Indices {
		want[i] = true
	}
	verified := s.verifiedIndex()
	conflicts := s.conflictIndex()
	for _, e := range pkg.Entries {
		if e.Index != e.Proof.Index {
			s.reject("index %d: wrapper index disagrees with proof index %d", e.Index, e.Proof.Index)
			continue
		}
		if !want[e.Index] {
			s.reject("index %d: outside the requested record set", e.Index)
			continue
		}
		normalized, err := compactJSON(e.Record)
		if err != nil {
			s.reject("index %d: invalid record JSON: %v", e.Index, err)
			continue
		}
		if at, ok := verified[e.Index]; ok {
			existing, _ := compactJSON(s.Verified[at].Record)
			if bytes.Equal(existing, normalized) {
				s.Duplicates++
				continue
			}
			s.addConflict(conflicts, e.Index, existing, normalized)
			continue
		}
		if err := e.Proof.Verify(*req.Root, pkg.Manifest.LeafCount, normalized); err != nil {
			s.reject("index %d: %v", e.Index, err)
			continue
		}
		verified[e.Index] = len(s.Verified)
		s.Verified = append(s.Verified, Entry{Index: e.Index, Record: normalized, Proof: e.Proof})
	}
	sort.Slice(s.Verified, func(a, b int) bool { return s.Verified[a].Index < s.Verified[b].Index })
}

// addConflict records contradictory content for an index, keeping
// every distinct observed record as evidence.
func (s *Session) addConflict(conflicts map[uint64]int, index uint64, existing, incoming json.RawMessage) {
	at, ok := conflicts[index]
	if !ok {
		s.Conflicts = append(s.Conflicts, Conflict{Index: index, Records: []json.RawMessage{existing}})
		at = len(s.Conflicts) - 1
		conflicts[index] = at
	}
	for _, r := range s.Conflicts[at].Records {
		if bytes.Equal(r, incoming) {
			return
		}
	}
	s.Conflicts[at].Records = append(s.Conflicts[at].Records, incoming)
}

// Status reports partial progress versus overall completion.
func (s *Session) Status() SessionStatus {
	verified := s.verifiedIndex()
	st := SessionStatus{
		Required:   len(s.Request.Indices),
		Verified:   len(s.Verified),
		Duplicates: s.Duplicates,
		Conflicts:  s.Conflicts,
		Rejected:   s.Rejected,
	}
	for _, i := range s.Request.Indices {
		if _, ok := verified[i]; !ok {
			st.Missing = append(st.Missing, i)
		}
	}
	st.Complete = len(st.Missing) == 0 && len(st.Conflicts) == 0
	return st
}

const sessionFormat = "vdex-session-v1"

type sessionFile struct {
	Format  string   `json:"format"`
	Session *Session `json:"session"`
}

// Save persists the session so verification can resume later.
func (s *Session) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(sessionFile{Format: sessionFormat, Session: s}, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadSession resumes a saved session, but only for the same request.
// A modified request is a new decision: earlier progress and any
// earlier pass state do not carry over, and the caller must start a
// fresh session instead.
func LoadSession(path string, req Request) (*Session, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f sessionFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.Format != sessionFormat {
		return nil, fmt.Errorf("unsupported session format %q", f.Format)
	}
	if f.Session == nil {
		return nil, errors.New("session file has no session")
	}
	if err := req.validate(); err != nil {
		return nil, err
	}
	if !sameRequirement(f.Session.Request, req) {
		return nil, errors.New("request changed since the session was saved: previous progress does not apply, start a new session")
	}
	return f.Session, nil
}
