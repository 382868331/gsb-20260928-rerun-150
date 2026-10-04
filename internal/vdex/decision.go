package vdex

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Decision is one frozen verification request together with the
// material and conclusion accumulated under it. Changing the request
// never mutates a decision: it produces a different fingerprint and
// therefore a separate record, and the old decision — including any
// pass, partial result or conflict — stays on disk and queryable.
type Decision struct {
	Fingerprint Hash     `json:"fingerprint"`
	Request     Request  `json:"request"`
	Snapshot    Snapshot `json:"snapshot"`
	Complete    bool     `json:"complete"`
}

// DecisionStore is an append-only archive of verification decisions,
// keyed by request fingerprint.
type DecisionStore struct{ root string }

// NewDecisionStore opens the decision archive rooted at dir.
func NewDecisionStore(dir string) *DecisionStore { return &DecisionStore{root: dir} }

func (d *DecisionStore) path(fp Hash) string {
	return filepath.Join(d.root, fmt.Sprintf("%x.json", fp[:]))
}

// Load returns the decision for req. It never accepts material saved
// under a different request: a fingerprint mismatch is reported rather
// than silently merging decisions.
func (d *DecisionStore) Load(req Request) (*Decision, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(d.path(req.Fingerprint()))
	if err != nil {
		return nil, err
	}
	var dec Decision
	if err := json.Unmarshal(b, &dec); err != nil {
		return nil, err
	}
	if dec.Fingerprint != req.Fingerprint() {
		return nil, errors.New("stored decision fingerprint does not match request")
	}
	return &dec, nil
}

// Open returns a resumed session for req when a prior decision exists,
// otherwise a fresh one. A changed request never opens the old
// decision: the caller gets a new session while the old file remains.
func (d *DecisionStore) Open(req Request) (*Session, bool, error) {
	dec, err := d.Load(req)
	if errors.Is(err, os.ErrNotExist) {
		s, err := NewSession(req)
		return s, false, err
	}
	if err != nil {
		return nil, false, err
	}
	s, err := Resume(req, dec.Snapshot)
	if err != nil {
		return nil, false, err
	}
	return s, true, nil
}

// Save persists the current state of s as its decision. Saving never
// touches any other fingerprint, so older decisions remain intact.
func (d *DecisionStore) Save(s *Session) (Decision, error) {
	snap := s.Snapshot()
	st := s.Status()
	dec := Decision{
		Fingerprint: s.Fingerprint(),
		Request:     s.Request(),
		Snapshot:    snap,
		Complete:    st.Complete,
	}
	b, err := json.MarshalIndent(&dec, "", "  ")
	if err != nil {
		return Decision{}, err
	}
	if err := os.MkdirAll(d.root, 0o755); err != nil {
		return Decision{}, err
	}
	tmp := d.path(dec.Fingerprint) + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return Decision{}, err
	}
	if err := os.Rename(tmp, d.path(dec.Fingerprint)); err != nil {
		return Decision{}, err
	}
	return dec, nil
}

// List returns every archived decision ordered by dataset, version and
// fingerprint, so superseded decisions stay inspectable.
func (d *DecisionStore) List() ([]Decision, error) {
	entries, err := os.ReadDir(d.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Decision
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(d.root, e.Name()))
		if err != nil {
			return nil, err
		}
		var dec Decision
		if err := json.Unmarshal(b, &dec); err != nil {
			continue
		}
		out = append(out, dec)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Request.Dataset != out[b].Request.Dataset {
			return out[a].Request.Dataset < out[b].Request.Dataset
		}
		if out[a].Request.Version != out[b].Request.Version {
			return out[a].Request.Version < out[b].Request.Version
		}
		return out[a].Fingerprint != out[b].Fingerprint
	})
	return out, nil
}

// Request exposes the pinned request of a session (used by decision
// archiving without widening the field itself).
func (s *Session) Request() Request { return s.req }
