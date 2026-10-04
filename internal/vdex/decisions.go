package vdex

import "sort"

// Decision is the frozen record of one verification request: what was
// demanded, what was concluded, and every piece of material gathered
// while deciding. Filing a session into an Archive produces one.
type Decision struct {
	Fingerprint Hash     `json:"fingerprint"`
	Dataset     string   `json:"dataset"`
	Version     uint64   `json:"version"`
	Indices     []uint64 `json:"indices"`
	Status      Status   `json:"status"`
	Snapshot    Snapshot `json:"snapshot"`
}

// Archive keeps past and current decisions queryable. Changing a
// request starts a new decision — but the old request’s material and
// conclusion must not vanish with it, so each session’s state is filed
// here under its request fingerprint and stays retrievable afterwards.
type Archive struct {
	byFingerprint map[Hash]Decision
}

// NewArchive returns an empty decision archive.
func NewArchive() *Archive {
	return &Archive{byFingerprint: map[Hash]Decision{}}
}

// File records the session’s current state as the decision for its
// request. Refiling under the same fingerprint replaces the earlier
// entry, so the archive always reflects the latest state of each
// distinct request; different requests never overwrite each other.
func (a *Archive) File(s *Session) Decision {
	d := Decision{
		Fingerprint: s.Fingerprint(),
		Dataset:     s.req.Dataset,
		Version:     s.req.Version,
		Indices:     append([]uint64(nil), s.req.Indices...),
		Status:      s.Status(),
		Snapshot:    s.Snapshot(),
	}
	a.byFingerprint[d.Fingerprint] = d
	return d
}

// Lookup returns the filed decision for a request fingerprint.
func (a *Archive) Lookup(fp Hash) (Decision, bool) {
	d, ok := a.byFingerprint[fp]
	return d, ok
}

// Decisions lists every filed decision, ordered by fingerprint for
// deterministic output.
func (a *Archive) Decisions() []Decision {
	out := make([]Decision, 0, len(a.byFingerprint))
	for _, d := range a.byFingerprint {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Fingerprint, out[j].Fingerprint
		for k := range a {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return false
	})
	return out
}
