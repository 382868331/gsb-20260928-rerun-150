package vdex

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Store is an append-only local archive of sealed versions.
// Re-sealing after a failed/interrupted publication never removes old data:
// each seal writes a new directory and only the latest-version pointer is
// updated atomically at the very end.
type Store struct{ root string }

func NewStore(root string) *Store { return &Store{root: root} }

func (s *Store) dir() string { return filepath.Join(s.root, "versions") }

func (s *Store) versionDir(version uint64) string {
	return filepath.Join(s.dir(), fmt.Sprintf("v%012d", version))
}

// LatestVersion returns 0 when the store has no sealed versions.
func (s *Store) LatestVersion() (uint64, error) {
	entries, err := os.ReadDir(s.dir())
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var latest uint64
	for _, e := range entries {
		var v uint64
		if _, err := fmt.Sscanf(e.Name(), "v%012d", &v); err == nil && v > latest {
			latest = v
		}
	}
	return latest, nil
}

// LoadManifest reads one version's manifest.
func (s *Store) LoadManifest(version uint64) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(filepath.Join(s.versionDir(version), "manifest.json"))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	return m, m.validate()
}

// ReadRecords streams the sealed records of a version.
func (s *Store) ReadRecords(version uint64, fn func(index uint64, record []byte) error) error {
	f, err := os.Open(filepath.Join(s.versionDir(version), "records.jsonl"))
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	var i uint64
	for sc.Scan() {
		var rec json.RawMessage
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
		if err := fn(i, rec); err != nil {
			return err
		}
		i++
	}
	return sc.Err()
}

// Seal seals records from r (one JSON value per line, blank lines skipped)
// into a new immutable version. If expectedNext is non-zero it must match
// the store's next version number, preventing a stale publisher from
// overwriting a concurrent publication.
func (s *Store) Seal(dataset string, r io.Reader, expectedNext uint64, now time.Time) (Manifest, error) {
	latest, err := s.LatestVersion()
	if err != nil {
		return Manifest{}, err
	}
	next := latest + 1
	if expectedNext != 0 && expectedNext != next {
		return Manifest{}, fmt.Errorf("expected to publish v%d but next version is v%d", expectedNext, next)
	}

	var leaves []Hash
	dir := s.versionDir(next)
	tmp := dir + ".tmp"
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return Manifest{}, err
	}
	fail := true
	defer func() {
		if fail {
			_ = os.RemoveAll(tmp)
		}
	}()

	out, err := os.Create(filepath.Join(tmp, "records.jsonl"))
	if err != nil {
		return Manifest{}, err
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytesTrimSpace(line)) == 0 {
			continue
		}
		var rec json.RawMessage
		if err := json.Unmarshal(line, &rec); err != nil {
			out.Close()
			return Manifest{}, fmt.Errorf("record %d: invalid JSON: %w", len(leaves), err)
		}
		normalized, err := compactJSON(rec)
		if err != nil {
			out.Close()
			return Manifest{}, err
		}
		idx := uint64(len(leaves))
		leaves = append(leaves, LeafHash(idx, normalized))
		if _, err := out.Write(append(normalized, '\n')); err != nil {
			out.Close()
			return Manifest{}, err
		}
	}
	if err := sc.Err(); err != nil {
		out.Close()
		return Manifest{}, err
	}
	if err := out.Close(); err != nil {
		return Manifest{}, err
	}

	tree := NewTree(leaves)
	var prev *Hash
	if latest > 0 {
		pm, err := s.LoadManifest(latest)
		if err != nil {
			return Manifest{}, err
		}
		prev = &pm.Root
	}
	m := Manifest{
		Format:    ManifestFormat,
		Dataset:   dataset,
		Version:   next,
		Prev:      prev,
		Root:      tree.Root(),
		LeafCount: uint64(len(leaves)),
		SealedAt:  now.UTC(),
	}
	mbytes, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	if err := os.WriteFile(filepath.Join(tmp, "manifest.json"), append(mbytes, '\n'), 0o644); err != nil {
		return Manifest{}, err
	}
	if err := os.Rename(tmp, dir); err != nil {
		return Manifest{}, err
	}
	fail = false
	return m, nil
}

// Versions lists all sealed versions in ascending order.
func (s *Store) Versions() ([]Manifest, error) {
	latest, err := s.LatestVersion()
	if err != nil {
		return nil, err
	}
	var out []Manifest
	for v := uint64(1); v <= latest; v++ {
		m, err := s.LoadManifest(v)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func bytesTrimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\r' || b[0] == '\n') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t' || b[len(b)-1] == '\r' || b[len(b)-1] == '\n') {
		b = b[:len(b)-1]
	}
	return b
}

func compactJSON(raw json.RawMessage) (json.RawMessage, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
