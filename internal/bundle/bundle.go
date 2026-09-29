// Package bundle creates and verifies portable, partial data packages.
package bundle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"vdx/internal/manifest"
	"vdx/internal/merkle"
	"vdx/internal/records"
)

const (
	Schema      = "vdx-bundle-v1"
	BundleFile  = "bundle.json"
	RecordsFile = "records.jsonl"
	ProofsFile  = "proofs.jsonl"
)

// Descriptor is the self-describing header of a partial package.
type Descriptor struct {
	Schema        string `json:"schema"`
	DatasetID     string `json:"dataset_id"`
	Version       uint64 `json:"version"`
	VersionID     string `json:"version_id"`
	TotalRecords  uint64 `json:"total_records"`
	StartIndex    uint64 `json:"start_index"`
	IncludedCount uint64 `json:"included_count"`
	RecordsFile   string `json:"records_file"`
	ProofsFile    string `json:"proofs_file"`
	Contiguous    bool   `json:"contiguous"`
}

// Create exports records [start,end) of a sealed version into dir.
func Create(m manifest.Manifest, allRecords [][]byte, tree *merkle.Tree, start, end uint64, dir string) (Descriptor, error) {
	if start > end || end > uint64(len(allRecords)) {
		return Descriptor{}, fmt.Errorf("invalid range [%d,%d) for %d records", start, end, len(allRecords))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Descriptor{}, err
	}
	var recBuf bytes.Buffer
	var proofBuf bytes.Buffer
	for i := start; i < end; i++ {
		recBuf.Write(allRecords[i])
		recBuf.WriteByte('\n')
		p, err := tree.ProofFor(i)
		if err != nil {
			return Descriptor{}, err
		}
		p.Version = m.Version
		raw, err := json.Marshal(p)
		if err != nil {
			return Descriptor{}, err
		}
		proofBuf.Write(raw)
		proofBuf.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, RecordsFile), recBuf.Bytes(), 0o644); err != nil {
		return Descriptor{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, ProofsFile), proofBuf.Bytes(), 0o644); err != nil {
		return Descriptor{}, err
	}
	d := Descriptor{
		Schema:        Schema,
		DatasetID:     m.DatasetID,
		Version:       m.Version,
		VersionID:     m.VersionID,
		TotalRecords:  m.RecordCount,
		StartIndex:    start,
		IncludedCount: end - start,
		RecordsFile:   RecordsFile,
		ProofsFile:    ProofsFile,
		Contiguous:    true,
	}
	return d, writeJSON(filepath.Join(dir, BundleFile), d)
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Result reports independent verification of a bundle against a trusted root.
type Result struct {
	OK              bool     `json:"ok"`
	DatasetID       string   `json:"dataset_id"`
	Version         uint64   `json:"version"`
	VersionID       string   `json:"version_id"`
	IncludedCount   uint64   `json:"included_count"`
	VerifiedRecords uint64   `json:"verified_records"`
	Errors          []string `json:"errors"`
}

// Load reads a bundle descriptor.
func Load(dir string) (Descriptor, error) {
	var d Descriptor
	data, err := os.ReadFile(filepath.Join(dir, BundleFile))
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return d, err
	}
	if d.Schema != Schema {
		return d, fmt.Errorf("unsupported bundle schema %q", d.Schema)
	}
	return d, nil
}

// Verify independently checks a package against a trusted version root.
// trustDataset anchors dataset identity; trustedVersion pins the version when
// non-zero. It detects content tampering, missing/extra payload lines, moved
// proofs and cross-version splicing.
func Verify(dir string, trustDataset string, trustedVersion uint64, trustRoot merkle.Hash) (Result, error) {
	d, err := Load(dir)
	if err != nil {
		return Result{}, err
	}
	res := Result{
		DatasetID:     d.DatasetID,
		Version:       d.Version,
		VersionID:     d.VersionID,
		IncludedCount: d.IncludedCount,
	}
	fail := func(format string, args ...any) {
		res.Errors = append(res.Errors, fmt.Sprintf(format, args...))
	}

	var declaredRoot merkle.Hash
	rootBytes, err := hex.DecodeString(d.VersionID)
	if err != nil || len(rootBytes) != len(declaredRoot) {
		fail("bundle version_id is not a 32-byte hex digest")
	} else {
		copy(declaredRoot[:], rootBytes)
	}
	if trustDataset != "" && d.DatasetID != trustDataset {
		fail("dataset id mismatch: bundle has %q, trusted anchor %q", d.DatasetID, trustDataset)
	}
	if trustedVersion != 0 && d.Version != trustedVersion {
		fail("version mismatch: bundle declares v%d, trusted anchor v%d", d.Version, trustedVersion)
	}
	if len(rootBytes) == len(declaredRoot) && declaredRoot != trustRoot {
		fail("bundle version id does not match trusted version root")
	}

	recF, err := os.Open(filepath.Join(dir, d.RecordsFile))
	if err != nil {
		fail("cannot open records: %v", err)
		return finalize(res), nil
	}
	recs, rerr := records.ReadAll(recF)
	recF.Close()
	if rerr != nil {
		fail("records framing: %v", rerr)
	}
	proofLines, perr := readJSONL[merkle.Proof](filepath.Join(dir, d.ProofsFile))
	if perr != nil {
		fail("proofs framing: %v", perr)
	}

	if uint64(len(recs)) != d.IncludedCount {
		fail("missing or extra records: header claims %d, payload contains %d", d.IncludedCount, len(recs))
	}
	if uint64(len(proofLines)) != d.IncludedCount {
		fail("missing or extra proofs: header claims %d, file contains %d", d.IncludedCount, len(proofLines))
	}
	if d.StartIndex+d.IncludedCount > d.TotalRecords {
		fail("claimed range [%d,%d) lies outside the %d-record version", d.StartIndex, d.StartIndex+d.IncludedCount, d.TotalRecords)
	}

	n := min(len(recs), len(proofLines))
	seen := map[uint64]bool{}
	for k := 0; k < n; k++ {
		p := proofLines[k]
		expectedIndex := d.StartIndex + uint64(k)
		if p.Index != expectedIndex {
			fail("line %d: proof index is %d, expected %d (position moved or spliced)", k, p.Index, expectedIndex)
			continue
		}
		if seen[p.Index] {
			fail("line %d: duplicate proof index %d", k, p.Index)
		}
		seen[p.Index] = true
		if p.Version != d.Version {
			fail("line %d: proof belongs to v%d, bundle is v%d (cross-version splice)", k, p.Version, d.Version)
			continue
		}
		if p.Total != d.TotalRecords {
			fail("line %d: proof total %d disagrees with bundle total %d", k, p.Total, d.TotalRecords)
		}
		if verr := merkle.Verify(d.DatasetID, p, recs[k], trustRoot); verr != nil {
			fail("line %d (index %d): %v", k, p.Index, verr)
		} else {
			res.VerifiedRecords++
		}
	}
	return finalize(res), nil
}

func finalize(res Result) Result {
	res.OK = len(res.Errors) == 0
	return res
}

func readJSONL[T any](path string) ([]T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []T
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var v T
		if err := json.Unmarshal(line, &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
