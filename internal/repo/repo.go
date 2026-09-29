// Package repo seals datasets into immutable, append-only versions.
package repo

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"vdx/internal/manifest"
	"vdx/internal/merkle"
	"vdx/internal/records"
)

type Repo struct {
	path string
	head manifest.RepoHead
}

// Init creates an empty repository. Publishing the first file produces v1.
func Init(dir, datasetID string) (*Repo, error) {
	if datasetID == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		datasetID = hex.EncodeToString(b[:])
	}
	if err := os.MkdirAll(filepath.Join(dir, manifest.VersionDir), 0o755); err != nil {
		return nil, err
	}
	r := &Repo{
		path: dir,
		head: manifest.RepoHead{
			Schema:    manifest.HeadSchema,
			DatasetID: datasetID,
		},
	}
	if _, err := os.Stat(filepath.Join(dir, manifest.HeadFile)); err == nil {
		return nil, fmt.Errorf("repository already exists at %s", dir)
	}
	if err := r.writeHead(); err != nil {
		return nil, err
	}
	return r, nil
}

// Open loads an existing repository.
func Open(dir string) (*Repo, error) {
	data, err := os.ReadFile(filepath.Join(dir, manifest.HeadFile))
	if err != nil {
		return nil, fmt.Errorf("not a vdx repository: %w", err)
	}
	var head manifest.RepoHead
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, err
	}
	if head.Schema != manifest.HeadSchema {
		return nil, fmt.Errorf("unexpected head schema %q", head.Schema)
	}
	return &Repo{path: dir, head: head}, nil
}

func (r *Repo) Head() manifest.RepoHead { return r.head }
func (r *Repo) Path() string            { return r.path }

func (r *Repo) writeHead() error {
	return atomicWriteJSON(filepath.Join(r.path, manifest.HeadFile), r.head)
}

func atomicWriteJSON(path string, v any) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// VersionPath returns the directory of a sealed version.
func (r *Repo) VersionPath(version uint64) string {
	return filepath.Join(r.path, manifest.VersionDir, fmt.Sprintf("v%d", version))
}

// LoadManifest reads one sealed version manifest.
func (r *Repo) LoadManifest(version uint64) (manifest.Manifest, error) {
	var m manifest.Manifest
	data, err := os.ReadFile(filepath.Join(r.VersionPath(version), manifest.ManifestName))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, err
	}
	return m, nil
}

// LoadRecords reads the records of one sealed version.
func (r *Repo) LoadRecords(version uint64) ([][]byte, error) {
	f, err := os.Open(filepath.Join(r.VersionPath(version), manifest.RecordsName))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return records.ReadAll(f)
}

// Publish seals file as a new version.
//
// The file must contain every record of the previous version as an exact byte
// prefix (append-only). The new version directory is fully written and fsynced
// before the head pointer is atomically swapped, so an interrupted publish
// leaves the previous version as the still-current, fully verifiable release.
func (r *Repo) Publish(file string) (manifest.Manifest, error) {
	f, err := os.Open(file)
	if err != nil {
		return manifest.Manifest{}, err
	}
	newRecords, err := records.ReadAll(f)
	f.Close()
	if err != nil {
		return manifest.Manifest{}, err
	}

	newVersion := r.head.Version + 1
	var parentRoot string
	if r.head.Version > 0 {
		parentRoot = r.head.VersionID
		oldRecords, err := r.LoadRecords(r.head.Version)
		if err != nil {
			return manifest.Manifest{}, fmt.Errorf("reading previous version: %w", err)
		}
		if uint64(len(newRecords)) < r.head.RecordCount {
			return manifest.Manifest{}, errors.New("new dataset removes records; versions are append-only")
		}
		for i := range oldRecords {
			if string(newRecords[i]) != string(oldRecords[i]) {
				return manifest.Manifest{}, fmt.Errorf("record %d differs from sealed previous version", i)
			}
		}
		if uint64(len(newRecords)) == r.head.RecordCount {
			return manifest.Manifest{}, errors.New("no new records appended; refusing to seal an identical version")
		}
	}

	// Stage into a sibling temporary directory on the same filesystem so the
	// final switch is one atomic rename.
	stage, err := os.MkdirTemp(filepath.Join(r.path, manifest.VersionDir), ".stage-*")
	if err != nil {
		return manifest.Manifest{}, err
	}
	stageName := stage
	commit := false
	defer func() {
		if !commit {
			os.RemoveAll(stageName)
		}
	}()

	var root merkle.Hash
	if len(newRecords) == 0 {
		root = merkle.EmptyRoot(r.head.DatasetID, newVersion)
	} else {
		leaves := make([]merkle.Hash, len(newRecords))
		// Version id depends on the root, but leaves commit to the version id:
		for i, rec := range newRecords {
			leaves[i] = merkle.LeafHash(r.head.DatasetID, newVersion, uint64(i), rec)
		}
		root = merkle.Build(leaves).Root()
	}
	versionID := hex.EncodeToString(root[:])

	if err := copyRecords(file, filepath.Join(stage, manifest.RecordsName)); err != nil {
		return manifest.Manifest{}, err
	}
	m := manifest.Manifest{
		Schema:          manifest.ManifestSchema,
		DatasetID:       r.head.DatasetID,
		Version:         newVersion,
		VersionID:       versionID,
		ParentVersionID: parentRoot,
		CreatedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		RecordCount:     uint64(len(newRecords)),
		RecordsFile:     manifest.RecordsName,
		LeafScheme:      manifest.LeafScheme,
	}
	if err := atomicWriteJSON(filepath.Join(stage, manifest.ManifestName), m); err != nil {
		return manifest.Manifest{}, err
	}

	dir, err := os.Open(stage)
	if err == nil {
		err = dir.Sync()
		dir.Close()
	}
	if err != nil {
		return manifest.Manifest{}, err
	}

	target := r.VersionPath(newVersion)
	if _, err := os.Stat(target); err == nil {
		return manifest.Manifest{}, fmt.Errorf("version directory %s already exists", target)
	}
	if err := os.Rename(stage, target); err != nil {
		return manifest.Manifest{}, err
	}
	commit = true

	r.head = manifest.RepoHead{
		Schema:      manifest.HeadSchema,
		DatasetID:   r.head.DatasetID,
		Version:     newVersion,
		VersionID:   versionID,
		RecordCount: uint64(len(newRecords)),
	}
	if err := r.writeHead(); err != nil {
		return manifest.Manifest{}, fmt.Errorf("version sealed at %s but head update failed: %w", target, err)
	}
	return m, nil
}

func copyRecords(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := out.Write(in); err != nil {
		return err
	}
	return out.Sync()
}
