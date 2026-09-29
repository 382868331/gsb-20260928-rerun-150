// Package manifest defines the on-disk identity documents of a sealed version.
package manifest

// Manifest is the immutable identity document of one sealed version.
type Manifest struct {
	// Schema is always "vdx-manifest-v1".
	Schema string `json:"schema"`
	// DatasetID stays constant across all versions of one dataset.
	DatasetID string `json:"dataset_id"`
	// Version is the monotonically increasing, gap-free version number.
	Version uint64 `json:"version"`
	// VersionID is the hex-encoded Merkle root of this version and is the
	// anchor every proof is checked against.
	VersionID string `json:"version_id"`
	// ParentVersionID links to the previous version (empty for version 1).
	ParentVersionID string `json:"parent_version_id"`
	CreatedAt       string `json:"created_at"`
	RecordCount     uint64 `json:"record_count"`
	// RecordsFile is the canonical relative path of the record payload.
	RecordsFile string `json:"records_file"`
	// LeafScheme documents how record leaves are hashed.
	LeafScheme string `json:"leaf_scheme"`
}

// RepoHead points at the current sealed version.
type RepoHead struct {
	Schema      string `json:"schema"`
	DatasetID   string `json:"dataset_id"`
	Version     uint64 `json:"version"`
	VersionID   string `json:"version_id"`
	RecordCount uint64 `json:"record_count"`
}

const (
	ManifestSchema = "vdx-manifest-v1"
	HeadSchema     = "vdx-head-v1"
	LeafScheme     = "sha256(domain|dataset_id|version|index|content)"
	HeadFile       = "repo.json"
	VersionDir     = "versions"
	RecordsName    = "records.jsonl"
	ManifestName   = "manifest.json"
)
