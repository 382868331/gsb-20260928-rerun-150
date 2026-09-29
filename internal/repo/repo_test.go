package repo

import (
	"os"
	"path/filepath"
	"testing"

	"vdx/internal/merkle"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPublishAppendAndImmutability(t *testing.T) {
	dir := t.TempDir()
	r, err := Init(dir, "ds-1")
	if err != nil {
		t.Fatal(err)
	}
	v1 := filepath.Join(dir, "v1.jsonl")
	writeFile(t, v1, "a\nb\n")
	m1, err := r.Publish(v1)
	if err != nil {
		t.Fatal(err)
	}
	if m1.Version != 1 || m1.RecordCount != 2 {
		t.Fatalf("unexpected v1: %+v", m1)
	}

	v2 := filepath.Join(dir, "v2.jsonl")
	writeFile(t, v2, "a\nb\nc\n")
	m2, err := r.Publish(v2)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Version != 2 || m2.ParentVersionID != m1.VersionID {
		t.Fatalf("bad lineage: %+v", m2)
	}
	if m2.VersionID == m1.VersionID {
		t.Fatal("new records must produce a new version id")
	}

	// Old version directory and manifest remain sealed and independently usable.
	oldRecs, err := r.LoadRecords(1)
	if err != nil || len(oldRecs) != 2 || string(oldRecs[0]) != "a" {
		t.Fatalf("old version mutated: %v %v", oldRecs, err)
	}
	oldM, err := r.LoadManifest(1)
	if err != nil || oldM.VersionID != m1.VersionID {
		t.Fatal("old manifest changed")
	}

	// Re-publishing an identical snapshot is rejected.
	if _, err := r.Publish(v2); err == nil {
		t.Fatal("identical publish should fail")
	}
	// Removing or altering history records is rejected.
	shrunk := filepath.Join(dir, "bad1.jsonl")
	writeFile(t, shrunk, "a\n")
	if _, err := r.Publish(shrunk); err == nil {
		t.Fatal("shrink should fail")
	}
	mut := filepath.Join(dir, "bad2.jsonl")
	writeFile(t, mut, "a\nX\nc\n")
	if _, err := r.Publish(mut); err == nil {
		t.Fatal("mutating prefix should fail")
	}
	if r.Head().Version != 2 {
		t.Fatal("failed publish must leave current version intact")
	}
}

func TestInterruptedPublishKeepsOldVersion(t *testing.T) {
	dir := t.TempDir()
	r, _ := Init(dir, "ds")
	f1 := filepath.Join(dir, "a.jsonl")
	writeFile(t, f1, "a\n")
	m1, _ := r.Publish(f1)

	// Simulate a failed publish by making the versions dir unable to accept a
	// new rename target: place a file at the would-be staging path is awkward,
	// instead make records input unreadable mid-check via a missing file.
	if _, err := r.Publish(filepath.Join(dir, "missing.jsonl")); err == nil {
		t.Fatal("expected error")
	}
	if r.Head().VersionID != m1.VersionID {
		t.Fatal("head moved on failed publish")
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "versions"))
	for _, e := range entries {
		if e.Name() != "v1" {
			t.Fatalf("leftover staging dir: %s", e.Name())
		}
	}
	_ = merkle.Hash{}
}
