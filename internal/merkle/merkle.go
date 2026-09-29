// Package merkle implements a position-bound, version-bound Merkle tree.
//
// Identity of a record is never the hash of its content alone: the leaf hash
// binds the exact byte content, its zero-based position, the dataset id, the
// version number and the version id. Two identical records at two positions
// (duplicates) therefore get distinct leaf identities, and a proof valid for
// one version can never be replayed against another.
package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	domainLeaf  = "vdx-leaf-v1"
	domainInner = "vdx-inner-v1"
	domainEmpty = "vdx-empty-v1"
)

// Hash is a SHA-256 digest.
type Hash [sha256.Size]byte

func writeTag(buf *bytes.Buffer, tag string) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(tag)))
	buf.Write(l[:])
	buf.WriteString(tag)
}

func writeBytes(buf *bytes.Buffer, b []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(b)))
	buf.Write(l[:])
	buf.Write(b)
}

func writeUint(buf *bytes.Buffer, n uint64) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], n)
	buf.Write(l[:])
}

// LeafHash computes the position-bound identity of a record. The version id
// (Merkle root) is deliberately not an input: it is derived from the leaves,
// and the version number committed in every leaf binds proofs to one version.
func LeafHash(datasetID string, version uint64, index uint64, content []byte) Hash {
	var buf bytes.Buffer
	writeTag(&buf, domainLeaf)
	writeBytes(&buf, []byte(datasetID))
	writeUint(&buf, version)
	writeUint(&buf, index)
	writeBytes(&buf, content)
	return sha256.Sum256(buf.Bytes())
}

func nodeHash(left, right Hash) Hash {
	var buf bytes.Buffer
	writeTag(&buf, domainInner)
	writeBytes(&buf, left[:])
	writeBytes(&buf, right[:])
	return sha256.Sum256(buf.Bytes())
}

// EmptyRoot is the version id of a dataset with zero records.
func EmptyRoot(datasetID string, version uint64) Hash {
	var buf bytes.Buffer
	writeTag(&buf, domainEmpty)
	writeBytes(&buf, []byte(datasetID))
	writeUint(&buf, version)
	return sha256.Sum256(buf.Bytes())
}

// Step is one node on the authentication path. When Left is true the sibling
// sits on the left of the running hash during verification, otherwise on the
// right. The explicit side flag prevents a path from being accepted at a moved
// position.
type Step struct {
	Sibling Hash `json:"sibling"`
	Left    bool `json:"left"`
}

// Proof is an inclusion proof for a single record.
type Proof struct {
	Index   uint64 `json:"index"`
	Total   uint64 `json:"total"`
	Version uint64 `json:"version"`
	Steps   []Step `json:"steps"`
}

// Tree holds the built Merkle tree. Layers[0] is the leaf layer.
type Tree struct {
	Leaves []Hash
	Layers [][]Hash
}

// Build constructs the tree from precomputed leaf hashes.
func Build(leaves []Hash) *Tree {
	t := &Tree{Leaves: leaves}
	layer := leaves
	t.Layers = append(t.Layers, layer)
	for len(layer) > 1 {
		next := make([]Hash, 0, (len(layer)+1)/2)
		for i := 0; i < len(layer); i += 2 {
			if i+1 == len(layer) {
				next = append(next, nodeHash(layer[i], layer[i]))
			} else {
				next = append(next, nodeHash(layer[i], layer[i+1]))
			}
		}
		layer = next
		t.Layers = append(t.Layers, layer)
	}
	return t
}

// Root returns the Merkle root (zero hash when there are no leaves).
func (t *Tree) Root() Hash {
	if len(t.Layers) == 0 || len(t.Layers[len(t.Layers)-1]) == 0 {
		return Hash{}
	}
	return t.Layers[len(t.Layers)-1][0]
}

// ProofFor returns the inclusion proof for the leaf at index.
func (t *Tree) ProofFor(index uint64) (Proof, error) {
	if int(index) >= len(t.Leaves) {
		return Proof{}, fmt.Errorf("index %d out of range (tree has %d leaves)", index, len(t.Leaves))
	}
	p := Proof{Index: index, Total: uint64(len(t.Leaves)), Steps: nil}
	pos := index
	for _, layer := range t.Layers[:len(t.Layers)-1] {
		if pos%2 == 0 {
			if int(pos+1) < len(layer) {
				p.Steps = append(p.Steps, Step{Sibling: layer[pos+1], Left: false})
			} else {
				// Odd node was promoted by hashing it with itself.
				p.Steps = append(p.Steps, Step{Sibling: layer[pos], Left: false})
			}
		} else {
			p.Steps = append(p.Steps, Step{Sibling: layer[pos-1], Left: true})
		}
		pos /= 2
	}
	return p, nil
}

// Verify recomputes the root from the record and its proof and compares it
// against want. The caller MUST first check p.Version against the sealed
// manifest version; every replay-sensitive claim is checked here.
func Verify(datasetID string, p Proof, content []byte, want Hash) error {
	if p.Index >= p.Total {
		return fmt.Errorf("proof index %d not within claimed total %d", p.Index, p.Total)
	}
	running := LeafHash(datasetID, p.Version, p.Index, content)
	pos := p.Index
	remaining := p.Total
	for _, step := range p.Steps {
		if pos%2 == 0 {
			// Even positions must carry a right sibling; a left sibling here
			// means the path was lifted from another position.
			if step.Left {
				return fmt.Errorf("side mismatch at node %d: expected right sibling", pos)
			}
			if remaining == 1 {
				return fmt.Errorf("path too long for claimed total %d", p.Total)
			}
			if remaining%2 == 1 && pos == remaining-1 {
				running = nodeHash(running, running)
			} else {
				running = nodeHash(running, step.Sibling)
			}
		} else {
			if !step.Left {
				return fmt.Errorf("side mismatch at node %d: expected left sibling", pos)
			}
			running = nodeHash(step.Sibling, running)
		}
		pos /= 2
		remaining = (remaining + 1) / 2
	}
	if remaining != 1 {
		return fmt.Errorf("path too short for claimed total %d", p.Total)
	}
	if running != want {
		return fmt.Errorf("computed root does not match version root")
	}
	return nil
}
