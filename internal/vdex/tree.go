package vdex

import (
	"errors"
	"fmt"
)

// ProofSide identifies the position of a sibling on the root path.
type ProofSide string

const (
	SideLeft  ProofSide = "L"
	SideRight ProofSide = "R"
)

// ProofStep is one sibling on the path from leaf to root.
type ProofStep struct {
	Side ProofSide `json:"side"`
	Hash Hash      `json:"hash"`
}

// Proof is a position-bound inclusion proof for one record.
type Proof struct {
	Index uint64      `json:"index"`
	Leaf  Hash        `json:"leaf"`
	Path  []ProofStep `json:"path"`
}

// Tree is an ordered binary Merkle tree. Duplicate records remain distinct
// because leaves commit to their index; odd nodes are padded with an
// index/height-bound empty digest rather than duplicated data.
type Tree struct {
	leaves []Hash
	// levels[0] holds the leaves; the last level holds only the root.
	levels [][]Hash
}

func padHash(level, pos uint64) Hash {
	return hashDomain("vdex-pad-v1", u64Bytes(level), u64Bytes(pos))
}

// NewTree builds a tree over the given leaf hashes.
func NewTree(leaves []Hash) *Tree {
	t := &Tree{leaves: append([]Hash(nil), leaves...)}
	level := append([]Hash(nil), leaves...)
	t.levels = append(t.levels, level)
	for depth := uint64(1); len(level) > 1; depth++ {
		next := make([]Hash, (len(level)+1)/2)
		for i := range next {
			left := level[2*i]
			right := padHash(depth, uint64(2*i+1))
			if 2*i+1 < len(level) {
				right = level[2*i+1]
			}
			next[i] = nodeHash(left, right)
		}
		level = next
		t.levels = append(t.levels, level)
	}
	return t
}

// Root returns the Merkle root. The empty dataset has a defined root.
func (t *Tree) Root() Hash {
	if len(t.levels[0]) == 0 {
		return hashDomain("vdex-empty-v1")
	}
	return t.levels[len(t.levels)-1][0]
}

// Proof returns the inclusion proof for index.
func (t *Tree) Proof(index uint64) (Proof, error) {
	if index >= uint64(len(t.leaves)) {
		return Proof{}, fmt.Errorf("index %d out of range (leaf count %d)", index, len(t.leaves))
	}
	p := Proof{Index: index, Leaf: t.leaves[index]}
	pos := index
	for depth := 1; depth < len(t.levels); depth++ {
		level := t.levels[depth-1]
		var step ProofStep
		if pos%2 == 0 {
			step.Side = SideRight
			if int(pos+1) < len(level) {
				step.Hash = level[pos+1]
			} else {
				step.Hash = padHash(uint64(depth), pos+1)
			}
		} else {
			step.Side = SideLeft
			step.Hash = level[pos-1]
		}
		p.Path = append(p.Path, step)
		pos /= 2
	}
	return p, nil
}

// Verify checks an inclusion proof against root, enforcing both the index
// commitment in the leaf and sibling ordering. Moving the proof to another
// index or swapping a sibling fails here.
func (p Proof) Verify(root Hash, leafCount uint64, record []byte) error {
	if p.Index >= leafCount {
		return fmt.Errorf("proof index %d out of range (leaf count %d)", p.Index, leafCount)
	}
	if LeafHash(p.Index, record) != p.Leaf {
		return errors.New("record does not match the index-bound leaf hash")
	}
	acc := p.Leaf
	pos := p.Index
	for depth, step := range p.Path {
		expected := SideRight
		if pos%2 == 1 {
			expected = SideLeft
		}
		if step.Side != expected {
			return fmt.Errorf("path step %d side %q does not match index bits", depth, step.Side)
		}
		switch step.Side {
		case SideLeft:
			acc = nodeHash(step.Hash, acc)
		case SideRight:
			acc = nodeHash(acc, step.Hash)
		default:
			return fmt.Errorf("path step %d has unknown side %q", depth, step.Side)
		}
		pos /= 2
	}
	if acc != root {
		return errors.New("recomputed root does not match version root")
	}
	return nil
}
