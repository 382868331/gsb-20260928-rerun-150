package vdex

import (
	"crypto/sha256"
	"encoding/binary"
)

// Hash is the 32-byte SHA-256 digest used everywhere in vdex.
type Hash [sha256.Size]byte

func hashDomain(domain string, parts ...[]byte) Hash {
	h := sha256.New()
	h.Write([]byte(domain))
	for _, p := range parts {
		h.Write(p)
	}
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

func u64Bytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// LeafHash binds a record to its absolute position. Two records with
// identical content at different indices therefore have distinct hashes,
// and a proof cannot be replayed at a different position.
func LeafHash(index uint64, record []byte) Hash {
	return hashDomain("vdex-leaf-v1", u64Bytes(index), record)
}

func nodeHash(left, right Hash) Hash {
	return hashDomain("vdex-node-v1", left[:], right[:])
}
