package vdex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Manifest is the fixed identity of a sealed dataset version.
type Manifest struct {
	Format    string    `json:"format"`
	Dataset   string    `json:"dataset"`
	Version   uint64    `json:"version"`
	Prev      *Hash     `json:"prevRoot"`
	Root      Hash      `json:"root"`
	LeafCount uint64    `json:"leafCount"`
	SealedAt  time.Time `json:"sealedAt"`
}

const ManifestFormat = "vdex-manifest-v1"

// VersionID is a stable textual identifier for a sealed version.
func (m Manifest) VersionID() string {
	return hex.EncodeToString(m.Root[:12])
}

func (m Manifest) validate() error {
	if m.Format != ManifestFormat {
		return fmt.Errorf("unsupported manifest format %q", m.Format)
	}
	if m.Version == 0 {
		return errors.New("manifest version must be positive")
	}
	return nil
}

func (h Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h[:]))
}

func (h *Hash) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != sha256.Size {
		return fmt.Errorf("expected %d-byte hex hash", sha256.Size)
	}
	copy(h[:], raw)
	return nil
}
