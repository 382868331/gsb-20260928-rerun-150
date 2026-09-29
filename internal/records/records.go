// Package records handles canonical JSONL record framing.
package records

import (
	"bytes"
	"errors"
	"io"
)

// ReadAll splits a canonical JSONL payload into records. The file MUST end
// with a newline, which makes an empty record unambiguously representable as a
// blank line; record byte content is otherwise preserved exactly.
func ReadAll(r io.Reader) ([][]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return nil, errors.New("records file must end with a newline")
	}
	var records [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			line := data[start:i]
			if bytes.ContainsRune(line, '\r') {
				return nil, errors.New("carriage return in records file; use LF newlines")
			}
			records = append(records, line)
			start = i + 1
		}
	}
	return records, nil
}
