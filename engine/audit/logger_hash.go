package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

func (l *Logger) previousHashForFile(path string) (string, error) {
	if hash, ok := l.lastHashByFile[path]; ok {
		return hash, nil
	}

	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			l.lastHashByFile[path] = ""
			return "", nil
		}
		return "", fmt.Errorf("stat %s: %w", path, err)
	}

	records, err := readJSONLFile(path)
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		l.lastHashByFile[path] = ""
		return "", nil
	}
	lastHash := records[len(records)-1].Hash
	l.lastHashByFile[path] = lastHash
	return lastHash, nil
}

func computeHash(r Record) string {
	r = r.withoutHash()
	data, _ := json.Marshal(r)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (r Record) withoutHash() Record {
	r.Hash = ""
	return r
}

func readJSONLFile(path string) ([]Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var records []Record
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var r Record
		if err := dec.Decode(&r); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode record in %s: %w", path, err)
		}
		records = append(records, r)
	}
	return records, nil
}
