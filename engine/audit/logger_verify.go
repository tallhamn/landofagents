package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// VerificationFailure describes a single integrity issue in the audit chain.
type VerificationFailure struct {
	File   string
	Line   int
	Reason string
}

// VerificationReport summarizes audit integrity verification.
type VerificationReport struct {
	FilesChecked int
	RecordsRead  int
	Failures     []VerificationFailure
}

// VerifyAll validates hash chaining for all JSONL audit files.
// Legacy records without hash fields are allowed only as a prefix in a file.
func (l *Logger) VerifyAll() (*VerificationReport, error) {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return nil, fmt.Errorf("read audit dir: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".jsonl" {
			continue
		}
		files = append(files, filepath.Join(l.dir, entry.Name()))
	}
	sort.Strings(files)

	report := &VerificationReport{FilesChecked: len(files)}
	for _, file := range files {
		if err := verifyFile(file, report); err != nil {
			return nil, err
		}
	}
	return report, nil
}

func verifyFile(path string, report *VerificationReport) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))

	var prevHash string
	chainStarted := false
	line := 0

	for {
		var r Record
		if err := dec.Decode(&r); err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
		line++
		report.RecordsRead++

		if r.Hash == "" {
			if chainStarted {
				report.Failures = append(report.Failures, VerificationFailure{
					File:   path,
					Line:   line,
					Reason: "missing hash after hash chain started",
				})
			}
			continue
		}

		if !chainStarted {
			chainStarted = true
			if r.PrevHash != "" {
				report.Failures = append(report.Failures, VerificationFailure{
					File:   path,
					Line:   line,
					Reason: "first hashed record must have empty prev_hash",
				})
			}
		} else if r.PrevHash != prevHash {
			report.Failures = append(report.Failures, VerificationFailure{
				File:   path,
				Line:   line,
				Reason: fmt.Sprintf("prev_hash mismatch: got %q want %q", r.PrevHash, prevHash),
			})
		}

		wantHash := computeHash(r.withoutHash())
		if r.Hash != wantHash {
			report.Failures = append(report.Failures, VerificationFailure{
				File:   path,
				Line:   line,
				Reason: "record hash mismatch",
			})
		}
		prevHash = r.Hash
	}
	return nil
}
