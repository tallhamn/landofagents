// Package audit provides append-only JSONL audit logging for LOA decisions.
package audit

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Record represents a single audit log entry.
type Record struct {
	ID            string         `json:"id"`
	Timestamp     time.Time      `json:"timestamp"`
	Agent         string         `json:"agent"`
	Scope         string         `json:"scope"`
	Action        string         `json:"action"`
	Resource      string         `json:"resource"`
	Decision      string         `json:"decision"`      // "permit" or "deny"
	DecisionPath  string         `json:"decision_path"` // "always_allowed", "policy", "unmapped", "pipe_to_shell"
	PolicyRef     string         `json:"policy_ref,omitempty"`
	PermissionRef string         `json:"permission_ref,omitempty"`
	Context       map[string]any `json:"context,omitempty"`
	LatencyMs     int64          `json:"latency_ms"`
	DenialReason  string         `json:"denial_reason,omitempty"`
	PrevHash      string         `json:"prev_hash,omitempty"`
	Hash          string         `json:"hash,omitempty"`
}

// Logger writes audit records as JSONL to date-partitioned files.
type Logger struct {
	dir            string
	mu             sync.Mutex
	counter        uint64
	instanceID     string
	lastHashByFile map[string]string
}

// NewLogger creates a new audit logger that writes to the given directory.
// The directory is created if it doesn't exist.
func NewLogger(dir string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}
	return &Logger{
		dir:            dir,
		instanceID:     newInstanceID(),
		lastHashByFile: make(map[string]string),
	}, nil
}

// Log appends a record to the audit log. It is safe for concurrent use.
func (l *Logger) Log(r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.counter++
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now().UTC()
	}
	if r.ID == "" {
		r.ID = fmt.Sprintf("AUD-%d-%s-%06d", r.Timestamp.UnixNano(), l.instanceID, l.counter)
	}

	filename := filepath.Join(l.dir, r.Timestamp.Format("2006-01-02")+".jsonl")
	prevHash, err := l.previousHashForFile(filename)
	if err != nil {
		return fmt.Errorf("resolve previous hash: %w", err)
	}
	r.PrevHash = prevHash
	r.Hash = computeHash(r)

	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal audit record: %w", err)
	}
	data = append(data, '\n')

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open audit file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}
	l.lastHashByFile[filename] = r.Hash
	return nil
}

func newInstanceID() string {
	b := make([]byte, 4)
	if _, err := crand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// ReadAll reads all records from all JSONL files in the audit directory.
func (l *Logger) ReadAll() ([]Record, error) {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return nil, fmt.Errorf("read audit dir: %w", err)
	}

	var records []Record
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".jsonl" {
			continue
		}
		recs, err := readJSONLFile(filepath.Join(l.dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		records = append(records, recs...)
	}
	return records, nil
}

// ReadByAgent reads all records for a specific agent.
func (l *Logger) ReadByAgent(agent string) ([]Record, error) {
	all, err := l.ReadAll()
	if err != nil {
		return nil, err
	}
	var filtered []Record
	for _, r := range all {
		if r.Agent == agent {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}
