package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLogAndReadBack(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewLogger(dir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	ts := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

	records := []Record{
		{
			Timestamp:    ts,
			Agent:        "goggins",
			Scope:        "goggins",
			Action:       "fs:Read",
			Resource:     "/workspace/tasks.md",
			Decision:     "permit",
			DecisionPath: "always_allowed",
			LatencyMs:    0,
		},
		{
			Timestamp:    ts.Add(2 * time.Second),
			Agent:        "goggins",
			Scope:        "goggins",
			Action:       "http:Request",
			Resource:     "api.myfitnesspal.com",
			Decision:     "deny",
			DecisionPath: "policy",
			PolicyRef:    "policies/deny-external.cedar",
			LatencyMs:    4,
			DenialReason: "No permission for api.myfitnesspal.com",
		},
		{
			Timestamp:    ts.Add(5 * time.Second),
			Agent:        "carmack",
			Scope:        "carmack",
			Action:       "http:Request",
			Resource:     "api.github.com",
			Decision:     "permit",
			DecisionPath: "policy",
			PolicyRef:    "policies/github-access.cedar",
			LatencyMs:    3,
		},
	}

	for _, r := range records {
		if err := logger.Log(r); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	// Read all back
	got, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ReadAll: got %d records, want 3", len(got))
	}

	// Verify IDs were auto-assigned
	for i, r := range got {
		if r.ID == "" {
			t.Errorf("record %d: empty ID", i)
		}
		if r.Hash == "" {
			t.Errorf("record %d: empty hash", i)
		}
		if i == 0 && r.PrevHash != "" {
			t.Errorf("record %d: expected empty prev_hash for first record", i)
		}
		if i > 0 && r.PrevHash == "" {
			t.Errorf("record %d: expected non-empty prev_hash", i)
		}
	}

	// Verify fields roundtrip
	if got[0].Agent != "goggins" {
		t.Errorf("record 0 agent: got %q, want %q", got[0].Agent, "goggins")
	}
	if got[0].Decision != "permit" {
		t.Errorf("record 0 decision: got %q, want %q", got[0].Decision, "permit")
	}
	if got[0].DecisionPath != "always_allowed" {
		t.Errorf("record 0 decision_path: got %q, want %q", got[0].DecisionPath, "always_allowed")
	}
	if got[1].Decision != "deny" {
		t.Errorf("record 1 decision: got %q, want %q", got[1].Decision, "deny")
	}
	if got[1].DenialReason == "" {
		t.Error("record 1: expected denial_reason to be set")
	}
	if got[2].Agent != "carmack" {
		t.Errorf("record 2 agent: got %q, want %q", got[2].Agent, "carmack")
	}
}

func TestReadByAgent(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewLogger(dir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	ts := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

	logger.Log(Record{Timestamp: ts, Agent: "goggins", Scope: "goggins", Action: "fs:Read", Resource: "a.txt", Decision: "permit", DecisionPath: "always_allowed"})
	logger.Log(Record{Timestamp: ts, Agent: "carmack", Scope: "carmack", Action: "fs:Read", Resource: "b.txt", Decision: "permit", DecisionPath: "always_allowed"})
	logger.Log(Record{Timestamp: ts, Agent: "goggins", Scope: "goggins", Action: "http:Request", Resource: "api.fitness.com", Decision: "deny", DecisionPath: "policy"})

	got, err := logger.ReadByAgent("goggins")
	if err != nil {
		t.Fatalf("ReadByAgent: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ReadByAgent(goggins): got %d records, want 2", len(got))
	}
	for _, r := range got {
		if r.Agent != "goggins" {
			t.Errorf("unexpected agent: %q", r.Agent)
		}
	}
}

func TestDatePartitioning(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewLogger(dir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	day1 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC)

	logger.Log(Record{Timestamp: day1, Agent: "goggins", Scope: "goggins", Action: "fs:Read", Resource: "a.txt", Decision: "permit", DecisionPath: "always_allowed"})
	logger.Log(Record{Timestamp: day2, Agent: "goggins", Scope: "goggins", Action: "fs:Read", Resource: "b.txt", Decision: "permit", DecisionPath: "always_allowed"})

	// Check two files were created
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var jsonlFiles []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".jsonl" {
			jsonlFiles = append(jsonlFiles, e.Name())
		}
	}
	if len(jsonlFiles) != 2 {
		t.Fatalf("expected 2 JSONL files, got %d: %v", len(jsonlFiles), jsonlFiles)
	}

	// ReadAll should still get both
	all, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ReadAll: got %d records, want 2", len(all))
	}
}

func TestContextRoundtrip(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewLogger(dir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	ts := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	err = logger.Log(Record{
		Timestamp:    ts,
		Agent:        "goggins",
		Scope:        "goggins",
		Action:       "email:Send",
		Resource:     "spouse@gmail.com",
		Decision:     "permit",
		DecisionPath: "policy",
		Context: map[string]any{
			"has_agent_disclaimer": true,
			"recipient_group":      "family",
		},
		LatencyMs: 7,
	})
	if err != nil {
		t.Fatalf("Log: %v", err)
	}

	got, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 record, got %d", len(got))
	}
	if got[0].Context == nil {
		t.Fatal("context is nil")
	}
	if got[0].Context["recipient_group"] != "family" {
		t.Errorf("context[recipient_group]: got %v, want %q", got[0].Context["recipient_group"], "family")
	}
}

func TestConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewLogger(dir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	ts := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	done := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() {
			done <- logger.Log(Record{
				Timestamp:    ts,
				Agent:        "goggins",
				Scope:        "goggins",
				Action:       "fs:Read",
				Resource:     "file.txt",
				Decision:     "permit",
				DecisionPath: "always_allowed",
			})
		}()
	}

	for i := 0; i < 20; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent Log: %v", err)
		}
	}

	got, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 20 {
		t.Fatalf("expected 20 records, got %d", len(got))
	}

	// Verify all IDs are unique
	ids := make(map[string]bool)
	for _, r := range got {
		if ids[r.ID] {
			t.Errorf("duplicate ID: %s", r.ID)
		}
		ids[r.ID] = true
	}
}

func TestUniqueIDsAcrossLoggerInstancesSameDirectory(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

	loggerA, err := NewLogger(dir)
	if err != nil {
		t.Fatalf("NewLogger A: %v", err)
	}
	loggerB, err := NewLogger(dir)
	if err != nil {
		t.Fatalf("NewLogger B: %v", err)
	}

	if err := loggerA.Log(Record{
		Timestamp:    ts,
		Agent:        "a",
		Scope:        "a",
		Action:       "exec:Run",
		Resource:     "ls",
		Decision:     "permit",
		DecisionPath: "shell_observe",
	}); err != nil {
		t.Fatalf("loggerA.Log: %v", err)
	}
	if err := loggerB.Log(Record{
		Timestamp:    ts,
		Agent:        "a",
		Scope:        "a",
		Action:       "exec:Run",
		Resource:     "grep",
		Decision:     "permit",
		DecisionPath: "shell_observe",
	}); err != nil {
		t.Fatalf("loggerB.Log: %v", err)
	}

	records, err := loggerA.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].ID == records[1].ID {
		t.Fatalf("expected unique IDs across logger instances, got duplicate %q", records[0].ID)
	}
}

func TestVerifyAll_ValidChain(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewLogger(dir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	ts := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	if err := logger.Log(Record{
		Timestamp: ts,
		Agent:     "goggins",
		Scope:     "goggins",
		Action:    "fs:Read",
		Resource:  "a.txt",
		Decision:  "permit",
	}); err != nil {
		t.Fatalf("Log #1: %v", err)
	}
	if err := logger.Log(Record{
		Timestamp: ts.Add(time.Second),
		Agent:     "goggins",
		Scope:     "goggins",
		Action:    "http:Request",
		Resource:  "api.example.com",
		Decision:  "deny",
	}); err != nil {
		t.Fatalf("Log #2: %v", err)
	}

	report, err := logger.VerifyAll()
	if err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}
	if report.FilesChecked != 1 {
		t.Fatalf("FilesChecked: got %d, want 1", report.FilesChecked)
	}
	if report.RecordsRead != 2 {
		t.Fatalf("RecordsRead: got %d, want 2", report.RecordsRead)
	}
	if len(report.Failures) != 0 {
		t.Fatalf("expected no failures, got: %+v", report.Failures)
	}
}

func TestVerifyAll_DetectsTampering(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewLogger(dir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	ts := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	if err := logger.Log(Record{Timestamp: ts, Agent: "goggins", Scope: "goggins", Action: "fs:Read", Resource: "a.txt", Decision: "permit"}); err != nil {
		t.Fatalf("Log #1: %v", err)
	}
	if err := logger.Log(Record{Timestamp: ts.Add(time.Second), Agent: "goggins", Scope: "goggins", Action: "fs:Read", Resource: "b.txt", Decision: "permit"}); err != nil {
		t.Fatalf("Log #2: %v", err)
	}

	logPath := filepath.Join(dir, "2026-03-01.jsonl")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := string(data)
	tampered = replaceOnce(tampered, "\"resource\":\"b.txt\"", "\"resource\":\"evil.txt\"")
	if err := os.WriteFile(logPath, []byte(tampered), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	report, err := logger.VerifyAll()
	if err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}
	if len(report.Failures) == 0 {
		t.Fatal("expected integrity failures after tampering")
	}
}

func TestVerifyAll_LegacyPrefixAllowed(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "2026-03-01.jsonl")

	legacy := `{"id":"AUD-LEGACY-1","timestamp":"2026-03-01T10:00:00Z","agent":"legacy","scope":"legacy","action":"fs:Read","resource":"a.txt","decision":"permit","decision_path":"policy","latency_ms":0}` + "\n"
	if err := os.WriteFile(logPath, []byte(legacy), 0644); err != nil {
		t.Fatalf("WriteFile legacy: %v", err)
	}

	logger, err := NewLogger(dir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if err := logger.Log(Record{
		Timestamp:    time.Date(2026, 3, 1, 10, 0, 1, 0, time.UTC),
		Agent:        "goggins",
		Scope:        "goggins",
		Action:       "fs:Read",
		Resource:     "b.txt",
		Decision:     "permit",
		DecisionPath: "policy",
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	report, err := logger.VerifyAll()
	if err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}
	if len(report.Failures) != 0 {
		t.Fatalf("expected no failures for legacy prefix, got: %+v", report.Failures)
	}
}

func replaceOnce(s, old, new string) string {
	idx := -1
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			idx = i
			break
		}
	}
	if idx == -1 {
		return s
	}
	return s[:idx] + new + s[idx+len(old):]
}
