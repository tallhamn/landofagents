package loaledger

import (
	"strings"
	"testing"
	"time"

	gaptrail "github.com/marcusmom/land-of-agents/gap/trail"
)

func TestAppendEventAndReadAll(t *testing.T) {
	kit := t.TempDir()
	svc, err := New(kit)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ts := time.Date(2026, 3, 7, 12, 30, 0, 0, time.UTC)
	err = svc.AppendEvent(gaptrail.Event{
		Version:      gaptrail.VersionV1,
		EventID:      "evt_1",
		Timestamp:    ts.Format(time.RFC3339),
		AgentID:      "hackerman",
		Scope:        "hackerman",
		Action:       "http:Request",
		Resource:     "news.google.com",
		Decision:     "deny",
		DecisionPath: "policy",
		Reason:       "No policy permits hackerman to reach news.google.com",
		LatencyMs:    42,
		Context: map[string]any{
			"run_id": "run_1",
		},
	})
	if err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}

	records, err := svc.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records len=%d want 1", len(records))
	}
	r := records[0]
	if r.ID != "evt_1" {
		t.Fatalf("id=%q want evt_1", r.ID)
	}
	if got := r.Timestamp.UTC().Format(time.RFC3339); got != ts.Format(time.RFC3339) {
		t.Fatalf("timestamp=%q want %q", got, ts.Format(time.RFC3339))
	}
	if r.Agent != "hackerman" || r.Scope != "hackerman" {
		t.Fatalf("agent/scope mismatch: agent=%q scope=%q", r.Agent, r.Scope)
	}
	if r.Action != "http:Request" || r.Resource != "news.google.com" {
		t.Fatalf("action/resource mismatch: action=%q resource=%q", r.Action, r.Resource)
	}
	if r.Decision != "deny" || r.DecisionPath != "policy" {
		t.Fatalf("decision mismatch: decision=%q path=%q", r.Decision, r.DecisionPath)
	}
	if r.DenialReason == "" {
		t.Fatal("denial reason should be set")
	}
	if r.Context["run_id"] != "run_1" {
		t.Fatalf("context mismatch: %+v", r.Context)
	}
}

func TestReadAllEventsRoundTrip(t *testing.T) {
	kit := t.TempDir()
	svc, err := New(kit)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := svc.AppendEvent(gaptrail.Event{
		Version:      gaptrail.VersionV1,
		EventID:      "evt_2",
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		AgentID:      "clawfather",
		Action:       "worker:Launch",
		Resource:     "wk_1",
		Decision:     "permit",
		DecisionPath: "worker_control_plane",
	}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	events, err := svc.ReadAllEvents()
	if err != nil {
		t.Fatalf("ReadAllEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events len=%d want 1", len(events))
	}
	e := events[0]
	if e.Version != gaptrail.VersionV1 {
		t.Fatalf("version=%q want %q", e.Version, gaptrail.VersionV1)
	}
	if e.AgentID != "clawfather" || e.Action != "worker:Launch" || e.Resource != "wk_1" {
		t.Fatalf("event mismatch: %+v", e)
	}
	if e.Decision != "permit" {
		t.Fatalf("decision=%q want permit", e.Decision)
	}
}

func TestAppendEventRejectsInvalidTimestamp(t *testing.T) {
	kit := t.TempDir()
	svc, err := New(kit)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = svc.AppendEvent(gaptrail.Event{
		Version:   gaptrail.VersionV1,
		Timestamp: "not-a-time",
		AgentID:   "hackerman",
		Action:    "exec:Run",
	})
	if err == nil {
		t.Fatal("expected timestamp parse error")
	}
	if !strings.Contains(err.Error(), "parse event timestamp") {
		t.Fatalf("unexpected error: %v", err)
	}
}
