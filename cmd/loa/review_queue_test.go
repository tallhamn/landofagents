package main

import (
	"testing"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

func TestPendingReviewDenials_UsesSharedDedupAndFilter(t *testing.T) {
	records := []audit.Record{
		{Agent: "hackerman", Action: "http:Request", Resource: "news.google.com", Decision: "deny", DecisionPath: "policy"},
		{Agent: "hackerman", Action: "http:Request", Resource: "news.google.com", Decision: "deny", DecisionPath: "policy"},
		{Agent: "goggins", Action: "http:Request", Resource: "news.google.com", Decision: "deny", DecisionPath: "policy"},
		{Agent: "hackerman", Action: "http:Request", Resource: "api.anthropic.com", Decision: "permit", DecisionPath: "policy"},
	}

	all := pendingReviewDenials(records, "")
	if got, want := len(all), 2; got != want {
		t.Fatalf("all pending len=%d want %d (%+v)", got, want, all)
	}

	hackerman := pendingReviewDenials(records, "hackerman")
	if got, want := len(hackerman), 1; got != want {
		t.Fatalf("hackerman pending len=%d want %d (%+v)", got, want, hackerman)
	}
}

func TestDenyBurstFilter_SuppressesRapidRepeats(t *testing.T) {
	filter := newDenyBurstFilter(2 * time.Second)
	now := time.Now()
	input := []audit.Record{
		{Agent: "hackerman", Action: "http:Request", Resource: "news.yahoo.com", Decision: "deny", DecisionPath: "policy"},
		{Agent: "hackerman", Action: "http:Request", Resource: "news.yahoo.com", Decision: "deny", DecisionPath: "policy"},
	}

	first := filter.Filter(input, now)
	if got, want := len(first), 1; got != want {
		t.Fatalf("first filter len=%d want %d", got, want)
	}

	second := filter.Filter(input, now.Add(500*time.Millisecond))
	if got, want := len(second), 0; got != want {
		t.Fatalf("second filter len=%d want %d", got, want)
	}

	third := filter.Filter(input, now.Add(3*time.Second))
	if got, want := len(third), 1; got != want {
		t.Fatalf("third filter len=%d want %d", got, want)
	}
}

func TestApprovedTracker_FiltersCoveredDenials(t *testing.T) {
	tracker := newApprovedTracker(5 * time.Second)
	now := time.Now()

	// Mark chatgpt.com as approved
	tracker.Mark([]audit.Record{
		{Agent: "hackerman", Action: "http:Request", Resource: "chatgpt.com", Decision: "deny"},
	}, now)

	// A new denial for the same resource should be filtered
	denials := []audit.Record{
		{Agent: "hackerman", Action: "http:Request", Resource: "chatgpt.com", Decision: "deny", DecisionPath: "policy"},
		{Agent: "hackerman", Action: "http:Request", Resource: "news.google.com", Decision: "deny", DecisionPath: "policy"},
	}
	kept, covered := tracker.Filter(denials, now.Add(1*time.Second))
	if got, want := len(covered), 1; got != want {
		t.Fatalf("covered len=%d want %d", got, want)
	}
	if got, want := covered[0].Resource, "chatgpt.com"; got != want {
		t.Fatalf("covered resource=%q want %q", got, want)
	}
	if got, want := len(kept), 1; got != want {
		t.Fatalf("kept len=%d want %d", got, want)
	}

	// After the window expires, the denial should come through
	kept2, covered2 := tracker.Filter(denials, now.Add(15*time.Second))
	if got, want := len(covered2), 0; got != want {
		t.Fatalf("expired covered len=%d want %d", got, want)
	}
	if got, want := len(kept2), 2; got != want {
		t.Fatalf("expired kept len=%d want %d", got, want)
	}
}

func TestIsUnmappedDecisionPath(t *testing.T) {
	if !isUnmappedDecisionPath("unmapped") {
		t.Fatal("expected unmapped to be classified as unmapped")
	}
	if !isUnmappedDecisionPath("pipe_to_shell") {
		t.Fatal("expected pipe_to_shell to be classified as unmapped")
	}
	if isUnmappedDecisionPath("policy") {
		t.Fatal("did not expect policy path to be classified as unmapped")
	}
}
