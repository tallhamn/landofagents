package approval

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

func writeDenial(t *testing.T, dir string, r audit.Record) {
	t.Helper()
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now().UTC()
	}
	if r.Decision == "" {
		r.Decision = "deny"
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := filepath.Join(dir, r.Timestamp.Format("2006-01-02")+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write(data)
}

func TestWatchDetectsNewDenial(t *testing.T) {
	dir := t.TempDir()
	w := NewWatcher(dir, "goggins")
	w.SetIntervals(10*time.Millisecond, 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch := w.Watch(ctx)

	// Write a denial after a short delay
	time.AfterFunc(20*time.Millisecond, func() {
		writeDenial(t, dir, audit.Record{
			ID:       "AUD-000001",
			Agent:    "goggins",
			Action:   "http:Request",
			Resource: "evil.com",
		})
	})

	select {
	case batch := <-ch:
		if len(batch) != 1 {
			t.Fatalf("expected 1 denial in batch, got %d", len(batch))
		}
		if batch[0].Resource != "evil.com" {
			t.Errorf("resource: got %q", batch[0].Resource)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for denial")
	}
}

func TestWatchFiltersAgent(t *testing.T) {
	dir := t.TempDir()
	w := NewWatcher(dir, "goggins")
	w.SetIntervals(10*time.Millisecond, 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch := w.Watch(ctx)

	// Write denials for two agents
	time.AfterFunc(20*time.Millisecond, func() {
		writeDenial(t, dir, audit.Record{
			ID:       "AUD-000001",
			Agent:    "carmack",
			Action:   "http:Request",
			Resource: "evil.com",
		})
		writeDenial(t, dir, audit.Record{
			ID:       "AUD-000002",
			Agent:    "goggins",
			Action:   "http:Request",
			Resource: "api.wrike.com",
		})
	})

	select {
	case batch := <-ch:
		if len(batch) != 1 {
			t.Fatalf("expected 1 denial (filtered), got %d", len(batch))
		}
		if batch[0].Agent != "goggins" {
			t.Errorf("agent: got %q, want goggins", batch[0].Agent)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for denial")
	}
}

func TestWatchAllAgentsWhenEmptyFilter(t *testing.T) {
	dir := t.TempDir()
	w := NewWatcher(dir, "")
	w.SetIntervals(10*time.Millisecond, 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch := w.Watch(ctx)

	time.AfterFunc(20*time.Millisecond, func() {
		writeDenial(t, dir, audit.Record{
			ID:       "AUD-000001",
			Agent:    "carmack",
			Action:   "http:Request",
			Resource: "evil.com",
		})
		writeDenial(t, dir, audit.Record{
			ID:       "AUD-000002",
			Agent:    "goggins",
			Action:   "http:Request",
			Resource: "api.wrike.com",
		})
	})

	select {
	case batch := <-ch:
		if len(batch) != 2 {
			t.Fatalf("expected 2 denials (all agents), got %d", len(batch))
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for denials")
	}
}

func TestWatchIncludesPermitsWhenEnabled(t *testing.T) {
	dir := t.TempDir()
	w := NewWatcher(dir, "goggins")
	w.SetIncludePermits(true)
	w.SetIntervals(10*time.Millisecond, 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch := w.Watch(ctx)

	time.AfterFunc(20*time.Millisecond, func() {
		writeDenial(t, dir, audit.Record{
			ID:       "AUD-000101",
			Agent:    "goggins",
			Action:   "http:Request",
			Resource: "api.wrike.com",
			Decision: "permit",
		})
		writeDenial(t, dir, audit.Record{
			ID:       "AUD-000102",
			Agent:    "goggins",
			Action:   "http:Request",
			Resource: "evil.com",
			Decision: "deny",
		})
	})

	select {
	case batch := <-ch:
		if len(batch) != 2 {
			t.Fatalf("expected 2 records (permit+deny), got %d", len(batch))
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for records")
	}
}

func TestWatchBatchesWithinWindow(t *testing.T) {
	dir := t.TempDir()
	w := NewWatcher(dir, "goggins")
	w.SetIntervals(10*time.Millisecond, 100*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch := w.Watch(ctx)

	// Write 3 denials quickly
	time.AfterFunc(20*time.Millisecond, func() {
		for i := 1; i <= 3; i++ {
			writeDenial(t, dir, audit.Record{
				ID:       fmt.Sprintf("AUD-%06d", i),
				Agent:    "goggins",
				Action:   "http:Request",
				Resource: fmt.Sprintf("site%d.com", i),
			})
		}
	})

	select {
	case batch := <-ch:
		if len(batch) != 3 {
			t.Fatalf("expected 3 denials in single batch, got %d", len(batch))
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for batch")
	}
}

func TestWatchSplitsBatches(t *testing.T) {
	dir := t.TempDir()
	w := NewWatcher(dir, "goggins")
	w.SetIntervals(10*time.Millisecond, 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch := w.Watch(ctx)

	// Write first denial
	time.AfterFunc(20*time.Millisecond, func() {
		writeDenial(t, dir, audit.Record{
			ID:       "AUD-000001",
			Agent:    "goggins",
			Action:   "http:Request",
			Resource: "site1.com",
		})
	})

	// Wait for first batch
	select {
	case batch := <-ch:
		if len(batch) != 1 {
			t.Fatalf("first batch: expected 1, got %d", len(batch))
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for first batch")
	}

	// Write second denial after first batch is emitted
	writeDenial(t, dir, audit.Record{
		ID:       "AUD-000002",
		Agent:    "goggins",
		Action:   "http:Request",
		Resource: "site2.com",
	})

	// Wait for second batch
	select {
	case batch := <-ch:
		if len(batch) != 1 {
			t.Fatalf("second batch: expected 1, got %d", len(batch))
		}
		if batch[0].Resource != "site2.com" {
			t.Errorf("resource: got %q", batch[0].Resource)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for second batch")
	}
}

func TestWatchDeduplicates(t *testing.T) {
	dir := t.TempDir()
	w := NewWatcher(dir, "goggins")
	w.SetIntervals(10*time.Millisecond, 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch := w.Watch(ctx)

	// Write same agent+action+resource twice with different IDs
	time.AfterFunc(20*time.Millisecond, func() {
		writeDenial(t, dir, audit.Record{
			ID:       "AUD-000001",
			Agent:    "goggins",
			Action:   "http:Request",
			Resource: "api.wrike.com",
		})
		writeDenial(t, dir, audit.Record{
			ID:       "AUD-000002",
			Agent:    "goggins",
			Action:   "http:Request",
			Resource: "api.wrike.com",
		})
	})

	select {
	case batch := <-ch:
		if len(batch) != 1 {
			t.Fatalf("expected 1 deduplicated denial, got %d", len(batch))
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for batch")
	}
}

func TestWatchSkipsPreExistingDenials(t *testing.T) {
	dir := t.TempDir()

	// Write a denial BEFORE creating the watcher (simulates previous session)
	writeDenial(t, dir, audit.Record{
		ID:       "AUD-000001",
		Agent:    "goggins",
		Action:   "http:Request",
		Resource: "old-session.com",
	})

	// Now create the watcher — should skip to end of existing files
	w := NewWatcher(dir, "goggins")
	w.SetIntervals(10*time.Millisecond, 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch := w.Watch(ctx)

	// Write a NEW denial after watcher starts
	time.AfterFunc(20*time.Millisecond, func() {
		writeDenial(t, dir, audit.Record{
			ID:       "AUD-000002",
			Agent:    "goggins",
			Action:   "http:Request",
			Resource: "new-session.com",
		})
	})

	select {
	case batch := <-ch:
		if len(batch) != 1 {
			t.Fatalf("expected 1 denial (new only), got %d", len(batch))
		}
		if batch[0].Resource != "new-session.com" {
			t.Errorf("got old denial %q, want new-session.com", batch[0].Resource)
		}
	case <-ctx.Done():
		t.Fatal("timeout — watcher may have re-surfaced old denial or missed new one")
	}
}

func TestWatchPicksUpNewSessions(t *testing.T) {
	dir := t.TempDir()

	// Start watcher with no audit files
	w := NewWatcher(dir, "goggins")
	w.SetIntervals(10*time.Millisecond, 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch := w.Watch(ctx)

	// Simulate a new session starting and writing to a new audit file
	time.AfterFunc(50*time.Millisecond, func() {
		writeDenial(t, dir, audit.Record{
			ID:        "AUD-000001",
			Agent:     "goggins",
			Action:    "http:Request",
			Resource:  "news.google.com",
			Timestamp: time.Now().UTC(),
		})
	})

	select {
	case batch := <-ch:
		if len(batch) != 1 {
			t.Fatalf("expected 1 denial from new session, got %d", len(batch))
		}
		if batch[0].Resource != "news.google.com" {
			t.Errorf("resource: got %q", batch[0].Resource)
		}
	case <-ctx.Done():
		t.Fatal("timeout — watcher did not pick up denial from new session")
	}
}

func TestWatchSkipsOldButPicksUpNewInSameFile(t *testing.T) {
	dir := t.TempDir()

	// Pre-existing denials from a previous session
	writeDenial(t, dir, audit.Record{
		ID:       "AUD-000001",
		Agent:    "goggins",
		Action:   "http:Request",
		Resource: "already-approved.com",
	})
	writeDenial(t, dir, audit.Record{
		ID:       "AUD-000002",
		Agent:    "goggins",
		Action:   "http:Request",
		Resource: "also-old.com",
	})

	w := NewWatcher(dir, "goggins")
	w.SetIntervals(10*time.Millisecond, 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	ch := w.Watch(ctx)

	// New denial appended to same file (same day)
	time.AfterFunc(30*time.Millisecond, func() {
		writeDenial(t, dir, audit.Record{
			ID:       "AUD-000003",
			Agent:    "goggins",
			Action:   "http:Request",
			Resource: "brand-new.com",
		})
	})

	select {
	case batch := <-ch:
		// Should only contain the new denial, not the 2 old ones
		if len(batch) != 1 {
			t.Fatalf("expected 1 new denial, got %d", len(batch))
		}
		if batch[0].Resource != "brand-new.com" {
			t.Errorf("resource: got %q, want brand-new.com", batch[0].Resource)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
}
