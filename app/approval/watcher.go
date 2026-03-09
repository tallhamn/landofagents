package approval

import (
	"context"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

// Watcher polls an audit directory for new denial records, batches them
// within a time window, and sends batches to a channel.
type Watcher struct {
	auditDir       string
	agent          string
	pollInterval   time.Duration
	batchWindow    time.Duration
	includePermits bool

	fileOffsets map[string]int64
	seen        map[string]bool
}

// NewWatcher creates a watcher for denials in the given audit directory.
// It initializes file offsets to current file sizes so only NEW denials
// (written after the watcher starts) are surfaced. Old denials are
// handled by `loa inbox`.
func NewWatcher(auditDir, agent string) *Watcher {
	w := &Watcher{
		auditDir:     auditDir,
		agent:        agent,
		pollInterval: 500 * time.Millisecond,
		batchWindow:  2 * time.Second,
		fileOffsets:  make(map[string]int64),
		seen:         make(map[string]bool),
	}
	w.skipExisting()
	return w
}

// SetIntervals overrides the default poll and batch intervals (for testing).
func (w *Watcher) SetIntervals(poll, batch time.Duration) {
	w.pollInterval = poll
	w.batchWindow = batch
}

// SetIncludePermits toggles whether watch emits permit events in addition to denies.
func (w *Watcher) SetIncludePermits(include bool) {
	w.includePermits = include
}

// Watch polls for new denials and sends batches to the returned channel.
// Runs until ctx is cancelled.
func (w *Watcher) Watch(ctx context.Context) <-chan []audit.Record {
	ch := make(chan []audit.Record, 16)
	go func() {
		defer close(ch)

		var pending []audit.Record
		var batchTimer *time.Timer
		var batchCh <-chan time.Time

		pollTicker := time.NewTicker(w.pollInterval)
		defer pollTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				if len(pending) > 0 {
					ch <- pending
				}
				return
			case <-pollTicker.C:
				newDenials := w.pollNewDenials()
				if len(newDenials) == 0 {
					continue
				}
				pending = append(pending, newDenials...)
				if batchTimer == nil {
					batchTimer = time.NewTimer(w.batchWindow)
					batchCh = batchTimer.C
				}
			case <-batchCh:
				if len(pending) > 0 {
					if w.includePermits {
						ch <- pending
					} else {
						ch <- dedupBatch(pending)
					}
					pending = nil
				}
				batchTimer = nil
				batchCh = nil
			}
		}
	}()
	return ch
}
