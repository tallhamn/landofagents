package approval

import (
	"encoding/json"
	"io"
	"os"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

// readNewRecords reads records from the given file starting at the last known offset.
func (w *Watcher) readNewRecords(path string) []audit.Record {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	offset := w.fileOffsets[path]
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil
		}
	}

	var records []audit.Record
	dec := json.NewDecoder(f)
	for dec.More() {
		var r audit.Record
		if err := dec.Decode(&r); err != nil {
			break
		}
		records = append(records, r)
	}

	if newOffset, err := f.Seek(0, io.SeekCurrent); err == nil {
		if info, statErr := f.Stat(); statErr == nil {
			w.fileOffsets[path] = info.Size()
		} else {
			w.fileOffsets[path] = newOffset
		}
	}
	return records
}
