//go:build windows

package worker

import (
	"os"
	"sync"
)

var stateLockMu sync.Mutex

func lockStateFile(_ *os.File) error {
	stateLockMu.Lock()
	return nil
}

func unlockStateFile(_ *os.File) {
	stateLockMu.Unlock()
}
