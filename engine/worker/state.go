package worker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type stateFile struct {
	Workers map[string]Record `json:"workers"`
}

func workersDir(kitDir string) string {
	return filepath.Join(kitDir, "workers")
}

func workersStatePath(kitDir string) string {
	return filepath.Join(workersDir(kitDir), "state.json")
}

func loadState(kitDir string) (stateFile, error) {
	path := workersStatePath(kitDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return stateFile{Workers: map[string]Record{}}, nil
		}
		return stateFile{}, fmt.Errorf("read worker state: %w", err)
	}
	var st stateFile
	if err := json.Unmarshal(data, &st); err != nil {
		return stateFile{}, fmt.Errorf("parse worker state: %w", err)
	}
	if st.Workers == nil {
		st.Workers = map[string]Record{}
	}
	return st, nil
}

func saveState(kitDir string, st stateFile) error {
	if st.Workers == nil {
		st.Workers = map[string]Record{}
	}
	dir := workersDir(kitDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create workers dir: %w", err)
	}
	path := workersStatePath(kitDir)
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal worker state: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write worker state temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace worker state: %w", err)
	}
	return nil
}

func sortedWorkerIDs(st stateFile) []string {
	out := make([]string, 0, len(st.Workers))
	for id := range st.Workers {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func withLockedStateRead(kitDir string, fn func(st stateFile) error) error {
	if fn == nil {
		return fmt.Errorf("read callback is required")
	}
	lockFileHandle, err := openStateLock(kitDir)
	if err != nil {
		return err
	}
	defer lockFileHandle.Close()
	if err := lockStateFile(lockFileHandle); err != nil {
		return fmt.Errorf("lock worker state: %w", err)
	}
	defer unlockStateFile(lockFileHandle)

	st, err := loadState(kitDir)
	if err != nil {
		return err
	}
	return fn(st)
}

func withLockedStateWrite(kitDir string, fn func(st *stateFile) error) error {
	if fn == nil {
		return fmt.Errorf("write callback is required")
	}
	lockFileHandle, err := openStateLock(kitDir)
	if err != nil {
		return err
	}
	defer lockFileHandle.Close()
	if err := lockStateFile(lockFileHandle); err != nil {
		return fmt.Errorf("lock worker state: %w", err)
	}
	defer unlockStateFile(lockFileHandle)

	st, err := loadState(kitDir)
	if err != nil {
		return err
	}
	if err := fn(&st); err != nil {
		return err
	}
	return saveState(kitDir, st)
}

func openStateLock(kitDir string) (*os.File, error) {
	dir := workersDir(kitDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create workers dir: %w", err)
	}
	lockPath := filepath.Join(dir, "state.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open worker state lock: %w", err)
	}
	return f, nil
}
