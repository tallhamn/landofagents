package worker

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// Get returns worker status.
func (m *Manager) Get(ctx context.Context, workerID string) (WorkerResponse, error) {
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return WorkerResponse{}, &APIError{Code: CodeInvalidRequest, Message: "worker_id is required"}
	}
	if err := ctx.Err(); err != nil {
		return WorkerResponse{}, wrapInternal(err)
	}

	var out WorkerResponse
	err := withLockedStateWrite(m.kitDir, func(st *stateFile) error {
		rec, ok := st.Workers[workerID]
		if !ok {
			return &APIError{Code: CodeWorkerNotFound, Message: fmt.Sprintf("worker %q not found", workerID)}
		}

		if rec.Status == "running" || rec.Status == "pending" {
			composeEnv := append(os.Environ(), composeEnvWithKit(m.kitDir)...)
			running, err := m.docker.ServiceRunning(rec.ComposePath, composeEnv, rec.Agent)
			if err != nil {
				return &APIError{Code: CodeInternal, Message: fmt.Sprintf("check worker status: %v", err)}
			}
			if !running {
				rec.Status = "failed"
				rec.UpdatedAt = time.Now().UTC()
				st.Workers[workerID] = rec
			}
		}

		out = workerResponse(rec)
		return nil
	})
	if err != nil {
		return WorkerResponse{}, wrapInternal(err)
	}
	return out, nil
}

// Terminate stops a running worker.
func (m *Manager) Terminate(ctx context.Context, workerID, reason string) (TerminateResponse, error) {
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return TerminateResponse{}, &APIError{Code: CodeInvalidRequest, Message: "worker_id is required"}
	}
	if err := ctx.Err(); err != nil {
		return TerminateResponse{}, wrapInternal(err)
	}

	var out TerminateResponse
	err := withLockedStateWrite(m.kitDir, func(st *stateFile) error {
		rec, ok := st.Workers[workerID]
		if !ok {
			return &APIError{Code: CodeWorkerNotFound, Message: fmt.Sprintf("worker %q not found", workerID)}
		}

		if rec.Status == "terminated" {
			out = TerminateResponse{Version: VersionV1, WorkerID: workerID, Status: "terminated"}
			return nil
		}

		composeEnv := append(os.Environ(), composeEnvWithKit(m.kitDir)...)
		if err := m.docker.ComposeDown(rec.ComposePath, composeEnv); err != nil {
			_ = m.logTerminateFailure(rec, reason, err)
			return &APIError{Code: CodeInternal, Message: fmt.Sprintf("terminate worker: %v", err)}
		}

		rec.Status = "terminated"
		rec.UpdatedAt = time.Now().UTC()
		st.Workers[workerID] = rec
		_ = m.logTerminate(rec, reason)

		out = TerminateResponse{
			Version:  VersionV1,
			WorkerID: workerID,
			Status:   "terminated",
		}
		return nil
	})
	if err != nil {
		return TerminateResponse{}, wrapInternal(err)
	}
	return out, nil
}

// List returns persisted workers in deterministic order.
func (m *Manager) List(ctx context.Context) (ListResponse, error) {
	if err := ctx.Err(); err != nil {
		return ListResponse{}, wrapInternal(err)
	}

	var out ListResponse
	err := withLockedStateRead(m.kitDir, func(st stateFile) error {
		ids := sortedWorkerIDs(st)
		workers := make([]WorkerResponse, 0, len(ids))
		for _, id := range ids {
			workers = append(workers, workerResponse(st.Workers[id]))
		}
		out = ListResponse{Version: VersionV1, Workers: workers}
		return nil
	})
	if err != nil {
		return ListResponse{}, wrapInternal(err)
	}
	return out, nil
}
