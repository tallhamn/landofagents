package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/marcusmom/land-of-agents/app/adapters/openclaw"
	gapcontrol "github.com/marcusmom/land-of-agents/gap/control"
	"github.com/marcusmom/land-of-agents/engine/worker"
)

func runWorkerLaunchCompat(ctx context.Context, req worker.LaunchRequest) (worker.LaunchResponse, error) {
	if svc, ok := workerAuthorityService(); ok {
		decision, err := svc.SpawnAsUID(ctx, os.Getuid(), workerLaunchToControlSpawn(req))
		if err == nil {
			if strings.EqualFold(strings.TrimSpace(decision.Decision), "permit") {
				return worker.LaunchResponse{
					Version:        worker.VersionV1,
					WorkerID:       strings.TrimSpace(decision.WorkerID),
					Agent:          strings.TrimSpace(req.Agent),
					SessionID:      strings.TrimSpace(req.SessionID),
					ParentWorkerID: strings.TrimSpace(req.ParentWorkerID),
					Status:         strings.TrimSpace(decision.Status),
				}, nil
			}
			if strings.TrimSpace(decision.ReasonCode) != "unauthenticated" {
				return worker.LaunchResponse{}, workerErrorFromControlDecision(decision)
			}
		} else if !isControlUnauthenticated(err) {
			return worker.LaunchResponse{}, workerErrorFromControlErr(err)
		}
	}

	mgr, err := workerManager()
	if err != nil {
		return worker.LaunchResponse{}, err
	}
	return mgr.Launch(ctx, req)
}

func runWorkerGetCompat(ctx context.Context, workerID string) (worker.WorkerResponse, error) {
	if svc, ok := workerAuthorityService(); ok {
		resp, err := svc.StatusAsUID(ctx, os.Getuid(), gapcontrol.WorkerStatusRequest{
			Version:   gapcontrol.VersionV1,
			RequestID: fmt.Sprintf("req_worker_get_%d", os.Getpid()),
			WorkerID:  strings.TrimSpace(workerID),
		})
		if err == nil {
			return worker.WorkerResponse{
				Version:   worker.VersionV1,
				WorkerID:  strings.TrimSpace(resp.WorkerID),
				Agent:     strings.TrimSpace(resp.AgentID),
				SessionID: strings.TrimSpace(resp.SessionID),
				Status:    strings.TrimSpace(resp.Status),
			}, nil
		}
		if !isControlUnauthenticated(err) {
			return worker.WorkerResponse{}, workerErrorFromControlErr(err)
		}
	}

	mgr, err := workerManager()
	if err != nil {
		return worker.WorkerResponse{}, err
	}
	return mgr.Get(ctx, workerID)
}

func runWorkerTerminateCompat(ctx context.Context, workerID, reason string) (worker.TerminateResponse, error) {
	if svc, ok := workerAuthorityService(); ok {
		decision, err := svc.TerminateAsUID(ctx, os.Getuid(), gapcontrol.TerminateRequest{
			Version:   gapcontrol.VersionV1,
			RequestID: fmt.Sprintf("req_worker_terminate_%d", os.Getpid()),
			WorkerID:  strings.TrimSpace(workerID),
			Reason:    strings.TrimSpace(reason),
		})
		if err == nil {
			if strings.EqualFold(strings.TrimSpace(decision.Decision), "permit") {
				return worker.TerminateResponse{
					Version:  worker.VersionV1,
					WorkerID: strings.TrimSpace(decision.WorkerID),
					Status:   strings.TrimSpace(decision.Status),
				}, nil
			}
			if strings.TrimSpace(decision.ReasonCode) != "unauthenticated" {
				return worker.TerminateResponse{}, workerErrorFromControlDecision(decision)
			}
		} else if !isControlUnauthenticated(err) {
			return worker.TerminateResponse{}, workerErrorFromControlErr(err)
		}
	}

	mgr, err := workerManager()
	if err != nil {
		return worker.TerminateResponse{}, err
	}
	return mgr.Terminate(ctx, workerID, reason)
}

func runWorkerListCompat(ctx context.Context) (worker.ListResponse, error) {
	if svc, ok := workerAuthorityService(); ok {
		resp, err := svc.ListAsUID(ctx, os.Getuid(), fmt.Sprintf("req_worker_list_%d", os.Getpid()))
		if err == nil {
			workers := make([]worker.WorkerResponse, 0, len(resp.Workers))
			for _, w := range resp.Workers {
				workers = append(workers, worker.WorkerResponse{
					Version:   worker.VersionV1,
					WorkerID:  strings.TrimSpace(w.WorkerID),
					Agent:     strings.TrimSpace(w.AgentID),
					SessionID: strings.TrimSpace(w.SessionID),
					Status:    strings.TrimSpace(w.Status),
				})
			}
			return worker.ListResponse{Version: worker.VersionV1, Workers: workers}, nil
		}
		if !isControlUnauthenticated(err) {
			return worker.ListResponse{}, workerErrorFromControlErr(err)
		}
	}

	mgr, err := workerManager()
	if err != nil {
		return worker.ListResponse{}, err
	}
	return mgr.List(ctx)
}

func workerManager() (*worker.Manager, error) {
	mgr, err := worker.NewManager(kitDir(), worker.WithLaunchValidator(openclaw.StrictValidator{}))
	if err != nil {
		return nil, &worker.APIError{Code: worker.CodeInternal, Message: err.Error()}
	}
	return mgr, nil
}
