package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	gapcontrol "github.com/marcusmom/land-of-agents/gap/control"
)

type fakeControlAuthority struct {
	mu         sync.Mutex
	lastSpawn  gapcontrol.SpawnRequest
	lastUID    int
	statusErr  error
	spawnErr   error
	listResp   gapcontrol.WorkerListResponse
	statusResp gapcontrol.WorkerStatusResponse
}

func (f *fakeControlAuthority) SpawnAsUID(_ context.Context, uid int, req gapcontrol.SpawnRequest) (gapcontrol.SpawnDecision, error) {
	f.mu.Lock()
	f.lastUID = uid
	f.lastSpawn = req
	err := f.spawnErr
	f.mu.Unlock()
	if err != nil {
		return gapcontrol.SpawnDecision{}, err
	}
	return gapcontrol.SpawnDecision{
		Version:              gapcontrol.VersionV1,
		RequestID:            req.RequestID,
		DecisionID:           "dec_test",
		Decision:             "permit",
		EffectivePrincipalID: "gateway:test",
		EffectiveAgentID:     req.AgentID,
		PolicyHash:           "sha256:test",
		WorkerID:             "wk_test",
		Status:               "running",
		ExpiresAt:            time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339),
	}, nil
}

func (f *fakeControlAuthority) StatusAsUID(_ context.Context, uid int, req gapcontrol.WorkerStatusRequest) (gapcontrol.WorkerStatusResponse, error) {
	f.mu.Lock()
	f.lastUID = uid
	err := f.statusErr
	resp := f.statusResp
	f.mu.Unlock()
	if err != nil {
		return gapcontrol.WorkerStatusResponse{}, err
	}
	if resp.Version == "" {
		resp = gapcontrol.WorkerStatusResponse{
			Version:   gapcontrol.VersionV1,
			RequestID: req.RequestID,
			WorkerID:  req.WorkerID,
			AgentID:   "hackerman",
			SessionID: "sess_test",
			Status:    "running",
		}
	}
	return resp, nil
}

func (f *fakeControlAuthority) TerminateAsUID(_ context.Context, uid int, req gapcontrol.TerminateRequest) (gapcontrol.SpawnDecision, error) {
	f.mu.Lock()
	f.lastUID = uid
	f.mu.Unlock()
	return gapcontrol.SpawnDecision{
		Version:              gapcontrol.VersionV1,
		RequestID:            req.RequestID,
		DecisionID:           "dec_term",
		Decision:             "permit",
		EffectivePrincipalID: "gateway:test",
		EffectiveAgentID:     "hackerman",
		PolicyHash:           "sha256:test",
		WorkerID:             req.WorkerID,
		Status:               "terminated",
		ExpiresAt:            time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339),
	}, nil
}

func (f *fakeControlAuthority) ListAsUID(_ context.Context, uid int, requestID string) (gapcontrol.WorkerListResponse, error) {
	f.mu.Lock()
	f.lastUID = uid
	resp := f.listResp
	f.mu.Unlock()
	if resp.Version == "" {
		resp = gapcontrol.WorkerListResponse{
			Version: gapcontrol.VersionV1,
			Workers: []gapcontrol.WorkerStatusResponse{
				{
					Version:   gapcontrol.VersionV1,
					RequestID: requestID,
					WorkerID:  "wk_1",
					AgentID:   "hackerman",
					SessionID: "sess_1",
					Status:    "running",
				},
			},
		}
	}
	return resp, nil
}

func TestControlClientSpawnOverUnixSocket(t *testing.T) {
	sock := shortSocketPath(t)
	_ = os.Remove(sock)
	defer os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	fake := &fakeControlAuthority{}
	srv := newControlHTTPServer(fake)
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(ln)
	}()
	defer func() {
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("server did not shut down")
		}
	}()

	client := newControlClient(sock)
	req := gapcontrol.SpawnRequest{
		Version:    gapcontrol.VersionV1,
		RequestID:  "req_spawn",
		AgentID:    "hackerman",
		SessionID:  "sess_1",
		WorkloadID: "task_1",
		Runtime:    "openclaw-worker",
	}
	got, err := client.Spawn(context.Background(), req)
	if err != nil {
		t.Fatalf("client spawn: %v", err)
	}
	if got.Decision != "permit" || got.WorkerID != "wk_test" {
		t.Fatalf("unexpected spawn response: %+v", got)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.lastSpawn.AgentID != "hackerman" {
		t.Fatalf("server saw agent_id=%q want hackerman", fake.lastSpawn.AgentID)
	}
	if fake.lastUID != os.Getuid() {
		t.Fatalf("server saw uid=%d want %d", fake.lastUID, os.Getuid())
	}
}

func TestControlClientStatusErrorPropagation(t *testing.T) {
	sock := shortSocketPath(t)
	_ = os.Remove(sock)
	defer os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	fake := &fakeControlAuthority{
		statusErr: &gapcontrol.APIError{Code: "unauthorized", Message: "principal cannot access agent"},
	}
	srv := newControlHTTPServer(fake)
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(ln)
	}()
	defer func() {
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("server did not shut down")
		}
	}()

	client := newControlClient(sock)
	_, err = client.Status(context.Background(), gapcontrol.WorkerStatusRequest{
		Version:   gapcontrol.VersionV1,
		RequestID: "req_status",
		WorkerID:  "wk_missing",
	})
	if err == nil {
		t.Fatal("expected status error")
	}
	apiErr, ok := err.(*gapcontrol.APIError)
	if !ok {
		t.Fatalf("expected *gapcontrol.APIError, got %T (%v)", err, err)
	}
	if apiErr.Code != "unauthorized" {
		t.Fatalf("error code=%q want unauthorized", apiErr.Code)
	}
}

func shortSocketPath(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("loa-ctrl-%d-%d.sock", os.Getpid(), time.Now().UnixNano())
	return filepath.Join("/tmp", name)
}
