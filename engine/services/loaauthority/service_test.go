package loaauthority

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	gapcontrol "github.com/marcusmom/land-of-agents/gap/control"
	"github.com/marcusmom/land-of-agents/engine/worker"
)

type fakeWorkers struct {
	launchFn    func(req worker.LaunchRequest) (worker.LaunchResponse, error)
	getFn       func(workerID string) (worker.WorkerResponse, error)
	terminateFn func(workerID string, reason string) (worker.TerminateResponse, error)
	listFn      func() (worker.ListResponse, error)
}

func (f *fakeWorkers) Launch(_ context.Context, req worker.LaunchRequest) (worker.LaunchResponse, error) {
	if f.launchFn == nil {
		return worker.LaunchResponse{}, &worker.APIError{Code: worker.CodeInternal, Message: "launch not configured"}
	}
	return f.launchFn(req)
}

func (f *fakeWorkers) Get(_ context.Context, workerID string) (worker.WorkerResponse, error) {
	if f.getFn == nil {
		return worker.WorkerResponse{}, &worker.APIError{Code: worker.CodeWorkerNotFound, Message: "not found"}
	}
	return f.getFn(workerID)
}

func (f *fakeWorkers) Terminate(_ context.Context, workerID string, reason string) (worker.TerminateResponse, error) {
	if f.terminateFn == nil {
		return worker.TerminateResponse{}, &worker.APIError{Code: worker.CodeWorkerNotFound, Message: "not found"}
	}
	return f.terminateFn(workerID, reason)
}

func (f *fakeWorkers) List(_ context.Context) (worker.ListResponse, error) {
	if f.listFn == nil {
		return worker.ListResponse{Version: worker.VersionV1}, nil
	}
	return f.listFn()
}

func TestSpawnDeniedWhenPrincipalMappingMissing(t *testing.T) {
	kit := t.TempDir()
	mustMkdirAll(t, filepath.Join(kit, "config"))
	mustMkdirAll(t, filepath.Join(kit, "policies", "active"))

	called := false
	svc := newWithWorkers(kit, &fakeWorkers{
		launchFn: func(req worker.LaunchRequest) (worker.LaunchResponse, error) {
			called = true
			return worker.LaunchResponse{Version: worker.VersionV1, WorkerID: "wk_1", Status: "running"}, nil
		},
	})

	decision, err := svc.Spawn(context.Background(), gapcontrol.SpawnRequest{
		Version:    gapcontrol.VersionV1,
		RequestID:  "req_1",
		AgentID:    "hackerman",
		SessionID:  "sess_1",
		WorkloadID: "task_1",
		Runtime:    "openclaw-worker",
	})
	if err != nil {
		t.Fatalf("Spawn error: %v", err)
	}
	if decision.Decision != "deny" {
		t.Fatalf("decision=%q want deny", decision.Decision)
	}
	if decision.ReasonCode != "unauthenticated" {
		t.Fatalf("reason_code=%q want unauthenticated", decision.ReasonCode)
	}
	if called {
		t.Fatal("expected launch not to be called when principal mapping is missing")
	}
}

func TestSpawnDeniedWhenPrincipalCannotManageAgent(t *testing.T) {
	kit := t.TempDir()
	mustMkdirAll(t, filepath.Join(kit, "config"))
	mustMkdirAll(t, filepath.Join(kit, "policies", "active"))
	writePrincipalsYAML(t, kit, os.Getuid(), "gateway:clawfather", []string{"clawfather"})

	called := false
	svc := newWithWorkers(kit, &fakeWorkers{
		launchFn: func(req worker.LaunchRequest) (worker.LaunchResponse, error) {
			called = true
			return worker.LaunchResponse{Version: worker.VersionV1, WorkerID: "wk_1", Status: "running"}, nil
		},
	})

	decision, err := svc.Spawn(context.Background(), gapcontrol.SpawnRequest{
		Version:    gapcontrol.VersionV1,
		RequestID:  "req_1",
		AgentID:    "hackerman",
		SessionID:  "sess_1",
		WorkloadID: "task_1",
		Runtime:    "openclaw-worker",
	})
	if err != nil {
		t.Fatalf("Spawn error: %v", err)
	}
	if decision.Decision != "deny" {
		t.Fatalf("decision=%q want deny", decision.Decision)
	}
	if decision.ReasonCode != "unauthorized" {
		t.Fatalf("reason_code=%q want unauthorized", decision.ReasonCode)
	}
	if called {
		t.Fatal("expected launch not to be called when agent is unauthorized")
	}
}

func TestSpawnPermittedWhenPrincipalAuthorized(t *testing.T) {
	kit := t.TempDir()
	mustMkdirAll(t, filepath.Join(kit, "config"))
	mustMkdirAll(t, filepath.Join(kit, "policies", "active"))
	writePrincipalsYAML(t, kit, os.Getuid(), "gateway:hackerman", []string{"hackerman"})

	var captured worker.LaunchRequest
	svc := newWithWorkers(kit, &fakeWorkers{
		launchFn: func(req worker.LaunchRequest) (worker.LaunchResponse, error) {
			captured = req
			return worker.LaunchResponse{
				Version:   worker.VersionV1,
				WorkerID:  "wk_123",
				Agent:     req.Agent,
				SessionID: req.SessionID,
				Status:    "running",
			}, nil
		},
	})

	decision, err := svc.Spawn(context.Background(), gapcontrol.SpawnRequest{
		Version:    gapcontrol.VersionV1,
		RequestID:  "req_1",
		AgentID:    "hackerman",
		SessionID:  "sess_1",
		WorkloadID: "task_1",
		Runtime:    "openclaw-worker",
	})
	if err != nil {
		t.Fatalf("Spawn error: %v", err)
	}
	if decision.Decision != "permit" {
		t.Fatalf("decision=%q want permit", decision.Decision)
	}
	if decision.WorkerID != "wk_123" {
		t.Fatalf("worker_id=%q want wk_123", decision.WorkerID)
	}
	if decision.EffectivePrincipalID != "gateway:hackerman" {
		t.Fatalf("effective_principal_id=%q want gateway:hackerman", decision.EffectivePrincipalID)
	}
	if captured.PrincipalID != "gateway:hackerman" {
		t.Fatalf("worker request principal_id=%q want gateway:hackerman", captured.PrincipalID)
	}
}

func TestSpawnDeniedOnUnsupportedVersion(t *testing.T) {
	kit := t.TempDir()
	mustMkdirAll(t, filepath.Join(kit, "config"))
	mustMkdirAll(t, filepath.Join(kit, "policies", "active"))
	writePrincipalsYAML(t, kit, os.Getuid(), "gateway:hackerman", []string{"hackerman"})

	called := false
	svc := newWithWorkers(kit, &fakeWorkers{
		launchFn: func(req worker.LaunchRequest) (worker.LaunchResponse, error) {
			called = true
			return worker.LaunchResponse{Version: worker.VersionV1, WorkerID: "wk_1", Status: "running"}, nil
		},
	})

	decision, err := svc.Spawn(context.Background(), gapcontrol.SpawnRequest{
		Version:    "gap.control.v0",
		RequestID:  "req_bad_ver",
		AgentID:    "hackerman",
		SessionID:  "sess_1",
		WorkloadID: "task_1",
		Runtime:    "openclaw-worker",
	})
	if err != nil {
		t.Fatalf("Spawn error: %v", err)
	}
	if decision.Decision != "deny" {
		t.Fatalf("decision=%q want deny", decision.Decision)
	}
	if decision.ReasonCode != "unsupported_version" {
		t.Fatalf("reason_code=%q want unsupported_version", decision.ReasonCode)
	}
	if called {
		t.Fatal("expected launch not to be called on unsupported version")
	}
}

func TestSpawnDeniedOnMissingRequiredField(t *testing.T) {
	kit := t.TempDir()
	mustMkdirAll(t, filepath.Join(kit, "config"))
	mustMkdirAll(t, filepath.Join(kit, "policies", "active"))
	writePrincipalsYAML(t, kit, os.Getuid(), "gateway:hackerman", []string{"hackerman"})

	svc := newWithWorkers(kit, &fakeWorkers{})
	decision, err := svc.Spawn(context.Background(), gapcontrol.SpawnRequest{
		Version:    gapcontrol.VersionV1,
		RequestID:  "req_missing_runtime",
		AgentID:    "hackerman",
		SessionID:  "sess_1",
		WorkloadID: "task_1",
		Runtime:    "",
	})
	if err != nil {
		t.Fatalf("Spawn error: %v", err)
	}
	if decision.Decision != "deny" {
		t.Fatalf("decision=%q want deny", decision.Decision)
	}
	if decision.ReasonCode != "invalid_request" {
		t.Fatalf("reason_code=%q want invalid_request", decision.ReasonCode)
	}
	if got := decision.Reason; got == "" || got != "runtime is required" {
		t.Fatalf("reason=%q want runtime is required", got)
	}
}

func TestListFiltersByPrincipalAgentScope(t *testing.T) {
	kit := t.TempDir()
	mustMkdirAll(t, filepath.Join(kit, "config"))
	mustMkdirAll(t, filepath.Join(kit, "policies", "active"))
	writePrincipalsYAML(t, kit, os.Getuid(), "gateway:hackerman", []string{"hackerman"})

	svc := newWithWorkers(kit, &fakeWorkers{
		listFn: func() (worker.ListResponse, error) {
			return worker.ListResponse{
				Version: worker.VersionV1,
				Workers: []worker.WorkerResponse{
					{Version: worker.VersionV1, WorkerID: "wk_1", Agent: "hackerman", SessionID: "s1", Status: "running"},
					{Version: worker.VersionV1, WorkerID: "wk_2", Agent: "lisa", SessionID: "s2", Status: "running"},
				},
			}, nil
		},
	})

	got, err := svc.List(context.Background(), "req_1")
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(got.Workers) != 1 {
		t.Fatalf("workers len=%d want 1", len(got.Workers))
	}
	if got.Workers[0].AgentID != "hackerman" {
		t.Fatalf("agent_id=%q want hackerman", got.Workers[0].AgentID)
	}
}

func TestSpawnAsUIDUsesCallerUIDNotProcessUID(t *testing.T) {
	kit := t.TempDir()
	mustMkdirAll(t, filepath.Join(kit, "config"))
	mustMkdirAll(t, filepath.Join(kit, "policies", "active"))
	writePrincipalsYAML(t, kit, 2101, "gateway:clawfather", []string{"clawfather"})

	svc := newWithWorkers(kit, &fakeWorkers{
		launchFn: func(req worker.LaunchRequest) (worker.LaunchResponse, error) {
			return worker.LaunchResponse{
				Version:   worker.VersionV1,
				WorkerID:  "wk_2101",
				Agent:     req.Agent,
				SessionID: req.SessionID,
				Status:    "running",
			}, nil
		},
	})

	req := gapcontrol.SpawnRequest{
		Version:    gapcontrol.VersionV1,
		RequestID:  "req_2101",
		AgentID:    "clawfather",
		SessionID:  "sess_2101",
		WorkloadID: "task_2101",
		Runtime:    "openclaw-worker",
	}

	// Regular Spawn uses process UID and should fail because only uid=2101 is mapped.
	denied, err := svc.Spawn(context.Background(), req)
	if err != nil {
		t.Fatalf("Spawn error: %v", err)
	}
	if denied.Decision != "deny" || denied.ReasonCode != "unauthenticated" {
		t.Fatalf("Spawn() should deny with unauthenticated, got decision=%q reason=%q", denied.Decision, denied.ReasonCode)
	}

	// SpawnAsUID should use the explicit caller UID and permit.
	permitted, err := svc.SpawnAsUID(context.Background(), 2101, req)
	if err != nil {
		t.Fatalf("SpawnAsUID error: %v", err)
	}
	if permitted.Decision != "permit" {
		t.Fatalf("SpawnAsUID decision=%q want permit", permitted.Decision)
	}
	if permitted.EffectivePrincipalID != "gateway:clawfather" {
		t.Fatalf("effective_principal_id=%q want gateway:clawfather", permitted.EffectivePrincipalID)
	}
}

func TestSpawnAsUIDIgnoresSpoofedPrincipalLabel(t *testing.T) {
	kit := t.TempDir()
	mustMkdirAll(t, filepath.Join(kit, "config"))
	mustMkdirAll(t, filepath.Join(kit, "policies", "active"))
	writePrincipalsYAML(t, kit, 2101, "gateway:clawfather", []string{"clawfather"})

	var captured worker.LaunchRequest
	svc := newWithWorkers(kit, &fakeWorkers{
		launchFn: func(req worker.LaunchRequest) (worker.LaunchResponse, error) {
			captured = req
			return worker.LaunchResponse{
				Version:   worker.VersionV1,
				WorkerID:  "wk_2101",
				Agent:     req.Agent,
				SessionID: req.SessionID,
				Status:    "running",
			}, nil
		},
	})

	req := gapcontrol.SpawnRequest{
		Version:    gapcontrol.VersionV1,
		RequestID:  "req_spoof",
		AgentID:    "clawfather",
		SessionID:  "sess_spoof",
		WorkloadID: "task_spoof",
		Runtime:    "openclaw-worker",
		Labels: map[string]string{
			"principal_id": "spoofed:actor",
		},
	}

	permitted, err := svc.SpawnAsUID(context.Background(), 2101, req)
	if err != nil {
		t.Fatalf("SpawnAsUID error: %v", err)
	}
	if permitted.Decision != "permit" {
		t.Fatalf("SpawnAsUID decision=%q want permit", permitted.Decision)
	}
	if permitted.EffectivePrincipalID != "gateway:clawfather" {
		t.Fatalf("effective_principal_id=%q want gateway:clawfather", permitted.EffectivePrincipalID)
	}
	if captured.PrincipalID != "gateway:clawfather" {
		t.Fatalf("worker request principal_id=%q want gateway:clawfather", captured.PrincipalID)
	}
	if captured.Labels["principal_id"] != "spoofed:actor" {
		t.Fatalf("expected spoofed label to remain opaque request metadata, got labels=%v", captured.Labels)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func writePrincipalsYAML(t *testing.T, kit string, uid int, principalID string, allowAgents []string) {
	t.Helper()
	content := "principals:\n" +
		"  - id: " + principalID + "\n" +
		"    uid: " + fmt.Sprintf("%d", uid) + "\n" +
		"    allow_agents:\n"
	for _, a := range allowAgents {
		content += "      - " + a + "\n"
	}
	if err := os.WriteFile(filepath.Join(kit, "config", "principals.yml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write principals.yml: %v", err)
	}
}
