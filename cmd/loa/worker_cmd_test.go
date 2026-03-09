package main

import (
	"testing"

	"github.com/marcusmom/land-of-agents/engine/worker"
)

func TestBuildLaunchRequestFromFlags(t *testing.T) {
	req, err := buildLaunchRequest(launchRequestInput{
		Agent:          "clawfather",
		SessionID:      "sess-1",
		WorkloadID:     "task-1",
		ParentWorkerID: "wk_parent",
		Runtime:        "openclaw-worker",
		Mode:           "enforce",
		InitialScope:   "existing-active",
		SecretExposure: "least",
		Volumes:        []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"},
		SecretRefs:     []string{"telegram.bot_token"},
		Labels: map[string]string{
			"source": "openclaw-gateway",
		},
	})
	if err != nil {
		t.Fatalf("buildLaunchRequest: %v", err)
	}
	if req.Version != worker.VersionV1 {
		t.Fatalf("version=%q want %q", req.Version, worker.VersionV1)
	}
	if req.Agent != "clawfather" || req.SessionID != "sess-1" || req.WorkloadID != "task-1" {
		t.Fatalf("unexpected identity fields: %+v", req)
	}
	if req.ParentWorkerID != "wk_parent" {
		t.Fatalf("parent_worker_id=%q want wk_parent", req.ParentWorkerID)
	}
	if len(req.MountProfile.Volumes) != 1 || req.MountProfile.Volumes[0] != "/srv/loa/resources/clawkeeper:/clawkeeper:rw" {
		t.Fatalf("mount profile mismatch: %+v", req.MountProfile)
	}
	if req.NetworkProfile.Mode != "enforce" || req.NetworkProfile.InitialPolicyScope != "existing-active" {
		t.Fatalf("network profile mismatch: %+v", req.NetworkProfile)
	}
	if len(req.SecretsProfile.Refs) != 1 || req.SecretsProfile.Refs[0] != "telegram.bot_token" {
		t.Fatalf("secret refs mismatch: %+v", req.SecretsProfile)
	}
	if req.Labels["source"] != "openclaw-gateway" {
		t.Fatalf("labels mismatch: %+v", req.Labels)
	}
}

func TestBuildLaunchRequestRequiresIdentityWhenNoJSON(t *testing.T) {
	_, err := buildLaunchRequest(launchRequestInput{
		Agent:      "clawfather",
		SessionID:  "",
		WorkloadID: "task-1",
	})
	if err == nil {
		t.Fatal("expected error for missing session id")
	}
	apiErr, ok := err.(*worker.APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.Code != worker.CodeInvalidRequest {
		t.Fatalf("error code=%q want %q", apiErr.Code, worker.CodeInvalidRequest)
	}
}

func TestBuildLaunchRequestRejectsMixedJSONAndFlags(t *testing.T) {
	_, err := buildLaunchRequest(launchRequestInput{
		RequestPath:    "/tmp/nonexistent.json",
		ParentWorkerID: "wk_parent",
	})
	if err == nil {
		t.Fatal("expected mixed input error")
	}
	apiErr, ok := err.(*worker.APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.Code != worker.CodeInvalidRequest {
		t.Fatalf("error code=%q want %q", apiErr.Code, worker.CodeInvalidRequest)
	}
}

func TestKeyValueFlagSet(t *testing.T) {
	var labels keyValueFlag
	if err := labels.Set("source=openclaw-gateway"); err != nil {
		t.Fatalf("Set valid label: %v", err)
	}
	if labels["source"] != "openclaw-gateway" {
		t.Fatalf("label value mismatch: %+v", labels)
	}
	if err := labels.Set("badlabel"); err == nil {
		t.Fatal("expected error for invalid key=value")
	}
}
