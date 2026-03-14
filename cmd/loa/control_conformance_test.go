package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	gapcontrol "github.com/marcusmom/land-of-agents/gap/control"
)

func TestGapControlConformanceSpawnEnvelope(t *testing.T) {
	ln, sock := newTestUnixListener(t)
	defer ln.Close()

	fake := &fakeControlAuthority{}
	srv := newControlHTTPServer(fake)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	defer func() {
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("server did not shut down")
		}
	}()

	client := newControlClient(sock)
	got, err := client.Spawn(context.Background(), gapcontrol.SpawnRequest{
		Version:    gapcontrol.VersionV1,
		RequestID:  "req_conf_1",
		AgentID:    "hackerman",
		SessionID:  "sess_conf_1",
		WorkloadID: "task_conf_1",
		Runtime:    "openclaw-worker",
	})
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	if got.Version != gapcontrol.VersionV1 {
		t.Fatalf("version=%q want %q", got.Version, gapcontrol.VersionV1)
	}
	if got.RequestID != "req_conf_1" {
		t.Fatalf("request_id=%q want req_conf_1", got.RequestID)
	}
	if got.Decision != "permit" {
		t.Fatalf("decision=%q want permit", got.Decision)
	}
	if strings.TrimSpace(got.DecisionID) == "" {
		t.Fatal("decision_id must be set")
	}
	if strings.TrimSpace(got.EffectivePrincipalID) == "" {
		t.Fatal("effective_principal_id must be set")
	}
	if got.EffectiveAgentID != "hackerman" {
		t.Fatalf("effective_agent_id=%q want hackerman", got.EffectiveAgentID)
	}
	if strings.TrimSpace(got.PolicyHash) == "" {
		t.Fatal("policy_hash must be set")
	}
	if strings.TrimSpace(got.ExpiresAt) == "" {
		t.Fatal("expires_at must be set")
	}
	if strings.TrimSpace(got.WorkerID) == "" {
		t.Fatal("worker_id must be set on permit")
	}
}

func TestGapControlConformanceStatusErrorCodes(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{name: "invalid request", code: "invalid_request"},
		{name: "unsupported version", code: "unsupported_version"},
		{name: "unauthenticated", code: "unauthenticated"},
		{name: "unauthorized", code: "unauthorized"},
		{name: "worker not found", code: "worker_not_found"},
		{name: "internal error", code: "internal_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, sock := newTestUnixListener(t)
			defer ln.Close()

			fake := &fakeControlAuthority{
				statusErr: &gapcontrol.APIError{Code: tc.code, Message: "test error"},
			}
			srv := newControlHTTPServer(fake)
			done := make(chan error, 1)
			go func() { done <- srv.Serve(ln) }()
			defer func() {
				_ = srv.Close()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("server did not shut down")
				}
			}()

		client := newControlClient(sock)
		_, err := client.Status(context.Background(), gapcontrol.WorkerStatusRequest{
			Version:   gapcontrol.VersionV1,
			RequestID: "req_status_conf",
			WorkerID:  "wk_missing",
			})
			if err == nil {
				t.Fatalf("expected %s error", tc.code)
			}
			apiErr, ok := err.(*gapcontrol.APIError)
			if !ok {
				t.Fatalf("expected *gapcontrol.APIError, got %T (%v)", err, err)
			}
			if apiErr.Code != tc.code {
				t.Fatalf("error code=%q want %q", apiErr.Code, tc.code)
			}
		})
	}
}

func TestGapControlConformanceInvalidJSONEnvelope(t *testing.T) {
	ln, sock := newTestUnixListener(t)
	defer ln.Close()

	fake := &fakeControlAuthority{}
	srv := newControlHTTPServer(fake)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	defer func() {
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("server did not shut down")
		}
	}()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://unix/v1/spawn", strings.NewReader("{not-json"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want %d", resp.StatusCode, http.StatusBadRequest)
	}

	var env controlErrorEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if env.Version != gapcontrol.VersionV1 {
		t.Fatalf("version=%q want %q", env.Version, gapcontrol.VersionV1)
	}
	if env.Error.Code != "invalid_request" {
		t.Fatalf("error.code=%q want invalid_request", env.Error.Code)
	}
}

func TestGapControlConformanceMethodNotAllowedEnvelope(t *testing.T) {
	ln, sock := newTestUnixListener(t)
	defer ln.Close()

	fake := &fakeControlAuthority{}
	srv := newControlHTTPServer(fake)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	defer func() {
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("server did not shut down")
		}
	}()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://unix/v1/status", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}

	var env controlErrorEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if env.Version != gapcontrol.VersionV1 {
		t.Fatalf("version=%q want %q", env.Version, gapcontrol.VersionV1)
	}
	if env.Error.Code != "invalid_request" {
		t.Fatalf("error.code=%q want invalid_request", env.Error.Code)
	}
}
