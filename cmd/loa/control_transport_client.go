package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	gapcontrol "github.com/marcusmom/land-of-agents/gap/control"
)

type controlClient struct {
	socketPath string
	httpClient *http.Client
}

func newControlClient(socketPath string) *controlClient {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &controlClient{
		socketPath: socketPath,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   60 * time.Second,
		},
	}
}

func (c *controlClient) Spawn(ctx context.Context, req gapcontrol.SpawnRequest) (gapcontrol.SpawnDecision, error) {
	var out gapcontrol.SpawnDecision
	if err := c.postJSON(ctx, "/v1/spawn", req, &out); err != nil {
		return gapcontrol.SpawnDecision{}, err
	}
	return out, nil
}

func (c *controlClient) Status(ctx context.Context, req gapcontrol.WorkerStatusRequest) (gapcontrol.WorkerStatusResponse, error) {
	var out gapcontrol.WorkerStatusResponse
	if err := c.postJSON(ctx, "/v1/status", req, &out); err != nil {
		return gapcontrol.WorkerStatusResponse{}, err
	}
	return out, nil
}

func (c *controlClient) Terminate(ctx context.Context, req gapcontrol.TerminateRequest) (gapcontrol.SpawnDecision, error) {
	var out gapcontrol.SpawnDecision
	if err := c.postJSON(ctx, "/v1/terminate", req, &out); err != nil {
		return gapcontrol.SpawnDecision{}, err
	}
	return out, nil
}

func (c *controlClient) List(ctx context.Context, requestID string) (gapcontrol.WorkerListResponse, error) {
	var out gapcontrol.WorkerListResponse
	if err := c.postJSON(ctx, "/v1/list", controlListRequest{RequestID: strings.TrimSpace(requestID)}, &out); err != nil {
		return gapcontrol.WorkerListResponse{}, err
	}
	return out, nil
}

func (c *controlClient) postJSON(ctx context.Context, path string, reqBody any, out any) error {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", c.socketPath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		var env controlErrorEnvelope
		if err := json.NewDecoder(resp.Body).Decode(&env); err == nil && strings.TrimSpace(env.Error.Code) != "" {
			return &gapcontrol.APIError{
				Code:    strings.TrimSpace(env.Error.Code),
				Message: strings.TrimSpace(env.Error.Message),
			}
		}
		return &gapcontrol.APIError{
			Code:    "internal_error",
			Message: fmt.Sprintf("control server returned status %d", resp.StatusCode),
		}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
