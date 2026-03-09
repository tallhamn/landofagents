package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	gapcontrol "github.com/marcusmom/land-of-agents/gap/control"
)

func makeSpawnHandler(auth controlAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeControlMethodNotAllowed(w)
			return
		}
		uid, ok := requirePeerUID(w, r)
		if !ok {
			return
		}
		var req gapcontrol.SpawnRequest
		if !decodeControlJSON(w, r, &req) {
			return
		}
		resp, err := auth.SpawnAsUID(r.Context(), uid, req)
		if err != nil {
			writeControlAPIError(w, err)
			return
		}
		writeControlJSONResponse(w, http.StatusOK, resp)
	}
}

func makeStatusHandler(auth controlAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeControlMethodNotAllowed(w)
			return
		}
		uid, ok := requirePeerUID(w, r)
		if !ok {
			return
		}
		var req gapcontrol.WorkerStatusRequest
		if !decodeControlJSON(w, r, &req) {
			return
		}
		resp, err := auth.StatusAsUID(r.Context(), uid, req)
		if err != nil {
			writeControlAPIError(w, err)
			return
		}
		writeControlJSONResponse(w, http.StatusOK, resp)
	}
}

func makeTerminateHandler(auth controlAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeControlMethodNotAllowed(w)
			return
		}
		uid, ok := requirePeerUID(w, r)
		if !ok {
			return
		}
		var req gapcontrol.TerminateRequest
		if !decodeControlJSON(w, r, &req) {
			return
		}
		resp, err := auth.TerminateAsUID(r.Context(), uid, req)
		if err != nil {
			writeControlAPIError(w, err)
			return
		}
		writeControlJSONResponse(w, http.StatusOK, resp)
	}
}

func makeListHandler(auth controlAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeControlMethodNotAllowed(w)
			return
		}
		uid, ok := requirePeerUID(w, r)
		if !ok {
			return
		}
		var req controlListRequest
		if !decodeControlJSON(w, r, &req) {
			return
		}
		resp, err := auth.ListAsUID(r.Context(), uid, req.RequestID)
		if err != nil {
			writeControlAPIError(w, err)
			return
		}
		writeControlJSONResponse(w, http.StatusOK, resp)
	}
}

func requirePeerUID(w http.ResponseWriter, r *http.Request) (int, bool) {
	if v := r.Context().Value(controlPeerErrKey{}); v != nil {
		if err, ok := v.(error); ok && err != nil {
			writeControlJSONResponse(w, http.StatusUnauthorized, controlErrorEnvelope{
				Version: gapcontrol.VersionV1,
				Error: struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}{Code: "unauthenticated", Message: err.Error()},
			})
			return 0, false
		}
	}
	v := r.Context().Value(controlPeerUIDKey{})
	uid, ok := v.(int)
	if !ok || uid < 0 {
		writeControlJSONResponse(w, http.StatusUnauthorized, controlErrorEnvelope{
			Version: gapcontrol.VersionV1,
			Error: struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}{Code: "unauthenticated", Message: "peer credentials missing"},
		})
		return 0, false
	}
	return uid, true
}

func decodeControlJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(out); err != nil {
		writeControlJSONResponse(w, http.StatusBadRequest, controlErrorEnvelope{
			Version: gapcontrol.VersionV1,
			Error: struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}{Code: "invalid_request", Message: fmt.Sprintf("invalid JSON: %v", err)},
		})
		return false
	}
	return true
}


func writeControlMethodNotAllowed(w http.ResponseWriter) {
	writeControlJSONResponse(w, http.StatusMethodNotAllowed, controlErrorEnvelope{
		Version: gapcontrol.VersionV1,
		Error: struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}{Code: "invalid_request", Message: "method not allowed"},
	})
}

func writeControlAPIError(w http.ResponseWriter, err error) {
	var apiErr *gapcontrol.APIError
	if errors.As(err, &apiErr) && apiErr != nil {
		writeControlJSONResponse(w, controlHTTPStatusForCode(apiErr.Code), controlErrorEnvelope{
			Version: gapcontrol.VersionV1,
			Error: struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}{Code: strings.TrimSpace(apiErr.Code), Message: strings.TrimSpace(apiErr.Message)},
		})
		return
	}
	writeControlJSONResponse(w, http.StatusInternalServerError, controlErrorEnvelope{
		Version: gapcontrol.VersionV1,
		Error: struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}{Code: "internal_error", Message: strings.TrimSpace(err.Error())},
	})
}

func writeControlJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func controlHTTPStatusForCode(code string) int {
	switch strings.TrimSpace(code) {
	case "invalid_request", "unsupported_version":
		return http.StatusBadRequest
	case "unauthenticated":
		return http.StatusUnauthorized
	case "unauthorized", "policy_denied":
		return http.StatusForbidden
	case "worker_not_found":
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}


const (
	controlSocketEnv = "LOA_CONTROL_SOCKET"
)

type controlListRequest struct {
	RequestID string `json:"request_id,omitempty"`
}

type controlAuthority interface {
	SpawnAsUID(ctx context.Context, uid int, req gapcontrol.SpawnRequest) (gapcontrol.SpawnDecision, error)
	StatusAsUID(ctx context.Context, uid int, req gapcontrol.WorkerStatusRequest) (gapcontrol.WorkerStatusResponse, error)
	TerminateAsUID(ctx context.Context, uid int, req gapcontrol.TerminateRequest) (gapcontrol.SpawnDecision, error)
	ListAsUID(ctx context.Context, uid int, requestID string) (gapcontrol.WorkerListResponse, error)
}

type controlPeerUIDKey struct{}
type controlPeerErrKey struct{}

func controlSocketPath() string {
	if v := strings.TrimSpace(os.Getenv(controlSocketEnv)); v != "" {
		return v
	}
	return filepath.Join(kitDir(), "run", "control.sock")
}
