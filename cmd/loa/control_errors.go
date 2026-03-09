package main

import (
	"encoding/json"
	"os"
	"strings"

	gapcontrol "github.com/marcusmom/land-of-agents/gap/control"
	"github.com/marcusmom/land-of-agents/engine/worker"
)

type controlErrorEnvelope struct {
	Version string `json:"version"`
	Error   struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeControlJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func exitControlError(err error) {
	env := controlErrorEnvelope{Version: gapcontrol.VersionV1}
	env.Error.Code = "internal_error"
	env.Error.Message = strings.TrimSpace(err.Error())
	if apiErr, ok := err.(*gapcontrol.APIError); ok && apiErr != nil {
		env.Error.Code = strings.TrimSpace(apiErr.Code)
		env.Error.Message = strings.TrimSpace(apiErr.Message)
		writeControlJSON(env)
		os.Exit(controlExitCode(env.Error.Code))
	}
	if apiErr, ok := err.(*worker.APIError); ok {
		env.Error.Code = mapControlWorkerError(apiErr.Code)
		env.Error.Message = strings.TrimSpace(apiErr.Message)
	}
	writeControlJSON(env)
	os.Exit(controlExitCode(env.Error.Code))
}

func mapControlWorkerError(code string) string {
	switch strings.TrimSpace(code) {
	case worker.CodeInvalidRequest, worker.CodeUnsupported:
		return "invalid_request"
	case worker.CodePolicyDenied:
		return "policy_denied"
	case worker.CodeWorkerNotFound:
		return "worker_not_found"
	default:
		return "internal_error"
	}
}

func controlExitCode(code string) int {
	switch strings.TrimSpace(code) {
	case "invalid_request", "unsupported_version":
		return 2
	case "policy_denied", "unauthorized":
		return 3
	case "worker_not_found":
		return 4
	default:
		return 6
	}
}
