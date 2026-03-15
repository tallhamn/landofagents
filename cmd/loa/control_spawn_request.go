package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	gapcontrol "github.com/marcusmom/land-of-agents/gap/control"
	"github.com/marcusmom/land-of-agents/engine/worker"
)

type controlSpawnInput struct {
	RequestPath    string
	RequestID      string
	Agent          string
	SessionID      string
	WorkloadID     string
	ParentWorkerID string
	Runtime        string
	Mode           string
	InitialScope   string
	SecretExposure string
	Volumes        []string
	SecretRefs     []string
	Labels         map[string]string
	Env            map[string]string
}

func buildControlSpawnRequest(in controlSpawnInput) (gapcontrol.SpawnRequest, error) {
	if in.RequestPath != "" {
		if in.Agent != "" || in.SessionID != "" || in.WorkloadID != "" || in.ParentWorkerID != "" || len(in.Volumes) > 0 || len(in.SecretRefs) > 0 || len(in.Labels) > 0 {
			return gapcontrol.SpawnRequest{}, &worker.APIError{Code: worker.CodeInvalidRequest, Message: "cannot combine --request-json with explicit spawn flags"}
		}
		data, err := os.ReadFile(in.RequestPath)
		if err != nil {
			return gapcontrol.SpawnRequest{}, &worker.APIError{Code: worker.CodeInvalidRequest, Message: fmt.Sprintf("read request json: %v", err)}
		}
		var req gapcontrol.SpawnRequest
		if err := json.Unmarshal(data, &req); err != nil {
			return gapcontrol.SpawnRequest{}, &worker.APIError{Code: worker.CodeInvalidRequest, Message: fmt.Sprintf("parse request json: %v", err)}
		}
		return req, nil
	}
	if in.Agent == "" || in.SessionID == "" || in.WorkloadID == "" {
		return gapcontrol.SpawnRequest{}, &worker.APIError{Code: worker.CodeInvalidRequest, Message: "either --request-json or --agent/--session-id/--workload-id is required"}
	}
	out := gapcontrol.SpawnRequest{
		Version:        gapcontrol.VersionV1,
		RequestID:      in.RequestID,
		AgentID:        in.Agent,
		SessionID:      in.SessionID,
		WorkloadID:     in.WorkloadID,
		ParentWorkerID: strings.TrimSpace(in.ParentWorkerID),
		Runtime:        in.Runtime,
		Labels:         in.Labels,
	}
	out.Env = in.Env
	out.MountProfile.Volumes = append([]string{}, in.Volumes...)
	out.NetworkProfile.Mode = in.Mode
	out.NetworkProfile.InitialPolicyScope = in.InitialScope
	out.SecretsProfile.Refs = append([]string{}, in.SecretRefs...)
	out.SecretsProfile.Exposure = in.SecretExposure
	return out, nil
}
