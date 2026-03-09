package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/worker"
)

func writeWorkerJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func exitWorkerError(err error) {
	apiErr, ok := err.(*worker.APIError)
	if !ok || apiErr == nil {
		apiErr = &worker.APIError{Code: worker.CodeInternal, Message: err.Error()}
	}
	writeWorkerJSON(worker.ErrorEnvelope{
		Version: worker.VersionV1,
		Error: worker.ErrorBody{
			Code:    apiErr.Code,
			Message: apiErr.Message,
		},
	})
	os.Exit(worker.ExitCode(apiErr))
}

type repeatableFlag []string

func (f *repeatableFlag) String() string {
	if len(*f) == 0 {
		return ""
	}
	return strings.Join(*f, ",")
}

func (f *repeatableFlag) Set(value string) error {
	v := strings.TrimSpace(value)
	if v == "" {
		return fmt.Errorf("value cannot be empty")
	}
	*f = append(*f, v)
	return nil
}

type keyValueFlag map[string]string

func (f *keyValueFlag) String() string {
	if f == nil || len(*f) == 0 {
		return ""
	}
	var parts []string
	for k, v := range *f {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

func (f *keyValueFlag) Set(value string) error {
	v := strings.TrimSpace(value)
	if v == "" {
		return fmt.Errorf("label cannot be empty")
	}
	kv := strings.SplitN(v, "=", 2)
	if len(kv) != 2 || strings.TrimSpace(kv[0]) == "" {
		return fmt.Errorf("label must be key=value")
	}
	if *f == nil {
		*f = map[string]string{}
	}
	(*f)[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	return nil
}

func (f keyValueFlag) Clone() map[string]string {
	if len(f) == 0 {
		return nil
	}
	out := make(map[string]string, len(f))
	for k, v := range f {
		out[k] = v
	}
	return out
}

type launchRequestInput struct {
	RequestPath    string
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
}

func buildLaunchRequest(in launchRequestInput) (worker.LaunchRequest, error) {
	if in.RequestPath != "" {
		if in.Agent != "" || in.SessionID != "" || in.WorkloadID != "" || in.ParentWorkerID != "" || len(in.Volumes) > 0 || len(in.SecretRefs) > 0 || len(in.Labels) > 0 {
			return worker.LaunchRequest{}, &worker.APIError{
				Code:    worker.CodeInvalidRequest,
				Message: "cannot combine --request-json with explicit launch flags",
			}
		}
		data, err := os.ReadFile(in.RequestPath)
		if err != nil {
			return worker.LaunchRequest{}, &worker.APIError{Code: worker.CodeInvalidRequest, Message: fmt.Sprintf("read request json: %v", err)}
		}
		var req worker.LaunchRequest
		if err := json.Unmarshal(data, &req); err != nil {
			return worker.LaunchRequest{}, &worker.APIError{Code: worker.CodeInvalidRequest, Message: fmt.Sprintf("parse request json: %v", err)}
		}
		return req, nil
	}
	if in.Agent == "" || in.SessionID == "" || in.WorkloadID == "" {
		return worker.LaunchRequest{}, &worker.APIError{
			Code:    worker.CodeInvalidRequest,
			Message: "either --request-json or --agent/--session-id/--workload-id is required",
		}
	}
	req := worker.LaunchRequest{
		Version:        worker.VersionV1,
		Agent:          in.Agent,
		SessionID:      in.SessionID,
		WorkloadID:     in.WorkloadID,
		ParentWorkerID: strings.TrimSpace(in.ParentWorkerID),
		Runtime:        in.Runtime,
		Labels:         in.Labels,
	}
	req.MountProfile.Volumes = append([]string{}, in.Volumes...)
	req.NetworkProfile.Mode = in.Mode
	req.NetworkProfile.InitialPolicyScope = in.InitialScope
	req.SecretsProfile.Refs = append([]string{}, in.SecretRefs...)
	req.SecretsProfile.Exposure = in.SecretExposure
	return req, nil
}
