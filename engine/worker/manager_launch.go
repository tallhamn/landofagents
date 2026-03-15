package worker

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/agent"
	"github.com/marcusmom/land-of-agents/engine/contain"
	"github.com/marcusmom/land-of-agents/engine/secrets"
)

// Launch starts a worker in detached mode.
func (m *Manager) Launch(ctx context.Context, req LaunchRequest) (LaunchResponse, error) {
	if err := validateLaunch(req); err != nil {
		return LaunchResponse{}, err
	}
	if err := ctx.Err(); err != nil {
		return LaunchResponse{}, wrapInternal(err)
	}

	mode := normalizeMode(req.NetworkProfile.Mode)

	mgr := agent.NewManager(m.kitDir)
	agentCfg, err := mgr.Get(req.Agent)
	if err != nil {
		return LaunchResponse{}, &APIError{Code: CodeInvalidRequest, Message: fmt.Sprintf("agent %q not found", req.Agent)}
	}

	requestedMounts := normalizeVolumeList(req.MountProfile.Volumes)
	requestedSecretRefs := secrets.NormalizeRefs(req.SecretsProfile.Refs)
	if err := m.validateLaunchPolicy(agentCfg.Runtime, requestedMounts, mode, req.NetworkProfile.InitialPolicyScope, req.SecretsProfile.Exposure, req.Labels); err != nil {
		m.logLaunchDeniedIfPolicy(req, err)
		return LaunchResponse{}, err
	}
	if err := ensureAllowedMounts(requestedMounts, agentCfg.Volumes); err != nil {
		m.logLaunchDeniedIfPolicy(req, err)
		return LaunchResponse{}, err
	}
	if err := ensureAllowedSecretRefs(requestedSecretRefs, agentCfg.AllowedSecrets); err != nil {
		m.logLaunchDeniedIfPolicy(req, err)
		return LaunchResponse{}, err
	}
	reg, err := loadSecretRegistry(m.kitDir)
	if err != nil {
		return LaunchResponse{}, err
	}
	if err := ensureSecretRefsDefined(reg, requestedSecretRefs); err != nil {
		m.logLaunchDeniedIfPolicy(req, err)
		return LaunchResponse{}, err
	}
	if err := ensureSecretRefsExposedToRole(reg, requestedSecretRefs, secrets.RoleWorker); err != nil {
		m.logLaunchDeniedIfPolicy(req, err)
		return LaunchResponse{}, err
	}

	var out LaunchResponse
	err = withLockedStateWrite(m.kitDir, func(st *stateFile) error {
		if existing, ok := findExistingWorker(*st, req.Agent, req.SessionID, req.WorkloadID); ok {
			if err := ensureExistingWorkerProfile(existing, requestedMounts, requestedSecretRefs, mode); err != nil {
				m.logLaunchDeniedIfPolicy(req, err)
				return err
			}
			out = LaunchResponse{
				Version:        VersionV1,
				WorkerID:       existing.WorkerID,
				Agent:          existing.Agent,
				SessionID:      existing.SessionID,
				ParentWorkerID: existing.ParentWorkerID,
				Depth:          existing.Depth,
				Status:         existing.Status,
			}
			return nil
		}
		maxDepth, err := configuredMaxDepth()
		if err != nil {
			return wrapInternal(err)
		}
		parentID, depth, err := resolveParentDepth(req, *st)
		if err != nil {
			m.logLaunchDeniedIfPolicy(req, err)
			return err
		}
		if depth > maxDepth {
			deniedErr := &APIError{
				Code:    CodePolicyDenied,
				Message: fmt.Sprintf("worker depth %d exceeds LOA_WORKER_MAX_DEPTH=%d", depth, maxDepth),
			}
			m.logLaunchDeniedIfPolicy(req, deniedErr)
			return deniedErr
		}

		env, err := m.setup(contain.Options{
			KitDir:              m.kitDir,
			AgentName:           req.Agent,
			Mode:                mode,
			ExtraVolumes:        requestedMounts,
			UseOnlyExtraVolumes: true,
			SecretRefs:          append([]string{}, requestedSecretRefs...),
			SecretRole:          secrets.RoleWorker,
			CallerEnv:           cloneLabels(req.Env),
			LogOut:              io.Discard,
		})
		if err != nil {
			_ = m.logLaunchFailure(req, err)
			return &APIError{Code: CodeInternal, Message: fmt.Sprintf("setup worker environment: %v", err)}
		}

		composeEnv := append(os.Environ(), composeEnvWithKit(env.KitDir)...)
		if err := m.docker.ComposeUp(env.ComposePath, composeEnv, "loa-authz", "envoy", req.Agent); err != nil {
			_ = m.docker.ComposeDown(env.ComposePath, composeEnv)
			_ = os.RemoveAll(env.TmpDir)
			_ = m.logLaunchFailure(req, err)
			return &APIError{Code: CodeInternal, Message: fmt.Sprintf("start worker stack: %v", err)}
		}

		workerID := newWorkerID()
		now := time.Now().UTC()
		rec := Record{
			WorkerID:       workerID,
			Agent:          req.Agent,
			SessionID:      req.SessionID,
			WorkloadID:     req.WorkloadID,
			PrincipalID:    strings.TrimSpace(req.PrincipalID),
			ParentWorkerID: parentID,
			Depth:          depth,
			Runtime:        runtimeName(req, agentCfg.Runtime),
			Status:         "running",
			ComposePath:    env.ComposePath,
			RunID:          filepath.Base(env.TmpDir),
			Mounts:         requestedMounts,
			SecretRefs:     requestedSecretRefs,
			Mode:           mode,
			Labels:         cloneLabels(req.Labels),
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		st.Workers[workerID] = rec
		audID := m.logLaunch(rec)

		out = LaunchResponse{
			Version:        VersionV1,
			WorkerID:       workerID,
			Agent:          req.Agent,
			SessionID:      req.SessionID,
			ParentWorkerID: parentID,
			Depth:          depth,
			Status:         "running",
			AuditRef:       &AuditRef{LaunchEventID: audID},
		}
		return nil
	})
	if err != nil {
		return LaunchResponse{}, wrapInternal(err)
	}
	return out, nil
}
