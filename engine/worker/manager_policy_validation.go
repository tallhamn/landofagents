package worker

import (
	"fmt"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/secrets"
)

func (m *Manager) validateLaunchPolicy(runtimeName string, requestedMounts []string, mode, initialScope, exposure string, labels map[string]string) error {
	if m.validator == nil {
		return nil
	}
	if err := m.validator.ValidateWorkerLaunch(runtimeName, requestedMounts, mode, initialScope, exposure, labels); err != nil {
		return &APIError{
			Code:    CodePolicyDenied,
			Message: err.Error(),
		}
	}
	return nil
}

func ensureAllowedMounts(requested, allowed []string) error {
	if len(requested) == 0 {
		return nil
	}
	allowedSet := map[string]bool{}
	for _, v := range allowed {
		nv := strings.TrimSpace(v)
		if nv != "" {
			allowedSet[nv] = true
		}
	}
	for _, v := range requested {
		if !allowedSet[v] {
			return &APIError{
				Code:    CodePolicyDenied,
				Message: fmt.Sprintf("requested mount %q is not allowed for this agent", v),
			}
		}
	}
	return nil
}

func ensureAllowedSecretRefs(requested, allowed []string) error {
	missing := secrets.MissingAllowedRefs(requested, allowed)
	if len(missing) > 0 {
		return &APIError{
			Code:    CodePolicyDenied,
			Message: fmt.Sprintf("requested secret ref %q is not allowed for this agent", missing[0]),
		}
	}
	return nil
}

func loadSecretRegistry(kitDir string) (*secrets.Registry, error) {
	reg, err := secrets.LoadRegistry(kitDir)
	if err != nil {
		return nil, &APIError{Code: CodeInternal, Message: fmt.Sprintf("load secret registry: %v", err)}
	}
	return reg, nil
}

func ensureSecretRefsDefined(reg *secrets.Registry, requested []string) error {
	missingRefs := secrets.MissingDefinedRefs(reg, requested)
	if len(missingRefs) > 0 {
		return &APIError{
			Code:    CodePolicyDenied,
			Message: fmt.Sprintf("requested secret refs are not defined: %s", strings.Join(missingRefs, ", ")),
		}
	}
	return nil
}

func ensureSecretRefsExposedToRole(reg *secrets.Registry, requested []string, role string) error {
	if len(requested) == 0 {
		return nil
	}
	role = secrets.NormalizeRole(role)
	if role == "" {
		role = secrets.RoleGateway
	}
	deniedRefs := reg.RefsNotExposedToRole(requested, role)
	if len(deniedRefs) > 0 {
		return &APIError{
			Code:    CodePolicyDenied,
			Message: fmt.Sprintf("requested secret refs are not exposed to role %q: %s", role, strings.Join(deniedRefs, ", ")),
		}
	}
	return nil
}
