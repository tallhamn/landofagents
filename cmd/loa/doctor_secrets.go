package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/marcusmom/land-of-agents/app/adapters/claudecode"
	"github.com/marcusmom/land-of-agents/engine/agent"
	"github.com/marcusmom/land-of-agents/engine/config"
	"github.com/marcusmom/land-of-agents/engine/secrets"
)

func reportSecretExposure(kitDir, agentName string, agentCfg *agent.Agent, verbose bool) {
	printDoctorSection("🔐 Secrets & Auth")

	kitCfg, err := config.LoadKit(kitDir)
	if err != nil {
		fmt.Printf("  Status: unavailable (load kit: %v)\n", err)
		return
	}
	rt, err := kitCfg.LoadAgentRuntime(agentName)
	if err != nil {
		fmt.Printf("  Status: unavailable (load runtime: %v)\n", err)
		return
	}
	reg, err := secrets.LoadRegistry(kitDir)
	if err != nil {
		fmt.Printf("  Status: unavailable (load secret registry: %v)\n", err)
		return
	}
	secretEnv, missingSecretRefs := reg.ResolveAllowedEnvFromRefs(agentCfg.AllowedSecrets)
	allowlist := append([]string{}, agentCfg.AllowedEnv...)
	allowlist = append(allowlist, secretEnv...)
	explicitSecretPolicy := len(secrets.NormalizeAllowlist(agentCfg.AllowedEnv)) > 0 || len(agentCfg.AllowedSecrets) > 0

	switch rt.Hook {
	case "claude-code":
		exposure := claudecode.SummarizeExposure(rt.Env)
		forwarded, blockedByPolicy := secrets.FilterDeclaredEnvStrict(exposure.ForwardedEnv, allowlist, explicitSecretPolicy)
		exposure.ForwardedEnv = forwarded
		_, declaredBlocked := secrets.FilterDeclaredEnvStrict(exposure.DeclaredEnv, allowlist, explicitSecretPolicy)
		fmt.Printf("  Effective auth mode: %s\n", exposure.EffectiveAuthMode)
		fmt.Printf("  Billing path: %s\n", exposure.BillingPath)
		fmt.Printf("  Command policy mode: %s\n", exposure.CommandPolicyMode)
		fmt.Printf("  Runtime env exposure: %d forwarded / %d declared\n", len(exposure.ForwardedEnv), len(exposure.DeclaredEnv))
		fmt.Printf("  Legend: declared = runtime-supported vars, forwarded = vars injected after policy filters\n")
		if explicitSecretPolicy {
			if len(agentCfg.AllowedEnv) > 0 {
				fmt.Printf("  Agent env allowlist: %s\n", strings.Join(secrets.NormalizeAllowlist(agentCfg.AllowedEnv), ", "))
			}
			if len(agentCfg.AllowedSecrets) > 0 {
				fmt.Printf("  Agent secret grants: %s\n", strings.Join(agentCfg.AllowedSecrets, ", "))
			}
			if len(secretEnv) > 0 {
				fmt.Printf("  Resolved secret env: %s\n", strings.Join(secretEnv, ", "))
			}
			if len(missingSecretRefs) > 0 {
				fmt.Printf("  Missing secret defs: %s\n", strings.Join(missingSecretRefs, ", "))
			}
			if len(declaredBlocked) > 0 {
				if verbose {
					fmt.Printf("  Blocked by secret policy: %s\n", strings.Join(declaredBlocked, ", "))
				} else {
					fmt.Printf("  Blocked by secret policy: %d runtime vars (use --verbose)\n", len(declaredBlocked))
				}
			}
		}
		if len(exposure.ForwardedEnv) == 0 {
			fmt.Printf("  Forwarded vars: (none)\n")
		} else {
			fmt.Printf("  Forwarded vars: %s\n", strings.Join(exposure.ForwardedEnv, ", "))
		}
		filteredMissing, _ := secrets.FilterDeclaredEnvStrict(exposure.MissingEnv, allowlist, explicitSecretPolicy)
		if len(filteredMissing) > 0 {
			fmt.Printf("  Missing on host: %s\n", strings.Join(filteredMissing, ", "))
		}
		if verbose {
			fmt.Printf("  Requested auth mode: %s\n", exposure.RequestedAuthMode)
			fmt.Printf("  Host OAuth available: %t\n", exposure.OAuthAvailable)
			filteredPresent, _ := secrets.FilterDeclaredEnvStrict(exposure.PresentEnv, allowlist, explicitSecretPolicy)
			if len(filteredPresent) > 0 {
				fmt.Printf("  Present on host: %s\n", strings.Join(filteredPresent, ", "))
			}
			if len(blockedByPolicy) > 0 {
				fmt.Printf("  Blocked by secret policy (forward pass): %s\n", strings.Join(blockedByPolicy, ", "))
			}
		}
	default:
		present := []string{}
		missing := []string{}
		for _, name := range rt.Env {
			if strings.TrimSpace(os.Getenv(name)) == "" {
				missing = append(missing, name)
			} else {
				present = append(present, name)
			}
		}
		forwarded, declaredBlocked := secrets.FilterDeclaredEnvStrict(rt.Env, allowlist, explicitSecretPolicy)
		present, _ = secrets.FilterDeclaredEnvStrict(present, allowlist, explicitSecretPolicy)
		missing, _ = secrets.FilterDeclaredEnvStrict(missing, allowlist, explicitSecretPolicy)
		fmt.Printf("  Runtime hook: %s\n", valueOrDefault(rt.Hook, rt.Name))
		fmt.Printf("  Runtime env exposure: %d forwarded / %d declared\n", len(forwarded), len(rt.Env))
		fmt.Printf("  Legend: declared = runtime-supported vars, forwarded = vars injected after policy filters\n")
		if explicitSecretPolicy {
			if len(agentCfg.AllowedEnv) > 0 {
				fmt.Printf("  Agent env allowlist: %s\n", strings.Join(secrets.NormalizeAllowlist(agentCfg.AllowedEnv), ", "))
			}
			if len(agentCfg.AllowedSecrets) > 0 {
				fmt.Printf("  Agent secret grants: %s\n", strings.Join(agentCfg.AllowedSecrets, ", "))
			}
			if len(secretEnv) > 0 {
				fmt.Printf("  Resolved secret env: %s\n", strings.Join(secretEnv, ", "))
			}
			if len(missingSecretRefs) > 0 {
				fmt.Printf("  Missing secret defs: %s\n", strings.Join(missingSecretRefs, ", "))
			}
			if len(declaredBlocked) > 0 {
				if verbose {
					fmt.Printf("  Blocked by secret policy: %s\n", strings.Join(declaredBlocked, ", "))
				} else {
					fmt.Printf("  Blocked by secret policy: %d runtime vars (use --verbose)\n", len(declaredBlocked))
				}
			}
		}
		if len(forwarded) == 0 {
			fmt.Printf("  Forwarded vars: (none)\n")
		} else {
			fmt.Printf("  Forwarded vars: %s\n", strings.Join(forwarded, ", "))
		}
		if len(missing) > 0 {
			fmt.Printf("  Missing on host: %s\n", strings.Join(missing, ", "))
		}
		if verbose && len(present) > 0 {
			fmt.Printf("  Present on host: %s\n", strings.Join(present, ", "))
		}
	}
}
