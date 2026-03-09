package authz

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/config"
	"github.com/marcusmom/land-of-agents/engine/protector"
)

type checkMeta struct {
	Host   string
	Domain string
	Method string
	Path   string
}

func extractCheckMeta(r *http.Request) checkMeta {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if host == "" {
		host = r.Header.Get("Host")
	}
	return checkMeta{
		Host:   host,
		Domain: extractDomain(host),
		Method: r.Method,
		Path:   r.URL.Path,
	}
}

// extractDomain strips port from host:port and lowercases.
func extractDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		port := host[idx+1:]
		isPort := true
		for _, c := range port {
			if c < '0' || c > '9' {
				isPort = false
				break
			}
		}
		if isPort {
			host = host[:idx]
		}
	}
	return host
}

func (s *Server) loadEvaluatorForCheck() (*config.Kit, *protector.CedarEvaluator, error) {
	kit, err := config.LoadKit(s.kitDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load kit: %w", err)
	}
	entitiesJSON, err := kit.Entities.EntitiesToCedarJSON()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build entities: %w", err)
	}
	eval, err := protector.NewCedarEvaluatorFromSources([]byte(kit.AlwaysAllowedCedar), kit.Policies, entitiesJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create evaluator: %w", err)
	}
	return kit, eval, nil
}

func scopeForAgent(kit *config.Kit, agentName string) string {
	agentConfig, _ := kit.GetAgent(agentName)
	scope := agentConfig.Scope
	if scope == "" {
		scope = agentName
	}
	return scope
}
