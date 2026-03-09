package loaadvisor

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/agent"
	"github.com/marcusmom/land-of-agents/app/approval"
	"github.com/marcusmom/land-of-agents/engine/audit"
)

type Service struct{}

type SuggestRequest struct {
	AgentName      string
	Since          time.Time
	NetworkScope   string // host|domain
	Records        []audit.Record
	Agent          agent.Agent
	ActivePolicies []PolicyEntry
}

type SuggestResult struct {
	Network    []NetworkSuggestion
	Filesystem []FilesystemSuggestion
}

type PolicyEntry struct {
	Effect   string
	Action   string
	Resource string
}

type NetworkSuggestion struct {
	Resource string
	Count    int
	LastSeen time.Time
	Examples []string
}

type FilesystemSuggestion struct {
	TargetDir string
	Count     int
	LastSeen  time.Time
	Examples  []string
	Mode      string // ro|rw
}

type networkSuggestionAccum struct {
	Resource string
	Count    int
	LastSeen time.Time
	Examples map[string]bool
}

type filesystemSuggestionAccum struct {
	TargetDir string
	Count     int
	LastSeen  time.Time
	Examples  map[string]bool
	Mode      string
}

type mountCoverage struct {
	Target string
	Mode   string // ro|rw
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func New() *Service { return &Service{} }

func (s *Service) Suggest(req SuggestRequest) (SuggestResult, error) {
	scope := strings.ToLower(strings.TrimSpace(req.NetworkScope))
	if scope == "" {
		scope = "host"
	}
	if scope != "host" && scope != "domain" {
		return SuggestResult{}, fmt.Errorf("network scope must be host or domain")
	}
	agentName := strings.TrimSpace(req.AgentName)
	if agentName == "" {
		return SuggestResult{}, fmt.Errorf("agent name is required")
	}
	result := SuggestResult{
		Network:    collectNetworkSuggestions(req.Records, agentName, req.Since, scope, req.ActivePolicies),
		Filesystem: collectFilesystemSuggestions(req.Records, agentName, req.Since, req.Agent),
	}
	return result, nil
}

func (s *Service) NetworkSuggestionProposal(agentName string, suggestion NetworkSuggestion, effect string) approval.ProposalWithCedar {
	effect = strings.ToLower(strings.TrimSpace(effect))
	if effect != "deny" {
		effect = "allow"
	}
	resource := strings.TrimSpace(suggestion.Resource)
	description := fmt.Sprintf("%s can make HTTP requests to %s", agentName, resource)
	c := fmt.Sprintf(`permit(
  principal == Agent::"%s",
  action == Action::"http:Request",
  resource == Resource::"%s"
);
`, agentName, resource)
	if effect == "deny" {
		description = fmt.Sprintf("%s cannot make HTTP requests to %s", agentName, resource)
		c = fmt.Sprintf(`forbid(
  principal == Agent::"%s",
  action == Action::"http:Request",
  resource == Resource::"%s"
);
`, agentName, resource)
	}
	return approval.ProposalWithCedar{
		Description: description,
		Reasoning:   fmt.Sprintf("Generated from audit activity (%d blocked request%s).", suggestion.Count, pluralSuffix(suggestion.Count)),
		Agent:       strings.TrimSpace(agentName),
		Cedar:       c,
		Filename:    SuggestedPolicyFilename(agentName, "http:Request", resource, effect),
	}
}

func SuggestedPolicyFilename(agentName, action, resource, effect string) string {
	slug := strings.ToLower(strings.TrimSpace(resource))
	slug = nonSlug.ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "resource"
	}
	verb := "http"
	if strings.HasPrefix(action, "http:") {
		verb = "http"
	}
	filename := fmt.Sprintf("%s-%s-%s.cedar", strings.TrimSpace(agentName), verb, slug)
	if strings.ToLower(strings.TrimSpace(effect)) == "deny" {
		filename = strings.TrimSuffix(filename, ".cedar") + "-forbid.cedar"
	}
	return filename
}
