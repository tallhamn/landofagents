// Package protector evaluates command activity against Cedar policy.
//
// Scope:
//   - classify shell commands into action/resource tuples
//   - label unmapped or flagged shell activity for observation
//   - evaluate mapped command segments through Cedar
//   - emit structured audit decisions
//
// Non-goals:
//   - hard process sandboxing
//   - syscall-level command containment
//
// This package provides policy decisions and audit context only.
package protector

import (
	"fmt"

	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/engine/classify"
	"github.com/marcusmom/land-of-agents/engine/config"
	"github.com/marcusmom/land-of-agents/engine/denial"
)

// Decision represents the result of evaluating a command.
type Decision struct {
	Result    string // "permit" or "deny"
	Path      string // "always_allowed", "policy", "activity_unmapped", "activity_flagged"
	Action    string
	Resource  string
	Reason    string
	PolicyRef string
	LatencyMs int64
	Denial    *denial.Message // non-nil when Result is "deny"
}

// Protector is the core evaluation engine. It classifies commands,
// evaluates them against Cedar policies, and logs decisions.
type Protector struct {
	classifier *classify.Classifier
	cedar      *CedarEvaluator
	logger     *audit.Logger
	agent      string
	scope      string
}

// NewProtector creates a new Protector from a loaded config kit.
func NewProtector(kit *config.Kit, agent string, logger *audit.Logger) (*Protector, error) {
	// Determine scope/runtime from agent config.
	agentConfig, err := kit.GetAgent(agent)
	if err != nil {
		return nil, err
	}

	// Build classifier from tool mappings
	effectiveMappings := append([]config.ToolMapping{}, kit.Protector.ToolMappings...)
	runtimeMappings, err := loadRuntimeToolMappings(kit.Dir, agentConfig.Runtime)
	if err != nil {
		return nil, fmt.Errorf("load runtime tool mappings: %w", err)
	}
	effectiveMappings = append(effectiveMappings, runtimeMappings...)

	var mappings []classify.Mapping
	for _, tm := range effectiveMappings {
		mappings = append(mappings, classify.Mapping{
			Executable:        tm.Executable,
			Pattern:           tm.Pattern,
			SubcommandPattern: tm.SubcommandPattern,
			Action:            tm.Action,
			ResourceExtractor: tm.ResourceExtractor,
		})
	}
	classifier := classify.NewClassifierWithOptions(mappings, kit.Protector.DefaultUnmapped, classify.ClassifierOptions{
		Strict: isStrictCommandModeEnabled(),
	})

	// Build Cedar entities JSON
	entitiesJSON, err := kit.Entities.EntitiesToCedarJSON()
	if err != nil {
		return nil, fmt.Errorf("build Cedar entities: %w", err)
	}

	cedar, err := NewCedarEvaluatorFromSources(
		[]byte(kit.AlwaysAllowedCedar), kit.Policies, entitiesJSON)
	if err != nil {
		return nil, fmt.Errorf("create Cedar evaluator: %w", err)
	}

	return &Protector{
		classifier: classifier,
		cedar:      cedar,
		logger:     logger,
		agent:      agent,
		scope:      agentConfig.Scope,
	}, nil
}

// Cleanup releases resources.
func (p *Protector) Cleanup() {
	if p.cedar != nil {
		p.cedar.Cleanup()
	}
}
