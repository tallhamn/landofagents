// Package protector implements the core LOA enforcement loop.
package protector

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cedar-policy/cedar-go"
)

// CedarDecision is the result of a Cedar authorization check.
type CedarDecision string

const (
	CedarPermit CedarDecision = "permit"
	CedarDeny   CedarDecision = "deny"
	CedarError  CedarDecision = "error"
)

// CedarRequest is the input to a Cedar authorization check.
type CedarRequest struct {
	Principal string
	Action    string
	Resource  string
	Context   map[string]any
}

// CedarEvaluator uses the cedar-go library for in-process policy evaluation.
type CedarEvaluator struct {
	policySet *cedar.PolicySet
	entities  cedar.EntityMap
}

// NewCedarEvaluator creates a new evaluator.
// policyFiles are paths to .cedar files. entitiesJSON is the Cedar entities as JSON bytes.
func NewCedarEvaluator(policyFiles []string, entitiesJSON []byte) (*CedarEvaluator, error) {
	// Read all policy files into one document
	var combined []byte
	for _, pf := range policyFiles {
		data, err := os.ReadFile(pf)
		if err != nil {
			return nil, fmt.Errorf("read policy %s: %w", pf, err)
		}
		combined = append(combined, data...)
		combined = append(combined, '\n')
	}

	return newEvaluator(combined, entitiesJSON)
}

// NewCedarEvaluatorFromSources creates an evaluator from raw Cedar text, policy files, and entities.
// extraCedar is prepended to the policy files (used for always-allowed policies loaded as strings).
func NewCedarEvaluatorFromSources(extraCedar []byte, policyFiles []string, entitiesJSON []byte) (*CedarEvaluator, error) {
	combined := make([]byte, 0, len(extraCedar))
	combined = append(combined, extraCedar...)
	combined = append(combined, '\n')

	for _, pf := range policyFiles {
		data, err := os.ReadFile(pf)
		if err != nil {
			return nil, fmt.Errorf("read policy %s: %w", pf, err)
		}
		combined = append(combined, data...)
		combined = append(combined, '\n')
	}

	return newEvaluator(combined, entitiesJSON)
}

func newEvaluator(policyData, entitiesJSON []byte) (*CedarEvaluator, error) {
	ps, err := cedar.NewPolicySetFromBytes("combined.cedar", policyData)
	if err != nil {
		return nil, fmt.Errorf("parse policies: %w", err)
	}

	var entities cedar.EntityMap
	if err := json.Unmarshal(entitiesJSON, &entities); err != nil {
		return nil, fmt.Errorf("parse entities: %w", err)
	}

	return &CedarEvaluator{
		policySet: ps,
		entities:  entities,
	}, nil
}

// Evaluate runs a Cedar authorization check and returns the decision.
func (e *CedarEvaluator) Evaluate(req CedarRequest) (CedarDecision, error) {
	principal, err := parseEntityUID(req.Principal)
	if err != nil {
		return CedarError, fmt.Errorf("parse principal: %w", err)
	}
	action, err := parseEntityUID(req.Action)
	if err != nil {
		return CedarError, fmt.Errorf("parse action: %w", err)
	}
	resource, err := parseEntityUID(req.Resource)
	if err != nil {
		return CedarError, fmt.Errorf("parse resource: %w", err)
	}

	context := cedar.NewRecord(cedar.RecordMap{})
	if len(req.Context) > 0 {
		contextJSON, err := json.Marshal(req.Context)
		if err != nil {
			return CedarError, fmt.Errorf("marshal context: %w", err)
		}
		var rec cedar.Record
		if err := json.Unmarshal(contextJSON, &rec); err != nil {
			return CedarError, fmt.Errorf("parse context: %w", err)
		}
		context = rec
	}

	cedarReq := cedar.Request{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   context,
	}

	decision, _ := cedar.Authorize(e.policySet, e.entities, cedarReq)
	if decision == cedar.Allow {
		return CedarPermit, nil
	}
	return CedarDeny, nil
}

// Cleanup is a no-op since the library evaluator has no temp files.
func (e *CedarEvaluator) Cleanup() {}

// parseEntityUID parses a Cedar entity reference like `Agent::"goggins"` into a cedar.EntityUID.
func parseEntityUID(s string) (cedar.EntityUID, error) {
	parts := strings.SplitN(s, "::", 2)
	if len(parts) != 2 {
		return cedar.EntityUID{}, fmt.Errorf("invalid entity UID: %s", s)
	}
	typeName := parts[0]
	id := strings.Trim(parts[1], `"`)
	return cedar.NewEntityUID(cedar.EntityType(typeName), cedar.String(id)), nil
}
