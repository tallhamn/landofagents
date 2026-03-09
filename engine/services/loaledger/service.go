package loaledger

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
	gaptrail "github.com/marcusmom/land-of-agents/gap/trail"
)

type Service struct {
	logger *audit.Logger
}

func New(kitDir string) (*Service, error) {
	logger, err := audit.NewLogger(filepath.Join(kitDir, "audit"))
	if err != nil {
		return nil, err
	}
	return &Service{logger: logger}, nil
}

// AppendRecord appends a raw audit record.
func (s *Service) AppendRecord(record audit.Record) error {
	return s.logger.Log(record)
}

// Log is a compatibility alias for AppendRecord.
func (s *Service) Log(record audit.Record) error {
	return s.AppendRecord(record)
}

// AppendEvent appends a normalized GAP trail event.
func (s *Service) AppendEvent(event gaptrail.Event) error {
	record, err := recordFromEvent(event)
	if err != nil {
		return err
	}
	return s.AppendRecord(record)
}

func (s *Service) ReadAll() ([]audit.Record, error) {
	return s.logger.ReadAll()
}

func (s *Service) ReadAllEvents() ([]gaptrail.Event, error) {
	records, err := s.ReadAll()
	if err != nil {
		return nil, err
	}
	out := make([]gaptrail.Event, 0, len(records))
	for _, r := range records {
		out = append(out, eventFromRecord(r))
	}
	return out, nil
}

func recordFromEvent(event gaptrail.Event) (audit.Record, error) {
	timestamp := time.Now().UTC()
	if strings.TrimSpace(event.Timestamp) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(event.Timestamp))
		if err != nil {
			return audit.Record{}, fmt.Errorf("parse event timestamp: %w", err)
		}
		timestamp = parsed.UTC()
	}
	decision := strings.ToLower(strings.TrimSpace(event.Decision))
	if decision == "" {
		decision = "permit"
	}
	scope := strings.TrimSpace(event.Scope)
	if scope == "" {
		scope = strings.TrimSpace(event.AgentID)
	}
	action := strings.TrimSpace(event.Action)
	if action == "" {
		action = strings.TrimSpace(event.EventType)
	}
	ctx := cloneContext(event.Context)
	if ctx == nil {
		ctx = map[string]any{}
	}
	if v := strings.TrimSpace(event.PrincipalID); v != "" {
		ctx["principal_id"] = v
	}
	if v := strings.TrimSpace(event.SessionID); v != "" {
		ctx["session_id"] = v
	}
	if v := strings.TrimSpace(event.WorkerID); v != "" {
		ctx["worker_id"] = v
	}
	if v := strings.TrimSpace(event.DecisionID); v != "" {
		ctx["decision_id"] = v
	}
	if v := strings.TrimSpace(event.EventType); v != "" {
		ctx["event_type"] = v
	}
	if v := strings.TrimSpace(event.PolicyHash); v != "" {
		ctx["policy_hash"] = v
	}
	if v := strings.TrimSpace(event.ReasonCode); v != "" {
		ctx["reason_code"] = v
	}
	if len(ctx) == 0 {
		ctx = nil
	}
	return audit.Record{
		ID:            strings.TrimSpace(event.EventID),
		Timestamp:     timestamp,
		Agent:         strings.TrimSpace(event.AgentID),
		Scope:         scope,
		Action:        action,
		Resource:      strings.TrimSpace(event.Resource),
		Decision:      decision,
		DecisionPath:  strings.TrimSpace(event.DecisionPath),
		PolicyRef:     strings.TrimSpace(event.PolicyRef),
		PermissionRef: strings.TrimSpace(event.PermissionRef),
		Context:       ctx,
		LatencyMs:     event.LatencyMs,
		DenialReason:  strings.TrimSpace(event.Reason),
	}, nil
}

func eventFromRecord(record audit.Record) gaptrail.Event {
	ctx := cloneContext(record.Context)
	return gaptrail.Event{
		Version:       gaptrail.VersionV1,
		EventID:       strings.TrimSpace(record.ID),
		Timestamp:     record.Timestamp.UTC().Format(time.RFC3339),
		EventType:     strings.TrimSpace(record.Action),
		PrincipalID:   contextString(ctx, "principal_id"),
		SessionID:     contextString(ctx, "session_id"),
		WorkerID:      contextString(ctx, "worker_id"),
		DecisionID:    contextString(ctx, "decision_id"),
		AgentID:       strings.TrimSpace(record.Agent),
		Scope:         strings.TrimSpace(record.Scope),
		Action:        strings.TrimSpace(record.Action),
		Resource:      strings.TrimSpace(record.Resource),
		Decision:      strings.TrimSpace(record.Decision),
		DecisionPath:  strings.TrimSpace(record.DecisionPath),
		PolicyRef:     strings.TrimSpace(record.PolicyRef),
		PermissionRef: strings.TrimSpace(record.PermissionRef),
		ReasonCode:    contextString(ctx, "reason_code"),
		Reason:        strings.TrimSpace(record.DenialReason),
		PolicyHash:    contextString(ctx, "policy_hash"),
		LatencyMs:     record.LatencyMs,
		Context:       ctx,
	}
}

func cloneContext(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func contextString(ctx map[string]any, key string) string {
	if len(ctx) == 0 {
		return ""
	}
	raw, ok := ctx[key]
	if !ok || raw == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", raw))
}
