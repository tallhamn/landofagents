# LOA Roadmap

## Cedar Context-Aware Policies

Currently the authz evaluator only passes `(principal, action, resource)` to Cedar — no context. Extending this enables powerful time/cost/attribute-based policies without changing the policy engine.

### Examples

```cedar
// Only allow API calls during business hours
permit(
  principal == Agent::"clawfather",
  action == Action::"http:Request",
  resource == Resource::"api.openai.com"
) when { context.hour >= 8 && context.hour < 18 };

// Cap per-request cost
permit(
  principal,
  action == Action::"http:Request",
  resource == Resource::"api.anthropic.com"
) when { context.estimated_cost_usd < 5.0 };

// Restrict model selection
permit(
  principal == Agent::"intern",
  action == Action::"http:Request",
  resource == Resource::"api.openai.com"
) when { context.model == "gpt-4o-mini" };
```

### Implementation

1. Populate `CedarRequest.Context` in `engine/authz/server_eval.go` with fields like `hour`, `day_of_week`, `request_path`
2. Extend entity definitions in `engine/config/entities_cedar.go` so Cedar validates the types
3. ~10-20 lines per context field

### Possible context fields

| Field | Source | Use case |
|-------|--------|----------|
| `hour`, `day_of_week` | `time.Now()` | Business hours restrictions |
| `request_path` | HTTP request URL path | Restrict to specific API endpoints |
| `model` | Parse request body for LLM APIs | Control which models agents can use |
| `estimated_cost_usd` | Token count heuristics | Cost caps |
| `run_duration_minutes` | Track since container start | Time-limit agent runs |
