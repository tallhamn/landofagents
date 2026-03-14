# LOA Architecture

## What LOA Does

LOA launches agents (Claude, Codex, OpenClaw) inside governed containers. It observes what they do, proposes restrictions, and enforces approved policy. The goal: agents get useful access, not unlimited access.

## Mental Model

1. Agent runs inside a container with an egress proxy (Envoy) and an authz sidecar.
2. Every outbound request goes through `Envoy -> loa authz -> Cedar policy evaluation`.
3. Denied requests become reviewable proposals. You approve them. They become policy.
4. Next time, the request is allowed automatically.

## Runtime Topology

Each `loa run` session creates three Docker containers in one compose stack:

1. **Agent runtime** (Claude/Codex/OpenClaw)
2. **Envoy proxy** (forced egress path)
3. **LOA authz** (Cedar policy evaluator)

`loa control spawn` creates the same topology but detached, tracked in `workers/state.json`.

## Enforcement Dimensions

- **Network**: forced egress proxy. All outbound HTTP/S goes through Envoy -> authz.
- **Filesystem**: explicit mount allowlist only. No host path access unless mounted.
- **Secrets**: runtime env vars filtered by per-agent allowlist + secret grants.
- **Activity**: command/file observation (audit-only, not blocked).

## Modes

- `ask`: deny = hold request, wait for approval (default).
- `log`: deny = allow + audit log (shadow mode).
- `enforce`: deny = HTTP 403.

## Policy Lifecycle

```
denied event -> proposal -> active policy
```

1. Denied events appear in audit.
2. `loa watch` / `loa inbox` shows pending denials.
3. Approval pipeline proposes Cedar policy (LLM-assisted or template fallback).
4. `WriteActivePolicy` writes directly to `policies/active/`. Future requests match.

## Repository Layout

```
gap/              # Protocol types
engine/           # Security-critical core (authz, audit, contain, worker, ...)
app/              # Product features (approval, advocate, codifier, adapters)
cmd/loa/          # CLI binary
```

Dependency direction: `cmd/loa -> app -> engine -> gap`. Enforced by boundary tests.

Key engine packages:
- `authz` — Cedar policy evaluation server
- `audit` — append-only JSONL logger with hash chains
- `contain` — Docker Compose orchestration
- `worker` — worker lifecycle state machine
- `protector` — command/file classification and policy evaluation
- `config` — kit layout, agent registry, Cedar loading
- `secrets` — secret registry and grant resolution

Key app packages:
- `approval` — interactive approval workflows and watch loops
- `advocate` — LLM-powered policy suggestions from audit trails
- `codifier` — natural language to Cedar policy conversion
- `adapters/` — runtime-specific integration (claudecode, codex, openclaw)

## Design Principles

- Verifiable security claims only — no unsubstantiated promises.
- Fail closed — missing identity, policy, or metadata = deny.
- Runtime-generic core — no runtime-name branching in engine code.
- Spec before behavior — GAP protocol specs precede implementation.
- Minimal blast radius — smallest possible scope for every approval.

## Safety Claims

LOA currently claims:
- Network egress is enforced via Envoy + authz policy.
- Filesystem is constrained to explicit mounts.
- Secrets exposure is runtime-declared env passthrough, narrowed by agent allowlist.
- Command layer is audit/telemetry, not hard sandbox enforcement.
