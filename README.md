# Land of Agents (LOA)

**Give your agents least privilege so they can move fast without breaking your things.**

LOA launches your AI agents inside governed containers — observes what they do, proposes restrictions, and enforces approved policy. One CLI, shared policies, isolated agents.

Built for people who want to `--safely-skip-permissions`.

## Architecture

Each `loa run` creates three Docker containers per agent:

```
                         loa CLI
                           |
                       LOA Kit
              (agents, policies, audit, secrets)
                           |
              +--------------------------+
              |      Agent Session       |
              |                          |
              |  +--------------------+  |
              |  | Agent Runtime      |  |
              |  | (Claude/Codex/...) |  |
              |  +--------+-----------+  |
              |           |              |
              |  +--------v-----------+  |
              |  | Envoy Proxy        |  |
              |  | (forced egress)    |  |
              |  +--------+-----------+  |
              |           |              |
              |  +--------v-----------+  |
              |  | LOA Authz Sidecar  |  |
              |  | (Cedar policies)   |  |
              |  +--------------------+  |
              |                          |
              |  no direct egress        |
              +--------------------------+
```

All outbound traffic flows through the proxy and is evaluated against Cedar policies. The agent never reaches the network directly.

## Quick Start

```bash
loa init
loa agent create my-agent --runtime claude-code --volume ~/project:/workspace
loa run my-agent
```

In a second terminal (Claude uses a full-screen TUI):

```bash
loa watch my-agent
```

Review and approve what your agent tried to do:

```bash
loa inbox                              # pending denials across all agents
loa approve <number>                   # approve -> becomes active policy
loa policy effective --agent my-agent  # see what's enforced
```

## What Gets Governed

| Layer | How |
|-------|-----|
| **Network** | Forced egress proxy. Every outbound connection is evaluated by Cedar policy. |
| **Filesystem** | Explicit mount allowlist. No host path access unless you approve it. |
| **Secrets** | Per-agent grants with role scoping. No blanket env var passthrough. |
| **Workers** | Agents can spawn workers via `gap.control.v1`. Each worker inherits at most its parent's policy. |
| **Audit** | Append-only JSONL with hash chains. Every decision is recorded and verifiable. |

## Modes

Set per-agent at creation (`--mode`). Default is `ask`.

| Mode | Behavior |
|------|----------|
| `ask` | Denied requests wait for your approval. |
| `log` | Allow everything, log what would have been denied. |
| `enforce` | Deny = HTTP 403. |

## Policy Lifecycle

```
denied event -> proposal -> staged policy -> active policy
```

Denials appear in `loa inbox`. The approval pipeline proposes Cedar policy (LLM-assisted or template fallback). You review and approve. Next time, the request is allowed automatically.

## The Protocol

LOA implements **GAP** (Governed Agent Protocol) — an open, implementation-neutral protocol for governed agent execution.

| Sub-protocol | Purpose |
|--------------|---------|
| **Control** (`gap.control.v1`) | Worker lifecycle: spawn, terminate, status. Replay protection via `issued_at` + `nonce`. |
| **Policy** (`gap.policy.v1`) | Permission bundles, activation records, canonical hashing. Deny always beats allow. |
| **Trail** (`gap.trail.v1`) | Audit events with decision correlation. Every permit and deny is recorded. |

See [gap/PROTOCOL.md](gap/PROTOCOL.md) for the full specification.

## Supported Runtimes

| Runtime | Status |
|---------|--------|
| `claude-code` | Supported |
| `codex` | Experimental |
| `openclaw` | Experimental |

## Docs

- [Architecture](docs/ARCHITECTURE.md) — topology, design principles, safety claims
- [Usage and CLI reference](docs/USAGE.md) — commands, modes, environment variables
- [GAP Protocol](gap/PROTOCOL.md) — Control, Policy, Trail v1 specification

Runtime setup:
- [Claude Code](docs/setup-claude.md)
- [Codex](docs/setup-codex.md)
- [OpenClaw](docs/setup-openclaw.md)

## Dev

```bash
go build ./...
go test ./...
go vet ./...
```
