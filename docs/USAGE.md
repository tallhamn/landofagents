# LOA Usage Guide

## Quick Start

```bash
loa init
loa agent create hackerman --runtime claude-code --volume ~/my-project:/workspace
loa run hackerman
```

Two-terminal setup (required for Claude, which uses full-screen TUI):

```bash
# Terminal 1
loa run hackerman

# Terminal 2
loa watch hackerman
```

## Core Commands

```bash
# Run and observe
loa run <agent> [--inline]
loa watch [agent] [--verbose]       # live denial stream; verbose adds permits
loa inbox                           # pending denials across all agents

# Policy
loa approve <number>                # stage + activate
loa approve <n> --stage             # stage only
loa approve <n> --network-scope domain
loa policy list [--staged|--active]
loa policy effective --agent <name>
loa policy suggest --agent <name> [--since 24h] [--interactive=false]
loa policy activate <filename|all>

# Audit
loa audit verify                    # hash-chain integrity check
loa audit summary [--agent <name>]

# Agent management
loa agent create <name> --runtime <runtime> [--mode ask] [--volume src:dst]
loa mounts <agent> [list|remove <idx>]
loa doctor [--agent <name>]

# Secrets
loa secret set <ref> --env <VAR> [--role gateway|worker]
loa secret grant --agent <agent> <ref>
loa secret revoke --agent <agent> <ref>

# Worker control plane (gap.control.v1)
loa serve control &
loa control spawn --request-json <path>
loa control spawn --agent <name> --session-id <id> --workload-id <id> [flags]
loa control status --worker-id <id>
loa control terminate --worker-id <id> [--reason <text>]
loa control list
```

## Run UX

- Mount prompt: `Read` / `Read+Write` / `Skip` with remember and never-mount options.
- Network approvals: `0-9` decision menu with host/domain scope and allow/block options.
- `loa watch` offers a mount wizard when it sees `fs:*` denials.
- Startup banner shows auth mode and billing path.

## Modes

Mode is set per-agent at creation time (`--mode`). Default is `ask`.

- `ask`: denied requests wait for your approval (default).
- `log`: allow + log what would be denied.
- `enforce`: Cedar deny = HTTP 403.

## Runtimes

| Runtime | Status | Auth modes |
|---------|--------|------------|
| `claude-code` | Supported | auto, oauth, api, bedrock, vertex, foundry |
| `openclaw` | Experimental | n/a |
| `codex` | Experimental | n/a |

Set Claude auth: `LOA_CLAUDE_AUTH_MODE=auto` (default). Prefers OAuth when available.

## Kit Layout

`loa init` creates under `$LOA_KIT` (default `~/land-of-agents`):

- `config/` — agent registry, secret registry, always-allowed Cedar
- `runtimes/` — runtime definitions (runtime.yml + build files)
- `policies/staged/` — proposed policies pending activation
- `policies/active/` — enforced Cedar policies
- `audit/` — JSONL audit records with hash chains
- `workers/` — worker state (state.json)

## OpenClaw Worker Control

For gateway integration, LOA exposes a JSON control plane over Unix socket:

```bash
loa serve control &
loa control spawn --request-json /tmp/launch.json
```

Strict mode (`LOA_OPENCLAW_REQUIRE_WORKER_API=1`) enforces:
- `WORKER_BACKEND=loa` + executable launcher script
- No Docker socket mounts
- `network_profile.mode=enforce`
- `secrets_profile.exposure=least`

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `LOA_KIT` | `~/land-of-agents` | Kit directory |
| `LOA_CLAUDE_AUTH_MODE` | `auto` | Claude auth mode |
| `LOA_COMMAND_POLICY_MODE` | `discover` | Command observation (discover\|off) |
| `LOA_OPENCLAW_REQUIRE_WORKER_API` | unset | Strict OpenClaw mode |
| `LOA_WORKER_MAX_DEPTH` | `0` | Max nested worker depth |
| `LOA_CONTROL_SOCKET` | `$LOA_KIT/run/control.sock` | Control socket path |
