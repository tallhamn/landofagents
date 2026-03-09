# Running Claude Code in Land of Agents

How to run Claude Code with LOA governance — network controls, filesystem isolation, secret management, and audit trail.

## Prerequisites

- Go installed (`go build ./cmd/loa`)
- Docker running
- Claude Code credentials on host (OAuth preferred, API key supported)

## Steps

### 1. Initialize LOA

```bash
loa init
```

Creates kit at `~/land-of-agents` (override with `LOA_KIT`).

### 2. Create the agent

```bash
loa agent create <name> --runtime claude-code --volume ~/my-project:/workspace
```

Pick a name that identifies this agent's purpose (e.g. `webdev`, `backend`, `infra`).

### 3. Choose auth mode

Default is `auto` (prefers OAuth when available). Override with:

```bash
export LOA_CLAUDE_AUTH_MODE=oauth   # subscription billing
export LOA_CLAUDE_AUTH_MODE=api     # API key billing
export LOA_CLAUDE_AUTH_MODE=bedrock # AWS Bedrock
export LOA_CLAUDE_AUTH_MODE=vertex  # Google Vertex
```

LOA blocks `ANTHROPIC_API_KEY` passthrough unless `api` mode is explicitly selected.

### 4. Run with governance

Two-terminal setup (required — Claude uses full-screen TUI):

```bash
# Terminal 1: run the agent
loa run <name>

# Terminal 2: watch and approve
loa watch <name>
```

Default mode is `ask`: denied requests are held until you approve them in `loa watch`. To change mode: `loa agent create <name> --mode log`.

### 5. Approve policies

When Claude tries to access a new host:
1. The request appears in `loa watch` with a decision menu.
2. Choose scope: exact host or domain (e.g. `api.github.com` vs `github.com`).
3. Approved policies auto-activate. Future requests are allowed.

Review what's been approved:

```bash
loa policy effective --agent <name>
```

### 6. Verify setup

```bash
loa doctor --agent <name>
```

Shows: auth mode, billing path, mounted paths, secret exposure, active policies, audit status.

## What Gets Governed

| Layer | Behavior |
|-------|----------|
| Network | All outbound HTTP/S goes through Envoy proxy -> Cedar policy eval |
| Filesystem | Only explicitly mounted paths are visible to Claude |
| Secrets | Only allowed env vars are forwarded (filtered by agent allowlist) |
| Commands | Observed and logged, not blocked (audit trail for visibility) |

## Adding Secrets

```bash
loa secret set github.token --env GITHUB_TOKEN
loa secret grant --agent <name> github.token
```

## Multiple Projects

Create separate agents per project for isolated policy:

```bash
loa agent create frontend --runtime claude-code --volume ~/frontend:/workspace
loa agent create backend --runtime claude-code --volume ~/backend:/workspace
```

Each agent gets its own audit trail, policy set, and mount surface.
