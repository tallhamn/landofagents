# Running OpenClaw in Land of Agents

How to run OpenClaw agents with LOA governance — worker control plane, network controls, secret management, and audit trail.

## Prerequisites

- Go installed (`go build ./cmd/loa`)
- Docker running
- OpenClaw gateway accessible

## Two Modes

**Interactive** (like Claude/Codex):

```bash
loa agent create clawfather --runtime openclaw
loa run clawfather
```

**Worker control plane** (gateway integration via `gap.control.v1`):

```bash
loa serve control &
loa control spawn --request-json /tmp/launch.json
```

## Worker Control Plane Setup

### 1. Initialize and create agent

```bash
loa init
loa agent create clawfather --runtime openclaw --volume /srv/resources:/workspace
```

### 2. Start the control server

```bash
loa serve control &
```

Listens on `$LOA_KIT/run/control.sock` (Unix socket, peer-cred authenticated).

### 3. Spawn workers

JSON request:

```json
{
  "version": "gap.control.v1",
  "agent_id": "clawfather",
  "request_id": "req_001",
  "session_id": "sess_123",
  "workload_id": "tool_42",
  "runtime": "openclaw-worker",
  "mount_profile": {
    "volumes": ["/srv/resources:/workspace:rw"]
  },
  "network_profile": {"mode": "enforce"},
  "secrets_profile": {"refs": ["telegram.bot_token"], "exposure": "least"}
}
```

```bash
loa control spawn --request-json /tmp/launch.json
loa control list
loa control status --worker-id wk_...
loa control terminate --worker-id wk_... --reason done
```

Or flag-based:

```bash
loa control spawn --agent clawfather --session-id sess_123 --workload-id tool_42 \
  --runtime openclaw-worker --mode enforce \
  --volume /srv/resources:/workspace:rw \
  --secret-ref telegram.bot_token --label source=openclaw-gateway
```

### 4. Enable strict mode

For production, enforce all safety checks:

```bash
export LOA_OPENCLAW_REQUIRE_WORKER_API=1
```

This requires:
- `WORKER_BACKEND=loa` on gateway
- `OPENCLAW_WORKER_LAUNCHER` pointing to executable launcher script
- No Docker socket mounts
- `network_profile.mode=enforce`
- `secrets_profile.exposure=least`

### 5. Configure secrets

```bash
loa secret set telegram.bot_token --env TELEGRAM_BOT_TOKEN --role gateway,worker
loa secret grant --agent clawfather telegram.bot_token
```

Worker secret refs must have `worker` role. Gateway-only refs are denied for workers.

### 6. Reference launcher

## What Gets Governed

| Layer | Behavior |
|-------|----------|
| Network | Forced egress proxy, Cedar policy per-request |
| Filesystem | Mount allowlist (requested mounts validated against agent config) |
| Secrets | Per-launch explicit refs, validated against grants + roles |
| Workers | Idempotent by (agent, session, workload), lifecycle audited |

## Security Properties

- Workers cannot escape mount allowlist.
- Workers cannot access secrets not granted to their agent.
- Worker launches are idempotent and audited.
- Strict mode prevents unmanaged spawn paths.
- All lifecycle events recorded: Launch, LaunchDenied, LaunchFailed, Terminate, TerminateFailed.

## Status

OpenClaw runtime is **experimental**. The adapter is at `app/adapters/openclaw/`.
