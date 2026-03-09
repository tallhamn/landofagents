# Running Codex in Land of Agents

How to run Codex with LOA governance — network controls, filesystem isolation, and audit trail.

## Prerequisites

- Go installed (`go build ./cmd/loa`)
- Docker running
- Codex credentials on host

## Steps

### 1. Initialize LOA

```bash
loa init
```

### 2. Create the agent

```bash
loa agent create <name> --runtime codex --volume ~/my-project:/workspace
```

### 3. Run with governance

```bash
# Terminal 1
loa run <name>

# Terminal 2
loa watch <name>
```

### 4. Approve network requests

When Codex tries to reach a new host, it appears in `loa watch`. Approve to create policy. Future requests are auto-allowed.

```bash
loa policy effective --agent <name>   # see active policies
loa doctor --agent <name>             # full setup check
```

## What Gets Governed

| Layer | Behavior |
|-------|----------|
| Network | All outbound HTTP/S through proxy -> Cedar policy eval |
| Filesystem | Only mounted paths visible |
| Secrets | Filtered by agent allowlist |
| Commands | Observed, not blocked |

## Status

Codex runtime is **experimental**. The adapter is at `app/adapters/codex/`.
