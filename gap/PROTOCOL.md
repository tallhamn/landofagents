# GAP (Governed Agent Protocol) v1

GAP is an implementation-neutral protocol family for governed agent execution. LOA is one implementation.

Three sub-protocols: **Control** (worker lifecycle), **Policy** (permission state), **Trail** (audit events).

Trust model: transport-authenticated identity (Unix socket peer creds on single host). Caller identity is kernel-provided, never request payload.

---

## Control v1

Standardizes worker lifecycle messages.

### Operations

| Operation | Purpose |
|-----------|---------|
| SpawnRequest | Request worker launch |
| SpawnDecision | Authority permit/deny response |
| TerminateRequest | Request worker termination |
| WorkerStatusRequest | Query worker state |
| WorkerStatusResponse | Worker state response |

### SpawnRequest (required fields)

`version` (`gap.control.v1`), `request_id`, `agent_id`, `session_id`, `workload_id`, `runtime`, `issued_at` (RFC 3339), `nonce`.

Optional: `parent_worker_id`, `mount_profile.volumes[]` (Docker-style strings, e.g. `/host:/container:rw`), `network_profile.mode`, `network_profile.initial_policy_scope`, `secrets_profile.refs[]`, `secrets_profile.exposure`, `labels`.

### SpawnDecision (required fields)

`version`, `request_id`, `decision_id`, `decision` (permit|deny), `effective_principal_id`, `effective_agent_id`, `policy_hash`, `authority_id`, `decided_at`, `expires_at`.

On permit: `worker_id`, `status`.
On deny: `reason_code`, `reason`.

### Structured Profiles

Mount profiles use Docker-style volume strings: `mount_profile.volumes[]` with entries like `/host/path:/container/path:rw`. This keeps the protocol surface simple and maps directly to container runtimes.

### Security Rules

- All requests include `issued_at` + `nonce`; authority rejects stale/replayed requests.
- Idempotency key: `(agent_id, session_id, workload_id)`. Matching profile = return existing; drift = deny.
- Caller identity from transport only, never caller-asserted.
- Decision signing (binding decision_id, request_id, principal, agent, policy_hash, expiry) is a future roadmap item for multi-host deployments.

### Error Codes

`invalid_request`, `unsupported_version`, `unauthenticated`, `unauthorized`, `policy_denied`, `replay_detected`, `idempotency_conflict`, `expired_decision`, `worker_not_found`, `internal_error`.

---

## Policy v1

Standardizes policy bundles, activation, and decision binding.

### PolicyBundle (required fields)

`version` (`gap.policy.v1`), `bundle_id`, `scope_id`, `policy_hash`, `policy_kinds[]`, `capabilities`, `created_at`.

`policy_kinds[]` MUST include `core`. May include `application` for app-level payload (opaque to GAP).

### Capabilities

Network: `allow_hosts[]`, `allow_domains[]`, `deny_hosts[]`, `deny_domains[]`. Deny has precedence over allow. Domain matching is label-boundary suffix (e.g. `example.com` matches `api.example.com`).

Mounts: validated against `mount_profile.volumes[]` entries. Access escalation (read_only -> read_write) denied.

Secrets: `allow_refs[]`. Missing ref = denied. Secret plaintext MUST NOT appear in protocol objects.

### ActivationRecord (required fields)

`version`, `activation_id`, `scope_id`, `policy_hash`, `activated_at`, `activated_by` (human|authority|automation).

Activation is append-only. Effective policy = latest `activated_at` (tie-break: lexicographic `activation_id`). Missing/unverifiable state MUST fail closed.

### Canonical Policy Hash

SHA-256 over canonical UTF-8 bytes with normalized line endings, deterministic ordering. Encoded as `sha256:<hex>`.

### Policy-specific error codes

`hash_mismatch`, `activation_conflict`, `state_unverifiable`.

---

## Trail v1

Standardizes audit events.

### TrailEvent (required fields)

`version` (`gap.trail.v1`), `event_id`, `timestamp`, `event_type`, `decision` (permit|deny|error), `enforced` (boolean), `principal_id`, `agent_id`, `session_id`.

Optional: `worker_id`, `decision_id`, `action`, `resource`, `reason_code`, `reason`, `policy_hash`, `context`.

### Event Types and Required Fields

| Type | Additional required fields |
|------|---------------------------|
| worker.launch | worker_id, decision_id, policy_hash |
| worker.launch_denied | decision_id, reason_code, reason |
| worker.terminate | worker_id |
| policy.activation | policy_hash, context.activation_id |
| network.request | action, resource, policy_hash, decision_id, worker_id |
| filesystem.access | action, resource, policy_hash, decision_id, worker_id |
| command.exec | action, resource, decision_id, worker_id |

Deny/error events MUST include reason_code and reason. Policy-sensitive events MUST include policy_hash.

### Context and Integrity

- `context` requires `context_type`. Secret plaintext MUST NOT appear.
- Storage is append-only. Implementations SHOULD use per-record hash chains (`prev_hash` + `hash`) for storage integrity, but these are storage-layer concerns, not trail event envelope fields.
- Timestamps monotonic per stream. Event IDs unique per stream.

---

## v1 Contract

Required fields and error codes are frozen. New optional fields may be added. Breaking changes require v2.
