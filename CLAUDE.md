# LOA Development Guide

LOA (Land of Agents) governs AI agent execution with least-privilege controls. GAP (Governed Agent Protocol) is the underlying protocol.

## Build and Test

```bash
go build ./...
go test ./...
go vet ./...
```

Key test suites:
- `go test ./engine/...` — core engine tests
- `go test ./app/...` — app layer tests
- `go test ./cmd/loa/...` — CLI tests (includes GAP conformance)
- `go test ./engine -run TestEngineNeverImportsAppOrCmd` — layer boundary enforcement

## Repository Layout

```
gap/              # GAP protocol types (zero deps)
engine/           # Security-critical core: authz, audit, contain, worker, protector
app/              # Product features: approval, advocate, codifier, adapters
cmd/loa/          # CLI binary
configs/          # Envoy template, authz Dockerfile
testdata/         # Test fixtures
```

Dependency rule: `cmd/loa -> app -> engine -> gap`. Never import upward.

## Key Conventions

- **Cedar only**: policy files are `*.cedar`, never YAML.
- **Fail closed**: missing identity, policy, or metadata = deny.
- **No runtime branching in engine**: engine code must not reference `"claude-code"`, `"openclaw"`, or `"codex"` by name. Use hooks/adapters.
- **Boundary tests**: AST-based import checks enforce layer separation. Run them before pushing.
- **Append-only audit**: JSONL with hash chains. Never mutate existing records.

## Architecture Quick Reference

Each `loa run` creates 3 Docker containers: agent runtime + Envoy proxy + LOA authz sidecar. Outbound traffic flows: agent -> Envoy -> authz (Cedar eval) -> internet.

Policy lifecycle: denied event -> proposal -> staged -> active. Approvals can be LLM-assisted (advocate/codifier) or template-based.

Modes: `ask` (deny=hold until approved, default), `log` (deny=allow+log), `enforce` (deny=403).

## When Modifying Code

- Read the file before editing it.
- Run `go build ./...` after changes.
- Run relevant tests: `go test ./<package>/... -count=1`
- If touching engine/: verify `go test ./engine -run TestEngine` boundary test passes.
- Don't add runtime-specific logic to engine packages — use app/adapters/ instead.
