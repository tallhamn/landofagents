#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COUNT="${1:-5}"
export GOCACHE="${GOCACHE:-/tmp/go-build}"

cd "$ROOT_DIR"

echo "LOA authz reload-path benchmark"
echo "  repo: $ROOT_DIR"
echo "  go: $(go version)"
echo "  count: $COUNT"
echo "  gocache: $GOCACHE"
echo

go test ./engine/authz -run '^$' -bench BenchmarkPolicyReloadPath -benchmem -count "$COUNT"
