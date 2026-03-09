#!/usr/bin/env bash
set -euo pipefail

AGENTS=(
  "david-clawggins"
  "clawlon-musk"
  "clawfather"
  "clawcus"
  "hackerman-claude"
)

STATE_ROOT="/srv/loa"
KIT_DIR=""
MIGRATE_ROOT=""
MIGRATE_MODE="copy" # copy|move
FORCE_INIT=0
AGENTS_CSV=""

usage() {
  cat <<'EOF'
Usage: setup-openclaw-lab.sh [options]

Bootstraps LOA OpenClaw agents and shared directories:
  - david-clawggins
  - clawlon-musk
  - clawfather
  - clawcus
  - hackerman-claude

Options:
  --state-root <dir>     Base state dir (default: /srv/loa)
  --kit-dir <dir>        LOA kit dir (default: <state-root>/kit)
  --agents <csv>         Comma-separated agent names
                         (default: david-clawggins,clawlon-musk,clawfather,clawcus,hackerman-claude)
  --migrate-root <dir>   Optional old data root; expects one subdir per agent name
  --migrate-mode <mode>  copy (default) or move
  --force-init           Always run 'loa init' even if kit looks initialized
  -h, --help             Show this help

Environment:
  LOA_BIN                Explicit LOA executable path/name (default auto-detect)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --state-root)
      STATE_ROOT="$2"
      shift 2
      ;;
    --kit-dir)
      KIT_DIR="$2"
      shift 2
      ;;
    --agents)
      AGENTS_CSV="$2"
      shift 2
      ;;
    --migrate-root)
      MIGRATE_ROOT="$2"
      shift 2
      ;;
    --migrate-mode)
      MIGRATE_MODE="$2"
      shift 2
      ;;
    --force-init)
      FORCE_INIT=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$MIGRATE_MODE" != "copy" && "$MIGRATE_MODE" != "move" ]]; then
  echo "Invalid --migrate-mode: $MIGRATE_MODE (expected copy|move)" >&2
  exit 1
fi

if [[ -n "$AGENTS_CSV" ]]; then
  IFS=',' read -r -a parsed_agents <<<"$AGENTS_CSV"
  AGENTS=()
  for raw in "${parsed_agents[@]}"; do
    trimmed="${raw#"${raw%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    if [[ -n "$trimmed" ]]; then
      AGENTS+=("$trimmed")
    fi
  done
  if [[ "${#AGENTS[@]}" -eq 0 ]]; then
    echo "Invalid --agents value: no agent names found" >&2
    exit 1
  fi
fi

if [[ -z "$KIT_DIR" ]]; then
  KIT_DIR="$STATE_ROOT/kit"
fi

AGENTS_ROOT="$STATE_ROOT/agents"
CLAWKEEPER_DIR="$STATE_ROOT/resources/clawkeeper"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

declare -a LOA_EXEC
if [[ -n "${LOA_BIN:-}" ]]; then
  LOA_EXEC=("$LOA_BIN")
elif command -v go >/dev/null 2>&1; then
  LOA_EXEC=("go" "run" "./cmd/loa")
elif [[ -x "$REPO_ROOT/loa" ]]; then
  LOA_EXEC=("$REPO_ROOT/loa")
else
  LOA_EXEC=("loa")
fi

loa() {
  (
    cd "$REPO_ROOT"
    LOA_KIT="$KIT_DIR" "${LOA_EXEC[@]}" "$@"
  )
}

agent_exists() {
  local name="$1"
  loa agent list 2>/dev/null | awk 'NR>1 {print $1}' | grep -Fxq "$name"
}

echo "==> Using LOA command: ${LOA_EXEC[*]}"
echo "==> State root: $STATE_ROOT"
echo "==> Kit dir:    $KIT_DIR"
echo "==> Agents:     ${AGENTS[*]}"

mkdir -p "$KIT_DIR" "$AGENTS_ROOT" "$CLAWKEEPER_DIR"
for agent in "${AGENTS[@]}"; do
  mkdir -p "$AGENTS_ROOT/$agent/openclaw"
done

if [[ "$FORCE_INIT" -eq 1 || ! -d "$KIT_DIR/config" || ! -d "$KIT_DIR/policies" ]]; then
  echo "==> Initializing kit"
  loa init
else
  echo "==> Kit already initialized; skipping 'loa init'"
fi

for agent in "${AGENTS[@]}"; do
  home_dir="$AGENTS_ROOT/$agent/openclaw"

  if agent_exists "$agent"; then
    echo "==> Agent exists: $agent (skipping create)"
    continue
  fi

  echo "==> Creating agent: $agent"
  loa agent create "$agent" \
    --runtime openclaw \
    --volume "$home_dir:/home/node/.openclaw" \
    --volume "$CLAWKEEPER_DIR:/clawkeeper"
done

if [[ -n "$MIGRATE_ROOT" ]]; then
  if [[ ! -d "$MIGRATE_ROOT" ]]; then
    echo "Migration root does not exist: $MIGRATE_ROOT" >&2
    exit 1
  fi

  echo "==> Migrating existing OpenClaw data from: $MIGRATE_ROOT"
  for agent in "${AGENTS[@]}"; do
    src="$MIGRATE_ROOT/$agent"
    dst="$AGENTS_ROOT/$agent/openclaw"
    if [[ ! -d "$src" ]]; then
      echo "   - $agent: source missing, skipped ($src)"
      continue
    fi

    echo "   - $agent: syncing $src -> $dst"
    rsync -a "$src"/ "$dst"/
    if [[ "$MIGRATE_MODE" == "move" ]]; then
      rm -rf "$src"
    fi
  done
fi

cat <<EOF
==> Done.

Directories:
  Kit:        $KIT_DIR
  Agent homes:$AGENTS_ROOT/<agent>/openclaw
  Shared app: $CLAWKEEPER_DIR (mounted at /clawkeeper)

Quick start:
  export LOA_KIT=$KIT_DIR
  ${LOA_EXEC[*]} watch --verbose
  ${LOA_EXEC[*]} run clawfather
EOF
