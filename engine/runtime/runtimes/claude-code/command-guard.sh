#!/usr/bin/env bash
# LOA command observer for bash shells launched by Claude Code.
# Modes:
#   discover (default): observe and log command activity
#   off: disable observer

if [[ -n "${LOA_GUARD_INITIALIZED:-}" ]]; then
  return 0
fi
export LOA_GUARD_INITIALIZED=1

__loa_should_skip_guard() {
  local cmd="$1"
  [[ -z "$cmd" ]] && return 0
  [[ "$cmd" == __loa_* ]] && return 0
  [[ "$cmd" == trap* ]] && return 0
  [[ "$cmd" == history* ]] && return 0
  [[ "$cmd" == "loa protect"* ]] && return 0
  [[ "$cmd" == "command -v loa"* ]] && return 0
  return 1
}

__loa_should_track_file_activity() {
  local mode="${LOA_FILE_ACTIVITY_MODE:-discover}"
  [[ "$mode" == "off" ]] && return 1
  local root="${LOA_ACTIVITY_ROOT:-/workspace}"
  [[ -d "$root" ]] || return 1
  return 0
}

__loa_guard_preexec() {
  local cmd="$BASH_COMMAND"

  __loa_should_skip_guard "$cmd" && return 0
  [[ "${LOA_GUARD_BUSY:-}" == "1" ]] && return 0

  local mode="${LOA_COMMAND_POLICY_MODE:-discover}"
  [[ "$mode" == "off" ]] && return 0

  __loa_guard_last_cmd="$cmd"
  __loa_guard_last_mode="$mode"

  if __loa_should_track_file_activity; then
    local snapshot_file
    snapshot_file="$(mktemp -t loa-activity.XXXXXX 2>/dev/null || true)"
    if [[ -n "$snapshot_file" ]]; then
      touch "$snapshot_file" >/dev/null 2>&1 || true
      __loa_guard_snapshot_file="$snapshot_file"
    else
      __loa_guard_snapshot_file=""
    fi
  else
    __loa_guard_snapshot_file=""
  fi

  export LOA_GUARD_BUSY=1
  loa protect --agent "${LOA_AGENT_NAME:-agent}" --command "$cmd" --stage pre >/dev/null 2>&1 || true
  unset LOA_GUARD_BUSY
  return 0
}

__loa_guard_postexec() {
  [[ "${LOA_GUARD_BUSY:-}" == "1" ]] && return 0
  [[ -z "${__loa_guard_last_cmd:-}" ]] && return 0

  local mode="${__loa_guard_last_mode:-${LOA_COMMAND_POLICY_MODE:-discover}}"
  local cmd="${__loa_guard_last_cmd:-}"
  local snapshot_file="${__loa_guard_snapshot_file:-}"
  local root="${LOA_ACTIVITY_ROOT:-/workspace}"

  __loa_guard_last_cmd=""
  __loa_guard_last_mode=""
  __loa_guard_snapshot_file=""

  [[ "$mode" == "off" ]] && {
    [[ -n "$snapshot_file" ]] && rm -f "$snapshot_file" >/dev/null 2>&1 || true
    return 0
  }

  if [[ -n "$snapshot_file" && -f "$snapshot_file" ]]; then
    export LOA_GUARD_BUSY=1
    loa protect --agent "${LOA_AGENT_NAME:-agent}" --command "$cmd" --stage post --file-root "$root" --since-file "$snapshot_file" >/dev/null 2>&1 || true
    unset LOA_GUARD_BUSY
    rm -f "$snapshot_file" >/dev/null 2>&1 || true
  fi
  return 0
}

__loa_guard_install_prompt_hook() {
  if [[ "${PROMPT_COMMAND:-}" == *"__loa_guard_postexec"* ]]; then
    return 0
  fi
  if [[ -n "${PROMPT_COMMAND:-}" ]]; then
    PROMPT_COMMAND="__loa_guard_postexec; ${PROMPT_COMMAND}"
  else
    PROMPT_COMMAND="__loa_guard_postexec"
  fi
}

trap '__loa_guard_preexec' DEBUG
__loa_guard_install_prompt_hook
