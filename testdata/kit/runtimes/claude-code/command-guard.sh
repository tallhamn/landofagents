#!/usr/bin/env bash
# test fixture copy of command guard
if [[ -n "${LOA_GUARD_INITIALIZED:-}" ]]; then
  return 0
fi
export LOA_GUARD_INITIALIZED=1
shopt -s extdebug
trap ':' DEBUG
