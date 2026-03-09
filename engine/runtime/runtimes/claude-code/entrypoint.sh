#!/bin/sh
if [ "${LOA_COMMAND_POLICY_MODE:-discover}" != "off" ]; then
  export BASH_ENV=/command-guard.sh
  export ENV=/command-guard.sh
fi
exec claude --dangerously-skip-permissions
