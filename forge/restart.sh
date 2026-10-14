#!/usr/bin/env bash
set -uo pipefail
. "$(dirname "$0")/lib.sh"
if have_user_systemd && [ -f "$UNIT_DIR/$UNIT" ]; then systemctl --user restart "$UNIT"; exit $?; fi
bash "$APP/forge/stop.sh"; sleep 1; bash "$APP/forge/start.sh"
