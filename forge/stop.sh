#!/usr/bin/env bash
set -uo pipefail
. "$(dirname "$0")/lib.sh"
if have_user_systemd && [ -f "$UNIT_DIR/$UNIT" ]; then systemctl --user stop "$UNIT"; exit 0; fi
pid="$(cat "$(PIDFILE)" 2>/dev/null)"; [ -n "$pid" ] && kill "$pid" 2>/dev/null; exit 0
