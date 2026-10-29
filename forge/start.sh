#!/usr/bin/env bash
set -uo pipefail
. "$(dirname "$0")/lib.sh"
if have_user_systemd && [ -f "$UNIT_DIR/$UNIT" ]; then systemctl --user start "$UNIT"; exit $?; fi
running && exit 0
home="$(cfg home)"; mkdir -p "$home/run"
nohup "$NODE" $(node_flags) "$APP/server.mjs" >> "$home/run/bulwark.log" 2>&1 &
echo $! > "$(PIDFILE)"
for i in $(seq 1 20); do running && exit 0; sleep 1; done
exit 1
