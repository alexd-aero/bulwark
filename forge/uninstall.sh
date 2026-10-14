#!/usr/bin/env bash
# Remove the service; the data stays unless the host says not to keep it.
set -uo pipefail
. "$(dirname "$0")/lib.sh"
if have_user_systemd && [ -f "$UNIT_DIR/$UNIT" ]; then
  systemctl --user disable --now "$UNIT" >/dev/null 2>&1; rm -f "$UNIT_DIR/$UNIT"; systemctl --user daemon-reload
else bash "$APP/forge/stop.sh"; fi
if [ "${ADDON_KEEP_DATA:-1}" = 0 ]; then rm -rf "$(cfg home)"; rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/bulwark"; echo "removed Bulwark and its data"
else echo "removed Bulwark; its data stays in $(cfg home)"; fi
