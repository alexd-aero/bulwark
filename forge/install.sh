#!/usr/bin/env bash
# Install (and update): config + data folders, then Bulwark as its own service
# (a systemd user service when there is one, else a background process the
# host's watchdog restarts through the "start" action).
set -uo pipefail
. "$(dirname "$0")/lib.sh"
[ -n "$NODE" ] || { echo "::warn Bulwark needs Node.js 18 or newer"; exit 1; }
echo "::phase Setting up"
home="$(cfg home)"; port="$(cfg port)"
# inside Aegis × Burrow the dashboard opens only through Aegis (its login), never by a key link
if [ "${ADDON_HOST:-}" = burrow ]; then
  "$NODE" --input-type=module -e "import('$APP/core/config.mjs').then((m) => m.setConfig({ access: 'host' }))" && echo "::progress 15 the dashboard opens only through your Aegis login"
fi
mkdir -p "$home"/{feeds,asn,logs,state,run}
echo "::progress 20 config in ${XDG_CONFIG_HOME:-$HOME/.config}/bulwark, data in $home"
if have_user_systemd; then
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT_DIR/$UNIT" <<UNITEOF
[Unit]
Description=Bulwark: the shield's app (dashboard, lookups, waves, reports)
After=network-online.target

[Service]
ExecStart=$NODE --max-old-space-size=384 $APP/server.mjs
Restart=always
RestartSec=3
Nice=5
# whatever a wave does to it, it never takes the machine with it
MemoryHigh=480M
MemoryMax=640M
CPUQuota=80%
IOWeight=50

[Install]
WantedBy=default.target
UNITEOF
  systemctl --user daemon-reload
  systemctl --user enable "$UNIT" >/dev/null 2>&1
  loginctl enable-linger "$USER" >/dev/null 2>&1 || true
  echo "::progress 60 starting the service"
  systemctl --user restart "$UNIT"
else
  echo "::progress 60 starting (no systemd user manager here)"
  bash "$APP/forge/start.sh"
fi
for i in $(seq 1 30); do running && break; sleep 1; done
if running; then
  echo "::progress 100 Bulwark is running"
  key="$(cfg key)"
  [ "${ADDON_HOST:-}" = burrow ] && echo "::open ${ADDON_HOST_URL:-}__gate/bulwark/" || echo "::open http://127.0.0.1:$port/?k=$key"
else
  echo "::warn Bulwark didn't answer yet; see: journalctl --user -u $UNIT"; exit 1
fi
