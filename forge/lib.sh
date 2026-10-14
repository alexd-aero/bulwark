# shared by the scripts: where node is, where Bulwark lives, how it runs
APP="${ADDON_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
find_node() {
  for n in "${BURROW_NODE:-}" "$(command -v node 2>/dev/null)" "$HOME"/.nvm/versions/node/*/bin/node /usr/local/bin/node /usr/bin/node; do
    [ -n "$n" ] && [ -x "$n" ] && "$n" -e 'process.exit(+process.versions.node.split(".")[0] >= 18 ? 0 : 1)' 2>/dev/null && { echo "$n"; return 0; }
  done
  return 1
}
NODE="$(find_node || true)"
cfg() { "$NODE" --input-type=module -e "import { loadConfig } from '$APP/core/config.mjs'; const c = loadConfig({ create: true }); console.log(c['$1'] ?? '');"; }
# from inside a host's service the user's systemd session isn't in the environment: point at it
if [ -z "${XDG_RUNTIME_DIR:-}" ] && [ -d "/run/user/$(id -u)" ]; then export XDG_RUNTIME_DIR="/run/user/$(id -u)"; fi
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] && [ -S "${XDG_RUNTIME_DIR:-/nonexistent}/bus" ]; then export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"; fi
UNIT=bulwark.service
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
have_user_systemd() { command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; }
running() { curl -fsS --max-time 3 "http://127.0.0.1:$(cfg port)/api/status" >/dev/null 2>&1; }
PIDFILE() { echo "$(cfg home)/run/bulwark.pid"; }
