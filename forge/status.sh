#!/usr/bin/env bash
# One JSON line: running with what it guards, or stopped.
set -uo pipefail
. "$(dirname "$0")/lib.sh"
[ -n "$NODE" ] || { echo '{"state":"error","detail":"needs Node.js 18+"}'; exit 0; }
port="$(cfg port)"
s="$(curl -fsS --max-time 3 "http://127.0.0.1:$port/api/status" -H "x-bulwark-key: $(cfg key)" 2>/dev/null)" || { echo '{"state":"stopped","name":"Bulwark","detail":"the app is not answering (the guard keeps enforcing)"}'; exit 0; }
URL="$([ "${ADDON_HOST:-}" = burrow ] && echo "${ADDON_HOST_URL:-}__gate/bulwark/" || echo "http://127.0.0.1:$port/?k=$(cfg key)")" S="$s" "$NODE" -e '
  const s = JSON.parse(process.env.S || "{}");
  console.log(JSON.stringify({ state: "running", name: "Bulwark", port: Number(process.env.PORT) || undefined, url: process.env.URL,
    detail: `${s.sensors || 0} host${s.sensors === 1 ? "" : "s"} guarded · ${s.bans || 0} banned` }));'
