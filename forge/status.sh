#!/usr/bin/env bash
# One JSON line: running with what it guards, or stopped.
set -uo pipefail
. "$(dirname "$0")/lib.sh"
[ -n "$NODE" ] || { echo '{"state":"error","detail":"needs Node.js 18+"}'; exit 0; }
# one Node process for all of it: config, the status call, the answer. Two `cfg` calls and a
# third Node took 8 s on a swapping Pi 3, past the host's status timeout, and the host then
# "restarted" an app that was running all along
URL_BASE="$([ "${ADDON_HOST:-}" = burrow ] && echo "${ADDON_HOST_URL:-}__gate/bulwark/" || echo "")" "$NODE" --input-type=module -e "
  import { loadConfig } from '$APP/core/config.mjs';
  const c = loadConfig({ create: true });
  const url = process.env.URL_BASE || 'http://127.0.0.1:' + c.port + '/?k=' + c.key;
  let s;
  try {
    const r = await fetch('http://127.0.0.1:' + c.port + '/api/status', { headers: { 'x-bulwark-key': c.key }, signal: AbortSignal.timeout(5000) });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    s = await r.json();
  } catch { console.log(JSON.stringify({ state: 'stopped', name: 'Bulwark', detail: 'the app is not answering (the guard keeps enforcing)' })); process.exit(0); }
  console.log(JSON.stringify({ state: 'running', name: 'Bulwark', port: Number(c.port) || undefined, url,
    detail: (s.sensors || 0) + ' host' + (s.sensors === 1 ? '' : 's') + ' guarded · ' + (s.bans || 0) + ' banned' }));"
