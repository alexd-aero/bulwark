<p align="center"><img src="public/logo.svg" width="84" alt=""></p>
<h1 align="center">Bulwark</h1>
<p align="center">A shield for everything you publish from home.<br>Every request checked in microseconds · attackers banned everywhere at once · every request logged in full · waves seen coming.</p>

Bulwark guards self-hosted gateways. It installs as an addon in **Aegis × Burrow** (on by default there) and in **Selkies Forge**, and runs as an app of its own with its own dashboard.

## How it works

Bulwark has two halves:

**The guard** runs *inside* the gateway (Burrow loads it as an extension) and answers for every request before anything else happens, synchronously, in a few microseconds:

- **Banned?** Banned addresses get `403`, on every tunnel and the dashboard.
- **On a blocklist?** About 250 000 addresses from public lists are held in memory as sorted ranges (a binary search per list). An address on a *strong* list is banned on its first request.
- **A payload?** Requests that hunt for secrets or holes (`/.env`, `/.git/`, `../../etc/passwd`, phpunit's `eval-stdin`, `${jndi:…}`, SQL and command injection, router exploits) get `404` and never reach your app. Two of them ban the address, as does one probe from an address with any other mark against it. During a critical wave, the first payload bans.
- **Yours?** Your own addresses are never banned: private ones, those you signed in from in the last 30 days, any request carrying your session, and your allow list. Signing in lifts a ban on your address. The machine's *own* public address is neither trusted nor banned, because Mysterium, proxyware and the like send other people's traffic out through it.

The guard never waits on the network. If the app is down, it keeps enforcing on the last state it saw.

**The app** (`bulwark.service`) does everything slow, behind the request:

- **Lookups.** Every new address is checked in the background against Spamhaus, DroneBL, StopForumSpam, and GreyNoise when it probed. Known attackers are banned. Known business services (GreyNoise "benign": search engines, scrapers, research scanners) are left alone.
- **Lists, every 5 s.** The update loop runs every five seconds. Each source is asked whether it changed (ETag / Last-Modified) as often as it publishes. Only addresses that weren't already on a list are added, and they go to the guard at once, with no reload. A full re-read every few hours also drops addresses that left a list.
- **Waves.** The app watches for:
  - surges of new addresses or attacks against a learned baseline (EWMA, z ≥ 4 warns, z ≥ 8 is critical)
  - campaigns: several addresses running the same sequence of payloads with the same kind of client
  - clusters: one network (AS), /24 or /16 probing
  - discovery: a name only you used, suddenly found by strangers (how a new name in the certificate logs looks)

  Every open wave forecasts how many more addresses to expect in the next hour. Alerts can go to ntfy or a webhook.
- **The full log.** Every request is kept with address, network (AS, hosting or not), country, host, method, path, user agent, referer, language, route, status, size, time, decision and reason. The last 50 000 are in memory and every one is on disk (30 days by default), searchable.
- **Vendors.** For every banned address, the app shows which vendors already know it (FireHOL, blocklist.de, CINS, Emerging Threats, GreenSnow, IPsum, elsnet, Spamhaus, DroneBL, GreyNoise, StopForumSpam, AbuseIPDB). Addresses banned *for what they did here* are reported to AbuseIPDB (free key) when it missed them, with the requests as evidence and never your host names.
- **Your blocklist.** Every ban with its reason and evidence, exportable as plain text, CIDR, nginx, iptables, CSV or JSON.

## The dashboard

- **Overview:** traffic by what happened, attack patterns as a heatmap over time, top patterns, networks, countries and strangers
- **Live log:** every request, live, filterable; click a row for everything
- **Waves:** open and past waves with members and forecasts, strict mode, the baseline
- **Patterns:** a large graph linking every attacker to what it tried, the network it came from and the campaigns it joined. The layout is kept between visits, so it doesn't jump.
- **Blocklist:** new bans appear within 5 s
- **Lists** and **Vendors**

Each address opens a drawer with everything known about it: verdict, network, lists, vendor coverage, its requests, the waves it joined, and ban / allow / report actions.

Inside Aegis × Burrow it lives at `https://<dashboard>/__gate/bulwark/`, behind the gateway's login. Standalone, it's at `http://127.0.0.1:4370/?k=<key>` (`bulwark url`).

## Install

- **Aegis × Burrow 2.15+** installs it by itself. Otherwise go to Burrow → Addons and add `https://github.com/alexd-aero/bulwark`.
- **Selkies Forge:** Addons → add the same link.
- **By hand:** `git clone https://github.com/alexd-aero/bulwark && bash bulwark/forge/install.sh`

It needs Node.js 18+ and nothing else (no dependencies). It runs as a systemd user service when there is one.

```
bulwark status            what it guards, bans, waves
bulwark url               the dashboard, with its key
bulwark check IP          everything about an address
bulwark ban IP [why]      bulwark unban IP · bulwark allow IP
bulwark log [-f]          the latest requests (follow)
```

## Files

`~/.config/bulwark/bulwark.json` holds the port and key. `~/.local/share/bulwark/` holds `feeds/` (the lists), `asn/` (the network database, from iptoasn.com), `logs/` (every request), `state/` (bans, settings, alerts, profiles) and `run/sensor.sock` (guard ↔ app).

MIT licensed.
