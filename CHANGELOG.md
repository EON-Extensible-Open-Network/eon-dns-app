<!--
SPDX-License-Identifier: GPL-3.0-or-later
SPDX-FileCopyrightText: 2026 EON contributors
-->

# Changelog

## v0.0.2 — 21 November 2026

### Added
- **The tunnel.** All traffic, not only names, can now go sealed through WireGuard, to one
  of three places:
  - **WARP**: Cloudflare's free network. EON DNS registers a device the way the 1.1.1.1
    app does.
  - **My tunnel**: a WireGuard configuration you paste in Settings, from your own server
    or a VPN provider.
  - **EON server**: an EON tunnel server. The client is ready; EON runs none yet.

  Names are still answered by EON's resolver, inside the tunnel. Sites that are blocked by
  name, which encrypted DNS alone cannot reach, open. CI brings a real WARP tunnel up and
  checks that Cloudflare's trace page says `warp=on`.
- **The connection chooser sits right under the switch:** DNS only, WARP, My tunnel, EON
  server. Changing it reconnects at once.
- **The EON DNS service.** It holds the rights that changing the system needs, as WARP's
  own service does.
  - It is installed once, the first time you press the switch, with one Windows consent
    prompt. After that, turning on and off and switching mode ask nothing.
  - It keeps protection on with the window closed.
  - When it stops, it puts your DNS back. When it starts, it reconnects.
- **Settings → Tunnel:**
  - addresses to keep off the tunnel;
  - the WireGuard configuration;
  - the EON server address;
  - a WARP+ key;
  - connecting at start;
  - a new WARP identity.
- **Settings → Diagnostics** copies a report: settings and counters, never a name you
  looked up. `eon-dns --status` prints the same report.

### Fixed
- **Turning protection off failed.** The record of your previous DNS settings carried NUL
  characters from the registry, and it could also carry EON DNS's own `::1` from an
  earlier attempt. Both are now cleaned when the record is read, and the service moves an
  old record over when it is installed.
- **A failed connection** (no tunnel, say) shows as off, with its reason, instead of
  "Protected" over nothing.
- **Lookups are fast again.** Checking DNSSEC on this computer is now optional and off by
  default. It made the first lookup of each name take 0.5–1.2 s instead of about 25 ms,
  and every preset already checks DNSSEC itself.

## v0.0.1 — 21 November 2026

### Fixed
- **Turning protection on failed on computers with a network adapter that cannot take
  a DNS setting.** A virtual adapter with no IPv4 is one example, and many Windows
  machines have one. Such an adapter is now skipped, and turning on fails only if no
  adapter took the setting. Found by the new CI step that applies and restores the
  system's DNS for real on the Windows runner: two adapters pointed at `127.0.0.1`, then
  put back exactly as they were.

## v0.0.0 — 21 November 2026

The first alpha: the encrypted-DNS half of plan madde 47.

### Lookups
- **The local resolver** listens on `127.0.0.1` and `::1`.
  - Every lookup goes out over DoH, DoT or DoQ to the chosen presets.
  - Several presets are raced.
  - DNSSEC is checked on the device: a domain with broken signatures is refused, and
    this is tested against a real one.
- **Answers** keep the time-to-live of the upstream answer, are cached, and are
  truncated correctly for UDP.
  - A failing upstream gives `SERVFAIL`, never silence.

### Blocking
- **Open lists:** malware and scams, ads and trackers, adult content.
  - Each list is fetched daily and checked before use. A list that fails keeps its last
    good copy.
- **The person's own rules:** *always allow* wins, and *always block* covers
  subdomains.
- **A blocked name** gets `0.0.0.0` or `::`, never leaves the computer, and carries its
  reason.

### The window
- **The overview:** a ring of sixty ticks that is both the switch and the last hour,
  with plain words for where lookups go, the counters, and what was blocked recently.
- **Protection:** the lists, the rules, and "why is this name blocked?".
- **Resolvers:** the two modes, the presets, encryption, DNSSEC, and timing each
  resolver from this connection.
- **Log:** off by default and kept in memory only. Each row can be allowed or blocked
  with one press.
- English and Turkish. The tray keeps running when the window closes.

### Windows
- **Turning on** points every connected adapter at the local resolver, after writing down
  what was there before, including whether it came from DHCP.
  - This runs through a single elevated run of the program.
- **Turning off, quitting, and the first start after a crash** put it back.
- **Windows' own encrypted DNS** is the alternative mode. It registers the preset's DoH
  template with Windows.

### Checks
- `--selftest`, engine tests on loopback, a real-network test, and `tools/ui-check.mjs`
  (19 checks in the real window).
