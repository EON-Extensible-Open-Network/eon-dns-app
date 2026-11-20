<!--
SPDX-License-Identifier: GPL-3.0-or-later
SPDX-FileCopyrightText: 2026 EON contributors
-->

# Changelog

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
