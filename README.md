<!--
SPDX-License-Identifier: GPL-3.0-or-later
SPDX-FileCopyrightText: 2026 EON contributors
-->

# EON DNS

EON DNS is one switch that makes every name lookup your computer sends encrypted,
checked and filtered (plan madde 47).

**Where lookups go**
- They go to the resolvers you choose: Cloudflare, Quad9, Mullvad, AdGuard, Google, or
  several at once, with the first good answer winning.
- They travel over **DNS over HTTPS, TLS or QUIC**.
- **DNSSEC** signatures are checked on this computer, so a resolver that lies is caught.

**Blocking**
- Blocking happens on this computer, from open lists (malware and scams, ads and trackers,
  adult content) plus your own *always allow* and *always block* rules.
- **Every block shows its reason**, and one press allows it.

**What you see**
- The switch is a ring of sixty ticks, one per minute of the last hour, with blocked
  lookups in amber.
- The resolvers you chose can be timed from this connection.
- The log is **off by default and kept in memory only**.

**Two modes**
- **EON's resolver** runs on `127.0.0.1` and does all of the above.
- **Windows' own encrypted DNS** hands encryption to Windows 11, which keeps doing it with
  EON DNS closed.

**EON DNS never leaves the computer without DNS.** It writes down the adapters' settings
before changing them, and puts them back when it is turned off, when it quits, and at the
first start after a crash.

There is no account and no telemetry. The only things that leave this computer are the
lookups themselves, encrypted, and the open lists EON DNS downloads.

## What it is not

It is not a VPN or a tunnel yet. The tunnel to an endpoint you bring, with a kill switch,
is the next slice. EON runs no resolver of its own and does not use Cloudflare's WARP
endpoints (madde 47a).

## Build and check

```
cargo build                                   # engine/ + the window (src-tauri/, src/)
cargo test                                    # the engine on loopback: answers, blocks, rules, restore scripts
cargo test --test engine -- --ignored         # real DoH, DoT and a deliberately broken DNSSEC domain
target/debug/eon-dns --selftest               # what CI runs before a release; never touches the system's DNS
node tools/ui-check.mjs target/debug/eon-dns.exe shots   # the real window over CDP, on a spare port
```

**Running it without the switch changing anything.** Set `EON_DNS_DATA` to a scratch
folder and `EON_DNS_PORT` to a free port, and set `EON_DNS_NO_SYSTEM=1` so that turning
it on never touches the adapters.

## Layout

| | |
|---|---|
| `engine/` | The local resolver: listeners, upstreams (`hickory-resolver`), filtering, counters, the benchmark, and the Windows apply and restore scripts. A library with no GUI dependency. |
| `src-tauri/` | The window and the tray. It runs itself elevated for the one step that changes the system (`--system apply\|native\|restore`). |
| `src/` | Static HTML, CSS and JavaScript. No network and no plugin of its own. |

Licence: [GPL-3.0-or-later](LICENSE) with the
[EON Module ABI Exception](LICENSE-EXCEPTION.md). The filter lists are HaGeZi's DNS
blocklists (GPL-3.0). They are downloaded at run time and not shipped.
