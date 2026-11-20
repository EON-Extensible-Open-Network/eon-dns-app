<!--
SPDX-License-Identifier: GPL-3.0-or-later
SPDX-FileCopyrightText: 2026 EON contributors
-->

# Security

Report privately through GitHub's **Security → Report a vulnerability** on this
repository. The organisation-wide policy is
[`.github/SECURITY.md`](https://github.com/EON-Extensible-Open-Network/.github/blob/main/SECURITY.md).

## What a DNS program has to get right

- **The resolver listens on loopback only.** It never listens on the network, so the
  computer does not become an open resolver.
- **Lookups go out encrypted.** Certificates are checked against the operating system's
  own trust store. A plain-DNS upstream exists only for tests and for an address a
  person adds themselves.
- **DNSSEC is checked on the device** when the setting is on, which it is by default. A
  validation failure is `SERVFAIL`, never an unchecked answer.
- **Changing the system needs consent every time.** Changing adapters runs one elevated
  copy of the program, through Windows' own prompt, with a fixed command. That copy
  writes no file other than the record of the previous settings and an error message.
- **The computer is never left without DNS.** The record of the previous settings exists
  exactly while EON DNS is in charge. Quitting is refused rather than leaving the
  adapters pointing at a resolver that is gone.
- **Lists are data, never code.** They are size-limited and parsed line by line; anything
  that is not a plausible domain is dropped.
- **The interface has no network and no plugin.** Names from lookups reach the page only
  as text.
- **No telemetry, and the log stays in memory.** CI checks for both.

## Known

- Builds are not signed (no keys yet; plan madde 30 and 34). Check `SHA256SUMS.txt`.
- Hickory DNS's own binary is not recommended for production. EON DNS uses its
  libraries, and the use is tested (plan madde 47, costs).
- In EON's mode the program must keep running. Closing the window keeps it in the tray;
  quitting puts the settings back first.
