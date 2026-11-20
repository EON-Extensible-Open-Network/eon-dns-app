<!--
SPDX-License-Identifier: GPL-3.0-or-later
SPDX-FileCopyrightText: 2026 EON contributors
-->

# Contributing to EON DNS

The organisation-wide guide,
[`.github/CONTRIBUTING.md`](https://github.com/EON-Extensible-Open-Network/.github/blob/main/CONTRIBUTING.md),
applies: DCO sign-off (`git commit -s`) and Conventional Commits (`feat(engine): ...`,
`fix(window): ...`). By contributing you license your work under `GPL-3.0-or-later` with
the EON Module ABI Exception.

- **Test the engine on loopback.** A change to how lookups are answered comes with a test
  in `engine/tests/engine.rs` that would fail without it.
- **Never run apply or restore on your own machine by accident.** Use `EON_DNS_DATA`,
  `EON_DNS_PORT` and `EON_DNS_NO_SYSTEM=1` while developing. Test the restore scripts as
  text (`engine/src/system.rs`).
- **Write every string in both languages** (`src-tauri/i18n/en.json` and `tr.json`).
  `--selftest` fails otherwise.
- **Register a new command twice:** in `generate_handler!` and in `COMMANDS`.
- **Look at it.** A change to the window comes with the screenshots
  `node tools/ui-check.mjs <exe> shots` produces.
- **Justify every new dependency** where it is declared (madde 37).
