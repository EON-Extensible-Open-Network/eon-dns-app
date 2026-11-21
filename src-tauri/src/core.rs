// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! What EON DNS does, whoever runs it: the settings, the local resolver, the
//! tunnel, and pointing the system at them. On Windows the EON DNS service
//! runs this with the rights changing the system needs; the window asks it
//! over `control`. Elsewhere, and in tests, the window runs it itself.
//!
//! Every request and every answer is JSON, so the two paths are one path.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use eon_dns_engine::filter::List;
use eon_dns_engine::tunnel::{self, TunnelConfig};
use eon_dns_engine::upstream::{Transport, Upstream, PRESETS};
use eon_dns_engine::{system, Engine, Settings};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// How the computer is connected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Lookups only: EON's resolver encrypts, filters and counts.
    #[default]
    #[serde(alias = "local")]
    Dns,
    /// All traffic through Cloudflare's free WARP network, lookups through EON's resolver.
    Warp,
    /// All traffic through a WireGuard endpoint the person brought.
    Wireguard,
    /// All traffic through an EON tunnel server (none runs yet; madde 30).
    Eon,
    /// Windows 11's own encrypted DNS to one preset; works with EON DNS closed.
    Native,
}

impl Mode {
    fn tunnels(self) -> bool {
        matches!(self, Self::Warp | Self::Wireguard | Self::Eon)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    pub engine: Settings,
    pub on: bool,
    pub mode: Mode,
    pub native_preset: String,
    /// A `wg-quick` configuration the person pasted, for `Mode::Wireguard`.
    pub wireguard: String,
    /// An EON tunnel server's address, for `Mode::Eon`.
    pub eon_server: String,
    /// Addresses and ranges that keep using the physical network (split tunnel).
    pub exclude: Vec<String>,
    /// A WARP+ licence key, if the person has one.
    pub warp_license: String,
    pub language: String,
    pub close_to_tray: bool,
    /// Turn on at sign-in, as WARP's "always on".
    pub auto_connect: bool,
    /// Bumped when a default changes in a way that should reach existing
    /// settings. A file without it is from before versions were written (1).
    #[serde(default = "first_version")]
    pub version: u32,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            engine: Settings::default(),
            on: false,
            mode: Mode::Dns,
            native_preset: "cloudflare".into(),
            wireguard: String::new(),
            eon_server: String::new(),
            exclude: Vec::new(),
            warp_license: String::new(),
            language: String::new(),
            close_to_tray: true,
            auto_connect: true,
            version: SETTINGS_VERSION,
        }
    }
}

fn first_version() -> u32 {
    1
}

/// v2: checking DNSSEC on the device became opt-in. It made the first
/// lookup of a name 0.5-1.2 s instead of ~25 ms (measured 21 November 2026),
/// and the presets validate it themselves.
const SETTINGS_VERSION: u32 = 2;

impl AppSettings {
    pub fn load(data: &Path) -> Self {
        let mut s: Self = std::fs::read_to_string(data.join("settings.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        if s.version < 2 {
            s.engine.validate = false;
            s.version = SETTINGS_VERSION;
        }
        s
    }

    pub fn save(&self, data: &Path) {
        if let Ok(text) = serde_json::to_string_pretty(self) {
            let _ = std::fs::create_dir_all(data);
            let tmp = data.join("settings.json.tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(tmp, data.join("settings.json"));
            }
        }
    }
}

/// What the window asks for.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "do", rename_all = "snake_case")]
pub enum Request {
    Boot,
    Turn {
        on: bool,
    },
    SaveSettings {
        settings: Value,
    },
    Stats,
    ClearLog,
    RefreshLists,
    Benchmark {
        transport: Transport,
    },
    Explain {
        name: String,
    },
    /// A fresh WARP device (new keys), as "reset" in the WARP client.
    WarpReset,
    Diagnostics,
}

pub struct Core {
    pub data: PathBuf,
    /// Whether this process may change the system (the service may; tests may not).
    pub system_allowed: bool,
    pub port: u16,
    settings: Mutex<AppSettings>,
    engine: Mutex<Option<Engine>>,
    #[cfg(windows)]
    tunnel: Mutex<Option<tunnel::windows::Tunnel>>,
    problem: Mutex<Option<String>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Runs async engine work from wherever this is called (a Tauri command is
/// inside a runtime already; the service is not), on a thread of its own.
fn block<T: Send>(
    f: impl std::future::Future<Output = Result<T, String>> + Send,
) -> Result<T, String> {
    std::thread::scope(|s| {
        s.spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?
                .block_on(f)
        })
        .join()
        .map_err(|_| "a background step failed".to_owned())?
    })
}

impl Core {
    pub fn new(data: PathBuf, system_allowed: bool, port: u16) -> Self {
        let settings = AppSettings::load(&data);
        Self {
            data,
            system_allowed,
            port,
            settings: Mutex::new(settings),
            engine: Mutex::new(None),
            #[cfg(windows)]
            tunnel: Mutex::new(None),
            problem: Mutex::new(None),
        }
    }

    pub fn settings(&self) -> AppSettings {
        lock(&self.settings).clone()
    }

    fn start_engine(&self) -> Result<(), String> {
        let mut engine = lock(&self.engine);
        if engine.is_none() {
            let settings = lock(&self.settings).engine.clone();
            *engine = Some(
                Engine::start(&settings, &self.data, self.port).map_err(|e| {
                    if e.contains("10048")
                        || e.contains("10013")
                        || e.to_lowercase().contains("in use")
                    {
                        "problem.port".to_owned()
                    } else {
                        e
                    }
                })?,
            );
        }
        Ok(())
    }

    fn stop_engine(&self) {
        if let Some(e) = lock(&self.engine).take() {
            e.stop();
        }
    }

    #[cfg_attr(not(windows), allow(clippy::unused_self))]
    fn tunnel_down(&self) {
        #[cfg(windows)]
        if let Some(t) = lock(&self.tunnel).take() {
            t.down();
        }
    }

    /// The configuration for the tunnel mode chosen, from its provider.
    fn tunnel_config(&self, mode: Mode) -> Result<TunnelConfig, String> {
        let s = self.settings();
        match mode {
            Mode::Warp => {
                let account_file = self.data.join("warp.json");
                let account: Option<tunnel::warp::WarpAccount> =
                    std::fs::read_to_string(&account_file)
                        .ok()
                        .and_then(|t| serde_json::from_str(&t).ok());
                let cached = self.data.join("warp-config.json");
                let (account, config) = match account {
                    Some(a) => match block(tunnel::warp::fetch(&a)) {
                        Ok(c) => (a, c),
                        // Offline, or the API is down: the last good configuration still works.
                        Err(e) => match std::fs::read_to_string(&cached)
                            .ok()
                            .and_then(|t| serde_json::from_str(&t).ok())
                        {
                            Some(c) => (a, c),
                            None => return Err(e),
                        },
                    },
                    None => block(tunnel::warp::register())?,
                };
                if !s.warp_license.trim().is_empty() && s.warp_license.trim() != account.license {
                    block(tunnel::warp::set_license(&account, &s.warp_license))?;
                }
                if let Ok(t) = serde_json::to_string_pretty(&account) {
                    let _ = std::fs::write(&account_file, t);
                }
                if let Ok(t) = serde_json::to_string_pretty(&config) {
                    let _ = std::fs::write(&cached, t);
                }
                Ok(config)
            }
            Mode::Wireguard => tunnel::wgconf::parse(&s.wireguard),
            Mode::Eon => {
                let cached = self.data.join("eon-tunnel.json");
                if let Some(c) = std::fs::read_to_string(&cached)
                    .ok()
                    .and_then(|t| serde_json::from_str::<TunnelConfig>(&t).ok())
                {
                    return Ok(c);
                }
                if s.eon_server.trim().is_empty() {
                    return Err("problem.noeonserver".into());
                }
                let (_, c) = block(tunnel::eon::register(&s.eon_server, None))?;
                if let Ok(t) = serde_json::to_string_pretty(&c) {
                    let _ = std::fs::write(&cached, t);
                }
                Ok(c)
            }
            _ => Err("not a tunnel mode".into()),
        }
    }

    #[cfg(windows)]
    fn tunnel_up(&self, mode: Mode) -> Result<(), String> {
        let config = self.tunnel_config(mode)?;
        let dll = block(tunnel::windows::ensure_driver(&self.data.join("tools")))?;
        let exclude = self.settings().exclude;
        let t = tunnel::windows::Tunnel::up(&dll, &config, &exclude)?;
        *lock(&self.tunnel) = Some(t);
        Ok(())
    }

    #[cfg(not(windows))]
    fn tunnel_up(&self, mode: Mode) -> Result<(), String> {
        self.tunnel_config(mode)?;
        Err("problem.tunnelplatform".into())
    }

    /// Connects in the chosen mode, or disconnects. Connecting when already
    /// connected reconnects: a change of mode takes effect at once.
    pub fn set_on(&self, on: bool) -> Result<(), String> {
        *lock(&self.problem) = None;
        let mode = self.settings().mode;
        let result = if on {
            self.connect(mode)
        } else {
            self.disconnect()
        };
        match result {
            Ok(()) => {
                let mut s = lock(&self.settings);
                s.on = on;
                s.save(&self.data);
                Ok(())
            }
            Err(e) => {
                // A connection that failed is no connection: say so, as off,
                // rather than show "protected" over nothing running.
                if on {
                    let mut s = lock(&self.settings);
                    s.on = false;
                    s.save(&self.data);
                }
                *lock(&self.problem) = Some(e.clone());
                Err(e)
            }
        }
    }

    fn connect(&self, mode: Mode) -> Result<(), String> {
        // Whatever was up goes first; the record of the computer's own
        // settings survives, so nothing is lost by reconnecting.
        self.tunnel_down();
        if mode.tunnels() {
            if !self.system_allowed {
                return Err("problem.tunnelservice".into());
            }
            if let Err(e) = self.tunnel_up(mode) {
                self.stop_engine();
                if system::in_charge(&self.data).is_some() {
                    let _ = system::restore(&self.data);
                }
                return Err(e);
            }
        }
        if mode == Mode::Native {
            self.stop_engine();
            if self.system_allowed {
                let id = self.settings().native_preset;
                let preset = eon_dns_engine::upstream::preset(&id).ok_or("unknown resolver")?;
                system::apply_native(&self.data, preset)?;
            }
            return Ok(());
        }
        self.start_engine()?;
        if self.system_allowed {
            if let Err(e) = system::apply_local(&self.data) {
                self.tunnel_down();
                self.stop_engine();
                return Err(e);
            }
        }
        Ok(())
    }

    fn disconnect(&self) -> Result<(), String> {
        if self.system_allowed && system::in_charge(&self.data).is_some() {
            system::restore(&self.data)?;
        }
        self.tunnel_down();
        self.stop_engine();
        Ok(())
    }

    /// At start: carry on if the switch was on, and never leave the system
    /// pointing at something that is not running (madde 47d).
    pub fn recover(&self) {
        let s = self.settings();
        if s.on && (s.auto_connect || system::in_charge(&self.data).is_some()) {
            if self.set_on(true).is_err() && self.system_allowed {
                let _ = system::restore(&self.data);
            }
        } else if self.system_allowed && system::in_charge(&self.data).is_some() {
            let _ = system::restore(&self.data);
        }
    }

    /// Covers adapters that came up after protection was turned on (Wi-Fi
    /// joining later): the service calls this every few seconds.
    pub fn keep_applied(&self) {
        let s = self.settings();
        if !self.system_allowed || !s.on || s.mode == Mode::Native || lock(&self.engine).is_none() {
            return;
        }
        if system::uncovered(&["127.0.0.1", "::1"]).is_ok_and(|missing| !missing.is_empty()) {
            let _ = system::apply_local(&self.data);
        }
    }

    /// Whether the tunnel still carries traffic well; `None` when there is
    /// no tunnel to judge. On the owner's network a WARP connection that ran
    /// fast for its first minutes later took 3-9 s for a TLS handshake and
    /// 0.8 MB/s, and was fast again the moment it was rebuilt: the service
    /// rebuilds it when this says no twice running (see `service.rs`).
    ///
    /// Every tunnel: no handshake for longer than WireGuard ever goes
    /// without one (it rekeys every two minutes). WARP also: Cloudflare's
    /// trace page must answer `warp=on` within three seconds. The other
    /// tunnels are not probed, because that would send a request to
    /// Cloudflare the person did not choose.
    #[cfg(windows)]
    pub fn tunnel_healthy(&self) -> Option<bool> {
        let s = self.settings();
        if !s.on || !s.mode.tunnels() {
            return None;
        }
        // A tunnel that should be up and is not (a rebuild that failed
        // while the network was away) is unwell too, so it is tried again.
        let Some(stats) = lock(&self.tunnel)
            .as_ref()
            .map(tunnel::windows::Tunnel::stats)
        else {
            return Some(false);
        };
        if stats.handshake_age.is_some_and(|age| age > 200) {
            return Some(false);
        }
        if s.mode != Mode::Warp {
            return Some(true);
        }
        let took = block(tunnel::warp::probe(std::time::Duration::from_secs(8)));
        Some(took.is_ok_and(|d| d < std::time::Duration::from_secs(3)))
    }

    /// Takes the tunnel down and brings it up again, leaving the resolver
    /// and the switch alone: a rebuild that fails (the network is away) is
    /// tried again on the next check instead of turning protection off.
    #[cfg(windows)]
    pub fn rebuild_tunnel(&self) {
        let mode = self.settings().mode;
        self.tunnel_down();
        *lock(&self.problem) = self.tunnel_up(mode).err();
    }

    /// Before the service stops: put the computer's own DNS back, keep the
    /// switch's position so the next start reconnects.
    #[cfg_attr(not(windows), allow(dead_code))] // only the Windows service stops this way
    pub fn shutdown(&self) {
        let on = self.settings().on;
        let _ = self.disconnect();
        let mut s = lock(&self.settings);
        s.on = on;
        s.save(&self.data);
    }

    fn state(&self) -> Value {
        let s = self.settings();
        #[cfg(windows)]
        let tunnel = lock(&self.tunnel).as_ref().map(|t| json!({"stats": t.stats(), "endpoint": t.config.endpoint.to_string(), "source": t.config.source, "addresses": t.config.addresses}));
        #[cfg(not(windows))]
        let tunnel: Option<Value> = None;
        json!({
            "on": s.on,
            "mode": s.mode,
            "running": lock(&self.engine).as_ref().map(|e| e.port),
            "tunnel": tunnel,
            "in_charge": system::in_charge(&self.data).map(|p| p.mode),
            "problem": lock(&self.problem).clone(),
            "system_allowed": self.system_allowed,
            "service": self.system_allowed,
        })
    }

    pub fn handle(self: &Arc<Self>, request: Request) -> Result<Value, String> {
        match request {
            Request::Boot => {
                let presets: Vec<Value> = PRESETS
                    .iter()
                    .map(|p| json!({"id": p.id, "name": p.name, "transports": p.transports, "ips": p.ips}))
                    .collect();
                let lists: Vec<Value> = List::ALL
                    .iter()
                    .map(|l| {
                        json!({
                            "id": l,
                            "updated": eon_dns_engine::lists::updated(&self.data, *l)
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map(|d| d.as_secs()),
                            "size": eon_dns_engine::lists::load(&self.data, *l).map(|s| s.len()),
                        })
                    })
                    .collect();
                let warp = std::fs::read_to_string(self.data.join("warp.json"))
                    .ok()
                    .and_then(|t| serde_json::from_str::<tunnel::warp::WarpAccount>(&t).ok())
                    .map(|a| json!({"registered": true, "warp_plus": a.warp_plus}));
                Ok(json!({
                    "settings": self.settings(),
                    "presets": presets,
                    "lists": lists,
                    "state": self.state(),
                    "warp": warp,
                    "version": env!("CARGO_PKG_VERSION"),
                }))
            }
            Request::Turn { on } => {
                let _ = self.set_on(on);
                if on {
                    self.refresh_lists_soon();
                }
                Ok(self.state())
            }
            Request::SaveSettings { settings } => self.save_settings(settings),
            Request::Stats => {
                // State first: it takes the engine's lock itself, and a Mutex
                // is not re-entrant (holding it here froze the window).
                let state = self.state();
                let engine = lock(&self.engine);
                Ok(match engine.as_ref() {
                    Some(e) => {
                        json!({"stats": e.stats(), "log": e.log(), "lists": e.list_sizes(), "state": state})
                    }
                    None => json!({"stats": null, "log": [], "lists": [], "state": state}),
                })
            }
            Request::ClearLog => {
                if let Some(e) = lock(&self.engine).as_ref() {
                    e.clear_log();
                }
                Ok(Value::Null)
            }
            Request::RefreshLists => Ok(json!(self
                .fetch_lists(true)
                .into_iter()
                .map(|(l, r)| match r {
                    Ok(n) => json!({"id": l, "ok": n}),
                    Err(e) => json!({"id": l, "error": e}),
                })
                .collect::<Vec<_>>())),
            Request::Benchmark { transport } => {
                let candidates: Vec<Upstream> = PRESETS
                    .iter()
                    .map(|p| Upstream::Preset { id: p.id.into() })
                    .collect();
                Ok(json!(block(async {
                    Ok(eon_dns_engine::bench::run(candidates, transport).await)
                })?))
            }
            Request::Explain { name } => Ok(lock(&self.engine)
                .as_ref()
                .map_or(Value::Null, |e| json!(e.explain(&name)))),
            Request::WarpReset => {
                let _ = std::fs::remove_file(self.data.join("warp.json"));
                let _ = std::fs::remove_file(self.data.join("warp-config.json"));
                let s = self.settings();
                if s.on && s.mode == Mode::Warp {
                    let _ = self.set_on(true);
                }
                Ok(self.state())
            }
            Request::Diagnostics => Ok(self.diagnostics()),
        }
    }

    fn save_settings(self: &Arc<Self>, value: Value) -> Result<Value, String> {
        let next: AppSettings = serde_json::from_value(value).map_err(|e| e.to_string())?;
        let before = self.settings();
        {
            let mut s = lock(&self.settings);
            let on = s.on;
            *s = next.clone();
            s.on = on;
            s.version = SETTINGS_VERSION;
            s.save(&self.data);
        }
        if let Some(engine) = lock(&self.engine).as_ref() {
            engine.update(&next.engine)?;
        }
        if next.wireguard != before.wireguard {
            let _ = std::fs::remove_file(self.data.join("eon-tunnel.json"));
        }
        if next.eon_server != before.eon_server {
            let _ = std::fs::remove_file(self.data.join("eon-tunnel.json"));
        }
        // Reconnect when how the computer is connected changed.
        let reconnect = next.mode != before.mode
            || (next.mode == Mode::Native && next.native_preset != before.native_preset)
            || (next.mode.tunnels()
                && (next.exclude != before.exclude
                    || next.wireguard != before.wireguard
                    || next.eon_server != before.eon_server
                    || next.warp_license != before.warp_license));
        if before.on && reconnect {
            let _ = self.set_on(true);
        }
        if next
            .engine
            .lists
            .iter()
            .any(|l| !before.engine.lists.contains(l))
        {
            self.refresh_lists_soon();
        }
        Ok(self.state())
    }

    /// Fetches the lists that need it on a thread of its own: a list is a
    /// few megabytes, and the switch must not wait for it.
    fn refresh_lists_soon(self: &Arc<Self>) {
        let core = Arc::clone(self);
        std::thread::spawn(move || {
            let _ = core.fetch_lists(false);
        });
    }

    /// Downloads the lists without holding the engine (a download takes
    /// seconds; the window and the resolver must not wait), then has the
    /// running engine read them.
    fn fetch_lists(&self, force: bool) -> Vec<(List, Result<usize, String>)> {
        let settings = self.settings().engine;
        let data = self.data.clone();
        let wanted = settings.lists.clone();
        let results =
            block(async move { Ok(eon_dns_engine::lists::refresh(&data, &wanted, force).await) })
                .unwrap_or_default();
        // The settings as they are now: the person may have changed them
        // while the download ran (switching the log on, say).
        let current = self.settings().engine;
        if let Some(e) = lock(&self.engine).as_ref() {
            let _ = e.update(&current);
        }
        results
    }

    /// A text a person can send to someone helping them, like `warp-cli debug`.
    fn diagnostics(&self) -> Value {
        let s = self.settings();
        let mut lines = vec![
            format!("EON DNS {}", env!("CARGO_PKG_VERSION")),
            format!("mode: {:?}, on: {}", s.mode, s.on),
            format!("service: {}", self.system_allowed),
            format!(
                "resolver running: {:?}",
                lock(&self.engine).as_ref().map(|e| e.port)
            ),
            format!(
                "in charge: {:?}",
                system::in_charge(&self.data).map(|p| p.mode)
            ),
            format!("problem: {:?}", lock(&self.problem)),
            format!(
                "upstreams: {:?}, transport: {:?}, dnssec here: {}",
                s.engine.upstreams, s.engine.transport, s.engine.validate
            ),
            format!(
                "lists: {:?}, rules: {} allow, {} block, exclude: {:?}",
                s.engine.lists,
                s.engine.allow.len(),
                s.engine.block.len(),
                s.exclude
            ),
        ];
        #[cfg(windows)]
        if let Some(t) = lock(&self.tunnel).as_ref() {
            lines.push(format!(
                "tunnel: {} via {} as {:?}, {:?}",
                t.config.source,
                t.config.endpoint,
                t.config.addresses,
                t.stats()
            ));
        }
        if let Some(e) = lock(&self.engine).as_ref() {
            let v = e.stats();
            lines.push(format!(
                "lookups: {}, blocked: {}, failed: {}, median: {:?} ms",
                v.lookups, v.blocked, v.failed, v.median_ms
            ));
        }
        json!(lines.join("\n"))
    }
}

/// The data folder: the service's is machine-wide, the window's own per person.
pub fn machine_data() -> PathBuf {
    if let Some(d) = std::env::var_os("EON_DNS_DATA") {
        return PathBuf::from(d);
    }
    std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
        .join("EON")
        .join("DNS")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A settings file from v0.0.0/v0.0.1 (no version, "local" mode, DNSSEC
    /// on the device) arrives as DNS-only with DNSSEC on the device off.
    #[test]
    fn old_settings_are_brought_forward() {
        let dir = std::env::temp_dir().join(format!("eon-dns-core-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("settings.json"),
            r#"{"engine":{"upstreams":[{"kind":"preset","id":"cloudflare"}],"transport":"https","validate":true,"lists":[],"allow":[],"block":[],"log":false,"cache":4096,"race":2},"on":true,"mode":"local","native_preset":"cloudflare","language":"","close_to_tray":true}"#,
        )
        .unwrap();
        let s = AppSettings::load(&dir);
        assert_eq!(s.mode, Mode::Dns);
        assert!(!s.engine.validate);
        assert_eq!(s.version, SETTINGS_VERSION);
        assert!(s.auto_connect);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
