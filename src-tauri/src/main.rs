// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! EON DNS: the window and the tray over the engine (plan madde 47).
//!
//! The interface has no network and no plugin; everything it does is one of
//! the commands below. Changing the system's DNS needs administrator rights,
//! so this program runs itself elevated for that one step (`--system ...`),
//! which does it and exits.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod selftest;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use eon_dns_engine::filter::List;
use eon_dns_engine::upstream::{Transport, Upstream, PRESETS};
use eon_dns_engine::{system, Engine, Settings};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager};

pub const EN: &str = include_str!("../i18n/en.json");
pub const TR: &str = include_str!("../i18n/tr.json");
pub const INDEX: &str = include_str!("../../src/index.html");
pub const SCRIPT: &str = include_str!("../../src/app.js");

/// What the interface may invoke (`--selftest` checks this list against the page).
pub const COMMANDS: &[&str] = &[
    "strings",
    "boot",
    "turn",
    "save_settings",
    "stats",
    "clear_log",
    "refresh_lists",
    "benchmark",
    "explain",
];

/// How the system is pointed at EON DNS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum Mode {
    /// EON's own resolver on this computer: encryption, filtering, counters.
    #[default]
    Local,
    /// Windows 11's built-in encrypted DNS, to one preset. Works with EON DNS closed.
    Native,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
struct AppSettings {
    engine: Settings,
    on: bool,
    mode: Mode,
    native_preset: String,
    language: String,
    close_to_tray: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            engine: Settings::default(),
            on: false,
            mode: Mode::Local,
            native_preset: "cloudflare".into(),
            language: String::new(),
            close_to_tray: true,
        }
    }
}

impl AppSettings {
    fn load(data: &Path) -> Self {
        std::fs::read_to_string(data.join("settings.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn save(&self, data: &Path) {
        if let Ok(text) = serde_json::to_string_pretty(self) {
            let _ = std::fs::create_dir_all(data);
            let tmp = data.join("settings.json.tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(tmp, data.join("settings.json"));
            }
        }
    }
}

struct App {
    data: PathBuf,
    settings: Mutex<AppSettings>,
    engine: Mutex<Option<Engine>>,
    /// The last thing that went wrong turning protection on or off, as a key.
    problem: Mutex<Option<String>>,
    lang: Mutex<String>,
}

type State<'a> = tauri::State<'a, Arc<App>>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Where this program keeps its settings and lists: the per-user data folder.
fn data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("EON_DNS_DATA") {
        return PathBuf::from(d);
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_default();
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA")
            .map_or_else(|| home.join("AppData").join("Local"), PathBuf::from)
    } else if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map_or_else(|| home.join(".local").join("share"), PathBuf::from)
    };
    base.join("EON").join("DNS")
}

/// The port the local resolver answers on: 53, or another for tests.
fn port() -> u16 {
    std::env::var("EON_DNS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(53)
}

/// Tests set this so the system's DNS is never touched.
fn system_allowed() -> bool {
    std::env::var_os("EON_DNS_NO_SYSTEM").is_none()
}

fn text(app: &tauri::AppHandle, key: &str) -> String {
    let lang = app
        .try_state::<Arc<App>>()
        .map_or_else(|| "en".to_owned(), |s| lock(&s.lang).clone());
    let catalogue: Value =
        serde_json::from_str(if lang == "tr" { TR } else { EN }).unwrap_or(Value::Null);
    catalogue[key].as_str().unwrap_or(key).to_owned()
}

/// Runs `--system <args>` elevated and reports what the elevated run wrote.
fn elevated(data: &Path, args: &[&str]) -> Result<(), String> {
    let data_text = data.to_string_lossy().into_owned();
    let mut all: Vec<&str> = vec!["--system"];
    all.extend_from_slice(args);
    all.extend_from_slice(&["--data", &data_text]);
    let _ = std::fs::remove_file(data.join("system-error.txt"));
    match system::run_elevated(&all) {
        Ok(_) => match std::fs::read_to_string(data.join("system-error.txt")) {
            Ok(e) if !e.trim().is_empty() => Err(e),
            _ => Ok(()),
        },
        Err(e) if e == "cancelled" => Err("problem.cancelled".into()),
        Err(e) => Err(e),
    }
}

fn state_view(app: &App) -> Value {
    let s = lock(&app.settings).clone();
    let running = lock(&app.engine).as_ref().map(|e| e.port);
    json!({
        "on": s.on,
        "mode": s.mode,
        "running": running,
        "in_charge": system::in_charge(&app.data).map(|p| p.mode),
        "problem": lock(&app.problem).clone(),
        "system_allowed": system_allowed(),
    })
}

/// Starts the local resolver if it is not running.
fn start_engine(app: &App) -> Result<(), String> {
    let mut engine = lock(&app.engine);
    if engine.is_none() {
        let settings = lock(&app.settings).engine.clone();
        *engine = Some(Engine::start(&settings, &app.data, port()).map_err(|e| {
            if e.contains("10048") || e.to_lowercase().contains("in use") {
                "problem.port".to_owned()
            } else {
                e
            }
        })?);
    }
    Ok(())
}

fn stop_engine(app: &App) {
    if let Some(engine) = lock(&app.engine).take() {
        engine.stop();
    }
}

/// Fetches the lists that need it, on a thread of its own (a list is ~4 MB).
fn refresh_lists_soon(app: &Arc<App>) {
    let app = Arc::clone(app);
    std::thread::spawn(move || {
        let settings = lock(&app.settings).engine.clone();
        let engine = lock(&app.engine);
        if let Some(engine) = engine.as_ref() {
            let _ = engine.refresh_lists(&settings, false);
        }
    });
}

/// Turns protection on or off, as the switch and the tray do.
fn set_on(app: &App, on: bool) -> Result<(), String> {
    let mode = lock(&app.settings).mode;
    *lock(&app.problem) = None;
    let result = if on {
        match mode {
            Mode::Local => start_engine(app).and_then(|()| {
                if system_allowed() {
                    elevated(&app.data, &["apply"]).inspect_err(|_| stop_engine(app))
                } else {
                    Ok(())
                }
            }),
            Mode::Native => {
                let preset = lock(&app.settings).native_preset.clone();
                stop_engine(app);
                if system_allowed() {
                    elevated(&app.data, &["native", &preset])
                } else {
                    Ok(())
                }
            }
        }
    } else {
        let restored = if system_allowed() && system::in_charge(&app.data).is_some() {
            elevated(&app.data, &["restore"])
        } else {
            Ok(())
        };
        if restored.is_ok() {
            stop_engine(app);
        }
        restored
    };
    match result {
        Ok(()) => {
            let mut s = lock(&app.settings);
            s.on = on;
            s.save(&app.data);
            Ok(())
        }
        Err(e) => {
            *lock(&app.problem) = Some(e.clone());
            Err(e)
        }
    }
}

// ---- commands --------------------------------------------------------------------

#[tauri::command]
fn strings(state: State<'_>, language: String) -> Value {
    let lang = if language.starts_with("tr") {
        "tr"
    } else {
        "en"
    };
    lang.clone_into(&mut lock(&state.lang));
    serde_json::from_str(if lang == "tr" { TR } else { EN }).unwrap_or(Value::Null)
}

#[tauri::command]
fn boot(state: State<'_>) -> Value {
    let settings = lock(&state.settings).clone();
    let presets: Vec<Value> = PRESETS
        .iter()
        .map(|p| json!({"id": p.id, "name": p.name, "transports": p.transports, "ips": p.ips}))
        .collect();
    let lists: Vec<Value> = List::ALL
        .iter()
        .map(|l| {
            json!({
                "id": l,
                "updated": eon_dns_engine::lists::updated(&state.data, *l)
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs()),
                "size": eon_dns_engine::lists::load(&state.data, *l).map(|s| s.len()),
            })
        })
        .collect();
    json!({
        "settings": settings,
        "presets": presets,
        "lists": lists,
        "state": state_view(&state),
        "version": env!("CARGO_PKG_VERSION"),
    })
}

#[tauri::command(async)]
fn turn(app: tauri::AppHandle, state: State<'_>, on: bool) -> Value {
    if set_on(&state, on).is_ok() && on {
        refresh_lists_soon(&state);
    }
    refresh_tray(&app);
    state_view(&state)
}

#[tauri::command(async)]
fn save_settings(
    app: tauri::AppHandle,
    state: State<'_>,
    settings: Value,
) -> Result<Value, String> {
    let next: AppSettings = serde_json::from_value(settings).map_err(|e| e.to_string())?;
    let before = lock(&state.settings).clone();
    {
        let mut s = lock(&state.settings);
        let on = s.on;
        *s = next.clone();
        s.on = on;
        s.save(&state.data);
    }
    if let Some(engine) = lock(&state.engine).as_ref() {
        engine.update(&next.engine)?;
    }
    if next.language != before.language {
        let lang = if next.language.starts_with("tr") {
            "tr"
        } else {
            "en"
        };
        lang.clone_into(&mut lock(&state.lang));
        let _ = tray(&app);
    }
    // A change of mode, or of the Windows preset, while on: re-apply.
    let mode_changed = next.mode != before.mode
        || (next.mode == Mode::Native && next.native_preset != before.native_preset);
    if before.on && mode_changed {
        let _ = set_on(&state, true);
    }
    // Lists switched on for the first time are fetched at once.
    let fresh: Vec<List> = next
        .engine
        .lists
        .iter()
        .filter(|l| !before.engine.lists.contains(l))
        .copied()
        .collect();
    if !fresh.is_empty() {
        refresh_lists_soon(&state);
    }
    Ok(state_view(&state))
}

#[tauri::command]
fn stats(state: State<'_>) -> Value {
    let engine = lock(&state.engine);
    match engine.as_ref() {
        Some(e) => json!({"stats": e.stats(), "log": e.log(), "lists": e.list_sizes()}),
        None => json!({"stats": null, "log": [], "lists": []}),
    }
}

#[tauri::command]
fn clear_log(state: State<'_>) {
    if let Some(e) = lock(&state.engine).as_ref() {
        e.clear_log();
    }
}

#[tauri::command(async)]
fn refresh_lists(state: State<'_>) -> Value {
    let settings = lock(&state.settings).engine.clone();
    let engine = lock(&state.engine);
    let results: Vec<Value> = match engine.as_ref() {
        Some(e) => e
            .refresh_lists(&settings, true)
            .into_iter()
            .map(|(l, r)| match r {
                Ok(n) => json!({"id": l, "ok": n}),
                Err(e) => json!({"id": l, "error": e}),
            })
            .collect(),
        None => Vec::new(),
    };
    json!(results)
}

#[tauri::command(async)]
fn benchmark(transport: Transport) -> Value {
    // A runtime of its own: the timing must not share threads with anything.
    let candidates: Vec<Upstream> = PRESETS
        .iter()
        .map(|p| Upstream::Preset { id: p.id.into() })
        .collect();
    // On a thread of its own: this command already runs inside an async runtime.
    let scores = std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .map(|rt| rt.block_on(eon_dns_engine::bench::run(candidates, transport)))
            .unwrap_or_default()
    })
    .join()
    .unwrap_or_default();
    json!(scores)
}

#[tauri::command]
fn explain(state: State<'_>, name: String) -> Value {
    lock(&state.engine)
        .as_ref()
        .map_or(Value::Null, |e| json!(e.explain(&name)))
}

// ---- the window and the tray ------------------------------------------------------

fn show(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn main_window(app: &tauri::AppHandle) -> tauri::Result<()> {
    #[allow(unused_mut)]
    let mut builder =
        tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::App("index.html".into()))
            .title("EON DNS")
            .inner_size(1040.0, 700.0)
            .min_inner_size(760.0, 560.0)
            .decorations(false)
            .shadow(true);
    #[cfg(debug_assertions)]
    if let Ok(extra) = std::env::var("EON_WEBVIEW_ARGS") {
        builder = builder.additional_browser_args(&format!(
            "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection {extra}"
        ));
    }
    let window = builder.build()?;
    let handle = app.clone();
    window.on_window_event(move |event| {
        if let tauri::WindowEvent::CloseRequested { api, .. } = event {
            let state = handle.state::<Arc<App>>();
            if lock(&state.settings).close_to_tray {
                api.prevent_close();
                if let Some(w) = handle.get_webview_window("main") {
                    let _ = w.hide();
                }
            } else if !quit(&handle) {
                api.prevent_close();
            }
        }
    });
    Ok(())
}

/// Leaves, putting the system's DNS back first when the local resolver is
/// what it points at. Answers false if that could not be done (the person
/// declined the prompt): quitting then would leave the computer without DNS.
fn quit(app: &tauri::AppHandle) -> bool {
    let state = app.state::<Arc<App>>();
    let local_in_charge = system::in_charge(&state.data).is_some_and(|p| p.mode == "local");
    if local_in_charge && system_allowed() && elevated(&state.data, &["restore"]).is_err() {
        *lock(&state.problem) = Some("problem.quit".into());
        show(app);
        let _ = app.emit("state", state_view(&state));
        return false;
    }
    if local_in_charge {
        let mut s = lock(&state.settings);
        s.on = false;
        s.save(&state.data);
    }
    stop_engine(&state);
    app.exit(0);
    true
}

fn tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    let on = app.state::<Arc<App>>().settings.lock().is_ok_and(|s| s.on);
    let show_item = MenuItem::with_id(app, "show", text(app, "tray.show"), true, None::<&str>)?;
    let toggle = MenuItem::with_id(
        app,
        "toggle",
        text(app, if on { "tray.off" } else { "tray.on" }),
        true,
        None::<&str>,
    )?;
    let quit_item = MenuItem::with_id(app, "quit", text(app, "tray.quit"), true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &show_item,
            &toggle,
            &PredefinedMenuItem::separator(app)?,
            &quit_item,
        ],
    )?;
    if let Some(existing) = app.tray_by_id("main") {
        existing.set_menu(Some(menu))?;
        return Ok(());
    }
    let mut builder = TrayIconBuilder::with_id("main")
        .tooltip("EON DNS")
        .menu(&menu)
        .show_menu_on_left_click(false);
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show(app),
            "toggle" => {
                let app = app.clone();
                std::thread::spawn(move || {
                    let state = app.state::<Arc<App>>();
                    let on = lock(&state.settings).on;
                    let _ = set_on(&state, !on);
                    refresh_tray(&app);
                    let _ = app.emit("state", state_view(&state));
                });
            }
            "quit" => {
                let app = app.clone();
                std::thread::spawn(move || {
                    quit(&app);
                });
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

fn refresh_tray(app: &tauri::AppHandle) {
    let _ = tray(app);
}

/// Counters to the window once a second, and to the tray's tooltip.
fn ticker(app: tauri::AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(1));
        let state = app.state::<Arc<App>>();
        let view = lock(&state.engine).as_ref().map(Engine::stats);
        let on = lock(&state.settings).on;
        if let Some(tray) = app.tray_by_id("main") {
            let tip = match (&view, on) {
                (Some(v), true) => format!(
                    "EON DNS\n{} {} · {} {}",
                    v.lookups,
                    text(&app, "tray.lookups"),
                    v.blocked,
                    text(&app, "tray.blocked")
                ),
                (_, true) => format!("EON DNS\n{}", text(&app, "tray.native")),
                _ => format!("EON DNS\n{}", text(&app, "tray.offline")),
            };
            let _ = tray.set_tooltip(Some(tip));
        }
        if let Some(v) = view {
            let _ = app.emit("stats", v);
        }
    });
}

/// Keeps the lists fresh: at start, then every six hours (each list is
/// fetched only when a day old).
fn list_keeper(app: tauri::AppHandle) {
    std::thread::spawn(move || loop {
        {
            let state = app.state::<Arc<App>>();
            let settings = lock(&state.settings).engine.clone();
            let engine = lock(&state.engine);
            if let Some(engine) = engine.as_ref() {
                let _ = engine.refresh_lists(&settings, false);
            }
        }
        std::thread::sleep(Duration::from_hours(6));
    });
}

/// At start: if the record says EON DNS is in charge, carry on (the switch
/// was on) or put things back (it should not be). Never leaves the computer
/// pointing at a resolver that is not running (madde 47d).
fn recover(app: &App) {
    let Some(previous) = system::in_charge(&app.data) else {
        return;
    };
    let wanted = lock(&app.settings).on;
    if previous.mode == "local" {
        if wanted && start_engine(app).is_ok() {
            return;
        }
        if system_allowed() && elevated(&app.data, &["restore"]).is_err() {
            *lock(&app.problem) = Some("problem.repair".into());
        } else {
            let mut s = lock(&app.settings);
            s.on = false;
            s.save(&app.data);
        }
    }
}

fn window() {
    let data = data_dir();
    let settings = AppSettings::load(&data);
    let lang = if settings.language.starts_with("tr") {
        "tr"
    } else {
        "en"
    }
    .to_owned();
    let app_state = Arc::new(App {
        data: data.clone(),
        settings: Mutex::new(settings),
        engine: Mutex::new(None),
        problem: Mutex::new(None),
        lang: Mutex::new(lang),
    });
    recover(&app_state);
    let built = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show(app);
        }))
        .manage(Arc::clone(&app_state))
        .setup(|app| {
            let handle = app.handle().clone();
            main_window(&handle)?;
            tray(&handle)?;
            ticker(handle.clone());
            list_keeper(handle);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            strings,
            boot,
            turn,
            save_settings,
            stats,
            clear_log,
            refresh_lists,
            benchmark,
            explain,
        ])
        .build(tauri::generate_context!());
    match built {
        Ok(app) => app.run(|_, _| {}),
        Err(e) => {
            eprintln!("EON DNS could not start: {e}");
            std::process::exit(1);
        }
    }
}

/// `--system apply|native <preset>|restore --data <dir>`: the elevated step.
fn system_command(args: &[String]) -> i32 {
    let data = args
        .iter()
        .position(|a| a == "--data")
        .and_then(|i| args.get(i + 1))
        .map_or_else(data_dir, PathBuf::from);
    let result = match args.get(2).map(String::as_str) {
        Some("apply") => system::apply_local(&data),
        Some("native") => match args
            .get(3)
            .and_then(|id| eon_dns_engine::upstream::preset(id))
        {
            Some(p) => system::apply_native(&data, p),
            None => Err("unknown resolver".into()),
        },
        Some("restore") => system::restore(&data),
        _ => Err("usage: --system apply|native <preset>|restore --data <dir>".into()),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            let _ = std::fs::create_dir_all(&data);
            let _ = std::fs::write(data.join("system-error.txt"), &e);
            1
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--version" | "-V") => println!("EON DNS {}", env!("CARGO_PKG_VERSION")),
        Some("--system") => std::process::exit(system_command(&args)),
        Some("--selftest") => {
            let report = selftest::run();
            match args.get(2) {
                Some(path) => {
                    if let Err(e) = std::fs::write(path, &report) {
                        eprintln!("could not write {path}: {e}");
                        std::process::exit(2);
                    }
                }
                None => print!("{report}"),
            }
            if !report.ends_with("ok\n") {
                std::process::exit(1);
            }
        }
        _ => window(),
    }
}
