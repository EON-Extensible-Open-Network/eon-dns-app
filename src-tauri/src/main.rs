// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! EON DNS: the window and the tray (plan madde 47).
//!
//! On Windows the work is done by the EON DNS service (`--service`), which
//! has the rights changing the system needs; the window asks it over
//! `control` and is installed with it once, through one consent prompt.
//! Elsewhere, and whenever `EON_DNS_NO_SYSTEM` is set (tests), the window
//! runs the same core itself and never touches the system.
//!
//! The interface has no network and no plugin; everything it does is one of
//! the commands below.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![deny(unsafe_code)]

mod control;
mod core;
mod selftest;
#[cfg(windows)]
#[allow(unsafe_code)] // the service entry point the system calls; see service.rs
mod service;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use eon_dns_engine::system;
use eon_dns_engine::upstream::Transport;
use serde_json::{json, Value};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager};

use crate::core::{Core, Request};

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
    "warp_reset",
    "diagnostics",
];

/// Who does the work.
enum Backend {
    /// This process, never touching the system (non-Windows, tests).
    Here(Arc<Core>),
    /// The EON DNS service, over `control`.
    Service(PathBuf),
}

struct App {
    backend: Backend,
    lang: Mutex<String>,
}

type State<'a> = tauri::State<'a, Arc<App>>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The window's own data folder (embedded mode): per person.
fn user_data() -> PathBuf {
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

fn port() -> u16 {
    std::env::var("EON_DNS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(53)
}

fn uses_service() -> bool {
    cfg!(windows) && std::env::var_os("EON_DNS_NO_SYSTEM").is_none()
}

/// How long the window waits for an answer: connecting can fetch a driver
/// and register with WARP.
fn wait_for(request: &Request) -> Duration {
    match request {
        Request::Turn { .. } | Request::SaveSettings { .. } | Request::WarpReset => {
            Duration::from_secs(90)
        }
        Request::Benchmark { .. } | Request::RefreshLists => Duration::from_secs(120),
        _ => Duration::from_secs(10),
    }
}

impl App {
    fn ask(&self, request: Request) -> Result<Value, String> {
        match &self.backend {
            Backend::Here(core) => core.handle(request),
            Backend::Service(data) => {
                let wait = wait_for(&request);
                control::ask(data, &request, wait)
                    .unwrap_or_else(|| Err("problem.noservice".into()))
            }
        }
    }

    /// Installs (or updates) the service through one consent prompt, then
    /// waits for it to answer.
    fn install_service(&self) -> Result<(), String> {
        let Backend::Service(data) = &self.backend else {
            return Ok(());
        };
        match system::run_elevated(&["--install-service"]) {
            Ok(_) => {}
            Err(e) if e == "cancelled" => return Err("problem.cancelled".into()),
            Err(e) => return Err(e),
        }
        for _ in 0..60 {
            if control::ask(data, &Request::Boot, Duration::from_secs(3)).is_some() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err("problem.noservice".into())
    }

    /// Asks, installing the service first when it is missing or older than this window.
    fn ask_or_install(&self, request: Request) -> Result<Value, String> {
        if let Backend::Service(data) = &self.backend {
            let current = control::ask(data, &Request::Boot, Duration::from_secs(5))
                .and_then(Result::ok)
                .is_some_and(|b| b["version"].as_str() == Some(env!("CARGO_PKG_VERSION")));
            if !current {
                self.install_service()?;
            }
        }
        self.ask(request)
    }
}

fn text(app: &tauri::AppHandle, key: &str) -> String {
    let lang = app
        .try_state::<Arc<App>>()
        .map_or_else(|| "en".to_owned(), |s| lock(&s.lang).clone());
    let catalogue: Value =
        serde_json::from_str(if lang == "tr" { TR } else { EN }).unwrap_or(Value::Null);
    catalogue[key].as_str().unwrap_or(key).to_owned()
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

/// The settings, presets, lists and state; with no service yet, a default
/// view that says the service is still to be set up.
#[tauri::command(async)]
fn boot(state: State<'_>) -> Value {
    if let Ok(mut v) = state.ask(Request::Boot) {
        let outdated = uses_service() && v["version"].as_str() != Some(env!("CARGO_PKG_VERSION"));
        v["state"]["service_needed"] = json!(outdated);
        v
    } else {
        // Nothing answers yet: show what a fresh install would, from a
        // throwaway core that touches nothing.
        let temp = std::env::temp_dir().join("eon-dns-preview");
        let core = Arc::new(Core::new(temp, false, 0));
        let mut v = core.handle(Request::Boot).unwrap_or(Value::Null);
        v["state"]["service_needed"] = json!(true);
        v
    }
}

#[tauri::command(async)]
fn turn(app: tauri::AppHandle, state: State<'_>, on: bool) -> Value {
    let result = state.ask_or_install(Request::Turn { on });
    refresh_tray(&app);
    result.unwrap_or_else(|e| json!({"on": !on, "problem": e}))
}

#[tauri::command(async)]
fn save_settings(
    app: tauri::AppHandle,
    state: State<'_>,
    settings: Value,
) -> Result<Value, String> {
    if let Some(l) = settings["language"].as_str() {
        let lang = if l.starts_with("tr") { "tr" } else { "en" };
        lang.clone_into(&mut lock(&state.lang));
    }
    let r = state.ask_or_install(Request::SaveSettings { settings });
    refresh_tray(&app);
    r
}

#[tauri::command(async)]
fn stats(state: State<'_>) -> Value {
    state
        .ask(Request::Stats)
        .unwrap_or_else(|_| json!({"stats": null, "log": [], "lists": []}))
}

#[tauri::command(async)]
fn clear_log(state: State<'_>) {
    let _ = state.ask(Request::ClearLog);
}

#[tauri::command(async)]
fn refresh_lists(state: State<'_>) -> Value {
    state.ask(Request::RefreshLists).unwrap_or(Value::Null)
}

#[tauri::command(async)]
fn benchmark(state: State<'_>, transport: Transport) -> Value {
    match &state.backend {
        // The window can time resolvers itself; it needs no rights for that.
        Backend::Service(_) => {
            let core = Arc::new(Core::new(
                std::env::temp_dir().join("eon-dns-preview"),
                false,
                0,
            ));
            core.handle(Request::Benchmark { transport })
                .unwrap_or(Value::Null)
        }
        Backend::Here(core) => core
            .handle(Request::Benchmark { transport })
            .unwrap_or(Value::Null),
    }
}

#[tauri::command(async)]
fn explain(state: State<'_>, name: String) -> Value {
    state.ask(Request::Explain { name }).unwrap_or(Value::Null)
}

#[tauri::command(async)]
fn warp_reset(state: State<'_>) -> Value {
    state.ask(Request::WarpReset).unwrap_or(Value::Null)
}

#[tauri::command(async)]
fn diagnostics(state: State<'_>) -> Value {
    state
        .ask(Request::Diagnostics)
        .unwrap_or_else(|e| json!(format!("no service: {e}")))
}

// ---- the window and the tray ------------------------------------------------------

fn show(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn settings_flag(app: &tauri::AppHandle, key: &str, default: bool) -> bool {
    app.state::<Arc<App>>()
        .ask(Request::Boot)
        .ok()
        .and_then(|b| b["settings"][key].as_bool())
        .unwrap_or(default)
}

fn main_window(app: &tauri::AppHandle) -> tauri::Result<()> {
    #[allow(unused_mut)]
    let mut builder =
        tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::App("index.html".into()))
            .title("EON DNS")
            .inner_size(1040.0, 720.0)
            .min_inner_size(760.0, 580.0)
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
            if settings_flag(&handle, "close_to_tray", true) {
                api.prevent_close();
                if let Some(w) = handle.get_webview_window("main") {
                    let _ = w.hide();
                }
            } else {
                quit(&handle);
            }
        }
    });
    Ok(())
}

/// Leaves. With the service, protection stays as it is: the service keeps
/// it, as WARP keeps connecting with its window closed. Without it, the
/// window's own resolver stops with it.
fn quit(app: &tauri::AppHandle) {
    if let Backend::Here(core) = &app.state::<Arc<App>>().backend {
        let _ = core.set_on(false);
    }
    app.exit(0);
}

fn tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    let on = settings_flag(app, "on", false);
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
                    let on = settings_flag(&app, "on", false);
                    let state = app.state::<Arc<App>>();
                    if let Ok(v) = state.ask_or_install(Request::Turn { on: !on }) {
                        let _ = app.emit("state", v);
                    }
                    refresh_tray(&app);
                });
            }
            "quit" => quit(app),
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

/// Counters and state to the window once a second, and to the tray's tooltip.
fn ticker(app: tauri::AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(1));
        let state = app.state::<Arc<App>>();
        let Ok(v) = state.ask(Request::Stats) else {
            continue;
        };
        let on = v["state"]["on"].as_bool().unwrap_or(false);
        if let Some(tray) = app.tray_by_id("main") {
            let tip = if !on {
                format!("EON DNS\n{}", text(&app, "tray.offline"))
            } else if !v["state"]["tunnel"].is_null() {
                format!("EON DNS\n{}", text(&app, "tray.tunnel"))
            } else if v["stats"].is_null() {
                format!("EON DNS\n{}", text(&app, "tray.native"))
            } else {
                format!(
                    "EON DNS\n{} {} · {} {}",
                    v["stats"]["lookups"],
                    text(&app, "tray.lookups"),
                    v["stats"]["blocked"],
                    text(&app, "tray.blocked")
                )
            };
            let _ = tray.set_tooltip(Some(tip));
        }
        let _ = app.emit("tick", v);
    });
}

fn window() {
    let backend = if uses_service() {
        Backend::Service(core::machine_data())
    } else {
        let core = Arc::new(Core::new(user_data(), false, port()));
        Backend::Here(core)
    };
    let app_state = Arc::new(App {
        backend,
        lang: Mutex::new("en".into()),
    });
    if let Ok(b) = app_state.ask(Request::Boot) {
        let l = b["settings"]["language"].as_str().unwrap_or("");
        *lock(&app_state.lang) = if l.starts_with("tr") { "tr" } else { "en" }.into();
    }
    if let Backend::Here(core) = &app_state.backend {
        core.recover();
    }
    let built = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show(app);
        }))
        .manage(Arc::clone(&app_state))
        .setup(|app| {
            let handle = app.handle().clone();
            main_window(&handle)?;
            tray(&handle)?;
            ticker(handle);
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
            warp_reset,
            diagnostics,
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

/// `--system apply|native <preset>|restore --data <dir>`: kept for checks
/// that exercise the system step on its own (CI's Windows runner).
fn system_command(args: &[String]) -> i32 {
    let data = args
        .iter()
        .position(|a| a == "--data")
        .and_then(|i| args.get(i + 1))
        .map_or_else(core::machine_data, PathBuf::from);
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
            eprintln!("{e}");
            1
        }
    }
}

fn exit_with(result: Result<(), String>) -> ! {
    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--version" | "-V") => println!("EON DNS {}", env!("CARGO_PKG_VERSION")),
        Some("--system") => std::process::exit(system_command(&args)),
        // Like `warp-cli status`: what the service is doing, as text.
        Some("--status") => {
            match control::ask(
                &core::machine_data(),
                &Request::Diagnostics,
                Duration::from_secs(10),
            ) {
                Some(Ok(v)) => println!("{}", v.as_str().unwrap_or_default()),
                Some(Err(e)) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                None => {
                    eprintln!("the EON DNS service is not answering");
                    std::process::exit(1);
                }
            }
        }
        #[cfg(windows)]
        Some("--service") => exit_with(service::run()),
        #[cfg(windows)]
        Some("--install-service") => exit_with(service::install()),
        #[cfg(windows)]
        Some("--uninstall-service") => exit_with(service::uninstall()),
        // The core in the foreground with the system's rights (CI, diagnosis):
        // connects as the settings say and serves the window until killed.
        Some("--foreground") => {
            let core = Arc::new(Core::new(core::machine_data(), true, port()));
            core.recover();
            exit_with(control::serve(core));
        }
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
