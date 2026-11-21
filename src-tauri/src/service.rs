// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! The EON DNS service: the part with the rights to change the system, as
//! the WARP client has `warp-svc`. Installed once (one consent prompt); from
//! then on the switch, a change of mode and reconnecting need no prompt.
//!
//! It copies the program to `Program Files\EON\DNS`, so updating or moving
//! the downloaded file does not break it, and keeps its data in
//! `ProgramData\EON\DNS`. When Windows stops it (shutdown included) it puts
//! the computer's own DNS back first, and connects again when it starts.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::core::{machine_data, Core};

pub const NAME: &str = "EONDNS";

fn status(state: ServiceState, accept: ServiceControlAccept) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(20),
        process_id: None,
    }
}

define_windows_service!(ffi_service_main, service_main);

/// Called by the service control manager.
pub fn run() -> Result<(), String> {
    service_dispatcher::start(NAME, ffi_service_main).map_err(|e| e.to_string())
}

fn service_main(_args: Vec<OsString>) {
    let (stop_tx, stop_rx) = mpsc::channel();
    let handler = move |event| -> ServiceControlHandlerResult {
        match event {
            ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let Ok(handle) = service_control_handler::register(NAME, handler) else {
        return;
    };
    let _ = handle.set_service_status(status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
    ));
    let core = Arc::new(Core::new(machine_data(), true, 53));
    core.recover();
    {
        let core = Arc::clone(&core);
        std::thread::spawn(move || {
            let _ = crate::control::serve(core);
        });
    }
    {
        // The lists stay fresh while the service runs (each is fetched when a day old).
        let core = Arc::clone(&core);
        std::thread::spawn(move || loop {
            let _ = core.handle(crate::core::Request::RefreshLists);
            std::thread::sleep(Duration::from_hours(6));
        });
    }
    {
        // Adapters that come up later (Wi-Fi joining, a cable) are covered too.
        let core = Arc::clone(&core);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(20));
            core.keep_applied();
        });
    }
    let _ = handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    ));
    let _ = stop_rx.recv();
    let _ = handle.set_service_status(status(
        ServiceState::StopPending,
        ServiceControlAccept::empty(),
    ));
    core.shutdown();
    let _ = handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()));
}

fn program_dir() -> PathBuf {
    std::env::var_os("ProgramFiles")
        .map_or_else(|| PathBuf::from(r"C:\Program Files"), PathBuf::from)
        .join("EON")
        .join("DNS")
}

fn sc(args: &[&str]) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    let out = Command::new("sc.exe")
        .args(args)
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(text)
    } else {
        Err(text.trim().to_owned())
    }
}

/// Whether the service is installed, from the service control manager.
pub fn installed() -> bool {
    sc(&["query", NAME]).is_ok()
}

/// `--install-service`, run elevated: copy the program, register the
/// service (automatic start, restarted if it fails), start it.
pub fn install() -> Result<(), String> {
    let dir = program_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let target = dir.join("eon-dns.exe");
    stop_and_wait()?;
    // Before the service, the window kept its settings and the record of
    // the computer's own DNS in the person's folder (v0.0.0, v0.0.1). The
    // service reads ProgramData, so both move there once, or the record that
    // puts the computer back would be left behind.
    let machine = machine_data();
    let _ = std::fs::create_dir_all(&machine);
    if let Some(local) =
        std::env::var_os("LOCALAPPDATA").map(|l| PathBuf::from(l).join("EON").join("DNS"))
    {
        for name in ["system-previous.json", "settings.json"] {
            let (from, to) = (local.join(name), machine.join(name));
            if from.is_file()
                && !to.exists()
                && std::fs::copy(&from, &to).is_ok()
                && name == "system-previous.json"
            {
                let _ = std::fs::remove_file(&from);
            }
        }
    }
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    if me != target {
        std::fs::copy(&me, &target).map_err(|e| format!("copying the program: {e}"))?;
    }
    let bin = format!("\"{}\" --service", target.display());
    if installed() {
        sc(&["config", NAME, "binPath=", &bin, "start=", "auto"])?;
    } else {
        sc(&[
            "create",
            NAME,
            "binPath=",
            &bin,
            "start=",
            "auto",
            "DisplayName=",
            "EON DNS",
        ])?;
    }
    let _ = sc(&[
        "description",
        NAME,
        "Encrypted DNS, filtering and the tunnel for EON DNS.",
    ]);
    let _ = sc(&[
        "failure",
        NAME,
        "reset=",
        "86400",
        "actions=",
        "restart/2000/restart/5000/restart/15000",
    ]);
    sc(&["start", NAME]).map(|_| ())
}

/// `--uninstall-service`, run elevated: stop it (which puts the computer's
/// DNS back) and remove it.
pub fn uninstall() -> Result<(), String> {
    stop_and_wait()?;
    sc(&["delete", NAME]).map(|_| ())
}

/// Stops the service and waits until it has: stopping puts the computer's
/// DNS back, which takes a few seconds, and nothing may happen before that
/// is done (deleting, replacing the program).
fn stop_and_wait() -> Result<(), String> {
    if !installed() {
        return Ok(());
    }
    let _ = sc(&["stop", NAME]);
    for _ in 0..120 {
        if sc(&["query", NAME]).is_ok_and(|t| t.contains("STOPPED")) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err("the EON DNS service did not stop".into())
}
