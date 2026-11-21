// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! How the window talks to the EON DNS service: one line of JSON each way,
//! over a loopback TCP port, carrying a token the service writes into its
//! data folder. Anyone who can read that folder could already change the
//! settings file; the token only keeps other machines and web pages out
//! (they cannot read it, and the port answers 127.0.0.1 only).

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::core::{Core, Request};

/// The service's port on 127.0.0.1.
pub const PORT: u16 = 47_053;
const TOKEN: &str = "control.token";

fn new_token() -> String {
    let (private, _) = eon_dns_engine::tunnel::new_keypair();
    private
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect()
}

/// Answers the window until the process ends. Each connection is one request.
pub fn serve(core: Arc<Core>) -> Result<(), String> {
    let token = new_token();
    std::fs::create_dir_all(&core.data).map_err(|e| e.to_string())?;
    std::fs::write(core.data.join(TOKEN), &token).map_err(|e| e.to_string())?;
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, PORT)))
        .map_err(|e| e.to_string())?;
    for stream in listener.incoming().flatten() {
        let core = Arc::clone(&core);
        let token = token.clone();
        std::thread::spawn(move || {
            let _ = answer(&core, &token, stream);
        });
    }
    Ok(())
}

fn answer(core: &Arc<Core>, token: &str, stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut line = String::new();
    BufReader::new(stream.try_clone()?)
        .take(1 << 20)
        .read_line(&mut line)?;
    let reply = match serde_json::from_str::<Value>(&line) {
        Ok(v) if v["token"].as_str() == Some(token) => {
            match serde_json::from_value::<Request>(v["request"].clone()) {
                Ok(request) => match core.handle(request) {
                    Ok(value) => json!({"ok": value}),
                    Err(e) => json!({"error": e}),
                },
                Err(e) => json!({"error": format!("not a request: {e}")}),
            }
        }
        _ => json!({"error": "not allowed"}),
    };
    let mut stream = stream;
    writeln!(stream, "{reply}")
}

use std::io::Read as _;

/// The window's side: one request, one answer. `None` when no service answers.
pub fn ask(data: &Path, request: &Request, wait: Duration) -> Option<Result<Value, String>> {
    let token = std::fs::read_to_string(data.join(TOKEN)).ok()?;
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, PORT)),
        Duration::from_secs(2),
    )
    .ok()?;
    stream.set_read_timeout(Some(wait)).ok()?;
    let line = json!({"token": token.trim(), "request": request});
    writeln!(stream, "{line}").ok()?;
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).ok()?;
    let v: Value = serde_json::from_str(&reply).ok()?;
    Some(match v.get("ok") {
        Some(ok) => Ok(ok.clone()),
        None => Err(v["error"]
            .as_str()
            .unwrap_or("the service did not answer")
            .to_owned()),
    })
}
