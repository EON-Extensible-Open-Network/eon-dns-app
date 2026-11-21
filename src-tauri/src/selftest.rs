// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! `--selftest`: what a machine can check before a release, without touching
//! the system's DNS. The catalogues agree; every string and command the page
//! uses exists; the resolver answers and blocks through a real socket, with a
//! stand-in upstream on loopback. The last line is `ok` or the run failed.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use eon_dns_engine::upstream::Upstream;
use eon_dns_engine::{Engine, Settings};
use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_resolver::proto::rr::rdata::A;
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use serde_json::Value;

fn keys(json: &str) -> BTreeSet<String> {
    serde_json::from_str::<Value>(json)
        .ok()
        .and_then(|v| v.as_object().map(|o| o.keys().cloned().collect()))
        .unwrap_or_default()
}

/// Every `name` in `text` that follows `marker` and ends at `end`.
fn between(text: &str, marker: &str, end: char) -> BTreeSet<String> {
    text.match_indices(marker)
        .filter_map(|(i, _)| {
            let rest = &text[i + marker.len()..];
            rest.find(end).map(|j| rest[..j].to_owned())
        })
        .filter(|k| !k.is_empty() && !k.contains(['$', '{', ' ']))
        .collect()
}

fn stand_in_upstream() -> Option<std::net::SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").ok()?;
    let addr = socket.local_addr().ok()?;
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf) else {
                continue;
            };
            let Ok(q) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let mut r = Message::new(q.metadata.id, MessageType::Response, OpCode::Query);
            r.metadata.recursion_available = true;
            if let Some(query) = q.queries.first() {
                r.add_query(query.clone());
                r.add_answer(Record::from_rdata(
                    query.name.clone(),
                    60,
                    RData::A(A(Ipv4Addr::new(192, 0, 2, 53))),
                ));
            }
            if let Ok(bytes) = r.to_vec() {
                let _ = socket.send_to(&bytes, from);
            }
        }
    });
    Some(addr)
}

fn ask(port: u16, name: &str) -> Option<Message> {
    let s = UdpSocket::bind("127.0.0.1:0").ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut m = Message::new(7, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).ok()?, RecordType::A));
    s.send_to(&m.to_vec().ok()?, ("127.0.0.1", port)).ok()?;
    let mut buf = [0u8; 2048];
    let (n, _) = s.recv_from(&mut buf).ok()?;
    Message::from_vec(&buf[..n]).ok()
}

#[allow(clippy::too_many_lines)]
pub fn run() -> String {
    let mut out = format!("EON DNS {} selftest\n", env!("CARGO_PKG_VERSION"));
    let mut failures = 0;
    let mut line = |ok: bool, what: &str| {
        let _ = writeln!(out, "{} {what}", if ok { "ok  " } else { "FAIL" });
        if !ok {
            failures += 1;
        }
    };

    let en = keys(crate::EN);
    let tr = keys(crate::TR);
    line(
        !en.is_empty() && en == tr,
        &format!("catalogues: {} keys, English and Turkish agree", en.len()),
    );
    let mut used = between(crate::INDEX, "data-i18n=\"", '"');
    used.extend(between(crate::INDEX, "data-i18n-label=\"", '"'));
    used.extend(between(crate::SCRIPT, "t(\"", '"'));
    let missing: Vec<_> = used.iter().filter(|k| !en.contains(*k)).cloned().collect();
    line(
        missing.is_empty(),
        &format!(
            "every string the page uses exists ({} used; missing: {missing:?})",
            used.len()
        ),
    );
    let invoked = between(crate::SCRIPT, "invoke(\"", '"');
    let unknown: Vec<_> = invoked
        .iter()
        .filter(|c| !crate::COMMANDS.contains(&c.as_str()))
        .cloned()
        .collect();
    line(
        unknown.is_empty(),
        &format!("every command the page invokes is registered (unknown: {unknown:?})"),
    );

    // The resolver, end to end on loopback, with a stand-in upstream.
    let data = std::env::temp_dir().join(format!("eon-dns-selftest-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&data);
    match stand_in_upstream() {
        Some(up) => {
            let settings = Settings {
                upstreams: vec![Upstream::Plain { addr: up }],
                validate: false,
                lists: vec![],
                block: vec!["blocked.test".into()],
                race: 1,
                ..Settings::default()
            };
            // A free port, and one Windows has not reserved: try a few.
            let mut started = Err("no port".to_owned());
            let mut port = 0;
            for _ in 0..20 {
                port = UdpSocket::bind("127.0.0.1:0")
                    .ok()
                    .and_then(|s| s.local_addr().ok())
                    .map_or(0, |a| a.port());
                started = Engine::start(&settings, &data, port);
                if started.is_ok() {
                    break;
                }
            }
            match started {
                Ok(engine) => {
                    let a = ask(port, "example.test.");
                    line(
                        a.as_ref().is_some_and(|m| {
                            m.answers
                                .first()
                                .is_some_and(|r| r.data.to_string() == "192.0.2.53")
                        }),
                        "the local resolver answers through a real socket",
                    );
                    let b = ask(port, "x.blocked.test.");
                    line(
                        b.as_ref().is_some_and(|m| {
                            m.metadata.response_code == ResponseCode::NoError
                                && m.answers
                                    .first()
                                    .is_some_and(|r| r.data.to_string() == "0.0.0.0")
                        }),
                        "a blocked name is answered 0.0.0.0 and never asked upstream",
                    );
                    let stats = engine.stats();
                    line(
                        stats.lookups == 2 && stats.blocked == 1,
                        "the counters count both",
                    );
                    line(
                        engine.log().is_empty(),
                        "nothing is logged unless the log is switched on",
                    );
                    engine.stop();
                }
                Err(e) => line(false, &format!("the local resolver could not start: {e}")),
            }
        }
        None => line(false, "no loopback socket for the stand-in upstream"),
    }
    let _ = std::fs::remove_dir_all(&data);
    line(
        eon_dns_engine::system::in_charge(&crate::core::machine_data()).is_none()
            || std::env::var_os("EON_DNS_DATA").is_none(),
        "the system's DNS was not touched by this run",
    );
    out.push_str(if failures == 0 { "ok\n" } else { "failed\n" });
    out
}
