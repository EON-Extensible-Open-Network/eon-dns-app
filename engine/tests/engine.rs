// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! The engine end to end on loopback: a fake upstream answers a few names,
//! the engine listens on a spare port, and a client asks it over UDP and TCP.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use eon_dns_engine::filter::{List, Verdict};
use eon_dns_engine::upstream::Upstream;
use eon_dns_engine::{Engine, Settings};
use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_resolver::proto::rr::rdata::A;
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};

/// A plain-DNS upstream on loopback: `known.test` is 192.0.2.7, every other
/// name does not exist. Counts what it was asked.
fn fake_upstream() -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = std::sync::Arc::clone(&asked);
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf) else {
                continue;
            };
            let Ok(q) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut r = Message::new(q.metadata.id, MessageType::Response, OpCode::Query);
            r.metadata.recursion_available = true;
            r.metadata.recursion_desired = q.metadata.recursion_desired;
            let query = q.queries[0].clone();
            r.add_query(query.clone());
            if query.name.to_ascii().eq_ignore_ascii_case("known.test.")
                && query.query_type == RecordType::A
            {
                r.add_answer(Record::from_rdata(
                    query.name.clone(),
                    300,
                    RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
                ));
            } else if !query.name.to_ascii().eq_ignore_ascii_case("known.test.") {
                r.metadata.response_code = ResponseCode::NXDomain;
            }
            let _ = socket.send_to(&r.to_vec().unwrap(), from);
        }
    });
    (addr, asked)
}

fn spare_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn query(name: &str, kind: RecordType) -> Vec<u8> {
    let mut m = Message::new(4242, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    m.to_vec().unwrap()
}

fn ask_udp(port: u16, name: &str, kind: RecordType) -> Message {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.send_to(&query(name, kind), ("127.0.0.1", port)).unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = s.recv_from(&mut buf).unwrap();
    Message::from_vec(&buf[..n]).unwrap()
}

fn ask_tcp(port: u16, name: &str, kind: RecordType) -> Message {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let q = query(name, kind);
    s.write_all(&u16::try_from(q.len()).unwrap().to_be_bytes())
        .unwrap();
    s.write_all(&q).unwrap();
    let mut len = [0u8; 2];
    s.read_exact(&mut len).unwrap();
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut buf).unwrap();
    Message::from_vec(&buf).unwrap()
}

fn engine(settings: &Settings, tag: &str) -> (Engine, std::path::PathBuf) {
    let data = std::env::temp_dir().join(format!("eon-dns-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(data.join("lists")).unwrap();
    std::fs::write(
        data.join("lists").join("ads.txt"),
        "# a list\nads.test\n0.0.0.0 tracker.test\n",
    )
    .unwrap();
    (Engine::start(settings, &data, spare_port()).unwrap(), data)
}

#[test]
fn answers_blocks_and_counts_over_udp_and_tcp() {
    let (up, asked) = fake_upstream();
    let settings = Settings {
        upstreams: vec![Upstream::Plain { addr: up }],
        validate: false,
        lists: vec![List::Ads],
        block: vec!["mine.test".into()],
        allow: vec!["ok.ads.test".into()],
        log: true,
        race: 1,
        ..Settings::default()
    };
    let (engine, data) = engine(&settings, "basic");
    let port = engine.port;

    let r = ask_udp(port, "known.test.", RecordType::A);
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert_eq!(r.metadata.id, 4242);
    assert_eq!(r.answers[0].data.to_string(), "192.0.2.7");
    let r = ask_tcp(port, "known.test.", RecordType::A);
    assert_eq!(
        r.answers[0].data.to_string(),
        "192.0.2.7",
        "TCP answers too"
    );

    let r = ask_udp(port, "missing.test.", RecordType::A);
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);

    let before = asked.load(std::sync::atomic::Ordering::SeqCst);
    let r = ask_udp(port, "x.ads.test.", RecordType::A);
    assert_eq!(
        r.answers[0].data.to_string(),
        "0.0.0.0",
        "a listed name fails at once"
    );
    let r = ask_udp(port, "tracker.test.", RecordType::AAAA);
    assert_eq!(r.answers[0].data.to_string(), "::");
    let r = ask_udp(port, "a.mine.test.", RecordType::A);
    assert_eq!(
        r.answers[0].data.to_string(),
        "0.0.0.0",
        "the person's own block"
    );
    assert_eq!(
        asked.load(std::sync::atomic::Ordering::SeqCst),
        before,
        "blocked names never leave the computer"
    );
    assert_eq!(
        engine.explain("ok.ads.test"),
        Verdict::Allowed("ok.ads.test".into())
    );

    let stats = engine.stats();
    assert_eq!(stats.lookups, 6);
    assert_eq!(stats.blocked, 3);
    let log = engine.log();
    assert_eq!(log.len(), 6);
    assert_eq!(log[0].name, "a.mine.test");
    assert!(matches!(log[0].verdict, Verdict::Rule(_)));

    // New settings apply live: the list off, the log off and cleared.
    let mut next = settings.clone();
    next.lists.clear();
    next.log = false;
    engine.update(&next).unwrap();
    assert!(engine.log().is_empty());
    assert_eq!(engine.explain("x.ads.test"), Verdict::Pass);
    engine.stop();
    let _ = std::fs::remove_dir_all(data);
}

#[test]
fn a_dead_upstream_is_servfail_not_silence() {
    // Nothing listens there.
    let dead: SocketAddr = format!("127.0.0.1:{}", spare_port()).parse().unwrap();
    let settings = Settings {
        upstreams: vec![Upstream::Plain { addr: dead }],
        validate: false,
        lists: vec![],
        race: 1,
        ..Settings::default()
    };
    let (engine, data) = engine(&settings, "dead");
    let r = ask_udp(engine.port, "known.test.", RecordType::A);
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(engine.stats().failed, 1);
    engine.stop();
    let _ = std::fs::remove_dir_all(data);
}

/// Real encrypted lookups to public resolvers. Run on purpose:
/// `cargo test --test engine -- --ignored`.
#[test]
#[ignore = "network: real DoH, DoT and DNSSEC lookups"]
fn real_encrypted_lookups_with_dnssec() {
    use eon_dns_engine::upstream::Transport;
    for transport in [Transport::Https, Transport::Tls] {
        let settings = Settings {
            upstreams: vec![
                Upstream::Preset {
                    id: "cloudflare".into(),
                },
                Upstream::Preset { id: "quad9".into() },
            ],
            transport,
            validate: true,
            lists: vec![],
            ..Settings::default()
        };
        let (engine, data) = engine(&settings, &format!("{transport:?}"));
        let r = ask_udp(engine.port, "wikipedia.org.", RecordType::A);
        assert_eq!(
            r.metadata.response_code,
            ResponseCode::NoError,
            "{transport:?}"
        );
        assert!(!r.answers.is_empty(), "{transport:?}");
        // A domain whose signatures are deliberately broken must not resolve.
        let r = ask_udp(engine.port, "dnssec-failed.org.", RecordType::A);
        assert_ne!(
            r.metadata.response_code,
            ResponseCode::NoError,
            "{transport:?}: a bad signature was accepted"
        );
        engine.stop();
        let _ = std::fs::remove_dir_all(data);
    }
}
