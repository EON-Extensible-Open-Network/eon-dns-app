// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! The local resolver: DNS questions in on `127.0.0.1` and `::1`, answers out.
//! A blocked name gets `0.0.0.0` or `::`, which fails at once in every
//! program; everything else is asked upstream, encrypted.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use hickory_resolver::proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_resolver::proto::rr::rdata::{A, AAAA};
use hickory_resolver::proto::rr::{RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::filter::Verdict;
use crate::stats::LogEntry;
use crate::Shared;

/// The TTL of a blocked answer: short, so lifting a block takes effect soon.
const BLOCKED_TTL: u32 = 60;
/// The UDP payload size offered with EDNS (the 2020 DNS flag day value).
const EDNS_PAYLOAD: u16 = 1232;

fn code_text(code: ResponseCode) -> String {
    match code {
        ResponseCode::NoError => "NOERROR".into(),
        ResponseCode::NXDomain => "NXDOMAIN".into(),
        ResponseCode::ServFail => "SERVFAIL".into(),
        ResponseCode::Refused => "REFUSED".into(),
        ResponseCode::FormErr => "FORMERR".into(),
        ResponseCode::NotImp => "NOTIMP".into(),
        other => format!("{other:?}").to_uppercase(),
    }
}

/// Answers one DNS message. `None` when it is not a DNS query at all.
pub async fn answer(shared: &Arc<Shared>, bytes: &[u8], udp: bool) -> Option<Vec<u8>> {
    let started = Instant::now();
    let request = Message::from_vec(bytes).ok()?;
    if request.metadata.message_type != MessageType::Query {
        return None;
    }
    let mut response = Message::new(
        request.metadata.id,
        MessageType::Response,
        request.metadata.op_code,
    );
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    let limit = request.edns.as_ref().map_or(512, |e| {
        usize::from(e.max_payload().clamp(512, EDNS_PAYLOAD))
    });
    if request.edns.is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_PAYLOAD);
        response.edns = Some(edns);
    }
    if request.metadata.op_code != OpCode::Query || request.queries.len() != 1 {
        response.metadata.response_code = if request.metadata.op_code == OpCode::Query {
            ResponseCode::FormErr
        } else {
            ResponseCode::NotImp
        };
        return response.to_vec().ok();
    }
    let query = request.queries[0].clone();
    response.add_query(query.clone());
    let name_text = query.name.to_ascii();
    let verdict = shared
        .filter
        .read()
        .map_or(Verdict::Pass, |f| f.check(&name_text));

    let mut answers_text = Vec::new();
    if verdict.blocked() {
        let rdata = match query.query_type {
            RecordType::A => Some(RData::A(A(Ipv4Addr::UNSPECIFIED))),
            RecordType::AAAA => Some(RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))),
            _ => None,
        };
        if let Some(rdata) = rdata {
            answers_text.push(rdata.to_string());
            response.add_answer(Record::from_rdata(query.name.clone(), BLOCKED_TTL, rdata));
        }
    } else {
        let resolver = shared.resolver.read().ok().map(|r| r.clone());
        let result = match resolver {
            Some(r) => Some(r.lookup(query.name.clone(), query.query_type).await),
            None => None,
        };
        match result {
            Some(Ok(lookup)) => {
                response.metadata.authentic_data = lookup.message().metadata.authentic_data;
                for record in lookup.answers() {
                    if answers_text.len() < 4 {
                        answers_text.push(record.data.to_string());
                    }
                }
                response.add_answers(lookup.answers().iter().cloned());
            }
            Some(Err(e)) if e.is_nx_domain() => {
                response.metadata.response_code = ResponseCode::NXDomain;
            }
            Some(Err(e)) if e.is_no_records_found() => {}
            _ => response.metadata.response_code = ResponseCode::ServFail,
        }
    }

    let mut bytes = response.to_vec().ok()?;
    if udp && bytes.len() > limit {
        // Too big for this datagram: say so, and the client asks over TCP.
        response.answers.clear();
        response.metadata.truncation = true;
        bytes = response.to_vec().ok()?;
    }
    shared.stats.record(LogEntry {
        at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        name: name_text.trim_end_matches('.').to_owned(),
        kind: query.query_type.to_string(),
        verdict,
        code: code_text(response.metadata.response_code),
        answers: answers_text,
        micros: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
    });
    Some(bytes)
}

/// Answers datagrams on `socket` until the task is dropped.
pub async fn serve_udp(shared: Arc<Shared>, socket: UdpSocket) {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((len, from)) = socket.recv_from(&mut buf).await else {
            continue;
        };
        let packet = buf[..len].to_vec();
        let (shared, socket) = (Arc::clone(&shared), Arc::clone(&socket));
        tokio::spawn(async move {
            if let Some(reply) = answer(&shared, &packet, true).await {
                let _ = socket.send_to(&reply, from).await;
            }
        });
    }
}

/// Answers length-prefixed messages on each TCP connection until it closes.
pub async fn serve_tcp(shared: Arc<Shared>, listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            loop {
                let Ok(len) = stream.read_u16().await else {
                    return;
                };
                let mut packet = vec![0u8; usize::from(len)];
                if stream.read_exact(&mut packet).await.is_err() {
                    return;
                }
                let Some(reply) = answer(&shared, &packet, false).await else {
                    return;
                };
                let Ok(n) = u16::try_from(reply.len()) else {
                    return;
                };
                if stream.write_u16(n).await.is_err() || stream.write_all(&reply).await.is_err() {
                    return;
                }
            }
        });
    }
}

/// The addresses the local resolver listens on for `port`.
#[must_use]
pub fn addresses(port: u16) -> [SocketAddr; 2] {
    [
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
    ]
}
