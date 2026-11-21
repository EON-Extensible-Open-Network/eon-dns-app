// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! An EON tunnel server: the infrastructure for the day EON (or anyone who
//! runs the server) offers an endpoint. No server runs yet (madde 30), so
//! this is a client against a small contract, ready to be pointed at one.
//!
//! The contract, v0:
//!
//! ```text
//! POST {server}/v0/tunnel/devices      {"public_key": base64}
//!   201 {"device": id, "addresses": ["10.x/32", "fd../128"],
//!        "peer_public_key": base64, "endpoint": "host:port", "dns": ["10.x"]}
//! DELETE {server}/v0/tunnel/devices/{id}
//! ```
//!
//! The server sees the device's public key and the traffic it carries, and
//! nothing that names a person. With EON Account it will also accept an
//! assertion (madde 46e), so the server can limit devices per account
//! without learning who the account is.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use serde_json::{json, Value};

use super::{new_keypair, TunnelConfig};

/// Registers this device with an EON tunnel server and answers its config.
pub async fn register(
    server: &str,
    assertion: Option<&str>,
) -> Result<(String, TunnelConfig), String> {
    let server = server.trim().trim_end_matches('/');
    if !server.starts_with("https://") {
        return Err("a tunnel server must be https://".into());
    }
    let (private_key, public_key) = new_keypair();
    let mut body = json!({ "public_key": public_key });
    if let Some(a) = assertion {
        body["assertion"] = json!(a);
    }
    let value: Value = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?
        .post(format!("{server}/v0/tunnel/devices"))
        .json(&body)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| format!("EON tunnel server: {}", e.without_url()))?
        .json()
        .await
        .map_err(|e| format!("EON tunnel server answer: {e}"))?;
    config_from(&value, &private_key)
}

fn config_from(value: &Value, private_key: &str) -> Result<(String, TunnelConfig), String> {
    let list = |k: &str| -> Vec<String> {
        value[k]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let endpoint_text = value["endpoint"].as_str().unwrap_or_default();
    let endpoint: SocketAddr = endpoint_text
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .ok_or_else(|| "the server gave no usable endpoint".to_owned())?;
    let config = TunnelConfig {
        private_key: private_key.to_owned(),
        addresses: list("addresses"),
        peer_public_key: value["peer_public_key"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        endpoint,
        dns: list("dns").iter().filter_map(|d| d.parse().ok()).collect(),
        mtu: 1280,
        preshared_key: None,
        source: "eon".into(),
    };
    config.check()?;
    Ok((
        value["device"].as_str().unwrap_or_default().to_owned(),
        config,
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_servers_answer_becomes_a_config() {
        let (private, _) = new_keypair();
        let (_, peer) = new_keypair();
        let answer = json!({"device": "d1", "addresses": ["10.7.0.2/32"], "peer_public_key": peer, "endpoint": "198.51.100.4:51820", "dns": ["10.7.0.1"]});
        let (id, c) = config_from(&answer, &private).unwrap();
        assert_eq!(id, "d1");
        assert_eq!(c.source, "eon");
        assert_eq!(c.endpoint.to_string(), "198.51.100.4:51820");
    }
}
