// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Cloudflare's free WARP network, registered as the 1.1.1.1 app registers a
//! device: a new WireGuard key, a `POST` to the client API, and the peer,
//! endpoint and addresses that come back. The owner chose this on 21
//! November 2026 knowing what it costs (plan madde 47): EON becomes an
//! unofficial client of Cloudflare's service, which Cloudflare may change or
//! close at any time.
//!
//! The API answers only TLS 1.2 and expects the official client's version
//! strings; both are written here, where a change will have to be made.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{new_keypair, TunnelConfig};

const API: &str = "https://api.cloudflareclient.com/v0a2483";
const CLIENT_VERSION: &str = "a-6.81-2410012252.0";

/// What EON DNS keeps about its WARP device: enough to fetch the
/// configuration again and to attach a WARP+ licence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WarpAccount {
    pub device_id: String,
    pub token: String,
    pub private_key: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub warp_plus: bool,
}

fn client() -> Result<reqwest::Client, String> {
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12])
    .map_err(|e| e.to_string())?
    .with_root_certificates(rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    })
    .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .user_agent("1.1.1.1/6.81")
        .http1_only()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())
}

fn config_from(value: &Value, private_key: &str) -> Result<TunnelConfig, String> {
    let cfg = &value["config"];
    let peer = &cfg["peers"][0];
    let text = |v: &Value| v.as_str().unwrap_or_default().to_owned();
    // `v4` is "IP:0"; the port is the one on `host`.
    let ip = text(&peer["endpoint"]["v4"]);
    let ip = ip
        .rsplit_once(':')
        .map_or(ip.as_str(), |(a, _)| a)
        .to_owned();
    let port = text(&peer["endpoint"]["host"])
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(2408);
    let endpoint = format!("{ip}:{port}")
        .parse()
        .map_err(|_| "WARP gave no usable endpoint".to_owned())?;
    let mut addresses = Vec::new();
    for (family, prefix) in [("v4", 32), ("v6", 128)] {
        let a = text(&cfg["interface"]["addresses"][family]);
        if !a.is_empty() {
            addresses.push(if a.contains('/') {
                a
            } else {
                format!("{a}/{prefix}")
            });
        }
    }
    let config = TunnelConfig {
        private_key: private_key.to_owned(),
        addresses,
        peer_public_key: text(&peer["public_key"]),
        endpoint,
        dns: vec![
            "1.1.1.1".parse().map_err(|_| "dns")?,
            "1.0.0.1".parse().map_err(|_| "dns")?,
        ],
        mtu: 1280,
        preshared_key: None,
        source: "warp".into(),
    };
    config.check()?;
    Ok(config)
}

/// Registers a new device with WARP.
pub async fn register() -> Result<(WarpAccount, TunnelConfig), String> {
    let (private_key, public_key) = new_keypair();
    let tos = chrono_now();
    let body = json!({
        "key": public_key, "install_id": "", "fcm_token": "", "tos": tos,
        "model": "PC", "locale": "en_US", "type": "Android",
    });
    let value: Value = client()?
        .post(format!("{API}/reg"))
        .header("CF-Client-Version", CLIENT_VERSION)
        .json(&body)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| format!("WARP registration: {}", e.without_url()))?
        .json()
        .await
        .map_err(|e| format!("WARP registration answer: {e}"))?;
    let account = WarpAccount {
        device_id: value["id"].as_str().unwrap_or_default().to_owned(),
        token: value["token"].as_str().unwrap_or_default().to_owned(),
        private_key: private_key.clone(),
        license: value["account"]["license"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        warp_plus: value["account"]["warp_plus"].as_bool().unwrap_or(false),
    };
    if account.device_id.is_empty() || account.token.is_empty() {
        return Err("WARP did not register this device".into());
    }
    let config = config_from(&value, &private_key)?;
    Ok((account, config))
}

/// The current configuration of a registered device.
pub async fn fetch(account: &WarpAccount) -> Result<TunnelConfig, String> {
    let value: Value = client()?
        .get(format!("{API}/reg/{}", account.device_id))
        .header("CF-Client-Version", CLIENT_VERSION)
        .bearer_auth(&account.token)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| format!("WARP configuration: {}", e.without_url()))?
        .json()
        .await
        .map_err(|e| format!("WARP configuration answer: {e}"))?;
    config_from(&value, &account.private_key)
}

/// Attaches a WARP+ licence key to the device.
pub async fn set_license(account: &WarpAccount, license: &str) -> Result<(), String> {
    client()?
        .put(format!("{API}/reg/{}/account", account.device_id))
        .header("CF-Client-Version", CLIENT_VERSION)
        .bearer_auth(&account.token)
        .json(&json!({ "license": license.trim() }))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| format!("WARP+ licence: {}", e.without_url()))?;
    Ok(())
}

/// RFC 3339 "now", which the registration asks for as the time terms were accepted.
fn chrono_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days.cast_signed() + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_registration_answer_becomes_a_config() {
        let (private, public) = new_keypair();
        let answer = json!({"config": {"interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:8a4a::1"}},
            "peers": [{"public_key": public, "endpoint": {"host": "engage.cloudflareclient.com:2408", "v4": "162.159.192.7:0", "v6": "[2606:4700:d0::a29f:c007]:0"}}]}});
        let c = config_from(&answer, &private).unwrap();
        assert_eq!(c.endpoint.to_string(), "162.159.192.7:2408");
        assert_eq!(c.addresses, ["172.16.0.2/32", "2606:4700:110:8a4a::1/128"]);
    }

    #[test]
    fn the_date_is_rfc3339() {
        let now = chrono_now();
        assert_eq!(now.len(), 24);
        assert!(now.starts_with("20") && now.ends_with('Z'));
    }

    /// Run on purpose: registers a real device with WARP.
    #[test]
    #[ignore = "network: registers a WARP device"]
    fn a_real_registration_and_fetch() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (account, config) = rt.block_on(register()).unwrap();
        assert!(config.check().is_ok());
        let again = rt.block_on(fetch(&account)).unwrap();
        assert_eq!(again.peer_public_key, config.peer_public_key);
    }
}
