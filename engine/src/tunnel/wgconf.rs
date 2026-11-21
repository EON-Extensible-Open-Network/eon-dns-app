// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! A WireGuard configuration file the person brings, in the `wg-quick`
//! format every provider exports: `[Interface]` with `PrivateKey`,
//! `Address`, `DNS`, `MTU`; one `[Peer]` with `PublicKey`, `PresharedKey`,
//! `Endpoint`. `AllowedIPs` is read but EON DNS always tunnels everything.

use std::net::{SocketAddr, ToSocketAddrs};

use super::TunnelConfig;

/// Reads a configuration. A host name in `Endpoint` is resolved here, once.
pub fn parse(text: &str) -> Result<TunnelConfig, String> {
    let mut section = String::new();
    let mut private_key = None;
    let mut addresses = Vec::new();
    let mut dns = Vec::new();
    let mut mtu = 1280;
    let mut peer_key = None;
    let mut psk = None;
    let mut endpoint = None;
    let mut peers = 0;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = line.trim_matches(['[', ']']).to_ascii_lowercase();
            if section == "peer" {
                peers += 1;
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("not a setting: {line}"));
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match (section.as_str(), k.as_str()) {
            ("interface", "privatekey") => private_key = Some(v.to_owned()),
            ("interface", "address") => addresses.extend(
                v.split(',')
                    .map(|a| a.trim().to_owned())
                    .filter(|a| !a.is_empty()),
            ),
            ("interface", "dns") => dns.extend(
                v.split(',')
                    .filter_map(|a| a.trim().parse::<std::net::IpAddr>().ok()),
            ),
            ("interface", "mtu") => mtu = v.parse().map_err(|_| "MTU is not a number")?,
            ("peer", "publickey") if peers == 1 => peer_key = Some(v.to_owned()),
            ("peer", "presharedkey") if peers == 1 => psk = Some(v.to_owned()),
            ("peer", "endpoint") if peers == 1 => endpoint = Some(v.to_owned()),
            _ => {}
        }
    }
    if peers > 1 {
        return Err("only one [Peer] is supported".into());
    }
    let endpoint_text = endpoint.ok_or("the [Peer] has no Endpoint")?;
    let endpoint: SocketAddr = match endpoint_text.parse() {
        Ok(a) => a,
        Err(_) => endpoint_text
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.find(SocketAddr::is_ipv4))
            .ok_or_else(|| format!("could not find {endpoint_text}"))?,
    };
    let config = TunnelConfig {
        private_key: private_key.ok_or("the [Interface] has no PrivateKey")?,
        addresses: addresses
            .into_iter()
            .map(|a| {
                if a.contains('/') {
                    a
                } else if a.contains(':') {
                    format!("{a}/128")
                } else {
                    format!("{a}/32")
                }
            })
            .collect(),
        peer_public_key: peer_key.ok_or("the [Peer] has no PublicKey")?,
        endpoint,
        dns,
        mtu,
        preshared_key: psk,
        source: "custom".into(),
    };
    config.check()?;
    Ok(config)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::tunnel::new_keypair;

    #[test]
    fn a_providers_file_is_read() {
        let (private, _) = new_keypair();
        let (_, peer) = new_keypair();
        let text = format!(
            "[Interface]\nPrivateKey = {private}\nAddress = 10.66.0.2/32, fd00::2\nDNS = 10.64.0.1\nMTU = 1380\n\n[Peer]\nPublicKey = {peer}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.9:51820 # home\n"
        );
        let c = parse(&text).unwrap();
        assert_eq!(c.addresses, ["10.66.0.2/32", "fd00::2/128"]);
        assert_eq!(c.endpoint.to_string(), "203.0.113.9:51820");
        assert_eq!(c.mtu, 1380);
        assert_eq!(c.dns[0].to_string(), "10.64.0.1");
        assert_eq!(c.source, "custom");
    }

    #[test]
    fn missing_parts_are_named() {
        assert!(parse("[Interface]\nAddress = 10.0.0.2\n")
            .unwrap_err()
            .contains("Endpoint"));
    }
}
