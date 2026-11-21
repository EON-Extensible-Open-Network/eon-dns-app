// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! The tunnel: all traffic, not only lookups, through WireGuard to an
//! endpoint (plan madde 47e, as the owner widened it on 21 November 2026).
//!
//! Where the tunnel ends is a *provider*. Each one produces the same
//! [`TunnelConfig`]:
//!
//! - [`warp`]: Cloudflare's free WARP network, registered the way the 1.1.1.1
//!   app registers a device.
//! - [`wgconf`]: a WireGuard configuration the person brings (their own
//!   server, a VPN provider's file).
//! - [`eon`]: an EON tunnel server. None runs yet (madde 30); the contract
//!   and the client are here so the day one does, it is a setting.
//!
//! Bringing the tunnel up is the system's business and needs administrator
//! rights: [`windows`] on Windows, run by the EON DNS service.

pub mod eon;
pub mod warp;
pub mod wgconf;
// Its scripts are built a line at a time; each `write!` ends its own line.
#[cfg(windows)]
#[allow(clippy::write_with_newline)]
pub mod windows;

use std::net::{IpAddr, SocketAddr};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Everything needed to bring a tunnel up, whichever provider made it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// This device's private key, base64.
    pub private_key: String,
    /// Addresses this device has inside the tunnel, with prefix (`172.16.0.2/32`).
    pub addresses: Vec<String>,
    pub peer_public_key: String,
    pub endpoint: SocketAddr,
    /// Resolvers inside the tunnel, used when the person has not chosen EON's resolver.
    #[serde(default)]
    pub dns: Vec<IpAddr>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub preshared_key: Option<String>,
    /// Where the configuration came from, for the window: `warp`, `custom`, `eon`.
    pub source: String,
}

fn default_mtu() -> u16 {
    1280
}

impl TunnelConfig {
    /// The private key as bytes.
    pub fn private_key_bytes(&self) -> Result<[u8; 32], String> {
        key(&self.private_key)
    }

    pub fn peer_key_bytes(&self) -> Result<[u8; 32], String> {
        key(&self.peer_public_key)
    }

    /// Checks the configuration hangs together before anything uses it.
    pub fn check(&self) -> Result<(), String> {
        self.private_key_bytes()?;
        self.peer_key_bytes()?;
        if self.addresses.is_empty() {
            return Err("the tunnel has no address".into());
        }
        for a in &self.addresses {
            let (ip, prefix) = a.split_once('/').unwrap_or((a, "32"));
            ip.parse::<IpAddr>()
                .map_err(|_| format!("not an address: {a}"))?;
            prefix
                .parse::<u8>()
                .map_err(|_| format!("not a prefix: {a}"))?;
        }
        if self.endpoint.port() == 0 {
            return Err("the endpoint has no port".into());
        }
        Ok(())
    }
}

pub fn key(text: &str) -> Result<[u8; 32], String> {
    B64.decode(text.trim())
        .ok()
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
        .ok_or_else(|| "a WireGuard key must be 32 bytes of base64".to_owned())
}

/// A new X25519 key pair for WireGuard: (private, public), base64.
#[must_use]
pub fn new_keypair() -> (String, String) {
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    (B64.encode(secret.to_bytes()), B64.encode(public.as_bytes()))
}

/// The public key that belongs to a private key.
pub fn public_of(private: &str) -> Result<String, String> {
    let secret = x25519_dalek::StaticSecret::from(key(private)?);
    Ok(B64.encode(x25519_dalek::PublicKey::from(&secret).as_bytes()))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_keypair_is_consistent() {
        let (private, public) = new_keypair();
        assert_eq!(public_of(&private).unwrap(), public);
        assert!(key("short").is_err());
    }

    #[test]
    fn a_config_is_checked() {
        let (private, public) = new_keypair();
        let good = TunnelConfig {
            private_key: private,
            addresses: vec!["172.16.0.2/32".into()],
            peer_public_key: public,
            endpoint: "162.159.192.7:2408".parse().unwrap(),
            dns: vec![],
            mtu: 1280,
            preshared_key: None,
            source: "warp".into(),
        };
        assert!(good.check().is_ok());
        let mut bad = good.clone();
        bad.addresses = vec!["nope".into()];
        assert!(bad.check().is_err());
    }
}
