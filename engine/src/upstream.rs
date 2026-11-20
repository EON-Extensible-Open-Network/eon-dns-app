// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Where lookups go. Every preset is reached encrypted; a plain address is
//! used only when the person adds one themselves, and the window says so.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolveHosts, ResolverConfig, ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};

/// How a lookup travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// DNS over HTTPS (RFC 8484), port 443: looks like any other web traffic.
    Https,
    /// DNS over TLS (RFC 7858), port 853.
    Tls,
    /// DNS over QUIC (RFC 9250), port 853.
    Quic,
}

/// A public resolver, as its operator publishes it.
pub struct Preset {
    pub id: &'static str,
    pub name: &'static str,
    /// What it does besides resolving, in a few words (English; the window translates by id).
    pub ips: &'static [&'static str],
    pub server_name: &'static str,
    pub https_path: &'static str,
    pub transports: &'static [Transport],
}

pub const PRESETS: &[Preset] = &[
    Preset {
        id: "cloudflare",
        name: "Cloudflare",
        ips: &[
            "1.1.1.1",
            "1.0.0.1",
            "2606:4700:4700::1111",
            "2606:4700:4700::1001",
        ],
        server_name: "cloudflare-dns.com",
        https_path: "/dns-query",
        transports: &[Transport::Https, Transport::Tls],
    },
    Preset {
        id: "cloudflare-security",
        name: "Cloudflare (malware blocking)",
        ips: &[
            "1.1.1.2",
            "1.0.0.2",
            "2606:4700:4700::1112",
            "2606:4700:4700::1002",
        ],
        server_name: "security.cloudflare-dns.com",
        https_path: "/dns-query",
        transports: &[Transport::Https, Transport::Tls],
    },
    Preset {
        id: "cloudflare-family",
        name: "Cloudflare (malware and adult blocking)",
        ips: &[
            "1.1.1.3",
            "1.0.0.3",
            "2606:4700:4700::1113",
            "2606:4700:4700::1003",
        ],
        server_name: "family.cloudflare-dns.com",
        https_path: "/dns-query",
        transports: &[Transport::Https, Transport::Tls],
    },
    Preset {
        id: "quad9",
        name: "Quad9",
        ips: &["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
        server_name: "dns.quad9.net",
        https_path: "/dns-query",
        transports: &[Transport::Https, Transport::Tls],
    },
    Preset {
        id: "mullvad",
        name: "Mullvad",
        ips: &["194.242.2.2", "2a07:e340::2"],
        server_name: "dns.mullvad.net",
        https_path: "/dns-query",
        transports: &[Transport::Https, Transport::Tls],
    },
    Preset {
        id: "adguard",
        name: "AdGuard",
        ips: &[
            "94.140.14.14",
            "94.140.15.15",
            "2a10:50c0::ad1:ff",
            "2a10:50c0::ad2:ff",
        ],
        server_name: "dns.adguard-dns.com",
        https_path: "/dns-query",
        transports: &[Transport::Https, Transport::Tls, Transport::Quic],
    },
    Preset {
        id: "google",
        name: "Google",
        ips: &[
            "8.8.8.8",
            "8.8.4.4",
            "2001:4860:4860::8888",
            "2001:4860:4860::8844",
        ],
        server_name: "dns.google",
        https_path: "/dns-query",
        transports: &[Transport::Https, Transport::Tls],
    },
];

#[must_use]
pub fn preset(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.id == id)
}

/// One upstream the person chose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Upstream {
    /// A preset, by id.
    Preset { id: String },
    /// An encrypted resolver the person entered: its addresses and the name
    /// its certificate carries.
    Custom {
        ips: Vec<IpAddr>,
        server_name: String,
        #[serde(default = "default_path")]
        https_path: String,
    },
    /// Unencrypted DNS to an address and port: only when the person adds it,
    /// and for tests.
    Plain { addr: SocketAddr },
}

fn default_path() -> String {
    "/dns-query".into()
}

impl Upstream {
    /// True when lookups to it can be read on the way.
    #[must_use]
    pub fn plain(&self) -> bool {
        matches!(self, Self::Plain { .. })
    }
}

fn connection(transport: Transport, server_name: &str, path: &str) -> ConnectionConfig {
    let name: Arc<str> = Arc::from(server_name);
    match transport {
        Transport::Https => ConnectionConfig::https(name, Some(Arc::from(path))),
        Transport::Tls => ConnectionConfig::tls(name),
        Transport::Quic => ConnectionConfig::quic(name),
    }
}

/// The name servers for `upstreams`, each over `transport` where it offers
/// it, otherwise over `DoH` (which every preset offers).
#[must_use]
pub fn name_servers(upstreams: &[Upstream], transport: Transport) -> Vec<NameServerConfig> {
    let mut out = Vec::new();
    for upstream in upstreams {
        match upstream {
            Upstream::Preset { id } => {
                let Some(p) = preset(id) else { continue };
                let t = if p.transports.contains(&transport) {
                    transport
                } else {
                    Transport::Https
                };
                for ip in p.ips.iter().filter_map(|ip| ip.parse::<IpAddr>().ok()) {
                    out.push(NameServerConfig::new(
                        ip,
                        true,
                        vec![connection(t, p.server_name, p.https_path)],
                    ));
                }
            }
            Upstream::Custom {
                ips,
                server_name,
                https_path,
            } => {
                for ip in ips {
                    out.push(NameServerConfig::new(
                        *ip,
                        true,
                        vec![connection(transport, server_name, https_path)],
                    ));
                }
            }
            Upstream::Plain { addr } => {
                let mut udp = ConnectionConfig::udp();
                udp.port = addr.port();
                let mut tcp = ConnectionConfig::tcp();
                tcp.port = addr.port();
                out.push(NameServerConfig::new(addr.ip(), true, vec![udp, tcp]));
            }
        }
    }
    out
}

/// How the resolver behaves, whatever the upstreams.
pub struct Tuning {
    pub validate: bool,
    pub cache: u64,
    /// How many upstreams are asked at once; the first good answer wins.
    pub race: usize,
}

/// A resolver over `upstreams`. Hosts files are never read: this is the
/// system's resolver now, and it answers from the network.
pub fn resolver(
    upstreams: &[Upstream],
    transport: Transport,
    tuning: &Tuning,
) -> Result<TokioResolver, String> {
    let servers = name_servers(upstreams, transport);
    if servers.is_empty() {
        return Err("no upstream resolver is chosen".into());
    }
    let mut opts = ResolverOpts::default();
    opts.validate = tuning.validate;
    opts.cache_size = tuning.cache;
    opts.num_concurrent_reqs = tuning.race.max(1);
    opts.timeout = Duration::from_secs(3);
    opts.attempts = 2;
    opts.ndots = 0;
    opts.use_hosts_file = ResolveHosts::Never;
    opts.preserve_intermediates = true;
    opts.recursion_desired = true;
    let _ = ProtocolConfig::Udp; // the protocol list is built per server above
    TokioResolver::builder_with_config(
        ResolverConfig::from_name_servers(servers),
        TokioRuntimeProvider::default(),
    )
    .with_options(opts)
    .build()
    .map_err(|e| e.to_string())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn presets_are_well_formed() {
        for p in PRESETS {
            assert!(!p.ips.is_empty(), "{}", p.id);
            for ip in p.ips {
                assert!(ip.parse::<IpAddr>().is_ok(), "{} {ip}", p.id);
            }
            assert!(
                p.transports.contains(&Transport::Https),
                "{} must offer DoH",
                p.id
            );
        }
    }

    #[test]
    fn a_transport_a_preset_lacks_falls_back_to_https() {
        let servers = name_servers(
            &[Upstream::Preset {
                id: "cloudflare".into(),
            }],
            Transport::Quic,
        );
        assert_eq!(servers.len(), 4);
        assert!(servers
            .iter()
            .all(|s| matches!(s.connections[0].protocol, ProtocolConfig::Https { .. })));
        let servers = name_servers(
            &[Upstream::Preset {
                id: "adguard".into(),
            }],
            Transport::Quic,
        );
        assert!(servers
            .iter()
            .all(|s| matches!(s.connections[0].protocol, ProtocolConfig::Quic { .. })));
    }
}
