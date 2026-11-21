// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! The tunnel on Windows: WireGuard's own signed kernel driver
//! (`wireguard-nt`) carries the packets; this module gives it a key, a peer
//! and an adapter, then routes the computer's traffic into it.
//!
//! **Routing without a loop.** Two halves, `0.0.0.0/1` and `128.0.0.0/1`
//! (`::/1`, `8000::/1` for IPv6), go into the tunnel. They are more specific
//! than the default route, so they win, while the network's own default
//! route stays as it was. The tunnel's endpoint, and anything the person
//! excludes, gets a `/32` route through that original gateway. Every route is
//! in the *active* store only, so a restart forgets them; the adapter, and
//! the routes on it, vanish when the service closes it.
//!
//! **The driver.** `wireguard.dll` is fetched once from WireGuard's own
//! download site and kept only if both the archive and the DLL match the
//! SHA-256 below: WireGuard LLC's signed 1.1 release, checked when this was
//! written (Authenticode: "WireGuard LLC").

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use super::TunnelConfig;

const ZIP_URL: &str = "https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip";
const ZIP_SHA256: &str = "dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace";
const DLL_SHA256: &str = "b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3";
/// The adapter's name, and a fixed identity so Windows does not collect a
/// new network profile ("EON DNS 2", "EON DNS 3"...) at every connection.
const NAME: &str = "EON DNS";
const GUID: u128 = 0x5e0d_45f1_b6a3_4c2e_9d1a_e0d5_c0ff_ee47;

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The driver, fetched and checked the first time.
pub async fn ensure_driver(tools: &Path) -> Result<PathBuf, String> {
    let dll = tools.join("wireguard.dll");
    if std::fs::read(&dll).is_ok_and(|b| sha256_hex(&b) == DLL_SHA256) {
        return Ok(dll);
    }
    std::fs::create_dir_all(tools).map_err(|e| e.to_string())?;
    let zip = reqwest::get(ZIP_URL)
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| format!("WireGuard driver: {}", e.without_url()))?
        .bytes()
        .await
        .map_err(|e| e.to_string())?;
    if sha256_hex(&zip) != ZIP_SHA256 {
        return Err("the WireGuard driver download did not match its checksum".into());
    }
    let work = tools.join("wireguard-nt-work");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let archive = work.join("wireguard-nt.zip");
    std::fs::write(&archive, &zip).map_err(|e| e.to_string())?;
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    };
    let inner = format!("wireguard-nt/bin/{arch}/wireguard.dll");
    let status = Command::new("tar")
        .arg("-xf")
        .arg(&archive)
        .arg("-C")
        .arg(&work)
        .arg(&inner)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("could not unpack the WireGuard driver".into());
    }
    let unpacked = work.join(&inner);
    let bytes = std::fs::read(&unpacked).map_err(|e| e.to_string())?;
    if arch == "amd64" && sha256_hex(&bytes) != DLL_SHA256 {
        return Err("the WireGuard driver did not match its checksum".into());
    }
    std::fs::rename(&unpacked, &dll).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&work);
    Ok(dll)
}

#[allow(unsafe_code)]
fn load(dll: &Path) -> Result<wireguard_nt::Wireguard, String> {
    // SAFETY: loading a DLL runs its code. This one was checked against the
    // SHA-256 of WireGuard LLC's signed release in `ensure_driver`, and lives
    // in the service's own data folder, which only administrators can write.
    unsafe { wireguard_nt::load_from_path(dll) }.map_err(|e| format!("WireGuard driver: {e}"))
}

fn powershell(script: &str) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// A tunnel that is up. Dropping it does not tear it down: call [`Tunnel::down`].
pub struct Tunnel {
    _driver: wireguard_nt::Wireguard,
    adapter: wireguard_nt::Adapter,
    /// Routes added through the physical gateway, to take away again.
    bypass: Vec<String>,
    pub index: u32,
    pub config: TunnelConfig,
}

/// How the tunnel is doing, for the window.
#[derive(Clone, Debug, serde::Serialize)]
pub struct TunnelStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Seconds since the last handshake; `None` before the first.
    pub handshake_age: Option<u64>,
}

/// The script that gives the adapter its addresses and routes the computer
/// into it; `bypass` are destinations that keep using the physical network.
#[must_use]
pub fn route_script(config: &TunnelConfig, bypass: &[String]) -> String {
    let mut s = String::from("$ErrorActionPreference = 'Stop'\n");
    let _ = write!(s, "$i = (Get-NetAdapter -Name '{NAME}').ifIndex\n");
    s.push_str(
        "$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.InterfaceIndex -ne $i } | Sort-Object { $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).InterfaceMetric } | Select-Object -First 1\n",
    );
    s.push_str("if (-not $r) { throw 'there is no network to reach the tunnel through' }\n");
    for b in bypass {
        let _ = write!(
            s,
            "New-NetRoute -DestinationPrefix '{b}' -InterfaceIndex $r.InterfaceIndex -NextHop $r.NextHop -RouteMetric 0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null\n"
        );
    }
    let mut v6 = false;
    for a in &config.addresses {
        let (ip, prefix) = a.split_once('/').unwrap_or((a, "32"));
        let family = if ip.contains(':') {
            v6 = true;
            "IPv6"
        } else {
            "IPv4"
        };
        let _ = write!(
            s,
            "Get-NetIPAddress -InterfaceIndex $i -AddressFamily {family} -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue\nNew-NetIPAddress -InterfaceIndex $i -IPAddress '{ip}' -PrefixLength {prefix} -PolicyStore ActiveStore | Out-Null\n"
        );
    }
    let _ = write!(
            s,
        "Set-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4 -NlMtuBytes {} -InterfaceMetric 1\n",
        config.mtu
    );
    for half in ["0.0.0.0/1", "128.0.0.0/1"] {
        let _ = write!(
            s,
            "New-NetRoute -DestinationPrefix '{half}' -InterfaceIndex $i -NextHop '0.0.0.0' -RouteMetric 0 -PolicyStore ActiveStore | Out-Null\n"
        );
    }
    if v6 {
        let _ = write!(s, "Set-NetIPInterface -InterfaceIndex $i -AddressFamily IPv6 -NlMtuBytes {} -InterfaceMetric 1\n", config.mtu);
        for half in ["::/1", "8000::/1"] {
            let _ = write!(
            s,
                "New-NetRoute -DestinationPrefix '{half}' -InterfaceIndex $i -NextHop '::' -RouteMetric 0 -PolicyStore ActiveStore | Out-Null\n"
            );
        }
    }
    s.push_str("Write-Output $i\n");
    s
}

/// The destinations that must not go through the tunnel: its own endpoint,
/// and what the person excluded (addresses or CIDR ranges, IPv4).
#[must_use]
pub fn bypass_for(config: &TunnelConfig, exclude: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    if let IpAddr::V4(v4) = config.endpoint.ip() {
        out.push(format!("{v4}/32"));
    }
    for e in exclude {
        let e = e.trim();
        let (ip, prefix) = e.split_once('/').unwrap_or((e, "32"));
        if ip.parse::<std::net::Ipv4Addr>().is_ok() && prefix.parse::<u8>().is_ok_and(|p| p <= 32) {
            out.push(format!("{ip}/{prefix}"));
        }
    }
    out.sort();
    out.dedup();
    out
}

impl Tunnel {
    /// Brings the tunnel up. Needs administrator rights (the service has them).
    pub fn up(dll: &Path, config: &TunnelConfig, exclude: &[String]) -> Result<Self, String> {
        config.check()?;
        let driver = load(dll)?;
        let adapter = wireguard_nt::Adapter::open(&driver, NAME)
            .or_else(|_| wireguard_nt::Adapter::create(&driver, NAME, NAME, Some(GUID)))
            .map_err(|e| format!("WireGuard adapter: {e}"))?;
        let allowed = vec![
            "0.0.0.0/0".parse().map_err(|_| "net")?,
            "::/0".parse().map_err(|_| "net")?,
        ];
        let interface = wireguard_nt::SetInterface {
            listen_port: None,
            public_key: None,
            private_key: Some(config.private_key_bytes()?),
            peers: vec![wireguard_nt::SetPeer {
                public_key: Some(config.peer_key_bytes()?),
                preshared_key: config
                    .preshared_key
                    .as_deref()
                    .map(super::key)
                    .transpose()?,
                keep_alive: Some(25),
                endpoint: config.endpoint,
                allowed_ips: allowed,
            }],
        };
        adapter
            .set_config(&interface)
            .map_err(|e| format!("WireGuard configuration: {e}"))?;
        adapter
            .up()
            .map_err(|e| format!("WireGuard adapter up: {e}"))?;
        let bypass = bypass_for(config, exclude);
        let index = powershell(&route_script(config, &bypass))
            .map_err(|e| format!("tunnel routes: {e}"))?
            .lines()
            .last()
            .and_then(|l| l.trim().parse().ok())
            .unwrap_or(0);
        Ok(Self {
            _driver: driver,
            adapter,
            bypass,
            index,
            config: config.clone(),
        })
    }

    #[must_use]
    pub fn stats(&self) -> TunnelStats {
        let info = self.adapter.get_config();
        let peer = info.peers.first();
        TunnelStats {
            rx_bytes: peer.map_or(0, |p| p.rx_bytes),
            tx_bytes: peer.map_or(0, |p| p.tx_bytes),
            handshake_age: peer
                .and_then(|p| p.last_handshake)
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .map(|d| d.as_secs()),
        }
    }

    /// Takes the routes away and closes the adapter, which removes it.
    pub fn down(self) {
        let mut s = String::new();
        for b in &self.bypass {
            let _ = write!(
            s,
                "Remove-NetRoute -DestinationPrefix '{b}' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue\n"
            );
        }
        if !s.is_empty() {
            let _ = powershell(&s);
        }
        let _ = self.adapter.down();
        drop(self.adapter);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::tunnel::new_keypair;

    fn config() -> TunnelConfig {
        let (private, public) = new_keypair();
        TunnelConfig {
            private_key: private,
            addresses: vec!["172.16.0.2/32".into(), "2606:4700:110::2/128".into()],
            peer_public_key: public,
            endpoint: "162.159.192.7:2408".parse().unwrap(),
            dns: vec![],
            mtu: 1280,
            preshared_key: None,
            source: "warp".into(),
        }
    }

    #[test]
    fn the_endpoint_and_exclusions_bypass_the_tunnel() {
        let b = bypass_for(
            &config(),
            &[
                "192.0.2.0/24".into(),
                "not an address".into(),
                "198.51.100.7".into(),
            ],
        );
        assert_eq!(b, ["162.159.192.7/32", "192.0.2.0/24", "198.51.100.7/32"]);
    }

    #[test]
    fn routes_are_halves_in_the_active_store() {
        let s = route_script(&config(), &bypass_for(&config(), &[]));
        for needle in [
            "'0.0.0.0/1'",
            "'128.0.0.0/1'",
            "'::/1'",
            "'8000::/1'",
            "'162.159.192.7/32'",
            "-IPAddress '172.16.0.2' -PrefixLength 32",
        ] {
            assert!(s.contains(needle), "{needle}");
        }
        assert!(
            !s.contains("'0.0.0.0/0' -InterfaceIndex $i"),
            "never replace the default route itself"
        );
        assert_eq!(
            s.matches("-PolicyStore ActiveStore").count(),
            s.matches("New-Net").count()
        );
    }
}
