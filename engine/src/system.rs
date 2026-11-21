// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Pointing the system's DNS at EON DNS, and putting it back.
//!
//! Before anything changes, each connected adapter's DNS servers are written
//! to `system-previous.json` in the data folder -- including whether they
//! were set by hand or came from the network (DHCP), so putting them back
//! restores the same behaviour, not just the same addresses. The file exists
//! exactly while EON DNS is in charge; finding it at start after a crash is
//! how the application knows to repair (madde 47d).
//!
//! Changing adapters needs administrator rights. The application does it by
//! running itself elevated for one command (`--system apply|native|restore`),
//! which does that one thing and exits. On Windows this uses the
//! `DnsClient` PowerShell module that ships with the system.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::upstream::Preset;

const FILE: &str = "system-previous.json";

/// One adapter's DNS settings before EON DNS changed them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Adapter {
    pub index: u32,
    pub name: String,
    /// Addresses set by hand; empty means they came from the network.
    pub static_v4: Vec<String>,
    pub static_v6: Vec<String>,
}

/// What `system-previous.json` holds.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Previous {
    /// `local` (127.0.0.1) or `native:<preset id>`.
    pub mode: String,
    pub adapters: Vec<Adapter>,
}

fn file(data: &Path) -> PathBuf {
    data.join(FILE)
}

/// Only real addresses: the registry can hand back a value padded with NUL
/// characters, and a loopback address is EON DNS's own setting, never what
/// the person had before. (v0.0.1 recorded `::1` plus NULs as "before" after
/// an earlier attempt, and then could not put anything back.)
fn clean(list: &[String]) -> Vec<String> {
    list.iter()
        .flat_map(|s| s.split(|c: char| c == '\0' || c == ',' || c.is_whitespace()))
        .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .map(|ip| ip.to_string())
        .collect()
}

impl Adapter {
    #[must_use]
    pub fn cleaned(mut self) -> Self {
        self.static_v4 = clean(&self.static_v4);
        self.static_v6 = clean(&self.static_v6);
        self.name = self.name.replace('\0', "");
        self
    }
}

/// Whether EON DNS is in charge of the system's DNS, by its own record.
#[must_use]
pub fn in_charge(data: &Path) -> Option<Previous> {
    std::fs::read_to_string(file(data))
        .ok()
        .and_then(|t| serde_json::from_str::<Previous>(&t).ok())
        .map(|mut p| {
            p.adapters = p.adapters.into_iter().map(Adapter::cleaned).collect();
            p
        })
}

fn powershell(script: &str) -> Result<String, String> {
    if !cfg!(windows) {
        return Err("changing the system's DNS is not supported on this system yet".into());
    }
    let mut cmd = Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = cmd.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// The connected adapters and their hand-set DNS servers, read from where
/// Windows keeps them (an empty value means DHCP).
const SNAPSHOT: &str = r#"
$ErrorActionPreference = 'Stop'
$list = @()
foreach ($a in Get-NetAdapter | Where-Object Status -eq 'Up') {
  $g = $a.InterfaceGuid
  $v4 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$g" -ErrorAction SilentlyContinue).NameServer
  $v6 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$g" -ErrorAction SilentlyContinue).NameServer
  $list += [pscustomobject]@{
    index = [int]$a.ifIndex; name = $a.Name;
    static_v4 = @(if ($v4) { $v4 -split '[ ,]' | Where-Object { $_ } } else { @() });
    static_v6 = @(if ($v6) { $v6 -split '[ ,]' | Where-Object { $_ } } else { @() })
  }
}
ConvertTo-Json -InputObject @($list) -Depth 3 -Compress
"#;

pub fn snapshot() -> Result<Vec<Adapter>, String> {
    let text = powershell(SNAPSHOT)?;
    let adapters: Vec<Adapter> =
        serde_json::from_str(text.trim()).map_err(|e| format!("adapter list: {e}"))?;
    Ok(adapters.into_iter().map(Adapter::cleaned).collect())
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\0', "").replace('\'', "''"))
}

/// The script that points every adapter in `adapters` at `servers`.
#[must_use]
pub fn set_script(adapters: &[Adapter], servers: &[&str]) -> String {
    let list = servers
        .iter()
        .map(|s| quote(s))
        .collect::<Vec<_>>()
        .join(",");
    // An adapter that cannot take the setting (no IPv4 on it, say) does not
    // stop the others; failing on every one of them is an error.
    let mut s = String::from("$ErrorActionPreference = 'Stop'\n$done = 0\n");
    for a in adapters {
        let _ = writeln!(
            s,
            "try {{ Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses @({list}); $done++ }} catch {{ }}",
            a.index
        );
    }
    if !adapters.is_empty() {
        s.push_str("if ($done -eq 0) { throw 'no network adapter took the setting' }\n");
    }
    s.push_str("Clear-DnsClientCache\n");
    s
}

/// The script that puts each adapter back as it was.
#[must_use]
pub fn restore_script(adapters: &[Adapter]) -> String {
    let mut s = String::from("$ErrorActionPreference = 'Continue'\n");
    for a in adapters {
        let mut servers: Vec<&String> = a.static_v4.iter().collect();
        servers.extend(a.static_v6.iter());
        if servers.is_empty() {
            let _ = writeln!(
                s,
                "Set-DnsClientServerAddress -InterfaceIndex {} -ResetServerAddresses\n",
                a.index
            );
        } else {
            let list = servers
                .iter()
                .map(|x| quote(x))
                .collect::<Vec<_>>()
                .join(",");
            let _ = writeln!(
                s,
                "Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses @({list})\n",
                a.index
            );
        }
    }
    s.push_str("Clear-DnsClientCache\n");
    s
}

/// The script that registers a preset's `DoH` template with Windows, so the
/// system's own resolver encrypts lookups to its addresses.
#[must_use]
pub fn doh_script(preset: &Preset) -> String {
    let template = format!("https://{}{}", preset.server_name, preset.https_path);
    let mut s = String::from("$ErrorActionPreference = 'Stop'\n");
    for ip in preset.ips {
        let _ = writeln!(
            s,
            "if (Get-DnsClientDohServerAddress -ServerAddress {ip} -ErrorAction SilentlyContinue) {{ Set-DnsClientDohServerAddress -ServerAddress {ip} -DohTemplate {t} -AllowFallbackToUdp $false -AutoUpgrade $true }} else {{ Add-DnsClientDohServerAddress -ServerAddress {ip} -DohTemplate {t} -AllowFallbackToUdp $false -AutoUpgrade $true }}\n",
            ip = quote(ip),
            t = quote(&template)
        );
    }
    s
}

fn save(data: &Path, previous: &Previous) -> Result<(), String> {
    std::fs::create_dir_all(data).map_err(|e| e.to_string())?;
    let text = serde_json::to_string_pretty(previous).map_err(|e| e.to_string())?;
    std::fs::write(file(data), text).map_err(|e| e.to_string())
}

/// Records the adapters as they are, unless a record already exists: a
/// second apply must not overwrite the real "before" with our own settings.
fn remember(data: &Path, mode: &str) -> Result<Vec<Adapter>, String> {
    if let Some(mut previous) = in_charge(data) {
        mode.clone_into(&mut previous.mode);
        save(data, &previous)?;
        return Ok(previous.adapters);
    }
    let adapters = snapshot()?;
    save(
        data,
        &Previous {
            mode: mode.to_owned(),
            adapters: adapters.clone(),
        },
    )?;
    Ok(adapters)
}

/// Points the system at the local resolver. Needs administrator rights.
pub fn apply_local(data: &Path) -> Result<(), String> {
    let adapters = remember(data, "local")?;
    powershell(&set_script(&adapters, &["127.0.0.1", "::1"])).map(|_| ())
}

/// Hands encryption to Windows itself, with `preset`'s `DoH` template.
pub fn apply_native(data: &Path, preset: &Preset) -> Result<(), String> {
    let adapters = remember(data, &format!("native:{}", preset.id))?;
    powershell(&doh_script(preset))?;
    powershell(&set_script(&adapters, preset.ips)).map(|_| ())
}

/// Puts every adapter back as it was and forgets the record.
pub fn restore(data: &Path) -> Result<(), String> {
    let Some(previous) = in_charge(data) else {
        return Ok(());
    };
    powershell(&restore_script(&previous.adapters))?;
    std::fs::remove_file(file(data)).map_err(|e| e.to_string())
}

/// Runs this executable elevated with `args`, waiting for it, through the
/// system's own consent prompt. Answers the child's exit code.
pub fn run_elevated(args: &[&str]) -> Result<i32, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let list = args
        .iter()
        .map(|a| quote(&format!("\"{a}\"")))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "$p = Start-Process -FilePath {} -ArgumentList @({list}) -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode",
        quote(&exe.to_string_lossy())
    );
    match powershell(&script) {
        Ok(_) => Ok(0),
        Err(e) if e.contains("canceled by the user") || e.contains("iptal") => {
            Err("cancelled".into())
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn adapters() -> Vec<Adapter> {
        vec![
            Adapter {
                index: 7,
                name: "Wi-Fi".into(),
                static_v4: vec![],
                static_v6: vec![],
            },
            Adapter {
                index: 12,
                name: "Ethernet".into(),
                static_v4: vec!["192.168.1.1".into()],
                static_v6: vec![],
            },
        ]
    }

    #[test]
    fn restoring_puts_dhcp_back_as_dhcp_and_hand_set_back_as_set() {
        let s = restore_script(&adapters());
        assert!(s.contains("-InterfaceIndex 7 -ResetServerAddresses"));
        assert!(s.contains("-InterfaceIndex 12 -ServerAddresses @('192.168.1.1')"));
    }

    #[test]
    fn applying_names_every_adapter_and_quotes_safely() {
        let s = set_script(&adapters(), &["127.0.0.1", "::1"]);
        assert!(s.contains("-InterfaceIndex 7 -ServerAddresses @('127.0.0.1','::1'); $done++"));
        assert!(s.contains("throw 'no network adapter took the setting'"));
        assert!(s.contains("-InterfaceIndex 12 "));
        assert_eq!(quote("it's"), "'it''s'");
    }

    #[test]
    fn the_doh_template_is_the_presets_own() {
        let p = crate::upstream::preset("quad9").expect("preset");
        let s = doh_script(p);
        assert!(s.contains("'https://dns.quad9.net/dns-query'"));
        assert!(s.contains("-AllowFallbackToUdp $false"));
        assert_eq!(s.matches("ServerAddress '").count(), p.ips.len() * 3);
    }

    #[test]
    fn the_record_is_what_says_eon_dns_is_in_charge() {
        let dir = std::env::temp_dir().join(format!("eon-dns-system-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(in_charge(&dir).is_none());
        save(
            &dir,
            &Previous {
                mode: "local".into(),
                adapters: adapters(),
            },
        )
        .expect("save");
        assert_eq!(in_charge(&dir).expect("record").adapters, adapters());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod repair_tests {
    use super::*;

    /// The record v0.0.1 wrote on the owner's machine: `::1` padded with NUL
    /// characters as the "before" IPv6 server. It must restore to DHCP, and
    /// the hand-set IPv4 servers must come back as they were.
    #[test]
    fn a_record_with_nul_padding_and_our_own_address_restores_cleanly() {
        let text = r#"{"mode":"local","adapters":[{"index":19,"name":"Ethernet","static_v4":["1.1.1.1","8.8.8.8"],"static_v6":["::1\u0000\u0000\u0000\u0000"]},{"index":11,"name":"Ethernet 4","static_v4":[],"static_v6":[]}]}"#;
        let dir = std::env::temp_dir().join(format!("eon-dns-repair-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join(FILE), text).expect("write");
        let previous = in_charge(&dir).expect("record");
        assert_eq!(previous.adapters[0].static_v4, ["1.1.1.1", "8.8.8.8"]);
        assert!(previous.adapters[0].static_v6.is_empty());
        let script = restore_script(&previous.adapters);
        assert!(!script.contains('\0'));
        assert!(script.contains("-InterfaceIndex 19 -ServerAddresses @('1.1.1.1','8.8.8.8')"));
        assert!(script.contains("-InterfaceIndex 11 -ResetServerAddresses"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
