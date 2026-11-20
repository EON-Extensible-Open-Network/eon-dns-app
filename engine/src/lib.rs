// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! The EON DNS engine (plan madde 47): a local resolver that sends every
//! lookup out encrypted to the resolvers the person chose, checks DNSSEC on
//! the device when asked, blocks what the lists that are on and the
//! person's own rules say, and counts what it did. No GUI dependency.
//!
//! Nothing here reports anywhere (madde 36). The log is in memory and off by
//! default.

#![forbid(unsafe_code)]

pub mod bench;
pub mod filter;
pub mod lists;
pub mod server;
pub mod stats;
pub mod system;
pub mod upstream;

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

use crate::filter::{Filter, List};
use crate::stats::Stats;
use crate::upstream::{Transport, Tuning, Upstream};

/// What the person chose. Saved by the application; the engine only reads it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub upstreams: Vec<Upstream>,
    pub transport: Transport,
    /// Check DNSSEC on this device.
    pub validate: bool,
    /// The lists that are on.
    pub lists: Vec<List>,
    pub allow: Vec<String>,
    pub block: Vec<String>,
    /// Keep the last lookups in memory for the window to show.
    pub log: bool,
    /// Answers kept in the cache.
    pub cache: u64,
    /// How many upstreams are asked at once.
    pub race: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            upstreams: vec![
                Upstream::Preset {
                    id: "cloudflare".into(),
                },
                Upstream::Preset { id: "quad9".into() },
            ],
            transport: Transport::Https,
            validate: true,
            lists: vec![List::Threats],
            allow: Vec::new(),
            block: Vec::new(),
            log: false,
            cache: 4096,
            race: 2,
        }
    }
}

/// What the engine shares between its listeners.
pub struct Shared {
    pub resolver: RwLock<TokioResolver>,
    pub filter: RwLock<Filter>,
    pub stats: Stats,
    pub data: PathBuf,
}

/// A running local resolver.
pub struct Engine {
    runtime: tokio::runtime::Runtime,
    shared: Arc<Shared>,
    tasks: Vec<JoinHandle<()>>,
    /// Where it answers.
    pub port: u16,
}

fn build_filter(data: &Path, settings: &Settings) -> Filter {
    let mut filter = Filter::default();
    for list in &settings.lists {
        filter.set_list(*list, Some(lists::load(data, *list).unwrap_or_default()));
    }
    filter.set_rules(&settings.allow, &settings.block);
    filter
}

fn tuning(settings: &Settings) -> Tuning {
    Tuning {
        validate: settings.validate,
        cache: settings.cache,
        race: settings.race,
    }
}

impl Engine {
    /// Starts answering on `127.0.0.1` (and `::1` where the system has it) at
    /// `port`, with `data` holding the downloaded lists.
    pub fn start(settings: &Settings, data: &Path, port: u16) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("eon-dns")
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let resolver = {
            let _guard = runtime.enter();
            upstream::resolver(&settings.upstreams, settings.transport, &tuning(settings))?
        };
        let stats = Stats::new();
        stats.set_logging(settings.log);
        let shared = Arc::new(Shared {
            resolver: RwLock::new(resolver),
            filter: RwLock::new(build_filter(data, settings)),
            stats,
            data: data.to_path_buf(),
        });
        let mut tasks = Vec::new();
        let mut bound = 0;
        let mut first_error = None;
        for (i, addr) in server::addresses(port).into_iter().enumerate() {
            let sockets = runtime.block_on(async {
                Ok::<_, std::io::Error>((
                    UdpSocket::bind(addr).await?,
                    TcpListener::bind(addr).await?,
                ))
            });
            match sockets {
                Ok((udp, tcp)) => {
                    tasks.push(runtime.spawn(server::serve_udp(Arc::clone(&shared), udp)));
                    tasks.push(runtime.spawn(server::serve_tcp(Arc::clone(&shared), tcp)));
                    bound += 1;
                }
                // IPv4 loopback is required; IPv6 loopback is welcome.
                Err(e) if i == 0 => first_error = Some(e.to_string()),
                Err(_) => {}
            }
        }
        if bound == 0 || first_error.is_some() {
            return Err(first_error.unwrap_or_else(|| "nothing to listen on".into()));
        }
        Ok(Self {
            runtime,
            shared,
            tasks,
            port,
        })
    }

    /// Applies new settings to the running resolver, without a restart.
    pub fn update(&self, settings: &Settings) -> Result<(), String> {
        let resolver = {
            let _guard = self.runtime.enter();
            upstream::resolver(&settings.upstreams, settings.transport, &tuning(settings))?
        };
        if let Ok(mut r) = self.shared.resolver.write() {
            *r = resolver;
        }
        if let Ok(mut f) = self.shared.filter.write() {
            *f = build_filter(&self.shared.data, settings);
        }
        self.shared.stats.set_logging(settings.log);
        Ok(())
    }

    /// Fetches the lists that are on and older than a day (or all of them
    /// with `force`), then applies them. A list that fails keeps its last copy.
    pub fn refresh_lists(
        &self,
        settings: &Settings,
        force: bool,
    ) -> Vec<(List, Result<usize, String>)> {
        let data = self.shared.data.clone();
        let wanted = settings.lists.clone();
        let results = self
            .runtime
            .block_on(async move { lists::refresh(&data, &wanted, force).await });
        if let Ok(mut f) = self.shared.filter.write() {
            *f = build_filter(&self.shared.data, settings);
        }
        results
    }

    #[must_use]
    pub fn stats(&self) -> stats::StatsView {
        self.shared.stats.view()
    }

    #[must_use]
    pub fn log(&self) -> Vec<stats::LogEntry> {
        self.shared.stats.log()
    }

    pub fn clear_log(&self) {
        self.shared.stats.clear_log();
    }

    /// Why `name` would be answered the way it is.
    #[must_use]
    pub fn explain(&self, name: &str) -> filter::Verdict {
        self.shared
            .filter
            .read()
            .map_or(filter::Verdict::Pass, |f| f.check(name))
    }

    /// How many names each list that is on holds.
    #[must_use]
    pub fn list_sizes(&self) -> Vec<(List, usize)> {
        self.shared
            .filter
            .read()
            .map(|f| f.sizes().into_iter().collect())
            .unwrap_or_default()
    }

    /// Times each candidate from this connection (see [`bench`]).
    pub fn benchmark(&self, candidates: &[Upstream], transport: Transport) -> Vec<bench::Score> {
        self.runtime
            .block_on(bench::run(candidates.to_vec(), transport))
    }

    /// Stops listening. The system's DNS settings are the application's to restore.
    pub fn stop(self) {
        for t in &self.tasks {
            t.abort();
        }
        self.runtime.shutdown_background();
    }
}
