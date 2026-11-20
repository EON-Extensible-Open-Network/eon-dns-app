// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Counters and the log. Both live in memory only and are gone at restart.
//! The log is off unless the person switches it on (madde 47c).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::filter::Verdict;

/// How many lookups the log keeps.
pub const LOG_SIZE: usize = 500;
/// An answer this fast came from the cache, not the network.
pub const CACHE_MICROS: u64 = 1500;
/// One bucket per minute, an hour of them, for the window's chart.
const MINUTES: usize = 60;

#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    pub at: u64,
    pub name: String,
    pub kind: String,
    pub verdict: Verdict,
    /// `NOERROR`, `NXDOMAIN`, `SERVFAIL`...
    pub code: String,
    /// The first few answers, as text.
    pub answers: Vec<String>,
    pub micros: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct StatsView {
    pub lookups: u64,
    pub blocked: u64,
    pub cached: u64,
    pub failed: u64,
    /// Median time of the last 200 lookups that went to the network.
    pub median_ms: Option<f64>,
    /// Lookups and blocks per minute, oldest first, for the last hour.
    pub minutes: Vec<(u64, u64)>,
    pub since: u64,
}

#[derive(Default)]
struct Window {
    /// (minute since epoch, lookups, blocked)
    buckets: VecDeque<(u64, u64, u64)>,
    network: VecDeque<u64>,
}

#[derive(Default)]
pub struct Stats {
    lookups: AtomicU64,
    blocked: AtomicU64,
    cached: AtomicU64,
    failed: AtomicU64,
    since: AtomicU64,
    window: Mutex<Window>,
    logging: AtomicBool,
    log: Mutex<VecDeque<LogEntry>>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Stats {
    #[must_use]
    pub fn new() -> Self {
        let s = Self::default();
        s.since.store(now(), Ordering::Relaxed);
        s
    }

    pub fn set_logging(&self, on: bool) {
        self.logging.store(on, Ordering::Relaxed);
        if !on {
            self.clear_log();
        }
    }

    pub fn clear_log(&self) {
        if let Ok(mut log) = self.log.lock() {
            log.clear();
        }
    }

    /// Records one answered lookup.
    pub fn record(&self, entry: LogEntry) {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        let blocked = entry.verdict.blocked();
        if blocked {
            self.blocked.fetch_add(1, Ordering::Relaxed);
        } else if entry.code == "SERVFAIL" {
            self.failed.fetch_add(1, Ordering::Relaxed);
        } else if entry.micros < CACHE_MICROS {
            self.cached.fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(mut w) = self.window.lock() {
            let minute = entry.at / 60;
            match w.buckets.back_mut() {
                Some(b) if b.0 == minute => {
                    b.1 += 1;
                    b.2 += u64::from(blocked);
                }
                _ => w.buckets.push_back((minute, 1, u64::from(blocked))),
            }
            while w.buckets.len() > MINUTES {
                w.buckets.pop_front();
            }
            if !blocked && entry.micros >= CACHE_MICROS && entry.code != "SERVFAIL" {
                w.network.push_back(entry.micros);
                while w.network.len() > 200 {
                    w.network.pop_front();
                }
            }
        }
        if self.logging.load(Ordering::Relaxed) {
            if let Ok(mut log) = self.log.lock() {
                log.push_front(entry);
                log.truncate(LOG_SIZE);
            }
        }
    }

    #[must_use]
    pub fn view(&self) -> StatsView {
        let (median_ms, minutes) = self.window.lock().map_or((None, Vec::new()), |w| {
            let mut times: Vec<u64> = w.network.iter().copied().collect();
            times.sort_unstable();
            #[allow(clippy::cast_precision_loss)]
            let median = times.get(times.len() / 2).map(|m| *m as f64 / 1000.0);
            let now_minute = now() / 60;
            let minutes = (0..MINUTES as u64)
                .rev()
                .map(|ago| {
                    let m = now_minute.saturating_sub(ago);
                    w.buckets
                        .iter()
                        .find(|b| b.0 == m)
                        .map_or((0, 0), |b| (b.1, b.2))
                })
                .collect();
            (median, minutes)
        });
        StatsView {
            lookups: self.lookups.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            cached: self.cached.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            median_ms,
            minutes,
            since: self.since.load(Ordering::Relaxed),
        }
    }

    #[must_use]
    pub fn log(&self) -> Vec<LogEntry> {
        self.log
            .lock()
            .map(|l| l.iter().cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn entry(verdict: Verdict, micros: u64) -> LogEntry {
        LogEntry {
            at: now(),
            name: "example.org".into(),
            kind: "A".into(),
            verdict,
            code: "NOERROR".into(),
            answers: vec![],
            micros,
        }
    }

    #[test]
    fn counters_add_up_and_the_log_is_off_until_asked() {
        let s = Stats::new();
        s.record(entry(Verdict::Pass, 20_000));
        s.record(entry(Verdict::Pass, 100));
        s.record(entry(Verdict::Listed(crate::filter::List::Ads), 50));
        let v = s.view();
        assert_eq!((v.lookups, v.blocked, v.cached), (3, 1, 1));
        assert_eq!(v.median_ms, Some(20.0));
        assert_eq!(v.minutes.len(), 60);
        assert_eq!(v.minutes.last().copied(), Some((3, 1)));
        assert!(s.log().is_empty(), "nothing is logged by default");
        s.set_logging(true);
        s.record(entry(Verdict::Pass, 10));
        assert_eq!(s.log().len(), 1);
        s.set_logging(false);
        assert!(s.log().is_empty(), "switching it off clears it");
    }
}
