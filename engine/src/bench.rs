// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Which resolver is fastest from here: the same real lookups against each
//! candidate, each with its own resolver and no cache, timed.

use std::time::Instant;

use hickory_resolver::proto::rr::RecordType;
use serde::Serialize;

use crate::upstream::{self, Transport, Tuning, Upstream};

/// Common names, so the upstream's own cache is warm -- which is what a
/// person actually experiences.
pub const NAMES: &[&str] = &[
    "wikipedia.org.",
    "github.com.",
    "microsoft.com.",
    "apple.com.",
    "mozilla.org.",
    "cloudflare.com.",
    "debian.org.",
    "openstreetmap.org.",
    "archive.org.",
    "w3.org.",
    "ietf.org.",
    "rust-lang.org.",
];

#[derive(Clone, Debug, Serialize)]
pub struct Score {
    pub upstream: Upstream,
    /// The median of the answered lookups, in milliseconds.
    pub median_ms: Option<f64>,
    pub failures: usize,
}

/// Times every candidate, one after another, so they do not slow each other.
pub async fn run(candidates: Vec<Upstream>, transport: Transport) -> Vec<Score> {
    let mut scores = Vec::new();
    for candidate in candidates {
        let tuning = Tuning {
            validate: false,
            cache: 0,
            race: 1,
        };
        let Ok(resolver) = upstream::resolver(std::slice::from_ref(&candidate), transport, &tuning)
        else {
            scores.push(Score {
                upstream: candidate,
                median_ms: None,
                failures: NAMES.len(),
            });
            continue;
        };
        // The first lookup opens the connection; it is not what is measured.
        let _ = resolver.lookup("example.com.", RecordType::A).await;
        let mut times = Vec::new();
        let mut failures = 0;
        for name in NAMES {
            let started = Instant::now();
            match resolver.lookup(*name, RecordType::A).await {
                Ok(_) => times.push(started.elapsed().as_secs_f64() * 1000.0),
                Err(_) => failures += 1,
            }
        }
        times.sort_by(f64::total_cmp);
        scores.push(Score {
            upstream: candidate,
            median_ms: times.get(times.len() / 2).copied(),
            failures,
        });
    }
    scores
}
