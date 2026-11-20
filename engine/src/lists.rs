// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! The published lists, kept in the data folder's `lists/`. A download is
//! checked for size and shape before it replaces the copy in use; one that
//! fails leaves the last good copy where it is.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::filter::{parse_list, List};

/// Lists bigger than this are refused: the largest used here is ~4 MB.
const MAX_BYTES: usize = 64 * 1024 * 1024;
/// A list with fewer names than this is not the list we asked for.
const MIN_NAMES: usize = 100;
const STALE: Duration = Duration::from_hours(24);

fn path(data: &Path, list: List) -> PathBuf {
    data.join("lists").join(format!("{}.txt", list.id()))
}

/// The copy on disk, read and parsed.
#[must_use]
pub fn load(data: &Path, list: List) -> Option<HashSet<String>> {
    std::fs::read_to_string(path(data, list))
        .ok()
        .map(|t| parse_list(&t))
}

/// When the copy on disk was last replaced.
#[must_use]
pub fn updated(data: &Path, list: List) -> Option<SystemTime> {
    std::fs::metadata(path(data, list))
        .and_then(|m| m.modified())
        .ok()
}

/// Downloads and checks one list, then replaces the copy on disk.
pub async fn fetch(client: &reqwest::Client, data: &Path, list: List) -> Result<usize, String> {
    let response = client
        .get(list.url())
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| e.without_url().to_string())?;
    if response
        .content_length()
        .is_some_and(|n| n as usize > MAX_BYTES)
    {
        return Err("the list is too large".into());
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|e| e.without_url().to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("the list is too large".into());
    }
    let text = String::from_utf8_lossy(&bytes);
    let names = parse_list(&text);
    if names.len() < MIN_NAMES {
        return Err(format!("the list has only {} names", names.len()));
    }
    let target = path(data, list);
    let dir = target.parent().ok_or("no folder")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tmp = target.with_extension("part");
    std::fs::write(&tmp, text.as_bytes()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &target).map_err(|e| e.to_string())?;
    Ok(names.len())
}

/// Fetches each of `lists` that is missing or a day old (all with `force`).
pub async fn refresh(
    data: &Path,
    lists: &[List],
    force: bool,
) -> Vec<(List, Result<usize, String>)> {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(concat!("eon-dns/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => return lists.iter().map(|l| (*l, Err(e.to_string()))).collect(),
    };
    let mut out = Vec::new();
    for list in lists {
        let fresh = updated(data, *list)
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age < STALE);
        if fresh && !force {
            continue;
        }
        out.push((*list, fetch(&client, data, *list).await));
    }
    out
}
