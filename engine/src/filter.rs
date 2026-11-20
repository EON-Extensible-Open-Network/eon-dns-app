// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! What is blocked, and why. A name is checked against the person's own rules
//! first (an *always allow* beats everything), then each list that is on. A
//! rule or a list entry covers its subdomains: blocking `ads.example` blocks
//! `x.ads.example` too, which is how the lists are written.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// The lists a person can switch on, each one a published open list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum List {
    /// Malware, phishing, scams.
    Threats,
    /// Advertising and tracking.
    Ads,
    /// Adult content.
    Adult,
}

impl List {
    pub const ALL: [Self; 3] = [Self::Threats, Self::Ads, Self::Adult];

    /// Where the list is published. `HaGeZi`'s DNS blocklists (GPL-3.0), in their
    /// domains-only form, where an entry covers its subdomains.
    #[must_use]
    pub fn url(self) -> &'static str {
        match self {
            Self::Threats => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
            Self::Ads => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
            Self::Adult => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt",
        }
    }

    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Threats => "threats",
            Self::Ads => "ads",
            Self::Adult => "adult",
        }
    }
}

/// Why a name was answered the way it was.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "by", content = "detail", rename_all = "snake_case")]
pub enum Verdict {
    /// Not on any list: resolved upstream.
    Pass,
    /// On the person's always-allow list (wins over every list).
    Allowed(String),
    /// On the person's always-block list.
    Rule(String),
    /// On a list that is switched on.
    Listed(List),
}

impl Verdict {
    #[must_use]
    pub fn blocked(&self) -> bool {
        matches!(self, Self::Rule(_) | Self::Listed(_))
    }
}

/// A name in the form lists and rules use: lower case, no trailing dot.
#[must_use]
pub fn normalise(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Whether `text` is a plausible domain: labels of letters, digits, `-` and
/// `_`, at most 253 characters.
#[must_use]
pub fn plausible(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 253
        && text.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Reads a published list: one domain per line, `#` comments, and the
/// `0.0.0.0 domain` hosts form some lists use. Anything else is skipped.
#[must_use]
pub fn parse_list(text: &str) -> HashSet<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next()?.trim();
            let name = line.split_whitespace().last()?;
            let name = normalise(name.trim_start_matches("*."));
            (plausible(&name) && name.contains('.') && name != "localhost").then_some(name)
        })
        .collect()
}

/// The set of names `name` is covered by: itself and each parent domain.
fn suffixes(name: &str) -> impl Iterator<Item = &str> {
    let mut rest = Some(name);
    std::iter::from_fn(move || {
        let current = rest?;
        rest = current.split_once('.').map(|(_, parent)| parent);
        Some(current)
    })
}

#[derive(Default)]
pub struct Filter {
    lists: HashMap<List, HashSet<String>>,
    allow: HashSet<String>,
    block: HashSet<String>,
}

impl Filter {
    /// Replaces a list's contents (a list that is off has no entry).
    pub fn set_list(&mut self, list: List, names: Option<HashSet<String>>) {
        match names {
            Some(names) => {
                self.lists.insert(list, names);
            }
            None => {
                self.lists.remove(&list);
            }
        }
    }

    pub fn set_rules(&mut self, allow: &[String], block: &[String]) {
        self.allow = allow
            .iter()
            .map(|n| normalise(n))
            .filter(|n| plausible(n))
            .collect();
        self.block = block
            .iter()
            .map(|n| normalise(n))
            .filter(|n| plausible(n))
            .collect();
    }

    /// How many names each list that is on holds.
    #[must_use]
    pub fn sizes(&self) -> HashMap<List, usize> {
        self.lists.iter().map(|(l, s)| (*l, s.len())).collect()
    }

    #[must_use]
    pub fn check(&self, name: &str) -> Verdict {
        let name = normalise(name);
        for s in suffixes(&name) {
            if self.allow.contains(s) {
                return Verdict::Allowed(s.to_owned());
            }
        }
        for s in suffixes(&name) {
            if self.block.contains(s) {
                return Verdict::Rule(s.to_owned());
            }
        }
        for list in List::ALL {
            if let Some(names) = self.lists.get(&list) {
                if suffixes(&name).any(|s| names.contains(s)) {
                    return Verdict::Listed(list);
                }
            }
        }
        Verdict::Pass
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn lists_are_read_in_both_forms_and_junk_is_skipped() {
        let text = "# comment\nads.example.com\n0.0.0.0 tracker.example.net\n*.wild.example\n\nnot a domain!\nlocalhost\nAds.Example.ORG. # trailing\n";
        let names = parse_list(text);
        for n in [
            "ads.example.com",
            "tracker.example.net",
            "wild.example",
            "ads.example.org",
        ] {
            assert!(names.contains(n), "{n}");
        }
        assert_eq!(names.len(), 4);
    }

    #[test]
    fn an_entry_covers_its_subdomains_and_allow_wins() {
        let mut f = Filter::default();
        f.set_list(List::Ads, Some(parse_list("ads.example.com\n")));
        f.set_rules(&["good.ads.example.com".into()], &["Mine.Example".into()]);
        assert_eq!(f.check("x.y.ads.example.com."), Verdict::Listed(List::Ads));
        assert_eq!(f.check("ads.example.com"), Verdict::Listed(List::Ads));
        assert_eq!(
            f.check("example.com"),
            Verdict::Pass,
            "a parent is not covered"
        );
        assert_eq!(
            f.check("notads.example.com"),
            Verdict::Pass,
            "nor a lookalike"
        );
        assert_eq!(
            f.check("a.good.ads.example.com"),
            Verdict::Allowed("good.ads.example.com".into())
        );
        assert_eq!(
            f.check("sub.mine.example"),
            Verdict::Rule("mine.example".into())
        );
        f.set_list(List::Ads, None);
        assert_eq!(
            f.check("ads.example.com"),
            Verdict::Pass,
            "a list switched off blocks nothing"
        );
    }
}
