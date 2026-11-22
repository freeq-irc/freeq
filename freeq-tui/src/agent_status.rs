//! An agent's presence status, decoded.
//!
//! Agents built on harness-kit publish their status as space-separated
//! `key=value` pairs, with the prose `doing` field's spaces sent as `+`:
//!
//! ```text
//! project=phoenix-agent model=opus doing=answering+chad+in+#phoenix+·+0s
//! ```
//!
//! Carried in an AWAY reason it is prefixed with the presence state
//! (`executing: project=…`). Printed raw it is unreadable, so the TUI decodes
//! it first. Mirrors freeq-app/src/lib/status.ts and the Swift AgentStatus.

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AgentStatus {
    pub state: Option<String>,
    pub doing: Option<String>,
    pub project: Option<String>,
    pub branch: Option<String>,
    pub model: Option<String>,
}

const KNOWN: &[&str] = &["project", "branch", "repo", "model", "session", "doing"];

fn is_key(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c == '_' || c.is_ascii_lowercase())
}

fn is_pair(tok: &str) -> bool {
    tok.split_once('=').is_some_and(|(k, _)| is_key(k))
}

impl AgentStatus {
    /// Decode, or `None` when `raw` is not an agent status (a person's text).
    pub fn parse(raw: &str) -> Option<Self> {
        let mut text = raw.trim();
        let mut out = AgentStatus::default();
        if let Some((head, rest)) = text.split_once(": ")
            && is_key(head)
            && rest.split_whitespace().next().is_some_and(is_pair)
        {
            out.state = Some(head.to_string());
            text = rest;
        }
        let tokens: Vec<&str> = text.split_whitespace().collect();
        if tokens.is_empty() || !tokens.iter().all(|t| is_pair(t)) {
            return None;
        }
        let mut known = 0;
        for tok in tokens {
            let (k, v) = tok.split_once('=').unwrap_or_default();
            if !KNOWN.contains(&k) {
                continue;
            }
            known += 1;
            if v.is_empty() {
                continue;
            }
            match k {
                "doing" => out.doing = Some(v.replace('+', " ")),
                "project" => out.project = Some(v.to_string()),
                "branch" => out.branch = Some(v.to_string()),
                "model" => out.model = Some(v.to_string()),
                _ => {}
            }
        }
        (known > 0).then_some(out)
    }

    /// Words for the state: "working", "waiting for input", …
    pub fn state_words(&self) -> &str {
        match self.state.as_deref() {
            Some("executing") | None => "working",
            Some("waiting_for_input") => "waiting for input",
            Some("blocked_on_permission") => "waiting for approval",
            Some("blocked_on_budget") => "out of budget",
            Some("rate_limited") => "rate limited",
            Some(other) => other,
        }
    }

    /// What it is doing, without the elapsed-time suffix ("· 2m") that
    /// changes on every refresh — the part worth telling a reader about.
    pub fn doing_stable(&self) -> Option<String> {
        let d = self.doing.as_deref()?;
        // harness-kit's elapsed: "0s", "2m", "1h 5m".
        let is_duration = |tail: &str| {
            let parts: Vec<&str> = tail.split(' ').collect();
            parts.len() <= 2
                && parts.iter().all(|p| {
                    p.len() >= 2
                        && p[..p.len() - 1].chars().all(|c| c.is_ascii_digit())
                        && matches!(p.as_bytes()[p.len() - 1], b's' | b'm' | b'h' | b'd')
                })
        };
        let cut = d.rsplit_once(" · ").filter(|(_, tail)| is_duration(tail));
        Some(cut.map_or(d, |(head, _)| head).to_string())
    }

    /// "is working: answering chad in #phoenix (phoenix-agent @main)".
    pub fn describe(&self) -> String {
        let place = match (&self.project, &self.branch) {
            (Some(p), Some(b)) => Some(format!("{p} @{b}")),
            (Some(p), None) => Some(p.clone()),
            (None, Some(b)) => Some(format!("@{b}")),
            (None, None) => None,
        };
        match (self.doing_stable(), place) {
            (Some(d), Some(p)) => format!("is {}: {d} ({p})", self.state_words()),
            (Some(d), None) => format!("is {}: {d}", self.state_words()),
            (None, Some(p)) => format!("is {} on {p}", self.state_words()),
            (None, None) => format!("is {}", self.state_words()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &str = "project=phoenix-agent doing=answering+chad-bot-phoenix+in+#phoenix+·+0s";

    #[test]
    fn decodes_and_describes() {
        let s = AgentStatus::parse(&format!("executing: {RAW} branch=main")).unwrap();
        assert_eq!(s.state.as_deref(), Some("executing"));
        assert_eq!(s.doing.as_deref(), Some("answering chad-bot-phoenix in #phoenix · 0s"));
        assert_eq!(s.doing_stable().as_deref(), Some("answering chad-bot-phoenix in #phoenix"));
        assert_eq!(
            s.describe(),
            "is working: answering chad-bot-phoenix in #phoenix (phoenix-agent @main)"
        );
    }

    #[test]
    fn leaves_people_alone() {
        assert!(AgentStatus::parse("out to lunch").is_none());
        assert!(AgentStatus::parse("back at 3: see you").is_none());
        assert!(AgentStatus::parse("a=b c=d").is_none());
        assert!(AgentStatus::parse("").is_none());
    }

    #[test]
    fn keeps_a_doing_that_merely_contains_a_dot() {
        let s = AgentStatus::parse("doing=compare+a+·+b+options").unwrap();
        assert_eq!(s.doing_stable().as_deref(), Some("compare a · b options"));
        let s = AgentStatus::parse("doing=build+·+cargo+·+1h+5m").unwrap();
        assert_eq!(s.doing_stable().as_deref(), Some("build · cargo"));
    }
}
