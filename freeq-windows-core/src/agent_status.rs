//! An agent's presence status, decoded for display.
//!
//! Agents built on harness-kit publish their status as space-separated
//! `key=value` pairs, with the prose `doing` field's spaces sent as `+`:
//!
//! ```text
//! project=phoenix-agent model=opus doing=answering+chad+in+#phoenix+·+0s
//! ```
//!
//! Carried in an AWAY reason it is prefixed with the presence state
//! (`executing: project=…`). Shown raw it is unreadable, so the bridge decodes
//! it before it reaches the Windows UI. Mirrors freeq-app/src/lib/status.ts and
//! freeq-macos/…/Models/AgentStatus.swift — keep the wording in step.

/// A decoded agent status. Every field is optional; `session` is recognised
/// but never kept (it is an internal id, not something to show).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentStatus {
    /// Presence state when the text carried one (`executing`, …).
    pub state: Option<String>,
    /// What the agent is doing right now, as prose.
    pub doing: Option<String>,
    pub project: Option<String>,
    pub branch: Option<String>,
    pub repo: Option<String>,
    pub model: Option<String>,
}

const KNOWN: &[&str] = &["project", "branch", "repo", "model", "session", "doing"];

fn is_key(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b == b'_' || b.is_ascii_lowercase())
}

/// `[a-z_]+=\S*`
fn is_pair(token: &str) -> bool {
    match token.split_once('=') {
        Some((k, _)) => is_key(k),
        None => false,
    }
}

impl AgentStatus {
    /// Decode, or `None` when `raw` is not an agent status (a person's free
    /// text, JSON, empty). A string is one only if every whitespace token is a
    /// `key=value` pair and at least one key is known.
    pub fn parse(raw: &str) -> Option<AgentStatus> {
        let mut text = raw.trim();
        if text.is_empty() {
            return None;
        }
        let mut out = AgentStatus::default();

        // "executing: project=…" — a state prefix, but only in front of pairs.
        if let Some((head, rest)) = text.split_once(':') {
            if is_key(head)
                && rest.starts_with(char::is_whitespace)
                && rest.split_whitespace().next().is_some_and(is_pair)
            {
                out.state = Some(head.to_string());
                text = rest.trim_start();
            }
        }

        let tokens: Vec<&str> = text.split_whitespace().collect();
        if tokens.is_empty() || !tokens.iter().all(|t| is_pair(t)) {
            return None;
        }
        let mut known = 0;
        for token in tokens {
            let (key, value) = token.split_once('=')?;
            if !KNOWN.contains(&key) {
                continue;
            }
            known += 1;
            if value.is_empty() {
                continue;
            }
            let value = value.to_string();
            match key {
                "doing" => out.doing = Some(value.replace('+', " ")),
                "project" => out.project = Some(value),
                "branch" => out.branch = Some(value),
                "repo" => out.repo = Some(value),
                "model" => out.model = Some(value),
                _ => {} // session: recognised, never shown
            }
        }
        (known > 0).then_some(out)
    }

    /// "phoenix-agent @main · opus": where the agent is working, in one line.
    pub fn context(&self) -> Option<String> {
        let where_: Vec<String> = [
            self.project.clone(),
            self.branch.as_ref().map(|b| format!("@{b}")),
        ]
        .into_iter()
        .flatten()
        .collect();
        let where_ = (!where_.is_empty()).then(|| where_.join(" "));
        let parts: Vec<String> = [where_, self.model.clone()].into_iter().flatten().collect();
        (!parts.is_empty()).then(|| parts.join(" · "))
    }

    /// One line: "Working · answering chad in #phoenix".
    pub fn summary(&self) -> Option<String> {
        let parts: Vec<String> = [
            state_label(self.state.as_deref()),
            self.doing.clone().or_else(|| self.context()),
        ]
        .into_iter()
        .flatten()
        .collect();
        (!parts.is_empty()).then(|| parts.join(" · "))
    }
}

/// Words for an agent presence state.
pub fn state_label(state: Option<&str>) -> Option<String> {
    let state = state.filter(|s| !s.is_empty())?;
    Some(
        match state {
            "executing" => "Working",
            "active" | "online" => "Available",
            "idle" => "Idle",
            "waiting_for_input" => "Waiting for input",
            "blocked_on_permission" => "Needs approval",
            "blocked_on_budget" => "Out of budget",
            "rate_limited" => "Rate limited",
            "degraded" => "Degraded",
            "paused" => "Paused",
            "sandboxed" => "Sandboxed",
            "revoked" => "Revoked",
            "offline" => "Offline",
            other => return Some(other.replace('_', " ")),
        }
        .to_string(),
    )
}

/// An AWAY reason as display text: an agent's decoded, anyone else's as is.
pub fn display_away(away: Option<&str>) -> Option<String> {
    let away = away.filter(|a| !a.is_empty())?;
    match AgentStatus::parse(away) {
        Some(agent) => agent.summary(),
        None => Some(away.to_string()),
    }
}

/// A structured PRESENCE as one display line: its status decoded (the
/// presence state filling in when the text has none), else just the state.
pub fn display_presence(state: &str, status: Option<&str>) -> Option<String> {
    if let Some(mut agent) = status.and_then(AgentStatus::parse) {
        if agent.state.is_none() {
            agent.state = Some(state.to_string());
        }
        if let Some(s) = agent.summary() {
            return Some(s);
        }
    }
    let label = state_label(Some(state));
    match (label, status.filter(|s| !s.is_empty())) {
        (Some(l), Some(s)) => Some(format!("{l} · {s}")),
        (Some(l), None) => Some(l),
        (None, s) => s.map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &str = "project=phoenix-agent doing=answering+chad-bot-phoenix+in+#phoenix+·+0s";

    #[test]
    fn decodes_the_harness_kit_status() {
        assert_eq!(
            AgentStatus::parse(RAW),
            Some(AgentStatus {
                project: Some("phoenix-agent".into()),
                doing: Some("answering chad-bot-phoenix in #phoenix · 0s".into()),
                ..Default::default()
            })
        );
    }

    #[test]
    fn takes_the_presence_state_off_an_away_reason() {
        let s = AgentStatus::parse(&format!("executing: {RAW} model=opus branch=main")).unwrap();
        assert_eq!(s.state.as_deref(), Some("executing"));
        assert_eq!(s.project.as_deref(), Some("phoenix-agent"));
        assert_eq!(s.model.as_deref(), Some("opus"));
        assert_eq!(s.branch.as_deref(), Some("main"));
    }

    #[test]
    fn never_shows_session() {
        let s = AgentStatus::parse("session=abc model=opus").unwrap();
        assert_eq!(s.summary().as_deref(), Some("opus"));
    }

    #[test]
    fn leaves_free_text_json_and_unknown_keys_alone() {
        for text in [
            "out to lunch",
            "back at 3: see you",
            "lunch: back at 2",
            r#"{"status":"lunch"}"#,
            "a=b c=d",
            "project=x and words",
            "Project=x",
            "",
            "   ",
        ] {
            assert_eq!(AgentStatus::parse(text), None, "{text:?}");
        }
    }

    #[test]
    fn reads_an_agent_away_line_as_words() {
        assert_eq!(
            display_away(Some(&format!("executing: {RAW}"))).as_deref(),
            Some("Working · answering chad-bot-phoenix in #phoenix · 0s")
        );
        assert_eq!(
            display_away(Some("executing: project=x model=m")).as_deref(),
            Some("Working · x · m")
        );
        assert_eq!(
            display_away(Some("executing: project=x branch=main model=m")).as_deref(),
            Some("Working · x @main · m")
        );
    }

    #[test]
    fn keeps_people_as_they_were() {
        assert_eq!(display_away(Some("lunch")).as_deref(), Some("lunch"));
        assert_eq!(display_away(Some("")), None);
        assert_eq!(display_away(None), None);
    }

    #[test]
    fn names_states() {
        for (state, label) in [
            ("executing", "Working"),
            ("active", "Available"),
            ("online", "Available"),
            ("idle", "Idle"),
            ("waiting_for_input", "Waiting for input"),
            ("blocked_on_permission", "Needs approval"),
            ("blocked_on_budget", "Out of budget"),
            ("rate_limited", "Rate limited"),
            ("degraded", "Degraded"),
            ("paused", "Paused"),
            ("sandboxed", "Sandboxed"),
            ("revoked", "Revoked"),
            ("offline", "Offline"),
            ("something_new", "something new"),
        ] {
            assert_eq!(state_label(Some(state)).as_deref(), Some(label));
        }
        assert_eq!(state_label(None), None);
    }

    #[test]
    fn context_is_project_branch_model() {
        let s = AgentStatus {
            project: Some("p".into()),
            branch: Some("b".into()),
            model: Some("m".into()),
            ..Default::default()
        };
        assert_eq!(s.context().as_deref(), Some("p @b · m"));
    }

    #[test]
    fn presence_lends_its_state_to_the_status() {
        assert_eq!(
            display_presence("active", Some("project=freeq doing=reviewing+a+PR")).as_deref(),
            Some("Available · reviewing a PR")
        );
        assert_eq!(display_presence("idle", None).as_deref(), Some("Idle"));
        assert_eq!(
            display_presence("executing", Some("building the thing")).as_deref(),
            Some("Working · building the thing")
        );
    }
}
