//! How join/part/quit lines are shown.
//!
//! The buffer always keeps every presence line; this decides, at draw time,
//! whether they are hidden (the default), collapsed run-by-run into one
//! summary line, or shown one by one. Kicks, modes and every other system
//! line are never presence lines, so they always show.

use std::borrow::Cow;
use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::app::BufferLine;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JoinPartDisplay {
    #[default]
    Hidden,
    Grouped,
    All,
}

impl JoinPartDisplay {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "hidden" | "off" | "hide" | "none" => Some(Self::Hidden),
            "grouped" | "group" => Some(Self::Grouped),
            "all" | "on" | "show" => Some(Self::All),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hidden => "hidden",
            Self::Grouped => "grouped",
            Self::All => "all",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Join,
    Leave,
}

/// The nick and direction of a presence line, or `None` for anything else.
/// Matches what this client writes: `nick has joined`, `nick [host] has
/// joined`, `nick has left`, `nick has quit (reason)`.
fn presence(line: &BufferLine) -> Option<(&str, Kind)> {
    if !line.is_system {
        return None;
    }
    let (nick, rest) = line.text.split_once(' ')?;
    if nick.is_empty() {
        return None;
    }
    // Skip an optional "[host] " cloak.
    let rest = match rest.strip_prefix('[') {
        Some(r) => r.split_once("] ")?.1,
        None => rest,
    };
    if rest == "has joined" {
        Some((nick, Kind::Join))
    } else if rest == "has left" || rest == "has quit" || rest.starts_with("has quit (") {
        Some((nick, Kind::Leave))
    } else {
        None
    }
}

/// "a, b, c and 2 more"
fn names(list: &[&str]) -> String {
    let shown = list.iter().take(3).copied().collect::<Vec<_>>().join(", ");
    if list.len() > 3 {
        format!("{shown} and {} more", list.len() - 3)
    } else {
        shown
    }
}

/// One line standing for a run of presence lines.
fn summarize(run: &[(&str, Kind)]) -> String {
    let joins = run.iter().filter(|(_, k)| *k == Kind::Join).count();
    let leaves = run.len() - joins;
    let first = run[0].0;
    if run.iter().all(|(n, _)| n.eq_ignore_ascii_case(first)) {
        return if joins > 0 && leaves > 0 {
            format!("{first} reconnected {}×", joins.min(leaves))
        } else if joins > 0 {
            format!("{first} joined {joins}×")
        } else {
            format!("{first} left {leaves}×")
        };
    }
    let mut joined: Vec<&str> = Vec::new();
    let mut left: Vec<&str> = Vec::new();
    for &(nick, kind) in run {
        let list = if kind == Kind::Join {
            &mut joined
        } else {
            &mut left
        };
        if !list.iter().any(|n| n.eq_ignore_ascii_case(nick)) {
            list.push(nick);
        }
    }
    let mut said = Vec::new();
    if !joined.is_empty() {
        said.push(format!("{} joined", names(&joined)));
    }
    if !left.is_empty() {
        said.push(format!("{} left", names(&left)));
    }
    said.join(" · ")
}

/// The lines to draw for `lines` under `mode`.
pub fn apply(lines: &VecDeque<BufferLine>, mode: JoinPartDisplay) -> Vec<Cow<'_, BufferLine>> {
    match mode {
        JoinPartDisplay::All => lines.iter().map(Cow::Borrowed).collect(),
        JoinPartDisplay::Hidden => lines
            .iter()
            .filter(|l| presence(l).is_none())
            .map(Cow::Borrowed)
            .collect(),
        JoinPartDisplay::Grouped => {
            let mut out = Vec::with_capacity(lines.len());
            let mut i = 0;
            while i < lines.len() {
                let mut run = Vec::new();
                while let Some(p) = lines.get(i + run.len()).and_then(presence) {
                    run.push(p);
                }
                match run.len() {
                    0 | 1 => {
                        out.push(Cow::Borrowed(&lines[i]));
                        i += 1;
                    }
                    n => {
                        // Stamped with the run's last time: the summary says
                        // where things stand as of then.
                        let mut summary = lines[i + n - 1].clone();
                        summary.text = summarize(&run);
                        out.push(Cow::Owned(summary));
                        i += n;
                    }
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Buffer;

    fn lines(texts: &[&str]) -> VecDeque<BufferLine> {
        let mut buf = Buffer::new("#t");
        for t in texts {
            buf.push_system(t);
            if let Some(said) = t.strip_prefix("<alice> ") {
                let line = buf.messages.back_mut().unwrap();
                line.is_system = false;
                line.from = "alice".into();
                line.text = said.into();
            }
        }
        buf.messages
    }

    fn texts(out: &[Cow<'_, BufferLine>]) -> Vec<String> {
        out.iter().map(|l| l.text.clone()).collect()
    }

    #[test]
    fn hidden_drops_only_presence_lines() {
        let l = lines(&[
            "bob has joined",
            "<alice> hi",
            "carol [freeq/guest] has joined",
            "dave has quit (bye)",
            "eve was kicked by alice (spam)",
            "frank has left",
        ]);
        let out = apply(&l, JoinPartDisplay::Hidden);
        assert_eq!(texts(&out), vec!["hi", "eve was kicked by alice (spam)"]);
    }

    #[test]
    fn all_keeps_everything() {
        let l = lines(&["bob has joined", "carol has left"]);
        assert_eq!(apply(&l, JoinPartDisplay::All).len(), 2);
    }

    #[test]
    fn grouped_collapses_runs_but_not_singles() {
        let l = lines(&[
            "bob has joined",
            "<alice> hi",
            "carol has joined",
            "dave has joined",
            "erin has quit (bye)",
            "eve was kicked by alice",
        ]);
        let out = apply(&l, JoinPartDisplay::Grouped);
        assert_eq!(
            texts(&out),
            vec![
                "bob has joined",
                "hi",
                "carol, dave joined · erin left",
                "eve was kicked by alice",
            ]
        );
    }

    #[test]
    fn grouped_one_person_churn_reads_as_reconnects() {
        let l = lines(&[
            "nap has quit (ping timeout)",
            "nap has joined",
            "nap has quit (ping timeout)",
            "nap has joined",
        ]);
        assert_eq!(
            texts(&apply(&l, JoinPartDisplay::Grouped)),
            vec!["nap reconnected 2×"]
        );
    }

    #[test]
    fn grouped_caps_names_at_three() {
        let l = lines(&[
            "a has joined",
            "b has joined",
            "c has joined",
            "d has joined",
            "e has joined",
        ]);
        assert_eq!(
            texts(&apply(&l, JoinPartDisplay::Grouped)),
            vec!["a, b, c and 2 more joined"]
        );
    }

    #[test]
    fn parse_accepts_aliases() {
        assert_eq!(JoinPartDisplay::parse("off"), Some(JoinPartDisplay::Hidden));
        assert_eq!(
            JoinPartDisplay::parse("Grouped"),
            Some(JoinPartDisplay::Grouped)
        );
        assert_eq!(JoinPartDisplay::parse("on"), Some(JoinPartDisplay::All));
        assert_eq!(JoinPartDisplay::parse("nope"), None);
        assert_eq!(JoinPartDisplay::default(), JoinPartDisplay::Hidden);
    }
}
