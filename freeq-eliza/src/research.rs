//! Ambient research — the quiet text-channel companion.
//!
//! While she is *not* being addressed, this monitor listens to the rolling
//! call transcript, recognizes the topics being discussed, logs them to a
//! note (`~/.freeq/bots/<nick>/topics.jsonl`), and — for technical / factual
//! topics where a reference would genuinely help the people talking —
//! researches the topic with the web-search model and drops a concise card
//! (a one-line definition + useful links) into the TEXT channel. It also
//! reflects the topic on the tile's ambient chip.
//!
//! It never speaks. It is the sibling of:
//!   - [`crate::proactive`] — decides *when to speak*,
//!   - [`crate::ambient`]   — decides *how the tile looks*.
//!
//! Research decides *what helpful reference to drop in chat*.
//!
//! Guardrails (anti-spam is the whole game):
//! - 30s tick, skip the first (let the call settle),
//! - ≥ 25 new transcript words since the last look,
//! - 75s cooldown between posts,
//! - never post while she's mid-answer (QA owns the channel then),
//! - dedup against recently-covered topics,
//! - off unless `--ambient-research` ([`crate::irc::RunConfig::research_enabled`]).

use std::sync::Arc;
use std::time::{Duration, Instant};

use freeq_sdk::client::ClientHandle;
use serde::Deserialize;
use tokio::sync::Mutex as AsyncMutex;

use crate::irc::{ActiveCall, SharedConfig};
use crate::video::VideoTile;

const TICK: Duration = Duration::from_secs(30);
const POST_COOLDOWN: Duration = Duration::from_secs(75);
const POST_ANSWER_GRACE: Duration = Duration::from_secs(20);
const MIN_NEW_WORDS: usize = 25;
const RECENT_TOPICS_MAX: usize = 24;
/// How many recent transcript lines to feed the recognizer — the topic
/// usually persists across a few lines, so a small window is enough.
const CONTEXT_LINES: usize = 16;

const RECOGNIZE_SYSTEM: &str = "You are listening to a live conversation you \
are NOT part of and were NOT addressed in. Do two things:\n\
1. List the main topics currently being discussed (1-4 short topic labels, \
1-4 words each).\n\
2. Decide whether ONE of those topics is a TECHNICAL or FACTUAL subject where \
a short definition, reference, or link would genuinely help the people talking \
— e.g. a technical term, a tool/library, a standard, a scientific or historical \
fact, a place. \n\n\
DEFAULT to help=null. Only set `help` when a reference clearly ADDS VALUE. Do \
NOT set help for: opinions, feelings, vibes, small talk, logistics, or anything \
already in the 'recently covered' list.\n\n\
Output STRICT JSON, no prose, no markdown:\n\
{\"topics\": [\"...\"], \"help\": {\"topic\": \"short label\", \"query\": \"what to look up / explain\"}}\n\
or, when nothing is worth surfacing:\n\
{\"topics\": [\"...\"], \"help\": null}";

#[derive(Deserialize)]
struct Recognized {
    #[serde(default)]
    topics: Vec<String>,
    #[serde(default)]
    help: Option<HelpPick>,
}

#[derive(Deserialize, Clone)]
struct HelpPick {
    topic: String,
    query: String,
}

struct Snapshot {
    transcript: Vec<String>,
    video: Option<VideoTile>,
    speaking: bool,
    last_answer: Option<Instant>,
}

pub(crate) fn spawn_monitor(
    cfg: Arc<SharedConfig>,
    handle: Arc<ClientHandle>,
    channel: String,
    active: Arc<AsyncMutex<Option<ActiveCall>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_monitor(cfg, handle, channel, active))
}

async fn run_monitor(
    cfg: Arc<SharedConfig>,
    handle: Arc<ClientHandle>,
    channel: String,
    active: Arc<AsyncMutex<Option<ActiveCall>>>,
) {
    tracing::info!("ambient-research monitor armed");
    let notes_path = notes_path_for(&cfg.nick);
    let mut consumed_lines: usize = 0;
    let mut last_post: Option<Instant> = None;
    let mut recent_topics: Vec<String> = Vec::new();

    // Skip the first tick — give the call a moment to accumulate real talk.
    tokio::time::sleep(TICK).await;

    loop {
        tokio::time::sleep(TICK).await;

        // Snapshot under the call lock; bail if the call ended.
        let snapshot = {
            let guard = active.lock().await;
            let Some(call) = guard.as_ref() else {
                continue;
            };
            Snapshot {
                transcript: call.transcript.clone(),
                video: Some(call.video.clone()),
                speaking: call.speaker.is_speaking(),
                last_answer: call.last_answer,
            }
        };

        // Drop her own lines — we react to what OTHERS are saying.
        let self_base = cfg
            .nick
            .split_once('-')
            .map(|(p, _)| p)
            .unwrap_or(&cfg.nick)
            .to_ascii_lowercase();
        let total = snapshot.transcript.len();
        if total <= consumed_lines {
            continue;
        }
        let new_lines: Vec<&String> = snapshot.transcript[consumed_lines..]
            .iter()
            .filter(|l| {
                let speaker = l.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
                !speaker.starts_with(&self_base)
            })
            .collect();
        let new_words: usize = new_lines.iter().map(|l| l.split_whitespace().count()).sum();
        if new_words < MIN_NEW_WORDS {
            continue;
        }
        // Consume regardless of outcome, so we don't reprocess the same talk.
        consumed_lines = total;

        // Recognizer context: the tail of the transcript (topic persists).
        let start = total.saturating_sub(CONTEXT_LINES);
        let context: String = snapshot.transcript[start..].join("\n");

        let Some(key) = cfg.groq_api_key.as_deref() else {
            continue;
        };
        let rec = match recognize(&cfg.http, key, &cfg.groq_chat_model, &context, &recent_topics)
            .await
        {
            Some(r) => r,
            None => continue,
        };

        // 1. Log the note — every recognized topic, always (cheap, useful).
        if !rec.topics.is_empty() {
            append_note(&notes_path, &channel, &rec.topics);
            tracing::info!(topics = ?rec.topics, "research: topics noted");
        }

        // 2. Surface help — only when worthwhile and not spammy.
        let Some(help) = rec.help else {
            continue;
        };
        if recent_topics
            .iter()
            .any(|t| t.eq_ignore_ascii_case(&help.topic))
        {
            continue;
        }
        if snapshot.speaking {
            tracing::debug!(topic = %help.topic, "research: mid-answer, holding help");
            continue;
        }
        if snapshot
            .last_answer
            .is_some_and(|t| t.elapsed() < POST_ANSWER_GRACE)
        {
            continue;
        }
        if last_post.is_some_and(|t| t.elapsed() < POST_COOLDOWN) {
            tracing::debug!(topic = %help.topic, "research: cooldown, holding help");
            continue;
        }

        // 3. Research + post.
        let card = match research_topic(&cfg, key, &help).await {
            Some(c) if !c.trim().is_empty() => c,
            _ => continue,
        };
        let msg = format!("📎 {} — {}", help.topic, card.trim());
        if let Err(e) = handle.privmsg(&channel, &msg).await {
            tracing::warn!(error = ?e, "research: failed to post card");
            continue;
        }
        tracing::info!(topic = %help.topic, card = %card.trim(), "research: posted help card to text channel");

        // Light visualization: reflect the topic on the tile's ambient chip.
        if let Some(v) = &snapshot.video {
            v.set_ambient(help.topic.clone(), "#5BC0EB".to_string());
        }

        recent_topics.push(help.topic.clone());
        if recent_topics.len() > RECENT_TOPICS_MAX {
            recent_topics.remove(0);
        }
        last_post = Some(Instant::now());
    }
}

/// Recognize topics + an optional help-worthy pick from recent transcript.
async fn recognize(
    http: &reqwest::Client,
    api_key: &str,
    model: &str,
    context: &str,
    recent_topics: &[String],
) -> Option<Recognized> {
    let recent = if recent_topics.is_empty() {
        "(none yet)".to_string()
    } else {
        recent_topics.join(", ")
    };
    let user = format!(
        "Recently covered (do NOT re-surface these): {recent}\n\n\
Conversation (most recent lines last):\n{context}"
    );
    let body = serde_json::json!({
        "model": model,
        "max_tokens": 220,
        "temperature": 0.2,
        "response_format": { "type": "json_object" },
        "messages": [
            { "role": "system", "content": RECOGNIZE_SYSTEM },
            { "role": "user", "content": user },
        ],
    });
    let resp = http
        .post("https://api.groq.com/openai/v1/chat/completions")
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        tracing::debug!(status = %resp.status(), "research: recognize call non-200");
        return None;
    }
    let v: serde_json::Value = resp.json().await.ok()?;
    let content = v
        .get("choices")?
        .get(0)?
        .get("message")?
        .get("content")?
        .as_str()?;
    serde_json::from_str::<Recognized>(content).ok()
}

/// Research a help-worthy topic with the web-search model: a 1-2 sentence
/// definition plus up to two reference links. Returns the post body.
async fn research_topic(cfg: &SharedConfig, api_key: &str, help: &HelpPick) -> Option<String> {
    let prompt = format!(
        "In a live conversation the topic \"{}\" came up. {}\n\n\
Write a SHORT, useful reference for the people talking: 1-2 sentences that \
define or explain it, then up to 2 high-quality links as `Title — URL`. \
Be concise and factual. No greeting, no preamble, no 'here is', just the note.",
        help.topic, help.query
    );
    // Reuse the web-search-capable model the voice path uses for live data.
    match crate::qa::answer(&cfg.http, api_key, &cfg.voice_search_model, "", &prompt).await {
        Ok(a) => {
            let mut body = a.text.trim().to_string();
            // Append the search source as a link when the model didn't already
            // inline one — Chad wants links, the compound model emits them
            // inconsistently in-text.
            if let Some(src) = a.source
                && !body.contains(&src.url)
            {
                body.push_str(&format!("\n🔗 {} — {}", src.title, src.url));
            }
            Some(body)
        }
        Err(e) => {
            tracing::warn!(error = ?e, topic = %help.topic, "research: lookup failed");
            None
        }
    }
}

/// `~/.freeq/bots/<nick>/topics.jsonl` — sibling of the memory db.
fn notes_path_for(nick: &str) -> Option<std::path::PathBuf> {
    dirs_home().map(|h| {
        h.join(".freeq")
            .join("bots")
            .join(nick)
            .join("topics.jsonl")
    })
}

fn dirs_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}

/// Append one JSON line per recognition pass. Best-effort; a notes failure
/// must never disturb the call.
fn append_note(path: &Option<std::path::PathBuf>, channel: &str, topics: &[String]) {
    let Some(path) = path else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = serde_json::json!({ "ts": ts, "channel": channel, "topics": topics });
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}
