//! Tiered context persistence for LLM agents.
//!
//! Solves the fundamental problem: every time an LLM agent restarts, it loses
//! all conversational context. This module provides layered context assembly
//! from multiple sources:
//!
//! - **Tier 0**: Identity & config (always loaded, ~500 tokens)
//! - **Tier 1**: Structured facts & decisions from Memory store (~1-3K tokens)
//! - **Tier 2**: Rolling conversation summaries (~500-1K tokens)
//! - **Tier 3**: Recent raw messages via CHATHISTORY (~2-5K tokens)
//! - **Tier 4**: On-demand retrieval for referenced history (~0-10K tokens)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use freeq_bots::context::{AgentContext, AgentIdentity, ContextConfig};
//! use freeq_bots::memory::Memory;
//! use std::path::Path;
//!
//! let memory = Memory::open(Path::new("agent.db")).unwrap();
//! let identity = AgentIdentity {
//!     nick: "factory".into(),
//!     did: Some("did:web:freeq.at:bots:factory".into()),
//!     role: "Software factory bot".into(),
//!     channels: vec!["#factory".into()],
//!     system_prompt: None,
//! };
//! let config = ContextConfig::default();
//! let ctx = AgentContext::new(identity, memory, config);
//!
//! // Before each LLM call: assemble the context prefix
//! let system_context = ctx.assemble("#factory");
//! ```

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use anyhow::Result;
use chrono::Utc;
use tokio::sync::Mutex;

use crate::llm::LlmClient;
use crate::memory::Memory;
use freeq_sdk::client::ClientHandle;
use freeq_sdk::event::Event;

/// A message from channel history.
#[derive(Debug, Clone)]
pub struct HistoryMessage {
    pub nick: String,
    pub text: String,
    pub timestamp: u64,
    pub msgid: Option<String>,
    pub tags: HashMap<String, String>,
}

/// Agent identity information (Tier 0).
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub nick: String,
    pub did: Option<String>,
    pub role: String,
    pub channels: Vec<String>,
    /// Extra system prompt lines.
    pub system_prompt: Option<String>,
}

/// Configuration for context behavior.
#[derive(Debug, Clone)]
pub struct ContextConfig {
    /// Max messages to fetch via CHATHISTORY on connect.
    pub history_fetch_count: usize,
    /// Max recent messages to keep in the sliding window per channel.
    pub recent_window_size: usize,
    /// How many messages before triggering a summary.
    pub summary_threshold: usize,
    /// How many minutes before forcing a summary.
    pub summary_interval_minutes: u64,
    /// Max structured facts to include in context.
    pub max_facts: usize,
    /// Max tokens (approximate) for the entire context prefix.
    pub max_context_tokens: usize,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            history_fetch_count: 50,
            recent_window_size: 100,
            summary_threshold: 50,
            summary_interval_minutes: 15,
            max_facts: 100,
            max_context_tokens: 10_000,
        }
    }
}

/// Per-channel context state.
struct ChannelContext {
    /// Recent messages (sliding window).
    recent: VecDeque<HistoryMessage>,
    /// Messages since last summary.
    since_summary: usize,
    /// Timestamp of last summary.
    last_summary_at: Option<i64>,
}

impl ChannelContext {
    fn new() -> Self {
        Self {
            recent: VecDeque::new(),
            since_summary: 0,
            last_summary_at: None,
        }
    }
}

/// The main context manager for an LLM agent.
pub struct AgentContext {
    pub identity: AgentIdentity,
    memory: Arc<Memory>,
    config: ContextConfig,
    channels: Mutex<HashMap<String, ChannelContext>>,
}

impl AgentContext {
    /// Create a new context manager.
    pub fn new(identity: AgentIdentity, memory: Arc<Memory>, config: ContextConfig) -> Self {
        Self {
            identity,
            memory,
            config,
            channels: Mutex::new(HashMap::new()),
        }
    }

    // ── Tier 0: Identity ──────────────────────────────────────────────

    fn tier0_identity(&self) -> String {
        let mut parts = vec![format!(
            "## Identity\nYou are **{}**, {}.",
            self.identity.nick, self.identity.role
        )];
        if let Some(did) = &self.identity.did {
            parts.push(format!("DID: `{did}`"));
        }
        if !self.identity.channels.is_empty() {
            parts.push(format!(
                "Active channels: {}",
                self.identity
                    .channels
                    .iter()
                    .map(|c| format!("`{c}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if let Some(sys) = &self.identity.system_prompt {
            parts.push(format!("\n{sys}"));
        }
        parts.join("\n")
    }

    // ── Tier 1: Structured facts & decisions ──────────────────────────

    fn tier1_facts(&self, project: &str) -> String {
        let mut sections = Vec::new();

        // Decisions
        if let Ok(decisions) = self.memory.list(project, "decision")
            && !decisions.is_empty()
        {
            let items: Vec<String> = decisions
                .iter()
                .take(self.config.max_facts)
                .map(|e| format!("- **{}**: {}", e.key, e.value))
                .collect();
            sections.push(format!("## Decisions\n{}", items.join("\n")));
        }

        // Facts
        if let Ok(facts) = self.memory.list(project, "fact")
            && !facts.is_empty()
        {
            let items: Vec<String> = facts
                .iter()
                .take(self.config.max_facts)
                .map(|e| format!("- **{}**: {}", e.key, e.value))
                .collect();
            sections.push(format!("## Known Facts\n{}", items.join("\n")));
        }

        // Commitments / action items
        if let Ok(actions) = self.memory.list(project, "action_item")
            && !actions.is_empty()
        {
            let items: Vec<String> = actions
                .iter()
                .take(20)
                .map(|e| format!("- [ ] {}", e.value))
                .collect();
            sections.push(format!("## Open Action Items\n{}", items.join("\n")));
        }

        // Preferences
        if let Ok(prefs) = self.memory.list(project, "preference")
            && !prefs.is_empty()
        {
            let items: Vec<String> = prefs
                .iter()
                .map(|e| format!("- {}: {}", e.key, e.value))
                .collect();
            sections.push(format!("## User Preferences\n{}", items.join("\n")));
        }

        if sections.is_empty() {
            String::new()
        } else {
            sections.join("\n\n")
        }
    }

    // ── Tier 2: Rolling summary ───────────────────────────────────────

    fn tier2_summary(&self, project: &str) -> String {
        if let Ok(Some(summary)) = self.memory.get(project, "summary", "latest") {
            format!("## Conversation Summary\n{summary}")
        } else {
            String::new()
        }
    }

    // ── Tier 3: Recent raw messages ───────────────────────────────────

    async fn tier3_recent(&self, channel: &str) -> String {
        let channels = self.channels.lock().await;
        let Some(ctx) = channels.get(channel) else {
            return String::new();
        };
        if ctx.recent.is_empty() {
            return String::new();
        }

        let lines: Vec<String> = ctx
            .recent
            .iter()
            .map(|m| {
                let ts = chrono::DateTime::from_timestamp(m.timestamp as i64, 0)
                    .map(|dt| dt.format("%H:%M").to_string())
                    .unwrap_or_default();
                if m.nick == self.identity.nick {
                    format!("[{ts}] <{} (you)> {}", m.nick, m.text)
                } else {
                    format!("[{ts}] <{}> {}", m.nick, m.text)
                }
            })
            .collect();

        format!("## Recent Messages\n```\n{}\n```", lines.join("\n"))
    }

    // ── Assembly ──────────────────────────────────────────────────────

    /// Assemble the full context prefix for a channel.
    ///
    /// The `project` name is used to look up facts/decisions in Memory.
    /// If None, defaults to the channel name (without #).
    pub async fn assemble(&self, channel: &str, project: Option<&str>) -> String {
        let proj = project.unwrap_or_else(|| channel.trim_start_matches('#'));

        let mut parts = Vec::new();

        // Tier 0
        parts.push(self.tier0_identity());

        // Tier 1
        let facts = self.tier1_facts(proj);
        if !facts.is_empty() {
            parts.push(facts);
        }

        // Tier 2
        let summary = self.tier2_summary(proj);
        if !summary.is_empty() {
            parts.push(summary);
        }

        // Tier 3
        let recent = self.tier3_recent(channel).await;
        if !recent.is_empty() {
            parts.push(recent);
        }

        parts.join("\n\n")
    }

    // ── History ingestion ─────────────────────────────────────────────

    /// Ingest messages (typically from CHATHISTORY replay) into a channel's context.
    pub async fn ingest_history(&self, channel: &str, messages: Vec<HistoryMessage>) {
        let mut channels = self.channels.lock().await;
        let ctx = channels
            .entry(channel.to_string())
            .or_insert_with(ChannelContext::new);

        for msg in messages {
            ctx.recent.push_back(msg);
            if ctx.recent.len() > self.config.recent_window_size {
                ctx.recent.pop_front();
            }
        }
    }

    /// Record a single new message (from live events).
    pub async fn record_message(&self, channel: &str, msg: HistoryMessage) {
        let mut channels = self.channels.lock().await;
        let ctx = channels
            .entry(channel.to_string())
            .or_insert_with(ChannelContext::new);

        ctx.recent.push_back(msg);
        if ctx.recent.len() > self.config.recent_window_size {
            ctx.recent.pop_front();
        }
        ctx.since_summary += 1;
    }

    // ── CHATHISTORY fetch helper ──────────────────────────────────────

    /// Fetch recent history for a channel and collect it into HistoryMessages.
    ///
    /// This sends CHATHISTORY LATEST and collects the batch response from the
    /// event stream. Call this right after joining a channel.
    pub async fn fetch_and_ingest(
        &self,
        handle: &ClientHandle,
        events: &mut tokio::sync::mpsc::Receiver<Event>,
        channel: &str,
    ) -> Result<usize> {
        handle
            .history_latest(channel, self.config.history_fetch_count)
            .await?;

        let mut messages = Vec::new();
        let mut in_batch = false;
        let mut batch_id = String::new();

        // Collect events until batch ends or timeout.
        let timeout = tokio::time::Duration::from_secs(5);
        loop {
            match tokio::time::timeout(timeout, events.recv()).await {
                Ok(Some(Event::BatchStart { id, batch_type, .. }))
                    if batch_type == "chathistory" =>
                {
                    in_batch = true;
                    batch_id = id;
                }
                Ok(Some(Event::Message {
                    from,
                    text,
                    tags,
                    target,
                    ..
                })) if in_batch && target == channel => {
                    let timestamp = tags
                        .get("time")
                        .and_then(|t| {
                            chrono::DateTime::parse_from_rfc3339(t)
                                .ok()
                                .map(|dt| dt.timestamp() as u64)
                        })
                        .unwrap_or(0);
                    let msgid = tags.get("msgid").cloned();
                    messages.push(HistoryMessage {
                        nick: from,
                        text,
                        timestamp,
                        msgid,
                        tags,
                    });
                }
                Ok(Some(Event::BatchEnd { id })) if id == batch_id => {
                    break;
                }
                // The server ended the session for good (a final close):
                // the caller ends on it, as on any final refusal.
                Ok(Some(Event::AuthFailed { reason })) => {
                    return Err(freeq_sdk::refusal::Refusal::Final(reason).into());
                }
                Ok(Some(_)) => {
                    // Ignore other events during batch collection
                }
                Ok(None) => break, // channel closed
                Err(_) => break,   // timeout
            }
        }

        let count = messages.len();
        self.ingest_history(channel, messages).await;
        Ok(count)
    }

    // ── Summarization ─────────────────────────────────────────────────

    /// Check if a summary is needed and generate one if so.
    ///
    /// Returns true if a new summary was generated.
    pub async fn maybe_summarize(
        &self,
        channel: &str,
        project: Option<&str>,
        llm: &LlmClient,
    ) -> Result<bool> {
        let needs_summary = {
            let channels = self.channels.lock().await;
            let Some(ctx) = channels.get(channel) else {
                return Ok(false);
            };

            let time_trigger = ctx.last_summary_at.is_none_or(|t| {
                let elapsed = Utc::now().timestamp() - t;
                elapsed > (self.config.summary_interval_minutes as i64 * 60)
            });

            let count_trigger = ctx.since_summary >= self.config.summary_threshold;

            (time_trigger || count_trigger) && !ctx.recent.is_empty()
        };

        if !needs_summary {
            return Ok(false);
        }

        let proj = project.unwrap_or_else(|| channel.trim_start_matches('#'));

        // Build the transcript to summarize
        let transcript = {
            let channels = self.channels.lock().await;
            let ctx = &channels[channel];
            ctx.recent
                .iter()
                .map(|m| format!("<{}> {}", m.nick, m.text))
                .collect::<Vec<_>>()
                .join("\n")
        };

        // Get existing summary for continuity
        let prev_summary = self.memory.get(proj, "summary", "latest")?;

        let prompt = if let Some(prev) = &prev_summary {
            format!(
                "Previous summary:\n{prev}\n\n\
                 New conversation since then:\n{transcript}\n\n\
                 Write an updated summary that:\n\
                 1. Preserves key decisions and commitments from the previous summary\n\
                 2. Incorporates new information\n\
                 3. Drops resolved items\n\
                 4. Stays under 500 words\n\
                 5. Uses bullet points for decisions and action items\n\
                 Focus on: decisions made, tasks assigned, open questions, key facts learned."
            )
        } else {
            format!(
                "Conversation transcript:\n{transcript}\n\n\
                 Write a concise summary (under 500 words) covering:\n\
                 1. Key decisions made\n\
                 2. Tasks assigned or committed to\n\
                 3. Open questions or unresolved issues\n\
                 4. Important facts or context established\n\
                 Use bullet points. Focus on what matters for continuing the conversation later."
            )
        };

        let summary = llm
            .complete(
                "You are a conversation summarizer. Be concise and factual. \
                 Preserve all actionable information. Do not editorialize.",
                &prompt,
            )
            .await?;

        // Store the summary
        self.memory.set(proj, "summary", "latest", &summary)?;

        // Also log it for history
        self.memory.log(
            proj,
            "summary_log",
            &format!("[{}] {summary}", Utc::now().format("%Y-%m-%d %H:%M")),
        )?;

        // Reset counter
        {
            let mut channels = self.channels.lock().await;
            if let Some(ctx) = channels.get_mut(channel) {
                ctx.since_summary = 0;
                ctx.last_summary_at = Some(Utc::now().timestamp());
            }
        }

        tracing::info!(
            channel,
            "Generated conversation summary ({} chars)",
            summary.len()
        );
        Ok(true)
    }

    // ── Fact extraction ───────────────────────────────────────────────

    /// Extract structured facts from a recent exchange and store them.
    ///
    /// Call this after significant exchanges (not every single message).
    pub async fn extract_facts(
        &self,
        channel: &str,
        project: Option<&str>,
        exchange: &str,
        llm: &LlmClient,
    ) -> Result<Vec<(String, String, String)>> {
        let proj = project.unwrap_or_else(|| channel.trim_start_matches('#'));

        let prompt = format!(
            "Extract structured facts from this exchange. Output ONLY a JSON array of objects, \
             each with \"kind\" (one of: decision, fact, preference, action_item, commitment), \
             \"key\" (short label), and \"value\" (the fact). \
             If nothing significant, return an empty array [].\n\n\
             Exchange:\n{exchange}"
        );

        let response = llm
            .complete(
                "You extract structured facts from conversations. \
                 Output valid JSON only, no markdown fences.",
                &prompt,
            )
            .await?;

        // Parse the JSON array
        let facts: Vec<serde_json::Value> = match serde_json::from_str(&response) {
            Ok(v) => v,
            Err(_) => {
                // Try to extract JSON from markdown fences
                let cleaned = response
                    .trim()
                    .strip_prefix("```json")
                    .or_else(|| response.trim().strip_prefix("```"))
                    .unwrap_or(&response)
                    .strip_suffix("```")
                    .unwrap_or(&response)
                    .trim();
                serde_json::from_str(cleaned).unwrap_or_default()
            }
        };

        let mut stored = Vec::new();
        for fact in &facts {
            let kind = fact["kind"].as_str().unwrap_or("fact");
            let key = fact["key"].as_str().unwrap_or("unknown");
            let value = fact["value"].as_str().unwrap_or("");
            if !value.is_empty() {
                self.memory.set(proj, kind, key, value)?;
                stored.push((kind.to_string(), key.to_string(), value.to_string()));
            }
        }

        if !stored.is_empty() {
            tracing::info!(channel, "Extracted {} facts from exchange", stored.len());
        }

        Ok(stored)
    }

    // ── Context file export (for pi bridge) ───────────────────────────

    /// Export the current context to a markdown file.
    ///
    /// Useful for the pi bridge: write this to a file that pi reads on startup.
    pub async fn export_context_file(
        &self,
        channel: &str,
        project: Option<&str>,
        path: &std::path::Path,
    ) -> Result<()> {
        let content = self.assemble(channel, project).await;
        let header = format!(
            "<!-- Auto-generated by freeq agent context system -->\n\
             <!-- Channel: {} | Updated: {} -->\n\n",
            channel,
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        );
        tokio::fs::write(path, format!("{header}{content}")).await?;
        Ok(())
    }

    // ── Convenience: store a fact directly ────────────────────────────

    /// Store a fact, decision, preference, etc. directly.
    pub fn store(&self, project: &str, kind: &str, key: &str, value: &str) -> Result<()> {
        self.memory.set(project, kind, key, value)
    }

    /// Clear a fact or decision.
    pub fn clear(&self, project: &str, kind: &str, key: &str) -> Result<()> {
        self.memory.delete(project, kind, key)
    }

    /// Get recent message count for a channel.
    pub async fn message_count(&self, channel: &str) -> usize {
        let channels = self.channels.lock().await;
        channels.get(channel).map(|c| c.recent.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A final close during the history fetch ends it with a final Refusal
    /// carrying the server's sentence, which the bot's loop ends on.
    #[tokio::test]
    async fn a_final_close_during_the_history_fetch_is_a_final_refusal() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (r, mut w) = stream.into_split();
            let mut lines = BufReader::new(r).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                if l.starts_with("NICK ") {
                    let _ = w.write_all(b":srv 001 testbot :Welcome\r\n").await;
                }
                if l.starts_with("CHATHISTORY") {
                    let _ = w
                        .write_all(
                            b":srv FAIL * ACCOUNT_REQUIRED :This server requires an account.\r\n",
                        )
                        .await;
                }
            }
        });
        let config = freeq_sdk::client::ConnectConfig {
            server_addr: addr,
            nick: "testbot".into(),
            user: "testbot".into(),
            realname: "Test".into(),
            ..Default::default()
        };
        let (handle, mut events) = freeq_sdk::client::connect(config, None);
        loop {
            if let Some(Event::Registered { .. }) = events.recv().await {
                break;
            }
        }
        let mem = Arc::new(Memory::in_memory().unwrap());
        let ctx = AgentContext::new(test_identity(), mem, ContextConfig::default());
        let err = ctx
            .fetch_and_ingest(&handle, &mut events, "#test")
            .await
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<freeq_sdk::refusal::Refusal>(),
            Some(&freeq_sdk::refusal::Refusal::Final(
                "This server requires an account.".into()
            ))
        );
    }

    fn test_identity() -> AgentIdentity {
        AgentIdentity {
            nick: "testbot".into(),
            did: Some("did:key:z6MkTest".into()),
            role: "Test agent".into(),
            channels: vec!["#test".into()],
            system_prompt: None,
        }
    }

    #[tokio::test]
    async fn test_tier0_identity() {
        let mem = Arc::new(Memory::in_memory().unwrap());
        let ctx = AgentContext::new(test_identity(), mem, ContextConfig::default());
        let assembled = ctx.assemble("#test", None).await;
        assert!(assembled.contains("testbot"));
        assert!(assembled.contains("did:key:z6MkTest"));
    }

    #[tokio::test]
    async fn test_ingest_and_recent() {
        let mem = Arc::new(Memory::in_memory().unwrap());
        let ctx = AgentContext::new(test_identity(), mem, ContextConfig::default());

        let msgs = vec![
            HistoryMessage {
                nick: "alice".into(),
                text: "hello world".into(),
                timestamp: 1000,
                msgid: Some("msg1".into()),
                tags: HashMap::new(),
            },
            HistoryMessage {
                nick: "testbot".into(),
                text: "hi alice".into(),
                timestamp: 1001,
                msgid: Some("msg2".into()),
                tags: HashMap::new(),
            },
        ];

        ctx.ingest_history("#test", msgs).await;
        let assembled = ctx.assemble("#test", None).await;
        assert!(assembled.contains("hello world"));
        assert!(assembled.contains("(you)"));
        assert_eq!(ctx.message_count("#test").await, 2);
    }

    #[tokio::test]
    async fn test_sliding_window() {
        let mem = Arc::new(Memory::in_memory().unwrap());
        let config = ContextConfig {
            recent_window_size: 3,
            ..Default::default()
        };
        let ctx = AgentContext::new(test_identity(), mem, config);

        for i in 0..5 {
            ctx.record_message(
                "#test",
                HistoryMessage {
                    nick: "alice".into(),
                    text: format!("message {i}"),
                    timestamp: 1000 + i,
                    msgid: None,
                    tags: HashMap::new(),
                },
            )
            .await;
        }

        assert_eq!(ctx.message_count("#test").await, 3);
        let assembled = ctx.assemble("#test", None).await;
        assert!(!assembled.contains("message 0"));
        assert!(!assembled.contains("message 1"));
        assert!(assembled.contains("message 2"));
        assert!(assembled.contains("message 4"));
    }

    #[tokio::test]
    async fn test_facts_in_context() {
        let mem = Arc::new(Memory::in_memory().unwrap());
        mem.set("test", "decision", "framework", "Use React")
            .unwrap();
        mem.set("test", "fact", "deployment", "Hosted on Miren")
            .unwrap();

        let ctx = AgentContext::new(test_identity(), mem, ContextConfig::default());
        let assembled = ctx.assemble("#test", None).await;
        assert!(assembled.contains("Use React"));
        assert!(assembled.contains("Hosted on Miren"));
        assert!(assembled.contains("Decisions"));
        assert!(assembled.contains("Known Facts"));
    }

    #[tokio::test]
    async fn test_summary_in_context() {
        let mem = Arc::new(Memory::in_memory().unwrap());
        mem.set(
            "test",
            "summary",
            "latest",
            "We discussed the architecture and decided on React + Rust.",
        )
        .unwrap();

        let ctx = AgentContext::new(test_identity(), mem, ContextConfig::default());
        let assembled = ctx.assemble("#test", None).await;
        assert!(assembled.contains("Conversation Summary"));
        assert!(assembled.contains("decided on React + Rust"));
    }

    #[tokio::test]
    async fn test_export_context_file() {
        let mem = Arc::new(Memory::in_memory().unwrap());
        mem.set("test", "decision", "stack", "Rust + React")
            .unwrap();

        let ctx = AgentContext::new(test_identity(), mem, ContextConfig::default());
        ctx.ingest_history(
            "#test",
            vec![HistoryMessage {
                nick: "alice".into(),
                text: "let's use Rust".into(),
                timestamp: 1000,
                msgid: None,
                tags: HashMap::new(),
            }],
        )
        .await;

        let tmp = std::env::temp_dir().join("freeq-context-test.md");
        ctx.export_context_file("#test", None, &tmp).await.unwrap();

        let content = tokio::fs::read_to_string(&tmp).await.unwrap();
        assert!(content.contains("Auto-generated"));
        assert!(content.contains("Rust + React"));
        assert!(content.contains("let's use Rust"));
        let _ = tokio::fs::remove_file(&tmp).await;
    }
}
