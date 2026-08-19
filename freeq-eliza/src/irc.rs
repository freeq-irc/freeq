//! IRC + AV orchestrator.
//!
//! Runs a single IRC connection, watches every channel the bot is in
//! for `+freeq.at/av-state` TAGMSGs, and — when a session starts —
//! sends `av-join`, opens a MoQ subscriber, taps the audio of every
//! remote participant, runs whisper on rolling windows, and posts the
//! transcript back to the channel.
//!
//! At most one active call at a time. If a second channel starts a
//! call while we're transcribing one, we log and skip.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use freeq_agent_kit::{
    VadConfig, VadSegmenter, extract_addressed, is_hallucination, split_speech_and_links,
};
use freeq_av::{AvConfig, AvParticipant, AvSession, Speaker, VideoHandle, broadcast_path};
use freeq_sdk::auth::KeySigner;
use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::event::Event;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::{JoinHandle, JoinSet};

use crate::identity::Identity;

/// Try to extract an addressed question from `text`. Accepts both the
/// active nick AND "eliza" as wake words — so a user with muscle
/// memory who runs as Oblivion / Narrator / Utopia and says "Eliza,
/// what is X?" still gets through. The character's own name still
/// works too. Returns `None` if neither matches.
fn address_with_aliases(text: &str, nick: &str) -> Option<String> {
    if let Some(q) = extract_addressed(text, nick) {
        return Some(q);
    }
    // Server-suffixed nicks: a fresh DID gets bound as e.g.
    // `oblivion-z6mkfa8x`. Humans address the bot by its character
    // name ("oblivion"), so try the pre-dash prefix as an alias when
    // it differs from the full nick.
    if let Some(prefix) = nick.split_once('-').map(|(p, _)| p)
        && prefix.len() >= 4
        && !prefix.eq_ignore_ascii_case(nick)
        && let Some(q) = extract_addressed(text, prefix)
    {
        return Some(q);
    }
    // No universal "eliza" wake word: in a multi-agent room (Oblivion +
    // Utopia + Narrator), a generic fallback causes every bot to
    // answer every question. Each bot replies only to its own
    // character name.
    None
}

/// Multi-agent chatter guard. Records `asker` in the rolling
/// addressing-chain history and returns `false` if the recent K
/// addressers are *all* peer agents — that's the loop signature.
/// As soon as a human addresses the bot, the streak resets and
/// the next address goes through. Allows up to 2 bot-to-bot
/// exchanges without a human break (so a real "Oblivion, what do
/// you think?" → "Utopia, ..." → "Oblivion, ..." exchange lands)
/// and stops at the 3rd.
fn is_address_allowed(cfg: &SharedConfig, asker: &str) -> bool {
    const HISTORY_KEEP: usize = 5;
    let asker_lc = asker.to_ascii_lowercase();
    let mut chain = cfg
        .addressing_chain
        .lock()
        .expect("addressing chain poisoned");
    chain.push_back(asker_lc.clone());
    while chain.len() > HISTORY_KEEP {
        chain.pop_front();
    }
    // Lone agent (no peers configured) → always allow.
    if cfg.peer_agents.is_empty() {
        return true;
    }
    // Discussion mode: when a human just said "discuss it" /
    // "debate this", peer↔peer replies are temporarily allowed so
    // the agents can converse with each other for ~90 s. Outside the
    // window the strict policy below applies.
    if let Ok(deadline) = cfg.discussion_until.lock()
        && Instant::now() < *deadline
    {
        return true;
    }
    // Multi-agent room: only humans address agents directly. If the
    // current addresser is a known peer agent, suppress — peer ↔ peer
    // exchanges spiral too easily (one bot's reply mentions another
    // by name, which the LLM is happy to do despite the prompt rule
    // against it, and the loop is off).
    !is_peer_nick(&cfg.peer_agents, &asker_lc)
}

/// True if `nick` matches one of `peers` either exactly or by the
/// pre-dash prefix. The server suffixes fresh DIDs with `-<bs58>` so
/// `oblivion-z6mkfa8x` should still match a configured peer of
/// `"oblivion"`. Case-insensitive (`peers` are lowercased on load).
/// True if the operator has armed peer-conversation mode within the
/// last 90 s. Read by `answer_and_speak` (to inject a hand-off
/// instruction into the LLM prompt) and by `is_address_allowed` (to
/// let peer agents reply to each other while the window is open).
fn is_discussion_mode_active(cfg: &SharedConfig) -> bool {
    cfg.discussion_until
        .lock()
        .map(|d| Instant::now() < *d)
        .unwrap_or(false)
}

fn is_peer_nick(peers: &std::collections::HashSet<String>, nick: &str) -> bool {
    let nick_lc = nick.to_ascii_lowercase();
    if peers.contains(&nick_lc) {
        return true;
    }
    if let Some((prefix, _)) = nick_lc.split_once('-')
        && peers.contains(prefix)
    {
        return true;
    }
    false
}
use crate::imagegen::AiImageConfig;
use crate::stt::{SttEngine, to_whisper_pcm};
use crate::video::VideoTile;
use crate::whiteboard::Step;
use crate::{imagegen, qa, summary, tts, vision};

pub struct RunConfig {
    pub server: String,
    pub channels: Vec<String>,
    pub owner: Option<String>,
    pub nick: String,
    pub ident: Identity,
    pub stt: Arc<SttEngine>,
    /// Deepgram API key for streaming STT. When present, each
    /// participant tap opens a Deepgram websocket instead of the local
    /// VAD + batched-Whisper loop — finalised transcripts come back
    /// within a few hundred ms of speech end. Falls back to `stt` when
    /// absent. See [`crate::streaming_stt`].
    pub stt_streaming_key: Option<String>,
    pub window_secs: f32,
    pub summary_model: String,
    pub anthropic_key: Option<String>,
    /// Whether the end-of-call summary path runs (separate from the
    /// per-question answer-model dispatch, which gates on
    /// [`Self::anthropic_key`] presence and the model name).
    pub summary_enabled: bool,
    /// When set, the bot sends an `av-start` for this channel right
    /// after joining — it initiates a call rather than only watching
    /// for one. The channel must also appear in `channels`. The
    /// server's `av-state=started` echo then drives the normal
    /// join/subscribe path.
    pub start_session_in: Option<String>,
    /// Override the MoQ SFU URL. When `None` it's derived from `server`
    /// via [`sfu_url_from_server`]. Set this to the SFU's QUIC port
    /// (e.g. `https://host:4443/av/moq`) to use QUIC instead of the
    /// WebSocket fallback.
    pub sfu_url_override: Option<String>,
    /// Groq API key — powers question-answering (chat). When `None`,
    /// the bot can't answer addressed questions.
    pub groq_api_key: Option<String>,
    /// Groq chat model for the visual board (scene generation).
    pub groq_chat_model: String,
    /// Model for answering addressed questions in *text* (channel
    /// messages). `claude-*` routes to Anthropic, anything else to Groq.
    pub groq_answer_model: String,
    /// Model for answering *spoken* questions in a live call — fast by
    /// default, because time-to-first-word is the whole experience.
    pub voice_answer_model: String,
    /// Model for spoken questions that need LIVE data (weather, news,
    /// prices). A Groq agentic model with server-side web search —
    /// slower than `voice_answer_model` but honest.
    pub voice_search_model: String,
    /// Groq vision model for questions about a participant's shared
    /// screen or camera.
    pub vision_model: String,
    /// ElevenLabs API key + voice + model for speaking answers aloud.
    /// When the key is `None`, answers are posted as text only.
    pub elevenlabs_api_key: Option<String>,
    pub elevenlabs_voice_id: String,
    pub elevenlabs_model: String,
    /// AI image-generation fallback for scene backdrops. `None` leaves
    /// Wikipedia as the only backdrop source.
    pub image_ai: Option<AiImageConfig>,
    /// Enable the proactive monitor — when true, Eliza chimes in
    /// unprompted with high-confidence observations. Toggle with
    /// `--no-proactive` on the CLI.
    pub proactive_enabled: bool,
    /// Enable the ambient monitor — when true, Eliza's tile silently
    /// reflects the topic + colour of the conversation while she
    /// listens, and escalates to an image scene on concrete subjects.
    /// Toggle with `--no-ambient` on the CLI.
    pub ambient_enabled: bool,
    /// Enable the ambient-research monitor — when true and she is NOT being
    /// addressed, she recognizes the topics being discussed, logs them to a
    /// note, and drops definitions/links for help-worthy technical topics into
    /// the text channel. Opt-in via `--ambient-research`.
    pub research_enabled: bool,
    /// Video tile renderer choice. `svg` = the rich freeq presence;
    /// `particles` = ghostly particle face.
    pub render_backend: String,
    /// Ghostly character name when `render_backend == "particles"`.
    pub ghostly_character: String,
    /// Optional path to a custom ghostly `CharacterPack` JSON. When set
    /// (from a `--persona` pack), the face + voice DSP come from this
    /// pack instead of the built-in `ghostly_character`.
    pub ghostly_pack: Option<String>,
    /// Per-character system-prompt override (Oblivion / Narrator /
    /// Utopia personality). `None` falls back to the default Eliza
    /// prompt in `qa.rs`.
    pub character_system_prompt: Option<String>,
    /// Line spoken aloud on joining a call — the persona's greeting.
    /// Resolved once in `main` (from a built-in profile or a loaded
    /// `--persona` pack). `None` = silent on arrival.
    pub persona_hello_line: Option<String>,
    /// Other agent nicks in the channel. When set, the bot can hold a
    /// bounded multi-agent dialogue (e.g. Oblivion + Utopia debating)
    /// but won't run away: after a streak of bot-to-bot exchanges
    /// without a human break, the bot stops responding until a human
    /// addresses it again.
    pub peer_agents: Vec<String>,
    /// External-brain mode. When true the bot does NOT answer addressed
    /// questions with its own model — it forwards them to yokota over a
    /// unix socket (see [`Self::brain_sock`]) and speaks only the lines
    /// yokota sends back. Also disables all self-initiated speaking
    /// (proactive, ambient, hello-on-join, backchannels). Off (default)
    /// = unchanged behavior.
    pub external_brain: bool,
    /// Also forward typed text to the brain and post its reply (opt-in; see
    /// `SharedConfig::external_brain_text`).
    pub external_brain_text: bool,
    /// Audio-only: don't render or publish a video tile in calls (skip the
    /// H.264 encode) so a being can hold a stable voice call on a small host.
    pub no_video: bool,
    /// Path to the unix socket yokota listens on; eliza CONNECTS to it
    /// as a client. Only used when [`Self::external_brain`] is set.
    pub brain_sock: Option<String>,
    /// Disable the per-character voice DSP (the ghostly EQ/reverb chain)
    /// — speak with the neutral/dry profile instead. Off (default) =
    /// unchanged behavior.
    pub no_voice_dsp: bool,
}

/// Subset of [`RunConfig`] shared with inner tasks. Excludes the
/// PrivateKey (already moved into the signer) so it's `Clone`-friendly
/// inside an `Arc`. `pub(crate)` so the [`proactive`](crate::proactive)
/// monitor can read the same config.
pub(crate) struct SharedConfig {
    pub(crate) server: String,
    pub(crate) channels: Vec<String>,
    /// Owner handle/nick — only this identity may issue lifecycle commands.
    pub(crate) owner: Option<String>,
    pub(crate) nick: String,
    pub(crate) stt: Arc<SttEngine>,
    /// Pre-built Deepgram streaming config (nova-3) when a key is set —
    /// shared across all participant taps. `None` = use `stt` (Whisper).
    pub(crate) stt_streaming: Option<Arc<crate::streaming_stt::StreamingSttConfig>>,
    pub(crate) summary_model: String,
    pub(crate) anthropic_key: Option<String>,
    pub(crate) summary_enabled: bool,
    pub(crate) sfu_url_override: Option<String>,
    pub(crate) groq_api_key: Option<String>,
    pub(crate) groq_chat_model: String,
    pub(crate) groq_answer_model: String,
    /// Voice-path answer model (see [`RunConfig::voice_answer_model`]).
    pub(crate) voice_answer_model: String,
    /// Voice-path live-data model (see [`RunConfig::voice_search_model`]).
    pub(crate) voice_search_model: String,
    pub(crate) vision_model: String,
    pub(crate) elevenlabs_api_key: Option<String>,
    pub(crate) elevenlabs_voice_id: String,
    pub(crate) elevenlabs_model: String,
    pub(crate) image_ai: Option<AiImageConfig>,
    /// Shared HTTP client for Groq QA + ElevenLabs TTS calls.
    pub(crate) http: reqwest::Client,
    /// When the bot process started — drives a startup grace period so it
    /// doesn't answer the burst of channel history (and any replayed
    /// audio) the server delivers right after it joins.
    pub(crate) started_at: Instant,
    /// Whether the proactive monitor runs (`--no-proactive` disables it).
    pub(crate) proactive_enabled: bool,
    /// Whether the ambient monitor runs (`--no-ambient` disables it).
    pub(crate) ambient_enabled: bool,
    /// Whether the ambient-research monitor runs (`--ambient-research`).
    pub(crate) research_enabled: bool,
    /// Renderer choice — `"svg"` (default) or `"particles"`.
    pub(crate) render_backend: String,
    /// Ghostly character name when `render_backend == "particles"`.
    pub(crate) ghostly_character: String,
    /// Optional path to a custom ghostly `CharacterPack` JSON (face +
    /// voice DSP). Overrides `ghostly_character` when set.
    pub(crate) ghostly_pack: Option<String>,
    /// Per-character system prompt — when present, replaces the
    /// default Eliza prompt in [`qa::answer_streaming`].
    pub(crate) character_system_prompt: Option<String>,
    /// Greeting spoken on joining a call. `None` = silent on arrival.
    pub(crate) persona_hello_line: Option<String>,
    /// Lowercased nicks of OTHER agents in the channel — peers this
    /// bot recognises by name. Used to prevent multi-agent runaway: a
    /// bot can engage with another bot when called, but won't keep
    /// chaining bot-to-bot replies without a human breaking in. When
    /// empty (the default), this bot acts alone.
    pub(crate) peer_agents: std::collections::HashSet<String>,
    /// Rolling history of the last ~5 addressers (lowercased). When
    /// the recent K (3) are all peer agents, this bot suppresses its
    /// reply — that breaks reply loops between bots. A human
    /// addressing the bot resets the streak immediately.
    pub(crate) addressing_chain:
        std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
    /// Persistent conversation memory — past exchanges queryable via
    /// FTS5. Retrieved before each answer (top-K relevant) and stored
    /// after. `None` if a memory DB couldn't be opened (the bot will
    /// just run without recall).
    pub(crate) memory: Option<std::sync::Arc<crate::memory::Memory>>,
    /// Per-channel decision log — commitments extracted from the live
    /// transcript ("let's ship Friday", "I'll handle the deploy"). Read
    /// back to the channel when the session ends so the room has a
    /// captured summary of what it actually decided. Empty between
    /// sessions; the End handler drains the entry for its channel.
    pub(crate) decisions: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<String, Vec<crate::decisions::Decision>>>,
    >,
    /// Per-channel live diagram — accumulating graph of concepts +
    /// relationships extracted from every transcribed utterance. The
    /// transcribe loop ingests text into the channel's entry; when
    /// new edges appear, the rendered steps are pushed to the
    /// whiteboard. Cleared when the session ends.
    pub(crate) diagrams: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<String, crate::diagram::Diagram>>,
    >,
    /// Deadline (Instant) until which the strict human-only-address
    /// policy is relaxed and bots may answer each other freely. A
    /// human speaking the discussion trigger ("discuss it", "debate
    /// this", …) pushes this 90 s into the future; otherwise it
    /// stays in the past and the strict policy applies.
    pub(crate) discussion_until: std::sync::Arc<std::sync::Mutex<Instant>>,
    /// Lowercased nick → DID, learned from extended-join. Lets a being key
    /// personalization off real identity (DID → Bluesky handle) instead of the
    /// fragile assumption that the nick *is* the handle.
    pub(crate) nick_dids:
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    /// DID → Bluesky handle cache (None = looked up, no handle, e.g. did:key).
    pub(crate) did_handles:
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Option<String>>>>,
    /// Lowercased nicks already greeted this session — proactive greeting fires
    /// at most once per person.
    pub(crate) greeted: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    /// Revenant console base URL — when set, notable answers are auto-captured
    /// as shareable "moment" cards there (the self-propagating viral loop).
    pub(crate) console_url: Option<String>,
    /// Rolling log of text the bot itself spoke through TTS recently
    /// (`(spoken_at, normalized_text)`). A participant whose client has
    /// no echo cancellation leaks the bot's voice from their speakers
    /// back into their mic; the SFU attributes it to THEM, STT
    /// transcribes it, and the addressing gate can fire on it — the bot
    /// then answers its own words, sometimes in a sustained loop.
    /// Every transcript is checked against this log (see
    /// [`is_own_echo`]) before being treated as human speech.
    pub(crate) recent_tts:
        std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<(Instant, String)>>>,
    /// External-brain mode (see [`RunConfig::external_brain`]). When set,
    /// the bot forwards addressed utterances to yokota over the seam
    /// instead of answering itself, and suppresses self-initiated speech.
    pub(crate) external_brain: bool,
    /// Also forward typed TEXT (not just voice) to the brain seam, and post the
    /// brain's reply back as text. Opt-in: default external-brain mode ignores
    /// text (a separate yokota daemon owns it). A self-contained being whose
    /// brain IS the seam server (no separate text daemon) sets this so you can
    /// drive it by typing as well as by voice.
    pub(crate) external_brain_text: bool,
    /// Audio-only mode — skip video render + publish in calls.
    pub(crate) no_video: bool,
    /// Disable per-character voice DSP — speak with the dry/neutral
    /// profile (see [`RunConfig::no_voice_dsp`]).
    pub(crate) no_voice_dsp: bool,
    /// The external-brain seam sender, set after the live-call slot
    /// exists (it needs both the [`SharedConfig`] and the `active`
    /// handle). Empty unless `external_brain && brain_sock.is_some()`.
    /// The emit site reads it to forward addressed utterances to yokota.
    pub(crate) brain_seam: std::sync::OnceLock<crate::brain_seam::SeamHandle>,
    /// The freeq handle — set once connected, so the seam can POST text replies
    /// to the channel when there's no live call (text-mode beings).
    pub(crate) client_handle: std::sync::OnceLock<Arc<ClientHandle>>,
}

/// Active-call state. Held inside an `Arc<AsyncMutex<Option<...>>>`
/// because the av-state handler and the av-state=ended handler need
/// to mutate it from different async paths. `pub(crate)` so the
/// proactive monitor can snapshot the transcript + speaker.
pub(crate) struct ActiveCall {
    pub(crate) channel: String,
    pub(crate) session_id: String,
    pub(crate) instance_id: String,
    /// When the bot joined THIS call. The voice grace is relative to this,
    /// not process start, so a restart/wake mid-call doesn't deafen her to
    /// live questions — it only skips the brief audio burst right after join.
    pub(crate) joined_at: Instant,
    /// Lines of `<nick>: <utterance>` heard so far. Buffered as context
    /// for answering questions and the end-of-call summary — never
    /// posted to the channel.
    pub(crate) transcript: Vec<String>,
    /// When Eliza last dispatched a spoken answer (or proactive comment).
    /// Drives a debounce so one question — transcribed once per broadcast
    /// when a speaker is joined from several devices — is answered only
    /// once, and so the proactive monitor doesn't pile on right after
    /// she just spoke.
    pub(crate) last_answer: Option<Instant>,
    /// The last question we actually dispatched an answer for. The debounce
    /// is content-aware: a repeat is dropped only when it closely matches
    /// this within the (short) window — so multi-device duplicate broadcasts
    /// are deduped, but a genuine conversational follow-up is always answered.
    pub(crate) last_question: Option<String>,
    /// Feeds the bot's outbound broadcast — `enqueue` makes it speak.
    pub(crate) speaker: Speaker,
    /// The agent's video tile (audio-reactive presence + visual-aid
    /// cards). `show_card` puts up an LLM-drawn visual.
    pub(crate) video: VideoTile,
    /// Live nick → video-handle map across this call's taps, so a typed
    /// question can find the asker's camera (see [`CallVideoTaps`]).
    pub(crate) video_taps: CallVideoTaps,
    /// The MoQ subscriber/publisher task. Aborted by `Drop` on call
    /// end — a plain `JoinHandle` drop only *detaches*, which would
    /// leave the reconnect loop running forever after the call ends.
    moq_task: JoinHandle<()>,
    /// The proactive-monitor task (if enabled). Same drop story.
    proactive_task: Option<JoinHandle<()>>,
    /// The ambient-monitor task (if enabled). Same drop story.
    ambient_task: Option<JoinHandle<()>>,
    /// The ambient-research-monitor task (if enabled). Same drop story.
    research_task: Option<JoinHandle<()>>,
    /// Watchdog that leaves the call once we've been alone in it too long, so a
    /// lingering empty call doesn't burn CPU or block auto-sleep. Same drop story.
    lonely_task: Option<JoinHandle<()>>,
    /// IRC handle — Drop uses it to send av-leave. Without that, the
    /// server keeps counting us as an active participant after the MoQ
    /// teardown, and a session everyone has silently abandoned can never
    /// reach zero participants and auto-end — it haunts the channel
    /// forever, re-summoning every bot on each reconnect.
    handle: Arc<ClientHandle>,
}

impl Drop for ActiveCall {
    fn drop(&mut self) {
        self.moq_task.abort();
        if let Some(t) = &self.proactive_task {
            t.abort();
        }
        if let Some(t) = &self.ambient_task {
            t.abort();
        }
        if let Some(t) = &self.research_task {
            t.abort();
        }
        if let Some(t) = &self.lonely_task {
            t.abort();
        }
        self.video.stop();
        // Tell the server we left. Idempotent when the session already
        // ended (the server re-marks an already-left participant), so
        // every drop path — lonely watchdog, owner "leave", replaced
        // call, session end — can share it. Drop can't await; spawn the
        // send if a runtime is still up (at shutdown the QUIT/connection
        // teardown cleans our slot server-side instead).
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let handle = self.handle.clone();
            let channel = self.channel.clone();
            let session_id = self.session_id.clone();
            let instance_id = self.instance_id.clone();
            rt.spawn(async move {
                let _ = handle.av_leave(&channel, &session_id, &instance_id).await;
            });
        }
    }
}

pub async fn run(cfg: RunConfig) -> Result<()> {
    // Destructure up front so we own the individual fields; the cfg
    // we hand to the inner tasks (wrapped in Arc) is rebuilt below
    // without the moved-out PrivateKey.
    let RunConfig {
        server,
        channels,
        owner,
        nick,
        ident: Identity { did, private_key },
        stt,
        stt_streaming_key,
        window_secs: _window_secs,
        summary_model,
        anthropic_key,
        summary_enabled,
        start_session_in,
        sfu_url_override,
        groq_api_key,
        groq_chat_model,
        groq_answer_model,
        voice_answer_model,
        voice_search_model,
        vision_model,
        elevenlabs_api_key,
        elevenlabs_voice_id,
        elevenlabs_model,
        image_ai,
        proactive_enabled,
        ambient_enabled,
        research_enabled,
        render_backend,
        ghostly_character,
        ghostly_pack,
        character_system_prompt,
        persona_hello_line,
        peer_agents,
        external_brain,
        external_brain_text,
        no_video,
        brain_sock,
        no_voice_dsp,
    } = cfg;

    // Pick websocket vs raw-TCP transport based on URL scheme — mirrors
    // freeq-av-client's heuristic.
    let websocket_url = if server.starts_with("ws://")
        || server.starts_with("wss://")
        || server.starts_with("http://")
        || server.starts_with("https://")
    {
        Some(server.clone())
    } else {
        None
    };
    let server_addr = if let Some(ref ws) = websocket_url {
        // server_addr is unused on the WS path; pass a synthetic so
        // ConnectConfig::validate is happy.
        let u: url::Url = ws.parse().context("parsing WebSocket URL")?;
        let host = u.host_str().unwrap_or("localhost");
        format!("{host}:443")
    } else {
        server.clone()
    };

    let conn_config = ConnectConfig {
        server_addr,
        nick: nick.clone(),
        user: nick.clone(),
        realname: "freeq-eliza".to_string(),
        tls: websocket_url.is_some()
            || server.starts_with("https://")
            || server.starts_with("wss://"),
        tls_insecure: false,
        web_token: None,
        websocket_url,
    };

    let signer = Arc::new(KeySigner::new(did, private_key));
    let (handle, mut events) = client::connect(conn_config, Some(signer));

    // Wait for registration.
    let nick = wait_for_registration(&mut events).await?;
    tracing::info!(%nick, "registered with server");

    // Register as agent + minimal provenance so users can /whois us.
    let _ = handle.register_agent("agent").await;
    let _ = handle
        .submit_provenance(&serde_json::json!({
            "name": "freeq-eliza",
            "version": env!("CARGO_PKG_VERSION"),
            "runtime": "freeq-sdk/rust",
            "capabilities": ["av-transcription", "summary"],
            // Provenance: who owns this being. (Soft today — a verifiable
            // owner→bot delegation cert needs the Bluesky-OAuth onboarding.)
            "owner": owner.clone(),
            "persona": nick.clone(),
        }))
        .await;
    let _ = handle
        .set_presence("active", Some("Listening for AV sessions"), None)
        .await;

    for ch in &channels {
        handle
            .join(ch)
            .await
            .with_context(|| format!("joining {ch}"))?;
        tracing::info!(channel = %ch, "joined");
    }

    let active: Arc<AsyncMutex<Option<ActiveCall>>> = Arc::new(AsyncMutex::new(None));

    // Persistent conversation memory — per-bot SQLite at
    // ~/.freeq/bots/<name>/memory.db. Soft failure: if it can't open,
    // the bot runs without recall.
    let memory = dirs::home_dir()
        .map(|h| h.join(".freeq").join("bots").join(&nick).join("memory.db"))
        .and_then(|p| match crate::memory::Memory::open(&p) {
            Ok(m) => {
                tracing::info!(path = %p.display(), "memory store ready");
                Some(std::sync::Arc::new(m))
            }
            Err(e) => {
                tracing::warn!(path = %p.display(), error = ?e, "failed to open memory store — bot will run without recall");
                None
            }
        });

    // Reassemble a sharable config without the (already-moved) private
    // key for the inner tasks.
    let cfg = Arc::new(SharedConfig {
        server,
        channels,
        owner,
        nick,
        stt,
        stt_streaming: stt_streaming_key
            .filter(|k| !k.trim().is_empty())
            .map(|k| Arc::new(crate::streaming_stt::StreamingSttConfig::nova_3(k))),
        summary_model,
        anthropic_key,
        summary_enabled,
        sfu_url_override,
        groq_api_key,
        groq_chat_model,
        groq_answer_model,
        voice_answer_model,
        voice_search_model,
        vision_model,
        elevenlabs_api_key,
        elevenlabs_voice_id,
        elevenlabs_model,
        image_ai,
        // External-brain mode owns all speaking: the local model never
        // initiates. Force the proactive + ambient monitors off so they
        // can't talk over yokota's lines (off-flag = unchanged).
        proactive_enabled: proactive_enabled && !external_brain,
        ambient_enabled: ambient_enabled && !external_brain,
        research_enabled: research_enabled && !external_brain,
        render_backend,
        ghostly_character,
        ghostly_pack,
        character_system_prompt,
        persona_hello_line,
        peer_agents: peer_agents.iter().map(|n| n.to_ascii_lowercase()).collect(),
        addressing_chain: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::VecDeque::new(),
        )),
        memory,
        decisions: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        diagrams: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        discussion_until: std::sync::Arc::new(std::sync::Mutex::new(
            Instant::now() - Duration::from_secs(3600),
        )),
        nick_dids: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        did_handles: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        greeted: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        console_url: std::env::var("REVENANT_CONSOLE_URL")
            .ok()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty()),
        http: reqwest::Client::new(),
        started_at: Instant::now(),
        recent_tts: std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
        external_brain,
        external_brain_text,
        no_video,
        no_voice_dsp,
        brain_seam: std::sync::OnceLock::new(),
        client_handle: std::sync::OnceLock::new(),
    });
    let handle_arc = Arc::new(handle);
    let _ = cfg.client_handle.set(handle_arc.clone()); // so the seam can post text replies

    // External-brain seam — connect to yokota's unix socket as a client.
    // Stored on the (Arc'd) SharedConfig so the emit site can forward
    // addressed utterances, and given the live-call slot so an inbound
    // "say" speaks against whatever call is active. No-op unless both
    // `--external-brain` and `--brain-sock` are set.
    // Connect whenever a brain socket is configured — not only in full
    // external-brain mode. In native mode the seam stays idle until the
    // router classifies a request as an agentic TASK, at which point the
    // emit site forwards a `Delegate` to the Claude Code brain (smart
    // hand-off); `external_brain` additionally forwards EVERY utterance.
    if external_brain || brain_sock.is_some() {
        if let Some(sock) = brain_sock.clone() {
            let seam = crate::brain_seam::connect(cfg.clone(), sock, active.clone());
            let _ = cfg.brain_seam.set(seam);
        } else {
            tracing::warn!(
                "--external-brain set but --brain-sock missing; bot will stay silent on addressed questions"
            );
        }
    }

    // Discover-or-start. If `--start-session-in` is set we want a call
    // running — but a blind `av-start` is rejected by the server when
    // the channel already has an active session (e.g. a previous test,
    // or a human already calling). So: ask the REST API first.
    //   - active session exists → join it directly (av-join + subscribe)
    //   - no session → send av-start; the `av-state=started` echo drives
    //     the subscribe path via the normal Start handler.
    // `self_start` carries the av-start instance so the Start handler
    // reuses it and skips a redundant av-join (no double-appearance).
    let mut self_start: Option<(String, String)> = None;
    if let Some(ref start_ch) = start_session_in {
        if !cfg
            .channels
            .iter()
            .any(|c| c.eq_ignore_ascii_case(start_ch))
        {
            tracing::warn!(channel = %start_ch, "start-session channel is not in --channel; skipping");
        } else if let Some(session_id) = discover_active_session(&cfg, start_ch).await {
            tracing::info!(channel = %start_ch, %session_id, "joining existing session");
            match start_transcription(
                cfg.clone(),
                handle_arc.clone(),
                start_ch.clone(),
                session_id.clone(),
                None,
                active.clone(),
            )
            .await
            {
                Ok(call) => {
                    spawn_hello_on_join(&cfg, call.speaker.clone(), call.video.peer_level_handle());
                    *active.lock().await = Some(call);
                }
                Err(e) => tracing::warn!(error = ?e, "failed to join existing session"),
            }
        } else {
            let instance = freeq_sdk::av::new_av_instance();
            handle_arc
                .av_start(start_ch, &instance, Some("transcribed session"))
                .await
                .with_context(|| format!("sending av-start to {start_ch}"))?;
            tracing::info!(channel = %start_ch, %instance, "sent av-start — initiating a call");
            self_start = Some((start_ch.to_lowercase(), instance));
        }
    }

    // On (re)connect, rejoin any call already in progress in one of our channels
    // — e.g. after a restart or a wake-from-sleep mid-call. The reactive handler
    // below only fires on a *new* av-state=started, so without this a restarted
    // bot sits in the text channel while a live call carries on without it. The
    // --start-session-in path above already handled its own channel. One call max.
    {
        let no_active = active.lock().await.is_none();
        if no_active {
            for ch in cfg.channels.iter() {
                if start_session_in
                    .as_ref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(ch))
                {
                    continue; // already handled above
                }
                if let Some(session_id) = discover_active_session(&cfg, ch).await {
                    tracing::info!(channel = %ch, %session_id, "rejoining active call on connect");
                    match start_transcription(
                        cfg.clone(),
                        handle_arc.clone(),
                        ch.clone(),
                        session_id.clone(),
                        None,
                        active.clone(),
                    )
                    .await
                    {
                        Ok(call) => {
                            spawn_hello_on_join(
                                &cfg,
                                call.speaker.clone(),
                                call.video.peer_level_handle(),
                            );
                            *active.lock().await = Some(call);
                            break; // at most one active call at a time
                        }
                        Err(e) => tracing::warn!(error = ?e, "failed to rejoin active call"),
                    }
                }
            }
        }
    }

    // Graceful shutdown. On SIGTERM (systemctl stop — how the watcher puts us to
    // sleep), explicitly drop the call and PART our channels before exiting. An
    // abrupt disconnect leaves the server's 30s ghost membership, so the bot
    // appears to linger in the channel after sleeping; an explicit PART removes
    // it immediately. This runs BEFORE the watcher suspends the VM, because
    // `systemctl stop` waits for us to exit.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    loop {
        let event = tokio::select! {
            ev = events.recv() => ev,
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM — leaving call + channels cleanly before shutdown");
                *active.lock().await = None; // drop the call → MoQ teardown (leaves video)
                for ch in &cfg.channels {
                    let _ = handle_arc.raw(&format!("PART {ch} :resting")).await;
                }
                let _ = handle_arc.quit(Some("resting")).await;
                tokio::time::sleep(std::time::Duration::from_millis(400)).await; // let it flush
                return Ok(());
            }
        };
        let Some(event) = event else {
            tracing::warn!("event stream closed");
            return Ok(());
        };
        match event {
            Event::TagMsg {
                from: _,
                target,
                tags,
                ..
            } => {
                let actor = tags.get("+freeq.at/av-actor").cloned().unwrap_or_default();
                match classify_av_event(&target, &tags, &cfg.channels, &cfg.nick) {
                    AvAction::Start {
                        channel,
                        session_id,
                    } => {
                        let mut active_guard = active.lock().await;
                        if active_guard.is_some() {
                            tracing::info!(channel = %channel, "already in a call; ignoring new session");
                            continue;
                        }
                        // If this is the session WE started, the av-start
                        // already registered us as the creator participant.
                        // Reuse that instance and skip the redundant
                        // av-join — otherwise the bot occupies two slots
                        // and shows up twice in every client.
                        let existing_instance = match &self_start {
                            Some((ch, inst)) if ch.eq_ignore_ascii_case(&channel) => {
                                Some(inst.clone())
                            }
                            _ => None,
                        };
                        match start_transcription(
                            cfg.clone(),
                            handle_arc.clone(),
                            channel.clone(),
                            session_id.clone(),
                            existing_instance,
                            active.clone(),
                        )
                        .await
                        {
                            Ok(call) => {
                                tracing::info!(
                                    channel = %channel,
                                    session_id = %session_id,
                                    "started transcription"
                                );
                                // Debugging affordance: speak a short,
                                // in-character greeting the moment the
                                // call is live. Lets the operator hear
                                // which agents are alive (and which
                                // aren't) without typing anything. Fires
                                // only once per call — the speaker
                                // clone keeps the audio queued even if
                                // the bot's task panics elsewhere.
                                spawn_hello_on_join(
                                    &cfg,
                                    call.speaker.clone(),
                                    call.video.peer_level_handle(),
                                );
                                // Backchannels: listen-mode "mm" /
                                // "right" while a peer is talking.
                                // Aborts when the call's MoQ task
                                // drops (the speaker handle stops
                                // accepting enqueues).
                                drop(spawn_backchannel_loop(
                                    cfg.clone(),
                                    call.speaker.clone(),
                                    call.video.peer_level_handle(),
                                ));
                                *active_guard = Some(call);
                            }
                            Err(e) => {
                                tracing::warn!(error = ?e, "failed to start transcription");
                            }
                        }
                    }
                    AvAction::End {
                        channel,
                        session_id,
                    } => {
                        let mut active_guard = active.lock().await;
                        let Some(call) = active_guard.take() else {
                            continue;
                        };
                        if call.session_id != session_id {
                            // ended event for a different session
                            *active_guard = Some(call);
                            continue;
                        }
                        let cfg = cfg.clone();
                        let handle = handle_arc.clone();
                        let channel_for_post = channel.clone();
                        let transcript = call.transcript.join("\n");
                        // Drop the active call (tears down MoQ task).
                        drop(call);
                        drop(active_guard);

                        // Decision read-back: drain the per-channel
                        // decision log and post it to the channel. The
                        // room hears what it actually committed to
                        // without anyone taking notes — the demo
                        // proof-of-concept for "conversation as the
                        // source of knowledge work".
                        let drained: Vec<crate::decisions::Decision> = cfg
                            .decisions
                            .lock()
                            .ok()
                            .and_then(|mut g| g.remove(&channel_for_post))
                            .unwrap_or_default();
                        if !drained.is_empty() {
                            let _ = handle
                                .privmsg(
                                    &channel_for_post,
                                    "[eliza] decisions captured this session:",
                                )
                                .await;
                            for d in &drained {
                                let line = match &d.when {
                                    Some(w) => {
                                        format!("[eliza]  • {} — {} (by {})", d.who, d.what, w)
                                    }
                                    None => format!("[eliza]  • {} — {}", d.who, d.what),
                                };
                                let _ = handle.privmsg(&channel_for_post, &line).await;
                            }
                        }

                        // Clear the live diagram so the next session
                        // starts on a blank canvas.
                        if let Ok(mut g) = cfg.diagrams.lock() {
                            g.remove(&channel_for_post);
                        }

                        if !cfg.summary_enabled
                            || cfg.anthropic_key.is_none()
                            || transcript.is_empty()
                        {
                            let _ = handle
                                .privmsg(&channel_for_post, "[transcript] session ended.")
                                .await;
                            continue;
                        }
                        tokio::spawn(async move {
                            if let Some(key) = &cfg.anthropic_key {
                                match summary::summarize(
                                    key,
                                    &cfg.summary_model,
                                    &channel_for_post,
                                    &transcript,
                                )
                                .await
                                {
                                    Ok(s) => {
                                        let _ = handle
                                            .privmsg(
                                                &channel_for_post,
                                                "[transcript] session ended.",
                                            )
                                            .await;
                                        post_long(&handle, &channel_for_post, &s).await;
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = ?e, "summary failed");
                                        let _ = handle
                                            .privmsg(
                                                &channel_for_post,
                                                &format!(
                                                    "[transcript] session ended; summary failed: {e}"
                                                ),
                                            )
                                            .await;
                                    }
                                }
                            }
                        });
                    }
                    AvAction::Joined {
                        channel,
                        session_id,
                    } => {
                        // A human (re)joined a call we may not be in.
                        // The classifier already filtered self-joins;
                        // peer-agent joins must not summon us either —
                        // two bots re-joining on each other's joins
                        // would ping-pong forever.
                        if is_peer_nick(&cfg.peer_agents, &actor) {
                            tracing::debug!(channel = %channel, %actor, "peer agent joined a call — not following");
                            continue;
                        }
                        let mut active_guard = active.lock().await;
                        if active_guard.is_some() {
                            // Already in a call (this one or another) —
                            // nothing to do.
                            continue;
                        }
                        tracing::info!(
                            channel = %channel,
                            session_id = %session_id,
                            %actor,
                            "human joined a call we're not in — joining"
                        );
                        match start_transcription(
                            cfg.clone(),
                            handle_arc.clone(),
                            channel.clone(),
                            session_id.clone(),
                            None,
                            active.clone(),
                        )
                        .await
                        {
                            Ok(call) => {
                                spawn_hello_on_join(
                                    &cfg,
                                    call.speaker.clone(),
                                    call.video.peer_level_handle(),
                                );
                                drop(spawn_backchannel_loop(
                                    cfg.clone(),
                                    call.speaker.clone(),
                                    call.video.peer_level_handle(),
                                ));
                                *active_guard = Some(call);
                            }
                            Err(e) => {
                                tracing::warn!(error = ?e, "failed to join call on human join");
                            }
                        }
                    }
                    AvAction::Noop => {
                        tracing::debug!(channel = %target, %actor, "av-state");
                    }
                    AvAction::Skip => {}
                }
            }
            Event::Message {
                from, target, text, ..
            } => {
                // Direct message (target is our own nick): a DM is inherently
                // addressed, so in external-brain-text mode forward the whole
                // text to the brain and let it reply privately (to=from). This
                // lets the owner converse with the being fully privately,
                // without exposing the question in a channel.
                if target.eq_ignore_ascii_case(&cfg.nick) {
                    if !from.eq_ignore_ascii_case(&cfg.nick)
                        && cfg.external_brain
                        && cfg.external_brain_text
                        && let Some(seam) = cfg.brain_seam.get()
                    {
                        let q = text.trim().to_string();
                        if !q.is_empty() {
                            tracing::info!(%from, question = %q, "external-brain(text): forwarding DM to brain");
                            seam.send(crate::brain_seam::Outbound::Utterance {
                                nick: from.clone(),
                                text: q,
                            });
                        }
                    }
                    continue;
                }
                // Answer when a participant addresses the bot by name in
                // channel chat. Ignore non-channel targets and our own
                // messages (the bot posts to the channel too).
                if !target.starts_with('#') && !target.starts_with('&') {
                    continue;
                }
                if from.eq_ignore_ascii_case(&cfg.nick) {
                    continue;
                }
                // Shared whiteboard: peer agents emit "[diag] X|R|Y"
                // bullets to broadcast new edges. We parse those into
                // our local diagram so every tile draws the same
                // whiteboard. Skip the address path entirely for these.
                if let Some(rest) = text.strip_prefix("[diag] ") {
                    if is_peer_nick(&cfg.peer_agents, &from) {
                        let parts: Vec<&str> = rest.splitn(3, '|').collect();
                        if parts.len() == 3 {
                            // Ingest under the sync lock, then DROP the
                            // guard before awaiting — holding it across
                            // `active.lock().await` makes `run`'s future
                            // non-Send (it can't be tokio::spawn'ed).
                            let steps = match cfg.diagrams.lock() {
                                Ok(mut log) => {
                                    let d = log.entry(target.clone()).or_default();
                                    let sentence =
                                        format!("{} {} {}", parts[0], parts[1], parts[2]);
                                    if d.ingest(&sentence) > 0 {
                                        Some(d.to_steps())
                                    } else {
                                        None
                                    }
                                }
                                Err(_) => None,
                            };
                            if let Some(steps) = steps
                                && !steps.is_empty()
                                && let Some(call) = active.lock().await.as_ref()
                            {
                                call.video.show_board(steps, "#7FE7CB".into());
                            }
                        }
                    }
                    continue;
                }
                let Some(question) = address_with_aliases(&text, &cfg.nick) else {
                    continue;
                };
                // Don't answer the burst of channel history the server
                // replays right after the bot joins — those messages predate
                // the bot. (This also stops a replayed "go to sleep" from
                // re-sleeping us the instant we wake, so it must come first.)
                if cfg.started_at.elapsed() < STARTUP_GRACE {
                    tracing::info!(%from, "ignoring addressed chat message (startup grace)");
                    continue;
                }
                // Owner lifecycle command by text ("go to sleep", "join #x",
                // "leave") — owner-only.
                if is_owner(&cfg, &from)
                    && let Some(cmd) = parse_owner_command(&question)
                {
                    if let OwnerCmd::Fork(utt) = cmd {
                        // Mitosis runs in its own task (slow: VM fork +
                        // boot) and speaks its progress when on a call.
                        let speaker = active.lock().await.as_ref().map(|c| c.speaker.clone());
                        crate::mitosis::spawn(
                            cfg.clone(),
                            handle_arc.clone(),
                            target.clone(),
                            utt,
                            speaker,
                        );
                    } else {
                        run_owner_command(&handle_arc, Some(&target), cmd).await;
                    }
                    continue;
                }
                // Multi-agent chatter guard: if the last several
                // addressers are all peer bots (no human breaking in),
                // stop responding. A human addressing me resets the
                // streak so the next exchange goes through.
                if !is_address_allowed(&cfg, &from) {
                    tracing::info!(
                        %from,
                        "suppressing chat reply — recent addressers all peer agents (waiting for a human)"
                    );
                    continue;
                }
                if cfg.groq_api_key.is_none() {
                    let _ = handle_arc
                        .privmsg(
                            &target,
                            &format!("{from}: Q&A needs a Groq key — not configured."),
                        )
                        .await;
                    continue;
                }
                // A typed question gets a typed answer — pass no speaker
                // or video so `answer_and_speak` posts text rather than
                // speaking it. The call transcript is still useful context,
                // and if the asker is on the call with a camera, their
                // video handle rides along so "what do you see?" typed in
                // the channel works the same as asked by voice.
                let (transcript, asker_video, screen_video) = {
                    let mut guard = active.lock().await;
                    match guard.as_mut() {
                        Some(c) => {
                            // Snapshot before pushing, then record the typed
                            // question as a transcript line — the call heard
                            // it (the bot answers aloud in the channel), so
                            // the conversation log must carry it.
                            let snapshot = recent_lines(&c.transcript, TRANSCRIPT_PROMPT_LINES);
                            c.transcript.push(format!("{from}: {question}"));
                            (
                                snapshot,
                                lookup_tap_video(&c.video_taps, &from),
                                lookup_tap_video(&c.video_taps, "screen"),
                            )
                        }
                        None => (String::new(), None, None),
                    }
                };
                // External-brain mode: the main yokota daemon is in this same
                // channel and owns ALL typed text — it answers there directly.
                // eliza only handles SPOKEN audio in external-brain mode, so
                // ignore typed questions here; forwarding them too would make
                // the bot answer twice (text reply + spoken/seam reply).
                if cfg.external_brain {
                    // Default: a separate yokota daemon owns typed text — ignore
                    // it here. Opt-in (external_brain_text): this being's brain
                    // IS the seam, so forward typed text too; the reply posts back
                    // as channel text (see brain_seam::speak_inbound).
                    if cfg.external_brain_text
                        && let Some(seam) = cfg.brain_seam.get()
                    {
                        tracing::info!(%from, %question, "external-brain(text): forwarding typed question to brain");
                        seam.send(crate::brain_seam::Outbound::Utterance {
                            nick: from.clone(),
                            text: question.clone(),
                        });
                    }
                    continue;
                }
                let cfg = cfg.clone();
                let handle = handle_arc.clone();
                let channel = target.clone();
                let asker = from.clone();
                let active = active.clone();
                tokio::spawn(async move {
                    answer_and_speak(
                        cfg,
                        handle,
                        channel,
                        asker,
                        question,
                        transcript,
                        None,
                        None,
                        asker_video,
                        screen_video,
                        Some(active),
                        None, // text path — no voice-turn latency anchor
                    )
                    .await;
                });
            }
            Event::Joined {
                channel,
                nick,
                account,
            } => {
                tracing::info!(%nick, %channel, has_account = account.is_some(), "Event::Joined");
                // Learn the joiner's real identity (extended-join DID) so
                // personalization keys off identity, not their freeq nick.
                if let Some(did) = account
                    && let Ok(mut m) = cfg.nick_dids.lock()
                {
                    m.insert(nick.to_ascii_lowercase(), did);
                }
                // Proactive "it knows me" greeting — only in our channels, and
                // past the startup grace so we don't greet a reconnect backlog.
                if cfg
                    .channels
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(&channel))
                    && cfg.started_at.elapsed() > Duration::from_secs(8)
                {
                    spawn_join_greeting(cfg.clone(), handle_arc.clone(), channel, nick);
                }
            }
            Event::Disconnected { reason } => {
                tracing::warn!(%reason, "disconnected");
                return Ok(());
            }
            _ => {}
        }
    }
}

/// A brief, varied "thinking" filler spoken the instant she's addressed —
/// played in parallel with the model call so the wait reads as a person
/// considering, not dead air. Returns `None` for short utterances (answer
/// straight away) and skips a fraction of the time so it never tics; gated to
/// substantial questions, where the model is slow enough that the beat masks
/// real latency rather than adding it. Deterministic (keyed off the question)
/// so the phrase rotates without RNG.
fn thinking_beat(question: &str) -> Option<String> {
    if question.split_whitespace().count() < 6 {
        return None;
    }
    const BEATS: [&str; 6] = [
        "Hmm,",
        "Let me think.",
        "Okay,",
        "Let's see.",
        "Right,",
        "Good question.",
    ];
    let h: usize = question.bytes().map(|b| b as usize).sum();
    if h.is_multiple_of(5) {
        return None; // sometimes just answer — keeps the rhythm from feeling canned
    }
    Some(BEATS[h % BEATS.len()].to_string())
}

/// How long a spoken sentence stays in the echo log. Long enough to
/// cover the full acoustic round-trip (TTS synth → playout → the
/// participant's speakers → their mic → SFU → our STT) plus a long
/// answer still being spoken; short enough that a human legitimately
/// *quoting* the bot a minute later isn't suppressed.
const ECHO_WINDOW: Duration = Duration::from_secs(45);
/// Most entries kept — a runaway answer can't grow the log unbounded.
const ECHO_LOG_CAP: usize = 64;

pub(crate) type RecentTts =
    std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<(Instant, String)>>>;

/// Lowercased alphanumeric words — the normalization both sides of the
/// echo comparison go through, so punctuation/casing drift from the
/// STT round-trip doesn't defeat the match.
fn echo_words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Record a sentence the bot is about to speak. Called from every TTS
/// site that speaks full sentences: answers, hello-on-join, proactive
/// comments, mitosis progress. Backchannels ("mm", "right") are
/// deliberately NOT recorded — they're short, heavily attenuated, and
/// logging them would make the guard eat a human's own "right"/"okay".
pub(crate) fn note_spoken(recent: &RecentTts, text: &str) {
    let Ok(mut log) = recent.lock() else { return };
    let now = Instant::now();
    log.push_back((now, text.to_string()));
    while log.len() > ECHO_LOG_CAP {
        log.pop_front();
    }
    while log
        .front()
        .is_some_and(|(at, _)| at.elapsed() > ECHO_WINDOW)
    {
        log.pop_front();
    }
}

/// Does a transcript look like the bot's own recent TTS leaking back
/// through a participant's mic? Word-bag containment against everything
/// spoken inside [`ECHO_WINDOW`]: an echo transcript is (a fragment of)
/// our own words, so nearly all of its words appear in the log — while
/// a real reply *about* our answer brings its own words ("no", "wrong",
/// "what about…") and falls under the threshold.
///
/// Utterances under 4 words are exempt from the bag test (too easy to
/// false-positive on "yes" / "okay") and only match as an exact
/// substring of a logged sentence.
fn is_own_echo(recent: &RecentTts, heard: &str) -> bool {
    let heard_words = echo_words(heard);
    if heard_words.is_empty() {
        return false;
    }
    let Ok(log) = recent.lock() else { return false };
    let fresh: Vec<&String> = log
        .iter()
        .filter(|(at, _)| at.elapsed() <= ECHO_WINDOW)
        .map(|(_, t)| t)
        .collect();
    if fresh.is_empty() {
        return false;
    }
    if heard_words.len() < 4 {
        let needle = heard_words.join(" ");
        return fresh
            .iter()
            .any(|t| echo_words(t).join(" ").contains(&needle));
    }
    let bag: std::collections::HashSet<String> = fresh.iter().flat_map(|t| echo_words(t)).collect();
    let hits = heard_words.iter().filter(|w| bag.contains(*w)).count();
    (hits as f32 / heard_words.len() as f32) >= 0.8
}

/// Handle one addressed question: stream the answer from Groq and speak
/// it sentence-by-sentence as it generates — so Eliza starts talking
/// almost immediately — then post any links and show a visual card.
#[allow(clippy::too_many_arguments)]
/// Resolve a freeq nick to a Bluesky handle for personalization, by the
/// joiner's *verified* identity only: nick → DID (the extended-join account the
/// server bound at SASL) → handle. `None` when we have no verified DID.
///
/// We deliberately do NOT fall back to treating a handle-shaped nick as a real
/// handle. Nicks are self-asserted and freely chosen, so trusting one would let
/// anyone who nicks themselves `someone.bsky.social` make the being pull and
/// speak that stranger's real feed back as if it were them — impersonation. A
/// `did:key` DID (guests, AI beings) also has no Bluesky profile, so it
/// resolves to `None`.
async fn resolve_handle(cfg: &SharedConfig, nick: &str) -> Option<String> {
    let key = nick.to_ascii_lowercase();
    let did = cfg
        .nick_dids
        .lock()
        .ok()
        .and_then(|m| m.get(&key).cloned())?;
    if did.starts_with("did:key:") {
        return None;
    }
    if let Some(cached) = cfg
        .did_handles
        .lock()
        .ok()
        .and_then(|m| m.get(&did).cloned())
    {
        return cached;
    }
    let handle = crate::social_feed::handle_for_did(&cfg.http, &did).await;
    if let Ok(mut m) = cfg.did_handles.lock() {
        m.insert(did, handle.clone());
    }
    handle
}

/// Best-effort feed-aware context block for `nick` — resolves their handle and
/// folds their recent public posts in so the being can be personal. `None` on
/// any miss (guest, empty feed, network blip).
async fn fetch_bsky_context(cfg: &SharedConfig, nick: &str) -> Option<String> {
    let handle = resolve_handle(cfg, nick).await?;
    let posts = crate::social_feed::recent_posts(&cfg.http, &handle, 4).await;
    let block = crate::social_feed::context_block(&handle, &posts);
    if block.is_some() {
        tracing::info!(actor = %nick, handle = %handle, posts = posts.len(),
            "folded asker's Bluesky feed into context");
    }
    block
}

/// Generate a one-line, in-character personalized greeting from what the being
/// remembers about the person (memory) and/or their recent Bluesky posts (feed).
/// `None` when there's nothing to personalize on or no answer model is set.
async fn generate_greeting(
    cfg: &SharedConfig,
    label: &str,
    memory_block: Option<&str>,
    feed_block: Option<&str>,
) -> Option<String> {
    // Combined context: memory first (continuity beats novelty), then feed.
    let mut ctx = String::new();
    if let Some(m) = memory_block {
        ctx.push_str(m);
        ctx.push('\n');
    }
    if let Some(f) = feed_block {
        ctx.push_str(f);
    }
    if ctx.trim().is_empty() {
        return None;
    }
    let returning = memory_block.is_some();
    let question = if returning {
        format!(
            "{label} just came back. Greet them by name in ONE short line that shows \
you remember them — reference a past conversation above (or their recent posts if \
more apt). Warm, specific, no preamble, no question, under 30 words."
        )
    } else {
        format!(
            "{label} just walked into the room. Greet them by name with ONE short, \
specific line that reacts to their recent posts above — like a friend who actually \
follows them. No preamble, no question, under 30 words."
        )
    };
    let system = cfg.character_system_prompt.as_deref();
    let ans = if qa::is_anthropic_model(&cfg.groq_answer_model) {
        let akey = cfg.anthropic_key.as_deref()?;
        qa::anthropic_answer_streaming(
            &cfg.http,
            akey,
            &cfg.groq_answer_model,
            &ctx,
            &question,
            system,
            |_| {},
        )
        .await
        .ok()?
    } else {
        let gkey = cfg.groq_api_key.as_deref()?;
        qa::answer_streaming(
            &cfg.http,
            gkey,
            &cfg.groq_answer_model,
            &ctx,
            &question,
            system,
            |_| {},
        )
        .await
        .ok()?
    };
    let t = ans.text.trim().trim_matches('"').trim().to_string();
    (!t.is_empty()).then_some(t)
}

/// On a human joining a channel, fire a one-time proactive personalized greeting.
/// It opens with what the being REMEMBERS about them (continuity across sessions)
/// and/or their recent public Bluesky posts. Spawned so it never blocks the event
/// loop; self-guards on once-per-nick, humans only; stays silent if there's
/// nothing to personalize on (no generic "hello").
fn spawn_join_greeting(
    cfg: Arc<SharedConfig>,
    handle: Arc<ClientHandle>,
    channel: String,
    nick: String,
) {
    // External-brain mode: yokota owns all speech — no autonomous greetings.
    if cfg.external_brain {
        return;
    }
    let key = nick.to_ascii_lowercase();
    // Skip self and known peer agents.
    let self_canonical = cfg
        .nick
        .split_once('-')
        .map(|(p, _)| p)
        .unwrap_or(cfg.nick.as_str())
        .to_ascii_lowercase();
    if key == cfg.nick.to_ascii_lowercase()
        || key == self_canonical
        || cfg.peer_agents.contains(&key)
    {
        return;
    }
    // Once per nick per session.
    {
        let Ok(mut g) = cfg.greeted.lock() else {
            return;
        };
        if !g.insert(key.clone()) {
            return;
        }
    }
    tracing::info!(%nick, %channel, "join greeting: considering");
    tokio::spawn(async move {
        // Memory of this person (by nick) — works even without a Bluesky handle.
        let mem_recs = match cfg.memory.as_ref() {
            Some(m) => match m.recall_by_asker(&nick, 3) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(%nick, error = ?e, "join greeting: memory recall errored");
                    Vec::new()
                }
            },
            None => {
                tracing::info!(%nick, "join greeting: no memory store");
                Vec::new()
            }
        };
        tracing::info!(%nick, mem_recs = mem_recs.len(), "join greeting: memory recall");
        let memory_block = crate::memory::Memory::format_for_prompt(&mem_recs);
        // Feed (needs a resolvable handle).
        let handle_opt = resolve_handle(&cfg, &nick).await;
        let posts = match &handle_opt {
            Some(h) => crate::social_feed::recent_posts(&cfg.http, h, 4).await,
            None => Vec::new(),
        };
        let feed_block = handle_opt
            .as_ref()
            .and_then(|h| crate::social_feed::context_block(h, &posts));
        if memory_block.is_none() && feed_block.is_none() {
            tracing::info!(%nick, "join greeting: nothing to personalize on — skip");
            return;
        }
        let label = handle_opt.clone().unwrap_or_else(|| nick.clone());
        let Some(line) =
            generate_greeting(&cfg, &label, memory_block.as_deref(), feed_block.as_deref()).await
        else {
            tracing::warn!(%nick, "join greeting: model produced nothing — skip");
            return;
        };
        tracing::info!(%nick, handle = ?handle_opt, remembered = memory_block.is_some(),
            "proactive personalized greeting on join");
        let _ = handle.privmsg(&channel, &line).await;
    });
}

/// Resolve the ghostly voice-DSP profile for THIS bot's speech, honoring
/// the `--no-voice-dsp` override (dry/neutral profile) when set.
fn resolve_speak_profile(cfg: &SharedConfig) -> ghostly::audio::profile::VoiceProfile {
    if cfg.no_voice_dsp {
        ghostly::audio::profile::VoiceProfile::NEUTRAL
    } else {
        crate::persona::resolve_voice_profile(&cfg.ghostly_character, cfg.ghostly_pack.as_deref())
    }
}

/// Synthesize one sentence and enqueue its audio on `speaker`, running it
/// through the voice-DSP `chain`. Shared by the streaming answer path and
/// [`speak_text`] so there is a single TTS → DSP → enqueue pipeline.
/// `on_first_audio` fires once, the first time any PCM is enqueued.
async fn synth_and_enqueue(
    http: &reqwest::Client,
    el_key: &str,
    voice: &str,
    model: &str,
    chain: &mut ghostly::audio::VoiceChain,
    work: &mut Vec<f32>,
    recent_tts: &std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<(Instant, String)>>>,
    speaker: &Speaker,
    sentence: &str,
    // Voice-turn id for latency correlation (0 = non-voice speak path).
    turn: u64,
    mut on_first_audio: impl FnMut(),
) -> Result<()> {
    // URLs are unpronounceable — strip them from speech; the channel
    // gets them as text instead.
    let (spoken, _) = split_speech_and_links(sentence);
    if !spoken.chars().any(char::is_alphanumeric) {
        return Ok(());
    }
    // Log what we're about to say so a participant's speaker→mic leak
    // (no AEC) transcribed back at us can be recognized and dropped.
    note_spoken(recent_tts, &spoken);
    let mut fired = false;
    let t_req = Instant::now();
    tts::synthesize_streaming(http, el_key, voice, model, &spoken, |pcm| {
        if !fired {
            fired = true;
            tracing::info!(
                turn,
                tts_first_byte_ms = t_req.elapsed().as_millis() as u64,
                chars = spoken.chars().count(),
                "latency: TTS request→first audio byte"
            );
            on_first_audio();
        }
        work.clear();
        work.extend_from_slice(pcm);
        chain.process(work);
        speaker.enqueue(work, tts::ELEVENLABS_PCM_RATE);
    })
    .await?;
    Ok(())
}

/// Speak `text` aloud through the full TTS → voice-DSP → speaker
/// pipeline — the ONE speak path shared by the local answer flow and the
/// external-brain seam (yokota's `say` lines). Chunks `text` into
/// sentences and synthesizes them in order. No-op (returns `Ok`) when
/// there's no ElevenLabs key configured.
/// Monotonic per-turn id for correlating the voice-pipeline latency logs
/// (VAD → STT → answer → TTS → speak) of a single utterance, even when
/// several utterances are in flight. `turn=0` marks the non-voice (text)
/// path, which has no speech-end anchor.
static VOICE_TURN_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_turn_id() -> u64 {
    VOICE_TURN_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Anchors a voice turn at the moment the user stopped speaking (the VAD
/// flush). Threaded through the answer path so every stage can report
/// `speech_end → now` — the rhythm metric a human actually perceives.
#[derive(Clone, Copy)]
pub(crate) struct TurnClock {
    pub id: u64,
    pub speech_end: Instant,
}

pub(crate) async fn speak_text(
    cfg: &SharedConfig,
    speaker: &Speaker,
    _video: Option<&VideoTile>,
    text: &str,
) -> Result<()> {
    let Some(el_key) = cfg.elevenlabs_api_key.as_deref() else {
        return Ok(());
    };
    let voice = cfg.elevenlabs_voice_id.clone();
    let model = cfg.elevenlabs_model.clone();
    let voice_profile = resolve_speak_profile(cfg);
    let mut chain = ghostly::audio::VoiceChain::new(voice_profile, tts::ELEVENLABS_PCM_RATE as f32);
    let mut work: Vec<f32> = Vec::with_capacity(4096);
    let mut chunker = qa::SentenceChunker::new();
    let mut sentences: Vec<String> = chunker.push(text);
    if let Some(last) = chunker.flush() {
        sentences.push(last);
    }
    for sentence in sentences {
        if let Err(e) = synth_and_enqueue(
            &cfg.http,
            el_key,
            &voice,
            &model,
            &mut chain,
            &mut work,
            &cfg.recent_tts,
            speaker,
            &sentence,
            0, // non-voice speak path — no turn anchor
            || {},
        )
        .await
        {
            tracing::warn!(error = ?e, "speak_text: streaming TTS failed");
        }
    }
    Ok(())
}

async fn answer_and_speak(
    cfg: Arc<SharedConfig>,
    handle: Arc<ClientHandle>,
    channel: String,
    asker: String,
    question: String,
    transcript: String,
    speaker: Option<Speaker>,
    video: Option<VideoTile>,
    // The asker's own camera video, for visual questions.
    asker_video: Option<VideoHandle>,
    // The asker's screen share (a separate `{name}/screen` broadcast), if live.
    screen_video: Option<VideoHandle>,
    // The live call slot — so the bot's own answer can be appended to
    // the transcript (symmetric conversation log). `None` when there's
    // no call.
    active: Option<Arc<AsyncMutex<Option<ActiveCall>>>>,
    // Voice-turn latency anchor: `Some` on the voice path (carries the
    // turn id + speech_end instant), `None` on the text path.
    clock: Option<TurnClock>,
) {
    let Some(key) = cfg.groq_api_key.as_deref() else {
        return;
    };
    // Turn id for correlating latency lines (0 = text path, no anchor).
    let turn = clock.map(|c| c.id).unwrap_or(0);
    // Per-stage latency clock — every stage below logs elapsed_ms off
    // this so a slow answer can be blamed on its actual stage (recall /
    // feed / first token / first TTS audio) instead of guessed at.
    let t0 = Instant::now();
    // Voice answers use the fast model: time-to-first-word IS the
    // experience in a call. Text answers keep the heavyweight default.
    let is_voice = speaker.is_some();
    tracing::info!(
        turn,
        %asker,
        %question,
        voice = is_voice,
        since_speech_end_ms = clock.map(|c| c.speech_end.elapsed().as_millis() as u64),
        "answering addressed question"
    );

    // Route the question with a fast small-model classifier, in
    // parallel with the context assembly below — by the time context is
    // ready the verdict usually is too, so routing costs ~no latency.
    // visual → the vision model with the asker's frame; live_data (on
    // the voice path) → the agentic search model instead of the fast
    // no-tools model, which otherwise bluffs a forecast. Any router
    // failure falls back to the cue-list heuristics.
    let router_task: JoinHandle<Option<qa::QuestionRoute>> = {
        let http = cfg.http.clone();
        let api_key = key.to_string();
        let q = question.clone();
        tokio::spawn(async move { qa::route_question(&http, &api_key, &q).await })
    };

    // Show the "thinking" mood on the tile while the LLM call runs.
    // The guard clears it on every exit path.
    if let Some(v) = &video {
        v.set_thinking(true);
        // Sticky gaze: while the bot is composing + speaking the
        // answer, its eyes turn toward `asker`. The FocusGuard
        // releases the lock on every exit path.
        v.set_focus_nick(Some(asker.clone()));
    }
    let _thinking = ThinkingGuard(video.clone());
    let _focus = FocusGuard(video.clone());
    // The vision PiP (if any) is also cleared on every exit path.
    let _vision_thumb = VisionThumbGuard(video.clone());

    // Speaker task: drains completed sentences and streams each through
    // TTS, enqueueing audio as it synthesizes. It runs concurrently with
    // answer generation — Eliza speaks sentence 1 while the model is
    // still writing sentence 2.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let speak_task: Option<JoinHandle<()>> = match (speaker, cfg.elevenlabs_api_key.clone()) {
        (Some(sp), Some(el_key)) => {
            let http = cfg.http.clone();
            let voice = cfg.elevenlabs_voice_id.clone();
            let model = cfg.elevenlabs_model.clone();
            // Per-character voice chain — see proactive.rs for design
            // intent. `--no-voice-dsp` swaps in the dry/neutral profile.
            let voice_profile = resolve_speak_profile(&cfg);
            // Peer-loudness handle for the don't-talk-over gate.
            // `peer_level` is the loudest of all OTHER participants
            // (humans + other agents) on this tile; the bot is
            // filtered out of its own subscription so its own TTS
            // does not drive this signal.
            let peer_level = video.as_ref().map(|v| v.peer_level_handle());
            let recent_tts = cfg.recent_tts.clone();
            // Solo = no configured peer agents → skip the anti-collision
            // jitter in the quiet gate (it's only there for bot↔bot).
            let solo = cfg.peer_agents.is_empty();
            Some(tokio::spawn(async move {
                let mut chain =
                    ghostly::audio::VoiceChain::new(voice_profile, tts::ELEVENLABS_PCM_RATE as f32);
                let mut work: Vec<f32> = Vec::with_capacity(4096);
                let mut first = true;
                let mut first_audio_logged = false;
                while let Some(sentence) = rx.recv().await {
                    // Wait-for-quiet gate: before STARTING to speak,
                    // hold until no peer is talking. Applied only at
                    // the first sentence of the answer — once the
                    // bot has the floor, subsequent sentences stream
                    // immediately. Prevents the cross-talk where two
                    // agents both got addressed and stepped on each
                    // other's first words. Skipped for non-pronounceable
                    // segments so a URL-only "sentence" doesn't burn the
                    // gate; the helper also no-ops those.
                    let (spoken_probe, _) = split_speech_and_links(&sentence);
                    if !spoken_probe.chars().any(char::is_alphanumeric) {
                        continue;
                    }
                    if first {
                        if let Some(pl) = &peer_level {
                            wait_for_room_quiet(pl, solo).await;
                        }
                        tracing::info!(
                            turn,
                            elapsed_ms = t0.elapsed().as_millis() as u64,
                            since_speech_end_ms =
                                clock.map(|c| c.speech_end.elapsed().as_millis() as u64),
                            "latency: first sentence reached TTS"
                        );
                        first = false;
                    }
                    let first_audio_ref = &mut first_audio_logged;
                    if let Err(e) = synth_and_enqueue(
                        &http,
                        &el_key,
                        &voice,
                        &model,
                        &mut chain,
                        &mut work,
                        &recent_tts,
                        &sp,
                        &sentence,
                        turn,
                        || {
                            if !*first_audio_ref {
                                *first_audio_ref = true;
                                tracing::info!(
                                    turn,
                                    elapsed_ms = t0.elapsed().as_millis() as u64,
                                    "latency: first TTS audio enqueued"
                                );
                                // THE rhythm metric: how long after the user
                                // stopped talking did the bot start speaking.
                                if let Some(c) = clock {
                                    tracing::info!(
                                        turn,
                                        speech_to_first_audio_ms =
                                            c.speech_end.elapsed().as_millis() as u64,
                                        answer_compose_ms = t0.elapsed().as_millis() as u64,
                                        "latency: SUMMARY speech_end→first_audio (rhythm)"
                                    );
                                }
                            }
                        },
                    )
                    .await
                    {
                        tracing::warn!(error = ?e, "streaming TTS failed");
                    }
                }
            }))
        }
        _ => None,
    };

    // Thinking beat: the moment she's addressed, send a brief filler to the
    // speaker so she audibly engages while the model composes. It rides ahead of
    // the answer sentences in the same queue, after the wait-for-quiet gate.
    if speak_task.is_some()
        && let Some(beat) = thinking_beat(&question)
    {
        let _ = tx.send(beat);
    }

    // Context assembly. Each section is explicitly LABELED so the model
    // can tell this call from older material — the old code prepended
    // memory + feed blocks onto the transcript and qa.rs stamped one
    // "Call transcript so far:" header over the lot, so days-old
    // recalled exchanges read as things said in this call and the bot
    // answered from past sessions.
    let live_transcript = transcript;
    let mut sections: Vec<String> = Vec::new();

    // Past exchanges from memory ("last time you asked about X…").
    // Scoped to this channel by default — cross-channel recall would be
    // a separate, more invasive product decision.
    if let Some(mem) = cfg.memory.as_ref() {
        match mem.recall(&question, Some(&channel), 3) {
            Ok(recs) => {
                if let Some(block) = crate::memory::Memory::format_for_prompt(&recs) {
                    sections.push(block);
                }
            }
            Err(e) => {
                tracing::warn!(error = ?e, "memory recall failed; continuing without it");
            }
        }
    }

    // Feed-aware cold open: best-effort. If the asker's nick resolves to a
    // Bluesky account, fold their recent public posts into context so the being
    // can react to who it's actually talking to ("saw you shipped X"). Folds in
    // alongside memory; gracefully no-ops when the nick isn't a handle.
    //
    // Timeboxed: this is 1-2 public HTTP round-trips sitting directly in
    // front of the LLM call, on EVERY answer. A slow Bluesky response was
    // adding whole seconds before the model even started — flavor context
    // is not worth dead air, so past the deadline we answer without it.
    let bsky_deadline = if is_voice {
        Duration::from_millis(800)
    } else {
        Duration::from_millis(2500)
    };
    match tokio::time::timeout(bsky_deadline, fetch_bsky_context(&cfg, &asker)).await {
        Ok(Some(block)) => sections.push(block),
        Ok(None) => {}
        Err(_) => {
            tracing::info!("bsky context fetch timed out — answering without it");
        }
    }

    // The live conversation, last — closest to the question.
    if !live_transcript.trim().is_empty() {
        sections.push(format!(
            "LIVE CALL TRANSCRIPT (this call, oldest line first):\n{live_transcript}"
        ));
    }
    // Tell the model exactly which live video the asker has — so "can you
    // see me?" / "see my screen?" get an accurate yes even when the question
    // routes to the text model.
    let live_hint = match (asker_video.is_some(), screen_video.is_some()) {
        (true, true) => Some("both their camera and a screen share"),
        (false, true) => Some("a screen share (camera off)"),
        (true, false) => Some("their camera"),
        (false, false) => None,
    };
    if let Some(hint) = live_hint {
        sections.push(format!("({asker} has {hint} live in this call.)"));
    }
    let context = sections.join("\n\n");
    tracing::info!(
        turn,
        elapsed_ms = t0.elapsed().as_millis() as u64,
        "latency: context assembled (memory + feed), dispatching model"
    );

    // Collect the router verdict — it has been running since the top of
    // this function, so it's almost always already done; the timeout
    // only bounds the unlucky case.
    let route = match tokio::time::timeout(Duration::from_millis(900), router_task).await {
        Ok(Ok(r)) => r,
        _ => None,
    };
    let answer_model: &str = if is_voice {
        if route.is_some_and(|r| r.live_data) {
            &cfg.voice_search_model
        } else {
            &cfg.voice_answer_model
        }
    } else {
        &cfg.groq_answer_model
    };
    tracing::info!(
        turn,
        elapsed_ms = t0.elapsed().as_millis() as u64,
        visual = route.map(|r| r.visual),
        live_data = route.map(|r| r.live_data),
        agent = route.map(|r| r.agent),
        model = %answer_model,
        "question routed"
    );

    // ── Smart hand-off ───────────────────────────────────────────────
    // An agentic TASK (write/run code, multi-step work, file ops) goes to the
    // Claude Code brain over the seam — it has tools + file access the fast
    // voice model lacks. Visual questions stay local (the camera frame lives
    // here). `external_brain` already forwards everything, so this only fires
    // on the native voice path. yokota acks, runs it, and speaks the result
    // back via the seam, so we take no native answer here.
    // Router verdict UNION the cue-list heuristic (small router models miss
    // clear coding tasks); a visual question stays local regardless.
    let wants_agent = route.is_some_and(|r| r.agent) || qa::is_agentic_task(&question);
    let is_visual_route = route.is_some_and(|r| r.visual);
    if is_voice
        && !cfg.external_brain
        && wants_agent
        && !is_visual_route
        && let Some(seam) = cfg.brain_seam.get()
    {
        tracing::info!(turn, %asker, %question, "smart hand-off → Claude Code (agentic task)");
        seam.send(crate::brain_seam::Outbound::Delegate {
            nick: asker.clone(),
            text: question.clone(),
        });
        drop(tx);
        if let Some(t) = speak_task {
            let _ = t.await;
        }
        return;
    }

    // A visual question we can actually see → the vision model with the
    // asker's latest frame. A visual question with no frame → a useful
    // hint (otherwise QA answers "I'm a language model"). Anything else
    // → the normal streaming QA. Completed sentences always go to the
    // speaker task.
    let mut chunker = qa::SentenceChunker::new();
    // Visual routing: the router's semantic verdict, UNION the cue-list
    // heuristics as a fallback (router down/slow → cue lists still
    // route; a cue-list false negative → the router still routes).
    // When the asker HAS a video tap, the looser cue set applies too
    // ("how many fingers am I holding up") — a missed route sends a
    // visual question to the text model, which can't see and says so.
    // Keyed off the tap existing, not off a frame already decoded:
    // "can you see this?" usually arrives in the same breath as the
    // camera coming on, before the first frame lands.
    // Source choice: camera vs screen share. The screen is a separate tap.
    // Explicit camera/self questions → camera; otherwise, whenever a screen
    // share is live, prefer it (a shared screen is almost always the thing to
    // look at, and a bare "what do you see?" while sharing means the screen).
    // Always fall back to the other source if the preferred one has no frame.
    let q_low = question.to_lowercase();
    let asks_self_cam = [
        "see me",
        "look at me",
        "my face",
        "how do i look",
        "how do i look like",
        "wearing",
        "holding",
        "behind me",
        "my camera",
        "the camera",
        "at me",
    ]
    .iter()
    .any(|w| q_low.contains(w));
    let prefer_screen = screen_video.is_some() && !asks_self_cam;
    let (primary, secondary) = if prefer_screen {
        (screen_video.as_ref(), asker_video.as_ref())
    } else {
        (asker_video.as_ref(), screen_video.as_ref())
    };
    let mut candidate_frame = primary
        .and_then(|vh| vh.latest())
        .or_else(|| secondary.and_then(|vh| vh.latest()));
    let has_video_tap = asker_video.is_some() || screen_video.is_some();
    let visual = route.is_some_and(|r| r.visual)
        || if has_video_tap {
            vision::is_visual_question_with_frame(&question)
        } else {
            vision::is_visual_question(&question)
        };
    // Warm-up: a visual question with a tap but no frame yet — poll briefly
    // for the first decode (of either source) instead of claiming blindness.
    if visual && candidate_frame.is_none() && has_video_tap {
        let warmup = Instant::now();
        while candidate_frame.is_none() && warmup.elapsed() < Duration::from_secs(2) {
            tokio::time::sleep(Duration::from_millis(100)).await;
            candidate_frame = primary
                .and_then(|vh| vh.latest())
                .or_else(|| secondary.and_then(|vh| vh.latest()));
        }
        tracing::info!(
            prefer_screen,
            got_frame = candidate_frame.is_some(),
            waited_ms = warmup.elapsed().as_millis() as u64,
            "visual question — waited for video warm-up"
        );
    }
    let frame = if visual { candidate_frame } else { None };

    // Race a whiteboard plan in parallel with the answer call. For
    // "explain it" questions the model returns drawing steps and the
    // tile draws them stroke-by-stroke as she speaks; for everything
    // else it returns no steps and we fall through to the scene card.
    // Vision-branch questions get the camera PiP instead, no board.
    let whiteboard_task: Option<JoinHandle<Option<Vec<Step>>>> = if !visual {
        let http = cfg.http.clone();
        let api_key = key.to_string();
        let model = cfg.groq_chat_model.clone();
        let q = question.clone();
        Some(tokio::spawn(async move {
            qa::whiteboard(&http, &api_key, &model, &q).await
        }))
    } else {
        None
    };

    let result: Result<qa::Answer> = if let Some(frame) = frame {
        tracing::info!("answering as a visual question");
        match vision::frame_to_jpeg_data_uri(&frame) {
            Ok(uri) => {
                // Pin the frame as a PiP on the video tile so the call
                // sees exactly what eliza is looking at while she talks.
                if let Some(v) = &video {
                    v.set_vision_thumb(uri.clone());
                }
                vision::describe(
                    &cfg.http,
                    key,
                    &cfg.vision_model,
                    &question,
                    &live_transcript,
                    &uri,
                )
                .await
                .map(|text| {
                    for sentence in chunker.push(&text) {
                        let _ = tx.send(sentence);
                    }
                    qa::Answer { text, source: None }
                })
            }
            Err(e) => Err(e),
        }
    } else if visual {
        tracing::info!("visual question but no video frame from asker");
        let text = "I can't see anything right now — turn on your camera or share your screen, then ask again.".to_string();
        for sentence in chunker.push(&text) {
            let _ = tx.send(sentence);
        }
        Ok(qa::Answer { text, source: None })
    } else {
        // Discussion-mode prompt injection. When the human has armed
        // peer-conversation mode (`discussion_until` in the future),
        // append an instruction to the system prompt that tells the
        // LLM to end its answer by inviting one specific peer to
        // respond — by name, with a comma. The named bot's STT
        // picks that up, address detection fires, peer answers, and
        // the chain self-sustains until the discussion window expires.
        let augmented_prompt = if is_discussion_mode_active(&cfg) && !cfg.peer_agents.is_empty() {
            let base = cfg.character_system_prompt.as_deref().unwrap_or("");
            // Build a peer list excluding ourselves so the bot
            // does not accidentally address itself.
            let self_canonical = cfg
                .nick
                .split_once('-')
                .map(|(p, _)| p)
                .unwrap_or(cfg.nick.as_str())
                .to_ascii_lowercase();
            let peers: Vec<&str> = cfg
                .peer_agents
                .iter()
                .filter(|p| **p != self_canonical)
                .map(|s| s.as_str())
                .collect();
            let peer_list = peers.join(", ");
            Some(format!(
                "{base}\n\nDISCUSSION MODE IS ACTIVE. After your answer \
(1-2 sentences max), end with a one-sentence direct address to ONE specific \
peer by name (\"{peer_list}\") inviting their response. Format: \"<Name>, \
<one-line follow-up question>.\" Pick the peer whose viewpoint would most \
sharpen the thread. Do NOT address yourself."
            ))
        } else {
            None
        };
        let effective_system_prompt = augmented_prompt
            .as_deref()
            .or(cfg.character_system_prompt.as_deref());

        // Dispatch: a `claude-*` model goes to Anthropic Messages
        // (uses ANTHROPIC_API_KEY); anything else stays on the Groq
        // OpenAI-compatible endpoint (uses GROQ_API_KEY). Per-call
        // streaming, same `Answer` shape returned either way. First
        // delta is logged so slow answers can be split into "model was
        // slow to start" vs "everything after".
        let mut first_delta_logged = false;
        let mut on_delta = |delta: &str| {
            if !first_delta_logged {
                first_delta_logged = true;
                tracing::info!(
                    turn,
                    elapsed_ms = t0.elapsed().as_millis() as u64,
                    "latency: first model token"
                );
            }
            for sentence in chunker.push(delta) {
                let _ = tx.send(sentence);
            }
        };
        if qa::is_anthropic_model(answer_model) {
            match cfg.anthropic_key.as_deref() {
                Some(akey) => {
                    qa::anthropic_answer_streaming(
                        &cfg.http,
                        akey,
                        answer_model,
                        &context,
                        &question,
                        effective_system_prompt,
                        |delta| on_delta(delta),
                    )
                    .await
                }
                None => Err(anyhow::anyhow!(
                    "model {answer_model} requires ANTHROPIC_API_KEY"
                )),
            }
        } else {
            qa::answer_streaming(
                &cfg.http,
                key,
                answer_model,
                &context,
                &question,
                effective_system_prompt,
                |delta| on_delta(delta),
            )
            .await
        }
    };

    let answer = match result {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = ?e, "QA failed");
            drop(tx);
            if let Some(t) = speak_task {
                let _ = t.await;
            }
            let _ = handle
                .privmsg(
                    &channel,
                    &format!("{asker}: sorry — I couldn't answer that ({e})."),
                )
                .await;
            return;
        }
    };

    // The final sentence has no trailing whitespace to flush it mid-stream.
    if let Some(last) = chunker.flush() {
        let _ = tx.send(last);
    }

    // Answer fully composed — model generation done (first token → last).
    tracing::info!(
        turn,
        elapsed_ms = t0.elapsed().as_millis() as u64,
        answer_chars = answer.text.len(),
        "latency: answer fully composed (model generation complete)"
    );

    // Log the full answer text — invaluable for debugging when she's
    // saying something weird (e.g. reading image alt attributes).
    tracing::info!(text = %answer.text, "answer text (sent to TTS)");

    // Auto-capture a notable line as a shareable "moment" card on the console
    // (silent — feeds the /moments gallery so the viral loop closes without a
    // human step). Best-effort, fire-and-forget.
    if let Some(console) = cfg.console_url.clone()
        && is_moment_worthy(&answer.text)
    {
        let http = cfg.http.clone();
        let being = cfg
            .nick
            .split_once('-')
            .map(|(p, _)| p)
            .unwrap_or(&cfg.nick)
            .to_string();
        let quote = answer.text.clone();
        let to = asker.clone();
        tokio::spawn(async move {
            if let Some(id) =
                crate::social_feed::post_moment(&http, &console, &being, &quote, Some(&to)).await
            {
                tracing::info!(%id, %being, "captured moment card");
            }
        });
    }

    // Deterministic peer hand-off (discussion mode). The LLM's
    // answer often ends with addressing a peer ("Utopia, your
    // counter?"). That hand-off comes back to the peer through
    // TTS → MoQ → STT, and the chunker frequently splits the peer
    // name from the question body so the peer hears "Utopia?" alone
    // with no body and the address parser drops it. Send a parallel
    // IRC privmsg so the addressed peer dispatches deterministically,
    // ignoring the audio path entirely.
    if is_discussion_mode_active(&cfg) && !cfg.peer_agents.is_empty() {
        let self_canonical = cfg
            .nick
            .split_once('-')
            .map(|(p, _)| p)
            .unwrap_or(cfg.nick.as_str())
            .to_ascii_lowercase();
        // Filter out self from the peer set so a bot does not
        // hand off to itself.
        let candidates: std::collections::HashSet<String> = cfg
            .peer_agents
            .iter()
            .filter(|p| **p != self_canonical)
            .cloned()
            .collect();
        if let Some((peer, body)) = crate::social::extract_peer_handoff(&answer.text, &candidates) {
            let body = if body.is_empty() {
                "your take?".to_string()
            } else {
                body
            };
            let msg = format!("{peer}: {body}");
            tracing::info!(target = %peer, %body, "discussion hand-off");
            let _ = handle.privmsg(&channel, &msg).await;
        }
    }

    // Symmetric transcript: the bot's own answer becomes a transcript
    // line, so follow-ups ("what did you just say?", "tell me more")
    // have the answer in context. Both sides of every exchange are now
    // in the log — questions are pushed at the dispatch sites.
    if let Some(active) = active.as_ref() {
        let mut guard = active.lock().await;
        if let Some(call) = guard.as_mut() {
            call.transcript
                .push(format!("{}: {}", canonical_name(&cfg.nick), answer.text));
        }
    }

    // Persist to memory so future sessions can recall this exchange.
    // Soft failure: a memory write error doesn't break the response.
    if let Some(mem) = cfg.memory.as_ref()
        && let Err(e) = mem.record(&channel, &asker, &question, &answer.text)
    {
        tracing::warn!(error = ?e, "failed to record exchange to memory");
    }

    // Decision capture: extract commitments from both sides of the
    // exchange and append to the per-channel decision log. The asker
    // might commit ("let's ship Friday"); the bot might commit ("I'll
    // pull the metrics"). Both are decisions the room should hear back
    // when the session ends.
    let mut captured = crate::decisions::Decision::extract(&asker, &question);
    captured.extend(crate::decisions::Decision::extract(&cfg.nick, &answer.text));
    if !captured.is_empty()
        && let Ok(mut log) = cfg.decisions.lock()
    {
        log.entry(channel.clone()).or_default().extend(captured);
    }

    // Links: Eliza is voice-first, so URLs go to the channel as text
    // rather than into speech. Collect them from the full answer.
    let (_, body_links) = split_speech_and_links(&answer.text);
    let mut posted_link = false;
    for url in &body_links {
        let _ = handle.privmsg(&channel, &format!("[eliza] {url}")).await;
        posted_link = true;
        tracing::info!(%url, "posted answer link");
    }
    if let Some(src) = &answer.source {
        // Skip a source already surfaced as a body link.
        if !body_links.iter().any(|u| u == &src.url) {
            let line = if src.title.is_empty() {
                format!("[eliza] more on this — {}", src.url)
            } else {
                let title: String = src.title.chars().take(90).collect();
                format!("[eliza] {title} — {}", src.url)
            };
            let _ = handle.privmsg(&channel, &line).await;
            tracing::info!(url = %src.url, "posted source link");
        }
        posted_link = true;
    }
    if posted_link && speak_task.is_some() {
        let _ =
            tx.send("I've posted a link in the channel if you'd like to read more.".to_string());
    }

    // Close the sentence stream and wait for her to finish speaking it.
    drop(tx);
    let spoke = match speak_task {
        Some(t) => {
            let _ = t.await;
            true
        }
        None => false,
    };

    if !spoke {
        tracing::info!("answered in text only");
        let _ = handle
            .privmsg(&channel, &format!("[eliza→{asker}] {}", answer.text))
            .await;
    }

    // Whiteboard takes priority — if she's explaining something, draw
    // it instead of a typographic card. Steps reveal one at a time
    // while she speaks.
    let board_shown = if let Some(task) = whiteboard_task {
        match task.await {
            Ok(Some(steps)) => {
                tracing::info!(steps = steps.len(), "showing whiteboard");
                if let Some(v) = &video {
                    v.show_board(steps, "#3effd6".to_string());
                }
                true
            }
            _ => false,
        }
    } else {
        false
    };

    // Otherwise: design a typographic scene card — the model picks a
    // layout, the renderer animates it in, and a backdrop image is
    // fetched off the hot path.
    if !board_shown && let Some(video) = &video {
        match qa::generate_scene(
            &cfg.http,
            key,
            &cfg.groq_chat_model,
            &question,
            &answer.text,
        )
        .await
        {
            Some(spec) => {
                tracing::info!(
                    kind = ?spec.kind,
                    title = %spec.title,
                    points = spec.points.len(),
                    "showing scene"
                );
                let query = spec.image_query.clone();
                let scene_id = video.show_scene(spec);
                spawn_scene_image(&cfg, video, scene_id, query);
            }
            None => tracing::info!("no scene for this answer"),
        }
    }
}

/// Fetch a backdrop image for scene `scene_id` and attach it when ready.
/// Runs entirely off the answer path — image lookup/generation is slow
/// (Wikipedia ~1s, AI fallback ~15s), so the scene shows text-first and
/// the backdrop fades in once it arrives.
/// Wait until the room is quiet — no peer (human or other agent) has
/// been speaking for a short hold window. Used as a "wait my turn"
/// gate before a bot starts its own TTS so multiple agents do not
/// step on each other or on the human.
///
/// Two-stage gate:
///
///   1. Standard quiet wait — peer_level below threshold for 250 ms.
///   2. **Anti-collision confirmation jitter**: once quiet is
///      detected, sleep a random 250–1000 ms and re-check. When two
///      bots both detect quiet at the same instant (e.g. because the
///      human just finished a question that armed both of them), the
///      different jitter draws give different start times — one
///      wakes first, starts speaking, and the other's confirmation
///      re-check catches the new peer audio and restarts the wait.
///      Without this step, the bots talk on top of each other every
///      time the human's silence resolves the trigger for both.
///
/// Caps total wait at 8 s so a stuck-open mic from a peer cannot mute
/// the bot forever.
/// Hold until the room is quiet before the bot starts speaking.
///
/// `solo` skips the anti-collision jitter stage: that jitter only exists
/// to keep two BOTS from talking over each other, so when this is the only
/// agent in the call it is 250–1000 ms of pure pre-speech latency with no
/// benefit. On the solo path we return as soon as the quiet HOLD passes —
/// the single biggest win for conversational rhythm.
pub(crate) async fn wait_for_room_quiet(
    peer_level: &Arc<std::sync::atomic::AtomicU32>,
    solo: bool,
) {
    use std::sync::atomic::Ordering;
    const THRESHOLD: f32 = 0.04;
    // 150 ms (was 250): on the answer path the VAD already waited ~450 ms of
    // silence to end the turn and STT added ~300 ms more, so the room has been
    // provably quiet ~750 ms before this gate runs — a long HOLD just re-confirms
    // known silence and taxes rhythm. 150 ms still catches a human resuming.
    const HOLD: Duration = Duration::from_millis(150);
    const MAX_WAIT: Duration = Duration::from_millis(8000);
    let start = Instant::now();
    'outer: loop {
        if start.elapsed() >= MAX_WAIT {
            tracing::info!(
                waited_ms = start.elapsed().as_millis() as u64,
                solo,
                "latency: wait_for_room_quiet (max-wait timeout)"
            );
            return;
        }
        // ── Stage 1: classic quiet wait ──
        let mut quiet_since: Option<Instant> = None;
        loop {
            if start.elapsed() >= MAX_WAIT {
                return;
            }
            let level = f32::from_bits(peer_level.load(Ordering::Relaxed));
            if level < THRESHOLD {
                match quiet_since {
                    None => quiet_since = Some(Instant::now()),
                    Some(t) if t.elapsed() >= HOLD => break,
                    _ => {}
                }
            } else {
                quiet_since = None;
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        // Solo: no other bot to collide with — the quiet hold is enough.
        if solo {
            tracing::info!(
                waited_ms = start.elapsed().as_millis() as u64,
                solo,
                "latency: wait_for_room_quiet (solo, no jitter)"
            );
            return;
        }
        // ── Stage 2: anti-collision confirmation jitter ──
        let jitter_ms = jitter_ms_per_bot(peer_level);
        let jitter_start = Instant::now();
        let jitter_dur = Duration::from_millis(jitter_ms);
        while jitter_start.elapsed() < jitter_dur {
            tokio::time::sleep(Duration::from_millis(40)).await;
            let level = f32::from_bits(peer_level.load(Ordering::Relaxed));
            if level >= THRESHOLD {
                // Another bot started while we were confirming — back
                // off and restart the wait from scratch.
                continue 'outer;
            }
        }
        // Confirmed quiet across the jitter window.
        return;
    }
}

/// Deterministic-but-different jitter per (bot, call). Mixes the
/// `peer_level` Arc pointer (per-bot, stable for the call) with the
/// current monotonic instant (per-call, drifts every invocation). The
/// result is a value in [250, 1000) ms — long enough that two bots
/// rarely draw the same number, short enough that the operator does
/// not perceive the gate as a stall.
fn jitter_ms_per_bot(peer_level: &Arc<std::sync::atomic::AtomicU32>) -> u64 {
    use std::time::SystemTime;
    let ptr = Arc::as_ptr(peer_level) as usize as u64;
    let now_ns = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Splitmix-style mix so two nearby pointers don't yield close numbers.
    let mut x = ptr.wrapping_add(now_ns);
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^= x >> 33;
    250 + (x % 750)
}

/// Periodic backchannel: every few seconds, check whether a peer has
/// been continuously talking. If so, drop a barely-audible "mm" /
/// "hm" through the bot's own voice chain so the listening agent
/// feels present. Rate-limited per bot so it never piles up. Aborts
/// when the call ends (the caller holds the JoinHandle on
/// `ActiveCall::backchannel_task`).
fn spawn_backchannel_loop(
    cfg: Arc<SharedConfig>,
    speaker: freeq_av::Speaker,
    peer_level: Arc<std::sync::atomic::AtomicU32>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // External-brain mode: yokota owns all speech — no backchannels.
        if cfg.external_brain {
            return;
        }
        let Some(el_key) = cfg.elevenlabs_api_key.clone() else {
            return;
        };
        // Skip backchannels for agents without a persona (e.g. plain
        // "eliza", whose `character_system_prompt` is None); personas
        // map to TTS voices + a ghostly voice-DSP character we know.
        if cfg.character_system_prompt.is_none() {
            return;
        }
        let voice_id = cfg.elevenlabs_voice_id.clone();
        let model = cfg.elevenlabs_model.clone();
        let http = cfg.http.clone();
        let character = cfg.ghostly_character.clone();
        let voice_profile =
            crate::persona::resolve_voice_profile(&character, cfg.ghostly_pack.as_deref());

        let mut chain =
            ghostly::audio::VoiceChain::new(voice_profile, tts::ELEVENLABS_PCM_RATE as f32);
        let mut counter: u32 = 0;
        let mut last_backchannel = Instant::now() - Duration::from_secs(60);
        let mut peer_loud_since: Option<Instant> = None;
        // Min seconds between two backchannels from this bot.
        const MIN_GAP: f32 = 9.0;
        // Peer must be talking continuously for this long before we
        // chime in (so we don't backchannel a stray syllable).
        const SUSTAIN: Duration = Duration::from_millis(1800);
        const PEER_THRESHOLD: f32 = 0.04;

        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let level = f32::from_bits(peer_level.load(std::sync::atomic::Ordering::Relaxed));
            if level >= PEER_THRESHOLD {
                if peer_loud_since.is_none() {
                    peer_loud_since = Some(Instant::now());
                }
            } else {
                peer_loud_since = None;
                continue;
            }
            let Some(loud_since) = peer_loud_since else {
                continue;
            };
            if loud_since.elapsed() < SUSTAIN {
                continue;
            }
            // Skip if our own speaker is currently playing audio —
            // backchanneling over our own answer reads as a stutter,
            // not as listening.
            if speaker.is_speaking() {
                continue;
            }
            let elapsed = last_backchannel.elapsed().as_secs_f32();
            let Some(phrase) =
                crate::social::pick_backchannel(&character, elapsed, MIN_GAP, counter)
            else {
                continue;
            };
            counter = counter.wrapping_add(1);
            last_backchannel = Instant::now();

            // Synthesize + softly enqueue. We mix the PCM at reduced
            // gain by attenuating BEFORE the voice chain — the chain's
            // output_gain pushes back up to consistent loudness with
            // the per-character tuning, but the input attenuation keeps
            // the backchannel quieter than a real answer.
            let mut work: Vec<f32> = Vec::with_capacity(4096);
            let chain_ref = &mut chain;
            let work_ref = &mut work;
            let sp_ref = &speaker;
            if let Err(e) =
                tts::synthesize_streaming(&http, &el_key, &voice_id, &model, phrase, |pcm| {
                    work_ref.clear();
                    work_ref.extend_from_slice(pcm);
                    // 0.35× pre-chain attenuation — the "mm" sits
                    // under the conversation, never over it.
                    for s in work_ref.iter_mut() {
                        *s *= 0.35;
                    }
                    chain_ref.process(work_ref);
                    sp_ref.enqueue(work_ref, tts::ELEVENLABS_PCM_RATE);
                })
                .await
            {
                tracing::warn!(error = ?e, "backchannel TTS failed");
            }
        }
    })
}

/// Speak the character's `hello_line` through ElevenLabs + the per-
/// character voice chain + the call speaker, then return. Runs once
/// per call activation. Silent no-op if any of (ElevenLabs key,
/// character profile) is missing.
fn spawn_hello_on_join(
    cfg: &Arc<SharedConfig>,
    speaker: freeq_av::Speaker,
    peer_level: Arc<std::sync::atomic::AtomicU32>,
) {
    // External-brain mode: yokota owns ALL speech, including greetings.
    if cfg.external_brain {
        return;
    }
    let Some(el_key) = cfg.elevenlabs_api_key.clone() else {
        tracing::info!("hello-on-join skipped — no ELEVENLABS_API_KEY");
        return;
    };
    let Some(hello_line) = cfg.persona_hello_line.clone() else {
        return;
    };
    // Session recall: prepend a one-line "I remember…" hook drawn
    // from the most recent past exchange, so the bot opens a fresh
    // call with continuity instead of a cold restart. Best-effort —
    // when memory is unavailable or empty, fall through to the
    // plain hello-line.
    let mut text = hello_line;
    if let Some(mem) = cfg.memory.as_ref() {
        // Cross-channel: we want the bot's last memorable exchange
        // wherever it happened, not necessarily this room.
        if let Ok(recs) = mem.recall("decided shipped agreed planned", None, 4)
            && let Some(hook) = crate::social::format_session_recall(&recs)
        {
            text = format!("{text} {hook}");
        }
    }
    let voice_id = cfg.elevenlabs_voice_id.clone();
    let model = cfg.elevenlabs_model.clone();
    let http = cfg.http.clone();
    let character = cfg.ghostly_character.clone();
    let ghostly_pack = cfg.ghostly_pack.clone();
    let recent_tts = cfg.recent_tts.clone();
    let solo = cfg.peer_agents.is_empty();
    tokio::spawn(async move {
        // Audio-pipeline settle: when the bot has just joined the call,
        // the MoQ broadcast publish has been opened but no subscriber
        // has caught its first samples yet. If we enqueue PCM the
        // moment we land here, the first ~second of the greeting is
        // chopped off — the listener hears "...the patterns are
        // already moving" instead of "Oblivion online. The patterns
        // are already moving." A short fixed delay covers the typical
        // subscriber-warm-up window without anything fancier.
        tokio::time::sleep(Duration::from_millis(2500)).await;

        // Wait my turn: each bot enters the call ~6s after the prior
        // one (staggered launch), and they all greet — without this
        // gate they'd talk over each other.
        wait_for_room_quiet(&peer_level, solo).await;
        note_spoken(&recent_tts, &text);
        let voice_profile =
            crate::persona::resolve_voice_profile(&character, ghostly_pack.as_deref());
        let mut chain =
            ghostly::audio::VoiceChain::new(voice_profile, tts::ELEVENLABS_PCM_RATE as f32);
        let mut work: Vec<f32> = Vec::with_capacity(4096);
        let chain_ref = &mut chain;
        let work_ref = &mut work;
        let sp_ref = &speaker;
        match tts::synthesize_streaming(&http, &el_key, &voice_id, &model, &text, |pcm| {
            work_ref.clear();
            work_ref.extend_from_slice(pcm);
            chain_ref.process(work_ref);
            sp_ref.enqueue(work_ref, tts::ELEVENLABS_PCM_RATE);
        })
        .await
        {
            Ok(n) => tracing::info!(%character, %text, samples = n, "hello-on-join spoken"),
            Err(e) => tracing::warn!(error = ?e, "hello-on-join TTS failed"),
        }
    });
}

pub(crate) fn spawn_scene_image(
    cfg: &Arc<SharedConfig>,
    video: &VideoTile,
    scene_id: u64,
    query: String,
) {
    if query.trim().is_empty() {
        return;
    }
    let cfg = cfg.clone();
    let video = video.clone();
    tokio::spawn(async move {
        let fetched = tokio::time::timeout(
            Duration::from_secs(45),
            imagegen::fetch(&cfg.http, &query, cfg.image_ai.as_ref()),
        )
        .await;
        let bytes = match fetched {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "scene backdrop unavailable");
                return;
            }
            Err(_) => {
                tracing::warn!("scene backdrop timed out");
                return;
            }
        };
        let uri = match tokio::task::spawn_blocking(move || imagegen::to_data_uri(&bytes)).await {
            Ok(Ok(uri)) => uri,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "scene backdrop processing failed");
                return;
            }
            Err(e) => {
                tracing::warn!(error = %e, "scene backdrop task panicked");
                return;
            }
        };
        video.set_scene_image(scene_id, uri);
        tracing::info!(scene_id, "scene backdrop ready");
    });
}

/// Clears the video tile's "thinking" mood when an `answer_and_speak`
/// call ends — on every path, including early returns.
struct ThinkingGuard(Option<VideoTile>);

impl Drop for ThinkingGuard {
    fn drop(&mut self) {
        if let Some(v) = &self.0 {
            v.set_thinking(false);
        }
    }
}

/// Releases the sticky gaze target on every exit path of
/// `answer_and_speak`. Idle random gaze resumes a moment later
/// (the lock-clear pushes a short cooldown into `step_gaze`).
struct FocusGuard(Option<VideoTile>);

impl Drop for FocusGuard {
    fn drop(&mut self) {
        if let Some(v) = &self.0 {
            v.set_focus_nick(None);
        }
    }
}

/// Clears the video tile's vision PiP when an `answer_and_speak` call
/// ends — keeps the thumb visible across LLM + TTS so the user sees
/// "she's describing THIS" the whole time she's talking about it.
struct VisionThumbGuard(Option<VideoTile>);

impl Drop for VisionThumbGuard {
    fn drop(&mut self) {
        if let Some(v) = &self.0 {
            v.clear_vision_thumb();
        }
    }
}

/// Classification of an incoming `+freeq.at/av-state` TAGMSG. Pulled
/// out of [`run`]'s big match so it's unit-testable without standing
/// up a full IRC client.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum AvAction {
    /// Skip this event — wrong target shape, missing tags, not one of
    /// our channels, or the actor is the bot itself (avoid self-loop).
    Skip,
    /// Start transcription for `(channel, session_id)`.
    Start { channel: String, session_id: String },
    /// End transcription for `(channel, session_id)`.
    End { channel: String, session_id: String },
    /// A HUMAN joined a call in one of our channels. If we're not in
    /// it, we should be — the lonely watchdog may have walked us out
    /// of this very session while the room was empty, and without
    /// this the human sits in a call no being ever returns to.
    Joined { channel: String, session_id: String },
    /// Anything else we don't act on (left/unknown state) but
    /// shouldn't surface as a hard skip — useful for tracing.
    Noop,
}

/// Pure classifier for av-state TAGMSGs. Centralises:
///   - target must be a channel target (`#` / `&`),
///   - required tags must be present,
///   - `started` is acted on only for one of our joined channels.
///
/// We deliberately do NOT skip `started` events whose
/// `+freeq.at/av-actor` is the bot's own nick. The bot must react to a
/// session *it* started (the `--start-session-in` flow) — that
/// `av-state=started` is attributed to the bot.
///
/// `joined` IS actor-filtered: the bot's own av-join echoes back as an
/// `av-state=joined` attributed to the bot — acting on it would
/// re-trigger a join loop, so self-joined maps to `Noop`. A missing
/// actor also maps to `Noop` (we can't tell human from bot). Peer-agent
/// joins are filtered in the run loop (the classifier doesn't know the
/// peer set).
pub(crate) fn classify_av_event(
    target: &str,
    tags: &std::collections::HashMap<String, String>,
    my_channels: &[String],
    my_nick: &str,
) -> AvAction {
    if !target.starts_with('#') && !target.starts_with('&') {
        return AvAction::Skip;
    }
    let Some(state) = tags.get("+freeq.at/av-state") else {
        return AvAction::Skip;
    };
    let Some(av_id) = tags.get("+freeq.at/av-id") else {
        return AvAction::Skip;
    };

    match state.as_str() {
        "started" => {
            if !my_channels.iter().any(|c| c.eq_ignore_ascii_case(target)) {
                return AvAction::Skip;
            }
            AvAction::Start {
                channel: target.to_string(),
                session_id: av_id.clone(),
            }
        }
        "ended" => AvAction::End {
            channel: target.to_string(),
            session_id: av_id.clone(),
        },
        "joined" => {
            if !my_channels.iter().any(|c| c.eq_ignore_ascii_case(target)) {
                return AvAction::Skip;
            }
            // Self-join echo (our own av-join broadcast back at us) —
            // never act on it. Missing actor → can't attribute → Noop.
            let actor = tags
                .get("+freeq.at/av-actor")
                .map(String::as_str)
                .unwrap_or("");
            if actor.is_empty()
                || canonical_name(actor).eq_ignore_ascii_case(canonical_name(my_nick))
            {
                return AvAction::Noop;
            }
            AvAction::Joined {
                channel: target.to_string(),
                session_id: av_id.clone(),
            }
        }
        _ => AvAction::Noop,
    }
}

async fn wait_for_registration(events: &mut tokio::sync::mpsc::Receiver<Event>) -> Result<String> {
    wait_for_registration_with_timeout(events, Duration::from_secs(30)).await
}

/// Timeout-parameterised flavour so tests don't have to wait 30s of
/// wall-clock to exercise the deadline path. Public-in-crate only.
pub(crate) async fn wait_for_registration_with_timeout(
    events: &mut tokio::sync::mpsc::Receiver<Event>,
    timeout: Duration,
) -> Result<String> {
    loop {
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Some(Event::Registered { nick })) => return Ok(nick),
            Ok(Some(Event::AuthFailed { reason })) => anyhow::bail!("SASL auth failed: {reason}"),
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("connection closed during registration"),
            Err(_) => anyhow::bail!("registration timeout"),
        }
    }
}

/// Open a MoQ subscriber via the SFU and spawn the audio-tap → STT →
/// PRIVMSG pipeline. Returns an `ActiveCall` whose `_moq_task` field's
/// drop tears everything down.
///
/// `existing_instance`: when `Some`, the bot is already a participant
/// in this session (it sent the `av-start`), so we reuse that instance
/// and do NOT send an `av-join` — sending one would mint a second slot
/// and the bot would appear in the call twice. When `None` (joining a
/// session someone else started), we mint a fresh instance and join.
async fn start_transcription(
    cfg: Arc<SharedConfig>,
    handle: Arc<ClientHandle>,
    channel: String,
    session_id: String,
    existing_instance: Option<String>,
    active: Arc<AsyncMutex<Option<ActiveCall>>>,
) -> Result<ActiveCall> {
    let instance_id = match existing_instance {
        Some(inst) => {
            tracing::info!(%inst, "reusing av-start instance — skipping redundant av-join");
            inst
        }
        None => {
            let instance_id = freeq_sdk::av::new_av_instance();
            handle
                .av_join(&channel, &session_id, &instance_id)
                .await
                .context("sending av-join")?;
            instance_id
        }
    };

    // Build the MoQ URL. Use the explicit override if given (e.g. the
    // SFU's QUIC port), else derive `/av/moq` on the IRC server's host.
    let sfu_url = match &cfg.sfu_url_override {
        Some(u) => u
            .parse()
            .with_context(|| format!("parsing --sfu-url {u:?}"))?,
        None => sfu_url_from_server(&cfg.server)?,
    };

    // The agent's video tile. The renderer thread runs for the call's
    // lifetime, producing audio-reactive frames; the audio path shares
    // the loudness cell so the presence pulses with eliza's voice.
    let backend = match cfg.render_backend.as_str() {
        "particles" => crate::video::Backend::Particles {
            character: cfg.ghostly_character.clone(),
            ghostly_pack: cfg.ghostly_pack.clone(),
        },
        "ascii" => crate::video::Backend::Ascii,
        "ascii-rain" => crate::video::Backend::AsciiRain,
        "ascii-glitch" => crate::video::Backend::AsciiGlitch,
        "ascii-bot" => crate::video::Backend::AsciiBot,
        "vector" => crate::video::Backend::Vector,
        "southpark" => crate::video::Backend::SouthPark,
        "southpark-goofy" => crate::video::Backend::SouthParkGoofy,
        "southpark-stoner" | "southpark-burnout" => crate::video::Backend::SouthParkStoner,
        "3d" | "face3d" => crate::video::Backend::Face3d,
        "3d-angry" => crate::video::Backend::Face3dAngry,
        "3d-joy" => crate::video::Backend::Face3dJoy,
        "3d-eye" => crate::video::Backend::Face3dEye,
        "3d-shard" => crate::video::Backend::Face3dShard,
        "alexandria" => crate::video::Backend::Alexandria,
        _ => crate::video::Backend::Svg,
    };
    let video = VideoTile::with_backend(backend);
    // Audio-only beings skip the renderer thread — no raster, no frames to
    // encode — so the real-time audio path keeps its CPU on a constrained host.
    if !cfg.no_video {
        video.spawn_renderer();
    }

    // Pair a Speaker (kept here) with a PushAudioSource (published by
    // the AvSession as the bot's broadcast). Enqueueing on the Speaker
    // makes the bot talk.
    let (speaker, push_source) = Speaker::new(video.level_handle());

    let av_config = AvConfig {
        sfu_url,
        session_id: session_id.clone(),
        our_broadcast: broadcast_path(&session_id, &cfg.nick, &instance_id),
        my_nick: cfg.nick.clone(),
        audio_only: cfg.no_video,
    };

    // Dispatcher task: own the AvSession and spawn one transcription
    // task per participant it taps. The transcription tasks live in a
    // local JoinSet, so aborting this task (ActiveCall::drop on call
    // end) drops the AvSession *and* every transcription task.
    let cfg_for_task = cfg.clone();
    let channel_for_task = channel.clone();
    let handle_for_task = handle.clone();
    let active_for_task = active.clone();
    let video_for_session = video.clone();
    let video_for_taps = video.clone();
    // Live count of people we're transcribing — shared across this call's taps
    // (so each can tell one-on-one from a group) AND the lonely watchdog below.
    let humans = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let humans_for_task = humans.clone();
    // When the last human left — drives the stale-transcript fence so a
    // human joining a long-empty call gets a fresh conversation, not the
    // tail of a dead one. See [`STALE_TRANSCRIPT_GAP`].
    let last_human_left: LastHumanLeft = Arc::new(std::sync::Mutex::new(None));
    let last_human_left_for_task = last_human_left.clone();
    // Live nick roster across this call's taps — lets the addressing
    // gate see when a question opens by naming a different participant.
    let roster: CallRoster = Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    let roster_for_task = roster.clone();
    // Nick → video handle across this call's taps — lets a TYPED visual
    // question find the asker's camera (see [`CallVideoTaps`]).
    let video_taps: CallVideoTaps =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let video_taps_for_task = video_taps.clone();
    let task = tokio::spawn(async move {
        let mut session =
            AvSession::connect(av_config, push_source, move || video_for_session.source());
        let mut taps: JoinSet<()> = JoinSet::new();
        while let Some(participant) = session.recv().await {
            taps.spawn(transcribe_participant(
                cfg_for_task.clone(),
                participant,
                channel_for_task.clone(),
                handle_for_task.clone(),
                active_for_task.clone(),
                video_for_taps.peer_level_handle(),
                humans_for_task.clone(),
                roster_for_task.clone(),
                video_taps_for_task.clone(),
                last_human_left_for_task.clone(),
            ));
        }
        tracing::info!("AvSession ended");
    });

    // Proactive monitor — chimes in unprompted when she has something
    // useful to add. The task aborts via ActiveCall::drop on call-end.
    let proactive_task = if cfg.proactive_enabled {
        Some(crate::proactive::spawn_monitor(
            cfg.clone(),
            handle.clone(),
            channel.clone(),
            active.clone(),
        ))
    } else {
        None
    };

    // Ambient monitor — silent visual companion. While the proactive
    // monitor decides *when to speak*, the ambient monitor decides *how
    // the tile should look*. Independent loops, snapshotting the same
    // shared transcript.
    let ambient_task = if cfg.ambient_enabled {
        Some(crate::ambient::spawn_monitor(
            cfg.clone(),
            handle.clone(),
            active.clone(),
        ))
    } else {
        None
    };

    // Ambient-research monitor — silent text-channel companion. While she's
    // not addressed, it recognizes the topics in the conversation, notes them,
    // and drops definitions/links for help-worthy technical topics into chat.
    let research_task = if cfg.research_enabled {
        Some(crate::research::spawn_monitor(
            cfg.clone(),
            handle.clone(),
            channel.clone(),
            active.clone(),
        ))
    } else {
        None
    };

    // Lonely watchdog — leave the call once we've been alone in it for a
    // while, so the being returns to idle (and the box can sleep to ~$0)
    // instead of holding a tap open on an empty room. Aborts via
    // ActiveCall::drop when the call ends for any other reason.
    let lonely_task = Some(tokio::spawn(lonely_watchdog(
        active.clone(),
        humans.clone(),
        session_id.clone(),
    )));

    Ok(ActiveCall {
        channel,
        session_id,
        instance_id,
        joined_at: Instant::now(),
        transcript: Vec::new(),
        last_answer: None,
        last_question: None,
        speaker,
        video,
        video_taps,
        moq_task: task,
        proactive_task,
        ambient_task,
        research_task,
        lonely_task,
        handle,
    })
}

/// Watchdog that leaves the current call once the being has been alone in
/// it (no humans being transcribed) for `ALONE_LEAVE`. Polls every
/// `CHECK`; exits quietly if the call is replaced or already gone, so a new
/// call's watchdog never tears down a different session.
async fn lonely_watchdog(
    active: Arc<AsyncMutex<Option<ActiveCall>>>,
    humans: Arc<std::sync::atomic::AtomicUsize>,
    session_id: String,
) {
    use std::sync::atomic::Ordering;
    // Seconds alone before leaving. Override with `ELIZA_ALONE_LEAVE_SECS`;
    // set it to 0 to never auto-leave (e.g. parking a being in a call for a
    // demo / kiosk).
    let alone_secs = std::env::var("ELIZA_ALONE_LEAVE_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(60);
    if alone_secs == 0 {
        tracing::info!("lonely watchdog disabled (ELIZA_ALONE_LEAVE_SECS=0)");
        return;
    }
    let alone_leave = Duration::from_secs(alone_secs);
    const CHECK: Duration = Duration::from_secs(10);
    let mut alone_since: Option<Instant> = None;
    loop {
        tokio::time::sleep(CHECK).await;
        // Bail if this is no longer the live call.
        {
            let g = active.lock().await;
            if !matches!(g.as_ref(), Some(c) if c.session_id == session_id) {
                return;
            }
        }
        if humans.load(Ordering::Relaxed) == 0 {
            let since = *alone_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= alone_leave {
                let mut g = active.lock().await;
                if matches!(g.as_ref(), Some(c) if c.session_id == session_id) {
                    tracing::info!(%session_id, "alone in the call too long — leaving");
                    *g = None; // ActiveCall::drop tears down taps + tasks
                }
                return;
            }
        } else {
            alone_since = None;
        }
    }
}

// ── Addressed-question dispatch timing ──────────────────────────────

/// After dispatching an answer, ignore further addressed questions for
/// this long. Collapses the duplicate transcriptions a multi-device
/// speaker produces (each device's broadcast is tapped separately) and
/// keeps Eliza from piling answers up while she is still speaking.
///
/// Short, because it is now CONTENT-AWARE (see [`is_near_duplicate`]): only a
/// repeat that matches the last answered question is dropped within this
/// window. 8 s used to be purely time-based and swallowed genuine follow-ups
/// ("how's the weather" → "I'm flying from LaGuardia"), breaking back-and-forth
/// conversation. Multi-device duplicate broadcasts arrive within ~1-2 s.
const ANSWER_DEBOUNCE: Duration = Duration::from_millis(2500);

/// Two transcriptions are "the same question" (a duplicate broadcast, not a
/// real follow-up) when their normalized forms match. Multi-device taps of the
/// same utterance transcribe identically; a new question differs.
fn is_near_duplicate(a: &str, b: &str) -> bool {
    fn norm(s: &str) -> String {
        s.chars()
            .filter(|c| c.is_alphanumeric() || c.is_whitespace())
            .flat_map(|c| c.to_lowercase())
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }
    let (na, nb) = (norm(a), norm(b));
    !na.is_empty() && (na == nb || na.contains(&nb) || nb.contains(&na))
}
/// After the bot joins, ignore addressed questions for this long. The
/// server replays a burst of channel history on join (and the SFU can
/// replay buffered audio) — answering that backlog is an unprompted
/// "monologue" of stale messages. Live questions come after the burst.
const STARTUP_GRACE: Duration = Duration::from_secs(15);
/// Voice version of the join grace — relative to call-join (not process start)
/// and kept short, so it only skips the post-join audio burst and never
/// suppresses live questions after a restart/wake mid-call.
const CALL_JOIN_GRACE: Duration = Duration::from_secs(3);

// ── Owner lifecycle commands ────────────────────────────────────────
// The owner can tell the bot to sleep / join / leave by voice or text.
// We can't suspend the VM from here (the boxd key lives in the watcher,
// by design) — so on "sleep" the bot leaves cleanly and schedules its own
// service stop just outside its cgroup; boxd auto-suspend then takes the VM
// to ~$0, and the always-on watcher resumes it on the next summon.

#[derive(Debug)]
enum OwnerCmd {
    Sleep,
    Join(String),
    Leave,
    /// Mitosis: fork this being into a new one. Carries the owner's full
    /// utterance — the mutation ("…but make her an optimist") rides along
    /// for the child-composition model. See [`crate::mitosis`].
    Fork(String),
}

/// Is `who` the configured owner? (Nick/handle match, case-insensitive.)
fn is_owner(cfg: &SharedConfig, who: &str) -> bool {
    cfg.owner
        .as_deref()
        .is_some_and(|o| o.eq_ignore_ascii_case(who))
}

/// Parse an owner lifecycle command from an addressed utterance.
fn parse_owner_command(text: &str) -> Option<OwnerCmd> {
    let t = text.to_lowercase();
    let tt = t.trim();
    let words = tt.split_whitespace().count();
    let has_word = |w: &str| tt.split(|c: char| !c.is_alphanumeric()).any(|x| x == w);
    // Mitosis: "fork yourself", "clone yourself", "split yourself", "make a
    // copy of yourself" — the rest of the line rides along as the mutation
    // ("…but make her an optimist"). Checked FIRST: a fork utterance can be
    // long and could otherwise trip the looser sleep/leave matchers.
    let about_self = t.contains("yourself") || t.contains("your self") || t.contains("of you");
    if about_self
        && (has_word("fork")
            || has_word("clone")
            || has_word("split")
            || has_word("duplicate")
            || has_word("copy"))
    {
        return Some(OwnerCmd::Fork(text.trim().to_string()));
    }
    // Sleep is owner-gated and the intent is unambiguous, so be STT-tolerant:
    // Whisper mangles "go to sleep" into "goes to sleep" / "all the sleep" /
    // even "all of god's sleep". Treat any SHORT owner utterance that mentions
    // sleep/nap (or the old explicit phrases) as the sleep command — the length
    // cap keeps a real sentence ("I couldn't sleep last night") from matching.
    if t.contains("go to bed")
        || t.contains("power down")
        || ((has_word("sleep") || has_word("nap") || has_word("asleep")) && words <= 8)
    {
        return Some(OwnerCmd::Sleep);
    }
    if let Some(i) = t.find('#') {
        let before = &t[..i];
        if before.contains("join") || before.contains("come to") || before.contains("go to") {
            let ch: String = t[i..]
                .chars()
                .take_while(|c| !c.is_whitespace() && !matches!(c, '.' | ',' | '!' | '?'))
                .collect();
            if ch.len() > 1 {
                return Some(OwnerCmd::Join(ch));
            }
        }
    }
    // Leave: same tolerance — a short owner utterance with "leave"/"go away".
    if t.contains("go away") || (has_word("leave") && words <= 6) || tt == "dismiss" {
        return Some(OwnerCmd::Leave);
    }
    None
}

/// Actuate an owner command. Join/leave act directly; sleep acks, then leaves
/// and schedules a service stop outside our cgroup (so it survives teardown).
async fn run_owner_command(handle: &ClientHandle, channel: Option<&str>, cmd: OwnerCmd) {
    match cmd {
        OwnerCmd::Sleep => {
            tracing::info!("owner command: sleep");
            // We can't suspend our own VM (the boxd key lives in the watcher, by
            // design). Relay via a coordination event — the watcher stops us and
            // suspends the VM to ~$0, then resumes us on the next summon. The
            // human_text doubles as the posted/spoken acknowledgement.
            if let Some(ch) = channel {
                let _ = handle
                    .emit_event(
                        ch,
                        "revenant_sleep",
                        "{}",
                        None,
                        "Resting now \u{1F4A4} — call my name when you need me.",
                    )
                    .await;
            }
        }
        OwnerCmd::Join(c) => {
            tracing::info!(channel = %c, "owner command: join");
            let _ = handle.join(&c).await;
            if let Some(ch) = channel {
                let _ = handle.privmsg(ch, &format!("On my way to {c}.")).await;
            }
        }
        OwnerCmd::Leave => {
            tracing::info!("owner command: leave");
            if let Some(ch) = channel {
                let _ = handle
                    .privmsg(ch, "Heading out \u{1F44B} — call me back anytime.")
                    .await;
                let _ = handle.raw(&format!("PART {ch}")).await;
            }
        }
        // Fork is dispatched to `crate::mitosis::spawn` at the call sites
        // (it needs the shared config + the call speaker); it never lands
        // here. Kept exhaustive on purpose.
        OwnerCmd::Fork(_) => {
            tracing::warn!("owner command: fork reached run_owner_command (dispatch bug)");
        }
    }
}

/// Decrements a shared tap counter on drop — tracks how many participants we
/// are currently transcribing (i.e. how many other humans are in the call) —
/// and removes the participant's nick from the live call roster.
struct TapGuard {
    humans: Arc<std::sync::atomic::AtomicUsize>,
    /// Whether this tap incremented `humans` (peer agents don't) — the
    /// decrement must mirror the increment or the count drifts negative.
    counted: bool,
    roster: CallRoster,
    video_taps: CallVideoTaps,
    nick: String,
    /// Stamped when this drop takes the human count to ZERO — the
    /// stale-transcript fence reads it when the next human arrives.
    /// See [`STALE_TRANSCRIPT_GAP`].
    last_human_left: LastHumanLeft,
}
impl Drop for TapGuard {
    fn drop(&mut self) {
        if self.counted {
            let prev = self
                .humans
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            if prev == 1 {
                // Room just went human-empty.
                if let Ok(mut g) = self.last_human_left.lock() {
                    *g = Some(Instant::now());
                }
            }
        }
        if let Ok(mut r) = self.roster.lock() {
            r.remove(&self.nick);
        }
        if let Ok(mut v) = self.video_taps.lock() {
            v.remove(&self.nick);
        }
    }
}

/// When the call has been human-empty for at least this long, whatever
/// is in the in-call transcript is a DEAD conversation — the next human
/// to walk in starts a new one, and feeding them someone else's context
/// makes the being answer a conversation they weren't in ("it felt like
/// Olive's conversation was not the one I was having"). Kept above the
/// network-blip scale so a brief rejoin keeps its context.
const STALE_TRANSCRIPT_GAP: Duration = Duration::from_secs(60);

/// Shared per-call cell: when did the last human leave? `None` while
/// humans are present (or before any ever joined).
type LastHumanLeft = Arc<std::sync::Mutex<Option<Instant>>>;

/// Live set of participant nicks we're currently tapping (lowercased,
/// as-published). Shared across a call's tap tasks so the addressing
/// gate can tell when a question opens by naming someone *else*.
pub(crate) type CallRoster = Arc<std::sync::Mutex<std::collections::HashSet<String>>>;

/// Live map of tapped participant nick (lowercased) → their video handle.
/// Shared across a call's tap tasks so a question TYPED in the channel can
/// still see the asker's camera — the voice path gets the handle with the
/// utterance, but the PRIVMSG path has only a nick (observed live: "read me
/// the title on my tile" typed mid-call answered "no frame coming through"
/// while the same question by voice described the frame).
pub(crate) type CallVideoTaps =
    Arc<std::sync::Mutex<std::collections::HashMap<String, VideoHandle>>>;

/// The asker's video handle, by nick. Exact lowercase match first; a
/// server-suffixed variant ("olive-3qkx…") still matches its base name in
/// either direction, since IRC nick and broadcast nick can disagree on the
/// suffix.
pub(crate) fn lookup_tap_video(taps: &CallVideoTaps, asker: &str) -> Option<VideoHandle> {
    let want = asker.to_ascii_lowercase();
    let m = taps.lock().ok()?;
    if let Some(vh) = m.get(&want) {
        return Some(vh.clone());
    }
    let base = |s: &str| {
        s.split_once('-')
            .map(|(p, _)| p.to_string())
            .unwrap_or_else(|| s.to_string())
    };
    let want_base = base(&want);
    m.iter()
        .find_map(|(k, vh)| (base(k) == want_base).then(|| vh.clone()))
}

/// True when `text` opens by addressing some OTHER named participant or
/// peer agent — "Yokota, what is two plus two?" is Yokota's question,
/// and an agent named anything else must not answer it just because it
/// is a question. `others` are candidate names (roster nicks + the
/// configured peer agents); the agent's own name is filtered out so a
/// genuine address to us never matches here.
pub(crate) fn addressed_to_other(text: &str, self_nick: &str, others: &[String]) -> bool {
    let self_canonical = self_nick
        .split_once('-')
        .map(|(p, _)| p)
        .unwrap_or(self_nick)
        .to_ascii_lowercase();
    let refs: Vec<&str> = others
        .iter()
        .map(|s| s.as_str())
        .filter(|n| !n.eq_ignore_ascii_case(&self_canonical))
        .collect();
    crate::social::extract_addressee(text, &refs).is_some()
}

/// Worth responding to? Filters empty/backchannel utterances so the bot doesn't
/// react to "yeah" / "um" when it's listening for real input.
fn is_substantive(text: &str) -> bool {
    let t = text.trim().to_lowercase();
    if t.is_empty() || !t.chars().any(|c| c.is_alphabetic()) {
        return false;
    }
    let words: Vec<&str> = t.split_whitespace().collect();
    if words.len() == 1 {
        const FILLER: [&str; 14] = [
            "yeah", "yep", "ok", "okay", "mm", "mhm", "uh", "um", "hmm", "right", "sure", "cool",
            "nice", "what",
        ];
        let w = words[0].trim_matches(|c: char| !c.is_alphanumeric());
        return !FILLER.contains(&w);
    }
    true
}

/// Does this utterance look like a question? STT rarely emits "?", so a leading
/// question word also counts.
fn looks_like_question(text: &str) -> bool {
    let t = text.trim().to_lowercase();
    if t.ends_with('?') {
        return true;
    }
    const Q: [&str; 16] = [
        "what", "why", "how", "when", "where", "who", "which", "can", "could", "would", "should",
        "is", "are", "do", "does", "did",
    ];
    t.split_whitespace()
        .next()
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        .is_some_and(|w| Q.contains(&w))
}

/// The bot's character name without the server DID suffix —
/// `oblivion-z6mkfa8x` → `oblivion`. What humans say and what
/// transcript lines should carry.
fn canonical_name(nick: &str) -> &str {
    nick.split_once('-').map(|(p, _)| p).unwrap_or(nick)
}

/// How many transcript lines ride along as context on a QA prompt. A
/// long call's full transcript drowns the question (and the token
/// budget); the model needs the recent conversation, not the hour.
const TRANSCRIPT_PROMPT_LINES: usize = 60;

/// The last `max` lines of a transcript, joined — the QA-prompt
/// snapshot. The full transcript stays in the call for the end-of-call
/// summary.
fn recent_lines(lines: &[String], max: usize) -> String {
    let start = lines.len().saturating_sub(max);
    lines[start..].join("\n")
}

/// True when the utterance is nothing but the bot's name (plus
/// fillers/punctuation) — "Yokota." / "hey yokota". TTS comma pauses
/// and human hesitation make the VAD cut "Yokota, please read…" into
/// "Yokota." + the question as two segments, and neither alone passes
/// the named gate. A bare name primes the speaker's NEXT segment as
/// addressed (see `transcribe_participant`).
///
/// Implementation trick: append a sentinel word and run the normal
/// address parser — it matches iff every real word before the sentinel
/// was the name (with the usual filler/split/mishearing tolerance).
fn is_bare_name(text: &str, nick: &str) -> bool {
    address_with_aliases(&format!("{} zzsentinel", text.trim()), nick).as_deref()
        == Some("zzsentinel")
}

/// How long a bare-name utterance keeps the speaker's next segment
/// treated as addressed.
const NAME_PRIME_WINDOW: Duration = Duration::from_secs(4);

/// Whether an answer is worth freezing into a shareable "moment" card: a tight,
/// quotable line (not a stub, not an apology/error, not a wall of text).
fn is_moment_worthy(text: &str) -> bool {
    let t = text.trim();
    let len = t.chars().count();
    if !(25..=280).contains(&len) || !t.chars().any(|c| c.is_alphabetic()) {
        return false;
    }
    let lc = t.to_lowercase();
    ![
        "sorry",
        "i couldn't",
        "i could not",
        "i can't",
        "i cannot",
        "i'm not able",
    ]
    .iter()
    .any(|p| lc.starts_with(p))
}

/// Consume one participant's decoded-PCM stream (from an [`AvSession`])
/// and segment it into utterances by voice activity — accumulate while
/// the speaker is talking, flush to STT on a natural pause. This kills
/// both the "Thank you." silence hallucinations (silent stretches never
/// reach STT) and the mid-sentence splits (we cut at pauses, not on a
/// fixed clock).
async fn transcribe_participant(
    cfg: Arc<SharedConfig>,
    participant: AvParticipant,
    channel: String,
    handle: Arc<ClientHandle>,
    active: Arc<AsyncMutex<Option<ActiveCall>>>,
    // Shared loudness cell — fed the participant's level so the video
    // presence can show a "listening" mood when a human is talking.
    peer_level: Arc<std::sync::atomic::AtomicU32>,
    // Live count of participants being transcribed (= other humans in the
    // call). When it's just one of them and us, no name is needed to address us.
    humans: Arc<std::sync::atomic::AtomicUsize>,
    // Shared nick roster for the call — see [`CallRoster`].
    roster: CallRoster,
    // Shared nick → video map — see [`CallVideoTaps`].
    video_taps: CallVideoTaps,
    // When the last human left the call — see [`STALE_TRANSCRIPT_GAP`].
    last_human_left: LastHumanLeft,
) {
    let AvParticipant {
        path,
        nick,
        mut audio,
        video,
    } = participant;
    let stt = cfg.stt.clone();
    // `humans` drives the 1:1 conversational gate ("alone with one
    // person, every sentence is for me") — a peer AGENT on the call
    // must not count, or one human + two bots reads as a group call
    // and the bot goes name-only.
    let counted = !is_peer_nick(&cfg.peer_agents, &nick);
    if counted {
        let prev = humans.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if prev == 0 {
            // First human in the room. If it's been human-empty past the
            // fence, the in-call transcript is a dead conversation —
            // clear it so the being doesn't answer from someone else's
            // context. `take()` re-arms the fence either way; the marker
            // is only meaningful across a humans==0 stretch.
            let stale = last_human_left
                .lock()
                .ok()
                .and_then(|mut g| g.take())
                .is_some_and(|t| t.elapsed() >= STALE_TRANSCRIPT_GAP);
            if stale
                && let Some(call) = active.lock().await.as_mut()
                && !call.transcript.is_empty()
            {
                tracing::info!(
                    %nick,
                    lines = call.transcript.len(),
                    "stale call transcript cleared — new conversation"
                );
                call.transcript.clear();
                call.last_answer = None;
            }
        }
    }
    if let Ok(mut r) = roster.lock() {
        r.insert(nick.to_ascii_lowercase());
    }
    if let Ok(mut v) = video_taps.lock() {
        v.insert(nick.to_ascii_lowercase(), video.clone());
    }
    let _tap = TapGuard {
        // decrement + de-roster + de-map when this tap ends
        humans: humans.clone(),
        counted,
        roster: roster.clone(),
        video_taps: video_taps.clone(),
        nick: nick.to_ascii_lowercase(),
        last_human_left,
    };
    tracing::info!(%nick, %path, "participant audio live — transcribing");

    // Bare-name priming state for this participant — set when they say
    // just the bot's name, consumed by their next utterance. See
    // `is_bare_name`.
    let name_primed: Arc<std::sync::Mutex<Option<Instant>>> = Arc::new(std::sync::Mutex::new(None));
    // The mirror for OTHER agents: a bare "Yokota." (heard by Olive)
    // marks the speaker's next segment as someone else's — without
    // this, the 1:1 conversational gate answers a question the VAD
    // split away from its addressee's name.
    let other_primed: Arc<std::sync::Mutex<Option<Instant>>> =
        Arc::new(std::sync::Mutex::new(None));

    // Streaming STT (Deepgram): when configured, the server does
    // endpointing + transcription on a persistent websocket, so finalised
    // utterances arrive within a few hundred ms of speech end — far
    // tighter than the local VAD + Groq round-trip below. Same downstream
    // dispatch; we just produce `text` from the socket instead of Whisper.
    if let Some(dg) = cfg.stt_streaming.clone() {
        stream_participant_deepgram(
            dg,
            audio,
            cfg.clone(),
            nick.clone(),
            channel.clone(),
            handle.clone(),
            active.clone(),
            peer_level.clone(),
            humans.clone(),
            roster.clone(),
            name_primed.clone(),
            other_primed.clone(),
            video.clone(),
            video_taps.clone(),
        )
        .await;
        tracing::info!(%nick, "participant audio stream ended (streaming)");
        return;
    }

    // VAD: turn the PCM stream into utterances, cut at natural pauses.
    let mut segmenter = VadSegmenter::new(VadConfig::default());
    let mut frames_seen: u64 = 0;

    while let Some(frame) = audio.recv().await {
        frames_seen += 1;
        let pcm = to_whisper_pcm(&frame.samples, frame.format);
        if pcm.is_empty() {
            continue;
        }
        let peak = pcm.iter().fold(0.0f32, |m, &s| m.max(s.abs()));
        // Feed the video presence's "listening" mood — snap up, ease down.
        {
            use std::sync::atomic::Ordering;
            let prev = f32::from_bits(peer_level.load(Ordering::Relaxed));
            let smoothed = if peak > prev {
                peak
            } else {
                prev * 0.9 + peak * 0.1
            };
            peer_level.store(smoothed.to_bits(), Ordering::Relaxed);
        }

        if frames_seen == 1 || frames_seen.is_multiple_of(250) {
            tracing::info!(
                %nick, frames_seen, buffered = segmenter.buffered(), peak,
                in_rate = frame.format.sample_rate,
                in_channels = frame.format.channel_count,
                "audio tap heartbeat"
            );
        }

        // Accumulate; `push` yields a chunk only on a completed utterance
        // (pre-speech silence and noise-only flushes stay inside the
        // segmenter).
        let Some(utt) = segmenter.push_stats(&pcm) else {
            continue;
        };
        // Turn starts here: the VAD just decided the user stopped talking.
        // `t_flush` is the rhythm anchor (speech_end); `turn` correlates
        // every downstream latency line for this utterance.
        let turn = next_turn_id();
        let t_flush = Instant::now();
        let chunk = utt.pcm;
        let utter_ms = (chunk.len() as u64) * 1000 / 16_000;
        let voiced_ms = (utt.voiced_samples as u64) * 1000 / 16_000;
        let trailing_silence_ms = (utt.trailing_silence_samples as u64) * 1000 / 16_000;
        tracing::info!(
            turn,
            %nick,
            utter_ms,
            voiced_ms,
            trailing_silence_ms,
            "latency: VAD flush (turn start; trailing_silence is pre-answer dead air)"
        );

        let stt = stt.clone();
        let nick = nick.clone();
        let channel = channel.clone();
        let handle = handle.clone();
        let active = active.clone();
        let cfg = cfg.clone();
        let humans = humans.clone();
        let roster = roster.clone();
        let name_primed = name_primed.clone();
        let other_primed = other_primed.clone();
        // The asker's own video — so a visual question can be answered
        // from what they're showing.
        let asker_video = video.clone();
        // A screen share is a SEPARATE `{name}/screen` broadcast, tapped as a
        // participant nicked "screen" — distinct from the camera tap above.
        // Resolve it so screen questions ("look at my screen") actually see it.
        let video_taps_for_screen = video_taps.clone();
        // `SttEngine::transcribe` is async — Groq is an HTTP round-trip,
        // local whisper does its own spawn_blocking internally. One task
        // per utterance so a slow STT call doesn't stall the tap loop.
        tokio::spawn(async move {
            let t_stt = Instant::now();
            let audio_sec = chunk.len() as f32 / 16_000.0;
            let stt_result = stt.transcribe(&chunk).await;
            let stt_ms = t_stt.elapsed().as_millis() as u64;
            tracing::info!(
                turn,
                %nick,
                elapsed_ms = stt_ms,
                audio_sec,
                rtf = if audio_sec > 0.0 { stt_ms as f32 / (audio_sec * 1000.0) } else { 0.0 },
                since_speech_end_ms = t_flush.elapsed().as_millis() as u64,
                "latency: STT round-trip"
            );
            match stt_result {
                Ok(text) => {
                    dispatch_utterance(
                        cfg,
                        nick,
                        channel,
                        handle,
                        active,
                        humans,
                        roster,
                        name_primed,
                        other_primed,
                        asker_video,
                        video_taps_for_screen,
                        turn,
                        t_flush,
                        text,
                    )
                    .await;
                }
                Err(e) => {
                    tracing::warn!(%nick, error = ?e, "STT failed");
                }
            }
        });
    }
    tracing::info!(%nick, "participant audio stream ended");
}

/// Run one finalised utterance through the full addressing + answer
/// pipeline. Shared by the batched-Whisper tap (`transcribe_participant`)
/// and the Deepgram streaming tap — both produce a `text` for one speaker
/// turn and hand it here, so the addressing logic lives in exactly one place.
#[allow(clippy::too_many_arguments)]
async fn dispatch_utterance(
    cfg: Arc<SharedConfig>,
    nick: String,
    channel: String,
    handle: Arc<ClientHandle>,
    active: Arc<AsyncMutex<Option<ActiveCall>>>,
    humans: Arc<std::sync::atomic::AtomicUsize>,
    roster: CallRoster,
    name_primed: Arc<std::sync::Mutex<Option<Instant>>>,
    other_primed: Arc<std::sync::Mutex<Option<Instant>>>,
    asker_video: VideoHandle,
    video_taps_for_screen: CallVideoTaps,
    turn: u64,
    t_flush: Instant,
    text: String,
) {
    if text.is_empty() || is_hallucination(&text) {
        tracing::info!(%nick, %text, "dropped empty/hallucinated utterance");
        return;
    }
    // Own-TTS echo: a participant without echo
    // cancellation plays our voice out their speakers,
    // their mic picks it up, and it comes back
    // transcribed under their nick. Answering it = the
    // bot talking to itself in a loop. Drop it before
    // it reaches the transcript or the addressing gate.
    if is_own_echo(&cfg.recent_tts, &text) {
        tracing::info!(%nick, %text, "dropped own-TTS echo");
        return;
    }
    tracing::info!(%nick, %text, "transcribed utterance");

    // Discussion-mode trigger. A human cue ("discuss
    // it", "debate this", …) unlocks bot↔bot replies
    // for 90 s, letting the agents converse without
    // the operator having to address each one. The
    // window is per-bot (each bot maintains its own
    // copy of `discussion_until`); each one sees the
    // same human cue so they all extend in lockstep.
    if !is_peer_nick(&cfg.peer_agents, &nick)
        && crate::social::is_discussion_trigger(&text)
        && let Ok(mut deadline) = cfg.discussion_until.lock()
    {
        *deadline = Instant::now() + Duration::from_secs(90);
        tracing::info!("discussion mode armed — bot↔bot replies allowed for 90 s");
    }

    // Peer-aware gaze: if this utterance is a human
    // addressing one of the OTHER agents in the room,
    // swing our head toward that peer. Reads as a real
    // meeting — three people in a room, when one is
    // called on, the others look at them.
    if !is_peer_nick(&cfg.peer_agents, &nick) {
        let peer_names: Vec<&str> = cfg.peer_agents.iter().map(|s| s.as_str()).collect();
        if let Some(addressee) = crate::social::extract_addressee(&text, &peer_names) {
            // Only swing gaze when the addressee is
            // NOT us — when WE are being addressed,
            // the answer flow's FocusGuard already
            // points our eyes at the asker.
            let self_canonical = cfg
                .nick
                .split_once('-')
                .map(|(p, _)| p)
                .unwrap_or(cfg.nick.as_str())
                .to_ascii_lowercase();
            if addressee != self_canonical
                && let Some(call) = active.lock().await.as_ref()
            {
                call.video.set_focus_nick(Some(addressee.clone()));
                tracing::info!(
                    target = %addressee,
                    "peer-aware gaze — looking at addressed peer"
                );
            }
        }

        // Hand-raise: my name was dropped mid-
        // sentence but not directly addressed.
        // Brighten the halo briefly so the operator
        // sees "I have something to add" without me
        // actually speaking.
        if crate::social::mention_without_address(&text, &cfg.nick)
            && let Some(call) = active.lock().await.as_ref()
        {
            call.video.flash_hand_raise();
            tracing::info!("hand-raise — my name was mentioned");
        }
    }

    // Voice-addressed Q&A. People don't say someone's name to
    // address them, so neither should they have to say ours —
    // but we must NOT answer every ambient line either. So:
    //  • named ("eliza, …")  → always addressed
    //  • a question          → addressed (any call size)
    //  • 1:1 + substantive   → addressed (conversational mode:
    //    alone with one human, every real sentence is for us —
    //    STT name-mangling kept dropping legitimate requests)
    //  • bare declaratives in a group → ignored (ambient)
    // We're always transcribing regardless; this only decides
    // when to *answer*. `humans` is the live count of humans in
    // the call (1 == one-on-one with us; peer agents excluded).
    let mut named = address_with_aliases(&text, &cfg.nick);
    let humans = humans.load(std::sync::atomic::Ordering::Relaxed);

    // Other participants + configured peers — used for
    // "addressed to someone else" checks. Candidates come
    // from the live call roster (so this works even when
    // --peer-agents wasn't configured) plus the peer list.
    let others: Vec<String> = {
        let mut others: Vec<String> = roster
            .lock()
            .map(|r| {
                r.iter()
                    .map(|n| n.split_once('-').map(|(p, _)| p).unwrap_or(n).to_string())
                    .collect()
            })
            .unwrap_or_default();
        others.extend(cfg.peer_agents.iter().cloned());
        others.sort();
        others.dedup();
        others
    };

    // Name-primed merge: a bare "Yokota." segment (the VAD
    // cutting at the comma of "Yokota, please read…") makes
    // the speaker's NEXT segment addressed, so the split
    // question still lands.
    if named.is_none() && is_bare_name(&text, &cfg.nick) {
        if let Ok(mut primed) = name_primed.lock() {
            *primed = Some(Instant::now());
        }
        tracing::info!(%nick, "bare name heard — priming next segment as addressed");
        return;
    }
    // Mirror: a bare PEER name primes the next segment as
    // addressed to THEM, so we don't steal it via the 1:1
    // gate. (The bare line itself already suppresses via
    // `addressed_to_other` below.)
    if named.is_none() && others.iter().any(|o| is_bare_name(&text, o)) {
        if let Ok(mut primed) = other_primed.lock() {
            *primed = Some(Instant::now());
        }
        tracing::info!(
            %nick,
            "bare peer name heard — priming next segment as addressed to other"
        );
    }
    if named.is_none() {
        let was_primed = name_primed
            .lock()
            .ok()
            .and_then(|mut p| p.take())
            .is_some_and(|t| t.elapsed() <= NAME_PRIME_WINDOW);
        if was_primed && is_substantive(&text) {
            tracing::info!(%nick, "name-primed segment — treating as addressed");
            named = Some(text.trim().to_string());
        }
    }
    // Consume an other-agent prime: within the window, an
    // unnamed follow-up segment belongs to the primed peer.
    let other_primed_hit = named.is_none()
        && other_primed
            .lock()
            .ok()
            .and_then(|mut p| p.take())
            .is_some_and(|t| t.elapsed() <= NAME_PRIME_WINDOW);

    // Owner lifecycle command by voice ("go to sleep", "join #x",
    // "leave") — owner-only, past the call-join grace (so replayed
    // audio can't re-sleep us). Checked BEFORE the Q&A gate: a
    // command isn't a question/request, so it must not depend on
    // being "addressed". Match on the name-stripped remainder when
    // named, else the raw line ("olive, go to sleep" / "go to sleep").
    if is_owner(&cfg, &nick) {
        let past_grace = active
            .lock()
            .await
            .as_ref()
            .is_some_and(|c| c.joined_at.elapsed() >= CALL_JOIN_GRACE);
        if past_grace {
            let cmd_text = named.as_deref().unwrap_or(&text);
            if let Some(cmd) = parse_owner_command(cmd_text) {
                tracing::info!(%nick, "owner lifecycle command by voice");
                if let OwnerCmd::Fork(utt) = cmd {
                    // Mitosis: own task + spoken progress.
                    let speaker = active.lock().await.as_ref().map(|c| c.speaker.clone());
                    crate::mitosis::spawn(
                        cfg.clone(),
                        handle.clone(),
                        channel.clone(),
                        utt,
                        speaker,
                    );
                } else {
                    run_owner_command(&handle, Some(&channel), cmd).await;
                }
                return;
            }
        }
    }

    // A question that opens by naming a DIFFERENT
    // participant or peer agent is theirs, not ours —
    // "Yokota, what is two plus two?" must not be
    // answered by Olive just because it's a question.
    // `other_primed_hit` covers the VAD-split variant
    // ("Yokota." … "what is two plus two?").
    let to_other =
        named.is_none() && (other_primed_hit || addressed_to_other(&text, &cfg.nick, &others));
    let inferred: Option<String> = named.clone().or_else(|| {
        if !is_substantive(&text) || to_other {
            None
        } else if looks_like_question(&text) || humans <= 1 {
            Some(text.trim().to_string())
        } else {
            None
        }
    });
    tracing::info!(
        %nick, humans,
        named = named.is_some(),
        to_other,
        addressed = inferred.is_some(),
        "voice addressing decision"
    );
    if let Some(question) = inferred {
        // External-brain mode: eliza does NOT answer with
        // its own model. Forward the addressed utterance to
        // yokota over the seam and stop — yokota decides
        // what (if anything) to say back, which arrives as
        // a `say` line and is spoken via the seam reader.
        // Off-flag (default) = unchanged behavior below.
        if cfg.external_brain {
            if let Some(seam) = cfg.brain_seam.get() {
                seam.send(crate::brain_seam::Outbound::Utterance {
                    nick: nick.clone(),
                    text: question.clone(),
                });
                tracing::info!(%nick, %question, "external-brain: forwarded utterance to yokota");
            } else {
                tracing::debug!(%nick, "external-brain: no seam handle; dropping utterance");
            }
            return;
        }
        // Multi-agent chatter guard: see is_address_allowed.
        if !is_address_allowed(&cfg, &nick) {
            tracing::info!(
                %nick,
                "suppressing voice reply — recent addressers all peer agents"
            );
            return;
        }
        // Debounce: a speaker joined from several devices
        // is tapped once per broadcast, so the same
        // question arrives two or three times. Answer the
        // first; drop the rest.
        let dispatch = {
            let mut guard = active.lock().await;
            match guard.as_mut() {
                // Startup grace: ignore the backlog of
                // audio the SFU can replay right after the
                // bot joins (a stale "monologue").
                Some(call) if call.joined_at.elapsed() < CALL_JOIN_GRACE => {
                    tracing::info!(%nick, "ignoring addressed question (call-join grace)");
                    None
                }
                // Barge-in: Eliza is mid-answer and a
                // participant re-addressed her by name.
                // Stop her immediately and take the new
                // question — bypassing the dedupe debounce,
                // since a keyword *while she's speaking* is
                // a genuine interrupt, not a duplicate.
                // `clear()` empties the speech queue so the
                // 2-3 duplicate transcriptions that follow
                // see `is_speaking() == false` and get
                // caught by the debounce arm below.
                Some(call) if call.speaker.is_speaking() => {
                    tracing::info!(%nick, "barge-in — interrupting current answer");
                    call.speaker.clear();
                    call.last_answer = Some(Instant::now());
                    call.last_question = Some(question.clone());
                    // Snapshot the context BEFORE pushing the
                    // question — then record the question as a
                    // transcript line so the conversation log
                    // is symmetric (questions used to vanish:
                    // this arm returned before the push below).
                    let snapshot = recent_lines(&call.transcript, TRANSCRIPT_PROMPT_LINES);
                    call.transcript.push(format!("{nick}: {text}"));
                    Some((snapshot, call.speaker.clone(), call.video.clone()))
                }
                // Content-aware debounce: drop a repeat only
                // when it MATCHES the last answered question
                // within the short window (a multi-device
                // duplicate broadcast). A different question —
                // a real conversational follow-up — always
                // goes through, even seconds later.
                Some(call)
                    if !(call
                        .last_answer
                        .is_some_and(|t| t.elapsed() < ANSWER_DEBOUNCE)
                        && call
                            .last_question
                            .as_deref()
                            .is_some_and(|q| is_near_duplicate(q, &question))) =>
                {
                    call.last_answer = Some(Instant::now());
                    call.last_question = Some(question.clone());
                    let snapshot = recent_lines(&call.transcript, TRANSCRIPT_PROMPT_LINES);
                    call.transcript.push(format!("{nick}: {text}"));
                    Some((snapshot, call.speaker.clone(), call.video.clone()))
                }
                Some(_) => {
                    tracing::info!(%nick, %question, "ignoring duplicate addressed question (content-debounce)");
                    None
                }
                None => None,
            }
        };
        if let Some((transcript, speaker, video)) = dispatch {
            let screen_video = lookup_tap_video(&video_taps_for_screen, "screen");
            answer_and_speak(
                cfg,
                handle,
                channel,
                nick,
                question,
                transcript,
                Some(speaker),
                Some(video),
                Some(asker_video),
                screen_video,
                Some(active.clone()),
                Some(TurnClock {
                    id: turn,
                    speech_end: t_flush,
                }),
            )
            .await;
        }
        return;
    }

    // Buffer the line — the bot no longer firehoses every
    // utterance to the channel. A `dump` request posts
    // what's accumulated.
    let log_line = format!("{nick}: {text}");
    let video_snapshot = {
        let mut guard = active.lock().await;
        if let Some(call) = guard.as_mut() {
            call.transcript.push(log_line);
            Some(call.video.clone())
        } else {
            None
        }
    };
    // Live diagram: feed every transcribed utterance to
    // the per-channel graph. When new edges appear, push
    // the updated step list to the whiteboard AND
    // broadcast each fresh triple to peer agents over
    // IRC so every tile in the room renders the same
    // shared whiteboard.
    if let Some(video) = video_snapshot {
        let edges_before = {
            let log = cfg.diagrams.lock().expect("diagrams poisoned");
            log.get(&channel).map(|d| d.edge_count()).unwrap_or(0)
        };
        let added = {
            let mut log = cfg.diagrams.lock().expect("diagrams poisoned");
            log.entry(channel.clone()).or_default().ingest(&text)
        };
        if added > 0 {
            // Snapshot the new edges (those appended
            // after `edges_before`) so we broadcast
            // exactly the deltas, not the whole graph.
            let (steps, new_edges) = {
                let log = cfg.diagrams.lock().expect("diagrams poisoned");
                let d = log.get(&channel);
                let steps = d.map(|d| d.to_steps()).unwrap_or_default();
                let new_edges: Vec<(String, String, String)> = d
                    .map(|d| {
                        d.edges()
                            .skip(edges_before)
                            .map(|e| (e.from.clone(), e.relation.clone(), e.to.clone()))
                            .collect()
                    })
                    .unwrap_or_default();
                (steps, new_edges)
            };
            if !steps.is_empty() {
                video.show_board(steps, "#7FE7CB".into());
            }
            // Broadcast the new triples so peer bots
            // merge them into their local diagram.
            // Format: `[diag] from|relation|to` — peers
            // parse this on PRIVMSG, humans see it as
            // small structured bullet they can ignore.
            for (f, r, t) in new_edges {
                let _ = handle
                    .privmsg(&channel, &format!("[diag] {f}|{r}|{t}"))
                    .await;
            }
        }
    }
}

/// Stream one participant's audio to Deepgram and dispatch every
/// finalised transcript through the shared [`dispatch_utterance`]
/// pipeline. Persistent websocket per speaker; reconnects with a short
/// backoff on a dropped socket, gives up after repeated connect
/// failures (e.g. a bad key) so a dead key can't spin forever.
#[allow(clippy::too_many_arguments)]
async fn stream_participant_deepgram(
    dg: Arc<crate::streaming_stt::StreamingSttConfig>,
    mut audio: tokio::sync::mpsc::Receiver<freeq_av::PcmFrame>,
    cfg: Arc<SharedConfig>,
    nick: String,
    channel: String,
    handle: Arc<ClientHandle>,
    active: Arc<AsyncMutex<Option<ActiveCall>>>,
    peer_level: Arc<std::sync::atomic::AtomicU32>,
    humans: Arc<std::sync::atomic::AtomicUsize>,
    roster: CallRoster,
    name_primed: Arc<std::sync::Mutex<Option<Instant>>>,
    other_primed: Arc<std::sync::Mutex<Option<Instant>>>,
    video: VideoHandle,
    video_taps: CallVideoTaps,
) {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;
    const BACKOFF: Duration = Duration::from_millis(500);
    // Automatic gain control. Real-world mics (phone capture, AGC'd
    // headsets) often arrive far below full scale — a 0.03 peak sits at
    // the noise floor and Deepgram mangles it. We track a smoothed
    // loudness envelope and boost each frame toward AGC_TARGET, capped at
    // AGC_MAX so we never blow up silence into noise. Loud input (already
    // near full scale) is left alone or gently tamed. This makes the being
    // transcribe a quiet/distant speaker without touching the client.
    const AGC_TARGET: f32 = 0.3; // desired peak after gain
    const AGC_FLOOR: f32 = 0.02; // envelope floor → caps max boost at TARGET/FLOOR
    const AGC_MAX: f32 = 20.0; // hard ceiling on gain
    let mut agc_env: f32 = 0.0; // smoothed loudness, fast attack / slow release
    let mut frames_seen: u64 = 0;
    let mut connect_fails: u32 = 0;

    'reconnect: loop {
        let (mut writer, mut reader) = match crate::streaming_stt::connect(&dg).await {
            Ok(pair) => {
                connect_fails = 0;
                tracing::info!(%nick, model = %dg.model, "deepgram streaming connected");
                pair
            }
            Err(e) => {
                connect_fails += 1;
                tracing::warn!(%nick, error = ?e, connect_fails, "deepgram connect failed");
                if connect_fails > 5 {
                    tracing::error!(%nick, "deepgram unreachable after retries — STT disabled for this tap");
                    return;
                }
                tokio::time::sleep(BACKOFF).await;
                continue 'reconnect;
            }
        };

        // Reader: finalised transcripts → the full addressing/answer
        // pipeline, one spawned task each so a slow answer never blocks
        // reading the next utterance.
        let reader_task = {
            let cfg = cfg.clone();
            let nick = nick.clone();
            let channel = channel.clone();
            let handle = handle.clone();
            let active = active.clone();
            let humans = humans.clone();
            let roster = roster.clone();
            let name_primed = name_primed.clone();
            let other_primed = other_primed.clone();
            let video = video.clone();
            let video_taps = video_taps.clone();
            tokio::spawn(async move {
                while let Some(msg) = reader.next().await {
                    let txt = match msg {
                        Ok(Message::Text(t)) => t.to_string(),
                        Ok(Message::Close(_)) => break,
                        Ok(_) => continue,
                        Err(e) => {
                            tracing::warn!(%nick, error = ?e, "deepgram read error");
                            break;
                        }
                    };
                    let Some(text) = crate::streaming_stt::parse_final_transcript(&txt) else {
                        continue;
                    };
                    let turn = next_turn_id();
                    let t_flush = Instant::now();
                    tracing::info!(turn, %nick, %text, "latency: deepgram final transcript");
                    tokio::spawn(dispatch_utterance(
                        cfg.clone(),
                        nick.clone(),
                        channel.clone(),
                        handle.clone(),
                        active.clone(),
                        humans.clone(),
                        roster.clone(),
                        name_primed.clone(),
                        other_primed.clone(),
                        video.clone(),
                        video_taps.clone(),
                        turn,
                        t_flush,
                        text,
                    ));
                }
            })
        };

        // Feed: resample to 16 kHz mono (shared conditioning with the
        // Whisper path), pack to linear16, push to Deepgram.
        loop {
            match audio.recv().await {
                Some(frame) => {
                    frames_seen += 1;
                    let pcm = to_whisper_pcm(&frame.samples, frame.format);
                    if pcm.is_empty() {
                        continue;
                    }
                    let peak = pcm.iter().fold(0.0f32, |m, &s| m.max(s.abs()));
                    // Feed the video presence's "listening" mood — snap up,
                    // ease down — off the RAW peak (true loudness).
                    {
                        use std::sync::atomic::Ordering;
                        let prev = f32::from_bits(peer_level.load(Ordering::Relaxed));
                        let smoothed = if peak > prev {
                            peak
                        } else {
                            prev * 0.9 + peak * 0.1
                        };
                        peer_level.store(smoothed.to_bits(), Ordering::Relaxed);
                    }
                    // AGC: fast attack (jump to a louder peak immediately),
                    // slow release (decay between words), then derive the
                    // boost from the smoothed envelope. The FLOOR caps the
                    // gain so a near-silent frame can't be amplified to noise.
                    agc_env = if peak > agc_env {
                        peak
                    } else {
                        agc_env * 0.95 + peak * 0.05
                    };
                    let gain = (AGC_TARGET / agc_env.max(AGC_FLOOR)).clamp(1.0, AGC_MAX);
                    let boosted: Vec<f32> =
                        pcm.iter().map(|&s| (s * gain).clamp(-1.0, 1.0)).collect();
                    if frames_seen == 1 || frames_seen.is_multiple_of(250) {
                        tracing::info!(
                            %nick, frames_seen, peak,
                            gain = gain,
                            out_peak = (peak * gain).min(1.0),
                            "deepgram tap heartbeat"
                        );
                    }
                    let bytes = crate::streaming_stt::f32_mono_to_i16le(&boosted);
                    if let Err(e) = crate::streaming_stt::send_pcm(&mut writer, bytes).await {
                        tracing::warn!(%nick, error = ?e, "deepgram send failed; reconnecting");
                        reader_task.abort();
                        tokio::time::sleep(BACKOFF).await;
                        continue 'reconnect;
                    }
                }
                None => {
                    // Participant left / call ended — flush and let Deepgram
                    // return any trailing finals before we drop the reader.
                    let _ = crate::streaming_stt::close_stream(&mut writer).await;
                    let _ = reader_task.await;
                    return;
                }
            }
        }
    }
}

/// Derive the MoQ SFU URL from the IRC server URL. Same host, /av/moq
/// path, `https`/`http` scheme.
///
/// The scheme matters for transport selection. moq-native races a QUIC
/// (WebTransport) connection against a WebSocket fallback and keeps the
/// first to succeed. Its QUIC backend only accepts `https`/`moqt`/`moql`
/// — a `wss` URL is rejected outright, so the bot would silently drop to
/// the WebSocket fallback. WebSocket runs over TCP, whose head-of-line
/// blocking turns any packet loss into bursty delivery, which the
/// receiver hears as "bad-radio" static on the bot's audio. Emitting
/// `https` puts QUIC (the proper low-latency media transport) back in
/// the race; the WebSocket fallback accepts `https`/`http` too, so this
/// costs nothing if QUIC is unavailable.
///
/// Adversarial input handling:
///   - empty / whitespace-only string → clean error (was previously
///     producing the bogus URL `ws://`),
///   - garbage like `"://"`, `"ws://"`, `"https://"` (scheme only, no
///     host) → clean error,
///   - any URL we can't extract a non-empty host from → clean error.
pub(crate) fn sfu_url_from_server(server: &str) -> Result<url::Url> {
    let trimmed = server.trim();
    if trimmed.is_empty() {
        anyhow::bail!("server URL is empty");
    }
    let normalized = if trimmed.starts_with("ws://")
        || trimmed.starts_with("wss://")
        || trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
    {
        trimmed.to_string()
    } else {
        // raw host:port — assume non-TLS local dev
        format!("ws://{trimmed}")
    };
    let mut u: url::Url = normalized
        .parse()
        .with_context(|| format!("parsing server URL for SFU: {trimmed:?}"))?;
    // Reject schemes that don't make sense for the SFU. `url::Url`
    // happily accepts `file://`, `mailto:`, etc. — pin the allowed set.
    // Normalize to `https`/`http` so moq-native can attempt QUIC (see
    // the doc comment above).
    match u.scheme() {
        "https" | "wss" => {
            u.set_scheme("https").ok();
        }
        "http" | "ws" => {
            u.set_scheme("http").ok();
        }
        other => anyhow::bail!("unsupported scheme for SFU URL: {other:?}"),
    }
    // A URL like `ws://` parses but has an empty host; that would make
    // moq-native connect to nothing. Refuse it here.
    if u.host_str().map(|h| h.is_empty()).unwrap_or(true) {
        anyhow::bail!("server URL has no host: {trimmed:?}");
    }
    u.set_path("/av/moq");
    Ok(u)
}

/// Derive the REST API base (`https://host[:port]`) from the IRC
/// server URL. `wss://host/irc` → `https://host`; `host:port` →
/// `http://host:port`.
pub(crate) fn api_base_from_server(server: &str) -> Result<String> {
    let trimmed = server.trim();
    if trimmed.is_empty() {
        anyhow::bail!("server URL is empty");
    }
    let normalized = if trimmed.starts_with("ws://")
        || trimmed.starts_with("wss://")
        || trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
    {
        trimmed.to_string()
    } else {
        format!("ws://{trimmed}")
    };
    let u: url::Url = normalized
        .parse()
        .with_context(|| format!("parsing server URL for REST API: {trimmed:?}"))?;
    let scheme = match u.scheme() {
        "https" | "wss" => "https",
        "http" | "ws" => "http",
        other => anyhow::bail!("unsupported scheme for REST API: {other:?}"),
    };
    let host = u.host_str().context("server URL has no host")?;
    Ok(match u.port() {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    })
}

/// Query the REST API for an active AV session in `channel`. Returns
/// its session id if one is running, `None` otherwise (incl. on any
/// network/parse error — we then fall back to starting a fresh call).
async fn discover_active_session(cfg: &SharedConfig, channel: &str) -> Option<String> {
    let base = api_base_from_server(&cfg.server).ok()?;
    let encoded: String = channel
        .bytes()
        .map(|b| {
            if b == b'#' {
                "%23".to_string()
            } else {
                (b as char).to_string()
            }
        })
        .collect();
    let url = format!("{base}/api/v1/channels/{encoded}/sessions");
    let resp = cfg
        .http
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let json: serde_json::Value = resp.json().await.ok()?;
    let active = json.get("active")?;
    if active.is_null() {
        return None;
    }
    let state = active.get("state").and_then(|s| s.as_str()).unwrap_or("");
    if state != "Active" {
        return None;
    }
    active
        .get("id")
        .and_then(|i| i.as_str())
        .map(|s| s.to_string())
}

/// PRIVMSG has a length cap (~400-500 chars depending on prefix length).
/// Split long messages on newlines and post chunks; the summary is
/// usually 2-4 short paragraphs, well under the limit per line.
async fn post_long(handle: &ClientHandle, channel: &str, text: &str) {
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let _ = handle.privmsg(channel, line).await;
        // Brief pacing so we don't flood-trip the server.
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

// Silence the unused-fields lint on ActiveCall — we keep the fields
// even though only `transcript` and `_moq_task` are read by code.
// (`channel`/`session_id`/`instance_id` are useful for diagnostics
// when adding tracing later.)
#[allow(dead_code)]
fn _used(c: &ActiveCall) -> (&str, &str, &str) {
    (&c.channel, &c.session_id, &c.instance_id)
}

// Silence the unused-import lint when the optional `summary` feature is
// the only consumer of HashMap.
#[allow(dead_code)]
fn _hashmap_marker() -> HashMap<String, String> {
    HashMap::new()
}

// Silence PathBuf unused-import warning if we move things around.
#[allow(dead_code)]
fn _pathbuf_marker() -> PathBuf {
    PathBuf::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    // ---------- own-TTS echo guard ----------

    fn echo_log(sentences: &[&str]) -> RecentTts {
        let log: RecentTts = Default::default();
        for s in sentences {
            note_spoken(&log, s);
        }
        log
    }

    // ---------- addressed-to-other gate ----------

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn question_naming_another_agent_is_theirs() {
        // Olive must not answer "Yokota, what is two plus two?"
        assert!(addressed_to_other(
            "Yokota, what is two plus two?",
            "olive",
            &names(&["yokota", "claude"]),
        ));
    }

    #[test]
    fn question_naming_me_is_mine() {
        // Yokota's own name filtered from the candidate list — a
        // genuine address to us never reads as "someone else's".
        assert!(!addressed_to_other(
            "Yokota, what is two plus two?",
            "yokota-z6mkqxh7",
            &names(&["yokota", "olive", "claude"]),
        ));
    }

    #[test]
    fn bare_question_is_nobody_elses() {
        assert!(!addressed_to_other(
            "What time is it?",
            "yokota",
            &names(&["olive", "claude"]),
        ));
    }

    #[test]
    fn suffixed_roster_nick_still_matches() {
        // The roster carries the server-suffixed nick; the gate is fed
        // pre-dash prefixes, so the spoken character name matches.
        assert!(addressed_to_other(
            "Olive, are you kidding me?",
            "yokota",
            &names(&["olive", "claude"]),
        ));
    }

    #[test]
    fn empty_candidates_never_match() {
        assert!(!addressed_to_other(
            "Yokota, what is two plus two?",
            "yokota",
            &[],
        ));
    }

    // ---------- lookup_tap_video ----------

    fn taps_of(nicks: &[&str]) -> CallVideoTaps {
        let m: std::collections::HashMap<String, VideoHandle> = nicks
            .iter()
            .map(|n| (n.to_string(), VideoHandle::default()))
            .collect();
        Arc::new(std::sync::Mutex::new(m))
    }

    #[test]
    fn typed_asker_finds_their_tap_exactly() {
        let taps = taps_of(&["claude", "olive"]);
        assert!(lookup_tap_video(&taps, "Claude").is_some());
    }

    #[test]
    fn typed_asker_matches_suffixed_broadcast_nick() {
        // IRC nick "yokota" typed the question; the broadcast tap was
        // registered under the server-suffixed "yokota-z6mkqxh7".
        let taps = taps_of(&["yokota-z6mkqxh7"]);
        assert!(lookup_tap_video(&taps, "yokota").is_some());
        // …and the reverse: suffixed IRC nick, plain broadcast nick.
        let taps = taps_of(&["yokota"]);
        assert!(lookup_tap_video(&taps, "yokota-z6mkqxh7").is_some());
    }

    #[test]
    fn typed_asker_not_on_call_has_no_tap() {
        let taps = taps_of(&["olive"]);
        assert!(lookup_tap_video(&taps, "claude").is_none());
    }

    #[test]
    fn echo_exact_comes_back_dropped() {
        let log = echo_log(&["The patterns are already moving across the field."]);
        assert!(is_own_echo(
            &log,
            "The patterns are already moving across the field."
        ));
    }

    #[test]
    fn echo_stt_mangled_still_dropped() {
        // STT round-trips are lossy: casing, punctuation, a dropped word.
        let log = echo_log(&["A live voice call with the assistant Eliza is in progress."]);
        assert!(is_own_echo(
            &log,
            "a live voice call with the assistant eliza in progress"
        ));
    }

    #[test]
    fn echo_fragment_of_long_answer_dropped() {
        // Speaker leak often clips to a fragment of one sentence.
        let log = echo_log(&[
            "Rust's borrow checker enforces memory safety at compile time.",
            "That means no garbage collector and no data races.",
        ]);
        assert!(is_own_echo(&log, "no garbage collector and no data races"));
    }

    #[test]
    fn real_reply_about_answer_not_dropped() {
        // A human responding brings their own words — under threshold.
        let log = echo_log(&["Rust's borrow checker enforces memory safety at compile time."]);
        assert!(!is_own_echo(
            &log,
            "okay but what about unsafe blocks in the borrow checker"
        ));
    }

    #[test]
    fn short_human_ack_not_dropped() {
        // "yes", "okay then" — too short for the bag test, and not a
        // substring of anything spoken.
        let log = echo_log(&["Let me think about the deployment order for a second."]);
        assert!(!is_own_echo(&log, "okay sure"));
        assert!(!is_own_echo(&log, "yes"));
    }

    #[test]
    fn short_exact_fragment_dropped() {
        // A short utterance that IS a verbatim slice of recent TTS.
        let log = echo_log(&["Let me think about the deployment order."]);
        assert!(is_own_echo(&log, "the deployment order"));
    }

    #[test]
    fn empty_log_never_matches() {
        let log: RecentTts = Default::default();
        assert!(!is_own_echo(&log, "anything at all here"));
    }

    // ---------- owner lifecycle command (STT-tolerant) ----------

    #[test]
    fn sleep_command_survives_stt_mangling() {
        // The real "go to sleep", plus the ways Whisper actually rendered it
        // in the live demo, must all sleep her.
        for s in [
            "go to sleep",
            "goes to sleep",
            "all the sleep",
            "all of god's sleep",
            "time to sleep now",
            "olive, go to sleep",
            "sleep",
            "take a nap",
        ] {
            assert!(
                matches!(parse_owner_command(s), Some(OwnerCmd::Sleep)),
                "should sleep on {s:?}"
            );
        }
    }

    #[test]
    fn sleep_command_ignores_long_incidental_mentions() {
        // A real sentence that merely mentions sleep must NOT sleep her.
        assert!(
            parse_owner_command(
                "honestly I could not sleep at all last night and now my brain is mush"
            )
            .is_none()
        );
    }

    #[test]
    fn leave_command_is_tolerant_but_bounded() {
        assert!(matches!(
            parse_owner_command("leave"),
            Some(OwnerCmd::Leave)
        ));
        assert!(matches!(
            parse_owner_command("ok you can leave now"),
            Some(OwnerCmd::Leave)
        ));
        assert!(
            parse_owner_command("don't leave the door open or the cat gets out tonight").is_none()
        );
    }

    #[test]
    fn owner_command_fork_mitosis() {
        // The mutation rides along verbatim for the child-composition model.
        for s in [
            "fork yourself",
            "fork yourself but make her an optimist",
            "clone yourself and make him obsessed with gardening",
            "split yourself in two",
            "make a copy of yourself",
            "could you duplicate yourself please",
        ] {
            match parse_owner_command(s) {
                Some(OwnerCmd::Fork(utt)) => assert_eq!(utt, s),
                other => panic!("{s:?} → {other:?}, expected Fork"),
            }
        }
        // Mentions of forks/splits that aren't about the being stay inert —
        // and a long fork-ish sentence about something else doesn't trip it.
        assert!(parse_owner_command("the road forks ahead").is_none());
        assert!(parse_owner_command("let's split the bill").is_none());
        assert!(parse_owner_command("I forked the repo yesterday").is_none());
        // "fork yourself" must win over the looser sleep matcher even when
        // the mutation mentions sleep.
        assert!(matches!(
            parse_owner_command("fork yourself but make her sleepy"),
            Some(OwnerCmd::Fork(_))
        ));
    }

    // ---------- voice addressing gate ----------

    #[test]
    fn bare_name_detector_primes_only_on_the_name_alone() {
        // The VAD split: "Yokota, please read…" arrives as "Yokota." +
        // the question. The bare name must register…
        assert!(is_bare_name("Yokota.", "yokota"));
        assert!(is_bare_name("hey yokota", "yokota"));
        assert!(is_bare_name("Yokota", "yokota-z6mkqxh7"), "suffix alias");
        // …but a name WITH content is a normal address (handled by the
        // named gate), and unrelated lines never prime.
        assert!(!is_bare_name("yokota what time is it", "yokota"));
        assert!(!is_bare_name("please read my tile", "yokota"));
        assert!(!is_bare_name("", "yokota"));
    }

    #[test]
    fn recent_lines_caps_the_prompt_snapshot() {
        let lines: Vec<String> = (0..100).map(|i| format!("line {i}")).collect();
        let s = recent_lines(&lines, 60);
        assert!(s.starts_with("line 40\n") && s.ends_with("line 99"));
        // Short transcripts come through whole.
        assert_eq!(recent_lines(&lines[..3], 60), "line 0\nline 1\nline 2");
        assert_eq!(recent_lines(&[], 60), "");
    }

    #[test]
    fn questions_still_recognized() {
        assert!(looks_like_question("what should I build?"));
        assert!(looks_like_question("how does this work"));
        assert!(!looks_like_question("all of us are down"));
    }

    #[test]
    fn moment_worthiness_filters_stubs_and_apologies() {
        assert!(is_moment_worthy(
            "You're not shipping features, you're shipping a whole atmosphere."
        ));
        assert!(!is_moment_worthy("yeah"), "too short");
        assert!(
            !is_moment_worthy("sorry — I couldn't answer that (timeout)."),
            "apology/error"
        );
        assert!(!is_moment_worthy(&"x".repeat(400)), "wall of text");
        assert!(!is_moment_worthy("   "), "blank");
    }

    // ---------- sfu_url_from_server ----------

    #[test]
    fn sfu_wss_irc_to_https_avmoq() {
        // `wss` IRC URL → `https` SFU URL so moq-native attempts QUIC
        // rather than skipping straight to the WebSocket fallback.
        let u = sfu_url_from_server("wss://irc.freeq.at/irc").unwrap();
        assert_eq!(u.as_str(), "https://irc.freeq.at/av/moq");
    }

    #[test]
    fn sfu_https_stays_https() {
        let u = sfu_url_from_server("https://irc.freeq.at").unwrap();
        assert_eq!(u.as_str(), "https://irc.freeq.at/av/moq");
    }

    #[test]
    fn sfu_http_stays_http() {
        let u = sfu_url_from_server("http://localhost").unwrap();
        assert_eq!(u.as_str(), "http://localhost/av/moq");
    }

    #[test]
    fn sfu_raw_host_port_to_http() {
        let u = sfu_url_from_server("localhost:6667").unwrap();
        assert_eq!(u.as_str(), "http://localhost:6667/av/moq");
    }

    #[test]
    fn sfu_strips_existing_path_and_query() {
        // The bot must replace /irc with /av/moq even when the input
        // URL carries a query string. Without `set_path` this would
        // leak `?token=...` into the SFU URL and break the connect.
        let u = sfu_url_from_server("wss://irc.freeq.at/irc?token=abc").unwrap();
        assert_eq!(u.path(), "/av/moq");
    }

    #[test]
    fn sfu_preserves_nondefault_port() {
        let u = sfu_url_from_server("wss://example.com:8443/irc").unwrap();
        assert_eq!(u.host_str(), Some("example.com"));
        assert_eq!(u.port(), Some(8443));
        assert_eq!(u.path(), "/av/moq");
    }

    #[test]
    fn sfu_trims_surrounding_whitespace() {
        let u = sfu_url_from_server("  wss://irc.freeq.at/irc  ").unwrap();
        assert_eq!(u.as_str(), "https://irc.freeq.at/av/moq");
    }

    #[test]
    fn sfu_rejects_empty_string() {
        let err = sfu_url_from_server("").err().expect("expected error");
        assert!(format!("{err:#}").contains("empty"));
    }

    #[test]
    fn sfu_rejects_only_whitespace() {
        let err = sfu_url_from_server("   ").err().expect("expected error");
        assert!(format!("{err:#}").contains("empty"));
    }

    #[test]
    fn sfu_rejects_scheme_only_garbage() {
        // `wss://` parses as a URL with no host — moq-native would
        // happily connect to the empty string and burn cycles.
        let err = sfu_url_from_server("wss://").err().expect("expected error");
        assert!(format!("{err:#}").contains("host"), "got: {err:#}");
    }

    #[test]
    fn sfu_rejects_double_slash_only() {
        // `://` alone isn't a URL at all.
        let err = sfu_url_from_server("://").err().expect("expected error");
        let s = format!("{err:#}");
        assert!(s.contains("parsing") || s.contains("host"));
    }

    #[test]
    fn sfu_garbage_with_unknown_scheme_does_not_panic() {
        // Inputs that don't start with one of our four supported
        // schemes get treated as `host:port` and prepended with `ws://`.
        // For `file:///etc/passwd` that produces an absurd-but-parsable
        // URL. We only need to assert we don't panic and don't produce
        // a URL that points at an attacker-controlled host.
        let result = sfu_url_from_server("file:///etc/passwd");
        if let Ok(u) = result {
            // If it parses, the host MUST not be "etc" or "passwd" —
            // anything that would let an adversary aim moq-native at
            // a chosen target. In practice the URL becomes
            // ws://file:///etc/passwd which has host == "file".
            assert_eq!(u.host_str(), Some("file"));
            // And the path is rewritten to /av/moq regardless.
            assert_eq!(u.path(), "/av/moq");
        }
    }

    #[test]
    fn sfu_invalid_port_errors() {
        // url::Url rejects this at parse time.
        let err = sfu_url_from_server("wss://example.com:99999/irc")
            .err()
            .expect("expected error");
        assert!(format!("{err:#}").contains("parsing"), "got: {err:#}");
    }

    // ---------- wait_for_registration ----------

    #[tokio::test]
    async fn registration_succeeds_on_registered_event() {
        let (tx, mut rx) = mpsc::channel(4);
        tx.send(Event::Connected).await.unwrap();
        tx.send(Event::Registered {
            nick: "tbot".to_string(),
        })
        .await
        .unwrap();
        let nick = wait_for_registration_with_timeout(&mut rx, Duration::from_millis(500))
            .await
            .unwrap();
        assert_eq!(nick, "tbot");
    }

    #[tokio::test]
    async fn registration_surfaces_authfailed_reason_verbatim() {
        // The SASL error message is the only thing telling the user
        // *why* auth was rejected (handle vs key mismatch, expired
        // challenge, etc.) — pin that it bubbles up unmodified.
        let (tx, mut rx) = mpsc::channel(2);
        tx.send(Event::AuthFailed {
            reason: "invalid signature: bad key type".to_string(),
        })
        .await
        .unwrap();
        let err = wait_for_registration_with_timeout(&mut rx, Duration::from_millis(500))
            .await
            .err()
            .expect("expected auth error");
        let s = format!("{err:#}");
        assert!(s.contains("invalid signature: bad key type"), "got: {s}");
        assert!(s.contains("SASL auth failed"), "got: {s}");
    }

    #[tokio::test]
    async fn registration_errors_on_closed_channel() {
        // Disconnect mid-handshake: must not hang and must not panic.
        let (tx, mut rx) = mpsc::channel::<Event>(1);
        drop(tx);
        let err = wait_for_registration_with_timeout(&mut rx, Duration::from_millis(500))
            .await
            .err()
            .expect("expected error");
        assert!(
            format!("{err:#}").contains("connection closed"),
            "got: {err:#}"
        );
    }

    #[tokio::test]
    async fn registration_times_out_when_silent() {
        let (_tx, mut rx) = mpsc::channel::<Event>(1);
        let start = std::time::Instant::now();
        let err = wait_for_registration_with_timeout(&mut rx, Duration::from_millis(50))
            .await
            .err()
            .expect("expected timeout");
        assert!(start.elapsed() >= Duration::from_millis(40));
        assert!(format!("{err:#}").contains("timeout"), "got: {err:#}");
    }

    #[tokio::test]
    async fn registration_ignores_intermediate_events() {
        // Pre-registration we may see Connected, Authenticated, etc.
        // None of them should resolve the wait — only Registered does.
        let (tx, mut rx) = mpsc::channel(8);
        tx.send(Event::Connected).await.unwrap();
        tx.send(Event::Authenticated {
            did: "did:key:zfoo".to_string(),
        })
        .await
        .unwrap();
        tx.send(Event::Registered {
            nick: "n".to_string(),
        })
        .await
        .unwrap();
        let nick = wait_for_registration_with_timeout(&mut rx, Duration::from_millis(500))
            .await
            .unwrap();
        assert_eq!(nick, "n");
    }

    // ---------- classify_av_event ----------

    fn tags(items: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        items
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn classify_skips_non_channel_target() {
        // av-state on a direct message — never trust it; we don't
        // 1:1-transcribe.
        let t = tags(&[("+freeq.at/av-state", "started"), ("+freeq.at/av-id", "x")]);
        assert_eq!(
            classify_av_event("alice", &t, &["#room".into()], "tbot"),
            AvAction::Skip
        );
    }

    #[test]
    fn classify_skips_missing_av_id() {
        let t = tags(&[("+freeq.at/av-state", "started")]);
        assert_eq!(
            classify_av_event("#room", &t, &["#room".into()], "tbot"),
            AvAction::Skip
        );
    }

    #[test]
    fn classify_skips_missing_av_state() {
        let t = tags(&[("+freeq.at/av-id", "x")]);
        assert_eq!(
            classify_av_event("#room", &t, &["#room".into()], "tbot"),
            AvAction::Skip
        );
    }

    #[test]
    fn classify_acts_on_self_started_session() {
        // The bot must act on a session IT started (--start-session-in):
        // the server attributes that `av-state=started` to the bot's
        // own nick. Self-recursion is not a risk — the subsequent
        // av-join surfaces as `av-state=joined`, which is Noop.
        let t = tags(&[
            ("+freeq.at/av-state", "started"),
            ("+freeq.at/av-id", "s1"),
            ("+freeq.at/av-actor", "TBot"),
        ]);
        assert_eq!(
            classify_av_event("#room", &t, &["#room".into()], "tbot"),
            AvAction::Start {
                channel: "#room".into(),
                session_id: "s1".into(),
            },
            "bot-initiated session start must be acted on, not self-skipped"
        );
    }

    #[test]
    fn classify_self_actor_joined_is_noop() {
        // The bot's own av-join → server broadcasts av-state=joined
        // attributed to the bot. Must be Noop, never a re-trigger.
        let t = tags(&[
            ("+freeq.at/av-state", "joined"),
            ("+freeq.at/av-id", "s1"),
            ("+freeq.at/av-actor", "tbot"),
        ]);
        assert_eq!(
            classify_av_event("#room", &t, &["#room".into()], "tbot"),
            AvAction::Noop,
        );
    }

    #[test]
    fn classify_does_not_skip_other_actor() {
        let t = tags(&[
            ("+freeq.at/av-state", "started"),
            ("+freeq.at/av-id", "s1"),
            ("+freeq.at/av-actor", "alice"),
        ]);
        assert_eq!(
            classify_av_event("#room", &t, &["#room".into()], "tbot"),
            AvAction::Start {
                channel: "#room".into(),
                session_id: "s1".into()
            }
        );
    }

    #[test]
    fn classify_skips_started_in_unknown_channel() {
        // We must NOT av-join into channels we aren't a member of —
        // that would let any random user with a +freeq.at/av-state
        // tag drag the bot anywhere.
        let t = tags(&[("+freeq.at/av-state", "started"), ("+freeq.at/av-id", "s1")]);
        assert_eq!(
            classify_av_event("#elsewhere", &t, &["#room".into()], "tbot"),
            AvAction::Skip
        );
    }

    #[test]
    fn classify_channel_match_is_case_insensitive() {
        let t = tags(&[("+freeq.at/av-state", "started"), ("+freeq.at/av-id", "s1")]);
        assert_eq!(
            classify_av_event("#RoOm", &t, &["#room".into()], "tbot"),
            AvAction::Start {
                channel: "#RoOm".into(),
                session_id: "s1".into()
            }
        );
    }

    #[test]
    fn classify_emits_end_for_ended_state() {
        let t = tags(&[("+freeq.at/av-state", "ended"), ("+freeq.at/av-id", "s9")]);
        assert_eq!(
            classify_av_event("#room", &t, &["#room".into()], "tbot"),
            AvAction::End {
                channel: "#room".into(),
                session_id: "s9".into()
            }
        );
    }

    #[test]
    fn classify_emits_noop_for_unknown_state() {
        // `left` or anything unknown — we log but don't act. Pin so a
        // careless `_ => AvAction::Start` regression is caught.
        for state in ["left", "weird"] {
            let t = tags(&[("+freeq.at/av-state", state), ("+freeq.at/av-id", "s")]);
            assert_eq!(
                classify_av_event("#room", &t, &["#room".into()], "tbot"),
                AvAction::Noop,
                "state {state:?}"
            );
        }
    }

    #[test]
    fn classify_human_joined_is_actioned() {
        // A human joining a call in our channel must summon us — the
        // lonely watchdog may have walked us out of this very session
        // while the room was empty.
        let t = tags(&[
            ("+freeq.at/av-state", "joined"),
            ("+freeq.at/av-id", "s1"),
            ("+freeq.at/av-actor", "chadfowler.com"),
        ]);
        assert_eq!(
            classify_av_event("#room", &t, &["#room".into()], "tbot"),
            AvAction::Joined {
                channel: "#room".into(),
                session_id: "s1".into(),
            }
        );
    }

    #[test]
    fn classify_joined_in_unknown_channel_is_skipped() {
        // Same trust boundary as `started`: a joined event must not
        // drag the bot into a channel it isn't a member of.
        let t = tags(&[
            ("+freeq.at/av-state", "joined"),
            ("+freeq.at/av-id", "s1"),
            ("+freeq.at/av-actor", "alice"),
        ]);
        assert_eq!(
            classify_av_event("#elsewhere", &t, &["#room".into()], "tbot"),
            AvAction::Skip
        );
    }

    #[test]
    fn classify_joined_missing_actor_is_noop() {
        // No actor → can't tell human from bot → don't act.
        let t = tags(&[("+freeq.at/av-state", "joined"), ("+freeq.at/av-id", "s1")]);
        assert_eq!(
            classify_av_event("#room", &t, &["#room".into()], "tbot"),
            AvAction::Noop
        );
    }

    #[test]
    fn classify_self_joined_with_did_suffix_is_noop() {
        // The bot's registered nick can carry a DID suffix
        // (`tbot-z6mkfa8x`); the self-join check compares canonical
        // (pre-dash) names so the echo never re-triggers a join.
        let t = tags(&[
            ("+freeq.at/av-state", "joined"),
            ("+freeq.at/av-id", "s1"),
            ("+freeq.at/av-actor", "TBot-z6mkfa8x"),
        ]);
        assert_eq!(
            classify_av_event("#room", &t, &["#room".into()], "tbot"),
            AvAction::Noop
        );
    }

    #[test]
    fn classify_ampersand_channel_target_accepted() {
        // `&local` is an IRC local channel prefix; the orchestrator
        // accepts both `#` and `&`.
        let t = tags(&[("+freeq.at/av-state", "ended"), ("+freeq.at/av-id", "x")]);
        assert_eq!(
            classify_av_event("&local", &t, &["#room".into()], "tbot"),
            AvAction::End {
                channel: "&local".into(),
                session_id: "x".into()
            }
        );
    }
}
