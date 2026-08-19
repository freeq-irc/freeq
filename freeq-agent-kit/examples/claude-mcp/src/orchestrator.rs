//! The lean bot.
//!
//! Owns the IRC connection, the AV session, every per-participant
//! audio tap, and the TTS speaker. Hands transcripts up through a
//! `Receiver` and accepts utterances through `say()`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use freeq_agent_kit::{VadConfig, VadSegmenter, addressing::word_is_name, extract_addressed};
use freeq_av::{AvConfig, AvParticipant, AvSession, Speaker, VideoHandle, broadcast_path};
use freeq_eliza::diagram::Diagram;
use freeq_eliza::identity;
use freeq_eliza::memory::Memory;
use freeq_eliza::stt::{SttEngine, to_whisper_pcm};
use freeq_eliza::tts::{ELEVENLABS_PCM_RATE, synthesize_streaming};
use freeq_sdk::auth::KeySigner;
use freeq_sdk::av::{AvAction, new_av_instance, parse_av_state};
use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::event::Event;
use tokio::sync::{Mutex as AsyncMutex, RwLock, mpsc};
use tokio::task::JoinHandle;

use crate::discover::{discover_active_session, sfu_url_from_server};
use crate::streaming_stt::{self, StreamingSttConfig};
use crate::video_face::{ParticleControl, ParticleVideoSource};

/// Configuration handed to [`Orchestrator::connect`].
#[derive(Debug, Clone)]
pub struct OrcConfig {
    pub server: String,
    pub channel: String,
    /// Bot nick on IRC. Also the name the user addresses by voice
    /// ("Claude, …"). Defaults to "claude" in the binary wrappers.
    pub nick: String,
    /// Identity name — directory under `~/.freeq/bots/<name>/`. A fresh
    /// did:key is generated on first run.
    pub identity_name: String,
    /// When true and discovery reports no active session, send
    /// `av-start`. When false, sit on the channel and join whatever
    /// session a human starts later.
    pub start_if_idle: bool,
    /// Required for STT (Groq Whisper). Without it, transcripts are
    /// empty and the bot is effectively deaf.
    pub groq_api_key: Option<String>,
    /// Required for TTS. Without it, `say()` errors and the bot is mute.
    pub elevenlabs_api_key: Option<String>,
    pub elevenlabs_voice_id: String,
    pub elevenlabs_model: String,
    /// Optional override for the SFU URL; useful for QUIC pinning.
    pub sfu_url_override: Option<String>,
    /// Other agent nicks in the room. Treated like humans by addressing
    /// (so "Oblivion, ask Claude X" still triggers the gaze), but the
    /// MCP layer can filter them out of the addressed pipeline.
    pub peer_agents: Vec<String>,
    /// Ghostly character name for the video tile face. Defaults to
    /// "eliza" — friendly mint-teal — which reads cleanly as Claude
    /// alongside oblivion / utopia / narrator on the demo grid.
    pub ghostly_character: String,
    /// Minimum gap (seconds) between *volunteered* utterances. Spoken
    /// replies to direct address are unrestricted; volunteering is
    /// cooldowned so the bot doesn't dominate the room.
    pub volunteer_cooldown_secs: u64,
    /// When true, also broadcast `[diag] from|rel|to` SVO triples
    /// extracted from each incoming transcript. Hooks the bot into the
    /// shared whiteboard the other eliza-class agents build.
    pub emit_diagrams: bool,
    /// When true, transcripts get persisted to a SQLite FTS5 store at
    /// `~/.freeq/bots/<identity>/memory.db`. The `freeq_recall` tool
    /// queries this store.
    pub enable_memory: bool,
    /// When true and the speaker is mid-utterance, sustained loud peer
    /// audio aborts the TTS queue. Off would let the bot finish even
    /// when interrupted — useful for monologues, terrible for meetings.
    pub barge_in: bool,
    /// If set, transcripts come from Deepgram's streaming websocket
    /// instead of the local VAD + Groq Whisper batched path. Cuts
    /// perceived latency 2–3× because Deepgram does server-side
    /// endpointing in ~200–300 ms instead of our 600 ms silence gap.
    pub deepgram_api_key: Option<String>,
    /// Deepgram model. Defaults to "nova-3" (English, current best).
    pub deepgram_model: String,
}

/// Priority on a `say` call. `Addressed` means the bot was directly
/// asked something — always speaks. `Volunteer` means the bot decided
/// the utterance is worth surfacing on its own — subject to the
/// cooldown to prevent room domination.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum SayPriority {
    Addressed,
    Volunteer,
}

/// Result of a `say` call. `suppressed` is true when a volunteer
/// utterance was rejected by the cooldown.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SayResult {
    pub suppressed: bool,
    /// Seconds until the next volunteer is allowed (0 if not cooled
    /// down or if this call was Addressed).
    pub cooldown_remaining_secs: u64,
}

/// A single utterance transcribed from one participant.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Transcript {
    pub speaker: String,
    pub text: String,
    /// True when the line directly addresses the bot by its nick (with
    /// fuzzy STT-tolerant matching). The MCP server uses this to gate
    /// whether Claude should respond in direct-address mode.
    pub addressed: bool,
    /// The bare question after the address, when `addressed=true`.
    /// E.g. "Claude, what's the risk?" → `Some("what's the risk?")`.
    pub question: Option<String>,
    /// Wall-clock at the moment STT returned, ms since epoch.
    pub timestamp_ms: u64,
}

/// Live handle to the bot.
pub struct Orchestrator {
    nick: String,
    channel: String,
    /// AV session + our instance within it — needed to send a proper
    /// av-leave on disconnect (ghost-tile prevention).
    session_id: String,
    instance_id: String,
    handle: ClientHandle,
    speaker: Speaker,
    transcripts: AsyncMutex<mpsc::Receiver<Transcript>>,
    tts: TtsConfig,
    /// Shared visual state — feeds the ghostly face's listening /
    /// thinking / speaking signals. Exposed so the MCP server can
    /// flip thinking on/off when it knows an LLM call is in flight.
    pub control: ParticleControl,
    /// Per-participant latest video frames. Populated by the participant
    /// loop as new participants stream in. Read by `freeq_look`.
    videos: Arc<RwLock<HashMap<String, VideoHandle>>>,
    /// Persistent conversation memory. None when `enable_memory=false`
    /// or when the SQLite store can't be opened.
    memory: Option<Arc<Memory>>,
    /// True from the moment a `say()` starts streaming TTS to the
    /// moment the speaker queue actually drains. Necessary because
    /// `Speaker::is_speaking` (queue.is_empty checked instantaneously)
    /// flickers false between TTS chunks while audio is still playing
    /// — and barge-in needs a stable "we're in the middle of saying
    /// something" signal. transcribe_participant reads this on every
    /// frame.
    say_active: Arc<AtomicBool>,
    volunteer_cooldown: Duration,
    /// Last time a `Volunteer`-priority utterance was spoken. Used to
    /// enforce `volunteer_cooldown`.
    last_volunteer_at: AsyncMutex<Option<Instant>>,
    /// Wall-clock ms of the most recent real reply — `say` or `post`.
    /// Heartbeats do NOT write this (an ack is not an answer); they
    /// pace themselves with their own beat clock.
    last_say_ms: Arc<AtomicI64>,
    /// Wall-clock ms of the last addressed *question* handed to the
    /// brain via `recv_batch`. Arms the heartbeat — see `heartbeat_due`.
    last_delivered_ms: Arc<AtomicI64>,
    _join_handles: Vec<JoinHandle<()>>,
    _av_session: Arc<AsyncMutex<Option<AvSession>>>,
    shutdown: Arc<AtomicBool>,
}

#[derive(Clone)]
struct TtsConfig {
    api_key: Option<String>,
    voice_id: String,
    model: String,
}

impl Orchestrator {
    /// Connect to IRC, join the channel, discover or start the AV
    /// session, and start the per-participant transcribe taps. Returns
    /// once the AV session is up and our broadcast is registered.
    pub async fn connect(cfg: OrcConfig) -> Result<Self> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let ident = identity::load_or_create(&cfg.identity_name).context("loading bot identity")?;
        tracing::info!(did = %ident.did, "bot identity ready");

        let stt = Arc::new(build_stt(&cfg)?);
        tracing::info!(backend = %stt.label(), "STT backend ready");

        let (websocket_url, server_addr) = derive_transport(&cfg.server)?;
        let conn_config = ConnectConfig {
            server_addr,
            nick: cfg.nick.clone(),
            user: cfg.nick.clone(),
            realname: "freeq-claude-mcp".to_string(),
            tls: websocket_url.is_some()
                || cfg.server.starts_with("https://")
                || cfg.server.starts_with("wss://"),
            tls_insecure: false,
            web_token: None,
            websocket_url,
        };
        let signer = Arc::new(KeySigner::new(ident.did.clone(), ident.private_key));
        let (handle, mut events) = client::connect(conn_config, Some(signer));

        // Everything between the raw connect and a live AV session can
        // fail (registration timeout, join failure, no av-state within
        // the wait). On ANY of those, quit the IRC connection before
        // surfacing the error — otherwise the half-joined bot lingers
        // as a ghost participant the room can see but never hear.
        let setup = async {
            wait_for_registration(&mut events).await?;
            handle.join(&cfg.channel).await.context("joining channel")?;
            tracing::info!(channel = %cfg.channel, nick = %cfg.nick, "joined channel");

            // Announce ourselves as a native agent so the server sets
            // actor_class=agent and clients render the agent badge. Without this
            // the bot joins as a plain Human and looks like a person in the UI.
            if let Err(e) = handle.register_agent("agent").await {
                tracing::warn!(error = %e, "AGENT REGISTER failed; will appear as human");
            } else {
                tracing::info!("registered as agent (actor_class=agent)");
            }

            let http = reqwest::Client::new();
            let session_id = match discover_active_session(&http, &cfg.server, &cfg.channel).await {
                Some(sid) => {
                    tracing::info!(%sid, "joining existing AV session");
                    sid
                }
                None if cfg.start_if_idle => {
                    let instance = new_av_instance();
                    handle
                        .av_start(&cfg.channel, &instance, Some("claude"))
                        .await
                        .context("sending av-start")?;
                    tracing::info!(%instance, "sent av-start; waiting for echo");
                    wait_for_av_started(&mut events, &cfg.channel).await?
                }
                None => wait_for_av_started(&mut events, &cfg.channel).await?,
            };

            let instance_id = new_av_instance();
            handle
                .av_join(&cfg.channel, &session_id, &instance_id)
                .await
                .context("sending av-join")?;

            let sfu_url: url::Url = match &cfg.sfu_url_override {
                Some(u) => u.parse().context("parsing --sfu-url")?,
                None => sfu_url_from_server(&cfg.server)?,
            };
            Ok::<_, anyhow::Error>((session_id, instance_id, sfu_url))
        };
        let (session_id, instance_id, sfu_url) = match setup.await {
            Ok(v) => v,
            Err(e) => {
                let _ = handle.quit(Some("connect failed")).await;
                return Err(e);
            }
        };
        let level = Arc::new(AtomicU32::new(0));
        let (speaker, push_source) = Speaker::new(level.clone());
        let av_config = AvConfig {
            sfu_url,
            session_id: session_id.clone(),
            our_broadcast: broadcast_path(&session_id, &cfg.nick, &instance_id),
            my_nick: cfg.nick.clone(),
            audio_only: false,
        };
        let control = ParticleControl::new();
        let make_video = {
            let character = cfg.ghostly_character.clone();
            let control = control.clone();
            move || ParticleVideoSource::spawn(character.clone(), control.clone())
        };
        let av_session = AvSession::connect(av_config, push_source, make_video);
        let av_session = Arc::new(AsyncMutex::new(Some(av_session)));

        let (tx, rx) = mpsc::channel::<Transcript>(256);
        let shutdown = Arc::new(AtomicBool::new(false));
        let videos: Arc<RwLock<HashMap<String, VideoHandle>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let memory = if cfg.enable_memory {
            let mem_path = dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".freeq/bots")
                .join(&cfg.identity_name)
                .join("memory.db");
            match Memory::open(&mem_path) {
                Ok(m) => {
                    tracing::info!(path = %mem_path.display(), "memory store ready");
                    Some(Arc::new(m))
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to open memory store — running without");
                    None
                }
            }
        } else {
            None
        };
        let mut handles: Vec<JoinHandle<()>> = Vec::new();

        // Drain remaining events so the channel doesn't back-pressure
        // the SDK loop — we don't actually need them past this point,
        // but TagMsg and Disconnected are useful diagnostics.
        let shutdown_for_events = shutdown.clone();
        handles.push(tokio::spawn(async move {
            while let Some(ev) = events.recv().await {
                if shutdown_for_events.load(Ordering::Relaxed) {
                    break;
                }
                if let Event::Disconnected { reason } = &ev {
                    tracing::warn!(%reason, "IRC disconnected");
                }
            }
        }));

        // The participant-loop owns the AvSession (it needs `&mut`
        // access for `recv()`), so it pops the Arc<Mutex<Option<_>>>
        // contents and threads them through.
        let say_active = Arc::new(AtomicBool::new(false));
        let last_addressed_ms: Arc<AtomicI64> = Arc::new(AtomicI64::new(0));
        let last_say_ms: Arc<AtomicI64> = Arc::new(AtomicI64::new(0));
        // Wall-ms of the last addressed *question* handed to the brain
        // via recv_batch — the honest arming signal for the heartbeat.
        let last_delivered_ms: Arc<AtomicI64> = Arc::new(AtomicI64::new(0));
        // Accumulating whiteboard graph — every utterance's triples
        // merge in. The transcribe loops push fresh layouts to the
        // tile overlay whenever new edges land.
        let accumulated_diagram: Arc<std::sync::Mutex<Diagram>> =
            Arc::new(std::sync::Mutex::new(Diagram::new()));
        let av_for_loop = av_session.clone();
        let nick_for_loop = cfg.nick.clone();
        let peers_for_loop = cfg.peer_agents.clone();
        let stt_for_loop = stt.clone();
        let tx_for_loop = tx.clone();
        let shutdown_for_loop = shutdown.clone();
        let control_for_loop = control.clone();
        let handle_for_loop = handle.clone();
        let channel_for_loop = cfg.channel.clone();
        let emit_diagrams = cfg.emit_diagrams;
        let barge_in = cfg.barge_in;
        let speaker_for_loop = speaker.clone();
        let videos_for_loop = videos.clone();
        let memory_for_loop = memory.clone();
        let say_active_for_loop = say_active.clone();
        let last_addressed_ms_for_loop = last_addressed_ms.clone();
        let accumulated_diagram_for_loop = accumulated_diagram.clone();
        let deepgram_key = cfg.deepgram_api_key.clone();
        let deepgram_model = cfg.deepgram_model.clone();
        if deepgram_key.is_some() {
            tracing::info!("STT backend: deepgram (streaming, model={deepgram_model})");
        }
        handles.push(tokio::spawn(async move {
            let mut guard = av_for_loop.lock().await;
            let Some(session) = guard.as_mut() else {
                return;
            };
            while let Some(participant) = session.recv().await {
                if shutdown_for_loop.load(Ordering::Relaxed) {
                    break;
                }
                // Stash the video handle for this participant under
                // their nick. The freeq_look tool reads it.
                videos_for_loop
                    .write()
                    .await
                    .insert(participant.nick.clone(), participant.video.clone());
                let tx = tx_for_loop.clone();
                let stt = stt_for_loop.clone();
                let nick = nick_for_loop.clone();
                let peers = peers_for_loop.clone();
                let control = control_for_loop.clone();
                let handle = handle_for_loop.clone();
                let channel = channel_for_loop.clone();
                let speaker = speaker_for_loop.clone();
                let memory = memory_for_loop.clone();
                let say_active = say_active_for_loop.clone();
                let last_addressed_ms = last_addressed_ms_for_loop.clone();
                let accumulated_diagram = accumulated_diagram_for_loop.clone();
                let args = TranscribeArgs {
                    participant,
                    stt,
                    my_nick: nick,
                    peers,
                    control,
                    speaker,
                    say_active,
                    last_addressed_ms,
                    accumulated_diagram,
                    handle,
                    channel,
                    emit_diagrams,
                    barge_in,
                    memory,
                    tx,
                };
                if let Some(key) = &deepgram_key {
                    // Bias the recognizer toward the names in this room —
                    // our own nick + peer agents. Without this, STT
                    // renders names as phonetic neighbours ("Clyde" →
                    // "Lighthouse") and addressing silently fails.
                    let mut keyterms = vec![nick_for_loop.clone()];
                    keyterms.extend(peers_for_loop.iter().cloned());
                    let cfg = StreamingSttConfig {
                        api_key: key.clone(),
                        model: deepgram_model.clone(),
                        // freeq-av decodes opus to 48 kHz; pass-through.
                        sample_rate: 48_000,
                        keyterms,
                    };
                    tokio::spawn(transcribe_participant_streaming(args, cfg));
                } else {
                    tokio::spawn(transcribe_participant(args));
                }
            }
        }));

        // Speak-state pump: poll the speaker every 50ms to flip the
        // face's self_level signal. Cheap (atomic load + atomic store).
        let speaker_for_pump = speaker.clone();
        let control_for_pump = control.clone();
        let shutdown_for_pump = shutdown.clone();
        handles.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(50));
            while !shutdown_for_pump.load(Ordering::Relaxed) {
                interval.tick().await;
                let lvl = if speaker_for_pump.is_speaking() {
                    1.0
                } else {
                    0.0
                };
                control_for_pump.set_self_level(lvl);
            }
        }));

        // Auto-heartbeat: when a delivered question has been pending a
        // reply for >12s without any say/post since, speak a soft ack so
        // the human knows we're still working. Repeats once after 15s,
        // then goes silent — a third "give me a sec" is nagging. Arms
        // ONLY on questions actually handed to the brain via recv_batch:
        // a bare name-mention or an unfetched transcript must never
        // trigger a promise nobody is working on.
        let last_delivered_hb = last_delivered_ms.clone();
        let last_say_hb = last_say_ms.clone();
        let say_active_hb = say_active.clone();
        let speaker_hb = speaker.clone();
        let handle_hb = handle.clone();
        let channel_hb = cfg.channel.clone();
        let control_hb = control.clone();
        let shutdown_hb = shutdown.clone();
        let tts_hb_key = cfg.elevenlabs_api_key.clone();
        let tts_hb_voice = cfg.elevenlabs_voice_id.clone();
        let tts_hb_model = cfg.elevenlabs_model.clone();
        handles.push(tokio::spawn(async move {
            let phrases = [
                "Give me a sec.",
                "Still working on it.",
                "Hang on, one moment.",
                "Almost there.",
            ];
            let mut phrase_idx: usize = 0;
            // Beats are per-question: the counter resets when a new
            // question is delivered, and heartbeats never touch
            // last_say_ms — an ack is not an answer.
            let mut beats: u32 = 0;
            let mut beats_for: i64 = 0;
            let mut last_beat_ms: i64 = 0;
            let mut interval = tokio::time::interval(Duration::from_millis(3_000));
            while !shutdown_hb.load(Ordering::Relaxed) {
                interval.tick().await;
                if say_active_hb.load(Ordering::Relaxed) {
                    continue;
                }
                let Some(api_key) = tts_hb_key.as_deref() else {
                    continue;
                };
                let now = now_ms();
                let delivered = last_delivered_hb.load(Ordering::Relaxed);
                let said = last_say_hb.load(Ordering::Relaxed);
                if delivered != beats_for {
                    beats = 0;
                    beats_for = delivered;
                }
                if !heartbeat_due(now, delivered, said, last_beat_ms, beats) {
                    continue;
                }
                let phrase = phrases[phrase_idx % phrases.len()];
                phrase_idx += 1;
                say_active_hb.store(true, Ordering::Relaxed);
                control_hb.set_thinking(true);
                let client = reqwest::Client::new();
                let synth_speaker = speaker_hb.clone();
                let r = synthesize_streaming(
                    &client,
                    api_key,
                    &tts_hb_voice,
                    &tts_hb_model,
                    phrase,
                    |pcm: &[f32]| synth_speaker.enqueue(pcm, ELEVENLABS_PCM_RATE),
                )
                .await;
                if let Err(e) = r {
                    tracing::warn!(error = %format!("{e:#}"), "heartbeat TTS failed");
                    say_active_hb.store(false, Ordering::Relaxed);
                    continue;
                }
                let _ = handle_hb.privmsg(&channel_hb, phrase).await;
                beats += 1;
                last_beat_ms = now_ms();
                tracing::info!(%phrase, beats, "heartbeat emitted");
                // Local drain monitor: flip say_active + thinking off
                // 200 ms after the queue empties.
                let sa = say_active_hb.clone();
                let sp = speaker_hb.clone();
                let ctl = control_hb.clone();
                tokio::spawn(async move {
                    let mut quiet_since: Option<Instant> = None;
                    loop {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        if sp.is_speaking() {
                            quiet_since = None;
                            continue;
                        }
                        match quiet_since {
                            None => quiet_since = Some(Instant::now()),
                            Some(t) if t.elapsed() >= Duration::from_millis(200) => {
                                sa.store(false, Ordering::Relaxed);
                                ctl.set_thinking(false);
                                return;
                            }
                            _ => {}
                        }
                    }
                });
            }
        }));

        Ok(Self {
            nick: cfg.nick,
            channel: cfg.channel,
            session_id,
            instance_id,
            handle,
            speaker,
            transcripts: AsyncMutex::new(rx),
            tts: TtsConfig {
                api_key: cfg.elevenlabs_api_key,
                voice_id: cfg.elevenlabs_voice_id,
                model: cfg.elevenlabs_model,
            },
            control,
            videos,
            memory,
            say_active,
            volunteer_cooldown: Duration::from_secs(cfg.volunteer_cooldown_secs),
            last_volunteer_at: AsyncMutex::new(None),
            last_say_ms,
            last_delivered_ms,
            _join_handles: handles,
            _av_session: av_session,
            shutdown,
        })
    }

    /// Snapshot the most recent video frame for `speaker`, or pick the
    /// most-recently-active participant when `speaker` is None. Returns
    /// `None` when there's no participant or no frame yet.
    pub async fn latest_frame(
        &self,
        speaker: Option<&str>,
    ) -> Option<(String, iroh_live::media::format::VideoFrame)> {
        let videos = self.videos.read().await;
        if let Some(target) = speaker {
            // Case-insensitive nick match — the user may type "narrator"
            // even though the participant nick is "narrator-z6mk…".
            let target_lc = target.to_lowercase();
            for (nick, vh) in videos.iter() {
                let nick_lc = nick.to_lowercase();
                let prefix = nick_lc.split('-').next().unwrap_or(&nick_lc).to_string();
                if (nick_lc == target_lc || prefix == target_lc)
                    && let Some(f) = vh.latest()
                {
                    return Some((nick.clone(), f));
                }
            }
            return None;
        }
        // No target — pick whichever participant has a frame, preferring
        // those whose nick isn't ourselves (the bot's own video).
        for (nick, vh) in videos.iter() {
            if nick.eq_ignore_ascii_case(&self.nick) {
                continue;
            }
            if let Some(f) = vh.latest() {
                return Some((nick.clone(), f));
            }
        }
        None
    }

    /// List the nicks of every participant we currently see in the call.
    pub async fn participants(&self) -> Vec<String> {
        self.videos.read().await.keys().cloned().collect()
    }

    /// Query persistent memory. Returns at most `limit` past exchanges
    /// matching `query`. Returns an empty Vec when memory is disabled.
    pub fn recall(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<freeq_eliza::memory::Recollection>> {
        let Some(mem) = self.memory.as_ref() else {
            return Ok(Vec::new());
        };
        mem.recall(query, Some(&self.channel), limit)
            .context("memory recall")
    }

    /// Long-poll for transcripts.
    ///
    /// Blocks up to `max_wait` for the *first* transcript. Once at
    /// least one arrives, drains any others already queued and returns
    /// them all. This shape fits the MCP `freeq_listen` tool naturally:
    /// CC calls it, the call blocks until something is said, and CC
    /// gets a coalesced batch.
    pub async fn recv_batch(&self, max_wait: Duration) -> Vec<Transcript> {
        let deadline = Instant::now() + max_wait;
        let mut rx = self.transcripts.lock().await;
        let mut out = Vec::new();
        let first = tokio::time::timeout(max_wait, rx.recv()).await;
        match first {
            Ok(Some(t)) => out.push(t),
            _ => return out,
        }
        // Drain anything already buffered without blocking.
        while let Ok(t) = rx.try_recv() {
            out.push(t);
            if Instant::now() >= deadline {
                break;
            }
        }
        // Arm the heartbeat: a real question is now in the brain's
        // hands. Bare mentions (empty question) don't count — there is
        // nothing to promise progress on.
        if out
            .iter()
            .any(|t| t.addressed && t.question.as_deref().is_some_and(|q| !q.is_empty()))
        {
            self.last_delivered_ms.store(now_ms(), Ordering::Relaxed);
        }
        out
    }

    /// Synthesize `text` and broadcast it. Returns once the audio is
    /// queued — the speaker keeps playing after the call returns.
    ///
    /// When `priority` is `Volunteer` and the last volunteer utterance
    /// was within `volunteer_cooldown`, the call is suppressed and
    /// returns `SayResult { suppressed: true, cooldown_remaining_secs }`
    /// without invoking TTS. `Addressed` calls are never suppressed —
    /// when a human asked, the bot replies.
    pub async fn say(&self, text: &str, priority: SayPriority) -> Result<SayResult> {
        if priority == SayPriority::Volunteer {
            let mut last = self.last_volunteer_at.lock().await;
            if let Some(t) = *last {
                let elapsed = t.elapsed();
                if elapsed < self.volunteer_cooldown {
                    let remaining = self.volunteer_cooldown.saturating_sub(elapsed).as_secs();
                    return Ok(SayResult {
                        suppressed: true,
                        cooldown_remaining_secs: remaining,
                    });
                }
            }
            *last = Some(Instant::now());
        }
        let Some(api_key) = self.tts.api_key.clone() else {
            return Err(anyhow!("ELEVENLABS_API_KEY not set — TTS unavailable"));
        };
        let voice_id = self.tts.voice_id.clone();
        let model = self.tts.model.clone();
        let speaker = self.speaker.clone();
        let client = reqwest::Client::new();
        self.say_active.store(true, Ordering::Relaxed);
        self.control.set_thinking(true);
        self.last_say_ms.store(now_ms(), Ordering::Relaxed);
        let synth_res = synthesize_streaming(
            &client,
            &api_key,
            &voice_id,
            &model,
            text,
            |pcm: &[f32]| {
                speaker.enqueue(pcm, ELEVENLABS_PCM_RATE);
            },
        )
        .await
        .context("ElevenLabs TTS stream");

        // Drain monitor: keep `say_active` true until either the queue
        // empties for a 200ms grace, OR another `say()` queues more
        // audio (which keeps the flag set anyway). Either way barge-in
        // sees a stable signal during the entire spoken response.
        let speaker_drain = speaker.clone();
        let say_active = self.say_active.clone();
        let control_drain = self.control.clone();
        tokio::spawn(async move {
            let mut quiet_since: Option<Instant> = None;
            loop {
                tokio::time::sleep(Duration::from_millis(50)).await;
                if speaker_drain.is_speaking() {
                    quiet_since = None;
                    continue;
                }
                match quiet_since {
                    None => quiet_since = Some(Instant::now()),
                    Some(t) if t.elapsed() >= Duration::from_millis(200) => {
                        say_active.store(false, Ordering::Relaxed);
                        control_drain.set_thinking(false);
                        return;
                    }
                    _ => {}
                }
            }
        });

        synth_res?;
        let _ = self.handle.privmsg(&self.channel, text).await;
        if let Some(mem) = self.memory.as_ref() {
            // Persist what we said in the same shape as incoming
            // utterances — content lives in `question`, `answer` stays
            // empty — so recall hits surface uniformly.
            let _ = mem.record(&self.channel, &self.nick, text, "");
        }
        Ok(SayResult {
            suppressed: false,
            cooldown_remaining_secs: 0,
        })
    }

    /// Returns true while there's audio still queued / being spoken.
    pub fn is_speaking(&self) -> bool {
        self.speaker.is_speaking()
    }

    /// Drop `text` into the IRC channel as PRIVMSG, no TTS. Long text
    /// is split on newlines and posted line-by-line — IRC has a
    /// ~400-byte PRIVMSG cap, so multi-paragraph artifacts (diffs,
    /// citations, bullets) must arrive pre-split by the caller.
    pub async fn post(&self, text: &str) -> Result<()> {
        // A post IS a reply — disarm the heartbeat. Answering in text
        // (a link, a diff) must not be followed by "still working on it".
        self.last_say_ms.store(now_ms(), Ordering::Relaxed);
        let mut sent = 0usize;
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            self.handle
                .privmsg(&self.channel, line)
                .await
                .context("PRIVMSG send")?;
            sent += 1;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        if sent == 0 && !text.is_empty() {
            self.handle
                .privmsg(&self.channel, text)
                .await
                .context("PRIVMSG send")?;
        }
        Ok(())
    }

    /// Leave the channel, drop the AV session, signal background tasks
    /// to stop. Safe to call concurrently with held `Arc<Orchestrator>`
    /// references — the pump tasks check `shutdown` and quiesce.
    pub async fn disconnect(&self) -> Result<()> {
        self.shutdown.store(true, Ordering::Relaxed);
        // Deregister from the AV session BEFORE quitting IRC — without
        // av-leave the server keeps announcing our broadcast and
        // clients render a ghost tile after we're gone.
        let _ = self
            .handle
            .av_leave(&self.channel, &self.session_id, &self.instance_id)
            .await;
        let _ = self.handle.quit(Some("leaving")).await;
        let mut guard = self._av_session.lock().await;
        guard.take();
        Ok(())
    }

    pub fn nick(&self) -> &str {
        &self.nick
    }

    pub fn channel(&self) -> &str {
        &self.channel
    }
}

/// Args bundle for `transcribe_participant`. Was a 9-arg function; now
/// a struct so adding a knob (barge-in, memory) doesn't sprawl.
struct TranscribeArgs {
    participant: AvParticipant,
    stt: Arc<SttEngine>,
    my_nick: String,
    peers: Vec<String>,
    control: ParticleControl,
    speaker: Speaker,
    /// Stable "we're in the middle of saying something" flag — true
    /// from say() entry through queue drain. Reused as barge-in gate
    /// in place of the flickery `Speaker::is_speaking`.
    say_active: Arc<AtomicBool>,
    /// Wall-clock ms of the last addressed transcript — bumped by the
    /// transcribe loops so the heartbeat task knows when a reply is
    /// pending.
    last_addressed_ms: Arc<AtomicI64>,
    /// Accumulating whiteboard. Each utterance's triples merge in; on
    /// new edges, a fresh Graph overlay is pushed.
    accumulated_diagram: Arc<std::sync::Mutex<Diagram>>,
    handle: ClientHandle,
    channel: String,
    emit_diagrams: bool,
    barge_in: bool,
    memory: Option<Arc<Memory>>,
    tx: mpsc::Sender<Transcript>,
}

/// The per-participant transcribe loop: PCM → VAD → STT → Transcript.
/// Also runs the barge-in detector (audio peak above threshold for N
/// consecutive frames aborts an in-flight TTS queue) and persists each
/// transcript to memory when enabled.
async fn transcribe_participant(args: TranscribeArgs) {
    let TranscribeArgs {
        participant,
        stt,
        my_nick,
        peers,
        control,
        speaker,
        say_active,
        last_addressed_ms,
        accumulated_diagram,
        handle,
        channel,
        emit_diagrams,
        barge_in,
        memory,
        tx,
    } = args;
    let AvParticipant {
        path,
        nick,
        mut audio,
        ..
    } = participant;
    tracing::info!(%nick, %path, "participant audio live — transcribing");
    let mut segmenter = VadSegmenter::new(VadConfig::default());
    // Barge-in state: count of consecutive loud frames from this peer.
    // Threshold tuned for opus-compressed remote audio: 0.03 is well
    // above background noise but reachable by normal speech levels
    // after SFU mixing. 8 frames at ~20ms each ≈ 160ms of sustained
    // voice — past where a click or breath would land.
    let mut sustained_loud: u32 = 0;
    let mut peak_log_throttle: u32 = 0;
    // Last time we saw sustained voice from this peer. Drives the
    // auto-thinking indicator — keeps the face's "working" arc on
    // through the STT round trip + LLM compose, so the human sees an
    // instant signal that we heard them.
    let mut last_voice_at: Option<Instant> = None;
    const BARGE_PEAK: f32 = 0.03;
    const BARGE_FRAMES: u32 = 8;
    const VOICE_GRACE: Duration = Duration::from_millis(2_000);

    while let Some(frame) = audio.recv().await {
        let pcm = to_whisper_pcm(&frame.samples, frame.format);
        if pcm.is_empty() {
            continue;
        }
        // Snap up to the peak, ease down — same shape the eliza tile uses.
        let peak = pcm.iter().fold(0.0f32, |m, &s| m.max(s.abs()));
        let prev = f32::from_bits(control.peer_level.load(Ordering::Relaxed));
        let smoothed = if peak > prev {
            peak
        } else {
            prev * 0.92 + peak * 0.08
        };
        control.set_peer_level(smoothed);

        // Auto-thinking: voice activity flips the face's working
        // indicator on immediately, before STT/LLM/TTS round-trip. The
        // signal holds for VOICE_GRACE after the last loud frame so it
        // covers the STT pause-to-finalize + composition window. We
        // never clear thinking while a say is in flight — the drain
        // monitor in say() will clear it when audio finishes playing.
        if smoothed > BARGE_PEAK {
            if last_voice_at.is_none() {
                control.set_thinking(true);
            }
            last_voice_at = Some(Instant::now());
        } else if let Some(t) = last_voice_at
            && t.elapsed() > VOICE_GRACE
            && !say_active.load(Ordering::Relaxed)
        {
            control.set_thinking(false);
            last_voice_at = None;
        }

        // Barge-in: when smoothed peer audio is sustained above the
        // threshold and we're in the middle of saying something, clear
        // the TTS queue. Smoothed (not raw) peak because per-frame
        // values swing wildly between syllables; say_active (not
        // `Speaker::is_speaking`) because the queue itself flickers
        // empty between TTS chunks.
        if barge_in {
            let active = say_active.load(Ordering::Relaxed);
            if smoothed > BARGE_PEAK {
                sustained_loud += 1;
                if active && sustained_loud == BARGE_FRAMES {
                    tracing::info!(%nick, smoothed, sustained_loud, "barge-in candidate (say active)");
                }
                if sustained_loud >= BARGE_FRAMES && active {
                    speaker.clear();
                    say_active.store(false, Ordering::Relaxed);
                    tracing::info!(%nick, smoothed, "barge-in — TTS queue cleared");
                    sustained_loud = 0;
                }
            } else {
                sustained_loud = sustained_loud.saturating_sub(1);
            }
            peak_log_throttle = peak_log_throttle.wrapping_add(1);
            if peak_log_throttle.is_multiple_of(25) && smoothed > 0.001 {
                tracing::info!(%nick, peak, smoothed, sustained_loud, active, "peer audio sample");
            }
        }

        let Some(chunk) = segmenter.push(&pcm) else {
            continue;
        };

        let stt = stt.clone();
        let nick = nick.clone();
        let my_nick = my_nick.clone();
        let peers = peers.clone();
        let tx = tx.clone();
        let handle = handle.clone();
        let channel = channel.clone();
        let memory = memory.clone();
        let last_addressed_ms = last_addressed_ms.clone();
        let accumulated_diagram = accumulated_diagram.clone();
        let control_for_graph = control.clone();
        tokio::spawn(async move {
            let Ok(text) = stt.transcribe(&chunk).await else {
                return;
            };
            if text.is_empty() || freeq_agent_kit::is_hallucination(&text) {
                return;
            }
            let (addressed, question) = lenient_address(&text, &my_nick, &peers, &nick);
            let now_ts = now_ms();
            if addressed {
                last_addressed_ms.store(now_ts, Ordering::Relaxed);
            }

            if emit_diagrams {
                let mut d = Diagram::new();
                if d.ingest(&text) > 0 {
                    for edge in d.edges() {
                        let line = format!("[diag] {}|{}|{}", edge.from, edge.relation, edge.to);
                        let _ = handle.privmsg(&channel, &line).await;
                    }
                }
                // Merge into the running whiteboard and re-render. Only
                // overwrites the tile when it's idle or already showing
                // a Graph — a deliberately-shown Card / File / Quote
                // wins.
                let steps = {
                    let mut acc = accumulated_diagram.lock().expect("diagram poisoned");
                    let added = acc.ingest(&text);
                    if added > 0 {
                        Some(acc.to_steps())
                    } else {
                        None
                    }
                };
                if let Some(steps) = steps {
                    control_for_graph.set_overlay_if_idle_or_graph(
                        crate::tile_overlay::TileOverlay::Graph { steps },
                    );
                }
            }

            if let Some(mem) = memory.as_ref() {
                // Persist every utterance as a one-sided record — asker
                // is the speaker; the "answer" column is empty until
                // (later) the bot's say() wraps it into a pair.
                let _ = mem.record(&channel, &nick, &text, "");
            }

            let t = Transcript {
                speaker: nick,
                text,
                addressed,
                question,
                timestamp_ms: now_ts as u64,
            };
            tracing::info!(speaker = %t.speaker, addressed = %t.addressed, text = %t.text, "transcript");
            let _ = tx.send(t).await;
        });
    }
}

/// Streaming variant of `transcribe_participant`. Same peak/smoothed/
/// barge-in/auto-thinking signals as the batched path — those are
/// purely local energy detection — but instead of running VAD +
/// batched STT, each PCM frame is forwarded as little-endian 16-bit to
/// a per-participant Deepgram websocket and finalised transcripts come
/// back on the same socket.
async fn transcribe_participant_streaming(args: TranscribeArgs, cfg: StreamingSttConfig) {
    let TranscribeArgs {
        participant,
        stt: _,
        my_nick,
        peers,
        control,
        speaker,
        say_active,
        last_addressed_ms,
        accumulated_diagram,
        handle,
        channel,
        emit_diagrams,
        barge_in,
        memory,
        tx,
    } = args;
    let AvParticipant {
        path,
        nick,
        mut audio,
        ..
    } = participant;
    tracing::info!(%nick, %path, "participant audio live — streaming STT");

    let (mut writer, reader) = match streaming_stt::connect(&cfg).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(%nick, error = %format!("{e:#}"), "deepgram connect failed — participant unmonitored");
            return;
        }
    };

    // Spawn the reader half: read JSON frames, emit Transcripts on
    // finalised text. Same downstream pipeline as the batched path —
    // address detection, diagram emit, memory persist.
    let nick_r = nick.clone();
    let my_nick_r = my_nick.clone();
    let peers_r = peers.clone();
    let channel_r = channel.clone();
    let handle_r = handle.clone();
    let memory_r = memory.clone();
    let tx_r = tx.clone();
    let last_addressed_ms_r = last_addressed_ms.clone();
    let accumulated_diagram_r = accumulated_diagram.clone();
    let control_r = control.clone();
    tokio::spawn(async move {
        use futures_util::StreamExt;
        let mut reader = reader;
        while let Some(msg) = reader.next().await {
            let Ok(msg) = msg else {
                tracing::warn!(nick = %nick_r, "deepgram read error — closing");
                break;
            };
            let text_msg = match msg {
                tokio_tungstenite::tungstenite::Message::Text(t) => t.to_string(),
                tokio_tungstenite::tungstenite::Message::Close(_) => {
                    tracing::info!(nick = %nick_r, "deepgram closed stream");
                    break;
                }
                _ => continue,
            };
            let Some(text) = streaming_stt::parse_final_transcript(&text_msg) else {
                continue;
            };
            if freeq_agent_kit::is_hallucination(&text) {
                continue;
            }
            let (addressed, question) = lenient_address(&text, &my_nick_r, &peers_r, &nick_r);
            let now_ts = now_ms();
            if addressed {
                last_addressed_ms_r.store(now_ts, Ordering::Relaxed);
            }
            if emit_diagrams {
                let mut d = Diagram::new();
                if d.ingest(&text) > 0 {
                    for edge in d.edges() {
                        let line = format!("[diag] {}|{}|{}", edge.from, edge.relation, edge.to);
                        let _ = handle_r.privmsg(&channel_r, &line).await;
                    }
                }
                let steps = {
                    let mut acc = accumulated_diagram_r.lock().expect("diagram poisoned");
                    let added = acc.ingest(&text);
                    if added > 0 {
                        Some(acc.to_steps())
                    } else {
                        None
                    }
                };
                if let Some(steps) = steps {
                    control_r.set_overlay_if_idle_or_graph(
                        crate::tile_overlay::TileOverlay::Graph { steps },
                    );
                }
            }
            if let Some(mem) = memory_r.as_ref() {
                let _ = mem.record(&channel_r, &nick_r, &text, "");
            }
            let t = Transcript {
                speaker: nick_r.clone(),
                text,
                addressed,
                question,
                timestamp_ms: now_ts as u64,
            };
            tracing::info!(speaker = %t.speaker, addressed = %t.addressed, text = %t.text, "transcript (streaming)");
            let _ = tx_r.send(t).await;
        }
    });

    // Writer half: per-frame local signals + push PCM to Deepgram.
    let mut sustained_loud: u32 = 0;
    let mut last_voice_at: Option<Instant> = None;
    const BARGE_PEAK: f32 = 0.03;
    const BARGE_FRAMES: u32 = 8;
    const VOICE_GRACE: Duration = Duration::from_millis(2_000);

    while let Some(frame) = audio.recv().await {
        if frame.samples.is_empty() {
            continue;
        }
        let peak = frame.samples.iter().fold(0.0f32, |m, &s| m.max(s.abs()));
        let prev = f32::from_bits(control.peer_level.load(Ordering::Relaxed));
        let smoothed = if peak > prev {
            peak
        } else {
            prev * 0.92 + peak * 0.08
        };
        control.set_peer_level(smoothed);

        if smoothed > BARGE_PEAK {
            if last_voice_at.is_none() {
                control.set_thinking(true);
            }
            last_voice_at = Some(Instant::now());
        } else if let Some(t) = last_voice_at
            && t.elapsed() > VOICE_GRACE
            && !say_active.load(Ordering::Relaxed)
        {
            control.set_thinking(false);
            last_voice_at = None;
        }

        if barge_in {
            let active = say_active.load(Ordering::Relaxed);
            if smoothed > BARGE_PEAK {
                sustained_loud += 1;
                if sustained_loud >= BARGE_FRAMES && active {
                    speaker.clear();
                    say_active.store(false, Ordering::Relaxed);
                    tracing::info!(%nick, smoothed, "barge-in — TTS queue cleared");
                    sustained_loud = 0;
                }
            } else {
                sustained_loud = sustained_loud.saturating_sub(1);
            }
        }

        let pcm_le = streaming_stt::f32_to_mono_i16le(&frame.samples, &frame.format);
        if let Err(e) = streaming_stt::send_pcm(&mut writer, pcm_le).await {
            tracing::warn!(%nick, error = %format!("{e:#}"), "deepgram send failed — closing stream");
            break;
        }
    }
    // Participant left or session ended — close the deepgram side.
    let _ = streaming_stt::close_stream(&mut writer).await;
    tracing::info!(%nick, "streaming STT closed");
}

/// Lenient address detection.
///
/// First try the strict parser from `freeq-agent-kit`: it returns the
/// question text when the line opens with the nick (optionally after a
/// filler word) and has a question after. If that fails, fall back to a
/// bareword check — any token in the line equal to the nick triggers
/// `addressed=true` with an empty question. This catches *"Hello
/// Claude"*, *"Claude!"*, *"Hey Claude"* — the natural openers we saw
/// fail in tonight's session.
fn lenient_address(
    text: &str,
    my_nick: &str,
    peers: &[String],
    from_nick: &str,
) -> (bool, Option<String>) {
    if is_peer(peers, from_nick) {
        return (false, None);
    }
    if let Some(q) = extract_addressed(text, my_nick) {
        return (true, Some(q.trim().to_string()));
    }
    let nick_lc = my_nick.to_lowercase();
    for token in text.split(|c: char| !c.is_alphanumeric()) {
        if token.is_empty() {
            continue;
        }
        if token.to_lowercase() == nick_lc {
            return (true, Some(String::new()));
        }
    }
    // Vocative fallback: a *misheard* name in the calling position —
    // the whole utterance being just the name ("Clide?"), or the last
    // word when the previous word carries a vocative comma ("what do
    // you think, Clide?"). Fuzzy matching is confined to these two
    // spots: applied mid-sentence it would trigger on phonetic
    // neighbours ("glide", "slide") in ordinary talk.
    let words: Vec<&str> = text.split_whitespace().collect();
    if let [only] = words[..]
        && word_is_name(only, my_nick)
    {
        return (true, Some(String::new()));
    }
    if words.len() >= 2 {
        let last = words[words.len() - 1];
        let before = words[words.len() - 2];
        if before.ends_with(',') && word_is_name(last, my_nick) {
            return (true, Some(String::new()));
        }
    }
    (false, None)
}

/// Whether the auto-heartbeat should speak a reassurance. Honest by
/// construction: `delivered` is the wall-ms the last *question* was
/// handed to the brain via `recv_batch` (0 = never) — a bare name
/// mention never arms it, and an undelivered transcript (brain not
/// listening) never arms it. `said` is the last real reply (say or
/// post). `last_beat`/`beats` throttle repeats: 15s apart, at most 2
/// per question — after that silence beats nagging.
fn heartbeat_due(now: i64, delivered: i64, said: i64, last_beat: i64, beats: u32) -> bool {
    const HEARTBEAT_AFTER_MS: i64 = 12_000;
    const HEARTBEAT_REPEAT_MS: i64 = 15_000;
    const HEARTBEAT_MAX_BEATS: u32 = 2;
    delivered != 0
        && delivered > said
        && now - delivered >= HEARTBEAT_AFTER_MS
        && now - last_beat >= HEARTBEAT_REPEAT_MS
        && beats < HEARTBEAT_MAX_BEATS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_address_question_preserved() {
        let (addressed, q) = lenient_address(
            "Claude, what is the architecture?",
            "claude",
            &[],
            "chadfowler.com",
        );
        assert!(addressed);
        assert_eq!(q.unwrap(), "what is the architecture?");
    }

    #[test]
    fn bare_hello_triggers_addressed() {
        let (a, q) = lenient_address("Hello Claude", "claude", &[], "chad");
        assert!(a);
        assert_eq!(q.unwrap(), "");
    }

    #[test]
    fn bare_name_with_punct_triggers() {
        for line in ["Claude!", "Claude?", "Claude.", "Claude"] {
            let (a, _) = lenient_address(line, "claude", &[], "chad");
            assert!(a, "should address: {line:?}");
        }
    }

    #[test]
    fn unrelated_line_not_addressed() {
        let (a, q) = lenient_address("Oblivion, what do you think?", "claude", &[], "chad");
        assert!(!a);
        assert!(q.is_none());
    }

    #[test]
    fn vocative_at_end_tolerates_misheard_name() {
        // Live failure class 2026-07-01: the name lands at the END of
        // the utterance and STT misspells it — exact bareword matching
        // missed it and the bot ignored a direct question.
        for line in [
            "What do you think, Clide?",
            "How's the weather today, Glyde?",
            "can you hear me, clyde",
        ] {
            let (a, _) = lenient_address(line, "clyde", &[], "chad");
            assert!(a, "should address: {line:?}");
        }
    }

    #[test]
    fn single_word_misheard_name_is_addressed() {
        // Calling the dog's name alone: "Clide?" must turn the head.
        let (a, q) = lenient_address("Clide?", "clyde", &[], "chad");
        assert!(a);
        assert_eq!(q.unwrap(), "");
    }

    #[test]
    fn fuzzy_word_mid_sentence_is_not_addressed() {
        // "glide" is 1 edit from "clyde" — mid-sentence, not vocative:
        // must NOT match or the bot answers every aviation chat.
        for line in [
            "the plane will glide down slowly",
            "watch the plane glide",
            "we should slide the meeting",
        ] {
            let (a, _) = lenient_address(line, "clyde", &[], "chad");
            assert!(!a, "must not address: {line:?}");
        }
    }

    // ---------- heartbeat_due ----------
    //
    // Live failure 2026-07-01: "Give me a sec" spoken when no question
    // was pending (a bare name-mention armed the timer), and the ack
    // repeated with no answer ever coming. The heartbeat must be
    // HONEST: only promise work the brain has actually been handed,
    // and stop nagging after a couple of beats.

    #[test]
    fn heartbeat_not_due_when_nothing_delivered() {
        // Nothing handed to the brain → no promise to make.
        assert!(!heartbeat_due(100_000, 0, 0, 0, 0));
    }

    #[test]
    fn heartbeat_not_due_before_grace() {
        // Question delivered 5s ago — too early to reassure.
        assert!(!heartbeat_due(105_000, 100_000, 0, 0, 0));
    }

    #[test]
    fn heartbeat_due_after_grace_with_no_reply() {
        // Delivered 13s ago, nothing said since → reassure once.
        assert!(heartbeat_due(113_000, 100_000, 0, 0, 0));
    }

    #[test]
    fn heartbeat_not_due_once_answered() {
        // The bot replied (say or post) after delivery → disarmed.
        assert!(!heartbeat_due(113_000, 100_000, 101_000, 0, 0));
    }

    #[test]
    fn second_heartbeat_waits_for_repeat_spacing() {
        // First beat at t=113s; at t=120s (7s later) → too soon.
        assert!(!heartbeat_due(120_000, 100_000, 0, 113_000, 1));
        // At t=129s (16s after the beat) → due again.
        assert!(heartbeat_due(129_000, 100_000, 0, 113_000, 1));
    }

    #[test]
    fn heartbeat_goes_silent_after_max_beats() {
        // Two beats already — a third "give me a sec" is nagging, not
        // reassurance. Stay quiet no matter how much time passes.
        assert!(!heartbeat_due(200_000, 100_000, 0, 145_000, 2));
    }

    #[test]
    fn peer_speaker_never_addressed() {
        let (a, _) = lenient_address(
            "Claude, you should respond",
            "claude",
            &["oblivion".to_string()],
            "oblivion-z6mk",
        );
        assert!(!a, "peers can't address us in direct-address mode");
    }

    /// Barge-in pure logic — given sustained-loud-frame count, speaker
    /// state, and threshold, decides whether to clear. Lifted from the
    /// inline check in `transcribe_participant` so we can prove it in
    /// isolation without spinning up an AvSession.
    fn should_barge(sustained: u32, speaking: bool, threshold_frames: u32) -> bool {
        sustained >= threshold_frames && speaking
    }

    #[test]
    fn barge_fires_when_sustained_and_speaking() {
        assert!(should_barge(8, true, 8));
        assert!(should_barge(20, true, 8));
    }

    #[test]
    fn barge_silent_when_not_sustained() {
        assert!(!should_barge(7, true, 8));
        assert!(!should_barge(0, true, 8));
    }

    #[test]
    fn barge_silent_when_not_speaking() {
        assert!(!should_barge(20, false, 8));
    }

    /// End-to-end check that the live Speaker's clear() actually drains
    /// the queue and flips is_speaking off. The barge handler in
    /// `transcribe_participant` relies on this contract.
    #[test]
    fn speaker_clear_drains_queue() {
        use std::sync::atomic::{AtomicU32, Ordering as O};
        let level = Arc::new(AtomicU32::new(0));
        let (speaker, _push_source) = Speaker::new(level.clone());
        // 1s of 48k audio enqueued → queue full.
        let pcm: Vec<f32> = (0..48_000)
            .map(|i| ((i as f32) * 0.01).sin() * 0.5)
            .collect();
        speaker.enqueue(&pcm, 48_000);
        assert!(
            speaker.is_speaking(),
            "queue should hold audio after enqueue"
        );
        speaker.clear();
        assert!(!speaker.is_speaking(), "queue should be empty after clear");
        // Touch the level cell so the dropped _push_source isn't elided.
        let _ = level.load(O::Relaxed);
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn is_peer(peers: &[String], nick: &str) -> bool {
    let prefix = nick.split('-').next().unwrap_or(nick).to_lowercase();
    peers.iter().any(|p| {
        let p = p.to_lowercase();
        p == nick.to_lowercase() || p == prefix
    })
}

async fn wait_for_registration(events: &mut mpsc::Receiver<Event>) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(Event::Registered { .. })) => return Ok(()),
            Ok(Some(Event::AuthFailed { reason })) => {
                return Err(anyhow!("SASL auth failed: {reason}"));
            }
            Ok(Some(_)) => continue,
            Ok(None) => return Err(anyhow!("event stream closed during registration")),
            Err(_) => return Err(anyhow!("registration timeout")),
        }
    }
    Err(anyhow!("registration timeout"))
}

/// Watch for a `+freeq.at/av-state=started` TAGMSG on the channel and
/// return its session id.
async fn wait_for_av_started(events: &mut mpsc::Receiver<Event>, channel: &str) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(Event::TagMsg { target, tags, .. })) if target == channel => {
                if let Some(state) = parse_av_state(&tags)
                    && state.action == AvAction::Started
                {
                    return Ok(state.session_id);
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => return Err(anyhow!("event stream closed waiting for av-state")),
            Err(_) => return Err(anyhow!("timed out waiting for av-state=started")),
        }
    }
    Err(anyhow!("timed out waiting for av-state=started"))
}

fn derive_transport(server: &str) -> Result<(Option<String>, String)> {
    if server.starts_with("ws://") || server.starts_with("wss://") {
        let u: url::Url = server.parse().context("parsing server URL")?;
        let host = u.host_str().unwrap_or("localhost");
        let port = u
            .port()
            .unwrap_or(if server.starts_with("wss") { 443 } else { 80 });
        Ok((Some(server.to_string()), format!("{host}:{port}")))
    } else if server.starts_with("https://") || server.starts_with("http://") {
        let u: url::Url = server.parse().context("parsing server URL")?;
        let host = u.host_str().unwrap_or("localhost");
        let port = u
            .port()
            .unwrap_or(if server.starts_with("https") { 443 } else { 80 });
        let ws_scheme = if server.starts_with("https") {
            "wss"
        } else {
            "ws"
        };
        let path = u.path();
        let ws = format!("{ws_scheme}://{host}:{port}{path}");
        Ok((Some(ws), format!("{host}:{port}")))
    } else {
        Ok((None, server.to_string()))
    }
}

fn build_stt(cfg: &OrcConfig) -> Result<SttEngine> {
    if let Some(key) = cfg.groq_api_key.clone()
        && !key.trim().is_empty()
    {
        // Vocabulary prompt: our own nick AND the peer agents' — every
        // name in the room that Whisper must not render as a phonetic
        // neighbour ("Clyde" → "Lighthouse").
        let mut vocab = vec![cfg.nick.clone()];
        vocab.extend(cfg.peer_agents.iter().cloned());
        return Ok(SttEngine::groq(
            key,
            "whisper-large-v3-turbo".to_string(),
            &vocab,
        ));
    }
    tracing::warn!(
        "no GROQ_API_KEY in config — transcription is a no-op. \
         Set GROQ_API_KEY before connecting."
    );
    Ok(SttEngine::noop())
}

/// Re-export for the binaries that need to look up an Identity
/// independently (e.g. for printing on startup).
pub use freeq_eliza::identity as eliza_identity;
