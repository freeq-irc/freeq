//! `voice_probe` — verification harness proving a freeq-eliza worker
//! (e.g. nick "alexandria") can HEAR a participant's spoken audio and run
//! her full voice pipeline (STT → answer → TTS → speak).
//!
//! Adapted from `vision_probe.rs`. Instead of (only) publishing a video
//! tile, it RETAINS the `Speaker` handle paired with the broadcast's audio
//! source, waits for the worker to join the call and subscribe to the
//! audio broadcast, then decodes a WAV file (a spoken question) and feeds
//! it into the call via `speaker.enqueue(&pcm, sample_rate)`. The worker
//! taps `voicetest`'s audio, transcribes it, composes an answer, and
//! speaks it back — driving the latency instrumentation in her log.
//!
//! A tiny static image is also published as video purely to keep the
//! AvSession alive and well-formed; the worker only needs the AUDIO track
//! for STT (has_audio=true in her catalog).
//!
//! Watch the worker's log (/Users/chad/.yokotabot/relaunch.out) for:
//!   - "participant audio live" / "audio tap heartbeat" (nonzero peak for voicetest)
//!   - "latency: VAD flush" / "transcribed utterance"
//!   - "latency: STT round-trip" / "answering addressed question"
//!   - "answer text (sent to TTS)" / "latency: SUMMARY speech_end→first_audio"
//!
//! Usage:
//!   cargo run --release --example voice_probe -p freeq-eliza -- \
//!     --server wss://staging.freeq.at/irc \
//!     --channel '#chadtest' \
//!     --nick voicetest \
//!     --wav /tmp/voice_q.wav

use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::Parser;
use freeq_av::{AvConfig, AvSession, Speaker, broadcast_path};
use freeq_sdk::auth::{ChallengeSigner, KeySigner};
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::event::Event;
use iroh_live::media::format::{PixelFormat, VideoFormat, VideoFrame};
use iroh_live::media::traits::VideoSource;

/// Small video tile — just enough to keep the AV session well-formed.
const TILE_W: u32 = 320;
const TILE_H: u32 = 240;
const FPS: f64 = 15.0;

#[derive(Parser)]
#[command(
    about = "Publish spoken audio (a WAV) into a freeq call and drive the eliza voice pipeline"
)]
struct Args {
    /// IRC server URL (wss://host/irc).
    #[arg(long, default_value = "wss://staging.freeq.at/irc")]
    server: String,
    /// Channel to join + start the call in.
    #[arg(long, default_value = "#chadtest")]
    channel: String,
    /// Our nick in the call (must NOT be a peer agent / contain
    /// "alexandria" or "yokota").
    #[arg(long, default_value = "voicetest")]
    nick: String,
    /// Path to the WAV file (mono 16-bit PCM) to speak into the call.
    #[arg(long, default_value = "/tmp/voice_q.wav")]
    wav: String,
    /// Seconds to wait after AvSession::connect before enqueueing the WAV
    /// (lets the worker join + subscribe to our audio broadcast).
    #[arg(long, default_value_t = 7)]
    settle_secs: u64,
    /// Total seconds to keep the session alive after enqueue (transcribe +
    /// compose + speak).
    #[arg(long, default_value_t = 45)]
    keepalive_secs: u64,
}

// ─────────────────────────────────────────────────────────────────────
// StaticImage VideoSource — emits one fixed RGBA frame at a steady
// cadence so the AV session has a valid (if dull) video track.
// ─────────────────────────────────────────────────────────────────────

struct StaticImage {
    data: bytes::Bytes,
    last: Option<Instant>,
    count: u64,
}

impl VideoSource for StaticImage {
    fn name(&self) -> &str {
        "image"
    }

    fn format(&self) -> VideoFormat {
        VideoFormat {
            pixel_format: PixelFormat::Rgba,
            dimensions: [TILE_W, TILE_H],
        }
    }

    fn pop_frame(&mut self) -> anyhow::Result<Option<VideoFrame>> {
        let now = Instant::now();
        let due = self
            .last
            .is_none_or(|t| now.duration_since(t).as_secs_f64() >= 1.0 / FPS);
        if !due {
            return Ok(None);
        }
        self.last = Some(now);
        self.count += 1;
        if self.count == 1 {
            tracing::info!("video subscriber present — emitting frames");
        }
        Ok(Some(VideoFrame::new_rgba(
            self.data.clone(),
            TILE_W,
            TILE_H,
            Duration::ZERO,
        )))
    }

    fn start(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn stop(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// A solid dark-gray TILE_W×TILE_H RGBA frame, in memory (no image file).
fn solid_frame() -> bytes::Bytes {
    let mut buf = Vec::with_capacity((TILE_W * TILE_H * 4) as usize);
    for _ in 0..(TILE_W * TILE_H) {
        buf.extend_from_slice(&[32, 32, 40, 255]);
    }
    bytes::Bytes::from(buf)
}

/// Decode a WAV file into mono f32 PCM. Parses the RIFF chunk list (the
/// `data` chunk is NOT necessarily at offset 44 — there can be padding
/// chunks like `FLLR` first), reads the `fmt ` chunk for the sample rate /
/// channels / bit depth, then converts the `data` chunk s16le → f32
/// (i16 / 32768.0). Down-mixes to mono if multi-channel. Returns
/// `(pcm, sample_rate)`.
fn decode_wav(path: &str) -> anyhow::Result<(Vec<f32>, u32)> {
    let bytes = std::fs::read(path).with_context(|| format!("read WAV {path}"))?;
    anyhow::ensure!(bytes.len() >= 12, "WAV too short");
    anyhow::ensure!(&bytes[0..4] == b"RIFF", "not a RIFF file");
    anyhow::ensure!(&bytes[8..12] == b"WAVE", "not a WAVE file");

    let read_u32 =
        |o: usize| u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
    let read_u16 = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]);

    let mut sample_rate: Option<u32> = None;
    let mut channels: u16 = 1;
    let mut bits: u16 = 16;
    let mut audio_fmt: u16 = 1;
    let mut data: Option<&[u8]> = None;

    let mut off = 12usize;
    while off + 8 <= bytes.len() {
        let id = &bytes[off..off + 4];
        let sz = read_u32(off + 4) as usize;
        let body_start = off + 8;
        let body_end = (body_start + sz).min(bytes.len());
        match id {
            b"fmt " => {
                anyhow::ensure!(sz >= 16, "fmt chunk too small");
                audio_fmt = read_u16(body_start);
                channels = read_u16(body_start + 2).max(1);
                sample_rate = Some(read_u32(body_start + 4));
                bits = read_u16(body_start + 14);
            }
            b"data" => {
                data = Some(&bytes[body_start..body_end]);
            }
            _ => {}
        }
        // Chunks are word-aligned: skip the body plus a pad byte if odd.
        off = body_start + sz + (sz & 1);
    }

    let sample_rate = sample_rate.context("WAV missing fmt chunk")?;
    let data = data.context("WAV missing data chunk")?;
    anyhow::ensure!(
        audio_fmt == 1,
        "only PCM WAV supported (audio_fmt={audio_fmt})"
    );
    anyhow::ensure!(bits == 16, "only 16-bit PCM supported (bits={bits})");

    let bytes_per_sample = 2usize;
    let frame_stride = bytes_per_sample * channels as usize;
    let frames = data.len() / frame_stride;
    let mut pcm = Vec::with_capacity(frames);
    for f in 0..frames {
        // Down-mix all channels to mono by averaging.
        let mut acc = 0.0f32;
        for c in 0..channels as usize {
            let o = f * frame_stride + c * bytes_per_sample;
            let s = i16::from_le_bytes([data[o], data[o + 1]]);
            acc += s as f32 / 32768.0;
        }
        pcm.push(acc / channels as f32);
    }
    Ok((pcm, sample_rate))
}

// ─────────────────────────────────────────────────────────────────────
// Server-URL helpers — replicate freeq-eliza/src/irc.rs.
// ─────────────────────────────────────────────────────────────────────

fn sfu_url_from_server(server: &str) -> anyhow::Result<url::Url> {
    let trimmed = server.trim();
    anyhow::ensure!(!trimmed.is_empty(), "server URL is empty");
    let normalized = if trimmed.starts_with("ws://")
        || trimmed.starts_with("wss://")
        || trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
    {
        trimmed.to_string()
    } else {
        format!("ws://{trimmed}")
    };
    let mut u: url::Url = normalized
        .parse()
        .with_context(|| format!("parsing server URL for SFU: {trimmed:?}"))?;
    match u.scheme() {
        "https" | "wss" => {
            u.set_scheme("https").ok();
        }
        "http" | "ws" => {
            u.set_scheme("http").ok();
        }
        other => anyhow::bail!("unsupported scheme for SFU URL: {other:?}"),
    }
    anyhow::ensure!(
        u.host_str().map(|h| !h.is_empty()).unwrap_or(false),
        "server URL has no host: {trimmed:?}"
    );
    u.set_path("/av/moq");
    Ok(u)
}

fn api_base_from_server(server: &str) -> anyhow::Result<String> {
    let trimmed = server.trim();
    anyhow::ensure!(!trimmed.is_empty(), "server URL is empty");
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

fn encode_channel(channel: &str) -> String {
    channel
        .bytes()
        .map(|b| {
            if b == b'#' {
                "%23".to_string()
            } else {
                (b as char).to_string()
            }
        })
        .collect()
}

async fn discover_active_session(
    http: &reqwest::Client,
    base: &str,
    channel: &str,
) -> Option<String> {
    let url = format!(
        "{base}/api/v1/channels/{}/sessions",
        encode_channel(channel)
    );
    let resp = http
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), %url, "session discovery non-200");
        return None;
    }
    let json: serde_json::Value = resp.json().await.ok()?;
    let active = json.get("active")?;
    if active.is_null() {
        return None;
    }
    let state = active.get("state").and_then(|s| s.as_str()).unwrap_or("");
    if state != "Active" {
        tracing::warn!(%state, "active session not in Active state");
        return None;
    }
    active
        .get("id")
        .and_then(|i| i.as_str())
        .map(|s| s.to_string())
}

// ─────────────────────────────────────────────────────────────────────

fn ephemeral_identity() -> (String, PrivateKey) {
    let key = PrivateKey::generate_ed25519();
    let did = format!("did:key:{}", key.public_key_multibase());
    (did, key)
}

fn connect_config(server: &str, nick: &str) -> anyhow::Result<ConnectConfig> {
    let websocket_url = if server.starts_with("ws://")
        || server.starts_with("wss://")
        || server.starts_with("http://")
        || server.starts_with("https://")
    {
        Some(server.to_string())
    } else {
        None
    };
    let server_addr = if let Some(ref ws) = websocket_url {
        let u: url::Url = ws.parse().context("parsing WebSocket URL")?;
        let host = u.host_str().unwrap_or("localhost");
        format!("{host}:443")
    } else {
        server.to_string()
    };
    Ok(ConnectConfig {
        server_addr,
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: "voice-probe".to_string(),
        tls: websocket_url.is_some()
            || server.starts_with("https://")
            || server.starts_with("wss://"),
        tls_insecure: false,
        web_token: None,
        websocket_url,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    anyhow::ensure!(
        !args.nick.to_ascii_lowercase().contains("alexandria")
            && !args.nick.to_ascii_lowercase().contains("yokota"),
        "probe nick must not contain a peer-agent name"
    );

    // Decode the WAV up front so we fail fast on a bad path/format.
    let (pcm, wav_rate) = decode_wav(&args.wav)?;
    tracing::info!(
        wav = %args.wav,
        rate = wav_rate,
        samples = pcm.len(),
        secs = pcm.len() as f32 / wav_rate as f32,
        "decoded WAV to mono f32 PCM"
    );

    let frame = solid_frame();

    // 1. Connect as a fresh ephemeral identity.
    let (did, private_key) = ephemeral_identity();
    tracing::info!(%did, nick = %args.nick, "ephemeral probe identity");
    let conn_config = connect_config(&args.server, &args.nick)?;
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(did, private_key));
    let (handle, mut events) = client::connect(conn_config, Some(signer));

    let registered = wait_for_registration(&mut events).await?;
    tracing::info!(nick = %registered, "registered with server");

    // 2. Join the channel.
    handle.join(&args.channel).await.context("JOIN")?;
    tracing::info!(channel = %args.channel, "joined channel");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 3. Start an AV call.
    let instance = freeq_sdk::av::new_av_instance();
    handle
        .av_start(&args.channel, &instance, Some("voice probe"))
        .await
        .context("av_start")?;
    tracing::info!(%instance, "sent av-start");

    // 4. Discover the active session id via REST.
    let http = reqwest::Client::new();
    let api_base = api_base_from_server(&args.server)?;
    let mut session_id = None;
    for attempt in 0..15 {
        if let Some(sid) = discover_active_session(&http, &api_base, &args.channel).await {
            session_id = Some(sid);
            break;
        }
        tracing::info!(attempt, "session not active yet — retrying");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let session_id = session_id.context("could not discover active AV session after av-start")?;
    tracing::info!(%session_id, "discovered active session");

    // 5. Build the AvConfig and connect. KEY CHANGE vs vision_probe: we
    //    RETAIN the Speaker handle (vision_probe discarded it as
    //    `_speaker`). The paired `audio` source is what AvSession
    //    publishes; `speaker.enqueue(...)` makes our broadcast speak.
    let sfu_url = sfu_url_from_server(&args.server)?;
    let our_broadcast = broadcast_path(&session_id, &args.nick, &instance);
    let av_config = AvConfig {
        sfu_url: sfu_url.clone(),
        session_id: session_id.clone(),
        our_broadcast: our_broadcast.clone(),
        my_nick: args.nick.clone(),
        audio_only: false,
    };
    tracing::info!(%sfu_url, broadcast = %our_broadcast, "connecting to SFU + publishing");

    let (speaker, audio) = Speaker::new(Arc::new(AtomicU32::new(0)));
    let frame_for_src = frame.clone();
    let mut session = AvSession::connect(av_config, audio, move || StaticImage {
        data: frame_for_src.clone(),
        last: None,
        count: 0,
    });

    // Drain participants the probe taps (informational only).
    tokio::spawn(async move {
        while let Some(p) = session.recv().await {
            tracing::info!(nick = %p.nick, "probe sees participant in call");
        }
    });

    // 6. Let the worker join + subscribe to our audio broadcast, then
    //    enqueue the spoken question.
    tracing::info!(
        secs = args.settle_secs,
        "settling — waiting for worker to subscribe to audio"
    );
    // Pump events during the settle so the connection stays healthy.
    pump_events(&mut events, Duration::from_secs(args.settle_secs)).await?;

    tracing::info!(
        samples = pcm.len(),
        rate = wav_rate,
        "enqueueing spoken question into the call audio"
    );
    speaker.enqueue(&pcm, wav_rate);
    let queued = speaker.queued_secs();
    tracing::info!(
        queued_secs = queued,
        "audio enqueued — speaker is now speaking"
    );

    // 7. Keep alive so the worker can transcribe + compose + speak.
    tracing::info!(
        secs = args.keepalive_secs,
        "keepalive — letting worker run the pipeline"
    );
    pump_events(&mut events, Duration::from_secs(args.keepalive_secs)).await?;

    tracing::info!("keepalive window elapsed — quitting");
    Ok(())
}

/// Pump inbound events for `dur`, surfacing any chat (e.g. if the bot
/// replies in channel) and bailing on disconnect.
async fn pump_events(
    events: &mut tokio::sync::mpsc::Receiver<Event>,
    dur: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + dur;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(());
        }
        let remaining = deadline - now;
        match tokio::time::timeout(remaining.min(Duration::from_millis(500)), events.recv()).await {
            Ok(Some(Event::Message {
                from, target, text, ..
            })) => {
                tracing::info!(%from, %target, %text, "inbound message");
            }
            Ok(Some(Event::Disconnected { reason })) => {
                anyhow::bail!("disconnected: {reason}");
            }
            Ok(Some(_)) => {}
            Ok(None) => anyhow::bail!("event stream closed"),
            Err(_) => {} // timeout tick
        }
    }
}

async fn wait_for_registration(
    events: &mut tokio::sync::mpsc::Receiver<Event>,
) -> anyhow::Result<String> {
    loop {
        match tokio::time::timeout(Duration::from_secs(30), events.recv()).await {
            Ok(Some(Event::Registered { nick })) => return Ok(nick),
            Ok(Some(Event::AuthFailed { reason })) => anyhow::bail!("SASL auth failed: {reason}"),
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("connection closed during registration"),
            Err(_) => anyhow::bail!("registration timeout"),
        }
    }
}
