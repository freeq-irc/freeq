//! `vision_probe` — verification harness proving a freeq-eliza worker
//! (e.g. nick "alexandria") can SEE a participant's camera/video.
//!
//! It connects to a freeq IRC server as a fresh ephemeral identity with
//! a distinctive nick (default "vistest"), starts an AV call in the
//! channel, discovers the session id via REST, and publishes a KNOWN
//! still image as its video tile (the same `StaticImage` VideoSource the
//! `freeq-av-image` tool uses). After a short delay — long enough for the
//! eliza worker to react to the `av-state=started` echo, join the call,
//! and tap the probe's video — it asks the worker by name in channel
//! chat ("<bot>, what do you see?"). eliza looks up the asker's (i.e.
//! vistest's) video tile, runs the vision model on the latest frame, and
//! both speaks AND logs the description.
//!
//! Watch the worker's log for:
//!   - "human joined a call we're not in — joining" / "participant audio
//!     live — transcribing  nick=vistest …"  (she tapped vistest)
//!   - "answering as a visual question"
//!   - "answer text (sent to TTS)  text=…"   (the vision description)
//!
//! Usage:
//!   cargo run --release --example vision_probe -- \
//!     --server wss://staging.freeq.at/irc \
//!     --channel '#chadtest' \
//!     --image /tmp/vision_probe.png \
//!     --nick vistest \
//!     --bot alexandria

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

/// 720p tile — matches freeq-eliza, reads well after H.264 + P360.
const TILE_W: u32 = 1280;
const TILE_H: u32 = 720;
const FPS: f64 = 15.0;

#[derive(Parser)]
#[command(about = "Publish a known image into a freeq call and prove the eliza worker sees it")]
struct Args {
    /// IRC server URL (wss://host/irc).
    #[arg(long, default_value = "wss://staging.freeq.at/irc")]
    server: String,
    /// Channel to join + start the call in.
    #[arg(long, default_value = "#chadtest")]
    channel: String,
    /// Path to the known test image (PNG/JPEG).
    #[arg(long, default_value = "/tmp/vision_probe.png")]
    image: String,
    /// Our nick in the call (must NOT be a peer agent / contain
    /// "alexandria" or "yokota").
    #[arg(long, default_value = "vistest")]
    nick: String,
    /// The eliza worker's nick to address with the vision question.
    #[arg(long, default_value = "alexandria")]
    bot: String,
    /// Seconds to wait after av-start before asking the vision question
    /// (lets the worker join + tap + warm up the first decoded frame).
    #[arg(long, default_value_t = 10)]
    settle_secs: u64,
    /// Total seconds to keep the session + connection alive.
    #[arg(long, default_value_t = 45)]
    keepalive_secs: u64,
}

// ─────────────────────────────────────────────────────────────────────
// StaticImage VideoSource + load_frame — copied verbatim from
// freeq-av-image/src/main.rs (lines 50-126).
// ─────────────────────────────────────────────────────────────────────

/// A [`VideoSource`] that emits one fixed RGBA frame at a steady cadence, so
/// the encoder produces a continuous static stream (late joiners still get
/// keyframes). The frame is shared `Bytes` — cloning per emit is a refcount.
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
        // First frame at info — confirms a subscriber pulled video and the
        // encoder started (if this never logs, nobody subscribed to our video
        // track). Thereafter periodic at debug to avoid log spam.
        if self.count == 1 {
            tracing::info!("video subscriber present — emitting frames");
        } else if self.count % 150 == 0 {
            tracing::debug!(frames = self.count, "emitting video frames");
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

/// Decode `path` and contain-fit it (preserving aspect) onto a black
/// TILE_W×TILE_H RGBA canvas. Returns the raw RGBA buffer as `Bytes`.
fn load_frame(path: &str) -> anyhow::Result<bytes::Bytes> {
    let src = image::open(path)
        .with_context(|| format!("open image {path}"))?
        .to_rgba8();
    let (sw, sh) = src.dimensions();
    let scale = (TILE_W as f32 / sw as f32).min(TILE_H as f32 / sh as f32);
    let nw = ((sw as f32 * scale).round() as u32).max(1);
    let nh = ((sh as f32 * scale).round() as u32).max(1);
    let scaled = image::imageops::resize(&src, nw, nh, image::imageops::FilterType::Lanczos3);

    let mut canvas = image::RgbaImage::from_pixel(TILE_W, TILE_H, image::Rgba([0, 0, 0, 255]));
    image::imageops::overlay(
        &mut canvas,
        &scaled,
        ((TILE_W - nw) / 2) as i64,
        ((TILE_H - nh) / 2) as i64,
    );
    Ok(bytes::Bytes::from(canvas.into_raw()))
}

// ─────────────────────────────────────────────────────────────────────
// Server-URL helpers — replicate freeq-eliza/src/irc.rs.
// ─────────────────────────────────────────────────────────────────────

/// Derive the MoQ SFU URL (`https://host[:port]/av/moq`) from the IRC
/// server URL. Mirrors `sfu_url_from_server` in irc.rs.
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

/// Derive the REST API base (`https://host[:port]`) from the IRC server
/// URL. Mirrors `api_base_from_server` in irc.rs.
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

/// Percent-encode `#` in the channel name for the REST path.
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

/// Query the REST API for the active AV session id in `channel`.
/// Mirrors `discover_active_session` in irc.rs.
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

/// did:key for an ed25519 public key — `did:key:{public_key_multibase}`
/// matches what freeq-eliza's identity module mints.
fn ephemeral_identity() -> (String, PrivateKey) {
    let key = PrivateKey::generate_ed25519();
    let did = format!("did:key:{}", key.public_key_multibase());
    (did, key)
}

/// Build the ConnectConfig for a wss:// / ws:// server URL — mirrors
/// freeq-eliza/src/irc.rs `run`.
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
        realname: "vision-probe".to_string(),
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

    let frame = load_frame(&args.image)?;
    tracing::info!(image = %args.image, "loaded test image into 1280x720 canvas");

    // 1. Connect as a fresh ephemeral identity.
    let (did, private_key) = ephemeral_identity();
    tracing::info!(%did, nick = %args.nick, "ephemeral probe identity");
    let conn_config = connect_config(&args.server, &args.nick)?;
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(did, private_key));
    let (handle, mut events) = client::connect(conn_config, Some(signer));

    // Wait for registration.
    let registered = wait_for_registration(&mut events).await?;
    tracing::info!(nick = %registered, "registered with server");

    // 2. Join the channel.
    handle.join(&args.channel).await.context("JOIN")?;
    tracing::info!(channel = %args.channel, "joined channel");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 3. Start an AV call.
    let instance = freeq_sdk::av::new_av_instance();
    handle
        .av_start(&args.channel, &instance, Some("vision probe"))
        .await
        .context("av_start")?;
    tracing::info!(%instance, "sent av-start");

    // 4. Discover the active session id via REST (retry briefly — the
    //    server creates the session on the av-start TAGMSG).
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

    // 5. Build the AvConfig and connect — publish the image tile.
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

    // Silent audio — video only.
    let (_speaker, audio) = Speaker::new(Arc::new(AtomicU32::new(0)));
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

    // 6. Wait for the worker to join + tap our video, then ask the
    //    vision question. Print any inbound chat from the bot.
    let settle = Duration::from_secs(args.settle_secs);
    tracing::info!(
        secs = args.settle_secs,
        "waiting for worker to join + tap video"
    );
    let deadline = Instant::now() + Duration::from_secs(args.keepalive_secs);

    let settle_until = Instant::now() + settle;
    let mut asked = false;
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if !asked && now >= settle_until {
            let q = format!("{}, what do you see in my video?", args.bot);
            handle
                .privmsg(&args.channel, &q)
                .await
                .context("asking vision question")?;
            tracing::info!(question = %q, "asked the vision question");
            asked = true;
        }
        // Pump events so we can surface the bot's chat replies.
        match tokio::time::timeout(Duration::from_millis(500), events.recv()).await {
            Ok(Some(Event::Message {
                from, target, text, ..
            })) => {
                tracing::info!(%from, %target, %text, "inbound message");
                if from
                    .to_ascii_lowercase()
                    .contains(&args.bot.to_ascii_lowercase())
                {
                    tracing::info!(%from, reply = %text, "BOT REPLY (chat)");
                }
            }
            Ok(Some(Event::Disconnected { reason })) => {
                anyhow::bail!("disconnected: {reason}");
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {} // timeout tick
        }
    }

    tracing::info!("keepalive window elapsed — quitting");
    Ok(())
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
