//! Cross-transport AV interop harness.
//!
//! Spins up several MoQ agents against a freeq SFU — some over the **native
//! QUIC** path (`https://host:8080/av/moq`), some over the **web WebSocket**
//! path (`wss://host/av/moq`) — each publishing a distinct audio tone and a
//! distinct solid-colour video frame. Every agent subscribes to every other
//! agent, decodes what it receives, and the harness prints a reachability
//! matrix and writes per-pair artifacts you can listen to / look at:
//!
//!   <out>/<subscriber>__from__<publisher>.wav   (decoded audio)
//!   <out>/<subscriber>__from__<publisher>.bmp    (one decoded video frame)
//!
//! This exists to verify the QUIC <-> WebSocket unification (av_sfu.rs roots
//! both transports at the same broadcast namespace). Before that fix, QUIC
//! agents and WS agents were mutually invisible; this harness's matrix would
//! show a clean block-diagonal (QUIC sees QUIC, WS sees WS, no crossing).
//! After it, the matrix is fully populated.
//!
//! It talks ONLY to the SFU relay — no IRC, no auth, no server-side session
//! roster — because cross-transport visibility is purely a relay-namespace
//! property. Agents agree on a shared `--session` path prefix and discover
//! each other through the relay's announce stream, exactly as real clients do.
//!
//! Usage (defaults target production):
//!   cargo run -p freeq-av-client --example av_cross_transport_e2e
//!   cargo run -p freeq-av-client --example av_cross_transport_e2e -- \
//!       --quic-url https://127.0.0.1:8080/av/moq \
//!       --ws-url   ws://127.0.0.1:8080/av/moq \
//!       --quic 2 --ws 2 --secs 15 --out /tmp/freeq-av-e2e

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use iroh_live::media::codec::{AudioCodec, VideoCodec};
use iroh_live::media::format::{
    AudioFormat, AudioPreset, PixelFormat, VideoFormat, VideoFrame, VideoPreset,
};
use iroh_live::media::publish::LocalBroadcast;
use iroh_live::media::subscribe::RemoteBroadcast;
use iroh_live::media::traits::{AudioSource, VideoSource};

use freeq_av::{PcmFrame, TapBackend};

const VID_W: u32 = 320;
const VID_H: u32 = 240;

// ── Synthetic media sources ────────────────────────────────────────

/// A pure sine tone at `freq` Hz, mono 48 kHz — a distinguishable audio
/// fingerprint per agent (so a received WAV is obviously "from agent N").
struct ToneSource {
    freq: f32,
    phase: f32,
}
impl AudioSource for ToneSource {
    fn format(&self) -> AudioFormat {
        AudioFormat {
            sample_rate: 48_000,
            channel_count: 1,
        }
    }
    fn pop_samples(&mut self, buf: &mut [f32]) -> anyhow::Result<Option<usize>> {
        let step = std::f32::consts::TAU * self.freq / 48_000.0;
        for s in buf.iter_mut() {
            *s = 0.3 * self.phase.sin();
            self.phase += step;
            if self.phase > std::f32::consts::TAU {
                self.phase -= std::f32::consts::TAU;
            }
        }
        Ok(Some(buf.len()))
    }
}

/// A solid-colour BGRA frame source — a distinguishable visual fingerprint
/// per agent (a received BMP is obviously "from the blue agent", etc.).
struct ColorSource {
    bgra_pixel: [u8; 4],
    idx: u64,
}
impl VideoSource for ColorSource {
    fn name(&self) -> &str {
        "xtest-color"
    }
    fn format(&self) -> VideoFormat {
        VideoFormat {
            pixel_format: PixelFormat::Bgra,
            dimensions: [VID_W, VID_H],
        }
    }
    fn pop_frame(&mut self) -> anyhow::Result<Option<VideoFrame>> {
        let mut buf = vec![0u8; (VID_W * VID_H * 4) as usize];
        for px in buf.chunks_exact_mut(4) {
            px.copy_from_slice(&self.bgra_pixel);
        }
        let ts = Duration::from_micros(self.idx * 33_333); // ~30 fps
        self.idx += 1;
        Ok(Some(VideoFrame::new_packed(
            buf.into(),
            VID_W,
            VID_H,
            PixelFormat::Bgra,
            ts,
        )))
    }
    fn start(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    fn stop(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

// ── Results ─────────────────────────────────────────────────────────

#[derive(Default)]
struct Cell {
    audio_frames: u64,
    video_frames: u64,
    peak: f32,
}
type Matrix = Arc<Mutex<BTreeMap<(String, String), Cell>>>;

#[derive(Clone)]
struct Agent {
    label: String,     // e.g. "qbot0" (also the IRC nick when --channel is set)
    transport: String, // "QUIC" | "WS"
    url: String,
    instance: String, // per-agent broadcast instance suffix
    // Distinct fingerprints.
    freq: f32,
    bgra: [u8; 4],
}

struct Args {
    quic_url: String,
    ws_url: String,
    quic: usize,
    ws: usize,
    secs: u64,
    out: PathBuf,
    session: String,
    capture_only: bool,
    channel: Option<String>,
    irc_ws: String,
}

fn parse_args() -> Args {
    let a: Vec<String> = std::env::args().collect();
    let get = |k: &str| {
        a.iter()
            .position(|x| x == k)
            .and_then(|i| a.get(i + 1))
            .cloned()
    };
    Args {
        quic_url: get("--quic-url").unwrap_or_else(|| "https://irc.freeq.at:8080/av/moq".into()),
        ws_url: get("--ws-url").unwrap_or_else(|| "wss://irc.freeq.at/av/moq".into()),
        quic: get("--quic").and_then(|s| s.parse().ok()).unwrap_or(1),
        ws: get("--ws").and_then(|s| s.parse().ok()).unwrap_or(1),
        secs: get("--secs").and_then(|s| s.parse().ok()).unwrap_or(12),
        out: get("--out")
            .map(PathBuf::from)
            .unwrap_or_else(|| "/tmp/freeq-av-e2e".into()),
        session: get("--session").unwrap_or_else(|| format!("xtest-{}", std::process::id())),
        capture_only: a.iter().any(|x| x == "--capture-only"),
        channel: get("--channel"),
        irc_ws: get("--irc-ws").unwrap_or_else(|| "wss://irc.freeq.at/irc".into()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("warn".parse()?),
        )
        .init();

    let args = parse_args();
    std::fs::create_dir_all(&args.out).ok();

    // Distinct fingerprints per agent. Hues chosen to be obviously different.
    let palette: [[u8; 4]; 6] = [
        [40, 40, 220, 255],  // red    (BGRA)
        [40, 200, 40, 255],  // green
        [220, 120, 40, 255], // blue
        [40, 200, 220, 255], // yellow
        [200, 60, 200, 255], // magenta
        [220, 200, 40, 255], // cyan
    ];

    let pid = std::process::id() & 0xffff;
    let mut agents: Vec<Agent> = Vec::new();
    let mut n = 0usize;
    for i in 0..args.quic {
        agents.push(Agent {
            label: format!("qbot{i}"),
            transport: "QUIC".into(),
            url: args.quic_url.clone(),
            instance: format!("{pid:04x}{n}"),
            freq: 330.0 + 70.0 * n as f32,
            bgra: palette[n % palette.len()],
        });
        n += 1;
    }
    for i in 0..args.ws {
        agents.push(Agent {
            label: format!("wbot{i}"),
            transport: "WS".into(),
            url: args.ws_url.clone(),
            instance: format!("{pid:04x}{n}"),
            freq: 330.0 + 70.0 * n as f32,
            bgra: palette[n % palette.len()],
        });
        n += 1;
    }

    println!("\n=== freeq AV cross-transport interop ===");
    println!("  session prefix : {}", args.session);
    println!("  QUIC url       : {}", args.quic_url);
    println!("  WS url         : {}", args.ws_url);
    println!("  agents         : {} QUIC + {} WS", args.quic, args.ws);
    println!("  duration       : {}s", args.secs);
    println!("  artifacts      : {}\n", args.out.display());
    for ag in &agents {
        println!(
            "  {:7} [{}]  tone={:.0}Hz  colorBGRA={:?}",
            ag.label, ag.transport, ag.freq, ag.bgra
        );
    }
    println!();

    let matrix: Matrix = Arc::new(Mutex::new(BTreeMap::new()));
    let mut tasks = tokio::task::JoinSet::new();
    let all_labels: Vec<String> = agents.iter().map(|a| a.label.clone()).collect();

    let _ = &all_labels;
    for ag in agents.clone() {
        let session = args.session.clone();
        let out = args.out.clone();
        let matrix = matrix.clone();
        let capture_only = args.capture_only;
        let channel = args.channel.clone();
        let irc_ws = args.irc_ws.clone();
        tasks.spawn(async move {
            if let Err(e) = run_agent(
                ag.clone(),
                session,
                out,
                matrix,
                capture_only,
                channel,
                irc_ws,
            )
            .await
            {
                eprintln!("  [{}] agent error: {e:#}", ag.label);
            }
        });
    }

    tokio::time::sleep(Duration::from_secs(args.secs)).await;
    tasks.abort_all();
    // Let in-flight artifact writes settle.
    tokio::time::sleep(Duration::from_millis(300)).await;

    if args.capture_only {
        print_capture_report(&matrix);
    } else {
        print_matrix(&agents, &matrix);
    }
    Ok(())
}

/// Capture-only report: per (observer, real peer) what was decoded. The peers
/// are real clients we discovered, not agents we spawned.
fn print_capture_report(matrix: &Matrix) {
    let g = matrix.lock().unwrap();
    println!("\n=== capture report (observer  <==  real peer) ===\n");
    if g.is_empty() {
        println!("  NOTHING captured — no peer broadcasts seen in this session.");
        println!("  (Is anyone actually publishing? Did they av-join THIS session id?)\n");
        return;
    }
    for ((obs, peer), c) in g.iter() {
        println!(
            "  {obs:>8}  <==  {peer:<28}  audio_frames={:<5} video_frames={:<5} peak={:.3}",
            c.audio_frames, c.video_frames, c.peak
        );
    }
    let any_audio = g.values().any(|c| c.audio_frames > 0);
    let any_video = g.values().any(|c| c.video_frames > 0);
    println!(
        "\n  observers heard real audio: {}   saw real video: {}",
        if any_audio { "YES" } else { "no" },
        if any_video { "YES" } else { "no" },
    );
    println!("  artifacts (real clients' decoded media) written to --out dir\n");
}

/// One agent: publish our own tone+colour broadcast, then subscribe to every
/// other agent and record what we decode.
#[allow(clippy::too_many_arguments)]
async fn run_agent(
    me: Agent,
    session: String,
    out: PathBuf,
    matrix: Matrix,
    capture_only: bool,
    channel: Option<String>,
    irc_ws: String,
) -> Result<()> {
    // When --channel is set, register over IRC and av-join the session so the
    // agent appears in the server's REST roster — which is what the WEB client
    // subscribes from. Without this the agent's broadcast is in the SFU but
    // invisible to web (web only renders roster participants). The broadcast
    // path then MUST be {session}/{nick}~{instance} to match the roster entry.
    let our_path = if capture_only {
        String::new()
    } else if channel.is_some() {
        format!("{session}/{}~{}", me.label, me.instance)
    } else {
        format!("{session}/{}", me.label)
    };

    if let (false, Some(chan)) = (capture_only, channel.as_deref()) {
        if let Err(e) = irc_av_join(&irc_ws, chan, &session, &me.label, &me.instance).await {
            eprintln!(
                "  [{}] av-join failed (will still publish to SFU): {e:#}",
                me.label
            );
        }
    }

    let pub_origin = moq_lite::Origin::produce();
    // In capture-only mode the agent publishes NOTHING — it's a silent
    // observer that only subscribes (so it can join a real human call and
    // record what's there without injecting test tones into it).
    let _broadcast = if capture_only {
        None
    } else {
        let broadcast = LocalBroadcast::new();
        broadcast
            .audio()
            .set(
                ToneSource {
                    freq: me.freq,
                    phase: 0.0,
                },
                AudioCodec::Opus,
                [AudioPreset::Hq],
            )
            .map_err(|e| anyhow::anyhow!("audio set: {e}"))?;
        broadcast
            .video()
            .set_source(
                ColorSource {
                    bgra_pixel: me.bgra,
                    idx: 0,
                },
                VideoCodec::H264,
                [VideoPreset::P360],
            )
            .map_err(|e| anyhow::anyhow!("video set: {e}"))?;
        pub_origin.publish_broadcast(our_path.as_str(), broadcast.consume());
        Some(broadcast)
    };

    let sub_origin = moq_lite::Origin::produce();
    let mut sub_consumer = sub_origin.consume();

    let mut cfg = moq_native::ClientConfig::default();
    cfg.tls.disable_verify = Some(true);
    cfg.backend = Some(moq_native::QuicBackend::Noq);
    let client = cfg.init()?;

    let _session = client
        .with_publish(pub_origin.consume())
        .with_consume(sub_origin)
        .connect(me.url.parse().context("parse sfu url")?)
        .await
        .context("MoQ connect")?;

    let prefix = format!("{session}/");
    let mut taps: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    while let Some((path, announce)) = sub_consumer.announced().await {
        let path = path.to_string();
        if announce.is_none() {
            continue;
        }
        if path == our_path || !path.starts_with(&prefix) || !seen.insert(path.clone()) {
            continue;
        }
        // Full last segment ({nick}~{instance}) so two devices on one DID
        // (e.g. web + iOS both "chadfowler.com") are distinguished.
        let peer_label = path.rsplit('/').next().unwrap_or(&path).to_string();
        let consumer = announce.unwrap();
        let (me_label, out, matrix) = (me.label.clone(), out.clone(), matrix.clone());
        taps.spawn(async move {
            tap_peer(me_label, peer_label, path, consumer, out, matrix).await;
        });
    }
    Ok(())
}

/// Subscribe to one peer's audio + video, decode, record counts/peak, and dump
/// a WAV (first ~1s of audio) + a BMP (first decoded frame).
async fn tap_peer(
    me: String,
    peer: String,
    path: String,
    consumer: moq_lite::BroadcastConsumer,
    out: PathBuf,
    matrix: Matrix,
) {
    let remote = match RemoteBroadcast::new(&path, consumer).await {
        Ok(r) => r,
        Err(_) => return,
    };
    let key = (me.clone(), peer.clone());
    matrix.lock().unwrap().entry(key.clone()).or_default();

    // ── audio ──
    {
        let (backend, mut audio_rx) = TapBackend::channel();
        if let Ok(_track) = remote.audio_ready(&backend).await {
            let matrix = matrix.clone();
            let key = key.clone();
            let out = out.clone();
            let (me, peer) = (me.clone(), peer.clone());
            tokio::spawn(async move {
                let _track = _track; // hold the subscription open
                let mut wav: Vec<f32> = Vec::new();
                while let Some(PcmFrame { samples, format }) = audio_rx.recv().await {
                    let rate = format.sample_rate;
                    let peak = samples.iter().fold(0f32, |m, s| m.max(s.abs()));
                    {
                        let mut g = matrix.lock().unwrap();
                        let c = g.entry(key.clone()).or_default();
                        c.audio_frames += 1;
                        c.peak = c.peak.max(peak);
                    }
                    if wav.len() < rate as usize {
                        wav.extend_from_slice(&samples);
                    }
                    if wav.len() >= rate as usize {
                        let p = out.join(format!("{me}__from__{peer}.wav"));
                        let _ = write_wav(&p, &wav, rate);
                        wav.clear();
                        wav.push(f32::NAN); // sentinel: already written
                    }
                }
            });
        }
    }

    // ── video ──
    if let Ok(mut vtrack) = remote.video_ready().await {
        let mut wrote_img = false;
        while let Some(frame) = vtrack.next_frame().await {
            {
                let mut g = matrix.lock().unwrap();
                g.entry(key.clone()).or_default().video_frames += 1;
            }
            if !wrote_img {
                let rgba = frame.rgba_image();
                let p = out.join(format!("{me}__from__{peer}.bmp"));
                let _ = write_bmp(&p, rgba.as_raw(), frame.width(), frame.height());
                wrote_img = true;
            }
        }
    }
}

// ── Reporting ───────────────────────────────────────────────────────

fn print_matrix(agents: &[Agent], matrix: &Matrix) {
    let g = matrix.lock().unwrap();
    let labels: Vec<&Agent> = agents.iter().collect();

    println!("\n=== reachability matrix (rows hear/see cols) ===");
    println!("  cell = A(udio) / V(ideo); '.' = nothing received\n");
    print!("{:>10} |", "subv \\ pub");
    for c in &labels {
        print!(" {:>8}", c.label);
    }
    println!();
    print!("{:->10}-+", "");
    for _ in &labels {
        print!("{:->9}", "");
    }
    println!();

    let mut cross_pairs = 0;
    let mut cross_ok_audio = 0;
    let mut cross_ok_video = 0;
    for r in &labels {
        print!("{:>10} |", r.label);
        for c in &labels {
            if r.label == c.label {
                print!("{:>9}", "self");
                continue;
            }
            let cell = g.get(&(r.label.clone(), c.label.clone()));
            let (a, v) = cell
                .map(|x| (x.audio_frames, x.video_frames))
                .unwrap_or((0, 0));
            let tag = format!(
                "{}{}",
                if a > 0 { "A" } else { "." },
                if v > 0 { "V" } else { "." }
            );
            print!("{:>9}", tag);
            if r.transport != c.transport {
                cross_pairs += 1;
                if a > 0 {
                    cross_ok_audio += 1;
                }
                if v > 0 {
                    cross_ok_video += 1;
                }
            }
        }
        println!();
    }

    println!("\n=== cross-transport (QUIC <-> WS) summary ===");
    println!("  ordered cross pairs : {cross_pairs}");
    println!("  with audio          : {cross_ok_audio}/{cross_pairs}");
    println!("  with video          : {cross_ok_video}/{cross_pairs}");
    let pass = cross_pairs > 0 && cross_ok_audio == cross_pairs;
    println!(
        "\n  RESULT: {}  (audio across every QUIC<->WS pair{})",
        if pass { "PASS" } else { "FAIL" },
        if cross_ok_video == cross_pairs {
            " + video"
        } else {
            "; video incomplete"
        },
    );
    if !pass {
        println!(
            "  → A FAIL with a clean QUIC-block / WS-block split means the SFU is\n     \
             rooting the two transports in different namespaces (av_sfu.rs)."
        );
    }
    println!("\n  artifacts (open to verify sound/images): see the --out dir\n");
}

// ── IRC av-join (so an agent shows up in the server's REST roster) ──

/// Register a guest over IRC-over-WebSocket, JOIN the channel, and send the
/// `av-join` TAGMSG with this agent's instance suffix — making it a real
/// roster participant the web client will subscribe to. Holds the IRC
/// connection open in a background task (the server marks a participant left
/// when its connection drops), responding to PINGs, until the process exits.
async fn irc_av_join(
    irc_ws: &str,
    channel: &str,
    session: &str,
    nick: &str,
    instance: &str,
) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio::time::timeout;
    use tokio_tungstenite::tungstenite::Message;

    let (ws, _) = tokio_tungstenite::connect_async(irc_ws)
        .await
        .context("IRC ws connect")?;
    let (mut w, mut r) = ws.split();
    w.send(Message::Text(
        format!("NICK {nick}\r\nUSER {nick} 0 * :av-e2e\r\n").into(),
    ))
    .await?;

    // Read until registration (numeric 001), answering PINGs.
    timeout(Duration::from_secs(10), async {
        while let Some(msg) = r.next().await {
            if let Ok(Message::Text(t)) = msg {
                for line in t.lines() {
                    let line = line.trim();
                    if line.starts_with("PING") {
                        let _ = w
                            .send(Message::Text(
                                format!("{}\r\n", line.replacen("PING", "PONG", 1)).into(),
                            ))
                            .await;
                    }
                    if line.contains(" 001 ") {
                        return Ok::<(), anyhow::Error>(());
                    }
                }
            }
        }
        anyhow::bail!("connection closed before registration")
    })
    .await
    .context("IRC registration timed out")??;

    w.send(Message::Text(
        format!("CAP REQ :message-tags\r\nJOIN {channel}\r\n").into(),
    ))
    .await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    w.send(Message::Text(
        format!(
            "@+freeq.at/av-join;+freeq.at/av-id={session};+freeq.at/av-instance={instance} TAGMSG {channel}\r\n"
        )
        .into(),
    ))
    .await?;

    // Keep the connection alive for the call's lifetime (PING every 20s,
    // answer server PINGs). Dies when the process exits → server reaps the
    // participant cleanly.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(20));
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if w.send(Message::Text("PING :keep\r\n".into())).await.is_err() {
                        break;
                    }
                }
                msg = r.next() => match msg {
                    Some(Ok(Message::Text(t))) => {
                        for line in t.lines() {
                            if line.starts_with("PING") {
                                let _ = w.send(Message::Text(
                                    format!("{}\r\n", line.trim().replacen("PING", "PONG", 1)).into(),
                                )).await;
                            }
                        }
                    }
                    Some(Ok(_)) => {}
                    _ => break,
                }
            }
        }
    });
    Ok(())
}

// ── Minimal artifact writers (no extra deps) ────────────────────────

/// Mono 16-bit PCM WAV.
fn write_wav(path: &PathBuf, samples: &[f32], rate: u32) -> std::io::Result<()> {
    let usable: Vec<&f32> = samples.iter().filter(|s| s.is_finite()).collect();
    let data_len = (usable.len() * 2) as u32;
    let mut b: Vec<u8> = Vec::with_capacity(44 + data_len as usize);
    b.extend_from_slice(b"RIFF");
    b.extend_from_slice(&(36 + data_len).to_le_bytes());
    b.extend_from_slice(b"WAVE");
    b.extend_from_slice(b"fmt ");
    b.extend_from_slice(&16u32.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes()); // PCM
    b.extend_from_slice(&1u16.to_le_bytes()); // mono
    b.extend_from_slice(&rate.to_le_bytes());
    b.extend_from_slice(&(rate * 2).to_le_bytes()); // byte rate
    b.extend_from_slice(&2u16.to_le_bytes()); // block align
    b.extend_from_slice(&16u16.to_le_bytes()); // bits
    b.extend_from_slice(b"data");
    b.extend_from_slice(&data_len.to_le_bytes());
    for s in usable {
        let v = (s.clamp(-1.0, 1.0) * 32767.0) as i16;
        b.extend_from_slice(&v.to_le_bytes());
    }
    std::fs::write(path, b)
}

/// 24-bit uncompressed BMP from RGBA pixels (opens in Preview / any viewer).
fn write_bmp(path: &PathBuf, rgba: &[u8], w: u32, h: u32) -> std::io::Result<()> {
    let (w, h) = (w as usize, h as usize);
    if rgba.len() < w * h * 4 {
        return Ok(());
    }
    let row_pad = (4 - (w * 3) % 4) % 4;
    let row_size = w * 3 + row_pad;
    let img_size = row_size * h;
    let file_size = 54 + img_size;
    let mut b: Vec<u8> = Vec::with_capacity(file_size);
    b.extend_from_slice(b"BM");
    b.extend_from_slice(&(file_size as u32).to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&54u32.to_le_bytes());
    b.extend_from_slice(&40u32.to_le_bytes()); // DIB header size
    b.extend_from_slice(&(w as i32).to_le_bytes());
    b.extend_from_slice(&(h as i32).to_le_bytes()); // positive => bottom-up
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&24u16.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
    b.extend_from_slice(&(img_size as u32).to_le_bytes());
    b.extend_from_slice(&2835u32.to_le_bytes());
    b.extend_from_slice(&2835u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    for y in (0..h).rev() {
        for x in 0..w {
            let i = (y * w + x) * 4;
            // RGBA -> BGR
            b.push(rgba[i + 2]);
            b.push(rgba[i + 1]);
            b.push(rgba[i]);
        }
        for _ in 0..row_pad {
            b.push(0);
        }
    }
    std::fs::write(path, b)
}
