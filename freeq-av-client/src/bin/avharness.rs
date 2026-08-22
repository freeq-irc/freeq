//! L2 — the tone mesh, through the full stack (`docs/AV-MAP.md` §7).
//!
//! N agents join one call the way a real client joins it — IRC connect, JOIN,
//! `av-start`/`av-join`, wait for `+freeq.at/av-token`, dial the SFU at
//! `?jwt=…&inst=…` — and each publishes a distinct sine. Every agent then
//! Goertzel-detects every other agent's tone. That matrix is invariant I1
//! ("X hears Y") as a number, and it is the only thing in this repo that
//! measures it end to end.
//!
//! The difference from `examples/av_cross_transport_e2e.rs`, which this reuses
//! the tone/Opus/decode machinery from, is the whole point: that harness talks
//! only to the relay, so it is blind to classes A and B — every failure that
//! lives in the session layer between IRC and the SFU. This one goes through
//! the session layer, so a roster that disagrees with the announcements, or a
//! call that split into two ids, shows up as a hole in the matrix.
//!
//! Then it breaks things (`--chaos`) and re-asserts the matrix after each:
//! a blipped IRC socket, a killed media socket, a server restart, a start
//! collision, and instance churn. Exit code is the verdict; a failure names
//! the pair, the direction, and the invariant.
//!
//! The harness owns the server process, because `restart` cannot be honest
//! otherwise. `scripts/avharness.sh` builds it and hands over the path.
//!
//!   cargo run -p freeq-av-client --bin avharness -- \
//!       --server-bin target/release/freeq-server --data-dir /tmp/avh --chaos

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use parking_lot::Mutex;
use tokio::time::Instant;

use freeq_sdk::auth::{ChallengeSigner, KeySigner};
use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::event::Event;

use iroh_live::media::codec::AudioCodec;
use iroh_live::media::format::{AudioFormat, AudioPreset};
use iroh_live::media::publish::LocalBroadcast;
use iroh_live::media::subscribe::RemoteBroadcast;
use iroh_live::media::traits::AudioSource;

use freeq_av::{PcmFrame, TapBackend};

// ── detection constants ─────────────────────────────────────────────

/// Samples of received audio kept per pair. Half a second at 48 kHz — a 2 Hz
/// bin, which is ample separation for tones 440 Hz apart, and short enough
/// that "went silent 5 s ago" doesn't linger in the window.
const WINDOW: usize = 24_000;

/// A pair counts as live only if audio arrived this recently. This, not the
/// window's contents, is what catches a peer that stopped publishing.
const FRESH: Duration = Duration::from_millis(2500);

/// Normalized Goertzel score above which we call the tone present.
///
/// Measured, not guessed: on a healthy 4-agent mesh the worst *matched* score
/// is ~0.44 and the best *mismatched* score is ~0.001 — three orders of
/// magnitude apart, because Opus at HQ doesn't move a pure sine's bin and
/// nothing else in the stream is near it. (Matched scores land near 0.44
/// rather than 1.0 because the median is taken over 40 ms blocks of a lossy
/// codec's output, not because detection is marginal.) This sits ~3× below
/// the worst true positive and ~150× above the best false one; every run
/// prints both populations so the margin stays answerable.
const TONE_SCORE: f64 = 0.15;

/// Absolute floor, so a decoder emitting near-silence can't score well on
/// numerical noise.
const RMS_FLOOR: f64 = 0.01;

// ── args ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Transport {
    Quic,
    Ws,
}

impl Transport {
    fn label(self) -> &'static str {
        match self {
            Transport::Quic => "QUIC",
            Transport::Ws => "WS",
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(name = "avharness", about = "L2 tone-mesh harness for freeq AV")]
struct Args {
    /// The `freeq-server` binary to run. MUST be built with
    /// `--features av-native`; a plain build has no SFU and every agent will
    /// fail to dial (which is failure class E1, and worth catching here too).
    #[arg(long, default_value = "target/release/freeq-server")]
    server_bin: PathBuf,

    /// Server data directory. Reused across the restart step, so it must
    /// survive the process it belongs to.
    #[arg(long)]
    data_dir: PathBuf,

    #[arg(long, default_value_t = 0)]
    irc_port: u16,

    #[arg(long, default_value_t = 0)]
    web_port: u16,

    #[arg(long, default_value_t = 4)]
    agents: usize,

    /// How long to let the mesh settle before the first matrix.
    #[arg(long, default_value_t = 8)]
    settle_secs: u64,

    /// Budget for the mesh to come back after the server restart.
    #[arg(long, default_value_t = 30)]
    recover_secs: u64,

    /// The server's AV disconnect grace. The blip step reads this to know
    /// which side of the boundary it's asserting on.
    #[arg(long, default_value_t = 6)]
    grace_secs: u64,

    #[arg(long, default_value = "#avharness")]
    channel: String,

    /// `quic`, `ws`, or `mixed` (alternating — which also exercises the
    /// QUIC↔WS namespace unification under the real lifecycle).
    #[arg(long, default_value = "mixed")]
    transport: String,

    /// Run the chaos steps after the baseline matrix.
    #[arg(long)]
    chaos: bool,

    /// Subset of chaos steps, comma-separated. Default: all of them.
    #[arg(long, default_value = "blip,media-kill,restart,collide,churn")]
    chaos_steps: String,

    /// Treat a QUIC-dialed agent's media surviving its roster teardown as a
    /// failure rather than a reported finding. Off by default because the
    /// server does not implement it yet — see the FINDINGS section this
    /// harness prints.
    #[arg(long)]
    strict_quic_revocation: bool,

    /// Run the server with `FREEQ_AV_REQUIRE_TOKEN=1`. This is the enforcement
    /// mode the token flip (E2 / test-plan §5.11) will turn on in production:
    /// every SFU connection must carry a valid `?jwt=`. A green run here is
    /// what F7's join→token→dial ordering was built to make possible.
    #[arg(long)]
    require_token: bool,

    /// DELIBERATE BREAKAGE, for verifying the harness itself: dial the SFU
    /// with no `?jwt=`. Against a `--require-token` server every agent is
    /// refused and the matrix must collapse. If this combination ever passes,
    /// the harness is measuring nothing and should not be trusted as a gate.
    #[arg(long)]
    break_token: bool,
}

// ── the tone ────────────────────────────────────────────────────────

/// A pure sine at `freq` Hz — one agent's audible fingerprint.
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

/// One block's worth of Goertzel, normalized so a pure matching tone scores
/// ~1.0 and anything off-bin ~0.
fn block_score(samples: &[f32], freq: f64, rate: f64) -> f64 {
    let n = samples.len();
    if n < 256 {
        return 0.0;
    }
    let k = (0.5 + (n as f64 * freq) / rate).floor();
    let w = std::f64::consts::TAU * k / n as f64;
    let coeff = 2.0 * w.cos();
    let (mut s1, mut s2) = (0.0f64, 0.0f64);
    let mut energy = 0.0f64;
    for &x in samples {
        let x = x as f64;
        energy += x * x;
        let s0 = x + coeff * s1 - s2;
        s2 = s1;
        s1 = s0;
    }
    let power = s1 * s1 + s2 * s2 - coeff * s1 * s2;
    let mean_square = energy / n as f64;
    if mean_square <= 0.0 {
        return 0.0;
    }
    // (N·A/2)² for a matching tone; mean_square is A²/2 — so this ratio is
    // ~1.0 on a match and collapses off-bin.
    let rel = power / ((n * n) as f64 / 4.0);
    (rel / (2.0 * mean_square)).min(1.5)
}

/// Median per-block score at `freq`. Blocks rather than one long transform,
/// because the decoder tap drops frames under backpressure (`TapBackend` uses
/// `try_send` on purpose — skipping a frame beats wedging the decoder). Every
/// dropped frame is a phase discontinuity, and a coherent transform across
/// half a second of those scores near zero on a tone that is plainly there.
/// Within a 40 ms block the tone is coherent; the median over ~12 blocks
/// shrugs off the odd bad one. Bin width at this size is 25 Hz, which
/// separates 440 Hz-spaced tones with room to spare.
fn tone_score(samples: &[f32], freq: f64, rate: f64) -> f64 {
    const BLOCK: usize = 1920;
    let mut scores: Vec<f64> = samples
        .as_chunks::<BLOCK>()
        .0
        .iter()
        .map(|b| block_score(b, freq, rate))
        .collect();
    if scores.is_empty() {
        return block_score(samples, freq, rate);
    }
    scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    scores[scores.len() / 2]
}

fn rms(samples: &[f32]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum: f64 = samples.iter().map(|s| (*s as f64) * (*s as f64)).sum();
    (sum / samples.len() as f64).sqrt()
}

// ── the matrix ──────────────────────────────────────────────────────

#[derive(Default)]
struct Cell {
    /// Most recent decoded samples, de-interleaved to channel 0 and capped at
    /// [`WINDOW`].
    pcm: Vec<f32>,
    rate: u32,
    /// The layout the decoder negotiated. Recorded rather than assumed: if it
    /// ever stops being mono the analysis above has to know, and a silent
    /// wrong assumption here reads exactly like "X can't hear Y".
    channels: u32,
    frames: u64,
    last: Option<Instant>,
}

/// (subscriber instance, publisher instance) → what the subscriber decoded.
/// Keyed on instance because that is the identity the whole AV system agrees
/// on: nicks change mid-call and DIDs are shared across devices.
type Matrix = Arc<Mutex<BTreeMap<(String, String), Cell>>>;

struct Verdict {
    heard: bool,
    score: f64,
    rms: f64,
    fresh: bool,
    frames: u64,
    rate: u32,
    channels: u32,
}

fn verdict(matrix: &Matrix, sub: &str, publisher: &str, freq: f64) -> Verdict {
    let g = matrix.lock();
    let Some(c) = g.get(&(sub.to_string(), publisher.to_string())) else {
        return Verdict {
            heard: false,
            score: 0.0,
            rms: 0.0,
            fresh: false,
            frames: 0,
            rate: 0,
            channels: 0,
        };
    };
    let fresh = c.last.is_some_and(|t| t.elapsed() < FRESH);
    let score = tone_score(&c.pcm, freq, c.rate.max(1) as f64);
    let r = rms(&c.pcm);
    Verdict {
        heard: fresh && score >= TONE_SCORE && r >= RMS_FLOOR,
        score,
        rms: r,
        fresh,
        frames: c.frames,
        rate: c.rate,
        channels: c.channels,
    }
}

// ── agents ──────────────────────────────────────────────────────────

/// What an agent's IRC stream has told us. A background pump keeps it current
/// so the driving code can ask questions instead of racing the event order.
#[derive(Default)]
struct Observed {
    /// Session ids seen in `av-state=started`/`joined` broadcasts.
    states: Vec<(String, String)>,
    /// (session id, token) from `+freeq.at/av-token`.
    tokens: Vec<(String, String)>,
    /// (code, session id) from `+freeq.at/av-error`.
    errors: Vec<(String, String)>,
    /// Instances named by `av-state=left`.
    left: Vec<String>,
    connected: bool,
}

impl Observed {
    fn token_for(&self, sid: &str) -> Option<String> {
        self.tokens
            .iter()
            .find(|(s, _)| s == sid)
            .map(|(_, t)| t.clone())
    }
    fn state_id(&self, action: &str) -> Option<String> {
        self.states
            .iter()
            .find(|(a, _)| a == action)
            .map(|(_, s)| s.clone())
    }
}

/// Media side of one agent: the live MoQ session plus everything that dies
/// with it. Dropping this is what `media-kill` does.
struct Media {
    /// Held only to keep the session and publisher alive.
    _session: Box<dyn std::any::Any + Send>,
    _broadcast: LocalBroadcast,
    tasks: tokio::task::JoinSet<()>,
}

impl Media {
    fn kill(mut self) {
        self.tasks.abort_all();
        // `_session` and `_broadcast` drop here: the transport closes and the
        // relay unannounces this agent's broadcast.
    }
}

struct Agent {
    idx: usize,
    nick: String,
    did: String,
    secret: Vec<u8>,
    freq: f64,
    transport: Transport,
    /// Fresh per (re)join — a client that rejoins under a new instance is a
    /// different participant to everyone else, which is what churn tests.
    inst: String,
    blip: Blip,
    handle: Option<ClientHandle>,
    observed: Arc<Mutex<Observed>>,
    media: Option<Media>,
}

impl Agent {
    fn path(&self, sid: &str) -> String {
        format!("{sid}/{}~{}", self.nick, self.inst)
    }
}

fn new_instance(idx: usize, epoch: usize) -> String {
    format!(
        "{:04x}{:02x}{:02x}",
        std::process::id() & 0xffff,
        idx,
        epoch
    )
}

// ── the blip (a socket that vanishes) ───────────────────────────────

/// Per-agent loopback relay so any single agent's IRC connection can be cut
/// without a QUIT. A QUIT ends the call immediately and would test nothing:
/// the scenario is a network that goes away and comes back.
struct Blip {
    addr: std::net::SocketAddr,
    cut: Arc<tokio::sync::Notify>,
}

impl Blip {
    async fn to(upstream: std::net::SocketAddr) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let cut = Arc::new(tokio::sync::Notify::new());
        let cut_loop = cut.clone();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let Ok(mut server) = tokio::net::TcpStream::connect(upstream).await else {
                    break;
                };
                let cut = cut_loop.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut client, &mut server) => {}
                        _ = cut.notified() => {}
                    }
                });
            }
        });
        Ok(Blip { addr, cut })
    }

    fn cut(&self) {
        self.cut.notify_waiters();
    }
}

// ── the server under test ───────────────────────────────────────────

struct Server {
    bin: PathBuf,
    args: Vec<String>,
    child: Child,
    log: PathBuf,
    require_token: bool,
    irc: std::net::SocketAddr,
    web: std::net::SocketAddr,
}

impl Server {
    /// The server's own logs go to a file, not to our stderr. A launch gate is
    /// something a person reads: a matrix interleaved with a few thousand
    /// relay log lines is a matrix nobody checks. The path is printed at
    /// startup and the log is what you reach for when a cell goes ✗.
    fn spawn_child(
        bin: &PathBuf,
        args: &[String],
        log: &std::path::Path,
        require_token: bool,
    ) -> Result<Child> {
        let out = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .with_context(|| format!("open {}", log.display()))?;
        let err = out.try_clone()?;
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .env("RUST_LOG", "freeq_server=info")
            .env(
                "FREEQ_AV_REQUIRE_TOKEN",
                if require_token { "1" } else { "0" },
            )
            .stdout(out)
            .stderr(err);
        cmd.spawn()
            .with_context(|| format!("spawn {}", bin.display()))
    }

    async fn start(args: &Args, dids: &[(String, String)]) -> Result<Self> {
        let irc_port = if args.irc_port == 0 {
            alloc_port()?
        } else {
            args.irc_port
        };
        let web_port = if args.web_port == 0 {
            alloc_port()?
        } else {
            args.web_port
        };
        let irc = format!("127.0.0.1:{irc_port}");
        let web = format!("127.0.0.1:{web_port}");
        let statics = dids
            .iter()
            .map(|(d, k)| format!("{d}={k}"))
            .collect::<Vec<_>>()
            .join(",");

        std::fs::create_dir_all(&args.data_dir).ok();
        let db = args.data_dir.join("avharness.db");
        // `--iroh` is not optional here even though nothing federates: the SFU
        // is initialized inside the iroh-endpoint branch of `Server::run`, so
        // a server started without it reports `av:false` and has no relay at
        // all. Production always passes it, which is why the coupling has gone
        // unnoticed. Fixed iroh port so the restart step rebinds the same one.
        let argv: Vec<String> = vec![
            "--listen-addr".into(),
            irc.clone(),
            "--web-addr".into(),
            web.clone(),
            "--iroh".into(),
            "--iroh-port".into(),
            alloc_port()?.to_string(),
            "--data-dir".into(),
            args.data_dir.to_string_lossy().into_owned(),
            "--db-path".into(),
            db.to_string_lossy().into_owned(),
            "--av-grace-secs".into(),
            args.grace_secs.to_string(),
            "--did-resolver-static".into(),
            statics,
            "--server-name".into(),
            "avharness".into(),
        ];

        let log = args.data_dir.join("server.log");
        let child = Self::spawn_child(&args.server_bin, &argv, &log, args.require_token)?;
        let server = Server {
            bin: args.server_bin.clone(),
            args: argv,
            child,
            log,
            require_token: args.require_token,
            irc: irc.parse()?,
            web: web.parse()?,
        };
        wait_port(server.irc).await?;
        wait_port(server.web).await?;
        server.require_av().await?;
        Ok(server)
    }

    /// The E1 gate, before anything else can waste its time: a server without
    /// `av-native` answers 503 on every AV route and no agent will ever dial.
    /// `deploy.sh` checks the same field for the same reason.
    async fn require_av(&self) -> Result<()> {
        let body: serde_json::Value = reqwest::get(format!("http://{}/api/v1/health", self.web))
            .await
            .context("health check")?
            .json()
            .await
            .context("health json")?;
        if body["av"] != serde_json::json!(true) {
            bail!(
                "server reports av={} — build it with `--features av-native` \
                 (a plain cargo build has no SFU; this is failure class E1)",
                body["av"]
            );
        }
        Ok(())
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    async fn restart(&mut self) -> Result<()> {
        self.kill();
        self.child = Self::spawn_child(&self.bin, &self.args, &self.log, self.require_token)?;
        wait_port(self.irc).await?;
        wait_port(self.web).await?;
        self.require_av().await
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.kill();
    }
}

fn alloc_port() -> Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

async fn wait_port(addr: std::net::SocketAddr) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if std::net::TcpStream::connect(addr).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("{addr} never came up");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ── the harness ─────────────────────────────────────────────────────

struct Harness {
    args: Args,
    server: Server,
    agents: Vec<Agent>,
    matrix: Matrix,
    session: String,
    /// Things the run noticed that aren't pass/fail verdicts — an unaudited
    /// behavior pinned down, a gap the server hasn't closed. Printed at the
    /// end whether or not the run passes, because "it went green" is not the
    /// only useful output a harness has.
    findings: Vec<String>,
    /// Which chaos steps failed, by name.
    failures: Vec<String>,
}

impl Harness {
    // ── IRC ─────────────────────────────────────────────────────────

    /// Connect an agent's IRC session through its own blip relay, register by
    /// DID (grace is only extended to authenticated users, so a guest agent
    /// could not exercise the blip window at all), and start the event pump.
    async fn connect_irc(&mut self, i: usize) -> Result<()> {
        let (nick, did, secret, addr) = {
            let a = &self.agents[i];
            (a.nick.clone(), a.did.clone(), a.secret.clone(), a.blip.addr)
        };
        let key = PrivateKey::ed25519_from_bytes(&secret).map_err(|e| anyhow::anyhow!("{e}"))?;
        let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(did, key));
        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: nick.clone(),
            user: nick.clone(),
            realname: "avharness agent".into(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, Some(signer));

        let observed = self.agents[i].observed.clone();
        {
            let mut o = observed.lock();
            *o = Observed::default();
        }
        let obs = observed.clone();
        tokio::spawn(async move {
            while let Some(e) = events.recv().await {
                let mut o = obs.lock();
                match e {
                    Event::Registered { .. } => o.connected = true,
                    Event::TagMsg { ref tags, .. } => {
                        if let (Some(st), Some(id)) =
                            (tags.get("+freeq.at/av-state"), tags.get("+freeq.at/av-id"))
                        {
                            o.states.insert(0, (st.clone(), id.clone()));
                            if st == "left"
                                && let Some(inst) = tags.get("+freeq.at/av-instance")
                            {
                                o.left.push(inst.clone());
                            }
                        }
                        if let (Some(tok), Some(id)) =
                            (tags.get("+freeq.at/av-token"), tags.get("+freeq.at/av-id"))
                        {
                            o.tokens.insert(0, (id.clone(), tok.clone()));
                        }
                        if let Some(code) = tags.get("+freeq.at/av-error") {
                            let id = tags.get("+freeq.at/av-id").cloned().unwrap_or_default();
                            o.errors.push((code.clone(), id));
                        }
                    }
                    Event::Disconnected { .. } => o.connected = false,
                    _ => {}
                }
            }
        });

        // Registration.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !observed.lock().connected {
            if Instant::now() >= deadline {
                bail!("{nick}: never registered");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        handle.join(&self.args.channel).await?;
        tokio::time::sleep(Duration::from_millis(250)).await;
        self.agents[i].handle = Some(handle);
        Ok(())
    }

    /// The full join: `av-start` or `av-join` over IRC, wait for the token
    /// that grants SFU access, then dial with it. Never the SFU shortcut —
    /// going straight to the relay is what makes the existing e2e blind to
    /// every session-layer failure.
    async fn join_call(&mut self, i: usize, start: bool, channel: &str) -> Result<String> {
        let (inst, observed) = {
            let a = &self.agents[i];
            (a.inst.clone(), a.observed.clone())
        };
        let handle = self.agents[i]
            .handle
            .clone()
            .context("agent has no IRC connection")?;

        let sid = if start {
            handle.av_start(channel, &inst, None).await?;
            await_for(Duration::from_secs(10), || {
                observed.lock().state_id("started")
            })
            .await
            .context("no av-state=started after av-start")?
        } else {
            let sid = await_for(Duration::from_secs(10), || {
                observed.lock().state_id("started")
            })
            .await
            .context("never saw the channel's call start")?;
            handle.av_join(channel, &sid, &inst).await?;
            await_for(Duration::from_secs(10), || {
                observed.lock().state_id("joined")
            })
            .await
            .context("no av-state=joined after av-join")?
        };

        // F7's rail: hold the dial until the token lands. A client that dials
        // first can never carry one, and breaks the day tokens are required.
        let token = await_for(Duration::from_secs(5), || observed.lock().token_for(&sid))
            .await
            .context("no +freeq.at/av-token — the dial would be tokenless")?;

        self.dial_media(i, &sid, &token).await?;
        Ok(sid)
    }

    /// Forget what this agent's stream has said so far. Every rejoin waits on
    /// an `av-state=joined` and an `av-token`, and both look identical to the
    /// ones from the join before — without this, a recovery step would match
    /// the *previous* join's signals and report success without the server
    /// having answered at all.
    fn reset_observed(&self, i: usize) {
        let mut o = self.agents[i].observed.lock();
        o.states.clear();
        o.tokens.clear();
        o.errors.clear();
        o.left.clear();
    }

    /// Rejoin a session that is already running, by id. Every recovery path
    /// goes through here: a client coming back mid-call joins the id it holds,
    /// it does not wait for a `started` broadcast that happened minutes ago.
    async fn rejoin(&mut self, i: usize, sid: &str, channel: &str) -> Result<()> {
        self.reset_observed(i);
        let handle = self.agents[i].handle.clone().context("no IRC handle")?;
        let inst = self.agents[i].inst.clone();
        let observed = self.agents[i].observed.clone();
        handle.av_join(channel, sid, &inst).await?;
        await_for(Duration::from_secs(10), || {
            observed.lock().state_id("joined")
        })
        .await
        .with_context(|| format!("a{i} never rejoined {sid}"))?;
        let token = await_for(Duration::from_secs(6), || observed.lock().token_for(sid))
            .await
            .with_context(|| format!("a{i} got no token rejoining {sid}"))?;
        self.dial_media(i, sid, &token).await
    }

    /// Leave a call cleanly: drop the roster slot AND the media. Recovery
    /// steps that move an agent to another channel have to do this, or the
    /// agent keeps a live slot in the call it walked away from — its IRC
    /// connection still claims the instance, so nothing reaps it.
    async fn leave_call(&mut self, i: usize, sid: &str, channel: &str) {
        if let Some(handle) = self.agents[i].handle.clone() {
            let inst = self.agents[i].inst.clone();
            let _ = handle.av_leave(channel, sid, &inst).await;
        }
        if let Some(m) = self.agents[i].media.take() {
            m.kill();
        }
    }

    async fn dial_media(&mut self, i: usize, sid: &str, token: &str) -> Result<()> {
        let (inst, freq, transport, path) = {
            let a = &self.agents[i];
            (a.inst.clone(), a.freq, a.transport, a.path(sid))
        };
        let base = match transport {
            // The QUIC listener binds the web port (UDP). Cert verification is
            // off because it self-signs on loopback, exactly as native clients
            // do against a dev server.
            Transport::Quic => format!("https://127.0.0.1:{}/av/moq", self.server.web.port()),
            Transport::Ws => format!("ws://127.0.0.1:{}/av/moq", self.server.web.port()),
        };
        let url = if self.args.break_token {
            format!("{base}?inst={}", urlencode(&inst))
        } else {
            format!("{base}?inst={}&jwt={}", urlencode(&inst), urlencode(token))
        };

        let pub_origin = moq_lite::Origin::produce();
        let broadcast = LocalBroadcast::new();
        broadcast
            .audio()
            .set(
                ToneSource {
                    freq: freq as f32,
                    phase: 0.0,
                },
                AudioCodec::Opus,
                [AudioPreset::Hq],
            )
            .map_err(|e| anyhow::anyhow!("audio set: {e}"))?;
        pub_origin.publish_broadcast(path.as_str(), broadcast.consume());

        let sub_origin = moq_lite::Origin::produce();
        let mut sub_consumer = sub_origin.consume();

        let mut cfg = moq_native::ClientConfig::default();
        cfg.tls.disable_verify = Some(true);
        cfg.backend = Some(moq_native::QuicBackend::Noq);
        let client = cfg.init()?;
        let session = client
            .with_publish(pub_origin.consume())
            .with_consume(sub_origin)
            .connect(url.parse().context("parse SFU url")?)
            .await
            .with_context(|| format!("MoQ connect ({}) for {}", transport.label(), path))?;

        // Subscribe to everything the relay announces under this session that
        // isn't us. This is the announcement-driven model — the one every
        // native client and bot uses.
        let mut tasks = tokio::task::JoinSet::new();
        let prefix = format!("{sid}/");
        let matrix = self.matrix.clone();
        let me = inst.clone();
        let mine = path.clone();
        tasks.spawn(async move {
            let mut seen: BTreeSet<String> = BTreeSet::new();
            while let Some((p, announce)) = sub_consumer.announced().await {
                let p = p.to_string();
                let Some(consumer) = announce else { continue };
                if p == mine || !p.starts_with(&prefix) || !seen.insert(p.clone()) {
                    continue;
                }
                // I6: never subscribe to our own broadcast. Keyed on instance,
                // not nick — two devices on one account share a nick.
                let peer_inst = p.rsplit('~').next().unwrap_or_default().to_string();
                if peer_inst == me {
                    continue;
                }
                let (me2, matrix2) = (me.clone(), matrix.clone());
                tokio::spawn(async move {
                    tap(me2, peer_inst, p, consumer, matrix2).await;
                });
            }
        });

        self.agents[i].media = Some(Media {
            _session: Box::new(session),
            _broadcast: broadcast,
            tasks,
        });
        Ok(())
    }

    // ── matrix ──────────────────────────────────────────────────────

    /// Instances currently expected to be publishing, in agent order.
    fn live_pairs(&self) -> Vec<(usize, String, f64)> {
        self.agents
            .iter()
            .filter(|a| a.media.is_some())
            .map(|a| (a.idx, a.inst.clone(), a.freq))
            .collect()
    }

    /// Wait until every ordered pair of live agents hears the other, or the
    /// budget runs out. Returns the last matrix so the caller can print it.
    async fn await_full_matrix(&self, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        loop {
            if self.matrix_holes().is_empty() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Ordered pairs (k, j) where k should hear j and doesn't.
    fn matrix_holes(&self) -> Vec<(usize, usize)> {
        let live = self.live_pairs();
        let mut holes = Vec::new();
        for (ki, k_inst, _) in &live {
            for (ji, j_inst, j_freq) in &live {
                if ki == ji {
                    continue;
                }
                if !verdict(&self.matrix, k_inst, j_inst, *j_freq).heard {
                    holes.push((*ki, *ji));
                }
            }
        }
        holes
    }

    /// Does anyone still hear `inst`? The blip and media-kill steps are about
    /// a *column* going quiet, which is a different question from the matrix
    /// being full.
    fn column_heard_by_anyone(&self, inst: &str, freq: f64) -> Vec<usize> {
        self.agents
            .iter()
            .filter(|a| a.media.is_some() && a.inst != inst)
            .filter(|a| verdict(&self.matrix, &a.inst, inst, freq).heard)
            .map(|a| a.idx)
            .collect()
    }

    async fn await_column_silent(&self, inst: &str, freq: f64, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        loop {
            if self.column_heard_by_anyone(inst, freq).is_empty() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    fn print_matrix(&self, title: &str) {
        let live = self.live_pairs();
        println!("\n── {title} ──");
        println!("   rows hear columns · ✓ = the column's tone is present, ✗ = it isn't");
        print!("{:>12} |", "hears →");
        for (ji, _, f) in &live {
            print!(" {:>10}", format!("a{ji}@{:.0}Hz", f));
        }
        println!();
        print!("{:->12}-+", "");
        for _ in &live {
            print!("{:->11}", "");
        }
        println!();
        for (ki, k_inst, _) in &live {
            print!("{:>12} |", format!("a{ki}"));
            for (ji, j_inst, j_freq) in &live {
                if ki == ji {
                    // I6: our own tone must NOT be in our own receive path.
                    let v = verdict(&self.matrix, k_inst, k_inst, *j_freq);
                    print!("{:>11}", if v.frames == 0 { "self" } else { "SELF-ECHO" });
                    continue;
                }
                let v = verdict(&self.matrix, k_inst, j_inst, *j_freq);
                let mark = if v.heard { "✓" } else { "✗" };
                print!("{:>11}", format!("{mark} {:.2}", v.score));
            }
            println!();
        }
        self.print_discrimination(&live);
    }

    /// How far apart the two populations of scores actually are — the tone we
    /// expect in a stream versus every tone we don't. Printed every run so the
    /// threshold is answerable from the output instead of taken on faith: if
    /// the gap ever narrows (a codec change, a resampler, a harmonic) the
    /// numbers say so before a flake does.
    fn print_discrimination(&self, live: &[(usize, String, f64)]) {
        let (mut matched, mut mismatched) = (Vec::new(), Vec::new());
        for (ki, k_inst, _) in live {
            for (ji, j_inst, j_freq) in live {
                if ki == ji {
                    continue;
                }
                matched.push(verdict(&self.matrix, k_inst, j_inst, *j_freq).score);
                // The same stream scored against everyone else's tone: what a
                // false positive would have to beat.
                for (oi, _, o_freq) in live {
                    if oi != ji {
                        mismatched.push(verdict(&self.matrix, k_inst, j_inst, *o_freq).score);
                    }
                }
            }
        }
        let lo = |v: &Vec<f64>| v.iter().cloned().fold(f64::INFINITY, f64::min);
        let hi = |v: &Vec<f64>| v.iter().cloned().fold(0.0f64, f64::max);
        if matched.is_empty() || mismatched.is_empty() {
            return;
        }
        println!(
            "   discrimination: worst matched {:.3} · best mismatched {:.3} · threshold {TONE_SCORE}",
            lo(&matched),
            hi(&mismatched)
        );
    }

    /// Report every hole with enough detail to act on: which direction, how
    /// much energy arrived, whether anything arrived at all.
    fn describe_holes(&self) -> Vec<String> {
        let live = self.live_pairs();
        let mut out = Vec::new();
        for (ki, k_inst, _) in &live {
            for (ji, j_inst, j_freq) in &live {
                if ki == ji {
                    continue;
                }
                let v = verdict(&self.matrix, k_inst, j_inst, *j_freq);
                if v.heard {
                    continue;
                }
                out.push(format!(
                    "I1 VIOLATED: a{ki} does not hear a{ji} ({:.0} Hz) — \
                     frames={} fresh={} score={:.3} rms={:.4} decoded={}Hz/{}ch \
                     [a{ki}={k_inst} a{ji}={j_inst}]",
                    j_freq, v.frames, v.fresh, v.score, v.rms, v.rate, v.channels
                ));
            }
        }
        out
    }

    /// I6, asserted rather than assumed: no agent may receive its own tone.
    fn self_echoes(&self) -> Vec<String> {
        self.agents
            .iter()
            .filter(|a| a.media.is_some())
            .filter_map(|a| {
                let v = verdict(&self.matrix, &a.inst, &a.inst, a.freq);
                (v.frames > 0).then(|| {
                    format!(
                        "I6 VIOLATED: a{} is subscribed to its own broadcast \
                         ({} frames of {:.0} Hz)",
                        a.idx, v.frames, a.freq
                    )
                })
            })
            .collect()
    }

    // ── REST roster ─────────────────────────────────────────────────

    async fn roster(&self, sid: &str) -> Result<serde_json::Value> {
        Ok(reqwest::get(format!(
            "http://{}/api/v1/sessions/{sid}?debug=1",
            self.server.web
        ))
        .await?
        .json()
        .await?)
    }

    async fn roster_instances(&self, sid: &str) -> Result<BTreeSet<String>> {
        let v = self.roster(sid).await?;
        Ok(v["participants"]
            .as_array()
            .map(|ps| {
                ps.iter()
                    .filter_map(|p| p["instance_id"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn announced(&self, sid: &str) -> Result<Vec<String>> {
        let v = self.roster(sid).await?;
        Ok(v["announced"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| p.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }
}

/// Subscribe to one peer's audio and keep the last [`WINDOW`] samples.
async fn tap(
    me: String,
    peer_inst: String,
    path: String,
    consumer: moq_lite::BroadcastConsumer,
    matrix: Matrix,
) {
    let Ok(remote) = RemoteBroadcast::new(&path, consumer).await else {
        return;
    };
    let key = (me, peer_inst);
    matrix.lock().entry(key.clone()).or_default();
    let (backend, mut audio_rx) = TapBackend::channel();
    let Ok(track) = remote.audio_ready(&backend).await else {
        return;
    };
    let _track = track; // holding this open is the subscription
    while let Some(PcmFrame { samples, format }) = audio_rx.recv().await {
        let ch = format.channel_count.max(1) as usize;
        let mut g = matrix.lock();
        let c = g.entry(key.clone()).or_default();
        c.rate = format.sample_rate;
        c.channels = format.channel_count;
        c.frames += 1;
        c.last = Some(Instant::now());
        // Keep channel 0 only. Analysing an interleaved buffer as if it were
        // mono halves every apparent frequency, which would put a 440 Hz tone
        // nowhere near the 440 Hz bin.
        if ch > 1 {
            c.pcm.extend(samples.iter().step_by(ch).copied());
        } else {
            c.pcm.extend_from_slice(&samples);
        }
        if c.pcm.len() > WINDOW {
            let drop_n = c.pcm.len() - WINDOW;
            c.pcm.drain(..drop_n);
        }
    }
}

/// Poll `f` until it yields a value or the budget runs out.
async fn await_for<T>(budget: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

// ── main ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    // Errors only by default. The MoQ stack is chatty at warn ("audio buffer
    // low", "using WebSocket fallback") and a matrix buried in it is a matrix
    // nobody reads; RUST_LOG=warn brings it back when a cell goes ✗. The
    // server's own log always goes to a file under --data-dir regardless.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("error".parse()?),
        )
        .init();

    let args = Args::parse();
    if args.agents < 2 {
        bail!("--agents must be at least 2; a mesh of one proves nothing");
    }

    // Identities up front: the server needs the DID→key map on its command
    // line, and the agents need grace, which guests don't get.
    let mut dids = Vec::new();
    let mut agents = Vec::new();
    for i in 0..args.agents {
        let key = PrivateKey::generate_ed25519();
        let did = format!("did:plc:avharness{i}");
        dids.push((did.clone(), key.public_key_multibase()));
        agents.push((did, key.secret_bytes(), i));
    }

    println!("\n=== freeq AV harness (L2 — tone mesh through the full stack) ===");
    println!("  agents      : {}", args.agents);
    println!("  transport   : {}", args.transport);
    println!("  settle      : {}s", args.settle_secs);
    println!("  grace       : {}s", args.grace_secs);
    println!(
        "  chaos       : {}",
        if args.chaos { &args.chaos_steps } else { "off" }
    );
    if args.require_token {
        println!("  tokens      : REQUIRED (FREEQ_AV_REQUIRE_TOKEN=1)");
    }
    if args.break_token {
        println!("  !! BREAK    : dialing WITHOUT ?jwt — the matrix is expected to FAIL");
    }

    let server = Server::start(&args, &dids).await?;
    println!("  server      : irc={} web={}", server.irc, server.web);
    println!("  server log  : {}", server.log.display());

    let matrix: Matrix = Arc::new(Mutex::new(BTreeMap::new()));
    let agents: Vec<Agent> = {
        let mut out = Vec::new();
        for (did, secret, i) in agents {
            let transport = match args.transport.as_str() {
                "quic" => Transport::Quic,
                "ws" => Transport::Ws,
                _ if i % 2 == 0 => Transport::Quic,
                _ => Transport::Ws,
            };
            out.push(Agent {
                idx: i,
                nick: format!("avh{i}"),
                did,
                secret,
                freq: 440.0 * (i + 1) as f64,
                transport,
                inst: new_instance(i, 0),
                blip: Blip::to(server.irc).await?,
                handle: None,
                observed: Arc::new(Mutex::new(Observed::default())),
                media: None,
            });
        }
        out
    };
    for a in &agents {
        println!(
            "    a{} {:>6} [{}] tone={:.0}Hz inst={}",
            a.idx,
            a.nick,
            a.transport.label(),
            a.freq,
            a.inst
        );
    }

    let channel = args.channel.clone();
    let mut h = Harness {
        args,
        server,
        agents,
        matrix,
        session: String::new(),
        findings: Vec::new(),
        failures: Vec::new(),
    };

    let result = run(&mut h, &channel).await;
    let ok = report(&h, &result);
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

async fn run(h: &mut Harness, channel: &str) -> Result<()> {
    // ── baseline: everybody in, through the real lifecycle ──
    for i in 0..h.agents.len() {
        h.connect_irc(i).await?;
    }
    let sid = h.join_call(0, true, channel).await?;
    h.session = sid.clone();
    for i in 1..h.agents.len() {
        h.join_call(i, false, channel).await?;
    }
    println!("\n  session     : {sid}");

    println!(
        "\n  settling for {}s (Opus pipeline + announce propagation)…",
        h.args.settle_secs
    );
    tokio::time::sleep(Duration::from_secs(h.args.settle_secs)).await;

    let full = h.await_full_matrix(Duration::from_secs(10)).await;
    h.print_matrix("baseline (I1: every agent hears every other)");
    if !full {
        for line in h.describe_holes() {
            println!("  {line}");
        }
        h.failures.push("baseline".into());
    }
    for line in h.self_echoes() {
        println!("  {line}");
        h.failures.push("baseline/I6".into());
    }

    // I2 alongside I1: the roster the web client subscribes from must agree
    // with the mesh that actually formed.
    let roster = h.roster_instances(&sid).await?;
    let expected: BTreeSet<String> = h.agents.iter().map(|a| a.inst.clone()).collect();
    if roster != expected {
        println!(
            "  I2 VIOLATED: roster {roster:?} != agents {expected:?} — web would \
             build broadcast paths for a set the wire disagrees with (class A)"
        );
        h.failures.push("baseline/I2".into());
    }

    if !h.args.chaos {
        return Ok(());
    }

    let steps: Vec<String> = h
        .args
        .chaos_steps
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    for step in steps {
        println!("\n══ chaos: {step} ══");
        let outcome = match step.as_str() {
            "blip" => chaos_blip(h, channel).await,
            "media-kill" => chaos_media_kill(h).await,
            "restart" => chaos_restart(h, channel).await,
            "collide" => chaos_collide(h).await,
            "churn" => chaos_churn(h, channel).await,
            other => Err(anyhow::anyhow!("unknown chaos step `{other}`")),
        };
        match outcome {
            Ok(()) => println!("  {step}: OK"),
            Err(e) => {
                println!("  {step}: FAILED — {e:#}");
                h.failures.push(step.clone());
            }
        }
    }
    Ok(())
}

// ── chaos step 1: the blip ──────────────────────────────────────────

/// C1: an agent's IRC dies but its media doesn't. Inside the grace window the
/// mesh must be unchanged (that is F2 — reaping the slot early is what made
/// web clients lose people natives could still hear). At expiry the roster
/// drops it AND the server revokes its media, so the column goes quiet for
/// everyone, on both subscription models at once.
async fn chaos_blip(h: &mut Harness, channel: &str) -> Result<()> {
    // Under --strict-quic-revocation the victim MUST be QUIC-dialed — that
    // flag exists to prove revocation reaches the QUIC transport (F10), and
    // a WS victim would prove nothing. Otherwise prefer WS, where the
    // registry has worked since F6.
    let want = if h.args.strict_quic_revocation {
        Transport::Quic
    } else {
        Transport::Ws
    };
    let victim = h
        .agents
        .iter()
        .position(|a| a.transport == want && a.media.is_some())
        .or_else(|| h.agents.iter().position(|a| a.media.is_some()))
        .context("no agent to blip")?;
    let (inst, freq, transport) = {
        let a = &h.agents[victim];
        (a.inst.clone(), a.freq, a.transport)
    };
    println!(
        "  blipping a{victim} ({}) — IRC only, media stays up",
        transport.label()
    );
    h.agents[victim].blip.cut();

    // Mid-grace: still a full mesh. Sampled at half the window so a slow
    // machine can't drift past the boundary and call a pass a failure.
    tokio::time::sleep(Duration::from_secs(h.args.grace_secs.max(2) / 2)).await;
    let holes = h.matrix_holes();
    if !holes.is_empty() {
        h.print_matrix("during grace (should be unchanged)");
        bail!(
            "F2/C1: the mesh broke inside the grace window — holes {holes:?}. \
             A blipped participant must keep its slot and its audio until the \
             grace decides."
        );
    }
    let during = h.roster_instances(&h.session).await?;
    if !during.contains(&inst) {
        bail!("F2: a{victim}'s roster slot was reaped inside the grace window");
    }
    println!("  mid-grace: mesh intact, roster still lists a{victim} ✓");

    // Past expiry: quiet, for everyone.
    let budget = Duration::from_secs(h.args.grace_secs + 5);
    let silent = h.await_column_silent(&inst, freq, budget).await;
    let announced = h.announced(&h.session).await.unwrap_or_default();
    let still_announced = announced.iter().any(|p| p.ends_with(&format!("~{inst}")));
    let roster_after = h.roster_instances(&h.session).await?;

    if roster_after.contains(&inst) {
        bail!("I4: a{victim}'s roster slot outlived the grace window");
    }
    if !silent {
        let hearers = h.column_heard_by_anyone(&inst, freq);
        let msg = format!(
            "C1: a{victim}'s media outlived its roster slot — still heard by {hearers:?} \
             {}s after grace expiry; announced={still_announced}. This is the F6 \
             ghost: roster-driven clients (web) lost them, announcement-driven \
             clients (native) did not.",
            budget.as_secs()
        );
        if transport == Transport::Quic && !h.args.strict_quic_revocation {
            // Reported, not failed: the server only registers media
            // connections that arrive over WebSocket, so there is nothing to
            // revoke on the QUIC path. See FINDINGS.
            h.findings.push(msg);
            println!("  (QUIC victim — recorded as a finding, not a failure)");
        } else {
            bail!("{msg}");
        }
    } else {
        println!("  post-grace: a{victim}'s column is silent for everyone ✓");
    }

    // Put the agent back so the remaining steps run at full strength. Its old
    // instance is dead, so it comes back as a new participant — which is what
    // a real reconnect does.
    if let Some(m) = h.agents[victim].media.take() {
        m.kill();
    }
    h.agents[victim].blip = Blip::to(h.server.irc).await?;
    h.agents[victim].inst = new_instance(victim, 1);
    h.connect_irc(victim).await?;
    let sid = h.session.clone();
    h.rejoin(victim, &sid, channel).await?;
    if !h.await_full_matrix(Duration::from_secs(20)).await {
        h.print_matrix("after blip recovery");
        bail!(
            "the mesh did not re-form after a{victim} rejoined: {:?}",
            h.describe_holes()
        );
    }
    Ok(())
}

// ── chaos step 2: media-kill ────────────────────────────────────────

/// C2, which `docs/AV-MAP.md` §5 lists as UNAUDITED: the media transport dies
/// while IRC lives. The agent's own client still believes it is in the call
/// (its roster slot is intact, nothing told it otherwise) but nobody can hear
/// it. The harness's job here is to *notice*, not to legislate — whatever it
/// finds is a finding.
async fn chaos_media_kill(h: &mut Harness) -> Result<()> {
    let victim = h
        .agents
        .iter()
        .position(|a| a.media.is_some())
        .context("no agent with media")?;
    let (inst, freq) = (h.agents[victim].inst.clone(), h.agents[victim].freq);
    println!("  killing a{victim}'s media transport only — IRC stays up");

    let killed = h.agents[victim].media.take().context("no media")?;
    killed.kill();

    let silent = h
        .await_column_silent(&inst, freq, Duration::from_secs(10))
        .await;
    let roster = h.roster_instances(&h.session).await?;
    let announced = h.announced(&h.session).await.unwrap_or_default();
    let still_announced = announced.iter().any(|p| p.ends_with(&format!("~{inst}")));

    if !silent {
        bail!(
            "a{victim}'s tone is still audible {}s after its transport closed — \
             the relay is serving a broadcast whose publisher is gone",
            10
        );
    }
    println!("  a{victim}'s column went silent ✓");

    // The C2 observation itself. Both outcomes are informative and neither is
    // currently specified, so record what happened rather than asserting it.
    h.findings.push(format!(
        "C2 (unaudited, now measured): a{victim} lost its media transport while \
         its IRC connection stayed up. Roster still lists it: {}. Relay still \
         announces it: {still_announced}. Nobody hears it. So a client in this \
         state shows itself in-call, shows a tile to every peer, and is mute — \
         with nothing in the protocol telling anyone. A media-liveness signal \
         (or a roster `publishing` flag) is what would close this.",
        roster.contains(&inst)
    ));

    // Restore.
    h.agents[victim].inst = new_instance(victim, 2);
    let (sid, channel) = (h.session.clone(), h.args.channel.clone());
    h.rejoin(victim, &sid, &channel).await?;
    if !h.await_full_matrix(Duration::from_secs(20)).await {
        h.print_matrix("after media-kill recovery");
        bail!("the mesh did not re-form: {:?}", h.describe_holes());
    }
    Ok(())
}

// ── chaos step 3: restart ───────────────────────────────────────────

/// §5.6 / B4 with audio attached: the server goes away under a live call. The
/// L1 suite proves nobody ends up in a *different* session; this proves they
/// can still hear each other afterwards, which is the part a roster can't tell
/// you.
async fn chaos_restart(h: &mut Harness, channel: &str) -> Result<()> {
    println!("  restarting the server under the call");
    for a in h.agents.iter_mut() {
        if let Some(m) = a.media.take() {
            m.kill();
        }
        a.handle = None;
    }
    h.matrix.lock().clear();
    h.server.restart().await?;

    for i in 0..h.agents.len() {
        h.agents[i].blip = Blip::to(h.server.irc).await?;
        h.agents[i].inst = new_instance(i, 3);
        h.connect_irc(i).await?;
    }

    // Rediscover the way a client does: try the channel's call, start one if
    // there isn't one. Either landing is legal; two of them is not.
    let first = {
        let observed = h.agents[0].observed.clone();
        let handle = h.agents[0].handle.clone().context("no handle")?;
        let inst = h.agents[0].inst.clone();
        handle.av_join(channel, &h.session, &inst).await?;
        match await_for(Duration::from_secs(4), || {
            let o = observed.lock();
            o.state_id("joined").or_else(|| {
                o.errors
                    .iter()
                    .any(|(c, _)| c == "join-failed")
                    .then(String::new)
            })
        })
        .await
        {
            Some(sid) if !sid.is_empty() => sid,
            _ => {
                println!("  the pre-restart session did not survive; starting a new one");
                h.join_call(0, true, channel).await?
            }
        }
    };
    if h.agents[0].media.is_none() {
        let observed = h.agents[0].observed.clone();
        let token = await_for(Duration::from_secs(5), || observed.lock().token_for(&first))
            .await
            .context("no token after restart rejoin")?;
        h.dial_media(0, &first, &token).await?;
    }
    h.session = first.clone();

    for i in 1..h.agents.len() {
        h.rejoin(i, &first, channel).await?;
    }

    let sessions: serde_json::Value =
        reqwest::get(format!("http://{}/api/v1/sessions", h.server.web))
            .await?
            .json()
            .await?;
    let in_channel: Vec<String> = sessions["sessions"]
        .as_array()
        .map(|ss| {
            ss.iter()
                .filter(|s| {
                    s["channel"]
                        .as_str()
                        .is_some_and(|c| c.eq_ignore_ascii_case(channel))
                })
                .filter_map(|s| s["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if in_channel.len() != 1 {
        bail!("I5/B4: the restart split the call — sessions {in_channel:?}");
    }

    let budget = Duration::from_secs(h.args.recover_secs);
    if !h.await_full_matrix(budget).await {
        h.print_matrix("after restart");
        bail!(
            "the mesh did not re-form within {}s: {:?}",
            budget.as_secs(),
            h.describe_holes()
        );
    }
    h.print_matrix("after restart");
    Ok(())
}

// ── chaos step 4: collide ───────────────────────────────────────────

/// §5.5 / F4 with audio: two agents start a call in the same tick. One session
/// survives, the loser is told which, it converges — and then the two of them
/// can actually hear each other, which is the assertion a signaling-only test
/// can't make.
async fn chaos_collide(h: &mut Harness) -> Result<()> {
    let channel = format!("{}-collide", h.args.channel);
    let (x, y) = (0usize, 1usize);

    let main_sid = h.session.clone();
    let main_channel = h.args.channel.clone();
    for i in [x, y] {
        // Leave the main call properly first. Killing only the media would
        // leave a live roster slot behind — the agent's IRC connection still
        // claims that instance, so nothing reaps it, and it turns up as a
        // ghost row two steps later.
        h.leave_call(i, &main_sid, &main_channel).await;
        h.agents[i].inst = new_instance(i, 4);
        let handle = h.agents[i].handle.clone().context("no handle")?;
        handle.join(&channel).await?;
        h.reset_observed(i);
    }
    tokio::time::sleep(Duration::from_millis(400)).await;

    let (hx, hy) = (
        h.agents[x].handle.clone().unwrap(),
        h.agents[y].handle.clone().unwrap(),
    );
    let (ix, iy) = (h.agents[x].inst.clone(), h.agents[y].inst.clone());
    let (rx, ry) = tokio::join!(
        hx.av_start(&channel, &ix, None),
        hy.av_start(&channel, &iy, None)
    );
    rx?;
    ry?;

    let sid = await_for(Duration::from_secs(8), || {
        h.agents[x].observed.lock().state_id("started")
    })
    .await
    .context("no session was started by the colliding pair")?;

    let losers: Vec<usize> = [x, y]
        .into_iter()
        .filter(|i| {
            h.agents[*i]
                .observed
                .lock()
                .errors
                .iter()
                .any(|(c, _)| c == "start-collision")
        })
        .collect();
    if losers.len() != 1 {
        bail!("expected exactly one start-collision, got {}", losers.len());
    }
    let loser = losers[0];
    let named = h.agents[loser]
        .observed
        .lock()
        .errors
        .iter()
        .find(|(c, _)| c == "start-collision")
        .map(|(_, id)| id.clone())
        .unwrap_or_default();
    if named != sid {
        bail!("the collision named `{named}` but the surviving session is `{sid}`");
    }

    // Both dial the one session and must cross.
    for i in [x, y] {
        if i == loser {
            let handle = h.agents[i].handle.clone().unwrap();
            let inst = h.agents[i].inst.clone();
            handle.av_join(&channel, &sid, &inst).await?;
        }
        let observed = h.agents[i].observed.clone();
        let token = await_for(Duration::from_secs(6), || observed.lock().token_for(&sid))
            .await
            .with_context(|| format!("a{i} got no token for the surviving session"))?;
        h.dial_media(i, &sid, &token).await?;
    }
    tokio::time::sleep(Duration::from_secs(h.args.settle_secs.min(6))).await;

    let (ix, iy) = (h.agents[x].inst.clone(), h.agents[y].inst.clone());
    let (fx, fy) = (h.agents[x].freq, h.agents[y].freq);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let a = verdict(&h.matrix, &ix, &iy, fy).heard;
        let b = verdict(&h.matrix, &iy, &ix, fx).heard;
        if a && b {
            println!("  both racers converged on {sid} and hear each other ✓");
            break;
        }
        if Instant::now() >= deadline {
            bail!("I1 after a start collision: a{x}→a{y}={a} a{y}→a{x}={b} in session {sid}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Leave the collision channel so `churn` runs against the main call.
    for i in [x, y] {
        h.leave_call(i, &sid, &channel).await;
    }
    Ok(())
}

// ── chaos step 5: churn ─────────────────────────────────────────────

/// Instance churn — the signature in the July logs. One agent leaves and
/// rejoins five times, each time with a *new* instance, because that is what a
/// reloading client actually does. Every stale instance is a ghost row and a
/// dead broadcast path for every roster-driven subscriber, so the assertion is
/// as much about what the roster does NOT contain as what it does.
async fn chaos_churn(h: &mut Harness, channel: &str) -> Result<()> {
    // Bring back anyone the collide step parked.
    let sid = h.session.clone();
    for i in 0..h.agents.len() {
        if h.agents[i].media.is_none() {
            h.agents[i].inst = new_instance(i, 5);
            let handle = h.agents[i].handle.clone().context("no handle")?;
            handle.join(channel).await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
            h.rejoin(i, &sid, channel).await?;
        }
    }
    if !h.await_full_matrix(Duration::from_secs(25)).await {
        h.print_matrix("before churn");
        bail!("mesh incomplete before churn: {:?}", h.describe_holes());
    }

    let victim = h.agents.len() - 1;
    let mut retired: Vec<String> = Vec::new();
    for round in 0..5 {
        let old = h.agents[victim].inst.clone();
        h.leave_call(victim, &sid, channel).await;
        retired.push(old);

        h.agents[victim].inst = new_instance(victim, 10 + round);
        let inst = h.agents[victim].inst.clone();
        h.rejoin(victim, &sid, channel).await?;
        println!("  churn {}/5: a{victim} is now {inst}", round + 1);
        tokio::time::sleep(Duration::from_millis(600)).await;
    }

    if !h.await_full_matrix(Duration::from_secs(25)).await {
        h.print_matrix("after churn");
        bail!("mesh incomplete after churn: {:?}", h.describe_holes());
    }

    let roster = h.roster_instances(&sid).await?;
    let expected: BTreeSet<String> = h.agents.iter().map(|a| a.inst.clone()).collect();
    let ghosts: Vec<&String> = retired.iter().filter(|r| roster.contains(*r)).collect();
    if !ghosts.is_empty() {
        bail!(
            "I2: {} retired instance(s) still on the roster after churn: {ghosts:?} — \
             every one is a tile web renders and a path nobody publishes",
            ghosts.len()
        );
    }
    if roster != expected {
        bail!("I2: roster {roster:?} != live agents {expected:?} after churn");
    }
    println!("  roster holds exactly {} rows, no ghosts ✓", roster.len());
    Ok(())
}

// ── report ──────────────────────────────────────────────────────────

fn report(h: &Harness, result: &Result<()>) -> bool {
    println!("\n════════════════════════════════════════════════════════════");
    if let Err(e) = result {
        println!("  ABORTED: {e:#}");
    }
    if !h.findings.is_empty() {
        println!("\n  FINDINGS (observed, not pass/fail):");
        for f in &h.findings {
            println!("   · {f}");
        }
    }
    let ok = result.is_ok() && h.failures.is_empty();
    println!();
    if ok {
        println!("  RESULT: PASS — I1 held across every agent pair, through every step.");
    } else if h.failures.is_empty() {
        // Aborted before any step could record a verdict — the reason is the
        // error above, and an empty list would read as "nothing went wrong".
        println!("  RESULT: FAIL — aborted before the mesh could be measured");
    } else {
        println!("  RESULT: FAIL — {:?}", h.failures);
    }
    println!("════════════════════════════════════════════════════════════\n");
    ok
}
