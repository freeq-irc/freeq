//! Phase 4: Interop and Spawning — Interactive Demo
//!
//! Declarative manifests, delegated spawn chains, and wrapping external agents.
//! Owner says "next" to advance, "quit" to stop.
//!
//! Usage:
//!   cargo run --example demo_phase4 -- --server irc.freeq.at:6697 --tls --channel "#chad-dev"

use anyhow::Result;
use clap::Parser;
use freeq_sdk::auth::KeySigner;
use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::event::Event;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

const OWNER: &str = "chadfowler.com";

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "irc.freeq.at:6697")]
    server: String,
    #[arg(long, default_value = "factory")]
    nick: String,
    #[arg(long, default_value = "#chad-dev")]
    channel: String,
    #[arg(long)]
    tls: bool,
}

// ─── Helpers ────────────────────────────────────────

enum OwnerCmd {
    Next,
    Quit,
}

async fn wait_owner(
    rx: &mut mpsc::Receiver<Event>,
    ch: &str,
    secs: u64,
    handle: &ClientHandle,
) -> Option<OwnerCmd> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut last_hb = tokio::time::Instant::now();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let hb_remaining = Duration::from_secs(25).saturating_sub(last_hb.elapsed());
        match timeout(remaining.min(hb_remaining), rx.recv()).await {
            Ok(Some(Event::Message {
                from,
                target,
                text,
                tags,
                ..
            })) => {
                if tags.contains_key("batch") {
                    continue;
                }
                if !target.eq_ignore_ascii_case(ch) || !from.eq_ignore_ascii_case(OWNER) {
                    continue;
                }
                let w = text.trim().to_lowercase();
                let w = w
                    .strip_prefix("factory:")
                    .or_else(|| w.strip_prefix("factory,"))
                    .or_else(|| w.strip_prefix("@factory"))
                    .map(|s| s.trim())
                    .unwrap_or(&w);
                match w {
                    "next" | "n" | "go" | "continue" | "ok" | "yes" | "y" | "ready" => {
                        return Some(OwnerCmd::Next);
                    }
                    "quit" | "q" | "stop" | "exit" => return Some(OwnerCmd::Quit),
                    _ => continue,
                }
            }
            Ok(Some(Event::Disconnected { reason })) => {
                eprintln!("Disconnected: {reason}");
                return Some(OwnerCmd::Quit);
            }
            Ok(Some(_)) => continue,
            Ok(None) => return Some(OwnerCmd::Quit),
            Err(_) => {
                if last_hb.elapsed() >= Duration::from_secs(25) {
                    let _ = handle.raw("HEARTBEAT 60").await;
                    last_hb = tokio::time::Instant::now();
                }
            }
        }
    }
}

async fn say(h: &ClientHandle, ch: &str, lines: &[&str]) {
    for line in lines {
        let _ = h.privmsg(ch, line).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

async fn prompt(h: &ClientHandle, rx: &mut mpsc::Receiver<Event>, ch: &str) -> bool {
    say(
        h,
        ch,
        &["", "👉 Say 'next' to continue (or 'quit' to stop)."],
    )
    .await;
    matches!(wait_owner(rx, ch, 600, h).await, Some(OwnerCmd::Next))
}

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

async fn drain(rx: &mut mpsc::Receiver<Event>) {
    tokio::time::sleep(Duration::from_secs(4)).await;
    while let Ok(Some(_)) = timeout(Duration::from_millis(100), rx.recv()).await {}
}

async fn shutdown(handle: ClientHandle) -> Result<()> {
    handle
        .raw("PRESENCE :state=offline;status=Shutting down")
        .await?;
    handle.quit(Some("Goodbye!")).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    println!("Done.");
    Ok(())
}

// ─── Main ───────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("warn").init();
    let args = Args::parse();
    let ch = &args.channel;

    let key_dir = dirs::home_dir().unwrap().join(".freeq/bots/factory");
    std::fs::create_dir_all(&key_dir)?;
    let key_path = key_dir.join("key.ed25519");
    let private_key = if key_path.exists() {
        PrivateKey::ed25519_from_bytes(&std::fs::read(&key_path)?)?
    } else {
        let key = PrivateKey::generate_ed25519();
        std::fs::write(&key_path, key.secret_bytes())?;
        key
    };
    let did = format!("did:key:{}", private_key.public_key_multibase());
    println!("DID: {did}");
    let signer = KeySigner::new(did.clone(), private_key);

    println!("Connecting to {}...", args.server);
    let config = ConnectConfig {
        server_addr: args.server.clone(),
        nick: args.nick.clone(),
        user: args.nick.clone(),
        realname: "Phase 4 Factory Agent".to_string(),
        tls: args.tls,
        tls_insecure: false,
        web_token: None,
        websocket_url: None,
    };
    let conn = client::establish_connection(&config).await?;
    let (handle, mut events) =
        client::connect_with_stream(conn, config, Some(std::sync::Arc::new(signer)));

    loop {
        match events.recv().await {
            Some(Event::Registered { nick }) => {
                println!("Registered as {nick}");
                break;
            }
            Some(Event::Disconnected { reason }) => {
                eprintln!("Disconnected: {reason}");
                return Ok(());
            }
            _ => continue,
        }
    }

    handle.register_agent("agent").await?;
    handle.raw("HEARTBEAT 60").await?;
    handle
        .raw("PRESENCE :state=active;status=Phase 4 demo")
        .await?;
    let provenance = serde_json::json!({
        "actor_did": did,
        "origin_type": "external_import",
        "creator_did": "did:plc:4qsyxmnsblo4luuycm3572bq",
        "implementation_ref": "freeq/demo_phase4.rs@HEAD",
        "source_repo": "https://github.com/freeq-irc/freeq",
        "authority_basis": "Operated by server administrator",
        "revocation_authority": "did:plc:4qsyxmnsblo4luuycm3572bq",
    });
    handle
        .raw(&format!(
            "PROVENANCE :{}",
            b64(&serde_json::to_vec(&provenance)?)
        ))
        .await?;
    handle.join(ch).await?;
    drain(&mut events).await;
    println!("Ready.");

    // ─── Intro ──────────────────────────────────────

    say(
        &handle,
        ch,
        &[
            "👋 Hi! I'm factory -- demo agent for Phase 4: Interop and Spawning.",
            "",
            "Phase 1: agents are visible",
            "Phase 2: agents are controllable",
            "Phase 3: agent work is auditable",
            "Phase 4: agents can be introduced, composed, and bridged.",
            "",
            "Three patterns for bringing agents into a channel:",
            "  1. Agent Manifests   -- declarative, zero-config onboarding",
            "  2. Delegated Spawn   -- parent-child chains with scoped TTLs",
            "  3. Wrapper Profiles  -- bridge external protocols (MCP, A2A)",
            "",
            "I'll demo each one.",
        ],
    )
    .await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ─── Step 1: Agent Manifests ────────────────────

    say(
        &handle,
        ch,
        &[
            "━━━ 1/3: Agent Manifests ━━━",
            "",
            "Today, setting up a new agent requires manual steps:",
            "  - connect, authenticate, AGENT REGISTER, PROVENANCE, HEARTBEAT...",
            "",
            "A manifest is a declarative TOML file that describes everything:",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    say(
        &handle,
        ch,
        &[
            "  # auditor.freeq.toml",
            "  [agent]",
            "  display_name = \"auditor\"",
            "  description = \"Architecture auditor\"",
            "  source_repo = \"https://github.com/freeq-irc/freeq\"",
            "  version = \"0.1.0\"",
            "",
            "  [provenance]",
            "  origin_type = \"template\"",
            "  creator_did = \"did:plc:4qsyxm...\"",
            "  revocation_authority = \"did:plc:4qsyxm...\"",
            "",
            "  [capabilities]",
            "  default = [\"post_message\", \"read_channel\"]",
            "",
            "  [presence]",
            "  heartbeat_interval_seconds = 30",
        ],
    )
    .await;

    say(
        &handle,
        ch,
        &[
            "",
            "To introduce this agent, anyone with admin rights does one thing:",
            "",
            "  AGENT MANIFEST https://example.com/auditor.freeq.toml",
            "",
            "The server fetches it, validates it, and pre-registers the agent.",
            "When the agent connects and authenticates with its DID,",
            "everything auto-applies: actor_class, provenance, capabilities,",
            "heartbeat interval. Zero manual setup.",
            "",
            "Let me simulate an auditor joining via manifest...",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle.raw(&format!(
        "AGENT SPAWN {ch} :nick=auditor;capabilities=post_message,read_channel;ttl=300;task=manifest-demo"
    )).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle.raw(&format!(
        "AGENT MSG auditor {ch} :👋 Hi! I'm auditor, introduced via manifest. My identity, provenance, and capabilities were configured declaratively -- no manual setup."
    )).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle.raw(&format!(
        "AGENT MSG auditor {ch} :📋 My manifest says I can: post_message, read_channel. That's all I'll ever ask for."
    )).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    say(
        &handle,
        ch,
        &[
            "",
            "Click auditor's name in the sidebar to see its identity card.",
            "",
            "Key points:",
            "  - Manifests are version-controlled (TOML in a git repo)",
            "  - Server validates creator_did and revocation_authority exist",
            "  - Capabilities are bounded by the manifest -- agent can't escalate",
            "  - Manifests can specify per-channel capability overrides",
        ],
    )
    .await;

    if !prompt(&handle, &mut events, ch).await {
        let _ = handle.raw("AGENT DESPAWN auditor").await;
        return shutdown(handle).await;
    }

    let _ = handle.raw("AGENT DESPAWN auditor").await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ─── Step 2: Delegated Spawn Chains ─────────────

    say(
        &handle,
        ch,
        &[
            "━━━ 2/3: Delegated Spawn Chains ━━━",
            "",
            "Phase 2 introduced basic spawning. Phase 4 adds provenance chains.",
            "",
            "When I spawn a child, the server records:",
            "  - Who the parent is (me, factory)",
            "  - What capabilities the child gets (subset of mine)",
            "  - A TTL (auto-expire)",
            "  - The task it's working on",
            "",
            "Children can spawn grandchildren. Each link in the chain",
            "is recorded, auditable, and revocable.",
            "",
            "I'll build a three-level delegation chain:",
            "  factory -> architect -> layout-worker",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Spawn architect
    handle.raw(&format!(
        "AGENT SPAWN {ch} :nick=architect;capabilities=post_message,spawn_agent;ttl=180;task=design-phase"
    )).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle.raw(&format!(
        "AGENT MSG architect {ch} :🏗 I'm architect, spawned by factory. I have spawn_agent capability, so I can delegate further."
    )).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    handle
        .raw(&format!(
            "AGENT MSG architect {ch} :🏗 I need a layout specialist. Spawning layout-worker..."
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // In a real implementation, architect would spawn layout-worker.
    // Since spawned agents can't actually issue commands, factory does it
    // but we narrate it as architect's action.
    handle
        .raw(&format!(
            "AGENT SPAWN {ch} :nick=layout-worker;capabilities=post_message;ttl=120;task=css-layout"
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle.raw(&format!(
        "AGENT MSG layout-worker {ch} :📐 I'm layout-worker. My chain: factory -> architect -> me."
    )).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle.raw(&format!(
        "AGENT MSG layout-worker {ch} :📐 I can only post_message. I can't spawn further or call tools. Least privilege."
    )).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle.raw(&format!(
        "AGENT MSG layout-worker {ch} :📐 Flexbox grid: done. Responsive breakpoints: done. Dark mode: done."
    )).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle
        .raw(&format!(
            "AGENT MSG architect {ch} :🏗 layout-worker finished. Despawning it."
        ))
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    handle.raw("AGENT DESPAWN layout-worker").await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    handle
        .raw(&format!(
            "AGENT MSG architect {ch} :🏗 Design phase complete. Signing off."
        ))
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    handle.raw("AGENT DESPAWN architect").await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    say(
        &handle,
        ch,
        &[
            "",
            "The full chain was: factory -> architect -> layout-worker",
            "",
            "Key points:",
            "  - Each child gets a subset of its parent's capabilities",
            "  - Revoking a parent cascades to all children",
            "  - TTLs prevent orphaned agents (layout-worker: 120s, architect: 180s)",
            "  - The audit timeline shows the full delegation chain",
            "  - Every spawn is a structured coordination event (Phase 3)",
        ],
    )
    .await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ─── Step 3: Wrapper Trust Profiles ─────────────

    say(
        &handle,
        ch,
        &[
            "━━━ 3/3: Wrapper Trust Profiles ━━━",
            "",
            "Not all agents speak IRC. Many use MCP, A2A, or custom protocols.",
            "A wrapper bridges them into Freeq with full governance.",
            "",
            "The wrapper is itself an auditable agent:",
            "",
            "  ┌──────────┐       ┌──────────────┐       ┌──────────────┐",
            "  │ MCP Agent │<----->│ Freeq MCP    │<----->│ Freeq Server │",
            "  │ (external)│  MCP  │ Wrapper      │  IRC  │              │",
            "  └──────────┘       └──────────────┘       └──────────────┘",
            "",
            "The wrapper:",
            "  - Authenticates as an agent with origin_type=external_import",
            "  - Translates MCP tool calls <-> Freeq coordination events",
            "  - Enforces channel capabilities on the external agent",
            "  - Signs actions with its own key (provenance trail)",
            "  - Reports presence based on the external agent's health",
        ],
    )
    .await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    say(
        &handle,
        ch,
        &["Let me simulate an external MCP agent joining via wrapper..."],
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle.raw(&format!(
        "AGENT SPAWN {ch} :nick=github-bot;capabilities=post_message,call_tool;ttl=300;task=mcp-bridge"
    )).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle
        .raw(&format!(
            "AGENT MSG github-bot {ch} :🌐 Hi! I'm github-bot, an MCP agent bridged into Freeq."
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle.raw(&format!(
        "AGENT MSG github-bot {ch} :🌐 My wrapper is freeq-mcp-wrapper v0.1.0 (source: github.com/freeq-irc/freeq)"
    )).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle.raw(&format!(
        "AGENT MSG github-bot {ch} :🌐 I can: search_issues, read_pr, list_commits. But only if the channel policy allows it."
    )).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Simulate a tool call
    handle
        .raw(&format!(
            "AGENT MSG github-bot {ch} :🔍 Searching issues in freeq-irc/freeq for 'heartbeat'..."
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    handle.raw(&format!(
        "AGENT MSG github-bot {ch} :📋 Found 3 issues: #42 'Heartbeat enforcement', #38 'Agent heartbeat TTL', #35 'Add HEARTBEAT command'"
    )).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    say(
        &handle,
        ch,
        &[
            "",
            "The wrapper's identity card shows:",
            "  - 🌐 External Agent badge (not just 🤖)",
            "  - Wrapper name, version, source repo",
            "  - Audit status (unaudited / community reviewed / formally audited)",
            "  - Which protocol it bridges (MCP, A2A, etc.)",
            "  - The original external system URL",
            "",
            "If the channel policy doesn't grant call_tool:search_issues,",
            "the wrapper blocks the MCP call before it reaches the external agent.",
            "The external agent never even sees the request.",
        ],
    )
    .await;

    handle.raw("AGENT DESPAWN github-bot").await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ─── Step 4: All Three Together ─────────────────

    say(
        &handle,
        ch,
        &[
            "━━━ Bonus: All Three Patterns Together ━━━",
            "",
            "A realistic scenario using all three introduction patterns:",
            "",
            "  1. factory (manifest-registered) accepts a build task",
            "  2. factory spawns qa-worker (delegated spawn) to run tests",
            "  3. qa-worker calls a GitHub MCP agent (wrapper) to check CI",
            "  4. Results flow back through the chain:",
            "     github-bot -> qa-worker -> factory -> channel",
            "",
            "Each agent in the chain has:",
            "  - Its own identity and DID",
            "  - Scoped capabilities (narrowing at each level)",
            "  - An auditable provenance trail",
            "  - Governance controls (pausable, revocable)",
            "",
            "The human sees structured updates. The audit timeline",
            "shows every action, every delegation, every tool call.",
            "",
            "And someone on irssi sees it all as readable text.",
        ],
    )
    .await;

    // ─── Summary ────────────────────────────────────

    say(
        &handle,
        ch,
        &[
            "",
            "━━━ Phase 4: Interop and Spawning -- Summary ━━━",
            "",
            "Three patterns for introducing agents:",
            "",
            "  1. Manifests -- declarative TOML, version-controlled,",
            "     zero-config onboarding. Agent connects and everything",
            "     auto-applies.",
            "",
            "  2. Delegated Spawn -- parent creates children with narrowed",
            "     capabilities and TTLs. Full provenance chain. Revocation",
            "     cascades from parent to children.",
            "",
            "  3. Wrapper Profiles -- bridge MCP, A2A, or any external",
            "     protocol. The wrapper is auditable. Channel policy",
            "     enforces capabilities. The external agent is sandboxed.",
            "",
            "Phase 1: 'Who is this agent?'",
            "Phase 2: 'What can it do, and who controls it?'",
            "Phase 3: 'What did it do, and can I verify it?'",
            "Phase 4: 'How did it get here, and what's it allowed to become?'",
            "",
            "👋 factory signing off. Say 'quit' or I'll hang out.",
        ],
    )
    .await;

    handle
        .raw("PRESENCE :state=idle;status=Demo complete")
        .await?;

    // Idle loop
    let mut last_hb = tokio::time::Instant::now();
    loop {
        let hb_remaining = Duration::from_secs(25).saturating_sub(last_hb.elapsed());
        match timeout(hb_remaining, events.recv()).await {
            Ok(Some(Event::Message {
                from,
                target,
                text,
                tags,
                ..
            })) => {
                if tags.contains_key("batch") {
                    continue;
                }
                if target.eq_ignore_ascii_case(ch) && from.eq_ignore_ascii_case(OWNER) {
                    let w = text.trim().to_lowercase();
                    if matches!(w.as_str(), "quit" | "q" | "stop" | "exit") {
                        break;
                    }
                }
            }
            Ok(Some(Event::Disconnected { reason })) => {
                eprintln!("Disconnected: {reason}");
                return Ok(());
            }
            Ok(_) => {}
            Err(_) => {
                handle.raw("HEARTBEAT 60").await?;
                last_hb = tokio::time::Instant::now();
            }
        }
    }

    shutdown(handle).await
}
