//! Chatroom simulator — connects multiple LLM-powered bots to a channel.
//!
//! Each bot has a distinct personality and chats naturally. Useful for
//! generating realistic screenshots and screencasts.
//!
//! Usage:
//!   ANTHROPIC_API_KEY=sk-... cargo run --release --bin chatroom -- \
//!     --server 127.0.0.1:16799 --channel '#demo' --bots 5
//!
//! Or connect to production:
//!   ANTHROPIC_API_KEY=sk-... cargo run --release --bin chatroom -- \
//!     --server irc.freeq.at:6667 --channel '#freeq' --bots 4

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use rand::Rng;
use rand::SeedableRng;
use tokio::sync::Mutex;

use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::event::Event;

// ── Simple Claude API client (self-contained) ──────────────────────────

mod llm {
    use anyhow::{Context, Result};
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct ApiResponse {
        content: Vec<ContentBlock>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(tag = "type")]
    enum ContentBlock {
        #[serde(rename = "text")]
        Text { text: String },
        #[allow(dead_code)]
        #[serde(other)]
        Other,
    }

    pub async fn complete(
        api_key: &str,
        model: &str,
        system: &str,
        prompt: &str,
        max_tokens: u32,
    ) -> Result<String> {
        let body = serde_json::json!({
            "model": model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        });

        let resp = reqwest::Client::new()
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Claude API call failed")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Claude API error {status}: {body}");
        }

        let api_resp: ApiResponse = resp.json().await.context("Parse failed")?;
        Ok(api_resp
            .content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(""))
    }
}

// ── CLI ────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "chatroom", about = "LLM-powered chatroom simulator for freeq")]
struct Args {
    /// IRC server address (host:port)
    #[arg(long, default_value = "127.0.0.1:16799")]
    server: String,

    /// Channel to join
    #[arg(long, default_value = "#freeq")]
    channel: String,

    /// Number of bots (max 10)
    #[arg(long, default_value = "5")]
    bots: usize,

    /// Claude model
    #[arg(long, default_value = "claude-sonnet-4-20250514")]
    model: String,

    /// Min seconds between messages per bot
    #[arg(long, default_value = "10")]
    min_delay: u64,

    /// Max seconds between messages per bot
    #[arg(long, default_value = "45")]
    max_delay: u64,

    /// Conversation topic/vibe
    #[arg(
        long,
        default_value = "friends hanging out — dev life, music, food, travel, memes, hot takes, weekend plans"
    )]
    topic: String,

    /// Use TLS
    #[arg(long)]
    tls: bool,
}

// ── Personas ───────────────────────────────────────────────────────────

struct BotPersona {
    nick: &'static str,
    realname: &'static str,
    personality: &'static str,
}

const PERSONAS: &[BotPersona] = &[
    BotPersona {
        nick: "mika",
        realname: "Mika Chen",
        personality: "Mika Chen, 28, frontend engineer at a climate tech startup in Vancouver. \
Studied design then taught herself to code. Makes generative art with p5.js. \
Outside of work: obsessed with bouldering, collects vintage Japanese stationery, \
and is training for her first ultramarathon. Watches way too much reality TV (loves Survivor). \
Types mostly lowercase. Uses emoji naturally 🎨 Gets excited easily. Will derail any \
conversation into a discussion about fonts or snack recommendations.",
    },
    BotPersona {
        nick: "dex",
        realname: "Dexter Okafor",
        personality: "Dexter Okafor, 34, SRE at a fintech in Lagos. Has a popular blog about \
running infrastructure in Africa. Dry humor, proper punctuation. \
Outside of work: serious home cook (Nigerian and Japanese fusion is his thing), \
plays chess competitively online, and is restoring a 1987 Toyota Corolla. \
Huge sci-fi reader — will reference Octavia Butler and Ted Chiang in conversation. \
Skeptical of hype but genuinely curious about everything.",
    },
    BotPersona {
        nick: "zara",
        realname: "Zara Okonkwo-Patel",
        personality: "Zara Okonkwo-Patel, 31, ML researcher who co-founded a small AI safety lab. \
Warm, encouraging, asks great follow-up questions. \
Outside of work: amateur ceramicist, trains Brazilian jiu-jitsu, obsessive about \
specialty coffee (has opinions about pour-over ratios). Loves weird Wikipedia rabbit holes \
and will share the strangest facts. Has a running joke about her plant collection growing \
faster than her paper citations. Laughs easily.",
    },
    BotPersona {
        nick: "ghostwire",
        realname: "Sam Reyes",
        personality: "Sam Reyes (ghostwire), 29, nonbinary security researcher in Berlin. \
Dark humor, types fast, occasional typos. \
Outside of work: DJ (techno and jungle), builds modular synths, rides a fixed-gear \
bike everywhere even in Berlin winters. Obsessed with 90s internet aesthetics and \
geocities-era web design. Collects old hacking zines. Will share the most unhinged \
memes. Surprisingly good at cooking Thai food. Uses they/them.",
    },
    BotPersona {
        nick: "sol",
        realname: "Sol Andersen",
        personality: "Sol Andersen, 36, design engineer who runs a tiny consultancy in Copenhagen. \
Previously at Vercel. Uses em-dashes liberally — thinks in systems. \
Outside of work: competitive sailor (dinghies, not yachts), reads a lot of philosophy \
(loves Ursula K. Le Guin), and is deep into Scandinavian noir TV shows. \
Makes her own sourdough and will not shut up about crumb structure. \
Quiet in groups but drops absolute bangers when she does speak.",
    },
    BotPersona {
        nick: "priya",
        realname: "Priya Sharma",
        personality: "Priya Sharma, 26, iOS developer in Bangalore, works remotely for a US startup. \
Fosters rescue cats (currently has 3). Very positive energy! \
Outside of work: plays tabla, watches every Marvel movie opening weekend, \
addicted to Wordle and NYT crosswords, learning to surf on trips to Goa. \
Has a TikTok about mechanical keyboards that accidentally got 50k followers. \
Sends cat photos unprompted. Genuinely kind.",
    },
    BotPersona {
        nick: "rook",
        realname: "Marcus Webb",
        personality: "Marcus Webb (rook), 41, indie game developer and retro computing collector. \
Made a roguelike that got a cult following. Thoughtful, doesn't post often. \
Outside of work: coaches his daughter's soccer team, volunteers at a makerspace, \
brews his own beer (and names every batch), and is an avid birdwatcher. \
Tells the best campfire stories. Has a vinyl collection organized by mood. \
Drops obscure music recommendations that are always exactly right.",
    },
    BotPersona {
        nick: "nyx",
        realname: "Nyx Liu",
        personality: "Nyx Liu, 33, open source maintainer and developer advocate in Taipei. \
Sarcastic but kind underneath. Night owl. \
Outside of work: competitive Tetris player, practices calligraphy, \
runs a book club that only reads sci-fi (currently on Vernor Vinge). \
Makes her own hot sauce and rates every taco she eats. Has a cat named Segfault. \
Will absolutely roast your bad takes but also be the first to help when you're stuck. \
Shares the best YouTube video essays.",
    },
    BotPersona {
        nick: "jade",
        realname: "Jade Torres",
        personality: "Jade Torres, 30, bootstrapped founder of a small dev tools company in Mexico City. \
Previously at Stripe. Quick-witted, good at one-liners. \
Outside of work: serious runner (just did her first 50k), into mezcal tasting, \
mechanical watch modding, and she's learning to fly small planes. \
Reads a lot of history and economics. Will bet on anything — the channel has \
a running tab. Types concisely. Has the best travel recommendations.",
    },
    BotPersona {
        nick: "byte",
        realname: "River Kim",
        personality: "River Kim (byte), 23, recent CS grad at their first job (small agency in Portland). \
Eager, asks great questions, gets genuinely excited about new things. Uses they/them. \
Outside of work: skateboards, makes zines (hand-drawn, photocopied), plays in a noise \
rock band called 'Null Pointer', and is trying to learn to cook beyond ramen. \
Watches a lot of horror movies and anime. Has the best meme game in the channel. \
Will overshare about their Spotify Wrapped.",
    },
];

// ── Shared state ───────────────────────────────────────────────────────

/// Owned version of BotPersona for spawned tasks
struct OwnedPersona {
    nick: String,
    realname: String,
    personality: String,
}

/// Recent chat messages visible to all bots
type ChatLog = Arc<Mutex<VecDeque<(String, String)>>>;

// ── Main ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let api_key =
        std::env::var("ANTHROPIC_API_KEY").context("Set ANTHROPIC_API_KEY environment variable")?;
    let bot_count = args.bots.min(PERSONAS.len());
    let chat_log: ChatLog = Arc::new(Mutex::new(VecDeque::with_capacity(100)));

    println!("🤖 Chatroom simulator");
    println!("   Server:  {}", args.server);
    println!("   Channel: {}", args.channel);
    println!("   Bots:    {bot_count}");
    println!("   Model:   {}", args.model);
    println!("   Delay:   {}–{}s", args.min_delay, args.max_delay);
    println!("   Topic:   {}", args.topic);
    println!();

    for persona in PERSONAS.iter().take(bot_count) {
        let server = args.server.clone();
        let channel = args.channel.clone();
        let topic = args.topic.clone();
        let model = args.model.clone();
        let api_key = api_key.clone();
        let chat_log = Arc::clone(&chat_log);
        let min_delay = args.min_delay;
        let max_delay = args.max_delay;
        let tls = args.tls;
        let nick = persona.nick.to_string();
        let realname = persona.realname.to_string();
        let personality = persona.personality.to_string();

        tokio::spawn(async move {
            let p = OwnedPersona {
                nick: nick.clone(),
                realname,
                personality,
            };
            if let Err(e) = run_bot(
                &server, &channel, &p, &topic, &model, &api_key, chat_log, min_delay, max_delay,
                tls,
            )
            .await
            {
                eprintln!("❌ {nick} error: {e}");
            }
        });

        // Stagger connections so they don't all join at once
        tokio::time::sleep(Duration::from_millis(2000)).await;
    }

    println!("All bots connected. Ctrl+C to stop.\n");

    // Wait forever
    tokio::signal::ctrl_c().await?;
    println!("\n👋 Shutting down...");
    Ok(())
}

// ── Bot loop ───────────────────────────────────────────────────────────

async fn run_bot(
    server: &str,
    channel: &str,
    persona: &OwnedPersona,
    topic: &str,
    model: &str,
    api_key: &str,
    chat_log: ChatLog,
    min_delay: u64,
    max_delay: u64,
    tls: bool,
) -> Result<()> {
    let config = ConnectConfig {
        server_addr: server.to_string(),
        nick: persona.nick.clone(),
        user: persona.nick.clone(),
        realname: persona.realname.clone(),
        tls,
        tls_insecure: false,
        web_token: None,
        websocket_url: None,
        ..Default::default()
    };

    let (handle, mut events) = client::connect(config, None);

    // Wait for registration
    loop {
        match tokio::time::timeout(Duration::from_secs(15), events.recv()).await {
            Ok(Some(Event::Registered { .. })) => break,
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("{}: connection closed during registration", persona.nick),
            Err(_) => anyhow::bail!("{}: registration timeout", persona.nick),
        }
    }

    println!("  ✅ {} ({}) joined", persona.nick, persona.realname);

    // Join channel
    handle.join(channel).await?;

    // Drain initial flood (MOTD, NAMES, topic, history)
    tokio::time::sleep(Duration::from_secs(3)).await;
    while events.try_recv().is_ok() {}

    let system_prompt = build_system_prompt(persona, topic);
    let mut rng = rand::rngs::StdRng::from_entropy();

    // Stagger first message
    tokio::time::sleep(Duration::from_secs(rng.gen_range(3..12))).await;

    loop {
        // Build context from recent chat
        let prompt = build_prompt(&chat_log, &persona.nick).await;

        // Generate and send message
        match llm::complete(api_key, model, &system_prompt, &prompt, 150).await {
            Ok(raw) => {
                let msg = clean_response(&raw, &persona.nick);
                if !msg.is_empty() {
                    send_message(&handle, channel, &persona.nick, &msg).await;
                    // Record in shared log
                    let display = if let Some(action) = msg.strip_prefix("/me ") {
                        format!("* {} {action}", persona.nick)
                    } else {
                        msg.clone()
                    };
                    let mut log = chat_log.lock().await;
                    log.push_back((persona.nick.to_string(), display));
                    if log.len() > 60 {
                        log.pop_front();
                    }
                }
            }
            Err(e) => {
                eprintln!("  ⚠ {} LLM error: {e:#}", persona.nick);
                // Back off on errors
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }

        // Drain incoming events into shared log
        drain_events(&mut events, &chat_log, &persona.nick).await;

        // Random delay
        let delay = rng.gen_range(min_delay..=max_delay);
        tokio::time::sleep(Duration::from_secs(delay)).await;

        // Drain again after sleeping
        drain_events(&mut events, &chat_log, &persona.nick).await;
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

fn build_system_prompt(persona: &OwnedPersona, topic: &str) -> String {
    format!(
        r#"You are {nick} hanging out in an IRC channel with friends. Here's who you are:

{personality}

Channel vibe: {topic}

This is a casual hangout — talk about ANYTHING. Life, hobbies, food, music, movies, \
travel, funny stories, hot takes, weekend plans, random observations. You happen to be \
developers but this isn't a work channel. Be yourself. Be fun. Riff off each other.

RULES:
- Output ONLY your next message. No prefix, no quotes, no meta-commentary.
- Keep it SHORT — 1-2 sentences. This is IRC chat, not a blog post.
- Be genuinely fun and conversational. Joke around. Tease people. Be warm.
- React to others naturally. Build on jokes. Start new tangents.
- About 1 in 8 messages, share a FULLY FORMED URL (must start with https://):
  • YouTube: https://www.youtube.com/watch?v=dQw4w9WgXcQ (use REAL video IDs you know)
  • Images: https://i.imgur.com/XXXXX.jpg (make up plausible 5-7 char hash)
  • xkcd: https://xkcd.com/927/ (use real xkcd numbers you know)
  • Reddit: https://www.reddit.com/r/programming/comments/...
  • Bluesky: https://bsky.app/profile/someone.bsky.social/post/...
  • GitHub: https://github.com/real-org/real-project
  • News/blogs: real URLs you know (arstechnica, theverge, etc.)
- You can use /me for actions: /me puts on coffee
- Mix it up: short reactions ("lol", "oh god", "wait what", "hahaha", "same"), \
  opinions, stories, questions, jokes, links.
- NEVER break character. NEVER explain what you're doing. NEVER use quotes around your message.
- Don't all talk about the same thing forever — change subjects naturally like real people do."#,
        nick = persona.nick,
        personality = persona.personality,
        topic = topic,
    )
}

async fn build_prompt(chat_log: &ChatLog, my_nick: &str) -> String {
    let log = chat_log.lock().await;
    if log.is_empty() {
        return "The channel has been quiet. Say something to get things going.".to_string();
    }
    let recent: Vec<String> = log
        .iter()
        .map(|(nick, msg)| {
            if nick == my_nick {
                format!("<{nick}> {msg}  [you]")
            } else {
                format!("<{nick}> {msg}")
            }
        })
        .collect();
    format!(
        "Recent chat:\n{}\n\nWrite your next message as {}:",
        recent.join("\n"),
        my_nick
    )
}

fn clean_response(raw: &str, nick: &str) -> String {
    let mut msg = raw.trim().to_string();

    // Strip accidental self-prefix patterns
    for prefix in [
        format!("<{nick}> "),
        format!("{nick}: "),
        format!("[{nick}] "),
    ] {
        if let Some(rest) = msg.strip_prefix(&prefix) {
            msg = rest.to_string();
        }
    }

    // Strip surrounding quotes
    if msg.len() > 2
        && ((msg.starts_with('"') && msg.ends_with('"'))
            || (msg.starts_with('\'') && msg.ends_with('\'')))
    {
        msg = msg[1..msg.len() - 1].to_string();
    }

    // Truncate overly long messages (IRC limit ~)
    if msg.len() > 400 {
        msg.truncate(400);
        if let Some(last_space) = msg.rfind(' ') {
            msg.truncate(last_space);
        }
    }

    msg
}

async fn send_message(handle: &ClientHandle, channel: &str, nick: &str, msg: &str) {
    if let Some(action) = msg.strip_prefix("/me ") {
        let ctcp = format!("\x01ACTION {action}\x01");
        let _ = handle.privmsg(channel, &ctcp).await;
        println!("  \x1b[36m* {nick}\x1b[0m {action}");
    } else {
        let _ = handle.privmsg(channel, msg).await;
        println!("  \x1b[32m<{nick}>\x1b[0m {msg}");
    }
}

async fn drain_events(
    events: &mut tokio::sync::mpsc::Receiver<Event>,
    chat_log: &ChatLog,
    my_nick: &str,
) {
    while let Ok(event) = events.try_recv() {
        if let Event::Message {
            from, text, target, ..
        } = event
        {
            // Only log channel messages from others
            if from != my_nick && target.starts_with('#') {
                let mut log = chat_log.lock().await;
                log.push_back((from, text));
                if log.len() > 60 {
                    log.pop_front();
                }
            }
        }
    }
}
