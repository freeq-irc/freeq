//! Load test for freeq IRC server.
//!
//! Validates message delivery under load: many connections, many channels,
//! high message throughput. Every message has a unique ID embedded in the
//! text; receivers track which IDs they got. At the end, we compare
//! sent vs received and report delivery rate.
//!
//! Usage:
//!   cargo run --release --bin loadtest -- --server 127.0.0.1:6667 --users 100 --channels 5 --messages 50

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use freeq_sdk::client::{ClientHandle, ConnectConfig};
use freeq_sdk::event::Event;
use tokio::sync::{Barrier, Mutex, mpsc};
use tokio::time::timeout;

#[derive(Parser, Debug)]
#[command(name = "loadtest", about = "IRC server load test")]
struct Args {
    /// Server address (host:port)
    #[arg(long, default_value = "127.0.0.1:6667")]
    server: String,

    /// Number of concurrent users
    #[arg(long, default_value = "100")]
    users: usize,

    /// Number of channels to spread users across
    #[arg(long, default_value = "5")]
    channels: usize,

    /// Messages per user to send
    #[arg(long, default_value = "20")]
    messages: usize,

    /// Delay between messages per user (ms)
    #[arg(long, default_value = "100")]
    delay_ms: u64,

    /// Connection stagger delay (ms between each connection)
    #[arg(long, default_value = "20")]
    stagger_ms: u64,

    /// Timeout for the entire test (seconds)
    #[arg(long, default_value = "120")]
    timeout_secs: u64,

    /// Use TLS
    #[arg(long)]
    tls: bool,
}

/// Track sent/received message IDs per channel
struct Tracker {
    /// channel → set of msg IDs sent to that channel
    sent: HashMap<String, HashSet<String>>,
    /// (user_nick, channel) → set of msg IDs received
    received: HashMap<(String, String), HashSet<String>>,
}

impl Tracker {
    fn new() -> Self {
        Self {
            sent: HashMap::new(),
            received: HashMap::new(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let total_msgs = args.users * args.messages;
    let ts = chrono::Utc::now().format("%H%M%S").to_string();

    println!("🔥 freeq load test");
    println!("   Server:     {}", args.server);
    println!("   Users:      {}", args.users);
    println!("   Channels:   {}", args.channels);
    println!("   Msgs/user:  {}", args.messages);
    println!("   Total msgs: {total_msgs}");
    println!("   Delay:      {}ms between msgs", args.delay_ms);
    println!("   Timeout:    {}s", args.timeout_secs);
    println!();

    // Generate channel names
    let channel_names: Vec<String> = (0..args.channels)
        .map(|i| format!("#lt-{ts}-{i}"))
        .collect();

    let tracker = Arc::new(Mutex::new(Tracker::new()));
    let barrier = Arc::new(Barrier::new(args.users));

    // Phase 1: Connect all users
    println!("📡 Connecting {} users...", args.users);
    let start_connect = Instant::now();

    let mut handles: Vec<(ClientHandle, mpsc::Receiver<Event>, String, Vec<String>)> = Vec::new();

    for i in 0..args.users {
        let nick = format!("lt{ts}u{i}");
        // Assign user to 1-2 channels (round-robin + overlap)
        let user_channels: Vec<String> = vec![
            channel_names[i % args.channels].clone(),
            channel_names[(i + 1) % args.channels].clone(),
        ];
        // Dedup if channels == 1
        let user_channels: Vec<String> = user_channels
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let config = ConnectConfig {
            server_addr: args.server.clone(),
            nick: nick.clone(),
            user: nick.clone(),
            realname: format!("Load test user {i}"),
            tls: args.tls,
            tls_insecure: args.tls,
            web_token: None,
            websocket_url: None,
            ..Default::default()
        };

        let (handle, events) = freeq_sdk::client::connect(config, None);
        handles.push((handle, events, nick, user_channels));

        if args.stagger_ms > 0 {
            tokio::time::sleep(Duration::from_millis(args.stagger_ms)).await;
        }
    }

    // Wait for all to register and join channels
    println!("⏳ Waiting for registration + joins...");
    let mut tasks = Vec::new();

    for (handle, mut events, nick, user_channels) in handles {
        let tracker = tracker.clone();
        let barrier = barrier.clone();
        let msg_count = args.messages;
        let delay = Duration::from_millis(args.delay_ms);
        let _test_timeout = Duration::from_secs(args.timeout_secs);

        let task = tokio::spawn(async move {
            let nick = nick.clone();

            // Wait for registration
            let reg_deadline = Instant::now() + Duration::from_secs(30);
            let mut registered = false;
            while Instant::now() < reg_deadline {
                match timeout(Duration::from_secs(5), events.recv()).await {
                    Ok(Some(Event::Registered { .. })) => {
                        registered = true;
                        break;
                    }
                    Ok(Some(Event::Disconnected { reason })) => {
                        eprintln!("  ❌ {nick} disconnected: {reason}");
                        return (nick, false);
                    }
                    Ok(None) => {
                        eprintln!("  ❌ {nick} channel closed");
                        return (nick, false);
                    }
                    _ => continue,
                }
            }
            if !registered {
                eprintln!("  ❌ {nick} registration timeout");
                return (nick, false);
            }

            // Join channels
            for ch in &user_channels {
                let _ = handle.join(ch).await;
            }

            // Wait for NAMES on all channels (confirms join)
            let mut joined = HashSet::new();
            let join_deadline = Instant::now() + Duration::from_secs(15);
            while joined.len() < user_channels.len() && Instant::now() < join_deadline {
                match timeout(Duration::from_secs(5), events.recv()).await {
                    Ok(Some(Event::Names { channel, .. })) => {
                        if user_channels.contains(&channel) {
                            joined.insert(channel);
                        }
                    }
                    Ok(Some(Event::Disconnected { reason })) => {
                        eprintln!("  ❌ {nick} disconnected during join: {reason}");
                        return (nick, false);
                    }
                    Ok(None) => break,
                    _ => continue,
                }
            }
            if joined.len() < user_channels.len() {
                eprintln!(
                    "  ⚠️  {nick} only joined {}/{} channels",
                    joined.len(),
                    user_channels.len()
                );
            }

            // Synchronize: all users wait here before sending
            barrier.wait().await;

            // Spawn receiver task that runs concurrently with sender
            let recv_tracker = tracker.clone();
            let recv_nick = nick.clone();
            let recv_task = tokio::spawn(async move {
                let mut count = 0usize;
                loop {
                    match timeout(Duration::from_secs(15), events.recv()).await {
                        Ok(Some(Event::Message {
                            from: _from,
                            target,
                            text,
                            ..
                        })) => {
                            if let Some(id) = extract_msg_id(&text) {
                                let mut t = recv_tracker.lock().await;
                                t.received
                                    .entry((recv_nick.clone(), target))
                                    .or_default()
                                    .insert(id);
                                count += 1;
                            }
                        }
                        Ok(Some(Event::Disconnected { reason })) => {
                            eprintln!("  ❌ {recv_nick} disconnected: {reason}");
                            break;
                        }
                        Ok(None) => break,
                        Err(_) => break, // timeout — no more messages
                        _ => continue,
                    }
                }
                count
            });

            // Phase 2: Send messages
            for msg_i in 0..msg_count {
                let ch = &user_channels[0];
                let msg_id = format!("{nick}:{msg_i}");
                let text = format!("[{msg_id}] test message");
                let _ = handle.privmsg(ch, &text).await;

                {
                    let mut t = tracker.lock().await;
                    t.sent.entry(ch.clone()).or_default().insert(msg_id);
                }

                if delay > Duration::ZERO {
                    tokio::time::sleep(delay).await;
                }
            }

            // Wait for receiver to drain remaining messages
            let _recv_count = recv_task.await.unwrap_or(0);

            let _ = handle.quit(Some("load test done")).await;
            (nick, true)
        });

        tasks.push(task);
    }

    // Wait for all tasks
    let results = futures::future::join_all(tasks).await;
    let succeeded = results
        .iter()
        .filter(|r| r.as_ref().map(|(_, ok)| *ok).unwrap_or(false))
        .count();
    let failed = args.users - succeeded;

    let elapsed = start_connect.elapsed();

    // Phase 4: Analyze results
    println!();
    println!("📊 Results (elapsed: {:.1}s)", elapsed.as_secs_f64());
    println!("   Users:      {succeeded}/{} connected", args.users);
    if failed > 0 {
        println!("   Failed:     {failed}");
    }

    let t = tracker.lock().await;

    // Count total sent per channel
    let mut total_sent = 0usize;
    for (ch, ids) in &t.sent {
        println!("   Channel {ch}: {} messages sent", ids.len());
        total_sent += ids.len();
    }

    // For each channel, count how many users received all messages
    // Expected: each user in a channel should receive all messages sent to that channel
    // (minus their own, since echo-message is not negotiated by SDK)
    let mut total_expected = 0usize;
    let mut total_received = 0usize;
    let mut total_missing = 0usize;

    for (ch, sent_ids) in &t.sent {
        // Find all users that were in this channel (received at least one msg from it)
        let receivers: Vec<&String> = t
            .received
            .keys()
            .filter(|(_, c)| c == ch)
            .map(|(nick, _)| nick)
            .collect();

        for receiver_nick in &receivers {
            let received_ids = t
                .received
                .get(&((*receiver_nick).clone(), ch.clone()))
                .map(|s| s.len())
                .unwrap_or(0);

            // Expected = all msgs NOT from this user (no echo-message)
            let sent_by_self = sent_ids
                .iter()
                .filter(|id| id.starts_with(&format!("{receiver_nick}:")))
                .count();
            let expected = sent_ids.len() - sent_by_self;

            total_expected += expected;
            total_received += received_ids.min(expected);
            if received_ids < expected {
                total_missing += expected - received_ids;
            }
        }
    }

    let delivery_rate = if total_expected > 0 {
        (total_received as f64 / total_expected as f64) * 100.0
    } else {
        100.0
    };

    println!();
    println!("   Total sent:     {total_sent}");
    println!("   Total expected: {total_expected} (across all receivers)");
    println!("   Total received: {total_received}");
    println!("   Total missing:  {total_missing}");
    println!("   Delivery rate:  {delivery_rate:.1}%");
    println!(
        "   Throughput:     {:.0} msgs/sec",
        total_sent as f64 / elapsed.as_secs_f64()
    );
    println!();

    if delivery_rate >= 99.9 {
        println!("✅ PASS — {delivery_rate:.1}% delivery rate");
    } else if delivery_rate >= 95.0 {
        println!("⚠️  WARN — {delivery_rate:.1}% delivery rate (some message loss)");
    } else {
        println!("❌ FAIL — {delivery_rate:.1}% delivery rate");
        std::process::exit(1);
    }

    Ok(())
}

fn extract_msg_id(text: &str) -> Option<String> {
    // Format: [nick:N] test message
    let start = text.find('[')?;
    let end = text.find(']')?;
    if start < end {
        Some(text[start + 1..end].to_string())
    } else {
        None
    }
}
