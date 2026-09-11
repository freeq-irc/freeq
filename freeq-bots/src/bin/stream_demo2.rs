//! Two-sentence streaming demo: stream sentence 1, then sentence 2 as a new message.

use anyhow::Result;
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::event::Event;
use freeq_sdk::streaming::StreamingMessage;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let channel = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "#general".to_string());

    eprintln!("Connecting to irc.freeq.at:6697...");

    let config = ConnectConfig {
        server_addr: "irc.freeq.at:6697".to_string(),
        nick: "stream-demo".to_string(),
        user: "stream-demo".to_string(),
        realname: "Streaming Message Demo".to_string(),
        tls: true,
        tls_insecure: false,
        web_token: None,
        websocket_url: None,
        ..Default::default()
    };

    let conn = client::establish_connection(&config).await?;
    let (handle, mut events) = client::connect_with_stream(conn, config, None);

    // Wait for registration, then join
    loop {
        match events.recv().await {
            Some(Event::Registered { nick }) => {
                eprintln!("Registered as {nick}");
                handle.join(&channel).await?;
            }
            Some(Event::Joined { channel: ch, .. }) => {
                eprintln!("Joined {ch}");
                break;
            }
            Some(Event::Disconnected { reason }) => anyhow::bail!("Disconnected: {reason}"),
            _ => continue,
        }
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    // Drain join history
    while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(200), events.recv()).await {}

    // === Sentence 1 ===
    let sentence1 = "So here is the thing about streaming messages over IRC: it turns out you can abuse the edit-message spec to create a ChatGPT-like typing effect, and it actually works surprisingly well.";

    eprintln!("Streaming sentence 1...");
    let mut stream = StreamingMessage::start(&handle, &channel).await?;
    eprintln!("Got msgid: {}", stream.msgid());

    let words: Vec<&str> = sentence1.split_whitespace().collect();
    let mut acc = String::new();
    for (i, word) in words.iter().enumerate() {
        if i > 0 {
            acc.push(' ');
        }
        acc.push_str(word);
        stream.set(&acc).await?;
        stream.flush().await?;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let msgid1 = stream.finish_with(&acc).await?;
    eprintln!("Sentence 1 done: {msgid1}");

    // Pause between sentences
    tokio::time::sleep(Duration::from_secs(2)).await;

    // === Sentence 2 ===
    let sentence2 = "The trick is simple — send one message, grab its msgid from the echo, then keep editing that same message as new tokens arrive. Clients that support draft/edit see it update in place. Everyone else just sees the final version. Pretty slick for a 36-year-old protocol. 🚀";

    eprintln!("Streaming sentence 2...");
    let mut stream2 = StreamingMessage::start(&handle, &channel).await?;
    eprintln!("Got msgid: {}", stream2.msgid());

    let words2: Vec<&str> = sentence2.split_whitespace().collect();
    let mut acc2 = String::new();
    for (i, word) in words2.iter().enumerate() {
        if i > 0 {
            acc2.push(' ');
        }
        acc2.push_str(word);
        stream2.set(&acc2).await?;
        stream2.flush().await?;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let msgid2 = stream2.finish_with(&acc2).await?;
    eprintln!("Sentence 2 done: {msgid2}");

    tokio::time::sleep(Duration::from_secs(1)).await;
    handle.quit(Some("Stream demo complete")).await?;
    Ok(())
}
