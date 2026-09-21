//! Demo: streaming message via the IRC edit-message hack.
//! Sends a message that types out word-by-word in real time.

use anyhow::Result;
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::event::Event;
use freeq_sdk::streaming::StreamingMessage;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let channel = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "#freeq".to_string());
    let message = std::env::args().nth(2).unwrap_or_else(|| {
        "Hello from the streaming message demo! This message is being typed out word by word using the IRC edit-message hack. Each update edits the same message in place. Pretty cool, right? 🚀".to_string()
    });

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
            Some(Event::Joined {
                channel: ch, nick, ..
            }) => {
                eprintln!("Joined {ch} as {nick}");
                break;
            }
            Some(Event::ServerNotice { text }) => {
                eprintln!("Server: {text}");
            }
            Some(Event::Disconnected { reason }) => {
                anyhow::bail!("Disconnected: {reason}");
            }
            Some(other) => {
                eprintln!("Event: {other:?}");
            }
            None => anyhow::bail!("Event channel closed"),
        }
    }

    // Small delay for server to settle
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain any remaining join events
    while let Ok(evt) = tokio::time::timeout(Duration::from_millis(200), events.recv()).await {
        if let Some(e) = evt {
            eprintln!("Drain: {e:?}");
        }
    }

    eprintln!("Starting stream in {channel}...");

    // Start a streaming message
    let mut stream = StreamingMessage::start(&handle, &channel).await?;
    eprintln!("Got msgid: {}", stream.msgid());

    // Type out word by word
    let words: Vec<&str> = message.split_whitespace().collect();
    let mut accumulated = String::new();
    for (i, word) in words.iter().enumerate() {
        if i > 0 {
            accumulated.push(' ');
        }
        accumulated.push_str(word);
        stream.set(&accumulated).await?;
        // Force flush so it's visible
        stream.flush().await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Finish — removes cursor and streaming indicator
    let msgid = stream.finish_with(&accumulated).await?;
    eprintln!("Stream complete! Final msgid: {msgid}");

    tokio::time::sleep(Duration::from_secs(1)).await;
    handle.quit(Some("Stream demo complete")).await?;
    Ok(())
}
