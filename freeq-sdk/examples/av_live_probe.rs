//! Live production probe: prove the AV signal path (av-state started,
//! av-token, av-error join-failed) on irc.freeq.at with a real guest client.
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::event::Event;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ConnectConfig {
        server_addr: "irc.freeq.at:6697".to_string(),
        nick: "avprobe".to_string(),
        user: "avprobe".to_string(),
        realname: "av live probe".to_string(),
        tls: true,
        ..Default::default()
    };
    let (handle, mut events) = client::connect(config, None);

    let mut registered = false;
    let mut got_started = false;
    let mut got_token = false;
    let mut got_error = false;
    let mut session_id = String::new();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let ev = match timeout(deadline - tokio::time::Instant::now(), events.recv()).await {
            Ok(Some(e)) => e,
            _ => break,
        };
        match &ev {
            Event::Registered { .. } if !registered => {
                registered = true;
                println!("PROBE: registered as guest");
                handle.join("#avprobe-test").await?;
            }
            Event::Joined { channel, .. } if channel == "#avprobe-test" => {
                println!("PROBE: joined {channel}");
                // 1. Prove av-error join-failed for a dead session.
                handle.raw("@+freeq.at/av-join;+freeq.at/av-id=01DEADBEEFDEAD;+freeq.at/av-instance=probe001 TAGMSG #avprobe-test").await?;
            }
            Event::TagMsg { tags, .. } => {
                if let Some(code) = tags.get("+freeq.at/av-error") {
                    println!(
                        "PROBE: got av-error={code} av-id={:?} reason={:?}",
                        tags.get("+freeq.at/av-id"),
                        tags.get("+freeq.at/av-reason")
                    );
                    got_error = true;
                    // 2. Now start a REAL session and expect started + token.
                    handle.raw("@+freeq.at/av-start;+freeq.at/av-instance=probe001 TAGMSG #avprobe-test").await?;
                }
                if tags.get("+freeq.at/av-state").map(String::as_str) == Some("started") {
                    session_id = tags.get("+freeq.at/av-id").cloned().unwrap_or_default();
                    println!("PROBE: got av-state=started id={session_id}");
                    got_started = true;
                }
                if let Some(tok) = tags.get("+freeq.at/av-token") {
                    println!(
                        "PROBE: got av-token ({} chars) for {:?}",
                        tok.len(),
                        tags.get("+freeq.at/av-id")
                    );
                    got_token = true;
                    // Clean up: end the probe session.
                    handle
                        .raw(&format!(
                            "@+freeq.at/av-end;+freeq.at/av-id={session_id} TAGMSG #avprobe-test"
                        ))
                        .await?;
                }
                if tags.get("+freeq.at/av-state").map(String::as_str) == Some("ended") && got_token
                {
                    println!("PROBE: session ended cleanly");
                    break;
                }
            }
            _ => {}
        }
    }

    println!(
        "RESULT: registered={registered} av_error={got_error} started={got_started} token={got_token}"
    );
    if registered && got_error && got_started && got_token {
        println!("LIVE PROBE PASSED");
        Ok(())
    } else {
        anyhow::bail!("LIVE PROBE FAILED");
    }
}
