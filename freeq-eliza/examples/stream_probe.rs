//! Unquestionable end-to-end probe for the Deepgram streaming-STT path.
//!
//! Reads a 16 kHz mono 16-bit PCM WAV, runs it through the EXACT same
//! conditioning the in-call tap uses (`stt::to_whisper_pcm` →
//! `streaming_stt::f32_mono_to_i16le`), streams it to Deepgram over the
//! real websocket (`streaming_stt::connect`/`send_pcm`) at ~real-time
//! pacing, and prints every finalised transcript. If the transcript
//! matches the spoken words, the streaming path is proven — no mic, no
//! client, no call. Run on the VM so it uses the VM's key + network:
//!
//!   DEEPGRAM_API_KEY=… cargo run --release --offline --example stream_probe -- /tmp/probe.wav

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::StreamExt;
use iroh_live::media::format::AudioFormat;
use tokio_tungstenite::tungstenite::Message;

use freeq_eliza::streaming_stt::{
    StreamingSttConfig, close_stream, connect, f32_mono_to_i16le, parse_final_transcript,
};
use freeq_eliza::stt::to_whisper_pcm;

#[tokio::main]
async fn main() -> Result<()> {
    // Same rustls provider the eliza binary installs at startup — without
    // it tokio-tungstenite's TLS handshake panics (the in-call path works
    // because main.rs installs this; the standalone example must too).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let path = std::env::args()
        .nth(1)
        .context("usage: stream_probe <wav>")?;
    let key = std::env::var("DEEPGRAM_API_KEY").context("DEEPGRAM_API_KEY not set")?;

    // Read the WAV; strip a 44-byte RIFF header if present, else treat
    // the whole file as raw little-endian 16-bit PCM.
    let raw = std::fs::read(&path).with_context(|| format!("reading {path}"))?;
    let body = if raw.len() > 44 && &raw[0..4] == b"RIFF" {
        &raw[44..]
    } else {
        &raw[..]
    };
    let mut samples = Vec::with_capacity(body.len() / 2);
    for ch in body.chunks_exact(2) {
        samples.push(i16::from_le_bytes([ch[0], ch[1]]) as f32 / 32768.0);
    }
    let peak = samples.iter().fold(0.0f32, |m, &s| m.max(s.abs()));
    println!(
        "[probe] loaded {} samples ({:.2}s @16k), input peak={:.3}",
        samples.len(),
        samples.len() as f32 / 16_000.0,
        peak
    );

    // EXACT tap conditioning: resample/sanitise (no-op at 16k mono) then
    // pack to linear16 in the same per-chunk shape as the live feed.
    let pcm = to_whisper_pcm(
        &samples,
        AudioFormat {
            sample_rate: 16_000,
            channel_count: 1,
        },
    );

    let cfg = StreamingSttConfig::nova_3(key);
    let (mut writer, mut reader) = connect(&cfg).await.context("deepgram connect")?;
    println!("[probe] deepgram connected (nova-3)");

    let t0 = Instant::now();
    let reader_task = tokio::spawn(async move {
        let mut finals = Vec::new();
        while let Some(msg) = reader.next().await {
            match msg {
                Ok(Message::Text(t)) => {
                    if let Some(text) = parse_final_transcript(&t) {
                        println!("[probe] FINAL (+{}ms): {text}", t0.elapsed().as_millis());
                        finals.push(text);
                    }
                }
                Ok(Message::Close(_)) => break,
                Ok(_) => {}
                Err(e) => {
                    eprintln!("[probe] read error: {e}");
                    break;
                }
            }
        }
        finals
    });

    // Stream in ~20 ms chunks (320 samples) at real-time pace, so the
    // server endpointer behaves exactly as it does in a live call.
    for chunk in pcm.chunks(320) {
        send_chunk(&mut writer, chunk).await?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    close_stream(&mut writer).await.context("close stream")?;

    let finals = tokio::time::timeout(Duration::from_secs(6), reader_task)
        .await
        .context("timed out waiting for finals")?
        .context("reader task panicked")?;

    println!("\n[probe] === {} finalised transcript(s) ===", finals.len());
    if finals.is_empty() {
        println!("[probe] NONE — streaming returned no transcript (silence or failure)");
        std::process::exit(1);
    }
    println!("[probe] joined: {}", finals.join(" "));
    Ok(())
}

async fn send_chunk(
    writer: &mut futures_util::stream::SplitSink<freeq_eliza::streaming_stt::WsStream, Message>,
    chunk: &[f32],
) -> Result<()> {
    freeq_eliza::streaming_stt::send_pcm(writer, f32_mono_to_i16le(chunk)).await
}
