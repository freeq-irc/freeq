//! Streaming speech-to-text via Deepgram's websocket API.
//!
//! Per-participant: open one persistent websocket to
//! `wss://api.deepgram.com/v1/listen`, push raw PCM frames in as they
//! arrive, get finalised transcripts back on the same socket as soon as
//! Deepgram's endpointing model decides the utterance is done.
//!
//! Why this beats the local VAD + batched-Whisper path: the local
//! segmenter waits a hard pause of silence to call an utterance "done"
//! before sending it for transcription, and the Groq round-trip adds
//! another 300–500 ms. Deepgram does endpointing server-side at
//! ~200–300 ms and is already mid-transcription before the speaker
//! stops, so the first text arrives within a few hundred ms of the end
//! of speech instead of a full second-plus. That latency cut is what
//! makes the being feel like it's actually listening, not buffering.
//!
//! We feed Deepgram 16 kHz mono PCM — the same conditioned signal the
//! Whisper path uses (`to_whisper_pcm`), so the resampler/sanitiser is
//! shared and the connection rate is fixed regardless of source format.

use anyhow::{Context, Result, anyhow};
use futures_util::{SinkExt, StreamExt, stream::SplitSink, stream::SplitStream};
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Bytes, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// What sample rate we hand Deepgram. We always resample to 16 kHz mono
/// before sending (see `to_whisper_pcm`), so this is fixed.
pub const STREAM_SAMPLE_RATE: u32 = 16_000;

#[derive(Debug, Clone)]
pub struct StreamingSttConfig {
    pub api_key: String,
    pub model: String,
    /// PCM sample rate we send (always 16 kHz here).
    pub sample_rate: u32,
}

impl StreamingSttConfig {
    pub fn nova_3(api_key: String) -> Self {
        Self {
            api_key,
            model: "nova-3".to_string(),
            sample_rate: STREAM_SAMPLE_RATE,
        }
    }
}

/// Connect a participant-scoped stream. Returns a (writer, reader)
/// split — the caller feeds PCM into the writer, reads finalised
/// transcripts off the reader.
pub async fn connect(
    cfg: &StreamingSttConfig,
) -> Result<(SplitSink<WsStream, Message>, SplitStream<WsStream>)> {
    let url = format!(
        "wss://api.deepgram.com/v1/listen\
         ?model={model}\
         &encoding=linear16\
         &sample_rate={rate}\
         &channels=1\
         &punctuate=true\
         &smart_format=true\
         &interim_results=false\
         &endpointing=300\
         &vad_events=false",
        model = cfg.model,
        rate = cfg.sample_rate,
    );
    let url_for_err = url.clone();
    let mut req = url
        .into_client_request()
        .with_context(|| format!("building deepgram request: {url_for_err}"))?;
    req.headers_mut().insert(
        "Authorization",
        format!("Token {}", cfg.api_key)
            .parse()
            .context("Token header value")?,
    );
    let (ws, _resp) = connect_async(req)
        .await
        .context("deepgram websocket connect")?;
    let (writer, reader) = ws.split();
    Ok((writer, reader))
}

/// Convert mono f32 [-1,1] PCM (already resampled to 16 kHz) to
/// little-endian 16-bit PCM — the shape Deepgram wants for
/// `encoding=linear16`. Non-finite samples are coerced to 0.
pub fn f32_mono_to_i16le(samples: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(samples.len() * 2);
    for &s in samples {
        let s = if s.is_finite() { s } else { 0.0 };
        let i = (s.clamp(-1.0, 1.0) * 32767.0) as i16;
        out.extend_from_slice(&i.to_le_bytes());
    }
    out
}

/// Deepgram response envelope — we only care about the `Results`
/// variant's `is_final` transcripts.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum DeepgramResponse {
    Results(ResultsBody),
    /// Other variants (Metadata, SpeechStarted, UtteranceEnd, Error) —
    /// we don't react to them today but tag-based deserialize keeps the
    /// stream parse-able without dropping the connection.
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
struct ResultsBody {
    channel: ResultsChannel,
    is_final: bool,
}

#[derive(Debug, Deserialize)]
struct ResultsChannel {
    alternatives: Vec<ResultsAlt>,
}

#[derive(Debug, Deserialize)]
struct ResultsAlt {
    #[serde(default)]
    transcript: String,
}

/// Parse one inbound message; return Some(text) on a finalised
/// utterance with non-empty text, None for any other message.
pub fn parse_final_transcript(text: &str) -> Option<String> {
    let resp: DeepgramResponse = serde_json::from_str(text).ok()?;
    let DeepgramResponse::Results(body) = resp else {
        return None;
    };
    if !body.is_final {
        return None;
    }
    let alt = body.channel.alternatives.into_iter().next()?;
    let t = alt.transcript.trim().to_string();
    if t.is_empty() { None } else { Some(t) }
}

/// Send a CloseStream control frame so Deepgram returns final
/// transcripts and closes cleanly.
pub async fn close_stream(writer: &mut SplitSink<WsStream, Message>) -> Result<()> {
    writer
        .send(Message::Text(
            r#"{"type":"CloseStream"}"#.to_string().into(),
        ))
        .await
        .context("sending CloseStream")
}

/// Send a chunk of raw little-endian 16-bit PCM.
pub async fn send_pcm(writer: &mut SplitSink<WsStream, Message>, pcm_le: Vec<u8>) -> Result<()> {
    if pcm_le.is_empty() {
        return Ok(());
    }
    writer
        .send(Message::Binary(Bytes::from(pcm_le)))
        .await
        .map_err(|e| anyhow!("deepgram send: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_finalised_text() {
        let raw = r#"{"type":"Results","channel":{"alternatives":[{"transcript":"hello there"}]},"is_final":true,"speech_final":true,"duration":1.2}"#;
        assert_eq!(parse_final_transcript(raw).as_deref(), Some("hello there"));
    }

    #[test]
    fn drops_partial_results() {
        let raw = r#"{"type":"Results","channel":{"alternatives":[{"transcript":"hello"}]},"is_final":false}"#;
        assert!(parse_final_transcript(raw).is_none());
    }

    #[test]
    fn drops_empty_finalised() {
        let raw =
            r#"{"type":"Results","channel":{"alternatives":[{"transcript":""}]},"is_final":true}"#;
        assert!(parse_final_transcript(raw).is_none());
    }

    #[test]
    fn ignores_other_message_types() {
        assert!(parse_final_transcript(r#"{"type":"Metadata","request_id":"abc"}"#).is_none());
        assert!(parse_final_transcript(r#"{"type":"SpeechStarted","channel":[0]}"#).is_none());
    }

    #[test]
    fn pcm_conversion_clamps_and_packs() {
        let samples = [0.0_f32, 1.0, -1.0, 0.5, f32::NAN, f32::INFINITY];
        let bytes = f32_mono_to_i16le(&samples);
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[0..2], &[0x00, 0x00]); // 0.0
        assert_eq!(&bytes[2..4], &[0xFF, 0x7F]); // 1.0 → 32767
        assert_eq!(&bytes[4..6], &[0x01, 0x80]); // -1.0 → -32767
        assert_eq!(&bytes[6..8], &[0xFF, 0x3F]); // 0.5 → 16383
        assert_eq!(&bytes[8..10], &[0x00, 0x00]); // NaN → 0
        assert_eq!(&bytes[10..12], &[0x00, 0x00]); // ∞ → 0
    }
}
