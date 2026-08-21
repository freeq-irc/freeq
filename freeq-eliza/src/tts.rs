//! Text-to-speech via the ElevenLabs API.
//!
//! `synthesize` turns a string into mono f32 PCM. We request
//! `pcm_48000` output — raw, headerless, 16-bit signed-LE mono at
//! 48 kHz — which is exactly the bot's broadcast rate, so the speak
//! path needs no resampling and no container decoding at all.

use anyhow::{Context, Result};

/// Decoded TTS audio: mono f32 PCM plus its sample rate.
pub struct TtsAudio {
    pub pcm: Vec<f32>,
    pub sample_rate: u32,
}

/// ElevenLabs `pcm_48000` is raw 16-bit signed-LE mono at 48 kHz.
pub const ELEVENLABS_PCM_RATE: u32 = 48_000;

/// The ElevenLabs request body — shared by the buffered and streaming
/// synthesizers.
fn tts_body(model: &str, text: &str) -> serde_json::Value {
    // Playback speed (ElevenLabs voice_settings.speed, range ~0.7–1.2).
    // Overridable per-launch via ELEVENLABS_SPEED so a deployment can make the
    // voice snappier without a rebuild; defaults to the prior 1.02.
    let speed: f32 = std::env::var("ELEVENLABS_SPEED")
        .ok()
        .and_then(|s| s.trim().parse::<f32>().ok())
        .map(|s| s.clamp(0.7, 1.2))
        .unwrap_or(1.02);
    serde_json::json!({
        "text": text,
        "model_id": model,
        "voice_settings": {
            "stability": 0.7,
            "similarity_boost": 0.75,
            "speed": speed,
        },
    })
}

/// Decodes a stream of raw s16le PCM bytes that may be split at *any*
/// byte boundary. A network chunk can end mid-sample (an odd byte
/// count); that dangling byte is carried into the next [`push`] so the
/// 16-bit framing never desyncs.
///
/// [`push`]: PcmStreamDecoder::push
#[derive(Default)]
pub struct PcmStreamDecoder {
    /// A dangling low byte from the previous chunk, awaiting its high byte.
    carry: Option<u8>,
}

impl PcmStreamDecoder {
    /// Decode the next run of stream bytes to f32 PCM, carrying any
    /// trailing odd byte forward.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<f32> {
        let mut buf = Vec::with_capacity(bytes.len() + 1);
        if let Some(b) = self.carry.take() {
            buf.push(b);
        }
        buf.extend_from_slice(bytes);
        if buf.len() % 2 == 1 {
            self.carry = Some(buf[buf.len() - 1]);
            buf.pop();
        }
        decode_pcm_s16le(&buf)
    }
}

/// Stream a synthesis from ElevenLabs, handing decoded PCM to `on_pcm`
/// as each network chunk arrives — so the agent can start speaking
/// before synthesis finishes.
///
/// Same voice/model/output as [`synthesize`], but the `/stream`
/// endpoint. `on_pcm` is called repeatedly with mono f32 PCM at
/// [`ELEVENLABS_PCM_RATE`]; returns the total sample count.
pub async fn synthesize_streaming(
    client: &reqwest::Client,
    api_key: &str,
    voice_id: &str,
    model: &str,
    text: &str,
    mut on_pcm: impl FnMut(&[f32]),
) -> Result<usize> {
    let url = format!(
        "https://api.elevenlabs.io/v1/text-to-speech/{voice_id}/stream?output_format=pcm_48000"
    );
    let mut resp = client
        .post(&url)
        .header("xi-api-key", api_key)
        .json(&tts_body(model, text))
        .send()
        .await
        .context("elevenlabs streaming TTS request failed")?;

    let status = resp.status();
    if !status.is_success() {
        let err = resp.text().await.unwrap_or_default();
        anyhow::bail!("elevenlabs streaming TTS {status}: {err}");
    }

    let mut decoder = PcmStreamDecoder::default();
    let mut total = 0usize;
    while let Some(chunk) = resp
        .chunk()
        .await
        .context("reading elevenlabs TTS stream")?
    {
        let pcm = decoder.push(&chunk);
        if !pcm.is_empty() {
            total += pcm.len();
            on_pcm(&pcm);
        }
    }
    Ok(total)
}

/// Synthesize `text` with ElevenLabs. `voice_id` is the ElevenLabs
/// voice (e.g. the "Eliza" voice). `model` is e.g.
/// `eleven_turbo_v2_5`. Voice tuning matches the avatar app's
/// settings. Returns mono f32 PCM at [`ELEVENLABS_PCM_RATE`].
pub async fn synthesize(
    client: &reqwest::Client,
    api_key: &str,
    voice_id: &str,
    model: &str,
    text: &str,
) -> Result<TtsAudio> {
    let url =
        format!("https://api.elevenlabs.io/v1/text-to-speech/{voice_id}?output_format=pcm_48000");
    let resp = client
        .post(&url)
        .header("xi-api-key", api_key)
        .json(&tts_body(model, text))
        .send()
        .await
        .context("elevenlabs TTS request failed")?;

    let status = resp.status();
    if !status.is_success() {
        let err = resp.text().await.unwrap_or_default();
        anyhow::bail!("elevenlabs TTS {status}: {err}");
    }
    let bytes = resp.bytes().await.context("reading elevenlabs TTS body")?;
    Ok(TtsAudio {
        pcm: decode_pcm_s16le(&bytes),
        sample_rate: ELEVENLABS_PCM_RATE,
    })
}

/// Decode raw 16-bit signed little-endian PCM into f32 `[-1, 1]`. A
/// trailing odd byte (shouldn't happen for valid PCM) is ignored.
pub(crate) fn decode_pcm_s16le(data: &[u8]) -> Vec<f32> {
    let (samples, _) = data.as_chunks::<2>();
    samples
        .iter()
        .map(|b| i16::from_le_bytes(*b) as f32 / 32768.0)
        .collect()
}

/// Encode mono f32 PCM as a 16-bit WAV byte stream. Used only to dump
/// the exact audio the bot is about to speak, so a "static" report can
/// be bisected: a clean dumped WAV proves the static is introduced
/// downstream (Opus encode / transport / playout), not in TTS.
pub fn encode_wav(pcm: &[f32], sample_rate: u32) -> Vec<u8> {
    let data_len = (pcm.len() * 2) as u32;
    let mut out = Vec::with_capacity(44 + data_len as usize);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36 + data_len).to_le_bytes());
    out.extend_from_slice(b"WAVE");
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&16u32.to_le_bytes()); // fmt chunk size
    out.extend_from_slice(&1u16.to_le_bytes()); // PCM
    out.extend_from_slice(&1u16.to_le_bytes()); // mono
    out.extend_from_slice(&sample_rate.to_le_bytes());
    out.extend_from_slice(&(sample_rate * 2).to_le_bytes()); // byte rate
    out.extend_from_slice(&2u16.to_le_bytes()); // block align
    out.extend_from_slice(&16u16.to_le_bytes()); // bits per sample
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_len.to_le_bytes());
    for &s in pcm {
        let v = (s.clamp(-1.0, 1.0) * 32767.0) as i16;
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_raw_s16le_pcm() {
        // 0, +half, -half, +max, -max
        let mut raw = Vec::new();
        for s in [0i16, 16384, -16384, 32767, -32768] {
            raw.extend_from_slice(&s.to_le_bytes());
        }
        let pcm = decode_pcm_s16le(&raw);
        assert_eq!(pcm.len(), 5);
        assert!((pcm[0] - 0.0).abs() < 1e-6);
        assert!((pcm[1] - 0.5).abs() < 1e-3);
        assert!((pcm[2] + 0.5).abs() < 1e-3);
        assert!(pcm[3] > 0.99 && pcm[3] <= 1.0);
        assert!((pcm[4] + 1.0).abs() < 1e-6);
    }

    #[test]
    fn raw_pcm_ignores_trailing_odd_byte() {
        // 3 bytes → one i16 sample + a dangling byte that must be dropped.
        let pcm = decode_pcm_s16le(&[0x00, 0x40, 0x7f]);
        assert_eq!(pcm.len(), 1);
        assert!((pcm[0] - 0.5).abs() < 1e-3);
    }

    #[test]
    fn raw_pcm_empty_input() {
        assert!(decode_pcm_s16le(&[]).is_empty());
    }

    // ---------- PcmStreamDecoder ----------

    /// Splitting a PCM byte stream at arbitrary (including odd) offsets
    /// must decode to exactly the same samples as decoding it whole.
    #[test]
    fn stream_decoder_survives_splits_at_odd_offsets() {
        let mut raw = Vec::new();
        for s in 0i16..200 {
            raw.extend_from_slice(&s.to_le_bytes());
        }
        let whole = decode_pcm_s16le(&raw);

        // Split at every offset, odd ones included — the worst case for
        // 16-bit framing.
        for split in 0..raw.len() {
            let mut dec = PcmStreamDecoder::default();
            let mut got = dec.push(&raw[..split]);
            got.extend(dec.push(&raw[split..]));
            assert_eq!(got, whole, "split at {split}");
        }
    }

    #[test]
    fn stream_decoder_handles_many_tiny_chunks() {
        let mut raw = Vec::new();
        for s in [-32768i16, -1, 0, 1, 32767, 12345, -9999] {
            raw.extend_from_slice(&s.to_le_bytes());
        }
        let whole = decode_pcm_s16le(&raw);
        // One byte at a time — every push but the last carries.
        let mut dec = PcmStreamDecoder::default();
        let mut got = Vec::new();
        for b in &raw {
            got.extend(dec.push(std::slice::from_ref(b)));
        }
        assert_eq!(got, whole);
    }

    #[test]
    fn stream_decoder_empty_push_is_inert() {
        let mut dec = PcmStreamDecoder::default();
        assert!(dec.push(&[]).is_empty());
        // A lone byte carries; the empty push must not flush or drop it.
        assert!(dec.push(&[0x34]).is_empty());
        assert!(dec.push(&[]).is_empty());
        let out = dec.push(&[0x12]);
        assert_eq!(out, vec![i16::from_le_bytes([0x34, 0x12]) as f32 / 32768.0]);
    }

    #[test]
    fn encode_wav_has_valid_header_and_round_trips() {
        let pcm = vec![0.0, 0.5, -0.5, 1.0, -1.0];
        let wav = encode_wav(&pcm, 48_000);
        // 44-byte header + 2 bytes per sample.
        assert_eq!(wav.len(), 44 + pcm.len() * 2);
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[36..40], b"data");
        // Sample rate (offset 24) round-trips.
        assert_eq!(
            u32::from_le_bytes([wav[24], wav[25], wav[26], wav[27]]),
            48_000
        );
        // Decoding the data section back yields the originals.
        let decoded = decode_pcm_s16le(&wav[44..]);
        for (a, b) in pcm.iter().zip(&decoded) {
            assert!((a - b).abs() < 1.0 / 32767.0, "{a} vs {b}");
        }
    }
}
