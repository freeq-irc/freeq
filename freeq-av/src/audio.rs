//! Audio primitives for freeq AV agents.
//!
//! Two halves:
//!
//! - **Capture** — [`TapBackend`] is an `AudioStreamFactory` that, instead
//!   of playing remote audio back, forwards every decoded PCM buffer to a
//!   channel. Build one per remote broadcast so each tap carries only
//!   that participant's samples.
//! - **Publish** — [`Speaker`] + [`PushAudioSource`] are a paired queue:
//!   the source feeds the Opus encoder a continuous stream (silence when
//!   idle), and the speaker lets the agent enqueue audio to say.
//!
//! [`resample_mono`] is the shared band-limited resampler.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use iroh_live::media::format::AudioFormat;
use iroh_live::media::traits::{AudioSink, AudioSinkHandle, AudioSource, AudioStreamFactory};
use tokio::sync::mpsc;

/// A "decoded sample" arriving from one remote track. `format` is
/// included so the consumer can resample (e.g. to whisper's 16 kHz
/// mono) without guessing.
pub struct PcmFrame {
    pub samples: Vec<f32>,
    pub format: AudioFormat,
}

/// Factory that captures PCM. Build one per remote broadcast and pass
/// `&factory` to `RemoteBroadcast::audio`. PCM lands on `rx`.
pub struct TapBackend {
    tx: mpsc::Sender<PcmFrame>,
}

impl TapBackend {
    /// Returns the factory + a receiver. The factory forwards every
    /// `push_samples` call to the receiver. Bounded channel — frames are
    /// dropped on backpressure rather than building a multi-second
    /// queue.
    pub fn channel() -> (Self, mpsc::Receiver<PcmFrame>) {
        let (tx, rx) = mpsc::channel(128);
        (Self { tx }, rx)
    }
}

impl AudioStreamFactory for TapBackend {
    fn create_input(
        &self,
        _format: AudioFormat,
    ) -> futures_util::future::BoxFuture<'static, Result<Box<dyn AudioSource>>> {
        // A tap never publishes audio; we don't need a real mic source,
        // but iroh-live still calls create_input in some paths. Return
        // silence.
        Box::pin(async move { Ok(Box::new(SilentSource) as Box<dyn AudioSource>) })
    }

    fn create_output(
        &self,
        format: AudioFormat,
    ) -> futures_util::future::BoxFuture<'static, Result<Box<dyn AudioSink>>> {
        let tx = self.tx.clone();
        Box::pin(async move {
            Ok(Box::new(TapSink {
                format,
                paused: Arc::new(AtomicBool::new(false)),
                tx,
            }) as Box<dyn AudioSink>)
        })
    }
}

struct TapSink {
    format: AudioFormat,
    paused: Arc<AtomicBool>,
    tx: mpsc::Sender<PcmFrame>,
}

impl AudioSinkHandle for TapSink {
    fn cloned_boxed(&self) -> Box<dyn AudioSinkHandle> {
        Box::new(NullHandle {
            paused: self.paused.clone(),
        })
    }
    fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }
    fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
    }
    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }
    fn toggle_pause(&self) {
        self.paused.fetch_xor(true, Ordering::Relaxed);
    }
}

impl AudioSink for TapSink {
    fn format(&self) -> Result<AudioFormat> {
        Ok(self.format)
    }
    fn push_samples(&mut self, buf: &[f32]) -> Result<()> {
        // Non-blocking send — drop on backpressure. A consumer (e.g.
        // whisper running in the background) can fall behind on a slow
        // box; skipping frames beats wedging the decoder.
        let _ = self.tx.try_send(PcmFrame {
            samples: buf.to_vec(),
            format: self.format,
        });
        Ok(())
    }
    fn handle(&self) -> Box<dyn AudioSinkHandle> {
        Box::new(NullHandle {
            paused: self.paused.clone(),
        })
    }
}

struct NullHandle {
    paused: Arc<AtomicBool>,
}

impl AudioSinkHandle for NullHandle {
    fn cloned_boxed(&self) -> Box<dyn AudioSinkHandle> {
        Box::new(NullHandle {
            paused: self.paused.clone(),
        })
    }
    fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }
    fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
    }
    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }
    fn toggle_pause(&self) {
        self.paused.fetch_xor(true, Ordering::Relaxed);
    }
}

struct SilentSource;
impl AudioSource for SilentSource {
    fn format(&self) -> AudioFormat {
        AudioFormat::mono_48k()
    }
    fn pop_samples(&mut self, buf: &mut [f32]) -> Result<Option<usize>> {
        for s in buf.iter_mut() {
            *s = 0.0;
        }
        Ok(Some(buf.len()))
    }
}

// ── Publish side: PushAudioSource + Speaker ─────────────────────────

/// Sample rate the agent's outbound broadcast runs at. 48 kHz — the
/// universal Opus rate every other freeq client (iOS mic, web mic)
/// publishes at and that receivers' Opus decoders expect from the
/// catalog. Publishing at a non-48 kHz rate decodes to silence on the
/// receivers. TTS output at a different rate (e.g. 24 kHz Orpheus) is
/// upsampled to this with [`resample_mono`] — a naïve linear resampler
/// leaves audible imaging artifacts ("bad-radio static").
pub const SPEAK_RATE: u32 = 48_000;

/// The publish-side audio source for the agent's own broadcast. The
/// Opus encoder pulls `pop_samples` continuously; it serves queued
/// audio when there's any, silence otherwise. A continuous stream
/// (silence included) keeps subscribers attached so there's no join
/// latency when the agent does speak.
///
/// `Clone` shares the same queue — so a reconnect loop can hand a fresh
/// clone to each new broadcast while the [`Speaker`] keeps feeding the
/// one queue.
#[derive(Clone)]
pub struct PushAudioSource {
    queue: Arc<std::sync::Mutex<std::collections::VecDeque<f32>>>,
    /// Smoothed loudness of what the encoder just pulled, `[0,1]` as
    /// `f32` bits — read by a video presence so it can pulse with the
    /// agent's voice.
    level: Arc<std::sync::atomic::AtomicU32>,
}

impl AudioSource for PushAudioSource {
    fn format(&self) -> AudioFormat {
        AudioFormat {
            sample_rate: SPEAK_RATE,
            channel_count: 1,
        }
    }
    fn pop_samples(&mut self, buf: &mut [f32]) -> Result<Option<usize>> {
        {
            let mut q = self.queue.lock().expect("speak queue poisoned");
            for slot in buf.iter_mut() {
                *slot = q.pop_front().unwrap_or(0.0);
            }
        }
        // Track loudness for a video presence: snap up fast, ease down
        // slow — reads like an audio meter.
        let peak = buf.iter().fold(0.0f32, |m, &s| m.max(s.abs()));
        let prev = f32::from_bits(self.level.load(Ordering::Relaxed));
        let smoothed = if peak > prev {
            peak
        } else {
            prev * 0.88 + peak * 0.12
        };
        self.level.store(smoothed.to_bits(), Ordering::Relaxed);
        Ok(Some(buf.len()))
    }
}

/// Handle the agent uses to make its broadcast speak. Clone-cheap; the
/// underlying queue is shared with the [`PushAudioSource`] feeding the
/// encoder.
#[derive(Clone)]
pub struct Speaker {
    queue: Arc<std::sync::Mutex<std::collections::VecDeque<f32>>>,
}

impl Speaker {
    /// Create a paired `(Speaker, PushAudioSource)`. The source goes to
    /// the broadcast; the speaker is kept by the orchestrator. `level`
    /// is shared so a video presence can track the agent's own speech.
    pub fn new(level: Arc<std::sync::atomic::AtomicU32>) -> (Speaker, PushAudioSource) {
        let queue = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
        (
            Speaker {
                queue: queue.clone(),
            },
            PushAudioSource { queue, level },
        )
    }

    /// Queue `pcm` (mono, at `from_rate`) for playback. Resampled to
    /// [`SPEAK_RATE`] and appended — concurrent enqueues just play one
    /// after another.
    pub fn enqueue(&self, pcm: &[f32], from_rate: u32) {
        let resampled = resample_mono(pcm, from_rate, SPEAK_RATE);
        let mut q = self.queue.lock().expect("speak queue poisoned");
        q.extend(resampled);
    }

    /// True while there's still queued audio the encoder hasn't drained.
    pub fn is_speaking(&self) -> bool {
        !self.queue.lock().expect("speak queue poisoned").is_empty()
    }

    /// Drop all queued audio — the agent stops speaking immediately.
    /// Used for barge-in: when a participant re-addresses the agent
    /// mid-answer, the rest of the current reply is discarded so it can
    /// respond to the new prompt instead of talking over it.
    pub fn clear(&self) {
        self.queue.lock().expect("speak queue poisoned").clear();
    }

    /// Approximate seconds of audio still queued — used to wait out a
    /// reply before tearing the broadcast down.
    pub fn queued_secs(&self) -> f32 {
        self.queue.lock().expect("speak queue poisoned").len() as f32 / SPEAK_RATE as f32
    }
}

/// Windowed-sinc mono resampler. The shared resampler for both the
/// whisper downsample path and the TTS-playback upsample path.
///
/// Naïve linear interpolation leaves strong spectral images when
/// upsampling (the source's content mirrored above its Nyquist) — on
/// speech that's audible as fizzy/static-y sibilants. A windowed-sinc
/// kernel is the correct band-limited interpolator: for each output
/// sample it sums `2*HALF+1` input taps weighted by a Hann-windowed
/// sinc. The sinc cutoff is `min(1, ratio)` so the same routine also
/// anti-aliases when *down*sampling (e.g. 48→16 kHz for whisper).
pub fn resample_mono(input: &[f32], from_rate: u32, to_rate: u32) -> Vec<f32> {
    if input.is_empty() || from_rate == 0 || to_rate == 0 {
        return Vec::new();
    }
    if from_rate == to_rate {
        return input.to_vec();
    }
    let ratio = to_rate as f64 / from_rate as f64;
    let out_len_f = input.len() as f64 * ratio;
    // Bound pathological ratios.
    let out_len = if out_len_f.is_finite() && out_len_f >= 0.0 {
        (out_len_f as usize).min(input.len().saturating_mul(16))
    } else {
        0
    };
    // Kernel half-width in input samples. 16 → 33-tap filter: a good
    // quality/cost balance for speech.
    const HALF: i64 = 16;
    // sinc cutoff (normalized to the input rate): for downsampling pull
    // it in to the output Nyquist to anti-alias; for upsampling it
    // stays at the input Nyquist (1.0).
    let cutoff = ratio.min(1.0);
    let half_f = HALF as f64;

    let mut out = Vec::with_capacity(out_len);
    for i in 0..out_len {
        let src = i as f64 / ratio; // position in input samples
        let center = src.floor() as i64;
        let mut acc = 0.0f64;
        let mut norm = 0.0f64;
        for k in -HALF..=HALF {
            let j = center + k;
            if j < 0 || j as usize >= input.len() {
                continue;
            }
            let x = src - j as f64; // tap distance, input samples
            if x.abs() > half_f {
                continue;
            }
            // Hann window over [-HALF, HALF].
            let w = 0.5 + 0.5 * (std::f64::consts::PI * x / half_f).cos();
            let weight = sinc(x * cutoff) * w;
            acc += input[j as usize] as f64 * weight;
            norm += weight;
        }
        // Normalize by the realized tap-weight sum — corrects gain at
        // the signal edges where the kernel is truncated.
        let s = if norm.abs() > 1e-9 { acc / norm } else { 0.0 };
        out.push(if s.is_finite() { s as f32 } else { 0.0 });
    }
    out
}

/// Normalized sinc: `sin(pi x) / (pi x)`, with the removable
/// singularity at 0 filled in.
fn sinc(x: f64) -> f64 {
    if x.abs() < 1e-9 {
        1.0
    } else {
        let px = std::f64::consts::PI * x;
        px.sin() / px
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use tokio::runtime::Runtime;

    fn fmt(rate: u32, channels: u32) -> AudioFormat {
        AudioFormat {
            sample_rate: rate,
            channel_count: channels,
        }
    }

    // ---------- resample_mono ----------

    #[test]
    fn resample_same_rate_is_identity() {
        let buf: Vec<f32> = (0..100).map(|i| i as f32 * 0.01).collect();
        assert_eq!(resample_mono(&buf, 48_000, 48_000), buf);
    }

    #[test]
    fn resample_empty_or_zero_rate_is_empty() {
        assert!(resample_mono(&[], 24_000, 48_000).is_empty());
        assert!(resample_mono(&[1.0, 2.0], 0, 48_000).is_empty());
        assert!(resample_mono(&[1.0, 2.0], 48_000, 0).is_empty());
    }

    #[test]
    fn resample_upsample_doubles_length() {
        // 24 kHz → 48 kHz ≈ 2× the samples.
        let buf: Vec<f32> = (0..1000).map(|i| (i as f32 * 0.05).sin()).collect();
        let out = resample_mono(&buf, 24_000, 48_000);
        assert!((1999..=2001).contains(&out.len()), "got {}", out.len());
        assert!(out.iter().all(|s| s.is_finite()));
    }

    #[test]
    fn resample_downsample_shrinks_length() {
        // 48 kHz → 16 kHz is a 3× downsample.
        let buf: Vec<f32> = (0..4800).map(|i| (i as f32 * 0.01).sin()).collect();
        let out = resample_mono(&buf, 48_000, 16_000);
        assert!((1599..=1601).contains(&out.len()), "got {}", out.len());
        assert!(out.iter().all(|s| s.is_finite()));
    }

    #[test]
    fn resample_preserves_a_dc_level() {
        // A constant input must come back ~constant (windowed-sinc with
        // realized-weight normalization preserves DC). Check the
        // interior, away from the truncated-kernel edges.
        let buf = vec![0.5_f32; 2400];
        let out = resample_mono(&buf, 24_000, 48_000);
        let mid = &out[200..out.len() - 200];
        assert!(
            mid.iter().all(|s| (s - 0.5).abs() < 0.02),
            "DC level not preserved through resample",
        );
    }

    #[test]
    fn resample_ratio_is_bounded_against_blowup() {
        // 1 Hz → 48 kHz would be a 48000× upsample; the cap keeps the
        // allocation at most 16× the input.
        let buf: Vec<f32> = (0..32).map(|i| i as f32).collect();
        let out = resample_mono(&buf, 1, 48_000);
        assert!(out.len() <= buf.len() * 16);
    }

    // ---------- Speaker / PushAudioSource ----------

    #[test]
    fn speaker_enqueue_then_drain_round_trips() {
        let (speaker, mut source) = Speaker::new(Arc::new(AtomicU32::new(0)));
        assert!(!speaker.is_speaking());
        // Exactly one second of audio at SPEAK_RATE.
        speaker.enqueue(&vec![0.3_f32; SPEAK_RATE as usize], SPEAK_RATE);
        assert!(speaker.is_speaking());
        assert!((speaker.queued_secs() - 1.0).abs() < 1e-3);

        let mut buf = vec![0.0_f32; SPEAK_RATE as usize];
        source.pop_samples(&mut buf).unwrap();
        assert!(buf.iter().all(|s| (*s - 0.3).abs() < 1e-6));
        assert!(!speaker.is_speaking(), "queue should be drained");
    }

    #[test]
    fn speaker_clear_drops_queued_audio() {
        let (speaker, _source) = Speaker::new(Arc::new(AtomicU32::new(0)));
        speaker.enqueue(&vec![0.5_f32; 9600], SPEAK_RATE);
        assert!(speaker.is_speaking());
        speaker.clear();
        assert!(!speaker.is_speaking());
        assert_eq!(speaker.queued_secs(), 0.0);
    }

    #[test]
    fn push_source_underrun_yields_exact_silence() {
        // Empty queue → pop_samples fills zeros, never blocks or errors.
        let (_speaker, mut source) = Speaker::new(Arc::new(AtomicU32::new(0)));
        let mut buf = vec![1.0_f32; 480];
        let n = source.pop_samples(&mut buf).unwrap();
        assert_eq!(n, Some(480));
        assert!(buf.iter().all(|s| s.to_bits() == 0.0_f32.to_bits()));
    }

    #[test]
    fn push_source_tracks_loudness_level() {
        let level = Arc::new(AtomicU32::new(0));
        let (speaker, mut source) = Speaker::new(level.clone());
        speaker.enqueue(&vec![0.8_f32; 4800], SPEAK_RATE);
        let mut buf = vec![0.0_f32; 4800];
        source.pop_samples(&mut buf).unwrap();
        let lvl = f32::from_bits(level.load(Ordering::Relaxed));
        assert!(lvl > 0.5, "level should reflect loud audio, got {lvl}");
    }

    #[test]
    fn speaker_clone_shares_the_queue() {
        let (speaker, _source) = Speaker::new(Arc::new(AtomicU32::new(0)));
        let clone = speaker.clone();
        clone.enqueue(&vec![0.1_f32; 4800], SPEAK_RATE);
        assert!(speaker.is_speaking(), "clones must share one queue");
    }

    // ---------- TapBackend / TapSink ----------

    #[test]
    fn tap_sink_format_matches_requested() {
        Runtime::new().unwrap().block_on(async {
            let (backend, _rx) = TapBackend::channel();
            let want = fmt(44_100, 2);
            let sink = backend.create_output(want).await.unwrap();
            assert_eq!(sink.format().unwrap(), want);
        });
    }

    #[test]
    fn tap_sink_push_preserves_samples_bit_for_bit() {
        Runtime::new().unwrap().block_on(async {
            let (backend, mut rx) = TapBackend::channel();
            let mut sink = backend.create_output(fmt(48_000, 1)).await.unwrap();
            let payload = vec![
                0.0_f32,
                1.0,
                -1.0,
                f32::MIN_POSITIVE,
                f32::MAX,
                f32::MIN,
                1.0e-30,
                -3.14159265,
            ];
            sink.push_samples(&payload).unwrap();
            let frame = rx.recv().await.expect("frame not delivered");
            assert_eq!(frame.samples, payload);
            for (a, b) in payload.iter().zip(frame.samples.iter()) {
                assert_eq!(a.to_bits(), b.to_bits());
            }
            assert_eq!(frame.format, fmt(48_000, 1));
        });
    }

    #[test]
    fn tap_sink_pause_resume_toggle_state() {
        Runtime::new().unwrap().block_on(async {
            let (backend, _rx) = TapBackend::channel();
            let sink = backend
                .create_output(AudioFormat::mono_48k())
                .await
                .unwrap();
            assert!(!sink.is_paused());
            sink.pause();
            assert!(sink.is_paused());
            sink.resume();
            assert!(!sink.is_paused());
            sink.toggle_pause();
            assert!(sink.is_paused());
            sink.toggle_pause();
            assert!(!sink.is_paused());
        });
    }

    #[test]
    fn tap_sink_push_after_receiver_drop_does_not_error() {
        Runtime::new().unwrap().block_on(async {
            let (backend, rx) = TapBackend::channel();
            let mut sink = backend
                .create_output(AudioFormat::mono_48k())
                .await
                .unwrap();
            drop(rx);
            for _ in 0..1000 {
                sink.push_samples(&[0.0; 480]).unwrap();
            }
        });
    }

    #[test]
    fn tap_sink_handle_clone_shares_pause_state() {
        Runtime::new().unwrap().block_on(async {
            let (backend, _rx) = TapBackend::channel();
            let sink = backend
                .create_output(AudioFormat::mono_48k())
                .await
                .unwrap();
            let handle = sink.handle();
            handle.pause();
            assert!(sink.is_paused(), "handle.pause() did not affect sink");
            let cloned = handle.cloned_boxed();
            cloned.resume();
            assert!(
                !sink.is_paused(),
                "cloned handle.resume() did not affect sink"
            );
        });
    }

    // ---------- SilentSource ----------

    #[test]
    fn silent_source_fills_with_exact_zeros() {
        let mut src = SilentSource;
        for len in [0usize, 1, 7, 480, 4096] {
            let mut buf = vec![1.0_f32; len];
            let n = src.pop_samples(&mut buf).unwrap();
            assert_eq!(n, Some(len), "len={len}");
            assert!(
                buf.iter().all(|s| s.to_bits() == 0.0_f32.to_bits()),
                "len={len}",
            );
        }
    }

    #[test]
    fn silent_source_format_is_mono_48k() {
        assert_eq!(SilentSource.format(), AudioFormat::mono_48k());
    }
}
