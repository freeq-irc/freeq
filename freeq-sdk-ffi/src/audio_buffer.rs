//! Mic-audio jitter buffer shared between the producer (Swift's
//! `push_audio_frame`) and the consumer (the Opus encoder's `pop_samples`).
//!
//! Swift captures the mic on its own thread and pushes mono-48 kHz float
//! samples in; the encoder pulls them out at its own cadence. The two run on
//! different clocks, so a small queue absorbs the jitter. Two invariants
//! matter for a real-time call:
//!
//! - **Bounded backlog.** If the consumer stalls (encoder paused, MoQ
//!   back-pressure, a hiccup), the producer must NOT grow the queue without
//!   bound — that's both a memory leak and, when the consumer resumes,
//!   seconds of stale audio drained as a delayed wall of sound. The bound is
//!   enforced on the PRODUCER side ([`push_capped`]) precisely because a
//!   stalled consumer never runs the cap itself.
//! - **Underrun = silence, not stall.** If the producer is behind (call
//!   start before the mic engine spins up, transient jitter), the consumer
//!   must still return a full buffer, zero-filled — the encoder needs a
//!   continuous stream. ([`drain_into`].)
//!
//! Both are pure `VecDeque<f32>` operations with no AV/codec dependencies, so
//! they're unit-testable without building the (heavy, feature-gated) media
//! stack.

use std::collections::VecDeque;

/// Sample rate Swift resamples mic audio to before pushing it in.
pub const PUSH_AUDIO_RATE: u32 = 48_000;

/// Max backlog the jitter buffer will hold, in samples. Beyond this the
/// OLDEST samples are dropped so playout latency stays bounded and memory
/// can't run away. 200 ms (at mono 48 kHz) is large enough to ride out
/// normal scheduling jitter, small enough that a recovering consumer doesn't
/// dump a noticeable slug of stale audio.
pub const MAX_BACKLOG_SAMPLES: usize = (PUSH_AUDIO_RATE as usize) / 5;

/// Producer side: append freshly-captured samples, then enforce the backlog
/// bound by dropping the oldest overflow. Runs on every push, so the queue
/// stays bounded regardless of whether the consumer is keeping up (or running
/// at all).
pub fn push_capped<I: IntoIterator<Item = f32>>(queue: &mut VecDeque<f32>, samples: I, cap: usize) {
    queue.extend(samples);
    if queue.len() > cap {
        let excess = queue.len() - cap;
        queue.drain(..excess);
    }
}

/// Consumer side: fill `buf` from the front of the queue in FIFO order,
/// zero-padding any shortfall so the encoder always gets a complete buffer.
/// Returns the count of REAL (non-padded) samples — callers that care about
/// underrun (metering, diagnostics) can tell silence-fill from signal.
pub fn drain_into(queue: &mut VecDeque<f32>, buf: &mut [f32]) -> usize {
    let mut real = 0;
    for slot in buf.iter_mut() {
        match queue.pop_front() {
            Some(s) => {
                *slot = s;
                real += 1;
            }
            None => *slot = 0.0,
        }
    }
    real
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_pulls_fifo_order() {
        let mut q: VecDeque<f32> = [1.0, 2.0, 3.0, 4.0].into_iter().collect();
        let mut buf = [0.0; 3];
        let real = drain_into(&mut q, &mut buf);
        assert_eq!(buf, [1.0, 2.0, 3.0]);
        assert_eq!(real, 3);
        assert_eq!(q.into_iter().collect::<Vec<_>>(), vec![4.0]);
    }

    #[test]
    fn drain_zero_pads_on_underrun_and_reports_real_count() {
        // Encoder pulls before the mic has delivered enough — the buffer must
        // still come back full, padded with silence, and report the shortfall.
        let mut q: VecDeque<f32> = [0.5, 0.5].into_iter().collect();
        let mut buf = [9.0; 5];
        let real = drain_into(&mut q, &mut buf);
        assert_eq!(buf, [0.5, 0.5, 0.0, 0.0, 0.0]);
        assert_eq!(real, 2, "only 2 real samples; the rest is silence-fill");
        assert!(q.is_empty());
    }

    #[test]
    fn drain_on_empty_queue_is_pure_silence() {
        let mut q: VecDeque<f32> = VecDeque::new();
        let mut buf = [7.0; 4];
        let real = drain_into(&mut q, &mut buf);
        assert_eq!(buf, [0.0; 4]);
        assert_eq!(real, 0);
    }

    #[test]
    fn push_under_cap_keeps_everything() {
        let mut q = VecDeque::new();
        push_capped(&mut q, [1.0, 2.0, 3.0], 10);
        assert_eq!(q.into_iter().collect::<Vec<_>>(), vec![1.0, 2.0, 3.0]);
    }

    #[test]
    fn push_over_cap_drops_oldest_keeping_newest() {
        let mut q = VecDeque::new();
        push_capped(&mut q, [1.0, 2.0, 3.0, 4.0, 5.0], 3);
        // Newest 3 survive; the two oldest are dropped to bound latency.
        assert_eq!(q.into_iter().collect::<Vec<_>>(), vec![3.0, 4.0, 5.0]);
    }

    /// The core regression: a STALLED consumer (encoder paused / never pulls)
    /// must not let the producer grow the queue without bound. Before the fix
    /// the cap lived only in the consumer's `pop_samples`, so with no pop ever
    /// happening the queue grew to however much the mic pushed — unbounded
    /// memory and seconds of latency on resume. Producer-side capping fixes it.
    #[test]
    fn stalled_consumer_cannot_grow_backlog_unbounded() {
        let mut q = VecDeque::new();
        // Five seconds of mic audio pushed in 10 ms chunks, consumer never pulls.
        let chunk = vec![0.1_f32; (PUSH_AUDIO_RATE as usize) / 100];
        for _ in 0..500 {
            push_capped(&mut q, chunk.iter().copied(), MAX_BACKLOG_SAMPLES);
        }
        assert!(
            q.len() <= MAX_BACKLOG_SAMPLES,
            "backlog must stay bounded with no consumer — got {} (cap {})",
            q.len(),
            MAX_BACKLOG_SAMPLES,
        );
    }

    /// And the bound really does keep playout latency low: after a long stall,
    /// the buffered audio is at most MAX_BACKLOG_SAMPLES (≤ 200 ms), so a
    /// recovering encoder drains a fraction of a second of audio, not seconds.
    #[test]
    fn bounded_backlog_caps_recovery_latency() {
        let mut q = VecDeque::new();
        push_capped(
            &mut q,
            std::iter::repeat(0.2).take(PUSH_AUDIO_RATE as usize * 5),
            MAX_BACKLOG_SAMPLES,
        );
        let latency_ms = q.len() as f64 / PUSH_AUDIO_RATE as f64 * 1000.0;
        assert!(
            latency_ms <= 200.0,
            "buffered latency {latency_ms}ms must stay ≤200ms"
        );
    }
}
