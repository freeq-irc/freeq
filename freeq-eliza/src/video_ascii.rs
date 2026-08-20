//! ASCII / text-mode video backend — the "terminal being".
//!
//! A glowing face drawn entirely out of monospace glyphs on black: a head
//! ring, two eyes that blink, and a mouth whose aperture tracks her speech
//! level (lip-sync). Idle breathing when quiet; the palette shifts with
//! mood (green at rest, acid-yellow speaking, mint listening).
//!
//! Same frame contract as every other backend — it fills the tile's
//! `latest` buffer with an RGBA [`VideoFrame`] at [`VIDEO_W`]×[`VIDEO_H`].
//! The look is produced in two cheap steps:
//!
//! 1. A procedural per-cell *intensity field* shaped like a face (pure
//!    math — no source image), modulated by audio level, blink, breath,
//!    and scanlines.
//! 2. Each cell's intensity picks a glyph from a density ramp; the glyph's
//!    pre-rasterized alpha mask (built once into a [`GlyphAtlas`]) is
//!    blitted, tinted by the cell colour, into the frame.
//!
//! Step 2 is the only place text is rasterized, and it happens once at
//! startup — per-frame work is just field math + alpha blits, so it stays
//! well inside the 2-vCPU / 15 fps budget.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use iroh_live::media::format::VideoFrame;

use crate::video::{VIDEO_H, VIDEO_W, VideoTile};

/// Frames per second — matches the SVG/particle backends.
const FPS: u64 = 15;

/// Glyph cell size in pixels. Monospace cells are taller than wide; the
/// face geometry is computed in true pixel space so it stays circular
/// regardless of this ratio.
const CELL_W: u32 = 12;
const CELL_H: u32 = 22;

/// Density ramp, sparse → dense. Deliberately free of XML-special chars
/// (`& < >`) so each glyph drops straight into the atlas SVG.
const RAMP: &[u8] = b" .,:;+*oxOX%#@";

/// Pre-rasterized alpha masks for each glyph in [`RAMP`], one `CELL_W*CELL_H`
/// coverage buffer per glyph. Built once; blitted every frame.
pub struct GlyphAtlas {
    masks: Vec<Vec<u8>>, // RAMP.len() masks, each CELL_W*CELL_H bytes (alpha 0..=255)
}

impl GlyphAtlas {
    /// Rasterize the density ramp. See [`build_set`](Self::build_set).
    pub fn build() -> Option<Self> {
        Self::build_set(RAMP)
    }

    /// Rasterize every glyph in `chars` (white, centred) into its own
    /// cell-sized alpha mask using resvg. `None` only if a pixmap can't be
    /// allocated. The returned masks are indexed parallel to `chars`.
    pub fn build_set(chars: &[u8]) -> Option<Self> {
        let mut opt = resvg::usvg::Options::default();
        opt.fontdb_mut().load_system_fonts();
        let mut masks = Vec::with_capacity(chars.len());
        for &ch in chars {
            let mut pixmap = resvg::tiny_skia::Pixmap::new(CELL_W, CELL_H)?;
            if ch != b' ' {
                let svg = format!(
                    r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}">
<text x="{cx}" y="{baseline}" font-family="Menlo, DejaVu Sans Mono, Courier New, monospace" font-size="{fs}" fill="#ffffff" text-anchor="middle">{ch}</text>
</svg>"##,
                    w = CELL_W,
                    h = CELL_H,
                    cx = CELL_W as f32 / 2.0,
                    baseline = CELL_H as f32 * 0.76,
                    fs = CELL_H as f32 * 0.95,
                    ch = ch as char,
                );
                if let Ok(tree) = resvg::usvg::Tree::from_str(&svg, &opt) {
                    resvg::render(
                        &tree,
                        resvg::tiny_skia::Transform::identity(),
                        &mut pixmap.as_mut(),
                    );
                }
            }
            // White text on a transparent pixmap → the alpha channel is the
            // glyph's coverage.
            let data = pixmap.data();
            let mut mask = Vec::with_capacity((CELL_W * CELL_H) as usize);
            let (px4, _) = data.as_chunks::<4>();
            for px in px4 {
                mask.push(px[3]);
            }
            masks.push(mask);
        }
        Some(Self { masks })
    }
}

/// Stateless-per-frame ASCII renderer. Holds the glyph atlas and grid
/// geometry; `frame_rgba` is pure given `(t, level, peer)`, which is what
/// lets the offline demo harness reuse the exact production look.
pub struct AsciiRenderer {
    atlas: GlyphAtlas,
    cols: u32,
    rows: u32,
    /// Pixel offsets to centre the grid in the tile (covers the remainder
    /// left by non-divisible cell sizes).
    ox: u32,
    oy: u32,
}

impl AsciiRenderer {
    pub fn new() -> Option<Self> {
        let atlas = GlyphAtlas::build()?;
        let cols = VIDEO_W / CELL_W;
        let rows = VIDEO_H / CELL_H;
        Some(Self {
            atlas,
            cols,
            rows,
            ox: (VIDEO_W - cols * CELL_W) / 2,
            oy: (VIDEO_H - rows * CELL_H) / 2,
        })
    }

    /// Render one RGBA frame (length `VIDEO_W*VIDEO_H*4`, opaque) for the
    /// given time and audio levels. `level` is her own voice (drives the
    /// mouth), `peer` the loudest human (drives the listening tint).
    pub fn frame_rgba(&self, t: f32, level: f32, peer: f32) -> Vec<u8> {
        let level = level.clamp(0.0, 1.0);
        let peer = peer.clamp(0.0, 1.0);
        let speaking = level > 0.03;
        let listening = !speaking && peer > 0.03;

        // Base palette: green at rest; acid-yellow while speaking; mint
        // while listening. The brighter a cell, the more it leans accent.
        let base = (0x33u16, 0xff, 0x88); // resting green
        let accent = if speaking {
            (0xffu16, 0xf0, 0x33) // acid yellow
        } else if listening {
            (0x3eu16, 0xff, 0xd6) // mint
        } else {
            (0x6cu16, 0xb0, 0xff) // idle blue
        };

        // Blink: open (1.0) almost always; a quick ~140ms close every 3.6s.
        let blink = {
            let phase = (t % 3.6) / 3.6;
            if phase > 0.96 {
                // ease down then up across the 0.04*3.6≈144ms window
                let p = (phase - 0.96) / 0.04; // 0..1
                let close = (p * std::f32::consts::PI).sin(); // 0→1→0
                (1.0 - close).clamp(0.05, 1.0)
            } else {
                1.0
            }
        };
        // Idle breathing — gentle brightness swell when quiet.
        let breath = if speaking || listening {
            1.0
        } else {
            0.9 + 0.1 * (t * 1.3).sin()
        };

        let mut buf = vec![0u8; (VIDEO_W * VIDEO_H * 4) as usize];
        // Opaque black background.
        let (px4, _) = buf.as_chunks_mut::<4>();
        for px in px4 {
            px[3] = 255;
        }

        let half_h = VIDEO_H as f32 / 2.0;
        let cx = VIDEO_W as f32 / 2.0;
        for row in 0..self.rows {
            for col in 0..self.cols {
                // Cell centre in pixels → normalised coords (y in [-1,1],
                // x scaled by the same factor so the face stays circular).
                let px = self.ox as f32 + (col as f32 + 0.5) * CELL_W as f32;
                let py = self.oy as f32 + (row as f32 + 0.5) * CELL_H as f32;
                let nx = (px - cx) / half_h;
                let ny = (py - half_h) / half_h;

                let mut i = face_intensity(nx, ny, t, level, blink);
                // Scanline shimmer + faint static.
                let scan = 0.86 + 0.14 * (py * 0.18 + t * 6.0).sin();
                i *= scan * breath;
                i = i.clamp(0.0, 1.0);
                if i <= 0.02 {
                    continue;
                }

                // Glyph by density.
                let gi = ((i * (RAMP.len() - 1) as f32).round() as usize).min(RAMP.len() - 1);
                if RAMP[gi] == b' ' {
                    continue;
                }

                // Colour: brighter cells lean toward the mood accent; the
                // eyes/mouth highlights ride the top of the range near-white.
                let mix = (i * 0.7).clamp(0.0, 1.0);
                let hi = (i.powi(3)).clamp(0.0, 1.0) * 0.6; // whiten the hottest cells
                let r = lerp3(base.0, accent.0, mix, hi);
                let g = lerp3(base.1, accent.1, mix, hi);
                let b = lerp3(base.2, accent.2, mix, hi);

                self.blit_glyph(&mut buf, col, row, gi, (r, g, b), i);
            }
        }
        buf
    }

    /// Alpha-blit one glyph mask into the frame at cell `(col,row)`, tinted
    /// `(r,g,b)` and scaled by `bright`.
    fn blit_glyph(
        &self,
        buf: &mut [u8],
        col: u32,
        row: u32,
        glyph: usize,
        color: (u8, u8, u8),
        bright: f32,
    ) {
        blit_mask(
            buf,
            &self.atlas.masks[glyph],
            self.ox + col * CELL_W,
            self.oy + row * CELL_H,
            color,
            bright,
        );
    }
}

/// Alpha-blit a glyph coverage mask at pixel origin `(x0,y0)`, tinted
/// `(r,g,b)` and scaled by `bright`, over an opaque background. Max-blends
/// so overlapping cells don't darken each other.
fn blit_mask(buf: &mut [u8], mask: &[u8], x0: u32, y0: u32, color: (u8, u8, u8), bright: f32) {
    blit_mask_i(buf, mask, x0 as i32, y0 as i32, color, bright);
}

/// Signed-origin variant — clips on all four edges so glitch displacement
/// and per-channel offsets can push a glyph partly (or fully) off-frame.
fn blit_mask_i(
    buf: &mut [u8],
    mask: &[u8],
    x0: i32,
    y0: i32,
    (r, g, b): (u8, u8, u8),
    bright: f32,
) {
    for cy in 0..CELL_H as i32 {
        let fy = y0 + cy;
        if fy < 0 || fy >= VIDEO_H as i32 {
            continue;
        }
        for cx in 0..CELL_W as i32 {
            let fx = x0 + cx;
            if fx < 0 || fx >= VIDEO_W as i32 {
                continue;
            }
            let cov = mask[(cy as u32 * CELL_W + cx as u32) as usize] as f32 / 255.0;
            if cov <= 0.0 {
                continue;
            }
            let a = (cov * bright).clamp(0.0, 1.0);
            let idx = ((fy as u32 * VIDEO_W + fx as u32) * 4) as usize;
            buf[idx] = buf[idx].max((r as f32 * a) as u8);
            buf[idx + 1] = buf[idx + 1].max((g as f32 * a) as u8);
            buf[idx + 2] = buf[idx + 2].max((b as f32 * a) as u8);
        }
    }
}

/// Face intensity field at normalised `(nx, ny)` (origin centre, `ny` in
/// `[-1,1]`). Returns ~`[0,1]`. Composed of a head ring, an interior glow,
/// two (blinking) eyes, and a mouth whose vertical aperture grows with
/// `level`.
fn face_intensity(nx: f32, ny: f32, t: f32, level: f32, blink: f32) -> f32 {
    let r = (nx * nx + ny * ny).sqrt();

    // Head ring at radius ~0.9 — thin bright shell that frames the face.
    let ring = gauss(r - 0.9, 0.04) * 0.85;
    // Faint interior fill — kept low so the features (eyes, mouth) read as
    // bright marks on a mostly-hollow mask rather than dissolving into a
    // glowing disc.
    let glow = ((0.9 - r) / 0.9).clamp(0.0, 1.0).powf(2.0) * 0.10;

    // Eyes — two bright blobs in the upper half (ny<0); blink scales them
    // shut. Amplified well above the interior glow so they clearly read.
    let eye_y = -0.18;
    let eye = (gauss2(nx - 0.30, ny - eye_y, 0.10) + gauss2(nx + 0.30, ny - eye_y, 0.10))
        * (0.12 + 0.88 * blink)
        * 1.25;

    // Mouth — filled ellipse below centre; vertical radius opens with
    // speech level (a thin line at rest, a wide oval when loud).
    let mw = 0.42;
    let mh = 0.045 + 0.34 * level;
    let mxn = nx / mw;
    let myn = (ny - 0.34) / mh;
    let md = (mxn * mxn + myn * myn).sqrt();
    let mouth = (1.0 - md).clamp(0.0, 1.0).powf(0.6) * 1.0;

    // A slow shimmer in the interior so the hollow doesn't read as dead.
    let shimmer = 0.05 * (nx * 6.0 + t * 1.5).sin() * glow;

    (ring + glow + eye + mouth + shimmer).clamp(0.0, 1.5)
}

/// 1-D gaussian-ish bump: 1.0 at `d==0`, falling off over `sigma`.
fn gauss(d: f32, sigma: f32) -> f32 {
    (-(d * d) / (2.0 * sigma * sigma)).exp()
}

/// 2-D radial gaussian bump centred at the offset `(dx,dy)`.
fn gauss2(dx: f32, dy: f32, sigma: f32) -> f32 {
    (-(dx * dx + dy * dy) / (2.0 * sigma * sigma)).exp()
}

/// Lerp `a→b` by `mix`, then lift toward white (255) by `hi`.
fn lerp3(a: u16, b: u16, mix: f32, hi: f32) -> u8 {
    let base = a as f32 + (b as f32 - a as f32) * mix;
    let lifted = base + (255.0 - base) * hi;
    lifted.clamp(0.0, 255.0) as u8
}

/// ASCII-backend render loop. Mirrors the particle loop: read the tile's
/// audio cells each frame, render, publish to `latest`, sleep to FPS.
pub(crate) fn render_loop(tile: VideoTile) {
    let renderer = match AsciiRenderer::new() {
        Some(r) => r,
        None => {
            tracing::error!("ascii video: could not build glyph atlas");
            return;
        }
    };
    let frame_dt = Duration::from_millis(1000 / FPS);
    let started = Instant::now();
    tracing::info!("eliza ascii renderer started ({VIDEO_W}x{VIDEO_H} @ {FPS}fps)");

    while tile.running.load(Ordering::Relaxed) {
        let tick = Instant::now();
        let t = started.elapsed().as_secs_f32();
        let level = f32::from_bits(tile.level.load(Ordering::Relaxed));
        let peer = f32::from_bits(tile.peer_level.load(Ordering::Relaxed));

        let rgba = renderer.frame_rgba(t, level, peer);
        let frame =
            VideoFrame::new_rgba(bytes::Bytes::from(rgba), VIDEO_W, VIDEO_H, Duration::ZERO);
        if let Ok(mut g) = tile.latest.lock() {
            *g = Some(frame);
        }

        if let Some(rest) = frame_dt.checked_sub(tick.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    tracing::info!("eliza ascii renderer stopped");
}

// ─────────────────────────────────────────────────────────────────────
// Digital-rain variant — a weirder ASCII style.
// ─────────────────────────────────────────────────────────────────────

/// Glyph set for the rain — digits, hex letters, and symbols (no XML
/// specials). Cells flicker through these like Matrix code.
const RAIN_CHARS: &[u8] = b"0123456789ABCDEFXYZ:=+*#$%abcdefkmnz";

/// "Digital rain" face: columns of falling glyphs (bright head, fading
/// tail) over black; the face emerges where the rain is brightened by the
/// face intensity field, and the eyes/mouth glow through. A weirder,
/// busier counterpart to the clean glyph face — same lip-sync + mood.
pub struct AsciiRainRenderer {
    atlas: GlyphAtlas,
    cols: u32,
    rows: u32,
    ox: u32,
    oy: u32,
}

impl AsciiRainRenderer {
    pub fn new() -> Option<Self> {
        let atlas = GlyphAtlas::build_set(RAIN_CHARS)?;
        let cols = VIDEO_W / CELL_W;
        let rows = VIDEO_H / CELL_H;
        Some(Self {
            atlas,
            cols,
            rows,
            ox: (VIDEO_W - cols * CELL_W) / 2,
            oy: (VIDEO_H - rows * CELL_H) / 2,
        })
    }

    pub fn frame_rgba(&self, t: f32, level: f32, peer: f32) -> Vec<u8> {
        let level = level.clamp(0.0, 1.0);
        let peer = peer.clamp(0.0, 1.0);
        let listening = level <= 0.03 && peer > 0.03;
        let blnk = {
            let phase = (t % 3.6) / 3.6;
            if phase > 0.96 {
                let p = (phase - 0.96) / 0.04;
                (1.0 - (p * std::f32::consts::PI).sin()).clamp(0.05, 1.0)
            } else {
                1.0
            }
        };

        let mut buf = vec![0u8; (VIDEO_W * VIDEO_H * 4) as usize];
        let (px4, _) = buf.as_chunks_mut::<4>();
        for px in px4 {
            px[3] = 255;
        }

        let half_h = VIDEO_H as f32 / 2.0;
        let cx = VIDEO_W as f32 / 2.0;
        let rows_f = self.rows as f32;

        for col in 0..self.cols {
            // Per-column drop: speed + phase from a hash so columns differ.
            let h = hash32(col.wrapping_mul(2_654_435_761));
            let speed = 5.0 + (h % 1000) as f32 / 1000.0 * 13.0; // rows/sec
            let tail = rows_f * (0.35 + (h >> 10 & 0xff) as f32 / 255.0 * 0.5);
            let span = rows_f + tail;
            let phase = (h >> 18 & 0xfff) as f32 / 4096.0;
            let head = (t * speed + phase * span) % span; // current head row

            for row in 0..self.rows {
                let r = row as f32;
                let dist = head - r; // >0 → head has passed (tail trails up)
                let rain = if dist >= 0.0 && dist < tail {
                    1.0 - dist / tail
                } else {
                    0.0
                };
                let is_head = (0.0..1.0).contains(&dist);

                // Face field at this cell.
                let px = self.ox as f32 + (col as f32 + 0.5) * CELL_W as f32;
                let py = self.oy as f32 + (row as f32 + 0.5) * CELL_H as f32;
                let nx = (px - cx) / half_h;
                let ny = (py - half_h) / half_h;
                let fi = face_intensity(nx, ny, t, level, blnk);

                // Rain reads dim off the face; the face is always at least
                // faintly lit (so it persists between drops) and the rain
                // brightens it further as drops sweep through. High contrast
                // so the face clearly emerges from the code.
                let bright = (0.15 * rain + 0.52 * fi + 0.5 * rain * fi).clamp(0.0, 1.0);
                if bright <= 0.09 {
                    continue;
                }

                // Flickering glyph — changes a few times a second; heads
                // churn faster.
                let k = (t * if is_head { 18.0 } else { 7.0 }) as u32;
                let gi = (hash32(
                    col.wrapping_mul(73_856_093)
                        ^ row.wrapping_mul(19_349_663)
                        ^ k.wrapping_mul(83_492_791),
                ) as usize)
                    % RAIN_CHARS.len();

                // Colour: green base; bright cells + heads whiten; listening
                // shifts toward cyan.
                let (br, bg, bb) = if listening {
                    (0x2eu16, 0xff, 0xe0)
                } else {
                    (0x33u16, 0xff, 0x66)
                };
                // Face cells whiten (so the face reads brighter than the
                // surrounding code); drop heads always flash white.
                let white = (fi * 0.6 + bright * bright * 0.25 + if is_head { 0.5 } else { 0.0 })
                    .clamp(0.0, 1.0);
                let r8 = (br as f32 + (255.0 - br as f32) * white) as u8;
                let g8 = (bg as f32 + (255.0 - bg as f32) * white) as u8;
                let b8 = (bb as f32 + (255.0 - bb as f32) * white) as u8;

                blit_mask(
                    &mut buf,
                    &self.atlas.masks[gi],
                    self.ox + col * CELL_W,
                    self.oy + row * CELL_H,
                    (r8, g8, b8),
                    bright,
                );
            }
        }
        buf
    }
}

/// Fast integer hash (fmix32-ish) for deterministic per-cell randomness.
fn hash32(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x7feb_352d);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846c_a68b);
    x ^= x >> 16;
    x
}

/// Digital-rain render loop.
pub(crate) fn render_loop_rain(tile: VideoTile) {
    let renderer = match AsciiRainRenderer::new() {
        Some(r) => r,
        None => {
            tracing::error!("ascii-rain video: could not build glyph atlas");
            return;
        }
    };
    let frame_dt = Duration::from_millis(1000 / FPS);
    let started = Instant::now();
    tracing::info!("eliza ascii-rain renderer started ({VIDEO_W}x{VIDEO_H} @ {FPS}fps)");

    while tile.running.load(Ordering::Relaxed) {
        let tick = Instant::now();
        let t = started.elapsed().as_secs_f32();
        let level = f32::from_bits(tile.level.load(Ordering::Relaxed));
        let peer = f32::from_bits(tile.peer_level.load(Ordering::Relaxed));
        let rgba = renderer.frame_rgba(t, level, peer);
        let frame =
            VideoFrame::new_rgba(bytes::Bytes::from(rgba), VIDEO_W, VIDEO_H, Duration::ZERO);
        if let Ok(mut g) = tile.latest.lock() {
            *g = Some(frame);
        }
        if let Some(rest) = frame_dt.checked_sub(tick.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    tracing::info!("eliza ascii-rain renderer stopped");
}

// ─────────────────────────────────────────────────────────────────────
// Glitch variant — a cursed, corrupted terminal face.
// ─────────────────────────────────────────────────────────────────────

/// "Cursed terminal": the glyph face, but unstable — chromatic channel
/// split (RGB fringing), datamosh row-tearing, random cell corruption,
/// and glitch bursts that spike on her speech. Same lip-sync + blink
/// underneath; it just won't hold still.
pub struct AsciiGlitchRenderer {
    atlas: GlyphAtlas,
    cols: u32,
    rows: u32,
    ox: u32,
    oy: u32,
}

impl AsciiGlitchRenderer {
    pub fn new() -> Option<Self> {
        let atlas = GlyphAtlas::build()?; // density ramp
        let cols = VIDEO_W / CELL_W;
        let rows = VIDEO_H / CELL_H;
        Some(Self {
            atlas,
            cols,
            rows,
            ox: (VIDEO_W - cols * CELL_W) / 2,
            oy: (VIDEO_H - rows * CELL_H) / 2,
        })
    }

    pub fn frame_rgba(&self, t: f32, level: f32, peer: f32) -> Vec<u8> {
        let level = level.clamp(0.0, 1.0);
        let peer = peer.clamp(0.0, 1.0);
        let listening = level <= 0.03 && peer > 0.03;
        let blnk = {
            let phase = (t % 3.6) / 3.6;
            if phase > 0.96 {
                let p = (phase - 0.96) / 0.04;
                (1.0 - (p * std::f32::consts::PI).sin()).clamp(0.05, 1.0)
            } else {
                1.0
            }
        };

        // Global instability: a steady floor, more while speaking, plus
        // periodic bursts (every ~0.4s, ~1-in-3 windows go loud).
        let burst_win = (t * 2.5) as u32;
        let burst = if hash32(burst_win.wrapping_mul(2_246_822_519)).is_multiple_of(3) {
            0.5 + (hash32(burst_win) % 100) as f32 / 100.0 * 0.5
        } else {
            0.0
        };
        let g = (0.12 + 0.3 * level + burst).clamp(0.0, 1.0);
        let chan = (2.0 + 12.0 * g) as i32; // chromatic split, px

        let mut buf = vec![0u8; (VIDEO_W * VIDEO_H * 4) as usize];
        let (px4, _) = buf.as_chunks_mut::<4>();
        for px in px4 {
            px[3] = 255;
        }

        let half_h = VIDEO_H as f32 / 2.0;
        let cx = VIDEO_W as f32 / 2.0;

        for row in 0..self.rows {
            // Per-row tear: some rows slip sideways when g is high.
            let rseed =
                hash32(row.wrapping_mul(374_761_393) ^ (burst_win.wrapping_mul(668_265_263)));
            let disp = if (rseed % 1000) as f32 / 1000.0 < g * 0.45 {
                ((((rseed >> 10) % 80) as i32) - 40) as f32 * g
            } else {
                0.0
            } as i32;

            for col in 0..self.cols {
                let px = self.ox as f32 + (col as f32 + 0.5) * CELL_W as f32;
                let py = self.oy as f32 + (row as f32 + 0.5) * CELL_H as f32;
                let nx = (px - cx) / half_h;
                let ny = (py - half_h) / half_h;
                let mut i = face_intensity(nx, ny, t, level, blnk);
                i *= 0.86 + 0.14 * (py * 0.2 + t * 6.0).sin();
                i = i.clamp(0.0, 1.0);

                // Corruption — random cells flare magenta with a wrong glyph.
                let cseed = hash32(
                    col.wrapping_mul(2_654_435_761) ^ row.wrapping_mul(40_503) ^ (t * 12.0) as u32,
                );
                let corrupt = (cseed % 1000) as f32 / 1000.0 < g * 0.12;

                if i <= 0.04 && !corrupt {
                    continue;
                }

                let (gi, color, bright) = if corrupt {
                    let gi = (cseed >> 12) as usize % RAMP.len();
                    (gi.max(1), (255u8, 40, 230), 1.0)
                } else {
                    let gi = ((i * (RAMP.len() - 1) as f32).round() as usize).min(RAMP.len() - 1);
                    if RAMP[gi] == b' ' {
                        continue;
                    }
                    // Base sickly green→cyan; hottest cells whiten. Shifts
                    // bluer (cyan) while listening.
                    let hi = i.powi(3) * 0.6;
                    let b_base = if listening { 0xe0 } else { 0x99 } as f32;
                    let r = (0x20 as f32 + (255.0 - 0x20 as f32) * hi) as u8;
                    let gc = 0xff_u8;
                    let b = (b_base + (255.0 - b_base) * hi) as u8;
                    (gi, (r, gc, b), i)
                };

                let mask = &self.atlas.masks[gi];
                let x0 = self.ox as i32 + col as i32 * CELL_W as i32 + disp;
                let y0 = self.oy as i32 + row as i32 * CELL_H as i32;
                // Chromatic split: R shifted +chan, B shifted -chan, G centred.
                blit_mask_i(&mut buf, mask, x0 + chan, y0, (color.0, 0, 0), bright);
                blit_mask_i(&mut buf, mask, x0 - chan, y0, (0, 0, color.2), bright);
                blit_mask_i(&mut buf, mask, x0, y0, (0, color.1, 0), bright);
            }
        }
        buf
    }
}

/// Glitch render loop.
pub(crate) fn render_loop_glitch(tile: VideoTile) {
    let renderer = match AsciiGlitchRenderer::new() {
        Some(r) => r,
        None => {
            tracing::error!("ascii-glitch video: could not build glyph atlas");
            return;
        }
    };
    let frame_dt = Duration::from_millis(1000 / FPS);
    let started = Instant::now();
    tracing::info!("eliza ascii-glitch renderer started ({VIDEO_W}x{VIDEO_H} @ {FPS}fps)");

    while tile.running.load(Ordering::Relaxed) {
        let tick = Instant::now();
        let t = started.elapsed().as_secs_f32();
        let level = f32::from_bits(tile.level.load(Ordering::Relaxed));
        let peer = f32::from_bits(tile.peer_level.load(Ordering::Relaxed));
        let rgba = renderer.frame_rgba(t, level, peer);
        let frame =
            VideoFrame::new_rgba(bytes::Bytes::from(rgba), VIDEO_W, VIDEO_H, Duration::ZERO);
        if let Ok(mut g) = tile.latest.lock() {
            *g = Some(frame);
        }
        if let Some(rest) = frame_dt.checked_sub(tick.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    tracing::info!("eliza ascii-glitch renderer stopped");
}

// ─────────────────────────────────────────────────────────────────────
// Bot variant — a boxy robot head (no round face at all).
// ─────────────────────────────────────────────────────────────────────

/// Intensity field for a rectangular "robot" head: a box outline with an
/// antenna, two rectangular LED eyes that blink, and an equalizer-bar
/// mouth whose bars bounce with `level` (instead of a round aperture).
/// `ny` in `[-1,1]`, origin centre.
fn box_face_intensity(nx: f32, ny: f32, t: f32, level: f32, blink: f32) -> f32 {
    let bw = 1.02; // half-width  (wide, boxy)
    let bh = 0.82; // half-height (leaves room for an antenna above)
    let q = (nx.abs() / bw).max(ny.abs() / bh);

    // Box outline (Chebyshev shell) + faint interior fill.
    let ring = gauss(q - 1.0, 0.035) * 0.95;
    let glow = (0.97 - q).clamp(0.0, 1.0).powf(2.0) * 0.07;

    // Antenna: a thin stalk above the top edge with a blob at the tip.
    let stalk = if nx.abs() < 0.03 && ny < -bh && ny > -bh - 0.26 {
        0.8
    } else {
        0.0
    };
    let tip = gauss2(nx, ny - (-bh - 0.30), 0.055) * 0.95;

    // Rectangular LED eyes; blink squashes their height.
    let eye_y = -0.24;
    let eye_h = 0.07 * (0.18 + 0.82 * blink);
    let eye =
        if (ny - eye_y).abs() < eye_h && ((nx - 0.40).abs() < 0.17 || (nx + 0.40).abs() < 0.17) {
            1.0
        } else {
            0.0
        };

    // Equalizer mouth: ~8 vertical bars across the lower face; each bar's
    // half-height jumps with speech level (a flat slit when quiet).
    let my = 0.42;
    let mouth = if nx.abs() < 0.56 {
        let col = ((nx + 0.56) / 0.14).floor();
        let bar = 0.025 + level * (0.10 + 0.16 * ((col * 1.7 + t * 9.0).sin() * 0.5 + 0.5));
        if (ny - my).abs() < bar { 1.0 } else { 0.0 }
    } else {
        0.0
    };

    (ring + glow + stalk + tip + eye + mouth).clamp(0.0, 1.2)
}

/// Boxy amber-CRT robot face.
pub struct AsciiBotRenderer {
    atlas: GlyphAtlas,
    cols: u32,
    rows: u32,
    ox: u32,
    oy: u32,
}

impl AsciiBotRenderer {
    pub fn new() -> Option<Self> {
        let atlas = GlyphAtlas::build()?;
        let cols = VIDEO_W / CELL_W;
        let rows = VIDEO_H / CELL_H;
        Some(Self {
            atlas,
            cols,
            rows,
            ox: (VIDEO_W - cols * CELL_W) / 2,
            oy: (VIDEO_H - rows * CELL_H) / 2,
        })
    }

    pub fn frame_rgba(&self, t: f32, level: f32, peer: f32) -> Vec<u8> {
        let level = level.clamp(0.0, 1.0);
        let peer = peer.clamp(0.0, 1.0);
        let listening = level <= 0.03 && peer > 0.03;
        let blnk = {
            let phase = (t % 4.2) / 4.2;
            if phase > 0.97 {
                let p = (phase - 0.97) / 0.03;
                (1.0 - (p * std::f32::consts::PI).sin()).clamp(0.05, 1.0)
            } else {
                1.0
            }
        };

        let mut buf = vec![0u8; (VIDEO_W * VIDEO_H * 4) as usize];
        let (px4, _) = buf.as_chunks_mut::<4>();
        for px in px4 {
            px[3] = 255;
        }

        let half_h = VIDEO_H as f32 / 2.0;
        let cx = VIDEO_W as f32 / 2.0;
        for row in 0..self.rows {
            for col in 0..self.cols {
                let px = self.ox as f32 + (col as f32 + 0.5) * CELL_W as f32;
                let py = self.oy as f32 + (row as f32 + 0.5) * CELL_H as f32;
                let nx = (px - cx) / half_h;
                let ny = (py - half_h) / half_h;
                let mut i = box_face_intensity(nx, ny, t, level, blnk);
                i *= 0.88 + 0.12 * (py * 0.18 + t * 5.0).sin();
                i = i.clamp(0.0, 1.0);
                if i <= 0.05 {
                    continue;
                }
                let gi = ((i * (RAMP.len() - 1) as f32).round() as usize).min(RAMP.len() - 1);
                if RAMP[gi] == b' ' {
                    continue;
                }
                // Amber CRT; greens-shift while listening; hot cells whiten.
                let (br, bg, bb) = if listening {
                    (0x33u16, 0xff, 0x99)
                } else {
                    (0xffu16, 0xb0, 0x18)
                };
                let hi = i.powi(3) * 0.6;
                let r = (br as f32 + (255.0 - br as f32) * hi) as u8;
                let g = (bg as f32 + (255.0 - bg as f32) * hi) as u8;
                let b = (bb as f32 + (255.0 - bb as f32) * hi) as u8;
                blit_mask(
                    &mut buf,
                    &self.atlas.masks[gi],
                    self.ox + col * CELL_W,
                    self.oy + row * CELL_H,
                    (r, g, b),
                    i,
                );
            }
        }
        buf
    }
}

/// Boxy-robot render loop.
pub(crate) fn render_loop_bot(tile: VideoTile) {
    let renderer = match AsciiBotRenderer::new() {
        Some(r) => r,
        None => {
            tracing::error!("ascii-bot video: could not build glyph atlas");
            return;
        }
    };
    let frame_dt = Duration::from_millis(1000 / FPS);
    let started = Instant::now();
    tracing::info!("eliza ascii-bot renderer started ({VIDEO_W}x{VIDEO_H} @ {FPS}fps)");

    while tile.running.load(Ordering::Relaxed) {
        let tick = Instant::now();
        let t = started.elapsed().as_secs_f32();
        let level = f32::from_bits(tile.level.load(Ordering::Relaxed));
        let peer = f32::from_bits(tile.peer_level.load(Ordering::Relaxed));
        let rgba = renderer.frame_rgba(t, level, peer);
        let frame =
            VideoFrame::new_rgba(bytes::Bytes::from(rgba), VIDEO_W, VIDEO_H, Duration::ZERO);
        if let Ok(mut g) = tile.latest.lock() {
            *g = Some(frame);
        }
        if let Some(rest) = frame_dt.checked_sub(tick.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    tracing::info!("eliza ascii-bot renderer stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atlas_builds_and_has_a_mask_per_glyph() {
        let atlas = GlyphAtlas::build().expect("atlas");
        assert_eq!(atlas.masks.len(), RAMP.len());
        for m in &atlas.masks {
            assert_eq!(m.len(), (CELL_W * CELL_H) as usize);
        }
        // The space glyph is empty; a dense glyph has real coverage.
        let space = &atlas.masks[0];
        assert!(space.iter().all(|&a| a == 0));
        let at = &atlas.masks[RAMP.len() - 1]; // '@'
        assert!(
            at.iter().any(|&a| a > 0),
            "dense glyph should have coverage"
        );
    }

    #[test]
    fn frame_has_right_size_and_lights_up_when_speaking() {
        let r = AsciiRenderer::new().expect("renderer");
        let quiet = r.frame_rgba(0.0, 0.0, 0.0);
        assert_eq!(quiet.len(), (VIDEO_W * VIDEO_H * 4) as usize);
        // Every pixel opaque.
        assert!(quiet.chunks_exact(4).all(|p| p[3] == 255));

        // Speaking lights up more pixels than silence (the mouth opens and
        // the palette brightens).
        let lit = |buf: &[u8]| {
            buf.chunks_exact(4)
                .filter(|p| p[0] as u16 + p[1] as u16 + p[2] as u16 > 24)
                .count()
        };
        let loud = r.frame_rgba(0.0, 0.8, 0.0);
        assert!(
            lit(&loud) > lit(&quiet),
            "speaking frame should be brighter"
        );
    }

    #[test]
    fn bot_renders_a_frame() {
        let r = AsciiBotRenderer::new().expect("bot renderer");
        let f = r.frame_rgba(1.0, 0.6, 0.0);
        assert_eq!(f.len(), (VIDEO_W * VIDEO_H * 4) as usize);
        assert!(f.chunks_exact(4).all(|p| p[3] == 255));
        let lit = f
            .chunks_exact(4)
            .filter(|p| p[0] as u16 + p[1] as u16 + p[2] as u16 > 24)
            .count();
        assert!(lit > 500, "bot should light up cells");
    }

    #[test]
    fn rain_renders_a_frame() {
        let r = AsciiRainRenderer::new().expect("rain renderer");
        let f = r.frame_rgba(1.0, 0.5, 0.0);
        assert_eq!(f.len(), (VIDEO_W * VIDEO_H * 4) as usize);
        assert!(f.chunks_exact(4).all(|p| p[3] == 255));
        let lit = f
            .chunks_exact(4)
            .filter(|p| p[0] as u16 + p[1] as u16 + p[2] as u16 > 24)
            .count();
        assert!(lit > 500, "rain should light up cells");
    }
}
