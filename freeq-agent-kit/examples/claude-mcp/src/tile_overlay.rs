//! Visual content the bot projects onto its tile, on top of the
//! ghostly face: scene cards (title + bullets), file slices, status
//! chips. All overlays render as small inline SVG documents that the
//! face renderer composites over the particle field.

use std::sync::Arc;

use freeq_eliza::whiteboard::{Step, TextSize};
use resvg::tiny_skia::{Pixmap, PixmapPaint, Transform};
use resvg::usvg;

/// Active overlay, swapped atomically by the MCP tools.
#[derive(Clone, Debug, Default)]
pub enum TileOverlay {
    #[default]
    None,
    /// Status chip — small text + glyph in a corner.
    Status { label: String },
    /// Scene card — title + bullet list, fills the lower half.
    Card { title: String, bullets: Vec<String> },
    /// Quote card — large pulled-out text, fills the lower half.
    Quote {
        text: String,
        source: Option<String>,
    },
    /// File slice — monospace code rendered as the tile.
    File {
        path: String,
        lines: Vec<String>,
        line_start: u32,
    },
    /// Live whiteboard — pre-laid-out nodes + arrows from the
    /// orchestrator's accumulated SVO triples.
    Graph { steps: Vec<Step> },
    /// Service/health grid — labelled cells colour-coded by state
    /// ("ok" green, "warn" amber, "down" red, else neutral). For the
    /// ops/on-call role (Sentinel).
    StatusGrid {
        title: String,
        items: Vec<(String, String)>,
    },
    /// Line chart / sparkline of a numeric series, with the latest
    /// value called out (rises green, falls red). For the markets role
    /// (Quant).
    Chart {
        title: String,
        points: Vec<f64>,
        caption: Option<String>,
    },
    /// Unified-diff view — lines prefixed `+`/`-`/` ` rendered green/
    /// red/grey in monospace. For the programmer role (Ada).
    Diff { path: String, lines: Vec<String> },
    /// Day agenda — time + event rows, fills the lower half. For the
    /// productivity role (Otto).
    Agenda {
        title: String,
        items: Vec<(String, String)>,
    },
}

/// Shared, thread-safe overlay slot. The MCP tools write to it; the
/// face render thread reads on each frame.
pub type OverlayCell = Arc<std::sync::Mutex<TileOverlay>>;

pub fn new_overlay_cell() -> OverlayCell {
    Arc::new(std::sync::Mutex::new(TileOverlay::None))
}

/// Rasterize the overlay onto an existing pixmap (the particle face
/// frame). No-op when the overlay is `None`.
pub fn composite_overlay(
    overlay: &TileOverlay,
    pixmap: &mut Pixmap,
    opt: &usvg::Options,
    scratch: &mut Pixmap,
) {
    let svg = match overlay_svg(overlay, pixmap.width(), pixmap.height()) {
        Some(s) => s,
        None => return,
    };
    let Ok(tree) = usvg::Tree::from_str(&svg, opt) else {
        tracing::debug!("overlay SVG parse failed");
        return;
    };
    scratch.data_mut().fill(0);
    resvg::render(&tree, Transform::identity(), &mut scratch.as_mut());
    pixmap.draw_pixmap(
        0,
        0,
        scratch.as_ref(),
        &PixmapPaint::default(),
        Transform::identity(),
        None,
    );
}

fn overlay_svg(overlay: &TileOverlay, w: u32, h: u32) -> Option<String> {
    match overlay {
        TileOverlay::None => None,
        TileOverlay::Status { label } => Some(status_svg(label, w, h)),
        TileOverlay::Card { title, bullets } => Some(card_svg(title, bullets, w, h)),
        TileOverlay::Quote { text, source } => Some(quote_svg(text, source.as_deref(), w, h)),
        TileOverlay::File {
            path,
            lines,
            line_start,
        } => Some(file_svg(path, lines, *line_start, w, h)),
        TileOverlay::Graph { steps } => {
            if steps.is_empty() {
                None
            } else {
                Some(graph_svg(steps, w, h))
            }
        }
        TileOverlay::StatusGrid { title, items } => Some(status_grid_svg(title, items, w, h)),
        TileOverlay::Chart {
            title,
            points,
            caption,
        } => Some(chart_svg(title, points, caption.as_deref(), w, h)),
        TileOverlay::Diff { path, lines } => Some(diff_svg(path, lines, w, h)),
        TileOverlay::Agenda { title, items } => Some(agenda_svg(title, items, w, h)),
    }
}

/// Colour for a status state keyword.
fn state_color(state: &str) -> &'static str {
    match state.to_ascii_lowercase().as_str() {
        "ok" | "up" | "green" | "healthy" | "pass" | "passed" => "#7cf3a0",
        "warn" | "warning" | "amber" | "degraded" | "slow" => "#ffd34d",
        "down" | "red" | "fail" | "failed" | "error" | "critical" => "#ff6b6b",
        _ => "#7cb5ff",
    }
}

/// Service/health grid — a row of labelled cells, each a coloured dot +
/// label + state. Wraps into a 2-column layout for longer lists.
fn status_grid_svg(title: &str, items: &[(String, String)], w: u32, h: u32) -> String {
    let title = escape(title);
    let card_top = h / 2;
    let card_h = h - card_top - 16;
    let cols = if items.len() > 4 { 2 } else { 1 };
    let col_w = (w - 64) / cols;
    let mut body = String::new();
    for (i, (label, state)) in items.iter().take(8).enumerate() {
        let col = (i as u32) % cols;
        let row = (i as u32) / cols;
        let x = 32 + col * col_w;
        let y = card_top + 56 + row * 30;
        body.push_str(&format!(
            r##"<circle cx="{dx}" cy="{dy}" r="5" fill="{c}" />
<text x="{tx}" y="{ty}" font-family="-apple-system, Helvetica, sans-serif" font-size="15" fill="#e6f3ff">{label}</text>
<text x="{sx}" y="{ty}" font-family="ui-monospace, Menlo, monospace" font-size="13" fill="{c}" text-anchor="end">{state}</text>"##,
            dx = x,
            dy = y - 5,
            c = state_color(state),
            tx = x + 14,
            ty = y,
            sx = x + col_w - 24,
            label = escape(label),
            state = escape(state),
        ));
    }
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
  <rect x="16" y="{ct}" width="{cw}" height="{ch}" rx="14" fill="#000d" stroke="#7cb5ff44" stroke-width="1.5" />
  <text x="32" y="{tt}" font-family="-apple-system, Helvetica, sans-serif" font-size="18" font-weight="600" fill="#7cb5ff">{title}</text>
  {body}
</svg>"##,
        ct = card_top,
        cw = w - 32,
        ch = card_h,
        tt = card_top + 32,
    )
}

/// Line chart of `points`, scaled to the lower-half card. The latest
/// value is called out and the line is tinted by overall direction.
fn chart_svg(title: &str, points: &[f64], caption: Option<&str>, w: u32, h: u32) -> String {
    let title = escape(title);
    let card_top = h / 2;
    let card_h = h - card_top - 16;
    let plot_x = 32.0;
    let plot_w = (w - 64) as f64;
    let plot_top = (card_top + 44) as f64;
    let plot_h = (card_h - 60) as f64;

    let (lo, hi) = points
        .iter()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), &p| {
            (lo.min(p), hi.max(p))
        });
    let span = if (hi - lo).abs() < f64::EPSILON {
        1.0
    } else {
        hi - lo
    };
    let rising = points.len() >= 2 && points[points.len() - 1] >= points[0];
    let line_color = if rising { "#7cf3a0" } else { "#ff6b6b" };

    let mut pts = String::new();
    if points.len() >= 2 {
        let step = plot_w / (points.len() - 1) as f64;
        for (i, &p) in points.iter().enumerate() {
            let x = plot_x + i as f64 * step;
            let y = plot_top + plot_h - ((p - lo) / span) * plot_h;
            pts.push_str(&format!("{x:.1},{y:.1} "));
        }
    }
    let last = points.last().copied().unwrap_or(0.0);
    let caption_block = caption
        .map(|c| {
            format!(
                r##"<text x="32" y="{cy}" font-family="-apple-system, Helvetica, sans-serif" font-size="13" fill="#8aa">{}</text>"##,
                escape(c),
                cy = card_top as i32 + card_h as i32 - 16,
            )
        })
        .unwrap_or_default();
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
  <rect x="16" y="{ct}" width="{cw}" height="{ch}" rx="14" fill="#000d" stroke="#7cb5ff44" stroke-width="1.5" />
  <text x="32" y="{tt}" font-family="-apple-system, Helvetica, sans-serif" font-size="18" font-weight="600" fill="#7cb5ff">{title}</text>
  <text x="{lvx}" y="{tt}" font-family="ui-monospace, Menlo, monospace" font-size="18" font-weight="600" fill="{lc}" text-anchor="end">{last:.2}</text>
  <polyline points="{pts}" fill="none" stroke="{lc}" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round" />
  {caption_block}
</svg>"##,
        ct = card_top,
        cw = w - 32,
        ch = card_h,
        tt = card_top + 32,
        lvx = w - 32,
        lc = line_color,
    )
}

/// Unified-diff view: `+`/`-`/` ` prefixed lines coloured green/red/grey.
fn diff_svg(path: &str, lines: &[String], w: u32, h: u32) -> String {
    let path = escape(path);
    let inner_h = h - 32;
    let max_lines = ((inner_h - 36) / 16) as usize;
    let mut body = String::new();
    let mut y = 52;
    for line in lines.iter().take(max_lines) {
        let (fill, bg) = match line.chars().next() {
            Some('+') => ("#7cf3a0", "#10341e88"),
            Some('-') => ("#ff8a8a", "#3a121288"),
            _ => ("#d6e3f3", "#0000"),
        };
        let trimmed = if line.chars().count() > 84 {
            line.chars().take(81).collect::<String>() + "…"
        } else {
            line.clone()
        };
        body.push_str(&format!(
            r##"<rect x="0" y="{ry}" width="{w}" height="16" fill="{bg}" />
<text x="16" y="{y}" font-family="ui-monospace, Menlo, monospace" font-size="11" fill="{fill}">{}</text>"##,
            escape(&trimmed),
            ry = y - 12,
        ));
        y += 16;
    }
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
  <rect x="0" y="0" width="{w}" height="{h}" fill="#0a0e15ee" />
  <text x="16" y="22" font-family="ui-monospace, Menlo, monospace" font-size="12" fill="#7cb5ff">{path}</text>
  <line x1="0" y1="32" x2="{w}" y2="32" stroke="#7cb5ff33" stroke-width="1" />
  {body}
</svg>"##,
    )
}

/// Day agenda — time + event rows in the lower-half card.
fn agenda_svg(title: &str, items: &[(String, String)], w: u32, h: u32) -> String {
    let title = escape(title);
    let card_top = h / 2;
    let card_h = h - card_top - 16;
    let mut body = String::new();
    let mut y = (card_top + 58) as i32;
    for (time, text) in items.iter().take(6) {
        body.push_str(&format!(
            r##"<text x="32" y="{y}" font-family="ui-monospace, Menlo, monospace" font-size="14" fill="#7cb5ff">{time}</text>
<text x="120" y="{y}" font-family="-apple-system, Helvetica, sans-serif" font-size="15" fill="#e6f3ff">{text}</text>"##,
            time = escape(time),
            text = escape(text),
        ));
        y += 30;
    }
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
  <rect x="16" y="{ct}" width="{cw}" height="{ch}" rx="14" fill="#000d" stroke="#7cb5ff44" stroke-width="1.5" />
  <text x="32" y="{tt}" font-family="-apple-system, Helvetica, sans-serif" font-size="18" font-weight="600" fill="#7cb5ff">{title}</text>
  {body}
</svg>"##,
        ct = card_top,
        cw = w - 32,
        ch = card_h,
        tt = card_top + 32,
    )
}

fn status_svg(label: &str, w: u32, _h: u32) -> String {
    let label = escape(label);
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="36" viewBox="0 0 {w} 36">
  <rect x="12" y="8" width="180" height="22" rx="11" fill="#000c" />
  <circle cx="28" cy="19" r="4" fill="#7cf3a0" />
  <text x="42" y="24" font-family="-apple-system, Helvetica, sans-serif" font-size="13" fill="#e6f3ff">{label}</text>
</svg>"##
    )
}

fn card_svg(title: &str, bullets: &[String], w: u32, h: u32) -> String {
    let title = escape(title);
    let card_top = h / 2;
    let card_h = h - card_top - 16;
    let mut body = String::new();
    let mut y = (card_top + 56) as i32;
    for (i, b) in bullets.iter().take(6).enumerate() {
        let bullet = escape(b);
        body.push_str(&format!(
            r##"<circle cx="32" cy="{cy}" r="3.5" fill="#7cb5ff" />
<text x="48" y="{ty}" font-family="-apple-system, Helvetica, sans-serif" font-size="16" fill="#e6f3ff">{bullet}</text>"##,
            cy = y - 5,
            ty = y,
        ));
        y += 28;
        let _ = i;
    }
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
  <rect x="16" y="{ct}" width="{cw}" height="{ch}" rx="14" fill="#000d" stroke="#7cb5ff44" stroke-width="1.5" />
  <text x="32" y="{tt}" font-family="-apple-system, Helvetica, sans-serif" font-size="18" font-weight="600" fill="#7cb5ff">{title}</text>
  {body}
</svg>"##,
        ct = card_top,
        cw = w - 32,
        ch = card_h,
        tt = card_top + 32,
    )
}

fn quote_svg(text: &str, source: Option<&str>, w: u32, h: u32) -> String {
    let text = escape(text);
    let card_top = h / 2;
    let card_h = h - card_top - 16;
    let source_block = match source {
        Some(s) => format!(
            r##"<text x="{tx}" y="{sy}" font-family="-apple-system, Helvetica, sans-serif" font-size="13" fill="#7cb5ff" text-anchor="end">— {}</text>"##,
            escape(s),
            tx = w - 32,
            sy = card_top + card_h - 18,
        ),
        None => String::new(),
    };
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
  <rect x="16" y="{ct}" width="{cw}" height="{ch}" rx="14" fill="#000d" stroke="#7cb5ff44" stroke-width="1.5" />
  <text x="36" y="{ty}" font-family="Georgia, serif" font-size="19" font-style="italic" fill="#e6f3ff">{text}</text>
  {source_block}
</svg>"##,
        ct = card_top,
        cw = w - 32,
        ch = card_h,
        ty = card_top + 56,
    )
}

fn file_svg(path: &str, lines: &[String], line_start: u32, w: u32, h: u32) -> String {
    let path = escape(path);
    let inner_h = h - 32;
    let mut body = String::new();
    let max_lines = ((inner_h - 36) / 16) as usize;
    let visible = lines.iter().take(max_lines);
    let mut y = 52;
    for (i, line) in visible.enumerate() {
        // Truncate at ~80 visible chars to keep lines from overflowing.
        let trimmed = if line.chars().count() > 78 {
            line.chars().take(75).collect::<String>() + "…"
        } else {
            line.to_string()
        };
        let n = line_start + i as u32;
        body.push_str(&format!(
            r##"<text x="20" y="{y}" font-family="ui-monospace, Menlo, monospace" font-size="11" fill="#566876">{n:>4}</text>
<text x="60" y="{y}" font-family="ui-monospace, Menlo, monospace" font-size="11" fill="#d6e3f3">{}</text>"##,
            escape(&trimmed),
            y = y,
        ));
        y += 16;
    }
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
  <rect x="0" y="0" width="{w}" height="{h}" fill="#0a0e15ee" />
  <text x="20" y="22" font-family="ui-monospace, Menlo, monospace" font-size="12" fill="#7cb5ff">{path}</text>
  <line x1="0" y1="32" x2="{w}" y2="32" stroke="#7cb5ff33" stroke-width="1" />
  {body}
</svg>"##,
    )
}

fn graph_svg(steps: &[Step], w: u32, h: u32) -> String {
    // Steps are positioned for a 640×360 canvas (see
    // freeq_eliza::diagram::to_steps). Our tile is also 640×360, so we
    // pass through. If the dimensions differed we'd scale here.
    let _ = (w, h);
    let mut body = String::new();
    // Defs once for the arrowhead.
    body.push_str(
        r##"<defs><marker id="ah" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 Z" fill="#7cb5ff"/></marker></defs>"##,
    );
    // Translucent dark canvas behind the graph so it reads over the face.
    body.push_str(&format!(
        r##"<rect x="0" y="0" width="{w}" height="{h}" fill="#000a" />"##
    ));
    // Title chip.
    body.push_str(
        r##"<rect x="12" y="8" width="120" height="22" rx="11" fill="#000c" />
<text x="28" y="24" font-family="-apple-system, Helvetica, sans-serif" font-size="13" fill="#7cb5ff">whiteboard</text>"##,
    );
    // Draw arrows first (under boxes) so labels read on top.
    for s in steps {
        if let Step::Arrow {
            x1,
            y1,
            x2,
            y2,
            label,
        } = s
        {
            body.push_str(&format!(
                r##"<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#7cb5ff" stroke-width="1.6" marker-end="url(#ah)" opacity="0.85" />"##,
            ));
            if let Some(lab) = label {
                let mx = (x1 + x2) / 2.0;
                let my = (y1 + y2) / 2.0 - 6.0;
                body.push_str(&format!(
                    r##"<rect x="{rx:.1}" y="{ry:.1}" width="{rw:.1}" height="14" rx="3" fill="#000c" />
<text x="{mx:.1}" y="{my:.1}" text-anchor="middle" font-family="-apple-system, Helvetica, sans-serif" font-size="11" fill="#d6e3f3">{lab}</text>"##,
                    rx = mx - (lab.chars().count() as f32 * 3.2) - 4.0,
                    ry = my - 11.0,
                    rw = (lab.chars().count() as f32 * 6.4) + 8.0,
                    lab = escape(lab),
                ));
            }
        }
    }
    // Then boxes.
    for s in steps {
        if let Step::Box {
            x,
            y,
            w: bw,
            h: bh,
            label,
        } = s
        {
            body.push_str(&format!(
                r##"<rect x="{x}" y="{y}" width="{bw}" height="{bh}" rx="8" fill="#0a1422ee" stroke="#7cb5ff" stroke-width="1.4" />
<text x="{cx:.1}" y="{cy:.1}" text-anchor="middle" font-family="-apple-system, Helvetica, sans-serif" font-size="14" fill="#e6f3ff">{label}</text>"##,
                cx = x + bw / 2.0,
                cy = y + bh / 2.0 + 5.0,
                label = escape(label),
            ));
        }
    }
    // Free-floating text steps (titles, captions).
    for s in steps {
        if let Step::Text {
            x,
            y,
            content,
            size,
        } = s
        {
            let px = match size {
                TextSize::Small => 12,
                TextSize::Med => 16,
                TextSize::Large => 22,
            };
            body.push_str(&format!(
                r##"<text x="{x}" y="{y}" text-anchor="middle" font-family="-apple-system, Helvetica, sans-serif" font-size="{px}" fill="#e6f3ff">{c}</text>"##,
                c = escape(content),
            ));
        }
    }
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">{body}</svg>"##
    )
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn renders(o: &TileOverlay) -> String {
        overlay_svg(o, 640, 360).expect("overlay should render")
    }

    #[test]
    fn status_grid_colors_by_state() {
        let svg = renders(&TileOverlay::StatusGrid {
            title: "fleet".into(),
            items: vec![
                ("freeq".into(), "up".into()),
                ("reth".into(), "warn".into()),
                ("ci".into(), "failed".into()),
            ],
        });
        assert!(svg.contains("fleet") && svg.contains("freeq"));
        assert!(svg.contains("#7cf3a0")); // up → green
        assert!(svg.contains("#ffd34d")); // warn → amber
        assert!(svg.contains("#ff6b6b")); // failed → red
    }

    #[test]
    fn chart_tints_by_direction_and_calls_out_last() {
        let up = renders(&TileOverlay::Chart {
            title: "BTC".into(),
            points: vec![100.0, 105.0, 110.0],
            caption: Some("+10%".into()),
        });
        assert!(up.contains("BTC") && up.contains("110.00") && up.contains("+10%"));
        assert!(up.contains("#7cf3a0")); // rising → green
        let down = renders(&TileOverlay::Chart {
            title: "x".into(),
            points: vec![10.0, 5.0],
            caption: None,
        });
        assert!(down.contains("#ff6b6b")); // falling → red
        // Degenerate inputs don't panic.
        let _ = renders(&TileOverlay::Chart {
            title: "f".into(),
            points: vec![1.0],
            caption: None,
        });
    }

    #[test]
    fn diff_colors_added_and_removed() {
        let svg = renders(&TileOverlay::Diff {
            path: "src/x.rs".into(),
            lines: vec!["+ added".into(), "- removed".into(), "  context".into()],
        });
        assert!(svg.contains("src/x.rs"));
        assert!(svg.contains("#7cf3a0")); // + green
        assert!(svg.contains("#ff8a8a")); // - red
    }

    #[test]
    fn agenda_lists_time_and_event() {
        let svg = renders(&TileOverlay::Agenda {
            title: "Today".into(),
            items: vec![
                ("09:00".into(), "Standup".into()),
                ("11:30".into(), "1:1".into()),
            ],
        });
        assert!(svg.contains("Today") && svg.contains("09:00") && svg.contains("Standup"));
    }

    /// Dev helper: render each role overlay to /tmp/overlay-*.png on a
    /// dark backdrop. `cargo test -p freeq-claude-mcp render_sample_pngs
    /// -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn render_sample_pngs() {
        use resvg::tiny_skia::Pixmap;
        use resvg::usvg;
        let mut opt = usvg::Options::default();
        opt.fontdb_mut().load_system_fonts();
        let mut scratch = Pixmap::new(640, 360).unwrap();
        let samples: Vec<(&str, TileOverlay)> = vec![
            (
                "statusgrid",
                TileOverlay::StatusGrid {
                    title: "fleet".into(),
                    items: vec![
                        ("freeq".into(), "up".into()),
                        ("reth".into(), "warn".into()),
                        ("ci".into(), "pass".into()),
                        ("bettina".into(), "asleep".into()),
                        ("golden".into(), "up".into()),
                        ("watch".into(), "up".into()),
                    ],
                },
            ),
            (
                "chart",
                TileOverlay::Chart {
                    title: "BTC".into(),
                    points: vec![100.0, 102.0, 101.5, 105.0, 104.0, 108.0, 107.0, 112.0],
                    caption: Some("+4.2% · 24h".into()),
                },
            ),
            (
                "diff",
                TileOverlay::Diff {
                    path: "src/auth.rs".into(),
                    lines: vec![
                        "  fn login(user: &str) -> Result<Session> {".into(),
                        "-     accept(user)".into(),
                        "+     if user.len() > 128 {".into(),
                        "+         return Err(Error::TooLong);".into(),
                        "+     }".into(),
                        "+     accept(user)".into(),
                        "  }".into(),
                    ],
                },
            ),
            (
                "agenda",
                TileOverlay::Agenda {
                    title: "Today".into(),
                    items: vec![
                        ("09:00".into(), "Standup".into()),
                        ("11:30".into(), "1:1 w/ Nap".into()),
                        ("14:00".into(), "Board prep".into()),
                        ("16:30".into(), "Ada code review".into()),
                    ],
                },
            ),
        ];
        for (name, ov) in &samples {
            let mut px = Pixmap::new(640, 360).unwrap();
            for p in px.data_mut().chunks_mut(4) {
                p[0] = 8;
                p[1] = 10;
                p[2] = 18;
                p[3] = 255;
            }
            composite_overlay(ov, &mut px, &opt, &mut scratch);
            px.save_png(format!("/tmp/overlay-{name}.png")).unwrap();
        }
    }

    #[test]
    fn empty_collections_dont_panic() {
        let _ = renders(&TileOverlay::StatusGrid {
            title: "e".into(),
            items: vec![],
        });
        let _ = renders(&TileOverlay::Agenda {
            title: "e".into(),
            items: vec![],
        });
        let _ = renders(&TileOverlay::Diff {
            path: "e".into(),
            lines: vec![],
        });
    }
}
