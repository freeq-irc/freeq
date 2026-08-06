//! Ratatui rendering for the TUI.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs};

use crate::app::App;
#[cfg(feature = "inline-images")]
use crate::app::{IMAGE_ROWS, ImageState};

pub fn draw(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // status bar
            Constraint::Length(1), // tab bar
            Constraint::Min(3),    // message + nicklist area
            Constraint::Length(3), // input
        ])
        .split(frame.area());

    draw_status_bar(frame, app, chunks[0]);
    draw_tab_bar(frame, app, chunks[1]);

    // If in a channel, show nick list sidebar
    let is_channel = app.active_buffer.starts_with('#') || app.active_buffer.starts_with('&');
    if is_channel {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Min(20),    // messages
                Constraint::Length(18), // nick list
            ])
            .split(chunks[2]);
        draw_messages(frame, app, cols[0]);
        draw_nicklist(frame, app, cols[1]);
    } else {
        draw_messages(frame, app, chunks[2]);
    }

    draw_input(frame, app, chunks[3]);

    // Overlay: network stats popup
    if app.show_net_popup {
        draw_net_popup(frame, app);
    }
}

fn draw_net_popup(frame: &mut Frame, app: &App) {
    use ratatui::widgets::Clear;

    let area = frame.area();
    // Center a box, 60 wide, 14 tall (or fit to screen)
    let w = 60u16.min(area.width.saturating_sub(4));
    let h = 16u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let popup_area = Rect::new(x, y, w, h);

    // Clear background
    frame.render_widget(Clear, popup_area);

    let uptime = app
        .connected_at
        .map(|t| {
            let d = t.elapsed();
            let secs = d.as_secs();
            format!(
                "{}h {:02}m {:02}s",
                secs / 3600,
                (secs % 3600) / 60,
                secs % 60
            )
        })
        .unwrap_or_else(|| "—".to_string());

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Transport:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} {}", app.transport.icon(), app.transport.description()),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Server:     ", Style::default().fg(Color::DarkGray)),
            Span::raw(&app.server_addr),
        ]),
        Line::from(vec![
            Span::styled("  State:      ", Style::default().fg(Color::DarkGray)),
            Span::raw(&app.connection_state),
        ]),
        Line::from(vec![
            Span::styled("  Uptime:     ", Style::default().fg(Color::DarkGray)),
            Span::raw(&uptime),
        ]),
        Line::from(vec![
            Span::styled("  Nick:       ", Style::default().fg(Color::DarkGray)),
            Span::raw(&app.nick),
        ]),
        Line::from(vec![
            Span::styled("  Auth:       ", Style::default().fg(Color::DarkGray)),
            Span::raw(
                app.authenticated_did
                    .as_deref()
                    .unwrap_or("guest (unauthenticated)"),
            ),
        ]),
    ];

    if let Some(ref id) = app.iroh_endpoint_id {
        lines.push(Line::from(vec![
            Span::styled("  Iroh ID:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(&id[..16.min(id.len())], Style::default().fg(Color::Magenta)),
            Span::styled("…", Style::default().fg(Color::DarkGray)),
        ]));
    }

    // E2EE status
    let e2ee_channels: Vec<&String> = app.channel_keys.keys().collect();
    let e2ee_str = if e2ee_channels.is_empty() {
        "none".to_string()
    } else {
        e2ee_channels
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    lines.push(Line::from(vec![
        Span::styled("  E2EE:       ", Style::default().fg(Color::DarkGray)),
        Span::raw(e2ee_str),
    ]));

    // P2P status
    let p2p_str = if app.p2p_handle.is_some() {
        "active"
    } else {
        "inactive"
    };
    lines.push(Line::from(vec![
        Span::styled("  P2P DMs:    ", Style::default().fg(Color::DarkGray)),
        Span::raw(p2p_str),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Press Esc or /net to close",
        Style::default().fg(Color::DarkGray),
    )));

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Network Info ")
        .style(Style::default().bg(Color::Black).fg(Color::White))
        .border_style(Style::default().fg(Color::Cyan));

    let popup = Paragraph::new(lines).block(block);
    frame.render_widget(popup, popup_area);
}

fn draw_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    use crate::app::Transport;

    // Transport badge: colored background, white bold text
    let badge_bg = match app.transport {
        Transport::Tcp => Color::Red,
        Transport::Tls => Color::Green,
        Transport::WebSocket => Color::Cyan,
        Transport::Iroh => Color::Magenta,
    };

    let auth_str = match &app.authenticated_did {
        Some(did) => format!(" auth:{did}"),
        None => " guest".to_string(),
    };

    let uptime = app
        .connected_at
        .map(|t| {
            let d = t.elapsed();
            if d.as_secs() < 60 {
                format!("{}s", d.as_secs())
            } else if d.as_secs() < 3600 {
                format!("{}m", d.as_secs() / 60)
            } else {
                format!("{}h{}m", d.as_secs() / 3600, (d.as_secs() % 3600) / 60)
            }
        })
        .unwrap_or_default();

    let spans = vec![
        Span::styled(
            format!(" {} {} ", app.transport.icon(), app.transport.label()),
            Style::default()
                .bg(badge_bg)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                " {} | {}{} | {} ",
                app.connection_state, app.nick, auth_str, uptime
            ),
            Style::default().bg(Color::DarkGray).fg(Color::White),
        ),
    ];

    let status = Paragraph::new(Line::from(spans));
    frame.render_widget(status, area);
}

fn draw_tab_bar(frame: &mut Frame, app: &App, area: Rect) {
    let names = app.buffer_names();
    let active_idx = names
        .iter()
        .position(|n| n == &app.active_buffer)
        .unwrap_or(0);

    let titles: Vec<Line> = names
        .iter()
        .map(|n| {
            let buf = app.buffers.get(n);
            let unread = buf.map(|b| b.unread).unwrap_or(0);
            let has_mention = buf.map(|b| b.has_mention).unwrap_or(false);
            let is_active = n == &app.active_buffer;
            // DID-keyed DM buffers render as the peer's nick, not the raw DID.
            let label = app.display_name(n);

            if is_active {
                Line::from(label)
            } else if has_mention {
                // Red bold for mentions
                Line::from(vec![
                    Span::styled(
                        label,
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(format!(" ({unread})"), Style::default().fg(Color::Red)),
                ])
            } else if unread > 0 {
                // Cyan for unread activity
                Line::from(vec![
                    Span::styled(label, Style::default().fg(Color::Cyan)),
                    Span::styled(format!(" ({unread})"), Style::default().fg(Color::Cyan)),
                ])
            } else {
                Line::from(label)
            }
        })
        .collect();

    let tabs = Tabs::new(titles)
        .select(active_idx)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .divider("|");

    frame.render_widget(tabs, area);
}

fn draw_messages(frame: &mut Frame, app: &mut App, area: Rect) {
    let title = {
        let buffer = match app.buffers.get(&app.active_buffer) {
            Some(b) => b,
            None => return,
        };
        let display = app.display_name(&buffer.name);
        match &buffer.topic {
            Some(topic) => format!(" {display} — {topic} "),
            None => format!(" {display} "),
        }
    };

    // Draw the block border first, then work inside it
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    #[cfg(feature = "inline-images")]
    let has_picker = app.picker.is_some();
    #[cfg(not(feature = "inline-images"))]
    let has_picker = false;

    let buffer = app.buffers.get(&app.active_buffer).unwrap();
    let inner_height = inner.height as usize;
    let inner_width = inner.width as usize;

    // Use the module-level wrapped_height so layout math is testable.

    // Calculate height of each message including wrapping + images
    let msg_heights: Vec<usize> = buffer
        .messages
        .iter()
        .map(|msg| {
            #[allow(unused_mut)]
            let mut h = wrapped_height(msg, inner_width);
            #[cfg(feature = "inline-images")]
            if has_picker {
                if let Some(ref url) = msg.image_url {
                    let cache = app.image_cache.lock().unwrap();
                    if matches!(cache.get(url.as_str()), Some(ImageState::Ready(_))) {
                        h += IMAGE_ROWS as usize;
                    }
                }
            }
            let _ = (has_picker, &msg.image_url); // suppress unused warnings
            h
        })
        .collect();

    let scroll = buffer.scroll as usize;

    // Find the range of messages to display, working backwards from the end
    let mut remaining = inner_height + scroll;
    let mut start_idx = msg_heights.len();
    for (i, &h) in msg_heights.iter().enumerate().rev() {
        if remaining == 0 {
            break;
        }
        start_idx = i;
        remaining = remaining.saturating_sub(h);
    }

    // Skip the scroll offset from the bottom
    let mut visible_msgs: Vec<(usize, usize)> = Vec::new(); // (msg_index, height)
    let mut total_visible: usize = 0;
    for (i, &h) in msg_heights.iter().enumerate().skip(start_idx) {
        visible_msgs.push((i, h));
        total_visible += h;
    }

    // Trim from top if we overshoot
    let mut rows_to_skip_top = if total_visible > inner_height + scroll {
        total_visible - inner_height - scroll
    } else {
        0
    };

    // Render messages top-down within the inner area
    let mut y = inner.y;
    let max_y = inner.y + inner.height;

    // Collect image URLs that need protocol state created
    #[allow(unused_mut, unused_variables)]
    let mut needs_proto: Vec<String> = Vec::new();

    for &(msg_idx, msg_h) in &visible_msgs {
        // Skip messages consumed by top overflow
        if rows_to_skip_top >= msg_h {
            rows_to_skip_top -= msg_h;
            continue;
        }

        if y >= max_y {
            break;
        }

        let msg = &buffer.messages[msg_idx];

        // Render the message with word wrapping
        if y < max_y {
            use ratatui::text::Text;
            use ratatui::widgets::Wrap;

            let is_mention = !msg.is_system && crate::app::is_mention(&msg.text, &app.nick);

            let text = if msg.is_system {
                // System messages may legitimately contain `\n` (MOTD,
                // some server NOTICEs). Split and render each source
                // line as its own row, with the prefix on the first
                // and an aligned indent on continuations.
                let prefix = format!("{} *** ", msg.timestamp);
                let indent = " ".repeat(prefix.chars().count());
                let source_lines: Vec<&str> = if msg.text.is_empty() {
                    vec![""]
                } else {
                    msg.text.split('\n').collect()
                };
                let lines: Vec<Line> = source_lines
                    .iter()
                    .enumerate()
                    .map(|(i, line)| {
                        Line::from(vec![
                            Span::styled(
                                if i == 0 {
                                    prefix.clone()
                                } else {
                                    indent.clone()
                                },
                                Style::default().fg(Color::DarkGray),
                            ),
                            Span::styled((*line).to_string(), Style::default().fg(Color::Cyan)),
                        ])
                    })
                    .collect();
                Text::from(lines)
            } else {
                let msg_style = if is_mention {
                    Style::default().fg(Color::White).bg(Color::DarkGray)
                } else {
                    Style::default()
                };
                let is_pinned = msg
                    .msgid
                    .as_deref()
                    .is_some_and(|id| buffer.pinned.contains(id));

                // First-line prefix spans: timestamp + (pin) + <from> ".
                // Continuation lines use an equal-width indent so the
                // body of every source line is column-aligned.
                let mut first_prefix_spans: Vec<Span> = vec![Span::styled(
                    format!("{} ", msg.timestamp),
                    Style::default().fg(Color::DarkGray),
                )];
                if is_pinned {
                    first_prefix_spans
                        .push(Span::styled("📌 ", Style::default().fg(Color::Yellow)));
                }
                // The sender's own device signed this one, and the server
                // relayed it untouched. Server-signed and unsigned traffic
                // gets no marker — the badge claims only what the wire proved.
                if msg.is_signed {
                    first_prefix_spans.push(Span::styled("🔒 ", Style::default().fg(Color::Green)));
                }
                first_prefix_spans.push(Span::styled(
                    format!("<{}> ", msg.from),
                    if is_mention {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Green)
                    },
                ));
                let prefix_width: usize = first_prefix_spans
                    .iter()
                    .map(|s| s.content.chars().count())
                    .sum();
                let continuation_indent = " ".repeat(prefix_width);

                let mut lines: Vec<Line> = Vec::new();
                // Reply indicator: small row above the message showing the
                // parent's author + snippet, so threading is legible.
                if let Some(ref parent_id) = msg.reply_to {
                    let label = reply_indicator_label(buffer, parent_id);
                    lines.push(Line::from(Span::styled(
                        label,
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::ITALIC),
                    )));
                }

                if msg.is_deleted {
                    let mut spans = first_prefix_spans.clone();
                    spans.push(Span::styled(
                        "[deleted]",
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::ITALIC),
                    ));
                    lines.push(Line::from(spans));
                } else {
                    let source_lines: Vec<&str> = if msg.text.is_empty() {
                        vec![""]
                    } else {
                        msg.text.split('\n').collect()
                    };
                    let last = source_lines.len() - 1;
                    for (i, source_line) in source_lines.iter().enumerate() {
                        let mut spans: Vec<Span> = if i == 0 {
                            first_prefix_spans.clone()
                        } else {
                            vec![Span::raw(continuation_indent.clone())]
                        };
                        spans.extend(markdown_spans(source_line, msg_style));
                        if i == last && msg.is_edited {
                            spans.push(Span::styled(
                                " (edited)",
                                Style::default()
                                    .fg(Color::DarkGray)
                                    .add_modifier(Modifier::ITALIC),
                            ));
                        }
                        lines.push(Line::from(spans));
                    }
                }
                Text::from(lines)
            };

            let h = wrapped_height(msg, inner.width as usize) as u16;
            let rows = h.min(max_y - y);
            let msg_area = Rect::new(inner.x, y, inner.width, rows);
            frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), msg_area);
            y += rows;
        }

        // Render image if present and ready
        #[cfg(feature = "inline-images")]
        if has_picker && y < max_y {
            if let Some(ref url) = msg.image_url {
                let cache = app.image_cache.lock().unwrap();
                if matches!(cache.get(url.as_str()), Some(ImageState::Ready(_))) {
                    let img_h = IMAGE_ROWS.min(max_y - y);
                    needs_proto.push(url.clone());
                    drop(cache);

                    let img_area = Rect::new(inner.x + 2, y, inner.width.saturating_sub(4), img_h);
                    y += img_h;

                    // Create protocol state if needed, then render
                    if !app.image_protos.contains_key(url) {
                        if let Some(ref mut picker) = app.picker {
                            let cache = app.image_cache.lock().unwrap();
                            if let Some(ImageState::Ready(img)) = cache.get(url.as_str()) {
                                let proto = picker.new_resize_protocol(img.clone());
                                drop(cache);
                                app.image_protos.insert(url.clone(), proto);
                            }
                        }
                    }
                    if let Some(proto) = app.image_protos.get_mut(url) {
                        let widget = ratatui_image::StatefulImage::<
                            ratatui_image::protocol::StatefulProtocol,
                        >::default();
                        frame.render_stateful_widget(widget, img_area, proto);
                    }
                } else if matches!(cache.get(url.as_str()), Some(ImageState::Loading)) {
                    drop(cache);
                    let loading = Paragraph::new("  ⏳ Loading image...")
                        .style(Style::default().fg(Color::DarkGray));
                    let load_area = Rect::new(inner.x, y, inner.width, 1);
                    frame.render_widget(loading, load_area);
                    y += 1;
                }
            }
        }
    }
}

fn draw_nicklist(frame: &mut Frame, app: &App, area: Rect) {
    let buffer = match app.buffers.get(&app.active_buffer) {
        Some(b) => b,
        None => return,
    };

    let inner_height = area.height.saturating_sub(2) as usize;

    // Sort nicks: ops (@) first, then voiced (+), then regular
    let mut nicks = buffer.nicks.clone();
    nicks.sort_by(|a, b| {
        let rank = |n: &str| -> u8 {
            if n.starts_with('@') {
                0
            } else if n.starts_with('+') {
                1
            } else {
                2
            }
        };
        rank(a).cmp(&rank(b)).then(a.cmp(b))
    });

    let nick_scroll = buffer
        .nick_scroll
        .min(nicks.len().saturating_sub(inner_height));
    let lines: Vec<Line> = nicks
        .iter()
        .skip(nick_scroll)
        .take(inner_height)
        .map(|n| {
            let (prefix, name) = if n.starts_with('@') || n.starts_with('+') {
                (&n[..1], &n[1..])
            } else {
                ("", n.as_str())
            };
            let prefix_color = if prefix == "@" {
                Color::Yellow
            } else {
                Color::Cyan
            };
            Line::from(vec![
                Span::styled(
                    prefix,
                    Style::default()
                        .fg(prefix_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(name),
            ])
        })
        .collect();

    let title = format!(" {} ", nicks.len());
    let nicklist = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(nicklist, area);
}

/// Build the label for a reply indicator. Returns one of three forms:
///
/// - `   ↳ replying to <author>: "snippet…"` when the parent is present
///   and undeleted.
/// - `   ↳ replying to <author> (deleted)` when the parent is present
///   but its body has been deleted — we don't quote empty content.
/// - `   ↳ replying to (unknown)` when the parent isn't in this buffer
///   (evicted from the ring buffer or never received).
///
/// How many terminal rows a single message occupies after `\n`-splitting
/// per source line and wrapping each at `width`. The first line carries
/// the timestamp + sender prefix; continuation lines are indented to the
/// same width so the body is column-aligned.
pub(crate) fn wrapped_height(msg: &crate::app::BufferLine, width: usize) -> usize {
    if width == 0 {
        return 1;
    }
    let prefix_len = if msg.is_system {
        // "HH:MM:SS *** "
        msg.timestamp.len() + 1 + 4
    } else {
        // "HH:MM:SS <nick> "
        msg.timestamp.len() + 1 + msg.from.len() + 2 + 1
    };
    let base = if msg.is_deleted {
        (prefix_len + "[deleted]".len()).div_ceil(width).max(1)
    } else {
        let mut lines: Vec<&str> = msg.text.split('\n').collect();
        if lines.is_empty() {
            lines.push("");
        }
        let last = lines.len() - 1;
        lines
            .iter()
            .enumerate()
            .map(|(i, line)| {
                let body_len = if i == last && msg.is_edited {
                    line.len() + " (edited)".len()
                } else {
                    line.len()
                };
                (prefix_len + body_len).div_ceil(width).max(1)
            })
            .sum()
    };
    if msg.reply_to.is_some() {
        base + 1
    } else {
        base
    }
}

pub fn reply_indicator_label(buffer: &crate::app::Buffer, parent_id: &str) -> String {
    match buffer.find_by_msgid(parent_id) {
        Some(parent) if parent.is_deleted => {
            format!("   ↳ replying to <{}> (deleted)", parent.from)
        }
        Some(parent) => {
            // Collapse internal whitespace (newlines, tabs, runs of spaces)
            // to a single space so the indicator stays on one terminal row.
            // Without this, a parent that legitimately contained `\n` would
            // wrap mid-snippet but `wrapped_height` only reserved one row.
            let snippet: String = parent
                .text
                .chars()
                .take(50)
                .map(|c| if c == '\n' || c == '\t' { ' ' } else { c })
                .collect();
            let ellipsis = if parent.text.chars().count() > 50 {
                "…"
            } else {
                ""
            };
            format!(
                "   ↳ replying to <{}>: \"{snippet}{ellipsis}\"",
                parent.from
            )
        }
        None => "   ↳ replying to (unknown)".into(),
    }
}

/// Tokenize a chat line into styled spans, honoring inline markdown:
/// `*bold*`, `_italic_`, `` `code` ``, `~strike~`. Delimiters that don't
/// pair up are emitted as literal characters. Code spans are not re-parsed
/// for other markup. Slack/Discord-style single-char delimiters (not
/// CommonMark `**bold**`) since this is chat.
pub fn markdown_spans(text: &str, base: Style) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let mut buf = String::new();

    let flush_buf = |buf: &mut String, out: &mut Vec<Span<'static>>| {
        if !buf.is_empty() {
            out.push(Span::styled(std::mem::take(buf), base));
        }
    };

    while i < chars.len() {
        let c = chars[i];
        if matches!(c, '*' | '_' | '`' | '~') {
            // Doubled delimiters (`**`, `__`, etc.) are not our convention
            // (single-char à la Slack) — emit both as literals to avoid the
            // surprising "*bold*" rendering when the user typed CommonMark
            // `**bold**`.
            if i + 1 < chars.len() && chars[i + 1] == c {
                buf.push(c);
                buf.push(c);
                i += 2;
                continue;
            }
            // Opening rules: previous char (if any) is not alphanumeric;
            // next char exists and is not whitespace. This avoids matching
            // `*` inside identifiers like `a*b` or trailing punctuation.
            let prev_ok = i == 0 || !chars[i - 1].is_alphanumeric();
            let next_ok = i + 1 < chars.len() && !chars[i + 1].is_whitespace();
            if prev_ok && next_ok {
                // Find matching close: closing char must not be preceded
                // by whitespace, must have non-empty content, and the
                // following char (if any) must not be alphanumeric — the
                // mirror of the opening rule, so identifiers like
                // `snake_case_var` and tokens like `*foo*bar` aren't
                // chopped up.
                let mut close = None;
                let mut j = i + 1;
                while j < chars.len() {
                    if chars[j] == c
                        && !chars[j - 1].is_whitespace()
                        && j > i + 1
                        && (j + 1 >= chars.len() || !chars[j + 1].is_alphanumeric())
                    {
                        close = Some(j);
                        break;
                    }
                    j += 1;
                }
                if let Some(end) = close {
                    flush_buf(&mut buf, &mut out);
                    let content: String = chars[i + 1..end].iter().collect();
                    let style = match c {
                        '*' => base.add_modifier(Modifier::BOLD),
                        '_' => base.add_modifier(Modifier::ITALIC),
                        '`' => Style::default().fg(Color::LightYellow).bg(Color::Black),
                        '~' => base.add_modifier(Modifier::CROSSED_OUT),
                        _ => base,
                    };
                    out.push(Span::styled(content, style));
                    i = end + 1;
                    continue;
                }
            }
        }
        buf.push(c);
        i += 1;
    }
    flush_buf(&mut buf, &mut out);
    out
}

fn draw_input(frame: &mut Frame, app: &App, area: Rect) {
    let title = if app.editor.is_vi_normal() {
        " Input [NORMAL] "
    } else {
        " Input "
    };
    let input = Paragraph::new(app.editor.text.as_str())
        .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(input, area);

    // Place cursor
    let cursor_x = area.x + 1 + app.editor.cursor as u16;
    let cursor_y = area.y + 1;
    frame.set_cursor_position((cursor_x, cursor_y));
}

#[cfg(test)]
mod tests {
    use super::markdown_spans;
    use ratatui::style::{Modifier, Style};

    /// Stringify a list of spans by joining their text content. Used to
    /// verify segmentation independently of style assertions.
    fn flat(spans: &[ratatui::text::Span<'_>]) -> String {
        spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn markdown_plain_text_is_one_span() {
        let spans = markdown_spans("hello world", Style::default());
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content, "hello world");
    }

    #[test]
    fn markdown_bold_emits_styled_span() {
        let spans = markdown_spans("hi *there* friend", Style::default());
        assert_eq!(flat(&spans), "hi there friend");
        // The middle span should have the BOLD modifier set.
        let bold = spans
            .iter()
            .find(|s| s.content == "there")
            .expect("bold span present");
        assert!(bold.style.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn markdown_italic_and_strike_and_code() {
        let spans = markdown_spans("a _b_ c `d` e ~f~ g", Style::default());
        assert_eq!(flat(&spans), "a b c d e f g");
        let italic = spans.iter().find(|s| s.content == "b").unwrap();
        assert!(italic.style.add_modifier.contains(Modifier::ITALIC));
        let strike = spans.iter().find(|s| s.content == "f").unwrap();
        assert!(strike.style.add_modifier.contains(Modifier::CROSSED_OUT));
        // Code keeps its content; styling differs from base but text is preserved.
        assert!(spans.iter().any(|s| s.content == "d"));
    }

    #[test]
    fn markdown_unmatched_delimiter_stays_literal() {
        let spans = markdown_spans("just one * star", Style::default());
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content, "just one * star");
    }

    #[test]
    fn markdown_skips_in_word_delimiter() {
        // `a*b*c` should NOT be parsed as bold — common false positive.
        let spans = markdown_spans("a*b*c", Style::default());
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content, "a*b*c");
    }

    #[test]
    fn markdown_rejects_whitespace_adjacent_delimiter() {
        // `* foo *` (space after open / before close) should stay literal.
        let spans = markdown_spans("* foo *", Style::default());
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content, "* foo *");
    }

    /// CORRECTNESS: when the parent of a reply has been deleted, the
    /// indicator used to render `↳ replying to <alice>: ""` (an empty
    /// quote) — both ugly and a tiny information leak (it confirms the
    /// referenced message existed but was deleted, while showing the
    /// author). Render an explicit `(deleted)` instead.
    #[test]
    fn reply_label_for_deleted_parent_says_deleted() {
        use crate::app::{Buffer, BufferLine};
        let mut buf = Buffer::new("#test");
        buf.push(BufferLine {
            timestamp: "12:00:00".into(),
            from: "alice".into(),
            text: "secret".into(),
            is_system: false,
            image_url: None,
            msgid: Some("01PARENT".into()),
            is_edited: false,
            is_deleted: false,
            reply_to: None,
            edit_of: None,
            is_signed: false,
            account: None,
        });
        buf.apply_delete("alice", "01PARENT");

        let label = super::reply_indicator_label(&buf, "01PARENT");
        assert!(
            label.contains("(deleted)"),
            "label should mark deleted parent: {label:?}"
        );
        assert!(
            !label.contains("\"\""),
            "must not show empty quotes: {label:?}"
        );
    }

    #[test]
    fn reply_label_for_unknown_parent_says_unknown() {
        use crate::app::Buffer;
        let buf = Buffer::new("#test");
        let label = super::reply_indicator_label(&buf, "01MISSING");
        assert!(label.contains("(unknown)"), "got {label:?}");
    }

    /// LAYOUT: a parent message containing `\n` (legitimate via the
    /// existing `sanitize_text` allow-list) bled the newline into the
    /// reply indicator's snippet, which is supposed to be a single
    /// quote on a single line. The downstream renderer would split it
    /// across two terminal rows but `wrapped_height` only reserves one,
    /// corrupting layout for everything after the indicator.
    #[test]
    fn reply_label_collapses_newlines_in_snippet() {
        use crate::app::{Buffer, BufferLine};
        let mut buf = Buffer::new("#test");
        buf.push(BufferLine {
            timestamp: "12:00:00".into(),
            from: "alice".into(),
            text: "line1\nline2".into(),
            is_system: false,
            image_url: None,
            msgid: Some("01P".into()),
            is_edited: false,
            is_deleted: false,
            reply_to: None,
            edit_of: None,
            is_signed: false,
            account: None,
        });
        let label = super::reply_indicator_label(&buf, "01P");
        assert!(
            !label.contains('\n'),
            "indicator must be one line: {label:?}"
        );
        assert!(
            !label.contains('\t'),
            "tab also breaks alignment: {label:?}"
        );
    }

    #[test]
    fn reply_label_for_present_parent_includes_snippet() {
        use crate::app::{Buffer, BufferLine};
        let mut buf = Buffer::new("#test");
        buf.push(BufferLine {
            timestamp: "12:00:00".into(),
            from: "alice".into(),
            text: "hello world".into(),
            is_system: false,
            image_url: None,
            msgid: Some("01P".into()),
            is_edited: false,
            is_deleted: false,
            reply_to: None,
            edit_of: None,
            is_signed: false,
            account: None,
        });
        let label = super::reply_indicator_label(&buf, "01P");
        assert!(label.contains("alice"), "got {label:?}");
        assert!(label.contains("hello world"), "got {label:?}");
    }

    /// CORRECTNESS: mention detection used a naive `.contains(nick)`,
    /// which false-positives whenever the nick is a substring of any
    /// word — e.g. nick "al" matches "alphabet", "ben" matches "benevolent".
    /// Short or common-substring nicks would highlight every message,
    /// destroying the signal of an actual ping.
    #[test]
    fn is_mention_requires_word_boundary() {
        use crate::app::is_mention;
        assert!(is_mention("hi alice", "alice"));
        assert!(is_mention("alice: hello", "alice"));
        assert!(is_mention("ALICE!", "alice")); // case-insensitive
        // No false positive when nick is a substring of a longer word.
        assert!(!is_mention("alphabet soup", "al"));
        assert!(!is_mention("benevolent", "ben"));
        assert!(!is_mention("malicious", "alice"));
        // Empty nick must not match anything (otherwise every line is "mention").
        assert!(!is_mention("hello world", ""));
    }

    /// CORRECTNESS: the closing delimiter must not be followed by an
    /// alphanumeric, mirroring the opening rule. Without this check,
    /// `_foo_bar` parses the leading `_foo_` as italic and emits "bar"
    /// as plain text — an obvious wrong segmentation since the original
    /// is clearly an identifier (snake_case).
    #[test]
    fn markdown_closing_delim_must_not_touch_alphanumeric() {
        let spans = markdown_spans("snake_case_var", Style::default());
        assert_eq!(flat(&spans), "snake_case_var");
        assert!(
            spans
                .iter()
                .all(|s| !s.style.add_modifier.contains(Modifier::ITALIC)),
            "snake_case identifiers must not be italicized"
        );

        // Symmetric for *: `*foo*bar` should stay literal too.
        let spans = markdown_spans("*foo*bar", Style::default());
        assert_eq!(flat(&spans), "*foo*bar");
        assert!(
            spans
                .iter()
                .all(|s| !s.style.add_modifier.contains(Modifier::BOLD)),
            "got spans = {spans:?}"
        );
    }

    /// CORRECTNESS: `**bold**` (Discord/CommonMark double-star) is
    /// commonly typed in chat. Our convention is single-star; we should
    /// at minimum not render `**bold**` as "*bold*" with the leading
    /// asterisk visible inside a bolded span. Render it as literal text
    /// so it doesn't surprise users.
    #[test]
    fn markdown_doubled_delimiters_stay_literal() {
        let spans = markdown_spans("**bold**", Style::default());
        assert_eq!(flat(&spans), "**bold**");
        // No span should be styled as bold — the doubled delimiter is
        // not our convention.
        assert!(
            spans
                .iter()
                .all(|s| !s.style.add_modifier.contains(Modifier::BOLD)),
            "doubled `**` should not produce a bold span"
        );
    }

    #[test]
    fn markdown_handles_unicode() {
        let spans = markdown_spans("hi *résumé* ok 🔥", Style::default());
        assert_eq!(flat(&spans), "hi résumé ok 🔥");
        assert!(spans.iter().any(|s| s.content == "résumé"));
    }

    // ─── wrapped_height (multi-line layout math) ──────────────────

    fn line(text: &str) -> crate::app::BufferLine {
        crate::app::BufferLine {
            timestamp: "12:00:00".into(),
            from: "alice".into(),
            text: text.into(),
            is_system: false,
            image_url: None,
            msgid: None,
            is_edited: false,
            is_deleted: false,
            reply_to: None,
            edit_of: None,
            is_signed: false,
            account: None,
        }
    }

    /// Single-line text within the width fits on one row. Prefix
    /// "12:00:00 <alice> " = 17 chars; body "hello" = 5; total 22.
    #[test]
    fn wrapped_height_single_line_fits() {
        let h = super::wrapped_height(&line("hello"), 80);
        assert_eq!(h, 1);
    }

    /// Three source lines (`\n`-separated) get three terminal rows
    /// when each fits within `width`.
    #[test]
    fn wrapped_height_three_source_lines() {
        let h = super::wrapped_height(&line("a\nb\nc"), 80);
        assert_eq!(h, 3);
    }

    /// A single source line that exceeds `width` wraps onto extra rows.
    #[test]
    fn wrapped_height_long_single_line_wraps() {
        // prefix 17 chars + 100-char body = 117 total chars at width 40
        // → ceil(117/40) = 3 rows
        let body = "x".repeat(100);
        let h = super::wrapped_height(&line(&body), 40);
        assert_eq!(h, 3);
    }

    /// Multi-line where each individual line wraps independently:
    /// row counts sum, each line gets its own wrap math.
    #[test]
    fn wrapped_height_multiline_each_wraps_independently() {
        // Two source lines, each 50 chars. Width 40, prefix 17.
        // Per-line: ceil((17+50)/40) = 2 rows. Total: 4.
        let body = format!("{}\n{}", "a".repeat(50), "b".repeat(50));
        let h = super::wrapped_height(&line(&body), 40);
        assert_eq!(h, 4);
    }

    /// `(edited)` suffix applies only to the LAST source line, not
    /// every line.
    #[test]
    fn wrapped_height_edited_suffix_only_on_last_line() {
        let mut m = line("a\nb\nc");
        m.is_edited = true;
        // First two lines: prefix + 1 char = 18 chars → 1 row each.
        // Last line: prefix + 1 + " (edited)".len()=9 → 27 chars → 1 row.
        let h = super::wrapped_height(&m, 80);
        assert_eq!(h, 3);
    }

    /// Reply indicator adds one row above the body, regardless of
    /// how many source lines the body has.
    #[test]
    fn wrapped_height_reply_indicator_adds_one_row() {
        let mut m = line("a\nb");
        m.reply_to = Some("01PARENT".into());
        let h = super::wrapped_height(&m, 80);
        // 2 body rows + 1 reply indicator = 3
        assert_eq!(h, 3);
    }

    /// Empty body still occupies one row.
    #[test]
    fn wrapped_height_empty_body_one_row() {
        let h = super::wrapped_height(&line(""), 80);
        assert_eq!(h, 1);
    }
}
