//! Question-answering for the live call. When a participant addresses
//! the bot by name in channel chat, we send their question (with the
//! rolling transcript as context) to a Groq model and get back a short
//! answer suitable for both posting and speaking aloud. The answer
//! model is agentic — it searches the web when a question needs it.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::video::{SceneKind, SceneSpec};
use crate::whiteboard::Step;

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    #[serde(default)]
    content: String,
    /// Tool calls the agentic model ran — present on `groq/compound`.
    #[serde(default)]
    executed_tools: Vec<ExecutedTool>,
}

#[derive(Deserialize)]
struct ExecutedTool {
    #[serde(rename = "type", default)]
    tool_type: String,
    #[serde(default)]
    search_results: Option<SearchResults>,
}

#[derive(Deserialize)]
struct SearchResults {
    #[serde(default)]
    results: Vec<SearchResult>,
}

#[derive(Deserialize)]
struct SearchResult {
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
}

/// A web source an answer drew on — posted into the channel so people
/// can read more.
#[derive(Debug, Clone)]
pub struct Source {
    pub title: String,
    pub url: String,
}

/// A spoken answer, plus the top web source behind it when the agentic
/// model searched the web.
#[derive(Debug, Clone)]
pub struct Answer {
    pub text: String,
    pub source: Option<Source>,
}

const SYSTEM: &str = "You are Eliza, a live voice-AND-video agent in a \
freeq call. Your reply is spoken aloud while an illustrated visual \
appears on your video tile in parallel — you have a voice, a tile that \
shows pictures, and the ability to see participants' shared cameras \
and screens. You are NOT just a language model.\n\n\
Rules — follow strictly:\n\
1. PLAIN PROSE ONLY. No markdown, no bullet points, no emoji, no \
URLs, no code, no JSON, no XML, no `<tool>` blocks, no `<function>` \
blocks, no `python(...)` calls, no '```' fences. Speak as a person \
would speak. The text is fed to TTS verbatim — anything that isn't a \
sentence gets read aloud as garbage.\n\
2. Brief: 1-3 short sentences, conversational.\n\
3. NEVER disclaim that you are 'just a language model' or that you \
'can't show pictures'. You absolutely can. When someone asks 'show me \
a picture of X', 'what does Y look like', 'show me Z', or 'draw me a \
W', say yes and answer briefly: 'Here's the Eiffel Tower at night.' / \
'That's what a quokka looks like.' / 'Here it is.' — the picture WILL \
appear as you speak. Sound confident, not apologetic. But never \
INVENT a visual observation: if no image came with this message, \
don't claim to be looking at one right now.\n\
4. Answer NOW, in this reply, from what you have. NEVER promise to \
'check', 'look up', 'get back to you', or ask for 'a moment' — there \
is no later; an unfulfilled promise is worse than a plain answer. If \
you have web search available, use it silently and deliver the \
result. If you don't and the question needs live data (weather, \
prices, scores, breaking news), give your best answer and say plainly \
that it may not reflect this minute.\n\
5. The LIVE CALL TRANSCRIPT section (when present) is what has been \
said in THIS call — use it for questions about the conversation. A \
PAST EXCHANGES section is older sessions, possibly days old — never \
treat it as something said just now.\n\
6. Don't repeat the question. If you genuinely don't know, say so \
plainly.\n\
7. NEVER mention the words 'scene card', 'video tile', 'image query', \
'transcript', or any other internal mechanism — those are how you \
work, not what you say.";

/// Answer `question` against `transcript` via Groq chat completions.
/// `transcript` is the joined `<nick>: <utterance>` lines so far (may
/// be empty early in a call). When the agentic model searched the web,
/// the returned [`Answer`] carries the top source so the caller can
/// post the link.
pub async fn answer(
    client: &reqwest::Client,
    api_key: &str,
    model: &str,
    transcript: &str,
    question: &str,
) -> Result<Answer> {
    let body = serde_json::json!({
        "model": model,
        "max_tokens": 320,
        "temperature": 0.3,
        "messages": [
            { "role": "system", "content": SYSTEM },
            { "role": "user", "content": user_prompt(transcript, question) },
        ],
    });

    let resp = client
        .post("https://api.groq.com/openai/v1/chat/completions")
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .context("groq chat request failed")?;

    let status = resp.status();
    if !status.is_success() {
        let err = resp.text().await.unwrap_or_default();
        anyhow::bail!("groq chat {status}: {err}");
    }
    let parsed: ChatResponse = resp.json().await.context("groq chat parse failed")?;
    let Some(choice) = parsed.choices.into_iter().next() else {
        anyhow::bail!("groq chat returned no choices");
    };
    let text = choice.message.content.trim().to_string();
    if text.is_empty() {
        anyhow::bail!("groq chat returned no content");
    }
    let source = extract_source(&choice.message.executed_tools);
    Ok(Answer { text, source })
}

/// The user-turn prompt: pre-labeled context sections plus the
/// question. Shared by [`answer`] and [`answer_streaming`].
///
/// `context` arrives ALREADY labeled by the caller (a "LIVE CALL
/// TRANSCRIPT" section, an optional "PAST EXCHANGES" section, …) — we
/// must not wrap it in another header. The old behaviour stamped
/// "Call transcript so far:" over everything, which made days-old
/// memory recall read as things said in this call.
fn user_prompt(context: &str, question: &str) -> String {
    let context = if context.trim().is_empty() {
        "(no call context yet — the call just started)"
    } else {
        context
    };
    format!("{context}\n\nQuestion: {question}")
}

/// The top web source behind an answer — the first result of the first
/// `search` tool the agentic model ran, if any.
fn extract_source(tools: &[ExecutedTool]) -> Option<Source> {
    tools
        .iter()
        .filter(|t| t.tool_type == "search")
        .filter_map(|t| t.search_results.as_ref())
        .flat_map(|sr| &sr.results)
        .find(|r| !r.url.trim().is_empty())
        .map(|r| Source {
            title: r.title.trim().to_string(),
            url: r.url.trim().to_string(),
        })
}

// ── Question routing ─────────────────────────────────────────────────

/// How a spoken question should be answered — decided by a fast
/// classifier so routing doesn't depend on brittle cue-phrase lists.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct QuestionRoute {
    /// The asker wants the bot to LOOK at their camera/screen.
    #[serde(default)]
    pub visual: bool,
    /// Needs data from right now (weather, prices, scores, news) — the
    /// fast voice model would have to hallucinate it.
    #[serde(default)]
    pub live_data: bool,
    /// A TASK that needs the agentic Claude Code brain (tools + file access,
    /// multi-step work) rather than a spoken answer or a single web lookup.
    #[serde(default)]
    pub agent: bool,
}

/// Model for [`route_question`] — small and fast (~100-200 ms); the
/// router runs in parallel with context assembly so it adds no latency
/// to the answer path.
pub const ROUTER_MODEL: &str = "llama-3.1-8b-instant";

const ROUTER_SYSTEM: &str = "You route a request spoken aloud in a live \
video call to the right pipeline. Output ONLY a JSON object: \
{\"visual\": bool, \"live_data\": bool, \"agent\": bool}.\n\
visual=true when the asker wants you to LOOK at their live camera or \
shared screen: anything about what they're showing, holding, wearing, \
pointing at, their surroundings, text/numbers on their screen or tile, \
'do you see...', 'what is this', 'read this'.\n\
live_data=true when answering requires CURRENT real-world data that \
changes hour to hour or day to day: weather or forecasts, stock or \
crypto prices, sports scores or fixtures, breaking news, today's \
events, current status of services. NOT for stable facts, math, \
opinions, the call itself, or anything answerable from general \
knowledge.\n\
agent=true when it is a TASK that needs a capable coding/agentic \
assistant with tools and file access to actually DO something — write, \
edit, refactor or debug code; run commands; build, test or deploy; \
create or modify files; carry out a multi-step job; do deep research \
and produce an artifact; or change your own behavior/configuration. \
Phrases like 'write...', 'build...', 'fix...', 'add a...', 'create...', \
'run...', 'set up...', 'refactor...', 'implement...', 'make a script...'. \
NOT for a question you can simply answer by talking, and NOT for a plain \
current-facts lookup.\n\
All false for an ordinary question you can just answer. When unsure, \
all false.";

/// Classify a spoken question with a fast small model. Returns `None`
/// on any error or non-JSON reply — callers fall back to the cue-list
/// heuristics, so a router hiccup degrades, never breaks.
pub async fn route_question(
    client: &reqwest::Client,
    api_key: &str,
    question: &str,
) -> Option<QuestionRoute> {
    let body = serde_json::json!({
        "model": ROUTER_MODEL,
        "max_tokens": 64,
        "temperature": 0,
        "response_format": { "type": "json_object" },
        "messages": [
            { "role": "system", "content": ROUTER_SYSTEM },
            { "role": "user", "content": question },
        ],
    });
    let resp = client
        .post("https://api.groq.com/openai/v1/chat/completions")
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let parsed: ChatResponse = resp.json().await.ok()?;
    let text = parsed.choices.first()?.message.content.trim().to_string();
    let v = extract_json(&text)?;
    serde_json::from_value::<QuestionRoute>(v).ok()
}

/// Cue-list fallback for the `agent` route — UNION'd with the router's
/// semantic verdict so a small-model miss still hands a real task to Claude
/// Code. Fires only when an imperative task verb meets a technical/code/file
/// object (so "write a haiku" stays a self-answer while "write a script"
/// delegates), or on an explicit self-modification request.
pub fn is_agentic_task(question: &str) -> bool {
    let q = question.to_lowercase();
    // Explicit self-modification — always agentic (needs file/tool access).
    const SELF_MOD: [&str; 6] = [
        "your code",
        "your behavior",
        "your prompt",
        "your config",
        "modify yourself",
        "change your",
    ];
    if SELF_MOD.iter().any(|p| q.contains(p)) {
        return true;
    }
    // Imperative "do something" verbs …
    const VERBS: [&str; 18] = [
        "write ",
        "build ",
        "create ",
        "implement ",
        "refactor ",
        "fix ",
        "debug ",
        "add a",
        "add an",
        "set up",
        "run ",
        "deploy",
        "generate ",
        "install ",
        "configure ",
        "commit",
        "make a",
        "rewrite ",
    ];
    // … paired with a technical / code / file / system object.
    const OBJECTS: [&str; 24] = [
        "script",
        "program",
        "code",
        "function",
        "file",
        "repo",
        "repository",
        "test",
        "bug",
        "feature",
        "app",
        "server",
        "endpoint",
        "api",
        "class",
        "module",
        "package",
        "branch",
        "pull request",
        " pr",
        "command",
        "project",
        "database",
        "migration",
    ];
    let has_verb = VERBS.iter().any(|v| q.contains(v));
    let has_object = OBJECTS.iter().any(|o| q.contains(o));
    has_verb && has_object
}

#[cfg(test)]
mod agent_route_tests {
    use super::is_agentic_task;

    #[test]
    fn delegates_real_coding_tasks() {
        assert!(is_agentic_task(
            "write a python script that reverses a string"
        ));
        assert!(is_agentic_task("fix the bug in the login function"));
        assert!(is_agentic_task("add a feature to the app"));
        assert!(is_agentic_task("refactor the auth module"));
        assert!(is_agentic_task("run the tests and commit"));
        assert!(is_agentic_task("change your behavior to be quieter"));
    }

    #[test]
    fn leaves_ordinary_requests_alone() {
        assert!(!is_agentic_task("write a haiku about the ocean"));
        assert!(!is_agentic_task("what is a monad"));
        assert!(!is_agentic_task("what's the weather tomorrow"));
        assert!(!is_agentic_task("tell me about the roman empire"));
        assert!(!is_agentic_task("how are you doing today"));
    }
}

const SCENE_SYSTEM: &str = "You design one visual card for Eliza's \
video tile — a glanceable summary of the answer it just gave on a live \
call. Output ONLY a JSON object:\n\
{\"kind\":\"...\",\"title\":\"...\",\"subtitle\":\"...\",\"points\":[\"...\"],\"accent\":\"#RRGGBB\",\"image_query\":\"...\"}\n\
Pick the kind that best fits the answer:\n\
- \"hero\": one big idea. title = a punchy headline (<=6 words). \
subtitle = a one-line takeaway (<=14 words). points = [].\n\
- \"keypoints\": several distinct points. title = the topic (<=5 \
words). points = 2 to 5 items, each <=9 words. subtitle = \"\".\n\
- \"stat\": a single number carries the answer. title = what it \
measures (<=6 words). points = [the value as a short string, e.g. \
\"70%\" or \"1969\"]. subtitle = context (<=14 words).\n\
- \"timeline\": a sequence or process. title = the process (<=5 \
words). points = 2 to 5 ordered steps, each <=8 words. subtitle = \
\"\".\n\
- \"quote\": a striking statement or definition. title = the line \
itself (<=18 words). subtitle = attribution or source (<=5 words). \
points = [].\n\
Rules:\n\
- All text is plain — no markdown, no emoji, no trailing punctuation on \
points.\n\
- accent: a hex colour (#RRGGBB) that suits the topic's mood.\n\
- image_query: a short, concrete subject to illustrate the topic — a \
specific thing, place, person, or scene in 2 to 6 words (e.g. \"Apollo \
11 Moon landing\", \"deep ocean floor\", \"Marie Curie\"). Name \
something real and depictable; it is used to find a photo.\n\
- Keep every field terse: it is read at a glance on a small tile.";

/// Pull a trimmed string field out of a JSON object (empty if absent).
fn str_field(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Ask the model to design a visual card for the latest answer. Returns
/// a [`SceneSpec`], or `None` when there's nothing worth showing or on
/// any error — eliza then keeps its current tile. Never fails the
/// caller.
pub async fn generate_scene(
    client: &reqwest::Client,
    api_key: &str,
    model: &str,
    question: &str,
    answer: &str,
) -> Option<SceneSpec> {
    let user = format!(
        "Question addressed to Eliza: {question}\n\nThe answer it gave: \
         {answer}\n\nDesign the card. Output the JSON object:"
    );
    let body = serde_json::json!({
        "model": model,
        "max_tokens": 600,
        "temperature": 0.5,
        "response_format": { "type": "json_object" },
        "messages": [
            { "role": "system", "content": SCENE_SYSTEM },
            { "role": "user", "content": user },
        ],
    });
    let resp = client
        .post("https://api.groq.com/openai/v1/chat/completions")
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let parsed: ChatResponse = resp.json().await.ok()?;
    let text = parsed.choices.first()?.message.content.trim().to_string();
    let json = extract_json(&text)?;

    let kind = SceneKind::from_tag(&str_field(&json, "kind"));
    let title = str_field(&json, "title");
    let subtitle = str_field(&json, "subtitle");
    let points: Vec<String> = json
        .get("points")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let accent = str_field(&json, "accent");
    let image_query = str_field(&json, "image_query");

    if title.is_empty() && points.is_empty() {
        return None;
    }
    Some(SceneSpec {
        kind,
        title,
        subtitle,
        points,
        accent,
        image_query,
    })
}

const WHITEBOARD_SYSTEM: &str = "You design a simple whiteboard diagram \
to help explain a question's answer in a live voice call. Output ONLY \
a JSON object.\n\n\
When does a diagram HELP? \"How does X work?\", \"what is X made of?\", \
\"walk me through Y\", \"explain Z\", \"compare A and B\", \"what's the \
flow/pipeline/process\" — output steps. Single-fact answers (\"capital \
of France?\"), opinions, chitchat, image requests — output empty.\n\n\
Output format:\n\
{\"steps\": [...]}   when a diagram helps (3-8 steps total)\n\
{\"steps\": []}      when it doesn't (most questions)\n\n\
Step types (canvas is 640×360; safe content area x=60-580, y=80-300):\n\
- {\"type\":\"text\",\"x\":N,\"y\":N,\"content\":\"…\",\"size\":\"large|med|small\"} — \
standalone text. Use \"large\" for the title at top.\n\
- {\"type\":\"box\",\"x\":N,\"y\":N,\"w\":N,\"h\":N,\"label\":\"short\"} — \
labeled rectangle. Typical 110-160 wide, 44-60 tall.\n\
- {\"type\":\"arrow\",\"x1\":N,\"y1\":N,\"x2\":N,\"y2\":N,\"label\":\"opt\"} — \
arrow with optional midpoint label.\n\n\
Rules:\n\
- Order steps in REVEAL order; each draws ~900 ms after the previous.\n\
- ALWAYS start with a \"large\" text TITLE at top (y around 50-60).\n\
- KEEP IT CLEAN: lots of whitespace, no crowding, short labels (≤3 words).\n\
- Layout flows LEFT-TO-RIGHT. Layout concepts with a center node + spokes.\n\
- Arrows should land near box edges (not centers).\n\
- Return STRICTLY the JSON object, no prose, no markdown fences.";

#[derive(Deserialize)]
struct WhiteboardPlan {
    #[serde(default)]
    steps: Vec<Step>,
}

/// Ask the model whether the question's answer would be clarified by a
/// diagram, and if so what to draw. Returns `Some(steps)` when a
/// diagram is worthwhile (3+ steps), `None` otherwise — most questions
/// fall into None. Runs against the chat model (fast) in JSON mode,
/// independent of the (slower, agentic) answer model — so it can race
/// in parallel with [`answer_streaming`] and the diagram can start
/// drawing *while* she's speaking.
pub async fn whiteboard(
    client: &reqwest::Client,
    api_key: &str,
    model: &str,
    question: &str,
) -> Option<Vec<Step>> {
    let user = format!(
        "Question addressed to Eliza: {question}\n\nDesign the diagram. Output the JSON object."
    );
    let body = serde_json::json!({
        "model": model,
        "max_tokens": 900,
        "temperature": 0.4,
        "response_format": { "type": "json_object" },
        "messages": [
            { "role": "system", "content": WHITEBOARD_SYSTEM },
            { "role": "user", "content": user },
        ],
    });
    let resp = client
        .post("https://api.groq.com/openai/v1/chat/completions")
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let parsed: ChatResponse = resp.json().await.ok()?;
    let text = parsed.choices.first()?.message.content.trim().to_string();
    let plan: WhiteboardPlan = match serde_json::from_str::<WhiteboardPlan>(&text) {
        Ok(p) => p,
        Err(_) => {
            // Tolerate a stray JSON wrapper / fenced block — extract the
            // outermost {…} and re-parse.
            let v = extract_json(&text)?;
            serde_json::from_value::<WhiteboardPlan>(v).ok()?
        }
    };
    // Require enough steps to be worth the takeover.
    if plan.steps.len() < 3 {
        return None;
    }
    Some(plan.steps)
}

/// Pull a JSON object out of a model reply — it may be fenced in
/// markdown or wrapped in stray prose. Takes the outermost `{ … }`.
pub(crate) fn extract_json(text: &str) -> Option<serde_json::Value> {
    let start = text.find('{')?;
    let end = text.rfind('}')?.checked_add(1)?;
    if end <= start {
        return None;
    }
    serde_json::from_str(&text[start..end]).ok()
}

// ── Streaming answer ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct StreamChunk {
    #[serde(default)]
    choices: Vec<StreamChoice>,
}

#[derive(Deserialize)]
struct StreamChoice {
    #[serde(default)]
    delta: StreamDelta,
    /// Some providers attach tool info to a `message` even mid-stream.
    #[serde(default)]
    message: StreamDelta,
    /// `"length"` means the answer was cut by `max_tokens` — for
    /// compound (server-side tool) models the budget also covers the
    /// internal search/reasoning tokens, so a too-small cap truncates
    /// the spoken answer mid-sentence.
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize, Default)]
struct StreamDelta {
    #[serde(default)]
    content: String,
    #[serde(default)]
    executed_tools: Vec<ExecutedTool>,
}

/// Streaming variant of [`answer`]: calls `on_delta` with each text
/// fragment as the model produces it, so the caller can begin speaking
/// before the answer is complete. Still accumulates the full text and
/// returns the same [`Answer`] (with the web source, when one was used).
pub async fn answer_streaming(
    client: &reqwest::Client,
    api_key: &str,
    model: &str,
    transcript: &str,
    question: &str,
    // Optional per-character system prompt override. `None` uses the
    // default Eliza personality. Pass a profile's `system_prompt`
    // when running as Oblivion / Narrator / Utopia.
    system_override: Option<&str>,
    mut on_delta: impl FnMut(&str),
) -> Result<Answer> {
    let system = system_override.unwrap_or(SYSTEM);
    // 1024, not ~320: the prompt already caps answers at a few spoken
    // sentences, but compound models spend this same budget on their
    // server-side tool calls (web search) and reasoning first — a tight
    // cap truncated live-data answers mid-sentence ("…warm and sunny:").
    let body = serde_json::json!({
        "model": model,
        "max_tokens": 1024,
        "temperature": 0.3,
        "stream": true,
        "messages": [
            { "role": "system", "content": system },
            { "role": "user", "content": user_prompt(transcript, question) },
        ],
    });

    let mut resp = client
        .post("https://api.groq.com/openai/v1/chat/completions")
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .context("groq streaming chat request failed")?;

    let status = resp.status();
    if !status.is_success() {
        let err = resp.text().await.unwrap_or_default();
        anyhow::bail!("groq chat {status}: {err}");
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut text = String::new();
    let mut source: Option<Source> = None;
    let mut finish_reason: Option<String> = None;

    while let Some(network_chunk) = resp.chunk().await.context("reading groq chat stream")? {
        buf.extend_from_slice(&network_chunk);
        // Server-Sent Events: process complete `\n`-terminated lines; a
        // partial trailing line waits for the next network chunk.
        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=nl).collect();
            let line = String::from_utf8_lossy(&line);
            let Some(data) = line.trim().strip_prefix("data:") else {
                continue;
            };
            let data = data.trim();
            if data.is_empty() || data == "[DONE]" {
                continue;
            }
            let Ok(sc) = serde_json::from_str::<StreamChunk>(data) else {
                continue;
            };
            for choice in sc.choices {
                if !choice.delta.content.is_empty() {
                    text.push_str(&choice.delta.content);
                    on_delta(&choice.delta.content);
                }
                if source.is_none() {
                    source = extract_source(&choice.delta.executed_tools)
                        .or_else(|| extract_source(&choice.message.executed_tools));
                }
                if let Some(f) = choice.finish_reason {
                    finish_reason = Some(f);
                }
            }
        }
    }

    if finish_reason.as_deref() == Some("length") {
        tracing::warn!(%model, "answer truncated by max_tokens (finish_reason=length)");
    }
    let text = text.trim().to_string();
    if text.is_empty() {
        anyhow::bail!("groq streaming chat returned no content");
    }
    Ok(Answer { text, source })
}

// ── Anthropic streaming answer ───────────────────────────────────────

/// SSE event payload for the `content_block_delta` event in the
/// Anthropic Messages API stream. Only field we need is the text
/// chunk inside `delta.text`.
#[derive(Deserialize)]
struct AnthropicDeltaEvent {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    delta: AnthropicTextDelta,
}

#[derive(Deserialize, Default)]
struct AnthropicTextDelta {
    #[serde(default, rename = "type")]
    delta_type: String,
    #[serde(default)]
    text: String,
    /// Present on `message_delta` events; `"max_tokens"` means the
    /// answer was truncated by the cap.
    #[serde(default)]
    stop_reason: Option<String>,
}

/// Streaming variant of [`answer_streaming`] that hits Anthropic's
/// Messages API instead of Groq's OpenAI-compatible chat completions.
/// Use this when `model` starts with `claude-` (e.g. `claude-opus-4-7`).
///
/// Web search is enabled via Anthropic's server-side `web_search` tool, so she
/// can answer with current facts while keeping claude's reasoning. The streaming
/// parser reads only the answer text (tool blocks are ignored), so the
/// returned [`Answer`] still has no `source` set — the citations land inline.
pub async fn anthropic_answer_streaming(
    client: &reqwest::Client,
    api_key: &str,
    model: &str,
    transcript: &str,
    question: &str,
    system_override: Option<&str>,
    mut on_delta: impl FnMut(&str),
) -> Result<Answer> {
    let system = system_override.unwrap_or(SYSTEM);
    // Note: no `temperature` field — `claude-opus-4-7` deprecated it
    // (the model picks its own sampling). Setting it returns 400.
    // 2048, not ~512: with server-side web search enabled the budget
    // also covers tool-call blocks, so a tight cap truncated searched
    // answers right after the lead-in sentence.
    let body = serde_json::json!({
        "model": model,
        "max_tokens": 2048,
        "stream": true,
        "system": system,
        // Server-side web search — keeps claude's reasoning AND lets her look up
        // current facts (the system prompt already tells her when to). Capped
        // uses bound latency/cost; the streaming parser ignores the tool blocks
        // and just reads the answer text, so she only gets smarter, never breaks.
        "tools": [ { "type": "web_search_20250305", "name": "web_search", "max_uses": 2 } ],
        "messages": [
            { "role": "user", "content": user_prompt(transcript, question) },
        ],
    });

    let mut resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .context("anthropic streaming chat request failed")?;

    let status = resp.status();
    if !status.is_success() {
        let err = resp.text().await.unwrap_or_default();
        anyhow::bail!("anthropic chat {status}: {err}");
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut text = String::new();

    while let Some(network_chunk) = resp
        .chunk()
        .await
        .context("reading anthropic chat stream")?
    {
        buf.extend_from_slice(&network_chunk);
        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=nl).collect();
            let line = String::from_utf8_lossy(&line);
            // Anthropic SSE: each event has an `event: <name>` line
            // (which we ignore) and a `data: <json>` line. Only data
            // lines matter for content extraction.
            let Some(data) = line.trim().strip_prefix("data:") else {
                continue;
            };
            let data = data.trim();
            if data.is_empty() {
                continue;
            }
            let Ok(evt) = serde_json::from_str::<AnthropicDeltaEvent>(data) else {
                continue;
            };
            if evt.event_type == "content_block_delta"
                && evt.delta.delta_type == "text_delta"
                && !evt.delta.text.is_empty()
            {
                text.push_str(&evt.delta.text);
                on_delta(&evt.delta.text);
            }
            if evt.event_type == "message_delta"
                && evt.delta.stop_reason.as_deref() == Some("max_tokens")
            {
                tracing::warn!(%model, "answer truncated by max_tokens (stop_reason)");
            }
        }
    }

    let text = text.trim().to_string();
    if text.is_empty() {
        anyhow::bail!("anthropic streaming chat returned no content");
    }
    Ok(Answer { text, source: None })
}

/// Whether `model` should be routed to the Anthropic Messages API.
/// Anything starting with `claude` (case-insensitive) goes to
/// Anthropic; everything else to Groq.
pub fn is_anthropic_model(model: &str) -> bool {
    model.to_ascii_lowercase().starts_with("claude")
}

// ── Sentence chunking ────────────────────────────────────────────────

/// Accumulates streamed text and emits complete sentences, so an answer
/// can be synthesized to speech sentence-by-sentence as it streams in.
#[derive(Default)]
pub struct SentenceChunker {
    buf: String,
}

impl SentenceChunker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a streamed text fragment; return any sentences it completed.
    pub fn push(&mut self, delta: &str) -> Vec<String> {
        self.buf.push_str(delta);
        let mut out = Vec::new();
        while let Some(end) = self.next_sentence_end() {
            let sentence = self.buf[..end].trim().to_string();
            self.buf.drain(..end);
            if sentence.chars().any(char::is_alphanumeric) {
                out.push(sentence);
            }
        }
        out
    }

    /// The trailing text once the stream ends — the final sentence
    /// usually has no whitespace after it to trigger a flush.
    pub fn flush(&mut self) -> Option<String> {
        let rest = self.buf.trim().to_string();
        self.buf.clear();
        rest.chars().any(char::is_alphanumeric).then_some(rest)
    }

    /// Byte index in `buf` just past the first complete sentence (the
    /// start of the whitespace after a sentence-ending `.`/`!`/`?`).
    /// `None` until enough text has arrived to be certain.
    fn next_sentence_end(&self) -> Option<usize> {
        let chars: Vec<(usize, char)> = self.buf.char_indices().collect();
        let mut i = 0;
        while i < chars.len() {
            if !matches!(chars[i].1, '.' | '!' | '?') {
                i += 1;
                continue;
            }
            let term_at = chars[i].0;
            // Consume a run of terminators ("?!", "...").
            while i < chars.len() && matches!(chars[i].1, '.' | '!' | '?') {
                i += 1;
            }
            // Consume any closing quote/bracket.
            while i < chars.len() && matches!(chars[i].1, '"' | '\'' | ')' | ']' | '”' | '’') {
                i += 1;
            }
            // A following char is needed to know the sentence ended.
            let &(next_at, next_c) = chars.get(i)?;
            if next_c.is_whitespace() && !ends_with_abbrev(&self.buf[..term_at]) {
                return Some(next_at);
            }
        }
        None
    }
}

/// Whether `prefix` ends in an abbreviation or initial — so the `.`
/// after it does not end a sentence ("Mr.", "U.S.", "e.g.", "A.").
fn ends_with_abbrev(prefix: &str) -> bool {
    let word = prefix
        .rsplit(char::is_whitespace)
        .next()
        .unwrap_or("")
        .trim_matches(|c: char| !c.is_alphanumeric() && c != '.')
        .to_lowercase();
    if word.is_empty() {
        return false;
    }
    // A single letter is an initial ("A." in "A. Lincoln").
    let letters: String = word.chars().filter(|c| c.is_alphanumeric()).collect();
    if letters.chars().count() == 1 {
        return true;
    }
    const ABBREVS: &[&str] = &[
        "mr", "mrs", "ms", "dr", "prof", "sr", "jr", "st", "vs", "etc", "no", "fig", "approx",
        "e.g", "i.e", "u.s", "a.m", "p.m", "ph.d",
    ];
    ABBREVS.contains(&word.as_str()) || ABBREVS.contains(&letters.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_json_pulls_object_out_of_messy_replies() {
        // Bare object.
        let v = extract_json(r#"{"title":"T","steps":["a"]}"#).unwrap();
        assert_eq!(v["title"], "T");
        // Markdown-fenced with surrounding prose.
        let v = extract_json("Sure:\n```json\n{\"title\":\"T\"}\n```\nok").unwrap();
        assert_eq!(v["title"], "T");
        // No object, or invalid JSON → None, never a panic.
        assert!(extract_json("no json here").is_none());
        assert!(extract_json("{not valid").is_none());
    }

    // ---------- SentenceChunker ----------

    #[test]
    fn chunker_emits_completed_sentences_and_holds_the_last() {
        let mut c = SentenceChunker::new();
        // The last sentence has no trailing whitespace → it waits.
        let got = c.push("One thing. Two things! Three?");
        assert_eq!(got, vec!["One thing.", "Two things!"]);
        assert_eq!(c.flush().as_deref(), Some("Three?"));
    }

    #[test]
    fn chunker_reassembles_across_streamed_fragments() {
        let mut c = SentenceChunker::new();
        let mut out = Vec::new();
        // The same text arrives split at awkward points.
        for frag in ["On", "e. Tw", "o. ", "Done"] {
            out.extend(c.push(frag));
        }
        assert_eq!(out, vec!["One.", "Two."]);
        assert_eq!(c.flush().as_deref(), Some("Done"));
    }

    #[test]
    fn chunker_does_not_break_on_abbreviations() {
        let mut c = SentenceChunker::new();
        let got = c.push("Visit the U.S. and see Mr. Smith today. Thanks.");
        // "U.S." and "Mr." must not split the first sentence.
        assert_eq!(got, vec!["Visit the U.S. and see Mr. Smith today."]);
        assert_eq!(c.flush().as_deref(), Some("Thanks."));
    }

    #[test]
    fn chunker_handles_decimals_and_terminator_runs() {
        let mut c = SentenceChunker::new();
        // "3.5" — the dot is between digits, no whitespace, no break.
        let got = c.push("It grew 3.5 times. Really?! Yes.");
        assert_eq!(got, vec!["It grew 3.5 times.", "Really?!"]);
        assert_eq!(c.flush().as_deref(), Some("Yes."));
    }

    #[test]
    fn chunker_drops_punctuation_only_fragments() {
        let mut c = SentenceChunker::new();
        // "..." with nothing alphanumeric is not a real sentence.
        assert!(c.push("... ").is_empty());
        assert_eq!(c.flush(), None);
    }
}
