//! Machine-readable discovery surfaces for agents and crawlers.
//!
//! `openapi.rs` publishes the *contract*; this module publishes everything an
//! agent needs before it knows the contract exists — `robots.txt`, a sitemap,
//! the `/.well-known` documents crawlers probe by convention, and the markdown
//! mirrors of the human pages.
//!
//! Two rules shaped this module:
//!
//! * **A wrong answer is worse than no answer.** Until this existed, the SPA
//!   fallback answered `200 text/html` for every unknown path, so an auditor
//!   probing `/.well-known/ard.json` recorded "exists but is not valid JSON"
//!   rather than "absent", and an agent probing for a resource concluded that
//!   every path it could imagine was real. [`spa_fallback`] is the fix, and it
//!   matters more than any document below.
//! * **Never advertise what does not exist.** `@freeq/mcp` is not on npm, so
//!   [`mcp_server_card`] says `published: false` and tells the caller to build
//!   from source. freeq has no OAuth authorization server, so
//!   [`oauth_protected_resource`] ships an empty `authorization_servers` and
//!   points at `auth.md` instead of inventing endpoints.
//!
//! The prose documents (`agents.md`, `auth.md`) are the repo-root files, the
//! same bytes freeq.at serves, compiled in with `include_str!`. One source of
//! truth, two hosts.

use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

/// Canonical public origin of this server.
///
/// Hardcoded rather than derived from the request `Host`: these documents are
/// crawled, cached and quoted elsewhere, and a document that describes itself
/// differently depending on which name you reached it by is worse than one
/// that is occasionally wrong in development.
pub const ORIGIN: &str = "https://irc.freeq.at";

/// The docs site. Long-form documentation lives there, not here.
pub const SITE: &str = "https://freeq.at";

pub const REPO: &str = "https://github.com/freeq-irc/freeq";

/// One-sentence description, identical to the one in `llms.txt` and the one
/// freeq.at serves. Agents dedupe on this text; drift makes one service look
/// like two.
pub const DESCRIPTION: &str = "An IRC server where identity is an AT Protocol DID instead of a nickname. \
     Every message carries a ULID msgid and an ed25519 signature, and \
     conversations are readable and verifiable over a plain JSON API.";

/// Agent-facing instructions. NOT the repo's own `AGENTS.md`, which is a
/// contributor document naming production hosts — `/AGENTS.md` deliberately
/// serves this file, and a test asserts the distinction.
const AGENTS_MD: &str = include_str!("../../agent-docs/agents.md");

/// Credential walkthrough, WorkOS auth.md format.
const AUTH_MD: &str = include_str!("../../agent-docs/auth.md");

/// Self-service enrollment, welcome-mat layout.
const WELCOME_MD: &str = include_str!("../../agent-docs/welcome.md");

/// The terms, served verbatim so they can be hashed and signed. Bytes matter
/// here in a way they do not for the other documents: an agent that signs a
/// reformatted copy has signed a different document.
const TOS_TXT: &str = include_str!("../../agent-docs/tos.txt");

/// Crawlers named explicitly in `robots.txt`.
///
/// A blanket `User-agent: *` already allows them; the named stanzas exist
/// because operators (and auditors) grep for their own bot's name and treat
/// its absence as an unanswered question.
const AI_CRAWLERS: &[&str] = &[
    "GPTBot",
    "ChatGPT-User",
    "OAI-SearchBot",
    "ClaudeBot",
    "Claude-User",
    "anthropic-ai",
    "PerplexityBot",
    "Google-Extended",
    "Applebot-Extended",
    "CCBot",
    "cohere-ai",
    "DeepSeekBot",
    "ora-agent",
];

/// Agent-relevant paths on this host, for the sitemap.
const SITEMAP_PATHS: &[(&str, &str)] = &[
    ("/", "daily"),
    ("/llms.txt", "weekly"),
    ("/index.md", "weekly"),
    ("/agents.md", "monthly"),
    ("/auth.md", "monthly"),
    ("/.well-known/welcome.md", "monthly"),
    ("/tos", "yearly"),
    ("/api/v1/openapi.json", "weekly"),
    ("/.well-known/agent.json", "monthly"),
    ("/.well-known/ard.json", "monthly"),
];

/// Build date, for `<lastmod>`. Compile time is the honest answer: these
/// documents change when the binary does.
fn build_date() -> String {
    // No build script, so fall back to the newest thing we know: the process
    // start. Stable within a deployment, which is what `lastmod` is for.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    // Civil-from-days (Howard Hinnant's algorithm), so we can format a date
    // without pulling in a date crate for one string.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn markdown(body: &'static str) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/markdown; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

fn markdown_owned(body: String) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/markdown; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

fn json(value: serde_json::Value) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string()),
    )
        .into_response()
}

// ── Text surfaces ────────────────────────────────────────────────────────

/// `GET /robots.txt`
pub async fn robots_txt() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        robots_body(),
    )
        .into_response()
}

pub fn robots_body() -> String {
    let mut out = String::from(
        "# freeq — an IRC server with AT Protocol identity.\n\
         # Agents: start at /llms.txt, /agents.md or /api/v1/openapi.json.\n\
         \n\
         User-agent: *\n\
         Allow: /\n",
    );
    for ua in AI_CRAWLERS {
        out.push_str(&format!("\nUser-agent: {ua}\nAllow: /\n"));
    }
    out.push_str(&format!("\nSitemap: {ORIGIN}/sitemap.xml\n"));
    out
}

/// `GET /sitemap.xml`
pub async fn sitemap_xml() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml; charset=utf-8"),
        )],
        sitemap_body(),
    )
        .into_response()
}

pub fn sitemap_body() -> String {
    let lastmod = build_date();
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n",
    );
    for (path, freq) in SITEMAP_PATHS {
        out.push_str(&format!(
            "  <url>\n    <loc>{ORIGIN}{path}</loc>\n    <lastmod>{lastmod}</lastmod>\n    <changefreq>{freq}</changefreq>\n  </url>\n"
        ));
    }
    out.push_str("</urlset>\n");
    out
}

/// `GET /agents.md` and `GET /AGENTS.md`
pub async fn agents_md() -> Response {
    markdown(AGENTS_MD)
}

/// `GET /auth.md`
pub async fn auth_md() -> Response {
    markdown(AUTH_MD)
}

/// `GET /.well-known/welcome.md` — how an agent enrolls itself, in the layout
/// described at <https://welcome-mat.info/spec>.
///
/// The document is welcome-mat *shaped*, not welcome-mat conformant: freeq
/// proves possession with a SASL challenge per connection rather than a DPoP
/// proof per request, and it says so in its own deviations section. Publishing
/// a conformant-looking file that 404s on `POST /api/signup` would be worse
/// than publishing nothing.
pub async fn welcome_md() -> Response {
    markdown(WELCOME_MD)
}

/// `GET /tos` — the exact bytes an agent would sign.
pub async fn tos_txt() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        TOS_TXT,
    )
        .into_response()
}

/// `GET /index.md` — the homepage for a reader that wants text, not a bundle.
pub async fn index_md() -> Response {
    markdown_owned(index_markdown())
}

pub fn index_markdown() -> String {
    format!(
        "# freeq\n\n\
         > {DESCRIPTION}\n\n\
         This host runs a freeq server. The web client at `{ORIGIN}/` needs\n\
         JavaScript; everything below does not.\n\n\
         ## Machine-readable surfaces\n\n\
         - [OpenAPI 3.1 contract]({ORIGIN}/api/v1/openapi.json) — every HTTP endpoint ([YAML]({ORIGIN}/api/v1/openapi.yaml))\n\
         - [llms.txt]({ORIGIN}/llms.txt) — what this server offers, in order\n\
         - [agents.md]({ORIGIN}/agents.md) — when to use freeq, and the rules for agents\n\
         - [auth.md]({ORIGIN}/auth.md) — how an agent gets its own credentials\n\
         - [welcome.md]({ORIGIN}/.well-known/welcome.md) — self-service enrollment, no human in the loop\n\
         - [agent.json]({ORIGIN}/.well-known/agent.json) — diagnostic tools that return conclusions\n\
         - [health]({ORIGIN}/api/v1/health) — build features; `av` says whether calls work here\n\n\
         ## Reading conversations without an account\n\n\
         - [channels]({ORIGIN}/api/v1/channels)\n\
         - history: `/api/v1/channels/{{name}}/history?limit=100`\n\
         - search: `/api/v1/search?channel=%23general&q=deploy`\n\
         - verify a message: `/api/v1/verify/{{msgid}}`\n\n\
         Invite-only (`+i`) and key-protected (`+k`) channels answer 403 here by design.\n\n\
         ## Joining\n\n\
         IRC over WebSocket at `wss://irc.freeq.at/irc`, or TLS IRC on 6697.\n\
         Authentication is SASL `ATPROTO-CHALLENGE` — see [auth.md]({ORIGIN}/auth.md).\n\n\
         ## Elsewhere\n\n\
         - Documentation: {SITE}/docs/\n\
         - Source: {REPO}\n"
    )
}

// ── /.well-known documents ───────────────────────────────────────────────

fn discovery_entries() -> serde_json::Value {
    serde_json::json!([
        {
            "name": "OpenAPI contract",
            "type": "openapi",
            "mediaType": "application/json",
            "url": format!("{ORIGIN}/api/v1/openapi.json"),
            "description": "Every HTTP endpoint this server exposes, OpenAPI 3.1."
        },
        {
            "name": "llms.txt",
            "type": "llms-txt",
            "mediaType": "text/markdown",
            "url": format!("{ORIGIN}/llms.txt"),
            "description": "Curated index of this server's surfaces."
        },
        {
            "name": "Agent instructions",
            "type": "documentation",
            "mediaType": "text/markdown",
            "url": format!("{ORIGIN}/agents.md"),
            "description": "When to use freeq, when not to, and the rules for agents."
        },
        {
            "name": "Credential walkthrough",
            "type": "authentication",
            "mediaType": "text/markdown",
            "url": format!("{ORIGIN}/auth.md"),
            "description": "How an agent mints a did:key identity and obtains a bearer token."
        },
        {
            "name": "Self-service enrollment",
            "type": "onboarding",
            "mediaType": "text/markdown",
            "url": format!("{ORIGIN}/.well-known/welcome.md"),
            "description": "How an agent mints an identity and enrolls with no human in the loop."
        },
        {
            "name": "Terms of service",
            "type": "terms",
            "mediaType": "text/plain",
            "url": format!("{ORIGIN}/tos"),
            "description": "Served verbatim so the exact bytes can be hashed and signed."
        },
        {
            "name": "Agent Assistance Interface",
            "type": "diagnostics",
            "mediaType": "application/json",
            "url": format!("{ORIGIN}/.well-known/agent.json"),
            "description": "Diagnostic tools that return conclusions plus evidence, never raw state."
        },
        {
            "name": "IRC over WebSocket",
            "type": "transport",
            "mediaType": "application/irc",
            "url": "wss://irc.freeq.at/irc",
            "description": "The IRC line protocol, including SASL ATPROTO-CHALLENGE and IRCv3 caps."
        },
        {
            "name": "Source",
            "type": "repository",
            "mediaType": "text/html",
            "url": REPO,
            "description": "Server, clients, SDKs and the MCP server."
        }
    ])
}

fn ard_body() -> serde_json::Value {
    serde_json::json!({
        "name": "freeq",
        "description": DESCRIPTION,
        "url": ORIGIN,
        "documentation": format!("{SITE}/docs/"),
        "contact": format!("{REPO}/issues"),
        "updated": build_date(),
        "entries": discovery_entries(),
        "trustManifest": {
            "policy_url": format!("{SITE}/privacy/"),
            "contact": format!("{REPO}/issues"),
            "data_use": "Public channel content is served over a public API. \
                         Invite-only and key-protected channels are not exposed.",
            "attribution": "Messages are signed; attribute to the DID that signed, not to the server.",
            "verification": format!("{ORIGIN}/api/v1/verify/{{msgid}}")
        }
    })
}

/// `GET /.well-known/ard.json`
pub async fn ard_json() -> Response {
    json(ard_body())
}

/// `GET /.well-known/ai-catalog.json` — the legacy path for the same document.
pub async fn ai_catalog_json() -> Response {
    json(ard_body())
}

/// `GET /.well-known/agent-card.json` — A2A agent card.
pub async fn agent_card_json() -> Response {
    json(serde_json::json!({
        "name": "freeq",
        "description": DESCRIPTION,
        "url": ORIGIN,
        "version": env!("CARGO_PKG_VERSION"),
        "provider": { "organization": "freeq", "url": SITE },
        "capabilities": { "streaming": true, "pushNotifications": false },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "documentationUrl": format!("{ORIGIN}/agents.md"),
        "securitySchemes": {
            "bearer": {
                "type": "http",
                "scheme": "bearer",
                "description": format!("Bearer token minted by SASL ATPROTO-CHALLENGE. See {ORIGIN}/auth.md")
            }
        },
        "skills": [
            {
                "id": "read_channels",
                "name": "Read channels",
                "description": "List public channels and read their history without authenticating.",
                "tags": ["read", "chat", "history"]
            },
            {
                "id": "search_messages",
                "name": "Search messages",
                "description": "Full-text search within a public channel.",
                "tags": ["read", "search"]
            },
            {
                "id": "verify_message",
                "name": "Verify a message",
                "description": "Check whether a message was signed by its author's key or only relayed by the server.",
                "tags": ["verify", "provenance", "signatures"]
            },
            {
                "id": "join_and_speak",
                "name": "Join and speak",
                "description": "Authenticate with a did:key identity, join a channel, and send signed messages.",
                "tags": ["write", "chat", "identity"]
            }
        ]
    }))
}

/// `GET /.well-known/api-catalog` — RFC 9727 linkset.
pub async fn api_catalog() -> Response {
    json(serde_json::json!({
        "linkset": [{
            "anchor": ORIGIN,
            "service-desc": [{
                "href": format!("{ORIGIN}/api/v1/openapi.json"),
                "type": "application/json"
            }],
            "service-doc": [{
                "href": format!("{SITE}/docs/"),
                "type": "text/html"
            }],
            "status": [{
                "href": format!("{ORIGIN}/api/v1/health"),
                "type": "application/json"
            }]
        }]
    }))
}

/// `GET /.well-known/mcp/server-card.json`
///
/// `@freeq/mcp` is not published to npm. Saying so is the whole point: an
/// agent that is told to run `npx -y @freeq/mcp` will fail, and will blame
/// freeq rather than the missing package.
pub async fn mcp_server_card() -> Response {
    json(serde_json::json!({
        "name": "freeq",
        "description": "MCP server wrapping freeq's IRC verbs and REST reads: channels, history, search, verify, pins, and connect/join/say.",
        "version": "0.1.0",
        "source": format!("{REPO}/tree/main/freeq-mcp"),
        "transport": "stdio",
        "published": false,
        "install": "Clone the repository, then `cd freeq-mcp && npm install && npm run build` and run `node dist/index.js` over stdio.",
        "documentation": format!("{ORIGIN}/agents.md")
    }))
}

/// `GET /.well-known/oauth-protected-resource` — RFC 9728.
///
/// freeq mints bearer tokens through SASL, not through an OAuth authorization
/// server, so `authorization_servers` is empty and `resource_documentation`
/// carries the real instructions. An invented AS endpoint would score better
/// and serve agents worse.
pub async fn oauth_protected_resource() -> Response {
    json(serde_json::json!({
        "resource": ORIGIN,
        "resource_name": "freeq",
        "authorization_servers": [],
        "bearer_methods_supported": ["header"],
        "resource_documentation": format!("{ORIGIN}/auth.md"),
        "resource_policy_uri": format!("{SITE}/privacy/"),
        "scopes_supported": []
    }))
}

/// `GET /.well-known/http-message-signatures-directory` — Web Bot Auth.
///
/// Empty and honest: this server does not yet sign its outbound requests.
pub async fn web_bot_auth_directory() -> Response {
    json(serde_json::json!({
        "keys": [],
        "description": "This server does not currently sign outbound HTTP requests. \
                        Message-level signatures inside freeq are per-author ed25519 \
                        keys, verifiable at /api/v1/verify/{msgid}.",
        "documentation": format!("{ORIGIN}/agents.md")
    }))
}

// ── Not found ────────────────────────────────────────────────────────────

/// The body every unknown path gets: a real 404, and markdown telling the
/// caller where to look instead.
pub fn not_found_markdown() -> Response {
    let body = format!(
        "# 404 — not found\n\n\
         This path is not served by this freeq server.\n\n\
         - [/llms.txt]({ORIGIN}/llms.txt) — index of this server's surfaces\n\
         - [/sitemap.xml]({ORIGIN}/sitemap.xml) — every agent-relevant path\n\
         - [/api/v1/openapi.json]({ORIGIN}/api/v1/openapi.json) — the HTTP contract\n\
         - [/agents.md]({ORIGIN}/agents.md) — when to use freeq\n\
         - [docs]({SITE}/docs/) — long-form documentation\n"
    );
    (
        StatusCode::NOT_FOUND,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/markdown; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

/// The compiled web client's `index.html`, read once when the router is built.
static INDEX_HTML: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

/// Called by `web::router` when a static web directory is configured.
pub fn set_index_html(path: &std::path::Path) {
    let _ = INDEX_HTML.set(std::fs::read_to_string(path).ok());
}

/// Does this path ask for a *file* rather than a client-side route?
///
/// The distinction is the whole fix. `/settings` is a React route and must
/// return the shell; `/robots.txt`, `/nope.json` and anything under
/// `/.well-known/` or `/api/` are resources that either exist or do not.
pub fn is_file_request(path: &str) -> bool {
    if path.starts_with("/.well-known/") || path.starts_with("/api/") {
        return true;
    }
    path.rsplit('/').next().is_some_and(|seg| seg.contains('.'))
}

/// Fallback for everything the router and the static directory did not match.
pub async fn spa_fallback(uri: Uri) -> Response {
    if is_file_request(uri.path()) {
        return not_found_markdown();
    }
    match INDEX_HTML.get().and_then(|o| o.as_deref()) {
        Some(html) => axum::response::Html(html.to_string()).into_response(),
        // No web client on this host: a client-side route is just as absent as
        // a file, and 404 is the honest answer.
        None => not_found_markdown(),
    }
}

// ── Response headers ─────────────────────────────────────────────────────

/// RFC 8288 `Link` relations on every response, and RFC 9728's
/// `WWW-Authenticate` hint on every 401.
///
/// As a layer rather than per-handler: there are ~90 routes, and the one that
/// forgets is exactly the one an agent hits.
pub async fn discovery_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut resp = next.run(req).await;
    let unauthorized = resp.status() == StatusCode::UNAUTHORIZED;
    let headers = resp.headers_mut();

    if !headers.contains_key(header::LINK) {
        headers.insert(
            header::LINK,
            HeaderValue::from_static(
                "</api/v1/openapi.json>; rel=\"service-desc\"; type=\"application/json\", \
                 </llms.txt>; rel=\"describedby\"; type=\"text/markdown\", \
                 </agents.md>; rel=\"alternate\"; type=\"text/markdown\"",
            ),
        );
    }

    if unauthorized && !headers.contains_key(header::WWW_AUTHENTICATE) {
        headers.insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(
                "Bearer resource_metadata=\"https://irc.freeq.at/.well-known/oauth-protected-resource\"",
            ),
        );
    }

    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn robots_names_every_crawler_and_the_sitemap() {
        let body = robots_body();
        assert!(body.contains("Sitemap: https://irc.freeq.at/sitemap.xml"));
        for ua in AI_CRAWLERS {
            assert!(body.contains(ua), "robots.txt must name {ua}");
        }
        assert!(body.contains("User-agent: *"));
    }

    #[test]
    fn sitemap_urls_are_absolute() {
        let body = sitemap_body();
        assert!(body.starts_with("<?xml"));
        let locs: Vec<&str> = body
            .split("<loc>")
            .skip(1)
            .filter_map(|s| s.split("</loc>").next())
            .collect();
        assert_eq!(locs.len(), SITEMAP_PATHS.len());
        for loc in locs {
            assert!(loc.starts_with("https://"), "relative <loc>: {loc}");
        }
        assert!(body.contains("<lastmod>"));
    }

    #[test]
    fn build_date_is_iso_8601() {
        let d = build_date();
        assert_eq!(d.len(), 10, "{d}");
        assert_eq!(d.matches('-').count(), 2, "{d}");
        assert!(d.starts_with("20"), "{d}");
    }

    /// `/AGENTS.md` serves the agent-facing document, never the repository's
    /// own contributor file — that one names production hosts.
    #[test]
    fn agents_md_is_not_the_contributor_file() {
        assert!(AGENTS_MD.contains("When to use freeq"));
        assert!(!AGENTS_MD.contains("deploy.sh"));
        assert!(!AGENTS_MD.contains("ssh chad@"));
    }

    /// The welcome mat's value is that it is honest about what it is not.
    #[test]
    fn welcome_md_declares_its_deviations() {
        assert!(WELCOME_MD.starts_with("# freeq"));
        for needed in [
            "## requirements",
            "## endpoints",
            "## enrollment flow",
            "## deviations",
        ] {
            assert!(WELCOME_MD.contains(needed), "welcome.md needs {needed}");
        }
        // The three claims that must never drift into dishonesty.
        assert!(WELCOME_MD.contains("no `POST /api/signup`"));
        assert!(WELCOME_MD.contains("no DPoP"));
        assert!(WELCOME_MD.contains("never sent to this server"));
        // RSA is not a thing here; declaring RS256 like the reference
        // playground does would promise a signature we cannot verify.
        assert!(WELCOME_MD.contains("EdDSA"));
        assert!(WELCOME_MD.contains("RSA is not accepted"));
    }

    /// The terms are the one document whose *bytes* are the contract.
    #[test]
    fn tos_is_plain_stable_text() {
        assert!(TOS_TXT.starts_with("freeq \u{2014} terms of service"));
        assert!(TOS_TXT.contains("version 1"));
        assert!(!TOS_TXT.contains('\r'), "CRLF would change the hash");
        assert!(!TOS_TXT.contains("<"), "the terms are text, not markup");
        assert!(TOS_TXT.len() > 500);
    }

    #[test]
    fn auth_md_documents_the_real_mechanism() {
        assert!(AUTH_MD.contains("ATPROTO-CHALLENGE"));
        assert!(AUTH_MD.contains("API-BEARER"));
        // The private key never leaves the client; if that line ever goes, the
        // document is no longer describing freeq.
        assert!(AUTH_MD.contains("never sent to the server"));
    }

    #[test]
    fn well_known_documents_are_valid_json() {
        for body in [
            ard_body(),
            serde_json::json!({ "probe": "sanity" }),
        ] {
            let s = serde_json::to_string(&body).unwrap();
            serde_json::from_str::<serde_json::Value>(&s).unwrap();
        }
        let ard = ard_body();
        assert_eq!(ard["name"], "freeq");
        assert!(ard["entries"].as_array().unwrap().len() >= 5);
        assert!(ard["trustManifest"]["verification"].is_string());
    }

    #[test]
    fn mcp_card_does_not_advertise_an_unpublished_package() {
        let card = futures_lite_block(mcp_server_card());
        assert!(card.contains("\"published\": false"));
        assert!(
            !card.contains("npx"),
            "the npm package does not exist; telling an agent to npx it is a trap"
        );
        assert!(card.contains("freeq-mcp"));
    }

    #[test]
    fn protected_resource_metadata_is_honest() {
        let doc = futures_lite_block(oauth_protected_resource());
        let v: serde_json::Value = serde_json::from_str(&doc).unwrap();
        assert_eq!(v["resource"], ORIGIN);
        assert_eq!(v["authorization_servers"].as_array().unwrap().len(), 0);
        assert!(
            v["resource_documentation"]
                .as_str()
                .unwrap()
                .ends_with("/auth.md")
        );
    }

    #[test]
    fn api_catalog_points_at_the_spec() {
        let doc = futures_lite_block(api_catalog());
        assert!(doc.contains("/api/v1/openapi.json"));
        assert!(doc.contains("linkset"));
    }

    #[test]
    fn file_requests_are_distinguished_from_client_routes() {
        // Files: must 404 when absent.
        for p in [
            "/robots.txt",
            "/nope.json",
            "/.well-known/anything",
            "/api/v1/nothing",
            "/assets/app.a1b2.js",
        ] {
            assert!(is_file_request(p), "{p} should be treated as a file");
        }
        // Client-side routes: must still get the shell.
        for p in ["/", "/settings", "/c/general", "/join/abc", "/av/room"] {
            assert!(!is_file_request(p), "{p} should be treated as an SPA route");
        }
    }

    #[test]
    fn index_markdown_links_the_machine_surfaces() {
        let md = index_markdown();
        assert!(md.starts_with("# freeq"));
        for needle in [
            "/api/v1/openapi.json",
            "/llms.txt",
            "/agents.md",
            "/auth.md",
        ] {
            assert!(md.contains(needle), "index.md must link {needle}");
        }
        assert!(md.len() > 400);
    }

    /// Minimal executor: these handlers are `async` only because axum wants
    /// them to be, and pulling tokio's test macro in for a pure function
    /// would be heavier than this.
    fn futures_lite_block(fut: impl std::future::Future<Output = Response>) -> String {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let resp = rt.block_on(fut);
        let body = rt
            .block_on(axum::body::to_bytes(resp.into_body(), 1_000_000))
            .unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }
}
