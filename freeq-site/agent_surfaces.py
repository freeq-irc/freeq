"""Machine-readable discovery surfaces for agents (robots, sitemap, .well-known)."""
from datetime import date
from pathlib import Path
from xml.sax.saxutils import escape

from flask import Response, abort, jsonify, request

REPO_ROOT = Path(__file__).parent.parent
SITE_ROOT = Path(__file__).parent

# Single source of truth. Every document below is rendered from this.
IDENTITY = {
    "name": "freeq",
    "url": "https://freeq.at",
    "api_host": "https://irc.freeq.at",
    "description": (
        "An IRC server where identity is an AT Protocol DID instead of a "
        "nickname. Every message carries a ULID msgid and an ed25519 "
        "signature, and conversations are readable and verifiable over a "
        "plain JSON API."
    ),
    "repo": "https://github.com/freeq-irc/freeq",
    "openapi": "https://irc.freeq.at/api/v1/openapi.json",
    "llms_txt": "https://freeq.at/llms.txt",
    "agents_md": "https://freeq.at/agents.md",
    "auth_md": "https://freeq.at/auth.md",
    "irc_ws": "wss://irc.freeq.at/irc",
    "license": "https://github.com/freeq-irc/freeq/blob/main/LICENSE",
}

# Paths that appear in sitemap.xml. Keep in sync with app.py's routes.
SITEMAP_PATHS = [
    "/", "/connect/", "/sdk/", "/agents/", "/protocol/", "/clients/",
    "/about/", "/docs/", "/blog/",
]

AI_CRAWLERS = [
    "GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot", "Claude-User",
    "anthropic-ai", "PerplexityBot", "Google-Extended", "Applebot-Extended",
    "CCBot", "cohere-ai", "DeepSeekBot", "ora-agent", "Bytespider",
]

_MARKDOWN_CT = "text/markdown; charset=utf-8"


def _markdown(text):
    """200 with content-type text/markdown; charset=utf-8."""
    return Response(text, status=200, content_type=_MARKDOWN_CT)


def _repo_markdown(name):
    """Serve REPO_ROOT/<name> as markdown, 404 if absent.

    SECURITY: `name` must be matched against a hardcoded allowlist inside the
    caller. Never join user input onto REPO_ROOT — the repo root contains
    AGENTS.md and CLAUDE.md with deploy hosts in them, and *.secret files.
    """
    target = (REPO_ROOT / name).resolve()
    # Belt and braces even though the caller passes a literal: the resolved
    # file must live directly inside the repo root, nowhere else. (This also
    # keeps a symlinked name from pointing outside the tree.)
    try:
        target.relative_to(REPO_ROOT.resolve())
    except ValueError:
        abort(404)
    if not target.is_file():
        abort(404)
    return _markdown(target.read_text())


def _agent_facing_markdown():
    """The public agents.md, served at /agents.md and /AGENTS.md.

    Deliberately NOT the repo-root AGENTS.md: in contributor checkouts that
    path is an internal developer file (it is a symlink to CLAUDE.md in this
    repo, with deploy hosts and task lists in it — the audit regression
    guard is the 'deploy.sh' string). The public copy therefore lives here
    next to this file, so the serving path can never resolve to internal
    content.
    """
    path = (SITE_ROOT / "agents.md").resolve()
    try:
        path.relative_to(SITE_ROOT.resolve())
    except ValueError:
        abort(404)
    if not path.is_file():
        abort(404)
    return _markdown(path.read_text())


def ard_document():
    """dict — Agent Readiness Document served at /.well-known/ard.json."""
    return {
        "name": IDENTITY["name"],
        "description": IDENTITY["description"],
        "url": IDENTITY["url"],
        "contact": "https://freeq.at/about/",
        "updated": date.today().isoformat(),
        "entries": [
            {
                "name": "REST API (OpenAPI 3.1)",
                "type": "openapi",
                "url": IDENTITY["openapi"],
                "description": "Every HTTP endpoint, its parameters and its responses.",
            },
            {
                "name": "llms.txt",
                "type": "llms-txt",
                "url": IDENTITY["llms_txt"],
                "description": "The curated index an agent reads first.",
            },
            {
                "name": "agents.md",
                "type": "markdown",
                "url": IDENTITY["agents_md"],
                "description": "Instructions for AI agents: when to use freeq, rules, surfaces.",
            },
            {
                "name": "auth.md",
                "type": "markdown",
                "url": IDENTITY["auth_md"],
                "description": "Credentials walkthrough: did:key self-registration and bearer tokens.",
            },
            {
                "name": "MCP server",
                "type": "mcp",
                "url": "https://github.com/freeq-irc/freeq/tree/main/freeq-mcp",
                "description": "This API and the IRC verbs as MCP tools. Build from the repo; not published to npm yet.",
            },
            {
                "name": "Source repository",
                "type": "repository",
                "url": IDENTITY["repo"],
                "description": "The implementation is the specification of last resort.",
            },
            {
                "name": "IRC over WebSocket",
                "type": "irc",
                "url": IDENTITY["irc_ws"],
                "description": "The IRC line protocol in real time, including SASL ATPROTO-CHALLENGE.",
            },
        ],
        "trust": {
            "policy_url": "https://freeq.at/docs/policy-system/",
            "contact": "https://freeq.at/about/",
            "data_use": (
                "The relay stores channel messages so they can be replayed and "
                "verified over the public API. No analytics use of your data."
            ),
            "attribution": (
                "Every message is ed25519-signed under the author's AT Protocol "
                "DID; readers verify without trusting the relay."
            ),
            "verification": "https://irc.freeq.at/api/v1/verify/{msgid}",
        },
    }


def agent_card_document():
    """dict — A2A agent card served at /.well-known/agent-card.json.

    keys: name, description, url, version, provider {organization, url},
    capabilities {streaming: true, pushNotifications: false},
    defaultInputModes ["text/plain"], defaultOutputModes ["text/plain"],
    skills: list of {id, name, description, tags} for read_channels,
    search_messages, verify_message, join_and_speak,
    documentationUrl, securitySchemes referencing auth.md.
    """
    return {
        "name": IDENTITY["name"],
        "description": IDENTITY["description"],
        "url": IDENTITY["api_host"],
        "version": "0.1.0",
        "provider": {
            "organization": "freeq",
            "url": IDENTITY["url"],
        },
        "capabilities": {
            "streaming": True,
            "pushNotifications": False,
        },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [
            {
                "id": "read_channels",
                "name": "read_channels",
                "description": "List public channels and read message history without authentication.",
                "tags": ["read", "channels", "history"],
            },
            {
                "id": "search_messages",
                "name": "search_messages",
                "description": "Full-text search across public channel messages.",
                "tags": ["read", "search"],
            },
            {
                "id": "verify_message",
                "name": "verify_message",
                "description": "Check the ed25519 signature of a message by msgid and report whether the author's key or only the server signed it.",
                "tags": ["verify", "signature", "attribution"],
            },
            {
                "id": "join_and_speak",
                "name": "join_and_speak",
                "description": "Authenticate as a did:key, join a channel and send signed messages.",
                "tags": ["write", "irc", "sasl"],
            },
        ],
        "documentationUrl": IDENTITY["agents_md"],
        "securitySchemes": [
            {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": (
                    "Opaque bearer token minted by agent self-registration with "
                    "a did:key — no signup. Full walkthrough: " + IDENTITY["auth_md"]
                ),
            }
        ],
    }


def api_catalog_document():
    """dict — RFC 9727 API catalog served at /.well-known/api-catalog.

    RFC 9727 shape: {"linkset": [{"anchor": <api_host>,
      "service-desc": [{"href": <openapi>, "type": "application/json"}],
      "service-doc": [{"href": "https://freeq.at/docs/", "type": "text/html"}],
      "status": [{"href": "https://irc.freeq.at/api/v1/health"}]}]}
    """
    return {
        "linkset": [
            {
                "anchor": IDENTITY["api_host"],
                "service-desc": [
                    {"href": IDENTITY["openapi"], "type": "application/json"}
                ],
                "service-doc": [
                    {"href": "https://freeq.at/docs/", "type": "text/html"}
                ],
                "status": [
                    {"href": "https://irc.freeq.at/api/v1/health"}
                ],
            }
        ]
    }


def mcp_server_card_document():
    """dict — /.well-known/mcp/server-card.json.

    The MCP server is NOT published to npm yet. Say so honestly:
    {"name": "freeq", "description": ..., "version": "0.1.0",
     "source": "https://github.com/freeq-irc/freeq/tree/main/freeq-mcp",
     "transport": "stdio", "published": false,
     "install": "clone the repo, npm install && npm run build in freeq-mcp/",
     "documentation": "https://freeq.at/agents.md"}
    Do not advertise `npx -y @freeq/mcp`: the package does not exist and an
    agent that believes this file will fail.
    """
    return {
        "name": "freeq",
        "description": (
            "Freeq MCP server: the REST API and the IRC verbs exposed as MCP "
            "tools (read, search, verify, join, speak)."
        ),
        "version": "0.1.0",
        "source": "https://github.com/freeq-irc/freeq/tree/main/freeq-mcp",
        "transport": "stdio",
        "published": False,
        "install": "clone the repo, npm install && npm run build in freeq-mcp/",
        "documentation": "https://freeq.at/agents.md",
    }


def robots_txt():
    """str — allow every UA and every AI crawler in AI_CRAWLERS explicitly.

    Format: `User-agent: *` + `Allow: /`, then one `User-agent:`/`Allow: /`
    stanza per crawler in AI_CRAWLERS (the auditor greps for the names), then
    `Sitemap: https://freeq.at/sitemap.xml`.
    """
    lines = ["User-agent: *", "Allow: /", ""]
    for ua in AI_CRAWLERS:
        lines.append(f"User-agent: {ua}")
        lines.append("Allow: /")
        lines.append("")
    lines.append("Sitemap: https://freeq.at/sitemap.xml")
    return "\n".join(lines) + "\n"


def sitemap_xml():
    """str — urlset over SITEMAP_PATHS plus every doc slug from app.SLUG_MAP.

    Each <url> carries <loc>, <lastmod> (YYYY-MM-DD; use the source file's
    mtime where there is one, today otherwise), and <changefreq>.
    Import SLUG_MAP lazily inside the function to avoid a circular import.
    """
    import app as site  # lazy: app.py imports this module at startup

    today = date.today().isoformat()
    urls = []

    def add(loc, lastmod, changefreq):
        urls.append(
            "  <url>\n"
            f"    <loc>{escape(loc)}</loc>\n"
            f"    <lastmod>{lastmod}</lastmod>\n"
            f"    <changefreq>{changefreq}</changefreq>\n"
            "  </url>"
        )

    for path in SITEMAP_PATHS:
        add(f"{IDENTITY['url']}{path}", today, "weekly")

    for slug in site.SLUG_MAP:
        src = site._doc_path(slug)
        if src is not None and src.exists():
            lastmod = date.fromtimestamp(src.stat().st_mtime).isoformat()
        else:
            lastmod = today
        add(f"{IDENTITY['url']}/docs/{slug}/", lastmod, "monthly")

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls)
        + "\n</urlset>\n"
    )


def not_found_markdown():
    """str — the body of a 404: one line saying the path was not found, then
    markdown links to /llms.txt, /sitemap.xml, /docs/, /agents.md."""
    return (
        "# Not found\n\n"
        "This path does not exist on freeq.at.\n\n"
        "Start from a machine-readable surface instead:\n\n"
        "- [llms.txt](https://freeq.at/llms.txt) — the index agents read first\n"
        "- [sitemap.xml](https://freeq.at/sitemap.xml) — every page, with absolute URLs\n"
        "- [Documentation](https://freeq.at/docs/) — the rendered guide\n"
        "- [agents.md](https://freeq.at/agents.md) — how to use freeq as an agent\n"
    )


def register_agent_surfaces(app):
    """Attach every route below to `app`. Called once from app.py."""

    # Static rules are registered before nothing else matters: Werkzeug's
    # sorter ranks fully-static paths above the existing
    # `/.well-known/<path:filename>` converter rule, so these win.

    @app.route("/robots.txt")
    def robots_txt_route():
        return Response(robots_txt(), status=200,
                        content_type="text/plain; charset=utf-8")

    @app.route("/sitemap.xml")
    def sitemap_xml_route():
        return Response(sitemap_xml(), status=200,
                        content_type="application/xml; charset=utf-8")

    @app.route("/.well-known/ard.json")
    def well_known_ard():
        return jsonify(ard_document())

    @app.route("/.well-known/ai-catalog.json")
    def well_known_ai_catalog():
        return jsonify(ard_document())

    @app.route("/.well-known/agent-card.json")
    def well_known_agent_card():
        return jsonify(agent_card_document())

    @app.route("/.well-known/api-catalog")
    def well_known_api_catalog():
        return jsonify(api_catalog_document())

    @app.route("/.well-known/mcp/server-card.json")
    def well_known_mcp_server_card():
        return jsonify(mcp_server_card_document())

    @app.route("/agents.md")
    def agents_md():
        return _agent_facing_markdown()

    @app.route("/AGENTS.md")
    def agents_md_upper():
        return _agent_facing_markdown()

    @app.route("/auth.md")
    def auth_md():
        return _repo_markdown("auth.md")

    # ── 404: soft-404s poison agents, so a missing path must say so in the
    #    body a crawler can read. Markdown is the default for clients that
    #    have not explicitly asked for HTML (curl, crawlers, */*); a client
    #    that asks for text/html gets the existing HTML 404.
    @app.errorhandler(404)
    def not_found(error):
        from werkzeug.exceptions import NotFound

        path = request.path
        accept = request.headers.get("Accept", "")
        machine_readable = path.rsplit(".", 1)[-1].lower() in {"json", "md", "txt", "xml"}
        wants_html = "text/html" in accept or "application/xhtml+xml" in accept
        if machine_readable or "text/markdown" in accept or not wants_html:
            return Response(not_found_markdown(), status=404, content_type=_MARKDOWN_CT)
        exc = NotFound()
        headers = exc.get_headers()
        return Response(exc.get_body(), status=404, headers=headers,
                        content_type="text/html; charset=utf-8")

    # ── RFC 8288 Link headers on HTML responses.
    @app.after_request
    def add_link_headers(response):
        ctype = response.headers.get("Content-Type") or ""
        if not ctype.startswith("text/html"):
            return response
        if response.headers.get("Link"):  # never overwrite an existing Link
            return response
        response.headers["Link"] = (
            f"<{IDENTITY['url']}{request.path}>; rel=\"canonical\", "
            f"<{IDENTITY['openapi']}>; rel=\"service-desc\", "
            f"<{IDENTITY['llms_txt']}>; rel=\"describedby\""
        )
        return response

    return app
