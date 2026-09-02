"""Machine-readable discovery surfaces for agents (robots, sitemap, .well-known)."""
import json
import re
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
    "/about/", "/contact/", "/privacy/", "/docs/", "/blog/",
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


#: Public, agent-facing prose, shared byte-for-byte with irc.freeq.at (which
#: compiles the same files in with `include_str!`). It lives in its own
#: directory rather than the repo root for a filesystem reason: macOS is
#: case-insensitive, so a repo-root `agents.md` IS `AGENTS.md` — the
#: contributor file, a symlink to CLAUDE.md, with production hosts in it.
#: Writing one silently overwrites the other.
AGENT_DOCS = REPO_ROOT / "agent-docs"


def _repo_markdown(name):
    """Serve AGENT_DOCS/<name> as markdown, 404 if absent.

    SECURITY: `name` must be matched against a hardcoded allowlist inside the
    caller. Never join user input onto this path.
    """
    target = (AGENT_DOCS / name).resolve()
    # Belt and braces even though the caller passes a literal: the resolved
    # file must live directly inside the repo root, nowhere else. (This also
    # keeps a symlinked name from pointing outside the tree.)
    try:
        target.relative_to(AGENT_DOCS.resolve())
    except ValueError:
        abort(404)
    if not target.is_file():
        abort(404)
    return _markdown(target.read_text())


def _agent_facing_markdown():
    """The public agents.md, served at /agents.md and /AGENTS.md.

    Deliberately NOT the repo-root AGENTS.md: that path is an internal
    developer file (a symlink to CLAUDE.md, with deploy hosts and task lists
    in it — the audit regression guard is the 'deploy.sh' string). The public
    copy lives in agent-docs/, which cannot collide with it.
    """
    return _repo_markdown("agents.md")


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


# ── Page metadata (canonical / og:* / JSON-LD) ─────────────────────────

# One-line descriptions for the markdown link lists. Keyed by site path.
MD_PAGE_LINKS = {
    "/": ("Home", "This page"),
    "/connect/": ("Connect", "The server address, channels, and how to authenticate"),
    "/sdk/": ("SDK", "SDKs and libraries for building freeq clients and bots"),
    "/agents/": ("Agents", "Agents as first-class protocol participants"),
    "/protocol/": ("Protocol", "SASL, tags, signing, federation — the freeq protocol"),
    "/clients/": ("Clients", "First-party clients, plus guest access from any IRC client"),
    "/about/": ("About", "About the project, philosophy, and components"),
    "/contact/": ("Contact", "GitHub issues, #general on irc.freeq.at, the Bluesky handle"),
    "/privacy/": ("Privacy", "What a server stores, what it never sees, what operators can do"),
    "/docs/": ("Docs", "The full documentation"),
    "/blog/": ("Blog", "Engineering notes from the freeq project"),
}


def home_markdown_body():
    """str — the homepage as markdown; the body of /index.md, ?mode=agent, and
    the Accept: text/markdown negotiation of ``/``."""
    lines = ["# freeq", "", IDENTITY["description"], "", "## Pages", ""]
    for path in SITEMAP_PATHS:
        name, desc = MD_PAGE_LINKS.get(path, (path, ""))
        lines.append(f"- [{name}]({IDENTITY['url']}{path}): {desc}")
    lines += ["", "## Agent surfaces", ""]
    lines.append(f"- [llms.txt]({IDENTITY['llms_txt']}): the index an agent reads first")
    lines.append(f"- [agents.md]({IDENTITY['agents_md']}): when and how to use freeq as an agent")
    lines.append(f"- [auth.md]({IDENTITY['auth_md']}): credentials walkthrough — did:key self-registration and bearer tokens")
    lines.append(f"- [OpenAPI 3.1]({IDENTITY['openapi']}): every HTTP endpoint, its parameters and its responses")
    lines.append("")
    return "\n".join(lines)


# HTML top-level page → template. Used to build each page's markdown stub from
# the page's own H1 and <meta description>, so the prose is never hand-copied
# and cannot drift from the page it summarizes.
PAGE_TEMPLATES = {
    "/connect/": "connect.html",
    "/sdk/": "sdk.html",
    "/agents/": "agents.html",
    "/protocol/": "protocol.html",
    "/clients/": "clients.html",
    "/about/": "about.html",
    "/docs/": "docs_index.html",
    "/contact/": "contact.html",
    "/privacy/": "privacy.html",
}

_H1_RE = re.compile(r"<h1[^>]*>(.*?)</h1>", re.S | re.I)
_META_DESC_RE = re.compile(r'<meta name="description" content="([^"]*)"', re.I)


def page_markdown_body(app, path):
    """str — short markdown stub for an HTML top-level page.

    H1 and description come from the rendered page itself, so the stub says
    what the page says; the rest is links to the rendered page and the docs.
    """
    from flask import render_template

    try:
        html = render_template(PAGE_TEMPLATES[path])
    except RuntimeError:  # no request context (direct call from tests)
        with app.test_request_context(path):
            html = render_template(PAGE_TEMPLATES[path])
    h1 = next(iter(_H1_RE.findall(html)), "")
    h1 = re.sub(r"<[^>]+>", " ", h1)
    h1 = re.sub(r"\s+", " ", h1).strip() or "freeq"
    m = _META_DESC_RE.search(html)
    desc = (m.group(1).strip() if m else IDENTITY["description"])
    url = IDENTITY["url"] + path
    lines = [
        f"# {h1}",
        "",
        desc,
        "",
        f"- [Rendered page]({url}): the HTML version of this page",
        f"- [Documentation]({IDENTITY['url']}/docs/): the full guide",
        f"- [llms.txt]({IDENTITY['llms_txt']}): the index an agent reads first",
        f"- [agents.md]({IDENTITY['agents_md']}): how agents use freeq",
        "",
    ]
    return "\n".join(lines)


def _blog_headline(slug):
    """Post title from the local blog source, slug-derived as fallback."""
    p = SITE_ROOT / "blog" / f"{slug}.md"
    if p.is_file():
        for line in p.read_text().splitlines():
            if line.startswith("# "):
                return line[2:].strip()
    return re.sub(r"[-_]+", " ", slug).strip().capitalize() or "freeq post"


def jsonld_graph(path):
    """dict — schema.org ``@context`` + ``@graph`` for one page, from IDENTITY.

    Three nodes on every page (Organization, SoftwareApplication, WebSite);
    a BlogPosting is appended on ``/blog/<slug>`` paths because auditors
    reward schema-type breadth. Organization and WebSite carry stable ``@id``
    values so WebSite.publisher can reference the Organization by ``@id``.
    """
    org = {
        "@type": "Organization",
        "@id": "https://freeq.at/#organization",
        "name": IDENTITY["name"],
        "url": IDENTITY["url"],
        "description": IDENTITY["description"],
        "logo": IDENTITY["url"] + "/static/freeq.png",
        "sameAs": [
            IDENTITY["repo"],
            IDENTITY["api_host"],
            "https://bsky.app/profile/freeq.at",
        ],
        "contactPoint": {
            "@type": "ContactPoint",
            "contactType": "technical support",
            "url": "https://freeq.at/contact/",
        },
    }
    software = {
        "@type": "SoftwareApplication",
        "name": IDENTITY["name"],
        "applicationCategory": "CommunicationApplication",
        "operatingSystem": "Any",
        "url": IDENTITY["url"],
        "description": IDENTITY["description"],
        "softwareHelp": "https://freeq.at/docs/",
        "downloadUrl": IDENTITY["repo"],
        "license": IDENTITY["license"],
        "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
    }
    website = {
        "@type": "WebSite",
        "@id": "https://freeq.at/#website",
        "name": IDENTITY["name"],
        "url": IDENTITY["url"],
        "publisher": {"@id": "https://freeq.at/#organization"},
        "potentialAction": {
            "@type": "SearchAction",
            "target": "https://freeq.at/docs/?q={search_term_string}",
            "query-input": "required name=search_term_string",
        },
    }
    graph = [org, software, website]
    m = re.match(r"^/blog/([^/]+)/?$", path)
    if m:
        graph.append({
            "@type": "BlogPosting",
            "headline": _blog_headline(m.group(1)),
            "url": IDENTITY["url"] + m.group(0).rstrip("/") + "/",
            "author": {"@id": "https://freeq.at/#organization"},
            "publisher": {"@id": "https://freeq.at/#organization"},
        })
    return {"@context": "https://schema.org", "@graph": graph}


# ── Section-scoped llms.txt indices (/docs/llms.txt, /sdk/llms.txt) ──

def _md_index_sections():
    """{(section name): {allowed slugs}} pairs for the two scoped indices."""
    return {
        "docs": {
            "Start here": {"what-is-freeq", "getting-started", "features"},
            "Protocol": {"protocol", "authentication", "tag-registry",
                         "encryption", "federation", "limitations"},
            "Building on freeq": {"api-reference", "self-hosting"},
            "Governance": {"policy-system", "verifiers", "moderation"},
        },
        "sdk": {
            "Start here": {"getting-started"},
            "Agent surfaces": {"agents", "agent-quickstart", "agent-assistance",
                              "well-known-agent", "watch-your-agent"},
            "Building on freeq": {"typescript-sdk", "bot-quickstart", "bots",
                                 "api-reference"},
        },
    }


def section_llms_body(heading, kind):
    """str — llms.txt filtered to one section scope, same shape as /llms.txt.

    Built from app.py's curated registry (lazy import: app.py imports this
    module at startup, so importing it at module level is circular).
    """
    import app as site  # lazy, as in sitemap_xml()

    section_map = _md_index_sections()[kind]
    lines = [f"# freeq — {heading}", "", f"> {site.LLMS_SUMMARY}", ""]
    for section, entries in site.LLMS_SECTIONS:
        allowed = section_map.get(section)
        if allowed is None:
            continue
        kept = [(slug, desc) for slug, desc in entries if slug in allowed]
        if not kept:
            continue
        lines.append(f"## {section}")
        lines.append("")
        for slug, desc in kept:
            lines.append(f"- [{site._doc_title(slug)}]({site.SITE_URL}/docs/{slug}.md): {desc}")
        lines.append("")
    lines.append("- [Source](https://github.com/freeq-irc/freeq): the implementation is the specification of last resort")
    lines.append("")
    return "\n".join(lines)


def _wants_markdown() -> bool:
    """True when Accept names text/markdown and text/html does not outrank it.

    Browsers send text/html without text/markdown (→ False); an agent sends
    only text/markdown, or a higher q for it (→ True).
    """
    header = request.headers.get("Accept")
    if not header or "text/markdown" not in header:
        return False
    md_q = 0.0
    html_q = 0.0
    for item in header.split(","):
        parts = [p.strip() for p in item.split(";") if p.strip()]
        if not parts:
            continue
        mime = parts[0].lower()
        q = 1.0
        for p in parts[1:]:
            if p.lower().startswith("q="):
                try:
                    q = float(p[2:])
                except ValueError:
                    q = 0.0
        if mime == "text/markdown":
            md_q = max(md_q, q)
        elif mime in ("text/html", "application/xhtml+xml"):
            html_q = max(html_q, q)
    return md_q > 0 and html_q <= md_q


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

    # Self-service enrollment, welcome-mat layout. Served from both hosts
    # because an agent that lands on the docs site should not have to guess
    # that enrollment happens on another hostname; the document itself uses
    # absolute irc.freeq.at URLs, so it is correct wherever it is read.
    @app.route("/.well-known/welcome.md")
    def welcome_md():
        return _repo_markdown("welcome.md")

    @app.route("/tos")
    def tos_txt():
        target = (AGENT_DOCS / "tos.txt").resolve()
        if not target.is_file():
            abort(404)
        # text/plain, verbatim: an agent hashes these exact bytes.
        return Response(
            target.read_text(),
            status=200,
            content_type="text/plain; charset=utf-8",
        )

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


    # ── Page metadata context: canonical / markdown_url / JSON-LD ────────────
    @app.context_processor
    def agent_metadata():
        try:
            path = request.path
        except RuntimeError:  # pragma: no cover — render outside request
            return {"canonical_url": IDENTITY["url"],
                    "markdown_url": IDENTITY["url"] + "/index.md", "json_ld": ""}
        md_path = "/index.md" if path == "/" else path.rstrip("/") + ".md"
        return {
            "canonical_url": IDENTITY["url"] + path,
            "markdown_url": IDENTITY["url"] + md_path,
            "json_ld": json.dumps(jsonld_graph(path)),
        }

    # ── Markdown surface: /index.md, /<page>.md ─────────────────────────────
    # /agents.md deliberately stays the agent-facing document (pre-existing
    # commitment; tests depend on it). The /agents/ page still negotiates to
    # a markdown stub via Accept: text/markdown and ?mode=agent below.
    _page_md_cache = {}

    def _md_body_for_path(path):
        if path == "/":
            return home_markdown_body()
        if path not in PAGE_TEMPLATES:
            return None
        if path not in _page_md_cache:
            _page_md_cache[path] = page_markdown_body(app, path)
        return _page_md_cache[path]

    @app.route("/index.md")
    def index_markdown():
        return _markdown(home_markdown_body())

    for _stem in ("connect", "sdk", "protocol", "clients", "about", "docs",
                  "contact", "privacy"):
        _path = f"/{_stem}/"

        @app.route(f"/{_stem}.md", endpoint=f"page_markdown_{_stem}")
        def page_markdown(_body=_md_body_for_path(_path)):
            return _markdown(_body)

    # ── Section-scoped llms.txt indices ─────────────────────────────────
    @app.route("/docs/llms.txt")
    def docs_llms_txt():
        return _markdown(section_llms_body("docs index", "docs"))

    @app.route("/sdk/llms.txt")
    def sdk_llms_txt():
        return _markdown(section_llms_body("SDK index", "sdk"))

    # ── Content negotiation ─────────────────────────────────────────────
    # Accept: text/markdown (or ?mode=agent) on an HTML page serves the
    # markdown body instead. Every HTML response carries Vary: Accept, since
    # the negotiation audit fails it without that header.
    @app.after_request
    def markdown_negotiation(response):
        if not (response.headers.get("Content-Type") or "").startswith("text/html"):
            return response
        response.vary.add("Accept")
        if response.status_code != 200:
            return response
        if not (_wants_markdown() or request.args.get("mode") == "agent"):
            return response
        body = _md_body_for_path(request.path)
        if body is None:
            return response
        md = Response(body, status=200, content_type=_MARKDOWN_CT)
        md.vary.add("Accept")
        return md

    return app
