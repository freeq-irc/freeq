"""
Metadata and markdown-surface audit (deliverable 5).

Covers the five deliverables: JSON-LD on every page, canonical/og:* head
metadata, the trust-anchor pages, the markdown content-negotiation surface,
and the section-scoped llms.txt indices. Also pins the pre-existing contract
that /agents.md stays the agent-facing document.
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as site  # noqa: E402
import agent_surfaces as surfaces  # noqa: E402

MD_LINK_RE = re.compile(r"\[[^\]]+\]\([^)]+\)")
JSONLD_RE = re.compile(r'<script[^>]+application/ld\+json[^>]*>(.*?)</script>', re.S)
SITE = "https://freeq.at"


def _client():
    return site.app.test_client()


def _ld_graph(body):
    blocks = JSONLD_RE.findall(body)
    assert len(blocks) == 1, f"{len(blocks)} JSON-LD blocks"
    return json.loads(blocks[0])


def _visible_words(body):
    """Word count of visible text only (scripts, styles, and tags removed)."""
    body = re.sub(r"<script[^>]*>.*?</script>", " ", body, flags=re.S)
    body = re.sub(r"<style[^>]*>.*?</style>", " ", body, flags=re.S)
    body = re.sub(r"<[^>]+>", " ", body)
    return len(body.split())


# ── JSON-LD ─────────────────────────────────────────────────────────────

def test_every_sitemap_page_carries_exactly_one_jsonld_block():
    client = _client()
    for path in surfaces.SITEMAP_PATHS:
        resp = client.get(path)
        assert resp.status_code == 200, path
        doc = _ld_graph(resp.data.decode())
        types = {node.get("@type") for node in doc["@graph"]}
        assert {"Organization", "SoftwareApplication", "WebSite"} <= types, path


def test_jsonld_structure():
    doc = _ld_graph(_client().get("/").data.decode())
    by_type = {node["@type"]: node for node in doc["@graph"]}
    org = by_type["Organization"]
    web = by_type["WebSite"]
    sw = by_type["SoftwareApplication"]
    # Stable @ids, publisher-by-@id reference (not a name copy).
    assert org["@id"].startswith(SITE + "/#")
    assert web["publisher"] == {"@id": org["@id"]}
    # SearchAction with the template literal the audit looks for.
    action = web["potentialAction"]
    assert action["@type"] == "SearchAction"
    assert "{search_term_string}" in action["target"]
    # Free software, honestly typed.
    assert sw["offers"]["price"] == "0"
    assert "license" in sw
    # Organization points at real surfaces.
    assert any(s.startswith("https://github.com/") for s in org.get("sameAs", []))


def test_blog_page_adds_blogposting_node():
    client = _client()
    posts = list((Path(__file__).resolve().parent.parent / "blog").glob("*.md"))
    slug = posts[0].stem
    body = client.get(f"/blog/{slug}/")
    assert body.status_code == 200
    types = {node.get("@type") for node in _ld_graph(body.data.decode())["@graph"]}
    assert "BlogPosting" in types
    posting = next(n for n in _ld_graph(body.data.decode())["@graph"] if n["@type"] == "BlogPosting")
    assert posting["headline"]


def test_jsonld_renders_with_html_entity_safety():
    """JSON in the script tag must not break the page (no raw </script>)."""
    body = _client().get("/about/").data.decode()
    script = JSONLD_RE.search(body).group(0)
    assert "</script>" not in script[: script.rindex("</script>")]


# ── Head metadata ───────────────────────────────────────────────────────

def test_canonical_link_is_absolute_and_matches_path():
    client = _client()
    for path in surfaces.SITEMAP_PATHS + ["/contact/", "/privacy/"]:
        body = client.get(path).data.decode()
        m = re.search(r'<link rel="canonical" href="([^"]+)"', body)
        assert m, path
        assert m.group(1) == SITE + path, path


def test_og_and_twitter_metadata_present_on_every_page():
    client = _client()
    for path in surfaces.SITEMAP_PATHS:
        body = client.get(path).data.decode()
        for needle in ('<meta property="og:type" content="', "og:title",
                       "og:description", "og:url", "og:image",
                       '<meta name="twitter:card" content="'):
            assert needle in body, f"{path}: missing {needle}"


def test_blog_pages_are_og_article():
    posts = list((Path(__file__).resolve().parent.parent / "blog").glob("*.md"))
    body = _client().get(f"/blog/{posts[0].stem}/").data.decode()
    assert '<meta property="og:type" content="article"' in body


def test_markdown_alternate_link_present():
    assert 'rel="alternate" type="text/markdown"' in _client().get("/").data.decode()
    body = _client().get("/about/").data.decode()
    assert re.search(r'<link rel="alternate" type="text/markdown" href="https://freeq\.at/about\.md"', body), body


# ── Trust-anchor pages ──────────────────────────────────────────────────

def test_trust_anchor_pages_are_substantive():
    client = _client()
    for path in ("/contact/", "/privacy/"):
        resp = client.get(path)
        assert resp.status_code == 200, path
        body = resp.data.decode()
        assert _visible_words(body) >= 300, f"{path}: only {_visible_words(body)} visible words"
        assert _ld_graph(body)  # JSON-LD on these too


def test_trust_anchor_pages_in_sitemap():
    xml = _client().get("/sitemap.xml").data.decode()
    assert SITE + "/contact/" in xml
    assert SITE + "/privacy/" in xml


# ── Markdown surface ────────────────────────────────────────────────────

def test_index_md_shape():
    resp = _client().get("/index.md")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/markdown")
    body = resp.data.decode()
    assert body.startswith("# ")
    for path in surfaces.SITEMAP_PATHS:
        assert f"{SITE}{path}" in body, f"missing link to {path}"
    assert "llms.txt" in body and "agents.md" in body and "openapi" in body.lower()


def test_page_markdown_routes_exist_and_are_markdown():
    client = _client()
    for stem in ("connect", "sdk", "protocol", "clients", "about", "docs"):
        resp = client.get(f"/{stem}.md")
        assert resp.status_code == 200, stem
        assert resp.headers["Content-Type"].startswith("text/markdown"), stem
        body = resp.data.decode()
        assert body.startswith("# "), f"{stem}: no H1"
        assert f"{SITE}/{stem}/" in body, f"{stem}: no link back to its HTML page"


def test_page_markdown_stub_is_built_from_the_page():
    """The stub's H1 comes from the page's own <h1>, not hand-copied prose."""
    html = _client().get("/about/").data.decode()
    page_h1 = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", re.search(r"<h1[^>]*>(.*?)</h1>", html, re.S).group(1))).strip()
    md = _client().get("/about.md").data.decode()
    assert ("# " + page_h1) in md


def test_accept_header_negotiates_markdown_on_homepage():
    client = _client()
    resp = client.get("/", headers={"Accept": "text/markdown"})
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/markdown")
    assert "Accept" in resp.headers.get("Vary", "")
    assert resp.data.decode().startswith("# ")


def test_what_mode_agent_matches_the_md_route():
    client = _client()
    assert client.get("/?mode=agent").data == client.get("/index.md").data
    assert (client.get("/about/?mode=agent").data == client.get("/about.md").data)


def test_html_wins_when_html_is_ranked_higher():
    client = _client()
    resp = client.get("/", headers={"Accept": "text/html, text/markdown;q=0.5"})
    assert resp.headers["Content-Type"].startswith("text/html")
    resp = client.get("/", headers={"Accept": "*/*"})
    assert resp.headers["Content-Type"].startswith("text/html")
    resp = client.get("/")  # no Accept: curl-equivalent default
    assert resp.headers["Content-Type"].startswith("text/html")


def test_every_html_response_carries_vary_accept():
    client = _client()
    paths = surfaces.SITEMAP_PATHS + ["/contact/", "/privacy/", "/docs/what-is-freeq/"]
    for path in paths:
        resp = client.get(path)
        if resp.status_code != 200:
            continue
        assert resp.headers["Content-Type"].startswith("text/html"), path
        assert "Accept" in resp.headers.get("Vary", ""), path
    # 404 HTML page negotiates too
    resp = client.get("/no-such-page-xyz/", headers={"Accept": "text/html"})
    assert resp.status_code == 404
    assert resp.headers["Content-Type"].startswith("text/html")
    assert "Accept" in resp.headers.get("Vary", "")


def test_agents_md_remains_the_agent_document():
    """Pre-existing commitment: /agents.md is NOT a page stub."""
    body = _client().get("/agents.md").data.decode()
    assert body.lower().find("deploy.sh") == -1
    assert "freeq" in body.lower()
    # The /agents/ page itself still negotiates to markdown.
    resp = _client().get("/agents/", headers={"Accept": "text/markdown"})
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/markdown")
    assert resp.data.decode().startswith("# ")


# ── Section-scoped llms.txt ─────────────────────────────────────────────

def test_section_scoped_llms_txt_indexes():
    client = _client()
    for path in ("/docs/llms.txt", "/sdk/llms.txt"):
        resp = client.get(path)
        assert resp.status_code == 200, path
        assert resp.headers["Content-Type"].startswith("text/markdown"), path
        body = resp.data.decode()
        assert body.startswith("# freeq"), path
        assert any(MD_LINK_RE.search(line) for line in body.splitlines()), f"{path}: no markdown links"
        assert "freeq" in body.lower()


def test_sdk_index_scopes_to_sdk_entries():
    body = _client().get("/sdk/llms.txt").data.decode()
    assert "typescript-sdk" in body or "bot" in body.lower()
    # Docs-scoped policy doc should not be in the SDK index
    assert "policy-system" not in body


def test_docs_index_scopes_to_docs_entries():
    body = _client().get("/docs/llms.txt").data.decode()
    assert "protocol" in body.lower()
    assert "policy-system" in body  # governance section is docs-scoped
