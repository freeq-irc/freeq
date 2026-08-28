"""
llms.txt is the entry point an LLM agent fetches first, so the failure mode
that matters is a link that doesn't resolve: a curated slug that was renamed
out of SLUG_MAP, or a /docs/<slug>.md route that 404s. These tests walk the
generated index and follow every on-site link.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as site  # noqa: E402

LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def _client():
    return site.app.test_client()


def test_llms_txt_served_as_markdown():
    resp = _client().get("/llms.txt")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/markdown")
    body = resp.data.decode()
    # llmstxt.org shape: H1, then a blockquote summary.
    assert body.startswith("# freeq\n")
    assert "\n> " in body


def test_llms_txt_covers_the_expected_sections():
    body = _client().get("/llms.txt").data.decode()
    for section, _entries in site.LLMS_SECTIONS:
        assert f"## {section}" in body
    assert "## Machine-readable surfaces" in body
    assert "/api/v1/openapi.json" in body, "the OpenAPI contract must be linked"
    assert "wss://irc.freeq.at/irc" in body, "the transport must be linked"


def test_every_curated_slug_is_mapped_and_exists():
    """A doc rename must not leave a dead entry in the index."""
    missing = []
    for _section, entries in site.LLMS_SECTIONS:
        for slug, desc in entries:
            path = site._doc_path(slug)
            if path is None or not path.exists():
                missing.append(slug)
            assert desc, f"{slug} needs a one-line description"
    assert not missing, f"curated slugs with no doc: {missing}"


def test_index_uses_doc_titles_not_slugs():
    body = _client().get("/llms.txt").data.decode()
    # Titles come from each doc's H1; a fallback would show the slug verbatim.
    assert f"({site.SITE_URL}/docs/getting-started.md)" in body
    assert "[Getting-started]" not in body


def test_on_site_links_all_resolve():
    client = _client()
    body = client.get("/llms.txt").data.decode()
    broken = []
    for href in LINK_RE.findall(body):
        if href.startswith(site.SITE_URL):
            path = href[len(site.SITE_URL):]
        elif href.startswith("/"):
            path = href
        else:
            continue  # off-site (github, npm, irc.freeq.at) — not ours to serve
        if client.get(path).status_code != 200:
            broken.append(path)
    assert not broken, f"llms.txt links that don't resolve: {broken}"


def test_docs_markdown_route_serves_source_not_html():
    resp = _client().get("/docs/getting-started.md")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/markdown")
    body = resp.data.decode()
    assert body.lstrip().startswith("#"), "must be markdown source"
    assert "<html" not in body.lower()


def test_docs_markdown_route_404s_for_unknown_slug():
    assert _client().get("/docs/not-a-real-doc.md").status_code == 404


def test_docs_markdown_route_does_not_shadow_rendered_page():
    resp = _client().get("/docs/getting-started/")
    assert resp.status_code == 200
    assert b"<" in resp.data, "the HTML page must still render"


def test_llms_full_concatenates_the_curated_docs():
    resp = _client().get("/llms-full.txt")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/markdown")
    body = resp.data.decode()
    assert body.startswith("# freeq — full documentation")
    # Every curated doc's H1 should appear somewhere in the concatenation.
    for _section, entries in site.LLMS_SECTIONS:
        for slug, _desc in entries:
            title = site._doc_title(slug)
            assert title in body, f"{slug} ({title}) missing from llms-full.txt"


def test_llms_full_is_bounded_to_the_curated_set():
    """It must not become 'every doc in the repo' by accident."""
    body = _client().get("/llms-full.txt").data.decode()
    curated = sum(len(entries) for _s, entries in site.LLMS_SECTIONS)
    assert body.count("<!-- source: docs/") == curated
    # Sanity: a doc that exists in SLUG_MAP but isn't curated stays out.
    assert "docs/AV-QUIC-MIGRATION.md" not in body


def test_repo_root_llms_txt_points_at_the_hosted_indexes():
    """GitHub is itself a discovery surface, so the repo carries an index too.

    It is hand-maintained (the site's is generated), so the thing worth
    checking is that it still points at the hosted versions and that its
    in-repo links exist.
    """
    root = Path(__file__).resolve().parent.parent.parent
    path = root / "llms.txt"
    assert path.exists(), "repo root llms.txt is missing"
    body = path.read_text()
    assert body.startswith("# freeq\n")
    for hosted in [
        "https://freeq.at/llms.txt",
        "https://freeq.at/llms-full.txt",
        "https://irc.freeq.at/api/v1/openapi.json",
        "https://irc.freeq.at/.well-known/agent.json",
    ]:
        assert hosted in body, f"repo llms.txt should link {hosted}"

    broken = [
        href for href in LINK_RE.findall(body)
        if not href.startswith(("http://", "https://")) and not (root / href).exists()
    ]
    assert not broken, f"repo llms.txt links to missing paths: {broken}"
