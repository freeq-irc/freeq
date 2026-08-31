"""
agent_surfaces.py must answer an auditor (ora.ai) with the right status,
content-type and parseable body for every discovery path. A 200 text/html
where JSON was promised scores WORSE than a 404, so every assertion here
checks status + content-type + parseability.

Two regressions are worth a permanent test:

- /agents.md and /AGENTS.md must serve the *agent-facing* agents.md, never
  the repo-root AGENTS.md. In this checkout that file is a symlink to
  CLAUDE.md — an internal developer document that names production deploy
  hosts and references deploy.sh. Leaking it to the world is the failure
  mode the 'deploy.sh' assertion guards against.
- Soft-404s are poison for agents: a missing path must be a real 404 whose
  body points at /llms.txt, /sitemap.xml and /docs/.
"""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as site  # noqa: E402

WELL_KNOWN_JSON = [
    "/.well-known/ard.json",
    "/.well-known/ai-catalog.json",
    "/.well-known/agent-card.json",
    "/.well-known/api-catalog",
    "/.well-known/mcp/server-card.json",
]


def _client():
    return site.app.test_client()


def test_well_known_routes_return_parseable_json():
    client = _client()
    for path in WELL_KNOWN_JSON:
        resp = client.get(path)
        assert resp.status_code == 200, f"{path}: {resp.status_code}"
        assert resp.headers["Content-Type"].startswith("application/json"), \
            f"{path}: {resp.headers.get('Content-Type')}"
        doc = json.loads(resp.data)  # must parse
        assert isinstance(doc, dict), f"{path}: not a JSON object"


def test_well_known_json_documents_name_freeq():
    client = _client()
    for path in WELL_KNOWN_JSON:
        doc = json.loads(client.get(path).data)
        blob = json.dumps(doc)
        assert "freeq" in blob, f"{path}: document does not mention freeq"


def test_ard_document_trust_block():
    doc = json.loads(_client().get("/.well-known/ard.json").data)
    trust = doc["trust"]
    assert trust["verification"] == "https://irc.freeq.at/api/v1/verify/{msgid}"
    assert trust["policy_url"].startswith("https://freeq.at/")
    for key in ("name", "description", "url", "contact", "updated", "entries", "trust"):
        assert key in doc, f"ard.json missing {key}"
    for entry in doc["entries"]:
        for key in ("name", "type", "url", "description"):
            assert key in entry, f"ard.json entry missing {key}"


def test_api_catalog_contains_openapi():
    doc = json.loads(_client().get("/.well-known/api-catalog").data)
    assert "openapi.json" in json.dumps(doc), \
        "api-catalog must carry the OpenAPI contract URL"
    linkset = doc["linkset"]
    assert linkset[0]["anchor"] == "https://irc.freeq.at"


def test_mcp_server_card_is_honest_about_publishing():
    """The package is not on npm; the card must not say it is."""
    doc = json.loads(_client().get("/.well-known/mcp/server-card.json").data)
    assert doc["published"] is False
    assert "npx -y @freeq/mcp" not in json.dumps(doc)
    assert doc["install"].startswith("clone the repo")


def test_robots_txt_allows_ai_crawlers_and_names_sitemap():
    resp = _client().get("/robots.txt")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/plain")
    body = resp.data.decode()
    assert "Sitemap: https://freeq.at/sitemap.xml" in body
    assert "User-agent: *" in body
    # The auditor greps for these literal names.
    for ua in ("GPTBot", "ClaudeBot", "ora-agent"):
        assert ua in body, f"robots.txt missing an explicit stanza for {ua}"
    assert "ora-agent" in body
    # At least one Allow per stanza: one for * plus one per named crawler.
    assert body.count("Allow: /") >= 14


def test_sitemap_xml_parses_and_is_absolute():
    resp = _client().get("/sitemap.xml")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("application/xml")
    root = ET.fromstring(resp.data)
    assert root.tag.endswith("urlset")
    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    urls = root.findall("sm:url", ns) or root.findall("url")
    assert urls, "empty urlset"
    locs = {u.findtext("sm:loc", namespaces=ns) or u.findtext("loc") for u in urls}
    for loc in locs:
        assert loc.startswith("https://"), f"non-absolute <loc>: {loc}"
        assert "<" not in loc  # unescaped user input would have broken the XML
    # The curated home pages and the doc slugs from SLUG_MAP.
    for path in site.SITEMAP_PATHS if hasattr(site, "SITEMAP_PATHS") else \
            ["/", "/docs/", "/blog/"]:
        assert f"https://freeq.at{path}" in locs, f"missing {path}"
    for slug in ("what-is-freeq", "agents", "protocol"):
        assert f"https://freeq.at/docs/{slug}/" in locs
    # Every entry carries lastmod + changefreq.
    for u in urls:
        assert u.findtext("sm:lastmod", namespaces=ns) or u.findtext("lastmod"), "missing <lastmod>"
        assert u.findtext("sm:changefreq", namespaces=ns) or u.findtext("changefreq"), \
            "missing <changefreq>"


def test_agents_md_served_as_markdown():
    resp = _client().get("/agents.md")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/markdown")
    body = resp.data.decode()
    assert body.strip(), "empty agents.md"
    # The auditor checks status + content-type + a recognizable body.
    import re
    assert re.search(r"when to use", body, re.I), "agents.md should say when to use freeq"


def test_agents_uppercase_route_matches_lowercase():
    upper = _client().get("/AGENTS.md")
    lower = _client().get("/agents.md")
    assert upper.status_code == 200
    assert upper.data == lower.data


def test_agents_md_is_agent_facing_not_internal():
    """Regression guard: never serve the repo's own AGENTS.md.

    In this checkout AGENTS.md is a symlink to CLAUDE.md, an internal
    developer document that references deploy.sh and production hosts.
    """
    body = _client().get("/AGENTS.md").data.decode()
    assert "deploy.sh" not in body
    # And it is the agent-facing document, not the dev one.
    assert "AT Protocol DID" in body


def test_auth_md_served_as_markdown():
    resp = _client().get("/auth.md")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/markdown")
    body = resp.data.decode()
    assert body.strip(), "empty auth.md"
    assert "ATPROTO-CHALLENGE" in body  # the auditor looks for this


def test_unknown_path_is_a_true_404():
    resp = _client().get("/this-path-does-not-exist-9f3a")
    assert resp.status_code == 404, \
        "soft-404: agents will believe every path exists"
    body = resp.data.decode()
    # The 404 body must point an agent at something real.
    assert "llms.txt" in body
    assert "sitemap.xml" in body
    assert "/docs/" in body


def test_unknown_json_path_is_404_markdown_not_200_html():
    resp = _client().get("/no/such/document.json")
    assert resp.status_code == 404
    assert resp.headers["Content-Type"].startswith("text/markdown")
    body = resp.data.decode()
    assert "llms.txt" in body and "sitemap.xml" in body


def test_well_known_catch_all_still_serves_existing_files():
    """The registered static rules must not shadow the directory route."""
    resp = _client().get("/.well-known/atproto-did")
    assert resp.status_code == 200


def test_link_header_on_html_responses():
    resp = _client().get("/about/")
    assert resp.status_code == 200
    link = resp.headers.get("Link", "")
    assert 'rel="canonical"' in link
    assert 'rel="service-desc"' in link
    assert 'rel="describedby"' in link
    assert link.startswith("<https://freeq.at/about/>")
