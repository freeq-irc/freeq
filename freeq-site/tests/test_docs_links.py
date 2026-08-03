"""
Relative .md links in docs are written for GitHub. On the site they must be
rewritten: known docs to /docs/<slug>/, other repo files to github.com blob
URLs, everything else left alone.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as site  # noqa: E402


def test_slug_map_targets_exist():
    """Every SLUG_MAP file must exist in the repo docs dir (deploy copies it)."""
    for slug, (source, fn) in site.SLUG_MAP.items():
        assert (site.REPO_DOCS_DIR / fn).exists(), f"{slug}: missing {fn}"


def test_rewrite_known_doc_to_site_url():
    html = '<a href="self-hosting.md#tls">TLS</a>'
    out = site.rewrite_links(html, "self-hosting-quickstart.md")
    assert 'href="/docs/self-hosting/#tls"' in out


def test_rewrite_known_doc_case_insensitive():
    html = '<a href="security.md">sec</a>'
    out = site.rewrite_links(html, "self-hosting.md")
    assert 'href="/docs/security/"' in out


def test_rewrite_repo_file_to_github():
    html = '<a href="../deploy/miren/README.md#auth-broker">broker</a>'
    out = site.rewrite_links(html, "self-hosting-quickstart.md")
    assert 'href="https://github.com/freeq-irc/freeq/blob/main/deploy/miren/README.md#auth-broker"' in out


def test_rewrite_non_md_repo_file_to_github():
    html = '<a href="../.miren/app.toml">config</a>'
    out = site.rewrite_links(html, "self-hosting.md")
    assert 'href="https://github.com/freeq-irc/freeq/blob/main/.miren/app.toml"' in out


def test_untouched_links():
    for href in (
        "https://miren.md/getting-started",
        "/docs/getting-started/",
        "#local-anchor",
        "mailto:hi@example.com",
        "irc.freeq.at",
        "../../outside-the-repo.md",
    ):
        html = f'<a href="{href}">x</a>'
        assert site.rewrite_links(html, "self-hosting.md") == html, href


def test_all_github_blob_links_resolve_to_repo_files():
    """Every blob URL produced on any docs page must point at a real repo file
    (render-time can't check — the deployed site only ships docs/)."""
    import re as _re
    c = site.app.test_client()
    checked = 0
    for slug in site.SLUG_MAP:
        body = c.get(f"/docs/{slug}/").data.decode()
        for url in _re.findall(r'href="(https://github\.com/freeq-irc/freeq/blob/main/[^"#]+)', body):
            repo_rel = url.split("/blob/main/", 1)[1]
            assert (site.REPO_DOCS_DIR.parent / repo_rel).exists(), f"{slug}: dead blob link {url}"
            checked += 1
    assert checked > 0


def test_quickstart_page_has_no_dead_md_links():
    body = site.app.test_client().get("/docs/self-hosting-quickstart/").data.decode()
    assert 'href="self-hosting.md"' not in body
    assert 'href="../deploy/miren/README.md"' not in body
    assert 'href="/docs/self-hosting/"' in body
    assert "github.com/freeq-irc/freeq/blob/main/deploy/miren/README.md" in body


def test_full_guide_links_resolve():
    body = site.app.test_client().get("/docs/self-hosting/").data.decode()
    assert 'href="/docs/self-hosting-quickstart/"' in body
    assert 'href="/docs/federation/"' in body
