"""freeq.at — static site with markdown docs rendering."""

import os
import re
import subprocess
from pathlib import Path

from flask import Flask, render_template, abort, send_from_directory, jsonify
import markdown
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.fenced_code import FencedCodeExtension
from markdown.extensions.tables import TableExtension
from markdown.extensions.toc import TocExtension

app = Flask(__name__)

# Resolve git commit at startup (written by deploy.sh or read from git)
_commit_file = Path(__file__).parent / ".git_commit"
if _commit_file.exists():
    GIT_COMMIT = _commit_file.read_text().strip()
else:
    try:
        GIT_COMMIT = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, cwd=Path(__file__).parent
        ).stdout.strip() or "unknown"
    except Exception:
        GIT_COMMIT = "unknown"

# Docs directory — site docs/ and repo docs/
SITE_DOCS_DIR = Path(__file__).parent / "docs"
REPO_DOCS_DIR = Path(__file__).parent.parent / "docs"
BLOG_DIR = Path(__file__).parent / "blog"

# ── Blog: read from AT Protocol ──────────────────────────────────────────────
# Posts are authored in Leaflet, which writes them to the author's own PDS as
# `site.standard.document` records. We read those directly, so the blog is a
# demonstration of the thing this site is about: the data is in the author's
# repo, and this renderer is replaceable.
#
#   FREEQ_BLOG_DID          contributing DIDs, comma-separated. A publication
#                           can have collaborators, and in AT Protocol you only
#                           write to your OWN repo — so a collaborator's post
#                           lives in their repo with `site` pointing at the
#                           owner's publication. Every contributing repo must be
#                           listed here or its posts are invisible.
#   FREEQ_BLOG_PUBLICATION  at:// of the publication to show. Unset shows every
#                           document in the repo, which is wrong once there is
#                           more than one publication — set it as soon as the
#                           freeq publication exists.
#
# Until a publication is configured and reachable, /blog falls back to the local
# blog/*.md files, so the page is never empty or broken.
import atproto_blog

BLOG_DIDS = [
    d.strip()
    for d in os.environ.get(
        "FREEQ_BLOG_DID",
        # publication owner (chadfowler.com), then contributors (freeq.at)
        "did:plc:4qsyxmnsblo4luuycm3572bq,did:plc:3wbo7sapgihteh7h46773ru6",
    ).split(",")
    if d.strip()
]
BLOG_DID = BLOG_DIDS[0]
BLOG_PUBLICATION = os.environ.get("FREEQ_BLOG_PUBLICATION") or None
BLOG_SOURCE = atproto_blog.BlogSource(BLOG_DIDS, BLOG_PUBLICATION, ttl=300.0)

# Markdown renderer
MD_EXTENSIONS = [
    FencedCodeExtension(),
    CodeHiliteExtension(css_class="highlight", guess_lang=False),
    TableExtension(),
    TocExtension(permalink=True),
    "nl2br",
]


def render_md(filepath: Path) -> dict:
    """Render a markdown file, return {html, toc, title}."""
    text = filepath.read_text()
    md = markdown.Markdown(extensions=MD_EXTENSIONS)
    html = md.convert(text)
    toc = getattr(md, "toc", "")
    # Extract title from first H1
    title = "freeq"
    for line in text.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            break
    md.reset()
    return {"html": html, "toc": toc, "title": title}


# ── Slug → file mapping ──────────────────────────────────────────

SLUG_MAP = {
    # Site docs (new content)
    "what-is-freeq": ("site", "what-is-freeq.md"),
    "getting-started": ("site", "getting-started.md"),
    "authentication": ("site", "authentication.md"),
    "web-client": ("site", "web-client.md"),
    "ios-app": ("site", "ios-app.md"),
    "bots": ("site", "bots.md"),
    "policy-framework": ("site", "policy-framework.md"),
    "verifiers": ("site", "verifiers.md"),
    "moderation": ("site", "moderation.md"),
    "federation": ("site", "federation.md"),
    "self-hosting": ("site", "self-hosting.md"),
    "self-hosting-quickstart": ("site", "self-hosting-quickstart.md"),
    "api-reference": ("site", "api-reference.md"),
    # Repo docs (existing technical docs)
    "protocol": ("site", "PROTOCOL.md"),
    "features": ("site", "Features.md"),
    "limitations": ("site", "KNOWN-LIMITATIONS.md"),
    "architecture": ("site", "architecture-decisions.md"),
    "s2s": ("site", "s2s-audit.md"),
    "future": ("site", "FutureDirection.md"),
    "web-infra": ("site", "proposal-web-infra.md"),
    "whats-new": ("site", "WHATS-NEW.md"),
    "demo": ("site", "DEMO.md"),
    "encryption": ("site", "ENCRYPTION.md"),
    "bot-quickstart": ("site", "BOT-QUICKSTART.md"),
    "policy-system": ("site", "POLICY.md"),
    "agents": ("site", "agents.md"),
    "agent-quickstart": ("site", "agent-quickstart.md"),
    "watch-your-agent": ("site", "watch-your-agent.md"),
    "tag-registry": ("site", "tag-registry.md"),
    "teams": ("site", "teams.md"),
    "security": ("site", "SECURITY.md"),
    "typescript-sdk": ("site", "typescript-sdk.md"),
    "agent-assistance": ("site", "agent-assistance.md"),
    "av-agents": ("site", "av-agents.md"),
    "av-protocol": ("site", "av-protocol.md"),
    "well-known-agent": ("site", "skills/well-known-agent.md"),
    "av-quic-migration": ("site", "AV-QUIC-MIGRATION.md"),
    # Company privacy / E2E encrypted channels
    "company-encrypted-channels": ("site", "COMPANY-ENCRYPTED-CHANNELS.md"),
    "vc-e2e-channels": ("site", "VC-BOOTSTRAPPED-CHANNEL-E2EE.md"),
    "self-hosting-e2e": ("site", "SELF-HOSTING-END-TO-END.md"),
}


# ── Relative .md link rewriting ──────────────────────────────────────
#
# Docs are written for the repo (GitHub), where relative links like
# `[guide](self-hosting.md)` or `[deploy](../deploy/miren/README.md)` work.
# Served on the site those hrefs are dead, so rewrite them at render time:
# links to files that have a docs page become `/docs/<slug>/`, anything else
# that exists in the repo becomes a github.com blob URL.

GITHUB_BLOB_BASE = "https://github.com/freeq-irc/freeq/blob/main/"

_MD_BASENAME_TO_SLUG = {}
for _slug, (_source, _fn) in SLUG_MAP.items():
    _MD_BASENAME_TO_SLUG.setdefault(Path(_fn).name.lower(), _slug)

_HREF_RE = re.compile(r'href="([^"]+)"')


def rewrite_links(html: str, doc_filename: str) -> str:
    """Rewrite relative .md hrefs in rendered HTML for site serving."""
    # Doc's directory, relative to the repo root (docs/<parent>).
    source_dir = Path("docs") / Path(doc_filename).parent

    def repl(m):
        href = m.group(1)
        if "://" in href or href.startswith(("/", "#", "mailto:")):
            return m.group(0)
        path_part, _, anchor = href.partition("#")
        is_md = path_part.lower().endswith(".md")
        # Process .md links anywhere, plus any explicit relative link
        # (../deploy/..., ../.miren/app.toml) — those are repo references.
        if not is_md and not path_part.startswith(("./", "../")):
            return m.group(0)
        slug = _MD_BASENAME_TO_SLUG.get(Path(path_part).name.lower()) if is_md else None
        if slug:
            new = f"/docs/{slug}/" + (f"#{anchor}" if anchor else "")
            return f'href="{new}"'
        resolved = os.path.normpath(str(source_dir / path_part))
        # Anything that resolves inside the repo → GitHub blob URL. (Can't
        # check existence here: the deployed site only ships docs/, not the
        # full repo. test_docs_links verifies targets locally.)
        if not resolved.startswith(".."):
            new = GITHUB_BLOB_BASE + resolved + (f"#{anchor}" if anchor else "")
            return f'href="{new}"'
        return m.group(0)

    return re.sub(_HREF_RE, repl, html)


# ── Routes ────────────────────────────────────────────────────────


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/connect/")
def connect():
    return render_template("connect.html")


@app.route("/sdk/")
def sdk():
    return render_template("sdk.html")


@app.route("/agents/")
def agents():
    return render_template("agents.html")


@app.route("/protocol/")
def protocol():
    return render_template("protocol.html")


@app.route("/clients/")
def clients():
    return render_template("clients.html")


def _blog_posts():
    """All posts, newest first: [{slug, title, date}]. Date = first *YYYY-MM-DD* line."""
    import re
    posts = []
    if not BLOG_DIR.exists():
        return posts
    for f in BLOG_DIR.glob("*.md"):
        text = f.read_text()
        title = next((l[2:].strip() for l in text.splitlines() if l.startswith("# ")), f.stem)
        m = re.search(r"\*(\d{4}-\d{2}-\d{2})\*", text)
        posts.append({"slug": f.stem, "title": title, "date": m.group(1) if m else ""})
    posts.sort(key=lambda p: p["date"], reverse=True)
    return posts


def _atproto_posts():
    """Posts from AT Protocol, or [] if unavailable/unconfigured."""
    try:
        return BLOG_SOURCE.posts()
    except Exception:
        return []


def _merged_posts():
    """
    Every post, newest first, from both sources.

    Posts live in two places during (and after) the move to Leaflet: AT Protocol
    records and the older blog/*.md files. Showing only one source would make
    the other's posts vanish from the index the moment the first Leaflet post
    went up, so they are merged. On a slug collision the AT Protocol record wins:
    if a file post has been migrated, the record is the canonical copy.
    """
    entries = []
    seen = set()
    # Defensive: a fault anywhere in the AT Protocol path must degrade to the
    # local posts, never 500 the blog index.
    try:
        remote = _atproto_posts()
    except Exception:
        remote = []
    for p in remote:
        seen.add(p.slug)
        entries.append(
            {"slug": p.slug, "title": p.title, "date": p.date,
             "description": p.description, "atproto": True}
        )
    for p in _blog_posts():
        if p["slug"] in seen:
            continue
        entries.append({**p, "description": p.get("description", ""), "atproto": False})
    entries.sort(key=lambda e: e["date"], reverse=True)
    return entries


@app.route("/blog/")
def blog_index():
    posts = _merged_posts()
    return render_template(
        "blog_index.html",
        posts=posts,
        from_atproto=any(p.get("atproto") for p in posts),
        publication_url=BLOG_PUBLICATION,
    )


@app.route("/blog/<slug>/")
def blog_post(slug):
    if ".." in slug or "/" in slug:
        abort(404)
    post = None
    try:
        post = BLOG_SOURCE.post(slug)
    except Exception:
        post = None
    if post is not None:
        return render_template("blog_post_atproto.html", post=post, did=BLOG_DID)
    filepath = BLOG_DIR / f"{slug}.md"
    if not filepath.exists():
        abort(404)
    return render_template("blog_post.html", doc=render_md(filepath))


def _feed_posts():
    """Feed entries: both sources, newest first."""
    return _merged_posts()


@app.route("/blog/feed.xml")
def blog_feed():
    items = "".join(
        f"<item><title>{p['title']}</title>"
        f"<link>https://freeq.at/blog/{p['slug']}/</link>"
        f"<guid>https://freeq.at/blog/{p['slug']}/</guid>"
        f"<pubDate>{p['date']}</pubDate></item>"
        for p in _feed_posts()
    )
    rss = (
        '<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel>'
        "<title>freeq blog</title><link>https://freeq.at/blog/</link>"
        "<description>Engineering notes from the freeq project</description>"
        f"{items}</channel></rss>"
    )
    return rss, 200, {"Content-Type": "application/rss+xml"}


@app.route("/about/")
def about():
    return render_template("about.html")


@app.route("/version")
def version():
    return jsonify({"service": "freeq-site", "git_commit": GIT_COMMIT})


@app.route("/docs/")
def docs_index():
    return render_template("docs_index.html")


@app.route("/docs/<path:slug>/")
def docs_page(slug):
    """Render a doc page from either site or repo docs."""
    entry = SLUG_MAP.get(slug)
    if not entry:
        abort(404)
    source, filename = entry
    if source == "site":
        filepath = SITE_DOCS_DIR / filename
    else:
        filepath = REPO_DOCS_DIR / filename
    if not filepath.exists():
        # Return helpful 404 with debug info
        import json
        info = {
            "slug": slug,
            "source": source,
            "filename": filename,
            "filepath": str(filepath),
            "exists": filepath.exists(),
            "site_docs_dir": str(SITE_DOCS_DIR),
            "site_docs_exists": SITE_DOCS_DIR.exists(),
            "site_docs_files": sorted(f.name for f in SITE_DOCS_DIR.iterdir()) if SITE_DOCS_DIR.exists() else [],
        }
        return f"<pre>Doc not found:\n{json.dumps(info, indent=2)}</pre>", 404
    doc = render_md(filepath)
    doc["html"] = rewrite_links(doc["html"], filename)
    return render_template("doc_page.html", doc=doc)


@app.route("/debug/docs")
def debug_docs():
    import json
    result = {
        "site_docs_dir": str(SITE_DOCS_DIR),
        "site_docs_exists": SITE_DOCS_DIR.exists(),
        "site_docs_files": sorted(f.name for f in SITE_DOCS_DIR.iterdir()) if SITE_DOCS_DIR.exists() else [],
        "repo_docs_dir": str(REPO_DOCS_DIR),
        "repo_docs_exists": REPO_DOCS_DIR.exists(),
        "app_file": str(Path(__file__)),
        "cwd": str(Path.cwd()),
    }
    return json.dumps(result, indent=2), 200, {"Content-Type": "application/json"}


@app.route("/.well-known/<path:filename>")
def well_known(filename):
    return send_from_directory(Path(__file__).parent / ".well-known", filename)


@app.route("/favicon.ico")
def favicon():
    return "", 204


if __name__ == "__main__":
    app.run(debug=True, port=8000)
