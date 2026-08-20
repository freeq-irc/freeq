#!/usr/bin/env python3
"""
Publish a markdown draft to a Leaflet / Standard-Sites publication.

    # inspect the record without writing anything (default)
    python3 freeq-site/publish.py drafts/what-is-freeq.md

    # actually write it
    python3 freeq-site/publish.py drafts/what-is-freeq.md --write

Credentials come from 1Password so nothing lands in a file or the shell history:

    --op-item <id>       1Password item holding the account password
    --identifier <h>     handle to authenticate as (default: freeq.at)

The record is written to the AUTHENTICATED account's repo, which is how AT
Protocol works: you can only write to your own. A collaborator's post therefore
lives in their repo with `site` pointing at the owner's publication, and readers
merge across contributing repos (see atproto_blog.BlogSource).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import atproto_blog  # noqa: E402
import leaflet_publish as lp  # noqa: E402

PUBLICATION = "at://did:plc:4qsyxmnsblo4luuycm3572bq/site.standard.publication/3mri2ajri7c2w"
DEFAULT_IDENTIFIER = "freeq.at"
DEFAULT_OP_ITEM = "ztqgknc3wo3za45mntn4xdm7fu"
B32 = "234567abcdefghijklmnopqrstuvwxyz"


def make_tid(clock_id: int = 17) -> str:
    """
    A TID record key, the same shape Leaflet uses ("3mri2ajri7c2w").

    64 bits: a 0 top bit, 53 bits of microseconds since the epoch, 10 bits of
    clock id; encoded big-endian in base32-sortable, 13 characters. Sortable by
    creation time, which is what makes repo listings chronological.
    """
    micros = int(time.time() * 1_000_000)
    n = ((micros & ((1 << 53) - 1)) << 10) | (clock_id & 0x3FF)
    out = []
    for i in range(13):
        out.append(B32[(n >> (60 - i * 5)) & 0x1F])
    return "".join(out)


def op_password(item: str) -> str:
    r = subprocess.run(
        ["op", "item", "get", item, "--fields", "password", "--reveal"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise SystemExit(f"1Password read failed: {r.stderr.strip()}")
    return r.stdout.strip()


def xrpc(url: str, body: dict | None = None, token: str | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{url.rsplit('/', 1)[-1]} failed: {e.code} {e.read().decode()[:300]}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("draft", nargs="?", help="markdown file")
    ap.add_argument("--delete", metavar="RKEY",
                    help="delete a document record instead of publishing")
    ap.add_argument("--update", metavar="RKEY",
                    help="replace an already-published record with this draft, "
                         "keeping its rkey (so the URL survives) and its "
                         "original publishedAt (so the date does not move)")
    ap.add_argument("--write", action="store_true", help="actually create the record")
    ap.add_argument("--publication", default=PUBLICATION)
    ap.add_argument("--identifier", default=DEFAULT_IDENTIFIER)
    ap.add_argument("--op-item", default=DEFAULT_OP_ITEM)
    ap.add_argument("--tags", default="freeq")
    ap.add_argument("--pds", default="https://bsky.social")
    args = ap.parse_args()

    if args.delete:
        pw = op_password(args.op_item)
        session = xrpc(
            f"{args.pds}/xrpc/com.atproto.server.createSession",
            {"identifier": args.identifier, "password": pw},
        )
        did, token = session["did"], session["accessJwt"]
        if not args.write:
            print(f"DRY RUN — would delete {lp.DOC_TYPE}/{args.delete} from {did}")
            return 0
        xrpc(
            f"{args.pds}/xrpc/com.atproto.repo.deleteRecord",
            {"repo": did, "collection": lp.DOC_TYPE, "rkey": args.delete},
            token=token,
        )
        print(f"deleted at://{did}/{lp.DOC_TYPE}/{args.delete}")
        return 0

    if not args.draft:
        raise SystemExit("need a draft file (or --delete RKEY)")
    md = pathlib.Path(args.draft).read_text()
    rkey = args.update or make_tid()
    tags = [t.strip() for t in args.tags.split(",") if t.strip()]
    value = lp.build_document(md, publication=args.publication, tags=tags, rkey=rkey)

    blocks = value["content"]["pages"][0]["blocks"]
    kinds: dict[str, int] = {}
    for b in blocks:
        k = b["block"]["$type"].rsplit(".", 1)[-1]
        kinds[k] = kinds.get(k, 0) + 1
    facets = sum(len(b["block"].get("facets") or []) for b in blocks)

    print(f"draft       {args.draft}")
    print(f"title       {value['title']}")
    print(f"description {value['description'][:90]}")
    print(f"publication {args.publication}")
    print(f"rkey        {rkey}")
    print(f"publishedAt {value['publishedAt']}")
    print(f"tags        {tags}")
    print(f"blocks      {sum(kinds.values())}  {kinds}")
    print(f"facets      {facets}")

    if not args.write:
        print("\nDRY RUN — nothing written. Re-run with --write to publish.")
        return 0

    pw = op_password(args.op_item)
    session = xrpc(
        f"{args.pds}/xrpc/com.atproto.server.createSession",
        {"identifier": args.identifier, "password": pw},
    )
    did, token = session["did"], session["accessJwt"]
    print(f"\nauthenticated as {session.get('handle')} ({did})")

    if args.update:
        # An edit is a replacement at the same key. Keep the original
        # publishedAt: the post is being corrected, not re-dated, and readers
        # sort by that field.
        existing = xrpc(
            f"{args.pds}/xrpc/com.atproto.repo.getRecord"
            f"?repo={did}&collection={lp.DOC_TYPE}&rkey={rkey}"
        )
        first_published = existing.get("value", {}).get("publishedAt")
        if first_published:
            value["publishedAt"] = first_published
            print(f"keeping publishedAt {first_published}")

    verb = "putRecord" if args.update else "createRecord"
    created = xrpc(
        f"{args.pds}/xrpc/com.atproto.repo.{verb}",
        {
            "repo": did,
            "collection": lp.DOC_TYPE,
            "rkey": rkey,
            "record": value,
        },
        token=token,
    )
    print(f"{'updated' if args.update else 'created'} {created['uri']}")
    print(f"cid     {created.get('cid')}")
    # The permalink readers get. Leaflet only serves documents in repos it
    # knows about, so a post written to a collaborator's repo has no
    # leaflet.pub page — which is the point of reading straight from the PDS.
    print(f"\nLive:     https://freeq.at/blog/{atproto_blog.slugify(value['title'])}")
    print("To remove:")
    print(
        f"  com.atproto.repo.deleteRecord repo={did} "
        f"collection={lp.DOC_TYPE} rkey={rkey}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
