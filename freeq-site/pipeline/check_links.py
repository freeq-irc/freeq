#!/usr/bin/env python3
"""Link gate for freeq launch posts.

"Nothing described as available unless it is actually deployed." A post that
links to a URL which does not resolve is the most embarrassing possible version
of that failure — the reader clicks the one thing you told them to open, on the
day you told the whole internet to look. This gate fetches every http(s) link in
the post and fails on anything that doesn't answer.

Also checks the IRC endpoint if the post tells readers to /connect somewhere:
a dead port is the same failure wearing a different hat.

Usage: python3 check_links.py blog/post.md [more.md ...]
"""
import re
import socket
import subprocess
import sys

URL_RE = re.compile(r"https?://[^\s)\]<>\"'`]+")
CONNECT_RE = re.compile(r"/connect\s+([a-z0-9.-]+)\s+(\d{2,5})", re.I)

# A URL written as `url=<...>` is a value a server stores, not a link a reader
# clicks: the credential endpoint in a channel policy, for instance, is a
# template a client completes with the subject's DID before fetching it, so it
# answers 4xx on its own. Those are checked for a live host rather than a 2xx,
# which keeps the gate strict about everything a reader can actually click.
CONFIG_URL_RE = re.compile(r"url=(https?://[^\s)\]<>\"'`]+)")


def check_url(url: str, timeout: int = 12):
    url = url.rstrip(".,;:")
    try:
        out = subprocess.run(
            ["curl", "-sS", "-L", "-m", str(timeout), "-o", "/dev/null",
             "-w", "%{http_code}", url],
            capture_output=True, text=True, timeout=timeout + 5)
        code = (out.stdout or "").strip()
        return (code.isdigit() and 200 <= int(code) < 400), code or "no-response"
    except Exception as e:
        return False, f"error: {type(e).__name__}"


def check_port(host: str, port: int, timeout: int = 8):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def main() -> int:
    files = sys.argv[1:]
    fails = 0
    for f in files:
        text = open(f).read()
        config = set(CONFIG_URL_RE.findall(text))
        urls = sorted(set(URL_RE.findall(text)) - config)
        print(f"=== {f} ===")
        for u in urls:
            ok, code = check_url(u)
            print(f"  [{'x' if ok else ' '}] {u}  ({code})")
            if not ok:
                fails += 1
        for u in sorted(config):
            host = u.split("/")[2].split(":")[0]
            ok = check_port(host, 443 if u.startswith("https") else 80)
            print(f"  [{'x' if ok else ' '}] {u}  "
                  f"(config value; host {'reachable' if ok else 'NOT reachable'})")
            if not ok:
                fails += 1
        for host, port in set(CONNECT_RE.findall(text)):
            ok = check_port(host, int(port))
            print(f"  [{'x' if ok else ' '}] irc {host}:{port}  "
                  f"({'reachable' if ok else 'NOT reachable from here'})")
            if not ok:
                fails += 1
        if not urls:
            print("  (no links)")
        print()
    if fails:
        print(f"FAIL: {fails} link/endpoint(s) not reachable. "
              f"Readers will click these on launch day.")
        return 1
    print(f"OK: every link and endpoint resolves in {len(files)} file(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
