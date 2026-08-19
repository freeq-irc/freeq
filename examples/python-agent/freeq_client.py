#!/usr/bin/env python3
"""
A freeq client in about ninety lines, with no SDK.

Mints an ed25519 keypair, turns the public half into a `did:key`, authenticates
with SASL `ATPROTO-CHALLENGE`, and prints every byte in both directions. The
point is that participating in freeq — as a person or as an agent — needs
nothing but a socket and a signature.

    pip install cryptography
    python3 freeq_client.py 127.0.0.1 6889

The private key lives for the length of the process. A real agent keeps one on
disk (see `freeq-bot-kit-js`, which stores it at ~/.freeq/bots/<name>/agent.key).
"""
import base64
import json
import socket
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58btc(data: bytes) -> str:
    """base58btc, the encoding did:key uses."""
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Client:
    """One connection. `echo=True` prints the wire, which is the whole point."""

    def __init__(self, host, port, nick, echo=True):
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        # multicodec ed25519-pub (0xed 0x01) + the raw key, base58btc, 'z' prefix
        self.did = "did:key:z" + b58btc(b"\xed\x01" + pub)
        self.nick, self.echo = nick, echo
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(2.0)
        self.buf = b""

    def tx(self, line):
        if self.echo:
            print(f"→ {line}")
        self.sock.sendall((line + "\r\n").encode())

    def rx(self, secs=1.5):
        """Read for `secs`, answering PINGs, returning the lines seen."""
        end, got = time.time() + secs, []
        while time.time() < end:
            try:
                chunk = self.sock.recv(65536)
                if not chunk:
                    break
                self.buf += chunk
            except socket.timeout:
                pass
            while b"\r\n" in self.buf:
                raw, self.buf = self.buf.split(b"\r\n", 1)
                line = raw.decode("utf-8", "replace")
                if line.startswith("PING"):
                    self.tx("PONG " + line.split(" ", 1)[1])
                    continue
                if self.echo:
                    print(f"← {line}")
                got.append(line)
        return got

    def login(self):
        """SASL ATPROTO-CHALLENGE: the server names a challenge, we sign it."""
        self.tx("CAP LS 302")
        self.rx(1.5)
        self.tx("CAP REQ :sasl message-tags")
        self.rx(1.0)
        self.tx("AUTHENTICATE ATPROTO-CHALLENGE")
        challenge = None
        for line in self.rx(2.0):
            if line.startswith("AUTHENTICATE "):
                challenge = line.split(" ", 1)[1].strip()
        if not challenge or challenge == "+":
            raise SystemExit("the server issued no challenge")
        # Sign the exact bytes the server sent — not a re-serialization of them.
        signature = b64u(self.key.sign(unb64u(challenge)))
        self.tx("AUTHENTICATE " + b64u(
            json.dumps({"did": self.did, "signature": signature}).encode()))
        self.rx(2.0)
        self.tx(f"NICK {self.nick}")
        self.tx(f"USER {self.nick} 0 * :{self.nick}")
        self.tx("CAP END")
        self.rx(2.0)
        return self


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 6889
    client = Client(host, port, "probe").login()
    print("\nDID:", client.did)
