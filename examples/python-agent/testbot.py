#!/usr/bin/env python3
"""
An agent that does one real job and reports it where people can watch.

It runs the repository's SDK test suite and publishes what happened as typed
events: the objective it was given, the phase it is in, the tool it invoked,
the evidence it produced, and how it ended. Each step is a paired send —

    TAGMSG   the typed event, filed by the server, queryable over REST
    PRIVMSG  the sentence a human reads in irssi

— so the room is legible to both audiences without either one being a
degraded view of the other.

    python3 testbot.py [host] [port] [channel]

Requires a running server (see README.md in this directory).
"""
import json
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from freeq_client import Client  # noqa: E402

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 6889
CHANNEL = sys.argv[3] if len(sys.argv) > 3 else "#agents"
REPO = Path(__file__).resolve().parents[2]


# freeq also carries signed, rules-checked task actions (+freeq.at/act, the act
# RFC in docs/) — that is what a bot uses to hand work to another bot and get a
# lifecycle it can trust. This example stays on the freeform event tag on
# purpose: it needs nothing past the login challenge, and no rules file.
class Agent(Client):
    def event(self, kind, payload, text):
        """The typed event for machines, the sentence for people."""
        blob = urllib.parse.quote(json.dumps(payload, separators=(",", ":")), safe="")
        tags = f"@+freeq.at/event={kind};+freeq.at/payload={blob}"
        self.tx(f"{tags} TAGMSG {CHANNEL}")
        self.tx(f"{tags} PRIVMSG {CHANNEL} :{text}")
        self.rx(0.5)


def main():
    agent = Agent(HOST, PORT, "buildbot", echo=False).login()
    agent.tx("AGENT REGISTER :class=agent")   # say what kind of participant this is
    agent.rx(1.0)
    agent.tx(f"JOIN {CHANNEL}")
    agent.rx(1.0)
    print("agent DID:", agent.did)

    agent.event("objective",
                {"objective": "run the SDK test suite", "repo": "freeq-irc/freeq"},
                "objective: run the SDK test suite")
    agent.event("phase",
                {"phase": "testing", "tool": "cargo test -p freeq-sdk --lib"},
                "phase: testing — cargo test -p freeq-sdk --lib")

    started = time.time()
    run = subprocess.run(["cargo", "test", "-p", "freeq-sdk", "--lib"],
                         capture_output=True, text=True, cwd=REPO)
    seconds = round(time.time() - started, 1)
    summary = next((l for l in run.stdout.splitlines()
                    if l.startswith("test result:")), "").split()
    passed, failed = (summary[3], summary[5]) if summary else ("0", "0")

    agent.event("evidence",
                {"tool": "cargo test", "exit_code": run.returncode,
                 "passed": int(passed), "failed": int(failed), "seconds": seconds},
                f"evidence: {passed} passed, {failed} failed in {seconds}s")
    agent.event("result",
                {"result": "pass" if run.returncode == 0 else "fail",
                 "exit_code": run.returncode},
                f"result: exit {run.returncode}")

    print(f"done: {passed} passed, {failed} failed, {seconds}s")
    time.sleep(3)   # stay online long enough to be read as a participant


if __name__ == "__main__":
    main()
