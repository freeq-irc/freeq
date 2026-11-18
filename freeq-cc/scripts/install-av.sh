#!/usr/bin/env bash
# Build the freeq voice bridge (freeq-claude-mcp) and put it where the
# plugin's `av` server looks for it: ~/.freeq/cc/bin. Run from anywhere in a
# clone of the freeq repository. Needs cargo (Rust 1.85+).
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
cargo build --release -p freeq-claude-mcp
mkdir -p "$HOME/.freeq/cc/bin"
install -m 0755 "target/release/freeq-claude-mcp" "$HOME/.freeq/cc/bin/freeq-claude-mcp"
echo "freeq voice bridge installed: $HOME/.freeq/cc/bin/freeq-claude-mcp"
echo "Restart Claude Code; set GROQ_API_KEY and ELEVENLABS_API_KEY for speech."
