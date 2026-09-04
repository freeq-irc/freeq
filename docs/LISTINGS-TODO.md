# Listings and publishing — what is left, and why it needs a person

Everything here is blocked on an account or a browser, not on code. Each item
says exactly what to click, so it can be done in one sitting.

Status as of 2026-09-04.

## 1. npm publish (#88)

**Not blocked on login.** `npm whoami` returns `chadfowler`, and both packages
produce clean tarballs:

| package | version | files | size |
|---|---|---|---|
| `@freeq/bot-kit` | 0.1.0 | 55 | 76 kB |
| `@freeq/pi` | 0.1.0 | 87 | 153 kB |

**Blocked on:** the `@freeq` scope does not exist on npm. A scoped package can
only be published to a scope you own, and npm auto-creates only your own
username scope (`@chadfowler`). An organisation scope must be created first.

**To do:** create the `freeq` org at <https://www.npmjs.com/org/create> (free
for public packages), then:

```
cd freeq-sdk-js     && npm publish --access public
cd freeq-bot-kit-js && npm publish --access public
cd freeq-mcp        && npm publish --access public
cd freeq-pi         && npm publish --access public
```

Order matters: `@freeq/pi` and `@freeq/mcp` depend on `@freeq/bot-kit`, which
depends on `@freeq/sdk`. The `file:../` dependencies must be changed to version
ranges before publishing, or the tarballs will reference paths that do not
exist on a consumer's machine.

**Decide first:** publishing a name is close to irreversible — unpublish is
allowed for 72 hours and never for a name someone else has since depended on.
`0.1.0` is the version that will exist forever.

## 2. Glama listing, and the awesome-mcp-servers PR (#89)

PR [punkpeye/awesome-mcp-servers#13577](https://github.com/punkpeye/awesome-mcp-servers/pull/13577)
is **open, mergeable, and gated on one bot comment**. It asks for two things:

1. The server listed at <https://glama.ai/mcp/servers>, passing checks. Glama
   builds a Dockerfile you supply *on Glama* and requires only that the server
   starts and answers an introspection request.
2. A score badge appended to the PR entry:

   ```
   [![freeq-irc/freeq MCP server](https://glama.ai/mcp/servers/freeq-irc/freeq/badges/score.svg)](https://glama.ai/mcp/servers/freeq-irc/freeq)
   ```

**Prepared for you:** `freeq-mcp/Dockerfile` builds the stdio server from the
repo root (it needs the two sibling workspaces, so build context is the root:
`docker build -f freeq-mcp/Dockerfile -t freeq-mcp .`).

Verified locally that introspection needs no credentials — the server answers
`initialize` and `tools/list` before any freeq connection is opened, which is
the whole of what Glama checks:

```
$ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize",...}' \
                '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | node dist/index.js
{"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"freeq",...
```

**Not verified:** the image build itself. Docker is not installed on this
machine, so the Dockerfile is reasoned, not run. Build it once before pointing
Glama at it.

## 3. skills.sh listing (#89)

Account-gated. Nothing to prepare.

---

## Why these are not done automatically

Publishing a package name, creating an organisation and submitting a project to
a third-party directory are all public, irreversible, and made in your name.
An agent should prepare them and stop.
