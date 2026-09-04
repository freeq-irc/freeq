# A container for the freeq MCP server.
#
# This exists for directory listings (Glama, and through it awesome-mcp-servers)
# which build the image and check that the server starts and answers an
# introspection request. It is a legitimate way to run the server too, but the
# usual route is `npx -y @freeq/mcp`, and the hosted remote server at
# https://irc.freeq.at/mcp needs no install at all.
#
# Built from the repo root, because the package depends on two sibling
# workspaces by file: path:
#
#     docker build -f freeq-mcp/Dockerfile -t freeq-mcp .

FROM node:20-slim AS build

WORKDIR /src

# The three workspaces this server is assembled from. Copied separately so a
# change to the MCP layer alone does not invalidate the SDK build cache.
COPY freeq-sdk-js/ freeq-sdk-js/
COPY freeq-bot-kit-js/ freeq-bot-kit-js/
COPY freeq-mcp/ freeq-mcp/

# `dist/` is gitignored in all three, so every layer is built here rather than
# trusted to be present — the same trap that made CI fail until the SDK build
# step was added.
WORKDIR /src/freeq-sdk-js
RUN npm ci --ignore-scripts && npm run build

WORKDIR /src/freeq-bot-kit-js
RUN npm ci --ignore-scripts && npm run build

WORKDIR /src/freeq-mcp
RUN npm ci --ignore-scripts && npm run build

# ── Runtime ──
FROM node:20-slim

# Introspection needs no credentials: tools/list is answered before any
# freeq connection is opened. Configuration arrives by environment when the
# server is actually used (see freeq-mcp/README.md).
ENV NODE_ENV=production

WORKDIR /app
COPY --from=build /src/freeq-sdk-js /app/freeq-sdk-js
COPY --from=build /src/freeq-bot-kit-js /app/freeq-bot-kit-js
COPY --from=build /src/freeq-mcp /app/freeq-mcp

# Nothing here needs root, and an MCP server that reads a config file should
# not be able to write one.
USER node

WORKDIR /app/freeq-mcp

# stdio transport: the client speaks JSON-RPC on stdin/stdout.
ENTRYPOINT ["node", "dist/index.js"]
