# One image for every service in the box (the proxy, the sample API, the sample MCP server and agent, the dashboard, the
# directory log and witness, the autopilot tools), built from this repository's own source. Build context: the repository root.
#   docker build -f packages/pca-proxy/deploy/pca-in-a-box/Dockerfile -t pca-box .
# (docker compose does it for you: see compose.yaml)
FROM node:22-bookworm-slim
ENV CI=true NODE_ENV=development
RUN corepack enable
WORKDIR /repo
COPY . .
RUN pnpm install --frozen-lockfile \
      --filter=@atlasauth/pca-proxy... --filter=@atlasauth/pca-cli... --filter=@atlasauth/pca-directory...
RUN pnpm -r --filter=@atlasauth/pca-proxy... --filter=@atlasauth/pca-cli... --filter=@atlasauth/pca-directory... run build
RUN set -e; \
    for b in "pca-proxy packages/pca-proxy/dist/cli.js" "pca packages/pca-cli/dist/cli.js" \
             "pca-directory-log packages/pca-directory/dist/bin-log.js" "pca-directory-witness packages/pca-directory/dist/bin-witness.js"; do \
      set -- $b; test -f "/repo/$2"; printf '#!/bin/sh\nexec node /repo/%s "$@"\n' "$2" > "/usr/local/bin/$1"; chmod +x "/usr/local/bin/$1"; \
    done
COPY packages/pca-proxy/deploy/pca-in-a-box /box
ENV NODE_ENV=production
WORKDIR /box
