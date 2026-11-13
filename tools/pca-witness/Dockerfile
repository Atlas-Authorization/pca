# syntax=docker/dockerfile:1
# pca-witness: the reference transparency-log witness in a minimal container.
#
#   docker build -f tools/pca-witness/Dockerfile -t pca-witness .        (from the repository root)
#
# Stage 1 bundles the witness and the PCA library into ONE JavaScript file; stage 2 is a distroless Node runtime that holds that
# file and nothing else: no shell, no package manager, runs as an unprivileged user, no network client of its own.
FROM node:22-alpine AS build
WORKDIR /src
RUN npm install --prefix /tmp/bundler --no-audit --no-fund --ignore-scripts \
      esbuild@0.24.2 @noble/curves@1.9.1 @noble/hashes@1.8.0 @noble/post-quantum@0.4.1 @scure/base@1.2.6 bignumber.js@9.3.1
COPY packages/pca/src ./packages/pca/src
COPY packages/pca-verified-core ./packages/pca-verified-core
COPY tools/pca-witness/src ./tools/pca-witness/src
ENV NODE_PATH=/tmp/bundler/node_modules
RUN /tmp/bundler/node_modules/.bin/esbuild tools/pca-witness/src/main.ts \
      --bundle --tsconfig-raw='{}' --platform=node --target=node22 --format=cjs --legal-comments=none \
      --alias:@atlasauth/pca=./packages/pca/src/index.ts \
      --alias:@atlasauth/pca/durable-state=./packages/pca/src/durable-state.ts \
      --alias:@atlasauth/pca/ext/ledger=./packages/pca/src/ext/ledger.ts \
      --alias:@atlasauth/pca-verified-core=./packages/pca-verified-core/src/index.ts \
      --external:@atlasauth/pca-fndsa-wasm --external:@atlasauth/pca-less-wasm \
      --outfile=/out/witness.js \
 && mkdir -p /out/state && chown 65532:65532 /out/state && chmod 700 /out/state

FROM gcr.io/distroless/nodejs22-debian12:nonroot
COPY --from=build /out/witness.js /witness.js
COPY --from=build --chown=65532:65532 /out/state /var/lib/witness
VOLUME /var/lib/witness
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
ENTRYPOINT ["/nodejs/bin/node", "/witness.js"]
CMD ["serve", "--key", "/etc/pca-witness/key", "--logs", "/etc/pca-witness/logs.json", "--state", "/var/lib/witness"]
