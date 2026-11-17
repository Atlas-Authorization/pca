# pca-proxy image: the HTTP reverse proxy (or any pca-proxy command) from the published package.
#   docker build -f deploy/Dockerfile -t pca-proxy .
#   docker run --rm -p 8788:8788 -v "$PWD/pca-proxy.yaml:/etc/pca-proxy/pca-proxy.yaml:ro" -e UPSTREAM_TOKEN pca-proxy
FROM node:22-alpine AS build
ARG PCA_PROXY_VERSION=0.5.0
WORKDIR /opt/pca-proxy
RUN npm install --omit=dev --no-audit --no-fund @atlasauth/pca-proxy@${PCA_PROXY_VERSION} @opentelemetry/api@1.9.0

FROM node:22-alpine
ENV NODE_ENV=production
COPY --from=build /opt/pca-proxy /opt/pca-proxy
WORKDIR /opt/pca-proxy
# state the proxy writes (audit log, approvals): mount a volume here if you want it to survive the container
RUN mkdir -p /var/lib/pca-proxy && chown node:node /var/lib/pca-proxy
USER node
EXPOSE 8788
VOLUME ["/var/lib/pca-proxy"]
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s CMD node -e "require('net').connect(8788,'127.0.0.1').on('connect',()=>process.exit(0)).on('error',()=>process.exit(1))"
ENTRYPOINT ["node", "/opt/pca-proxy/node_modules/@atlasauth/pca-proxy/dist/cli.js"]
CMD ["http", "--config", "/etc/pca-proxy/pca-proxy.yaml"]
