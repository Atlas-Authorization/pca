# Changelog

## 0.5.0

- `--connect` follows the agreed contract: events are reported under the source the server returns, the ingest key is ingest-only, a lost reply is retried with the same token and key, and the instance's grant signer is saved.
- `--enforce --grant FILE`: enforce with an issued grant verified under the pinned signer (a tampered grant or the wrong signer is refused, at init and at every start); `--observe` switches back; idempotent.
- `--include-params`: observed parameters travel to the control plane with the proxy's rules and digest binding.

- Verbs: the wiring resolves each request through `pca.routes.json` (written from the imported action definitions) with pca-proxy's own matcher; unmapped routes are logged as unmapped in observe mode and denied in enforce mode.
- `--connect <token>`: register a locally generated source key with the control plane and report observed events from the wiring.

- First release. `pca init`: detect the project (language, framework, agent frameworks, MCP servers), show the plan as a diff, and with `--yes` add the PCA package, the wiring (a generated module plus one import and one registration line, edited with the TypeScript compiler, for Express, Fastify, Hono, NestJS and Next.js; the exact snippet and location for every other language), a gitignored dev key, an observe-mode `pca.init.json` and draft actions from an OpenAPI file, an MCP tool list or the route table.
- Safe by construction: dry run unless `--yes`; refuses a dirty git tree without `--force`; refuses to write a key into a tracked path or one git would not ignore; never overwrites a key, an action file or an edited wiring file; idempotent.
- `pca init --proxy`: a validated pca-proxy config in front of your MCP servers or HTTP service, and the one command that runs it.
- `pca init --mode enforce` (needs the signed grant) and `pca init --check` (package, registration, config, key safety, mode; the doctor for the live parts).
