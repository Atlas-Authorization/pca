# Adding PCA (Proof-Carrying Authority) to a project

PCA makes an AI agent prove, on every tool call, that a human authorized that exact action within exact limits. The
server (or a proxy in front of it) verifies the proof and allows or refuses. Use it when the user asks to "add PCA",
"add agent authorization", "protect this MCP server", "protect this API from agents", "stop my agent doing X without
approval", or to explain a PCA refusal.

## First, ask the tools, do not guess

If the `pca` MCP server is available (`pca-dev-mcp`), use it:

1. `pca_detect` - what the project is and which integration fits.
2. `pca_plan_integration` - the exact edits and commands, as steps. Apply them yourself; the server only plans.
3. `pca_docs_search` - the PCA docs, offline, for anything the plan does not cover.
4. `pca_explain` - paste a refusal reason or a PCActn to get what it means and the fix.
5. `pca_lint_policy`, `pca_simulate` - check a policy before it is signed; `pca_actions_import` - draft actions from an
   OpenAPI document or an MCP tool list; `pca_doctor` - check a deployment.

Without the MCP server, read the plan below and the PCA docs (docs/pca/guides/five-minute-quickstart.md,
framework-recipes.md, mcp-quickstart.md).

## Pick the integration

| The project is | Use | Code change |
|---|---|---|
| an MCP server (or the user wants to protect MCP tools an agent uses) | `pca-proxy mcp` in front of it | none |
| an HTTP API with an OpenAPI document | `pca-proxy http` as a sidecar or gateway | none |
| an HTTP API without OpenAPI, or one that must verify proofs itself | the guard for its framework (below) | a few lines per route |
| an agent that calls tools | a proxy per tool server; the SDK only if the agent delegates to sub-agents | none or small |

## Recipe: MCP server or API behind the proxy (any language)

```sh
npx -y @atlasauth/pca-proxy mcp --observe --audit ./pca.audit.jsonl -- <the command that starts the server>
npx -y @atlasauth/pca-proxy init mcp --ns <name> --out pca-proxy.yaml -- <the same command>
```

For an HTTP API: write `pca-proxy.yaml` with `mode: observe`, `http.upstream`, `http.openapi` and one entry per operation
under `http.actions`, then `npx -y @atlasauth/pca-proxy http --config pca-proxy.yaml --observe`.
Point the MCP client (or the agent's base URL) at the proxy. Then:

```sh
npx @atlasauth/pca-cli autopilot observe ./pca.audit.jsonl --out autopilot.traces.json
npx @atlasauth/pca-cli autopilot propose autopilot.traces.json --out autopilot.proposal.json
npx @atlasauth/pca-cli autopilot verify  autopilot.proposal.json autopilot.traces.json --out autopilot.report.json
npx @atlasauth/pca-cli autopilot review  autopilot.proposal.json autopilot.report.json
```

The human reads the review and signs it (`--reviewer-key ... --yes`). Then set `mode: enforce`.

## Recipe: guard in the server's own code

Every language has one guard that takes the same four inputs: `audience` (this server's id), a grant lookup (the
principal's signed grant, from YOUR store), a replay store plus revocation source, and the operation (verb, resource,
params) taken from your routing, never from the proof. The agent sends the proof in the `PCA-Action` header (base64url)
or as a JSON body `{ "pcactn": ... }`.

- TypeScript (Express, Fastify, Hono, Next): `npm i @atlasauth/pca @atlasauth/pca-express` (or `-fastify`, `-hono`, `-next`);
  `const server = protect({ audience, grants, operation })` then `app.post('/route', pcaExpress(server.options), handler)`.
- Python (FastAPI, Flask, Django): `pip install atlas-pca`; `RequirePCA(audience=..., resolve_grant=..., authorize=AuthorizeOptions(...), operation=...)` as a FastAPI dependency; Django uses settings `PCA_AUTHORIZE`, `PCA_OPERATION`.
- Go (net/http, chi, Gin): `go get github.com/Atlas-Authorization/pca-go`; `pca.RequirePCA(pca.RequirePCAOptions{...})` wraps an `http.Handler`.
- Rust (axum), Ruby (Rails, Rack), PHP (Laravel, PSR-15), Java/Kotlin (Spring, Ktor), .NET (ASP.NET Core), Swift (Vapor,
  Hummingbird): see docs/pca/guides/framework-recipes.md (or `pca_docs_search "framework recipes <framework>"`).

Guard every route that changes something or reads sensitive data. An unguarded route is open; a guarded route without a
valid proof is refused.

## Security rules (do not break these)

- Default deny. Anything not mapped to an action is refused. Never add a catch-all allow.
- Observe first. Run in observe mode, read the audit log, then enforce. Never start in enforce on a live service.
- Never disable, skip or loosen a PCA check to make a test or a request pass. Fix the action mapping, the audience or
  the grant. A test that needs a valid proof should mint one with throwaway keys (`npx @atlasauth/pca-cli keygen`).
- Keys are never committed. Before the first run add `pca-proxy-state/`, `pca.audit.jsonl*`, `pca-proxy.approvals.json`
  and `*.key` to `.gitignore`. Never print or paste a secret key into code, a config or a log.
- Anything learned or inferred (autopilot proposals, imported actions, a tool that "looks read-only") is a proposal. A
  human confirms it and signs it. You never sign a review or a grant for the human, and you never mark an imported
  action reviewed.
- The grant comes from your own store, the operation from your own routing. Never take either from the request or the proof.
- Do not hold the upstream credential in the agent: with the proxy it lives in `http.upstreamHeaders` / the server env.

## Common errors and fixes

Every refusal starts with the check that failed. `pca_explain` returns the fix; the usual ones:

| Refusal | Usually means | Fix |
|---|---|---|
| `audience: ...` | the agent signed for another server id | use the same audience string on both sides (watch trailing slashes) |
| `replay: ...` | the same proof or counter was used twice, or two instances share no store | one shared replay store; a fresh proof per action |
| `operation: ...` | the signed action is not what the route runs | one verb/resource mapping on both sides; take it from routing |
| `grant_ref...` | the server does not know the grant | register the principal's grant in the grant lookup |
| `validity: ...` | the proof is outside its window | check clocks on both sides (`pca_doctor`) |
| `plan_root_authorized: ...` | a multi-step plan was not authorized | use a single-step plan, or authorize the plan root |
| `authorize_config: missing ...` | the guard was built without a required component | supply the named component (`protect()` fills safe defaults) |
| proxy: tool or route "not mapped" | default deny working | add the action to the config, as approve, then let a human relax it |
| proxy: tool definition changed (pin) | the upstream tool changed since it was reviewed | `pca-proxy review --config ...` and have the human accept it |

## Check your work

- Run the project's tests and add one test for an allowed and one for a denied request. A guard that has never refused anything proves nothing.
- `npx -y @atlasauth/pca-proxy audit verify ./pca.audit.jsonl` (proxy) and `pca_doctor` / `npx @atlasauth/pca-doctor --url <deployment>` (deployed).
