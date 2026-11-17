# @atlasauth/pca-proxy

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Protect any agent in five minutes. `pca-proxy` puts Proof-Carrying Authority in front of **any MCP server** (stdio or streamable
HTTP) or **any HTTP API**, with **no SDK and no code change** in the agent or in the server behind it.

```
agent  ->  pca-proxy  ->  the MCP server / the API
```

Every tool call and every request is mapped to an action (anything unmapped is refused), checked against that action's definition,
and decided by the full PCA pipeline: the grant's limits and caveats, revocation, the replay counter, the trust budget, and the
provenance gate. Results that come back are labelled untrusted, so text injected into a tool result cannot talk the agent into a
sensitive action: once a session has seen untrusted content, a sensitive call is held for a human.

## Install

```sh
npm i -g @atlasauth/pca-proxy     # or use npx @atlasauth/pca-proxy
```

Node 20 or later. For OpenTelemetry, also install `@opentelemetry/api` (optional).

## Quickstart: Claude Desktop and Claude Code (MCP)

**1. See what it would do, changing nothing.** Observe mode forwards every call and records what enforce mode would have refused:

```sh
npx @atlasauth/pca-proxy mcp --observe --audit ./pca.audit.jsonl -- npx -y @modelcontextprotocol/server-github
```

**2. Write the starting config.** `init` connects to the server, lists its tools and pins each one to the definition it has now:

```sh
npx @atlasauth/pca-proxy init mcp --ns github --out pca-proxy.yaml -- npx -y @modelcontextprotocol/server-github
```

Every tool starts as `policy: approve, effect: write`: a human approves each call. That is the safe start and it works
immediately. Open `pca-proxy.yaml` and make the decisions only you can make:

```yaml
mcp:
  tools:
    search_issues: { policy: allow, effect: read, pin: "..." }       # only reads: let it through
    create_issue:  { policy: allow, effect: write, reversibility: reversible, limit: "10/hour", pin: "..." }
    delete_repo:   { policy: deny, effect: write, pin: "..." }       # never (delete the entry to the same effect)
```

(`--trust-read-only-hints` marks the tools that declare `readOnlyHint: true` as `allow` / `read` for you. Use it only for a
server you trust: the hint is the server's own claim.)

**3. Point the client at the proxy.** Claude Desktop (`claude_desktop_config.json`) or any client that takes a command:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@atlasauth/pca-proxy", "mcp", "--config", "/absolute/path/pca-proxy.yaml"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "..." }
    }
  }
}
```

Claude Code:

```sh
claude mcp add github -- npx -y @atlasauth/pca-proxy mcp --config /absolute/path/pca-proxy.yaml
```

The model now sees only the tools you allowed or approve. Calls that need a human wait (up to `approvals.waitSeconds`); decide them
from a terminal:

```sh
pca-proxy approvals list    --config pca-proxy.yaml
pca-proxy approvals approve <id> --config pca-proxy.yaml --by you
```

Resources and prompts are mapped the same way (`mcp.resources` keyed by the exact `uri` or the `uriTemplate` the server lists,
`mcp.prompts` keyed by name; default effect `read`, pinned like tools). `init` writes them as `approve`. A read of a resource
nobody mapped is refused, and what a mapped read returns is labelled untrusted like a tool result.

The proxy keeps its state (the grant's identity, the replay counters, the budget, the session taint, the rate windows) in
`./pca-proxy-state` (`state.dir`): keep it out of version control. It is created mode 0700 and every write is fsync'd and
hash-chained, so the budget and the taint survive a restart. The taint is sticky on purpose: the proxy cannot tell when a conversation
ends, so a session that saw untrusted content stays tainted until you run `pca-proxy taint clear --config pca-proxy.yaml` (the
starting point for a new conversation). For development you can ask for `state: { backend: memory }`.

## Quickstart: Cursor

Same file, same config. In `.cursor/mcp.json` (or the global one):

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@atlasauth/pca-proxy", "mcp", "--config", "/absolute/path/pca-proxy.yaml"]
    }
  }
}
```

A remote server works too: put `mcp.upstream: { url: "https://mcp.example.com/mcp", headers: { Authorization: "Bearer ${TOKEN}" } }`
in the config (or pass `--upstream URL`).

## Remote and hosted clients (MCP over streamable HTTP)

```yaml
mcp:
  upstream: { command: npx, args: ["-y", "@modelcontextprotocol/server-github"] }
  ns: github
  tools: { ... }
  listen:
    host: 127.0.0.1                 # put a TLS terminator in front for anything else
    port: 8789
    path: /mcp
    allowedOrigins: ["https://app.example"]
    clients:                        # one named client per token; a session belongs to the client that opened it
      alice: { tokenEnv: ALICE_TOKEN }
      bob:   { tokenEnv: BOB_TOKEN }
```

```sh
ALICE_TOKEN=... BOB_TOKEN=... pca-proxy mcp --config pca-proxy.yaml      # serves stdio, or HTTP when mcp.listen is set
```

Clients send `Authorization: Bearer <token>`; `initialize` opens a session and returns `Mcp-Session-Id`; every later request
carries it; `DELETE` closes it. Each session gets its own upstream process or connection and its own tool lists, so sessions do not
share anything but the proxy's one grant, budget and audit chain. Another client presenting a session id gets a 404. An `Origin`
that is not in `allowedOrigins` is refused (DNS rebinding), and so is a `Host` that is not loopback while the proxy listens on
loopback. Untrusted content in one client never taints another; a client that has seen untrusted content starts its next session
tainted. Answers are plain JSON (no server-sent stream), so a server's own requests to the client (sampling, elicitation) are
refused. `insecureNoAuth: true` serves with no token and is accepted only on a loopback address.

## Quickstart: a generic HTTP API

```yaml
# pca-proxy.yaml
mode: enforce
audience: orders-api
http:
  upstream: http://127.0.0.1:9000
  listen: { host: 127.0.0.1, port: 8788 }
  openapi: ./openapi.yaml                            # or write routes by hand, see below
  upstreamHeaders: { Authorization: "Bearer ${UPSTREAM_TOKEN}" }   # the credential stays with the proxy, not the agent
  actions:                                           # by operationId, or "METHOD /path"
    getOrder:    { policy: allow,   effect: read }
    createOrder: { policy: allow,   effect: write, limit: "20/hour" }
    refundOrder: { policy: approve, effect: write, reversibility: irreversible }
```

```sh
UPSTREAM_TOKEN=... pca-proxy http --config pca-proxy.yaml
```

Point the agent at `http://127.0.0.1:8788` instead of the API. No OpenAPI document? Write the routes:

```yaml
http:
  upstream: http://127.0.0.1:9000
  routes:
    - { method: GET,  path: "/orders/{id}", policy: allow, effect: read }
    - { method: POST, path: "/orders", policy: approve, effect: write,
        schema: { type: object, required: [sku], properties: { sku: { type: string }, qty: { type: integer, minimum: 1, maximum: 10 } } } }
```

Two ways to prove a call. **Sidecar** (default): the proxy mints the proof from its own grant, for an agent that cannot sign.
**Verify** (`http.mode: verify`, with `http.grants`): the caller sends `PCA-Action`, bound to the request and signing
`{...pathParams, ...query, ...body}` plus the request binding (see `@atlasauth/pca-gateway`), and the proxy verifies it.

## One command from the dashboard: `--connect`

The dashboard's **Get started with agents** shows a single command with a one-time setup token:

```sh
npx @atlasauth/pca-proxy mcp --observe --connect pcs1.... -- npx -y @modelcontextprotocol/server-github
npx @atlasauth/pca-proxy http --config pca-proxy.yaml --observe --connect pcs1....
```

The token is single use, belongs to one instance and one setup, expires in ten minutes, and can only register one source key. The proxy
makes that key itself (in `./pca-proxy-connect/`, mode 0600, never sent anywhere), registers its public half, and then reports every
decision to your instance, signed with it. For MCP you need no config: the proxy lists the server's tools and pins them. Later runs
need only `--connect` (the saved connection is reused). In observe mode it also records the parameters that cannot carry content
(`--include-params amount,qty` names the money-like ones you accept recording), each bound to its receipt by a digest the receipt
carries, which the dashboard checks before it lets an amount cap into a proposal. Reporting never slows or changes a call; if your
instance is unreachable events queue (bounded) and are retried.

## Enforcing a signed grant: `--grant`

When the setup ends with a grant you signed with a passkey, switch to enforcing it:

```sh
npx @atlasauth/pca-proxy mcp --enforce --connect --grant grant.json -- npx -y @modelcontextprotocol/server-github
```

(or, in a config, `agent: { issuedGrant: { file: grant.json, signer: <the instance signer key> } }`; `--signer KEY` overrides the key
`--connect` saved). The proxy refuses to start if the grant does not verify under that key. From then on a call is admitted only when the
grant's predicates and caveats admit it (verb, resource, parameter caps, expiry, rate); the grant can only tighten what your rules
allow (a `deny` rule still denies), and a call it admits no longer waits for a human, except in a session that has seen untrusted
content. The grant's risk budget is not replayed (the proxy keeps its own), and the rate window lives in the proxy's state directory.

## What a call goes through

1. **Mapped?** A tool or route with no rule is refused (`unmapped`). A tool whose rule has no pin, or whose definition changed since
   you pinned it, is refused until you review it again (`pca-proxy review`): a server cannot swap a tool's behavior or description
   under you.
2. **Rule.** `deny` is refused; `approve` goes to a human every time.
3. **Arguments.** Every argument must be one the action declares, every required one present, every value inside its declared
   domain, the whole inside `limits.maxRequestBytes`, and inside the strict canonical JSON profile the proof signs. For HTTP, a name
   that appears in the path, query or body twice is refused, and the request sent upstream is rebuilt from what was checked.
4. **The grant.** The proxy builds a proof of this exact call and runs it through the PCA verifier: chain, audience, the limits and
   caveats you wrote (`limit: 10/hour`), revocation (`agent.revocationFile`: create the file to stop everything), the replay counter,
   and the budget (`budget.max`, in blast-radius units).
5. **Reads.** `resources/read` and `prompts/get` go through the same steps as a tool call, as read actions: the uri is matched
   to a listed resource or template (a value that walks, with `..`, an encoded dot or slash, is refused), the prompt's
   arguments are checked, and a changed definition is held like a changed tool.
6. **Provenance.** The proxy records everything it relays as untrusted content. A call it cannot show derives from you (it cannot:
   the proxy sees tool traffic, not your messages) is held when it is sensitive. `effect: read` actions are not sensitive. A
   `write` with `policy: allow` is answered by the proxy only while the session is still clean; after any tool result it goes to a
   human. `insecureAllowAfterUntrusted: true` turns that off for one tool, and is named to be noticed.
7. **Receipt.** The decision is written to the audit log before the call is forwarded.

If the upstream fails, times out, redirects, answers too much, or the audit log cannot be written, the call is refused. Nothing the
upstream said in an error is relayed.

## Modes and the audit log

- `mode: enforce` (default) refuses. `mode: observe` (or `--observe`) forwards everything, runs the same decisions and records
  `allowed: false` plus the reason for each call enforce mode would have refused. Run it first.
- `audit.path`: one hash-chained receipt per line (`receiptFor` of `@atlasauth/pca`), written before the call is forwarded.
  `pca-proxy audit verify FILE` checks the chain; an edited, dropped or reordered line breaks it. The proxy refuses to append to a log
  whose chain is broken.
- `otel: true` emits a span (`pca.proxy.call`) and the `pca.verifications` counter per decision through `@opentelemetry/api`.
  Attribute values pass through the same secret redaction as `@atlasauth/pca-otel`.

## Learning a grant from what the agent did (`pca autopilot`)

A receipt carries only a digest of the arguments, so amount caps cannot be learned from the audit log alone. In **observe** mode
the proxy can also write the arguments that cannot carry content, for `pca autopilot` to learn from:

```yaml
audit:
  path: ./pca.audit.jsonl
  observedParams:
    enabled: true            # off by default
    include: [amount]        # parameters of material sensitivity you allow (money amounts are material)
  # observedParamsPath: ./pca.audit.jsonl.params.jsonl   (the default: the audit path plus .params.jsonl)
```

```sh
pca-proxy http --config pca-proxy.yaml --observe          # watch; enforce mode refuses to start with observedParams on
pca-proxy audit verify ./pca.audit.jsonl --params ./pca.audit.jsonl.params.jsonl
pca autopilot observe ./pca.audit.jsonl --params ./pca.audit.jsonl.params.jsonl
```

What is written: a safe integer, a boolean, or a string from a declared closed enum of at most 64 characters, and only for a
parameter whose sensitivity is `free`, or `material` and named in `include`. A `critical` parameter, and any parameter whose role
or tags say credential, personal data, contact, party, path, query, code, url, text or SQL, is never written, whatever `include`
says. Free strings, dates, arrays, objects and nulls are never written. For anything left out only its **name** is listed. A
decision with nothing to record or leave out has no line.

Each line names its receipt (`seq`, `receipt` hash, `verb`, `resource`) and is hash-chained to the line before it; the file is
append-only (mode 0600) and the proxy refuses to append to one whose chain is broken. The binding also runs the other way: the
receipt carries the digest of its line's content in two facts, `obs1` and `obs2` (the 43-character digest split in two), so
neither file can be rewritten without the other disagreeing. `audit verify --params` checks all of it, including that a receipt
with a digest has its line. A line that cannot be written is a warning: watching never blocks a call.

## Approvals

A held call becomes a step-up request that carries the canonical approval render of the exact arguments, so what the approver sees
is what is signed. Requests live in `approvals.store` (a file), so you can decide them from another terminal or `kubectl exec`.
`approvals.webhook: { url, secretEnv }` also posts a signed `step_up.created` event (Stripe-style signature, `@atlasauth/pca-events`)
to an inbox, a chat bot or a pager. A call that cannot be shown to a human completely (an argument outside the canonical domain, a
float, a free-form object) is refused instead of approved blind.

## Configuration reference

| Key | Meaning |
| --- | --- |
| `mode` | `enforce` (default) or `observe` |
| `audience` | the audience the proofs are for (default `pca-proxy`) |
| `budget.max` | blast-radius budget of the grant (default 100: a read costs 0.05, a reversible write 0.2, a rate-limited one 0.5, an irreversible one 0.8) |
| `agent.goal`, `agent.principalKeyEnv`, `agent.revocationFile` | the grant's goal; a base64url 32-byte key in this environment variable (default: a fresh key per start); a file whose existence revokes the grant |
| `mcp.upstream` | `{ command, args, env }` or `{ url, headers }` |
| `mcp.ns`, `mcp.tools.<name>` | the verb namespace; per tool `policy` (`allow`/`approve`/`deny`), `effect` (`read`/`write`, default `write`), `reversibility`, `limit` (`10/hour`: a sliding window kept by the proxy for that action; or `$100/day` with `amountField`: a per-call ceiling on the grant), `pin`, `insecureAllowAfterUntrusted` |
| `mcp.resources`, `mcp.prompts` | rules for the resources (key: `uri` or `uriTemplate`) and prompts (key: name); same fields as a tool, default `effect: read` |
| `mcp.listen` | `host`, `port`, `path`, `clients` (name to `tokenEnv`), `allowedOrigins`, `allowedHosts`, `insecureNoAuth`, `maxSessions` (64), `idleSeconds` (1800) |
| `state.backend`, `state.dir`, `state.hmacKeyEnv` | `file` (default) or `memory` (development); the directory; an environment variable with a 32-byte key that MACs the journal |
| `mcp.relistSeconds`, `mcp.allowServerRequests` | how long a tool list is trusted (30); server-to-client requests relayed besides `ping` and `roots/list` |
| `http.upstream`, `http.listen`, `http.mode` | the API; the address to listen on; `sidecar` or `verify` |
| `http.openapi`, `http.actions`, `http.routes` | the OpenAPI file; rules by `operationId` or `METHOD /path`; hand-written routes |
| `http.upstreamHeaders`, `http.forwardHeaders` | headers added upstream (`${ENV}` expanded); extra client headers passed through (a short safe list always is) |
| `http.grants`, `http.attachProof`, `http.sessionHeader` | verify mode: grant files; send the minted proof upstream; the header a trusted layer in front of the proxy uses to name an agent session (unset: all callers share one session, so the agent cannot pick a clean one) |
| `approvals.store`, `approvals.waitSeconds`, `approvals.webhook` | approvals file (default: memory); how long a call waits (120); signed notification |
| `audit.path` | the receipt log |
| `audit.observedParams`, `audit.observedParamsPath` | `{ enabled, include }`: the optional observed-parameters log (observe mode only); its path |
| `otel` | emit spans and metrics |
| `limits` | `maxRequestBytes` (262144), `maxResponseBytes` (1048576), `upstreamTimeoutMs` (30000) |

A file that has an unknown key, a wrong type or a duplicate key does not load. Secrets are never in the file: name the environment
variable.

## Docker and Kubernetes

`deploy/Dockerfile` builds an image from the published package; `deploy/k8s-sidecar.yaml` runs it as a sidecar in the API's pod,
with the API bound to the pod's loopback so the proxy is the only way in. `deploy/pca-proxy.http.example.yaml` and
`deploy/pca-proxy.mcp.example.yaml` are complete example configurations.

```sh
docker build -f deploy/Dockerfile -t pca-proxy .
docker run --rm -p 8788:8788 -v "$PWD/pca-proxy.yaml:/etc/pca-proxy/pca-proxy.yaml:ro" -e UPSTREAM_TOKEN pca-proxy
```

## What this does not do

- **It does not know what you typed.** The proxy sees tool traffic, never your messages, so it cannot tell a call you asked for
  from one an injected result asked for. It errs the safe way: after untrusted content, a write waits for you.
- **It guards the path through it.** An agent that can reach the server or the API another way is not protected. Run the server
  as the proxy's child (stdio), or make the proxy the only route in (the sidecar example).
- **State is on one host.** The counters, the budget and the taint are in a hash-chained file store with an atomic claim, safe for
  processes on one machine and across restarts; it is not a shared database, so run one proxy per state directory. A state that
  cannot be read or written refuses the call, and a corrupt or rolled-back directory stops the proxy from starting instead of
  starting empty (recovery is an operator action, not a flag). A change to the rules is a different grant: it starts with a
  fresh budget. A limit with a period (`$100/day`) gives the grant a one-period life; the proxy mints the next one from the same
  keys. Approvals and the audit log are files too.
- **MCP:** stdio is one client per process; the HTTP listener serves many. There is no server-sent stream, and batches are refused.
  A resource template other than `{name}` and `{+name}` is not mapped.
- **HTTP:** JSON bodies only; a response is read in full (up to `maxResponseBytes`), not streamed; WebSocket and server-sent events
  are not proxied.
- **Imported definitions are lossy.** A JSON `number` is declared as a string by the importer, and an object with no declared
  members is a placeholder; for those the proxy checks presence and size, not shape. An argument that cannot be rendered for a human
  (a float, a free-form object) cannot be approved.
- It enforces what you wrote. A rule that says `allow` for a tool that can do harm allows it.
