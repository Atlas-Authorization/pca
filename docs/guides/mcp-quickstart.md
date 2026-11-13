---
title: MCP quickstart
order: 6
---

# MCP quickstart: an authorized tool call in 10 minutes

You will build an [MCP](https://modelcontextprotocol.io) server whose tools refuse to run unless the call carries a
**proof-carrying action** (PCActn), and an MCP agent that sends one with each tool call. At the end you will see one
call allowed and one refused, with the reason:

```
refund -> ALLOWED: refunded $42 on ch_123
delete_customer -> DENIED: PCA denied: the grant does not permit stripe.delete_customer (it permits: stripe.refund)
```

The idea in three sentences. A person (the **principal**) gives an agent a **grant**: what it may do and within which
limits, signed with the principal's key. For every tool call the agent signs a PCActn that names the exact action
(verb, resource, arguments) and chains back to that grant. The MCP server loads the grant from its own store, checks
the proof, and runs the tool only if the grant allows this exact call.

You need Node.js 20 or later. No account, API key or Docker.

## The fastest start: scaffold it (2 minutes)

```bash
npm create pca-app@latest my-mcp -- --template mcp
cd my-mcp
npm install
npm run demo
```

`npm run demo` starts the MCP server, runs the agent against it and stops. The agent makes five calls:

```
ok   refund $42        -> ALLOWED: refunded $42 on ch_123
ok   refund $100       -> ALLOWED: refunded $100 on ch_124
ok   delete_customer   -> DENIED: PCA denied: the grant does not permit stripe.delete_customer (it permits: stripe.refund)
ok   refund $5000      -> DENIED: PCA denied: amount <= 500 not satisfied for stripe.refund on charge:ch_456
ok   refund, no proof  -> DENIED: PCA denied: tool 'refund' requires a proof-carrying action: send it in the PCA-Action header
```

To run the two sides separately, use `npm start` in one terminal and `npm run agent` in another. The rest of this page
builds the same thing by hand, in three files.

## Build it by hand (about 10 minutes)

### Step 1: install

```bash
mkdir pca-mcp-quickstart && cd pca-mcp-quickstart
npm init -y && npm pkg set type=module
npm install @atlasauth/pca @atlasauth/pca-mcp @atlasauth/pca-mcp-rs @modelcontextprotocol/sdk express zod tsx
```

- `@atlasauth/pca`: the agent's grant and keys, and the server's state store.
- `@atlasauth/pca-mcp` (agent side): `pcaFetch`, which signs a PCActn for each MCP tool call.
- `@atlasauth/pca-mcp-rs` (server side): `authorizeToolCall`, the complete check for one tool call.
- `@modelcontextprotocol/sdk`, `express`, `zod`: the MCP server and client. `tsx` runs TypeScript directly.

### Step 2: map tool calls to actions (`tools.ts`)

A PCActn names a **verb** and a **resource**. This file says which verb and resource each MCP tool call is. The agent
uses it to build proofs; the server uses it to check that a proof is for the call it is about to run.

```ts
// This MCP server's URL. It is also its audience: proofs are minted for it, and proofs for other servers are refused.
export const MCP_URL = 'http://127.0.0.1:8788/mcp';

// Which PCA action each MCP tool call is. The agent signs this; the server checks the proof matches the call.
export function toolAction(tool: string, args: Record<string, unknown>): { verb: string; resource: string } | null {
  if (tool === 'refund') return { verb: 'stripe.refund', resource: `charge:${String(args['chargeId'])}` };
  if (tool === 'delete_customer') return { verb: 'stripe.delete_customer', resource: `customer:${String(args['customerId'])}` };
  return null;
}
```

### Step 3: the MCP server (`server.ts`)

The server has two tools, `refund` and `delete_customer`. Each handler is wrapped by `requirePca`, which passes the
tool call's headers, name and arguments to `authorizeToolCall` and runs the handler only if it allows the call. That
one call checks:

1. A proof is present, chains back to a grant from the server's own store, is signed by the agent the grant names,
   is for this server (`resource`) and has not expired.
2. The proof is for this call: its signed verb and resource match `toolAction(tool, args)`, and the tool arguments
   match the signed digest.
3. The grant allows it: its permissions and limits, revocation, replay (a counter per agent), and the agent's trust
   budget. The server prices a money-moving call itself from the amount, so a $42 refund under a $500 limit spends
   42 of the budget.

A refusal is returned as an MCP tool error (`isError: true`) with the reason, so the model sees why.

```ts
import { existsSync, readFileSync } from 'node:fs';
import { memoryPcaStore, type Capability } from '@atlasauth/pca';
import { authorizeToolCall } from '@atlasauth/pca-mcp-rs';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import { z } from 'zod';
import { MCP_URL, toolAction } from './tools.js';

// 1. The server's own grant store: grants the principal registered out of band (here, files in ./grants).
function loadGrant(ref: string): Capability | null {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(ref) || !existsSync(`grants/${ref}.json`)) return null;
  return JSON.parse(readFileSync(`grants/${ref}.json`, 'utf8')) as Capability;
}

// 2. Replay counters and trust budgets per agent (in memory; in production a shared store with withKeyLock).
const state = memoryPcaStore();

type Result = { content: Array<{ type: 'text'; text: string }>; isError?: boolean };
type Extra = { requestInfo?: { headers: Record<string, string | string[] | undefined> } };

// 3. Wrap each tool handler: authorize the call, run the handler only if it is allowed.
function requirePca<A extends Record<string, unknown>>(tool: string, handler: (args: A) => Result) {
  return async (args: A, extra: Extra): Promise<Result> => {
    const r = await authorizeToolCall({ headers: extra.requestInfo?.headers ?? {} }, {
      resource: MCP_URL, // the proof must be minted for this server
      prmUrl: 'http://127.0.0.1:8788/.well-known/oauth-protected-resource',
      tool,
      args,
      toolAction, // binds the proof to this exact call
      resolveGrant: (ref) => loadGrant(ref), // from our store, never from the request
      isRevoked: () => false, // plug in your revocation list here
      state,
    });
    console.log(r.ok ? `ALLOWED ${tool} ${JSON.stringify(args)}` : `DENIED  ${tool}: ${r.reason}`);
    return r.ok ? handler(args) : { content: [{ type: 'text', text: `PCA denied: ${r.reason}` }], isError: true };
  };
}

function mcpServer(): McpServer {
  const server = new McpServer({ name: 'pca-mcp-quickstart', version: '0.1.0' });
  server.registerTool('refund', { description: 'Refund a charge.', inputSchema: { chargeId: z.string(), amount: z.number() } },
    requirePca('refund', (a: { chargeId: string; amount: number }) => ({ content: [{ type: 'text', text: `refunded $${a.amount} on ${a.chargeId}` }] })));
  server.registerTool('delete_customer', { description: 'Delete a customer.', inputSchema: { customerId: z.string() } },
    requirePca('delete_customer', (a: { customerId: string }) => ({ content: [{ type: 'text', text: `deleted ${a.customerId}` }] })));
  return server;
}

// 4. Serve MCP over Streamable HTTP (stateless: a fresh server and transport per request).
const app = createMcpExpressApp();
app.post('/mcp', async (req, res) => {
  const server = mcpServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on('close', () => void transport.close());
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});
app.listen(8788, '127.0.0.1', () => console.log(`MCP server on ${MCP_URL}`));
```

### Step 4: the agent (`agent.ts`)

The agent gets a grant for `stripe.refund` only, at most $500 per refund, and registers it with the server. Its MCP
client uses `pcaFetch`, which adds a fresh, signed `PCA-Action` header to every `tools/call` request. Then it calls one tool
inside the grant and one outside it. The agent signs the out-of-scope call too: think of it as a prompt-injected agent.
Its key can sign anything; the server still refuses, because the grant decides.

```ts
import { mkdirSync, writeFileSync } from 'node:fs';
import { agent, generateKeyPair } from '@atlasauth/pca';
import { pcaFetch } from '@atlasauth/pca-mcp';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { MCP_URL, toolAction } from './tools.js';

// 1. The principal (the human) gives the agent a grant: refunds only, at most $500 each.
const a = agent({
  principal: generateKeyPair(), // in production: the human's own key
  goal: 'refund customers for broken orders',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500/day' },
  aud: MCP_URL,
});

// 2. The principal registers the grant with the server, out of band (here: a file the server reads).
mkdirSync('grants', { recursive: true });
writeFileSync(`grants/${a.grant.id}.json`, JSON.stringify(a.grant));

// 3. An MCP client whose fetch adds a fresh, signed PCA-Action header to every tools/call.
const client = new Client({ name: 'pca-quickstart-agent', version: '0.1.0' });
await client.connect(new StreamableHTTPClientTransport(new URL(MCP_URL), { fetch: pcaFetch(a, toolAction) }));

// 4. One call inside the grant, one outside it.
for (const [name, args] of [
  ['refund', { chargeId: 'ch_123', amount: 42 }],
  ['delete_customer', { customerId: 'cus_42' }],
] as const) {
  const result = await client.callTool({ name, arguments: args });
  const text = (result.content as Array<{ text?: string }>).map((c) => c.text).join(' ');
  console.log(`${name} -> ${result.isError ? 'DENIED' : 'ALLOWED'}: ${text}`);
}
await client.close();
```

### Step 5: run it

In one terminal:

```bash
npx tsx server.ts
```

In another, in the same directory:

```bash
npx tsx agent.ts
```

The agent prints:

```
refund -> ALLOWED: refunded $42 on ch_123
delete_customer -> DENIED: PCA denied: the grant does not permit stripe.delete_customer (it permits: stripe.refund)
```

and the server logs:

```
ALLOWED refund {"chargeId":"ch_123","amount":42}
DENIED  delete_customer: the grant does not permit stripe.delete_customer (it permits: stripe.refund)
```

Try these next:

- In `agent.ts`, add `['refund', { chargeId: 'ch_456', amount: 5000 }]` to the list of calls. Denied:
  `amount <= 500 not satisfied for stripe.refund on charge:ch_456`.
- In `agent.ts`, set `aud: 'https://other.example.com/mcp'`. Every call is denied:
  `RFC 8707: PCActn audience (https://other.example.com/mcp) is not this resource server (http://127.0.0.1:8788/mcp)`.
- In `server.ts`, make `isRevoked` return `true` and restart the server. Every call is denied:
  `revocation: rejected`.

## What you just built, and what it does not do

- **The server holds the grant.** It loads the grant by the proof's signed `grant_ref` from a store the agent cannot
  write to. Here that store is a folder the agent process writes, because both run on your machine; in production it
  is your admin flow or database. Never accept a grant that arrives inside a request.
- **A valid signature is not a permission.** `authorizeToolCall` evaluates the grant's permissions and limits. A
  check that only looks at structure and signatures would have allowed `delete_customer`.
- **The proof is bound to the call.** A proof for "refund $42 on ch_123" cannot be reused for another charge,
  another amount or another tool, or replayed.
- **State is in memory.** `memoryPcaStore()` keeps the replay counters and budgets of one process. Use a shared store
  (Redis or your database) when you run more than one server process, and give it a `withKeyLock`: an exclusive
  per-key lock across all processes that does not expire under its holder. Without it the default lock is in-process
  and two processes can accept the same counter.
- **This is not the MCP OAuth flow.** When an HTTP MCP server uses authorization, the
  [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
  makes it an OAuth 2.1 resource server: the client presents an access token, and the server advertises its
  authorization servers with OAuth Protected Resource Metadata ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)).
  A PCActn is a per-call proof that the specific action is inside what the principal granted. You can use it alone,
  as here, or alongside an access token. `@atlasauth/pca-mcp-rs` also serves the RFC 9728 metadata document, and a
  denial from `authorizeToolCall` carries a ready `WWW-Authenticate` value if you refuse at the HTTP level instead.
  `authorizeRequest` is the same complete check by default. Admission alone (`admissionOnly: true`, or
  `admitRequest`) does not check limits, the binding to the call, or replay.

## Next

- [Add PCA in 5 minutes](./five-minute-quickstart.md): the same loop on a plain HTTP route.
- [Resource-server quickstart](./resource-server-quickstart.md): every check the full verifier can require.
- [Credential model](../concepts/credential-model.md): grants, capability chains and the PCActn.
