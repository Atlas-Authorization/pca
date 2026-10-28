# @atlasauth/pca-mcp

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Model Context Protocol adapter for Proof-Carrying Authority (PCA). It is the **agent side**: it turns each tool call
into a signed proof-carrying action (PCActn) that the server receiving the call verifies. The decision is always the
server's, made with `requirePCA` / `verifyPCActn` from `@atlasauth/pca`.

The fastest way to see it working end to end, an MCP server whose tools require a PCActn and an agent that sends one:

```sh
npm create pca-app@latest my-mcp -- --template mcp
cd my-mcp && npm install && npm run demo
```

The PCA docs walk through the same project by hand in the **MCP quickstart**.

## Install

```sh
npm i @atlasauth/pca-mcp @atlasauth/pca
npm i @modelcontextprotocol/sdk   # optional peer dependency (^1)
```

## Calling an MCP server that requires PCA

The server reads the PCActn from the `PCA-Action` header of each `tools/call` request. Give the MCP client transport
`pcaFetch`: for every `tools/call` it builds a fresh PCActn for that exact call (verb and resource from your mapping,
the arguments committed by digest, a new counter) and adds the header. Other requests pass through unchanged.

```ts
import { agent, generateKeyPair } from '@atlasauth/pca';
import { pcaFetch } from '@atlasauth/pca-mcp';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const pcaAgent = agent({
  principal: generateKeyPair(),
  goal: 'process refunds',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500/day' },
  aud: 'http://127.0.0.1:8788/mcp', // the MCP server's `resource`: the proof is only valid there
});
// Register pcaAgent.grant with the server out of band (its grant store), before the first call.

// Which PCA verb and resource each tool call is. The server checks the proof against the same mapping.
const toolAction = (tool: string, args: Record<string, unknown>) =>
  tool === 'refund' ? { verb: 'stripe.refund', resource: `charge:${String(args.chargeId)}` } : null;

const client = new Client({ name: 'my-agent', version: '1.0.0' });
await client.connect(new StreamableHTTPClientTransport(new URL('http://127.0.0.1:8788/mcp'), { fetch: pcaFetch(pcaAgent, toolAction) }));
await client.callTool({ name: 'refund', arguments: { chargeId: 'ch_123', amount: 42 } });
```

The PCActn commits to the tool arguments by digest, so the server must receive exactly the arguments that were signed.
On the server, check each call with `authorizeToolCall` from `@atlasauth/pca-mcp-rs` using the same `toolAction`
mapping. `pcaFetch(agent, toolAction, { fetch, aud })` takes an optional inner fetch and audience override.

## Wrapping a tool whose handler calls a protected API

When an MCP tool you run on the agent's side (for example a local stdio server) forwards the call to an API that
requires PCA, wrap its handler with `withPCA`. Each call first builds a PCActn, fails fast if the agent's own grant
does not permit the call, hands you the proof in `onProof`, then runs your handler:

```ts
server.registerTool(
  'refund',
  { inputSchema: { chargeId: z.string(), amount: z.number() } },
  withPCA(
    pcaAgent,
    { verb: 'stripe.refund', resource: (args) => `charge:${args.chargeId}` },
    async (args) => ({ content: [{ type: 'text', text: await callRefundApi(args) }] }),
  ),
);
```

Send the proof with the downstream request: the handler does not receive it, so capture it in `onProof(pca, args)` and
add `pca.headers` (the `PCA-Action` header) to the API call. When the local check denies the action, the wrapped
handler returns an MCP tool error (`isError: true`) with the reason instead of throwing, so the model can see the
refusal. `withPCA` does not protect the MCP server it is registered on; that server's caller sends no proof.

## API

- `pcaFetch(agent, toolAction, opts?)`: a fetch for MCP client transports that signs a PCActn per `tools/call`.
- `withPCA(agent, spec, handler)`: spec is `{ verb, resource, aud?, failFast?, onProof? }`.
- `guardToolResult(pca, result)`: adds the encoded PCActn to a tool result's `_meta['x-pca-action']`, keeping existing content.
- `draftActionSchemaFromMcp`, `applySchemaDecisions`, `verbOfTool`, `conformToolCall`: derive a site's signed action schema from an MCP tool list, and check a tool call against it.
- Re-exports `bridgeToolCall`, `pcaHeaders`, and the `PcaCall` type from `@atlasauth/pca`.

For the server side, use `authorizeToolCall` from `@atlasauth/pca-mcp-rs`.

## Fail-closed behaviour

This package is the agent side, so "fail closed" means it never invents authority: where it cannot build a proof it sends none, and the server's verifier refuses the call.

| Missing or invalid | Result |
|---|---|
| `toolAction` returns `null` for a tool (an unmapped tool) | `pcaFetch` forwards the request unchanged with no `PCA-Action` header; a server that requires PCA refuses it |
| The request is not a JSON `tools/call` (other methods, non-JSON or non-string bodies) | Passed through unchanged; no proof is added |
| `tools/call` with absent or non-object `arguments` | Signed over `{}` |
| The agent's own grant does not permit the call (`withPCA`, `failFast` on by default) | The wrapped handler returns an MCP tool error (`isError: true`) with the reason; your handler does not run and no proof is handed out |
| `failFast: false` and the grant does not permit the call | A proof is still built and handed to `onProof`; the server is then the only gate |
| Your handler throws something other than a PCA denial | The error is rethrown unchanged |
| `applySchemaDecisions` names a verb or parameter the draft does not have | Throws |
| `conformToolCall` for a tool the site schema does not declare | `{ ok: false, code: 'unknown_verb' }` (a closed world) |
| `importActionDefsFromMcp` without the optional `@atlasauth/pca-actions` installed | Throws, naming the package and the v1 alternative |

## Limits

- It authorizes nothing and never sees the server's decision logic; a call it signs can still be refused by the server.
- The proof commits to the arguments by digest, so a server that receives different arguments refuses; it does not protect a server whose caller sends no proof (`withPCA` does not protect the MCP server it is registered on).
- `pcaFetch` only recognises JSON `tools/call` requests carried in a string body; other transports or encodings need their own signing.
- Your `toolAction` mapping is trusted on the agent side; the server must use the same mapping.
- The tool annotations and descriptions an MCP server publishes are untrusted hints; a drafted schema stays a draft until a person reviews and signs it.

## Status

This package does not authorize anything. It attaches a proof-carrying action; the resource server's verifier (see `@atlasauth/pca`) decides. The MCP SDK is matched structurally and never imported. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
