# @atlasauth/pca-mcp

Model Context Protocol adapter for Proof-Carrying Authority (PCA). `withPCA` wraps an MCP tool handler so every call first builds a signed PCActn (failing fast if the agent's own grant does not permit it), hands you the proof to forward to the resource server, and then runs the original handler.

## Install

```sh
npm i @atlasauth/pca-mcp @atlasauth/pca
npm i @modelcontextprotocol/sdk   # optional peer dependency (^1)
```

## Usage

```ts
import { agent, generateKeyPair } from '@atlasauth/pca';
import { withPCA } from '@atlasauth/pca-mcp';

const pcaAgent = agent({
  principal: generateKeyPair(),
  goal: 'process refunds',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500/day' },
  aud: 'ins_acme',
});

server.tool(
  'refund',
  schema,
  withPCA(
    pcaAgent,
    {
      verb: 'stripe.refund',
      resource: (args) => `ch_${args.chargeId}`,
      onProof: (pca, args) => {
        // forward pca.headers (PCA-Action) to the resource server with your request
      },
    },
    async (args) => ({ content: [{ type: 'text', text: await doRefund(args) }] }),
  ),
);
```

The wrapped handler keeps the MCP handler shape `(args, extra?) => result`. When the local dry-run denies the action it returns an MCP error result (`isError: true`) instead of throwing, so the model can see the refusal.

## API

- `withPCA(agent, spec, handler)` - spec is `{ verb, resource, aud?, failFast?, onProof? }`.
- `guardToolResult(pca, result)` - adds the encoded PCActn to a tool result's `_meta['x-pca-action']`, keeping existing content.
- Re-exports `bridgeToolCall`, `pcaHeaders`, and the `PcaCall` type from `@atlasauth/pca`.

To make the server that receives these calls an OAuth resource server, see `@atlasauth/pca-mcp-rs`.

## Status

This package does not authorize anything. It attaches a proof-carrying action; the resource server's verifier (see `@atlasauth/pca`) decides. The MCP SDK is matched structurally and never imported. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
