# @atlasauth/pca-mcp

Model Context Protocol adapter for Proof-Carrying Authority: wrap an MCP tool handler so every call emits a PCActn (and attaches the proof) before the handler runs.

## Install

```sh
npm i @atlasauth/pca-mcp
# peer dependency, install alongside:
npm i @modelcontextprotocol/sdk
```

`@modelcontextprotocol/sdk` (^1) is an optional peer dependency.

## Usage

```ts
import { withPCA } from '@atlasauth/pca-mcp';

server.tool(
  'refund',
  schema,
  withPCA(
    agent,                                       // core @atlasauth/pca Agent
    {
      verb: 'stripe.refund',
      resource: (args) => `ch_${args.chargeId}`,
      onProof: (pca) => { /* forward pca.encoded to the resource server */ },
    },
    async (args) => ({ content: [{ type: 'text', text: await doRefund(args) }] }),
  ),
);
```

The wrapped handler keeps the MCP handler shape. On a local fast-fail it returns an MCP error result (`isError: true`) rather than throwing. It builds + attaches a PCActn; it does not authorize on its own — the resource server's verifier decides.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
