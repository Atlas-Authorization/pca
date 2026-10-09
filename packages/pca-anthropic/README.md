# @atlasauth/pca-anthropic

Anthropic (Claude) adapter for Proof-Carrying Authority (PCA). It sits between a Claude `tool_use` block and the `tool_result` you send back: it turns the block into a PCActn (a signed proof-carrying action) using a PCA `Agent`, runs your handler with the proof in hand, and returns the `tool_result` block, including the error-shaped result Claude expects when a tool is declined or throws.

It does not authorize anything itself: it attaches a proof, and the resource server's verifier decides. A handler that forgets to forward the proof just produces a downstream call without a valid PCActn, which fails server-side.

## Install

```sh
npm i @atlasauth/pca-anthropic @atlasauth/pca
npm i @anthropic-ai/sdk
```

`@anthropic-ai/sdk` is an optional peer dependency; the adapter models only the block shapes it touches and does not import the SDK at runtime.

## Usage

```ts
import { agent, generateKeyPair } from '@atlasauth/pca';
import { handleToolUses, extractToolUses } from '@atlasauth/pca-anthropic';

const pcaAgent = agent({
  principal: generateKeyPair(),
  goal: 'issue refunds',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500/day' },
  aud: 'ins_acme',                       // the id your resource server verifies against
});

// After each assistant turn, answer every tool_use block:
const toolResults = await handleToolUses(
  pcaAgent,
  extractToolUses(message.content),
  ({ name, input }) =>                   // map tool -> { verb, resource }; return null to decline
    name === 'refund' ? { verb: 'stripe.refund', resource: `charge:${input.chargeId}` } : null,
  {
    refund: async (input, pca) => {      // pca.headers / pca.encoded carry the signed proof
      return doRefund(input, pca.headers);
    },
  },
);
// -> [{ type: 'tool_result', tool_use_id, content }]; is_error: true when declined, unhandled or thrown
// Append them to your next user message's content.
```

`handleToolUse` does the same for a single block. On success `content` is the JSON of your handler's return value (or `{ pca: <encoded> }` if it returns nothing).

## API

- `handleToolUse(agent, block, map, handlers, opts?)`, `handleToolUses(agent, blocks, map, handlers, opts?)`, `extractToolUses(content)`.
- Types: `ToolUseBlock`, `ToolResultBlock`, `ToolMapping`, `ToolHandler`.
- Re-exports from `@atlasauth/pca`: `pcaHeaders`, `PcaCall`.

## Status

Experimental. The underlying cryptography in `@atlasauth/pca` has not been independently audited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
