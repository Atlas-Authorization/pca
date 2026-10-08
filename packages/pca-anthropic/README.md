# @atlasauth/pca-anthropic

Anthropic (Claude) adapter for Proof-Carrying Authority: turn a tool_use block into a PCActn and build the tool_result with the proof attached.

## Install

```sh
npm i @atlasauth/pca-anthropic
# peer dependency, install alongside:
npm i @anthropic-ai/sdk
```

`@anthropic-ai/sdk` is an optional peer dependency.

## Usage

```ts
import { handleToolUse, extractToolUses } from '@atlasauth/pca-anthropic';

// For each tool_use block in the assistant message:
for (const block of extractToolUses(message.content)) {
  const toolResult = await handleToolUse(
    agent,                                 // core @atlasauth/pca Agent
    block,                                 // { type: 'tool_use', id, name, input }
    ({ name, input }) =>                   // map tool → catalog { verb, resource }; null declines
      name === 'refund' ? { verb: 'stripe.refund', resource: `ch_${input.chargeId}` } : null,
    {
      refund: async (input, pca) => {      // pca carries the signed proof to forward downstream
        return doRefund(input);
      },
    },
  );
  // → { type: 'tool_result', tool_use_id, content } (is_error:true on a declined/failed tool)
}
```

`handleToolUse` builds a PCActn and attaches the proof; it does not authorize on its own — the resource server's verifier decides.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
