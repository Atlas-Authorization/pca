# @atlasauth/pca-openai

OpenAI adapter for Proof-Carrying Authority: turn a model tool_call into a PCActn and run the handler with the proof attached.

## Install

```sh
npm i @atlasauth/pca-openai
# peer dependency, install alongside:
npm i openai
```

`openai` (v4 or v5) is an optional peer dependency.

## Usage

```ts
import { dispatchToolCall } from '@atlasauth/pca-openai';

// For each tool_call the model returns:
const toolMessage = await dispatchToolCall(
  agent,                                   // core @atlasauth/pca Agent
  toolCall,                                // { id, function: { name, arguments } }
  ({ name, arguments: args }) =>           // map tool → catalog { verb, resource }; null declines
    name === 'refund' ? { verb: 'stripe.refund', resource: `ch_${args.chargeId}` } : null,
  {
    refund: async (args, pca) => {         // pca carries the signed proof to forward downstream
      return doRefund(args);
    },
  },
);
// → { role: 'tool', tool_call_id, content } to feed back to the next model turn
```

`dispatchToolCall` builds + signs a PCActn and attaches it; it does not dry-run or authorize on its own — an over-cap or out-of-policy call still produces a signed PCActn here and is rejected by the resource server's verifier.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
