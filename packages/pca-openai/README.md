# @atlasauth/pca-openai

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| The mapping declines the tool (returns `null`) | Throws `dispatchToolCall: no PCActn for unmapped tool ...`; no handler runs |
| `arguments` is not valid JSON, or is JSON that is not an object | Throws before any proof is built; no handler runs |
| Empty `arguments` string | Treated as `{}` (a signed proof for empty arguments) |
| No handler registered for the tool name | No tool runs; a proof-echoing tool message is returned |
| The handler throws | The error reaches the caller; no tool message is produced |
| The agent cannot build the PCActn (the proof cannot be built) | The call rejects and no handler runs |

## Limits

- It signs; it does not authorize and does not dry-run, so an over-cap call still gets a signed PCActn and is refused only by the resource server's verifier.
- In `dispatchToolCalls` calls run one after another, with the counter incremented per call only when you pass `counter`; without it the agent chooses the counters.
- A handler that does not forward the proof downstream makes the downstream action fail server-side.
- The OpenAI SDK is never imported; tool calls are matched by shape.
-

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca); see `@atlasauth/pca`.

## License

MIT - see LICENSE
