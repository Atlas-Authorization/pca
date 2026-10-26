# @atlasauth/pca-events

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Typed step-up lifecycle events + signed webhooks for Proof-Carrying Authority: build, HMAC-sign and verify step-up.created/approved/denied/expired events so integrators can run their own inbox, Slack bot or audit sink.

## Install

```sh
npm i @atlasauth/pca-events
```

Depends on `@atlasauth/pca` and `@noble/hashes` (runtime-portable: no `node:crypto`).

## Usage

```ts
import { buildStepUpEvent, serializeEvent, webhookHeaders, verifyWebhook, parseEvent } from '@atlasauth/pca-events';

// Sender: build a content-addressed event and sign the delivery.
const event = buildStepUpEvent('step_up.created', {
  grant_ref: 'grant_123',
  action: { verb: 'stripe.refund', resource: 'ch_123' },
  tier: 3,
});
const payload = serializeEvent(event);
const headers = webhookHeaders(secret, payload);        // { 'PCA-Signature': 't=...,v1=...', 'content-type': ... }

// Receiver: verify the Stripe-style signature, then parse.
if (verifyWebhook(secret, payload, headers['PCA-Signature'])) {
  const e = parseEvent(payload);
}
```

This is a transport contract — a stable event shape plus a webhook signature so the receiver can tell a real delivery from a forged one. It decides nothing; the authority decision lives in the PCA verifier, and these events only report what it already did.

## API

`buildStepUpEvent`, `serializeEvent`, `parseEvent` (validates, throws on a malformed event), `signWebhook`, `webhookHeaders`, `verifyWebhook`. Event types: `step_up.created`, `step_up.approved`, `step_up.denied`, `step_up.expired`. `verifyWebhook` returns `false` (never throws) on a bad signature, a malformed or oversized header, a timestamp outside the tolerance (default 300 s, `toleranceSec`), a secret shorter than 16 bytes, or a tolerance or clock that is not a finite non-negative number. A header may carry several `v1` entries (secret rotation); any one may match. `signWebhook` throws on a secret shorter than 16 bytes. `parseEvent` refuses an event whose `id` is not the digest of its content. The signature alone does not stop a replay within the tolerance window: `verifyDelivery(secret, payload, header, { replay })` also takes the event id once from a `ReplayStore` (the same contract `requirePCA` uses) and refuses a second delivery of the same event.

## Failure modes

| Situation | Result |
|---|---|
| Secret shorter than 16 bytes | `signWebhook` throws; `verifyWebhook` is false |
| Timestamp outside the tolerance, or two different `t` in one header | false |
| Tolerance or clock not finite, or negative tolerance | false |
| Signature does not match (every `v1` tried) | false |
| Payload is not a well-formed event, or its `id` is not its content digest | `parseEvent` throws; `verifyDelivery` refuses with that reason |
| Event id already seen | `verifyDelivery`: `replayed delivery` |
| No replay store, or the store throws | `verifyDelivery` refuses; nothing is accepted |

No error or refusal contains the secret, the signature or the payload.

## Status

Experimental. Part of Proof-Carrying Authority (see `@atlasauth/pca`); the HMAC webhook scheme is unaudited.

## License

MIT - see LICENSE
