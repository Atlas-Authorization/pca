# @atlasauth/pca-events

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| Secret shorter than 16 bytes | `signWebhook` throws; `verifyWebhook` is false |
| Timestamp outside the tolerance, or two different `t` in one header | false |
| Tolerance or clock not finite, or negative tolerance | false |
| Signature does not match (every `v1` tried) | false |
| Payload is not a well-formed event, or its `id` is not its content digest | `parseEvent` throws; `verifyDelivery` refuses with that reason |
| Event id already seen | `verifyDelivery`: `replayed delivery` |
| No replay store, or the store throws | `verifyDelivery` refuses; nothing is accepted |

No error or refusal contains the secret, the signature or the payload.

## Limits

- It is a transport contract. It does not decide, authorize or retry anything, and it does not deliver: you send the request and run the receiving endpoint.
- The signature proves the sender held the shared secret. It does not identify which of several holders sent it, and anyone with the secret can forge a delivery.
- Replay protection is only as strong as the replay store you pass: a store that forgets, or is not shared between receiver instances, lets a replay through after a restart or on another instance. The timestamp tolerance bounds how long ids need to be remembered.
- An event reports what happened; its fields (`actor`, `grant_ref`) are claims the sender made, not verified identities.
- The HMAC scheme is symmetric: anyone holding the shared secret can sign a delivery, so keep the secret scoped to one receiver.

## Status

Production. Part of Proof-Carrying Authority (see `@atlasauth/pca`). The HMAC webhook scheme is the one it documents; the shared secret must be at least the documented length and is yours to rotate.

## License

MIT - see LICENSE
