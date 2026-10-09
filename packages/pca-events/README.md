# @atlasauth/pca-events

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

`buildStepUpEvent`, `serializeEvent`, `parseEvent` (validates, throws on a malformed event), `signWebhook`, `webhookHeaders`, `verifyWebhook`. Event types: `step_up.created`, `step_up.approved`, `step_up.denied`, `step_up.expired`. `verifyWebhook` returns `false` (never throws) on a bad signature, malformed header or a timestamp outside the tolerance (default 300 s, `toleranceSec`). The event `id` is a content hash, so receivers can dedupe redeliveries by `id`; the signature alone does not stop a replay within the tolerance window.

## Status

Experimental. Part of Proof-Carrying Authority (see `@atlasauth/pca`); the HMAC webhook scheme is unaudited.

## License

MIT - see LICENSE
