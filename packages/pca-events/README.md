# @atlasauth/pca-events

Typed step-up lifecycle events + signed webhooks for Proof-Carrying Authority: build, HMAC-sign and verify step-up.created/approved/denied/expired events so integrators can run their own inbox, Slack bot or audit sink.

## Install

```sh
npm i @atlasauth/pca-events
```

Depends on the core `@atlasauth/pca` and `@noble/hashes` (runtime-portable: no `node:crypto`).

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
const headers = webhookHeaders(secret, payload);        // { 'PCA-Signature': 't=…,v1=…', ... }

// Receiver: verify the Stripe-style signature, then parse.
if (verifyWebhook(secret, payload, headers['PCA-Signature'])) {
  const e = parseEvent(payload);
}
```

This is a transport contract — a stable event shape plus a webhook signature so the receiver can tell a real delivery from a forged or replayed one. It decides nothing; the authority decision lives in the PCA verifier, and these events only report what it already did.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
