# @atlasauth/pca-ciba

A CIBA (OpenID Connect Client-Initiated Backchannel Authentication) on-ramp for Proof-Carrying Authority (PCA) step-up. It turns a risk-gated step-up into a standard asynchronous human-approval flow, interrupting a person only for the actions that actually need it.

In CIBA a backend opens an `auth_req_id`, the human is notified out of band, and the decision comes back by poll or ping/push. The `binding_message` carries the human-readable approval context, so the thing approved on the phone is the thing the agent is about to do ("Approve stripe.refund $480 on charge:ch_1 - because you asked support-bot to 'reconcile October refunds'").

This is a bridge, not a replacement. PCA's cryptographic step-up (a FROST threshold cosign, in `@atlasauth/pca`) stays the enforcement; CIBA is the notification and decision envelope around it.

Gating is risk-adaptive: only a tier-3 step-up (human required, typically irreversible) is routed through CIBA. Tier-2 (guardian auto-cosign) and tier-1 (`auto`) never interrupt a person.

## Install

```sh
npm i @atlasauth/pca-ciba @atlasauth/pca
```

## Usage

```ts
import { agent, generateKeyPair, reviewAction } from '@atlasauth/pca';
import { requiresCiba, createCibaBroker, cibaDecisionToCosign } from '@atlasauth/pca-ciba';

const a = agent({
  principal: generateKeyPair(),
  goal: 'reconcile October refunds',
  permissions: { stripe: ['payout'] },
  limits: { payout: '$100' },
  aud: 'rs_demo',
  riskPolicy: { theta1: 0.3, theta2: 0.6 },
});

const review = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80 }, { goal: 'reconcile October refunds' });

if (review.kind === 'step_up' && requiresCiba(review)) {
  const broker = createCibaBroker({ onComplete: (session) => console.log(session.status) }); // omit onComplete for POLL
  const ciba = broker.start(review.request, { actsFor: 'support-bot', loginHint: 'owner@acme' });
  // ciba.auth_req_id, ciba.binding_message, ciba.requested_expiry, ...

  broker.poll(ciba.auth_req_id).status; // 'pending' | 'approved' | 'denied' | 'expired'

  // The human decides out of band:
  const session = broker.resolve(ciba.auth_req_id, 'approve', 'owner@acme');

  // Fold the decision back into the trust budget:
  const { budget, cosigned } = cibaDecisionToCosign(
    session.status === 'approved' ? 'approve' : 'deny',
    a.budget,
    a.policy.riskPolicy,
    Date.now(),
  );
}
```

`toCibaAuthRequest(stepUp, opts?)` is the pure mapping from a step-up to a CIBA request, if you want to drive your own broker or a real OpenID provider.

## Status

Experimental. The broker is in-memory and models the CIBA lifecycle without any network; a production deployment would swap in a real OpenID provider. The package computes approval envelopes and the derived trust budget and authorises nothing on its own: `cibaDecisionToCosign` is only the budget-level effect. The cryptographic cosign (FROST) is produced and verified separately, and the resource server's verifier remains the authority. Cryptography in PCA is unaudited.

What has been checked against OpenID Connect CIBA Core 1.0 (Final): the specification's own examples (committed with source URL and sha256) are replayed through the independent `openid-client` library (6.8.2), which also drives the broker end to end through a small HTTP provider written for the tests (initiate, poll through `authorization_pending`, approve, deny, expiry). The values the package emits are asserted against the specification's requirements: `auth_req_id` is unguessable (160 random bits, restricted character set), `requested_expiry` is a positive integer, `scope` carries `openid` and only valid scope-token characters, and `binding_message` is a single short line of plain text.

Not validated: interoperability with a production OpenID provider, `slow_down` and `interval` enforcement (the broker reports the interval but does not rate-limit polls), signed authentication requests, and the ping/push callback handlers (the specification's callback examples are not exercised).

## License

MIT - see LICENSE
