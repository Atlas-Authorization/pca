# @atlasauth/pca-ciba

A CIBA (OpenID Connect Client-Initiated Backchannel Authentication) on-ramp for PCA's FROST step-up: turn a risk-gated step-up into a standard async human-approval flow, interrupting a person only for the actions that actually need it.

CIBA is the convergent human-in-the-loop primitive every modern IdP ships (Auth0, Descope, Stytch): a backend opens an `auth_req_id`, the human is notified out of band, and the decision comes back by POLL or PING/PUSH. Its `binding_message` carries the human-readable approval context — so the thing approved on the phone is provably the thing the agent is about to do (OpenID CIBA Core).

This is a **bridge, not a replacement**. PCA's cryptographic step-up (FROST threshold cosign, in `@atlasauth/pca`) stays the enforcement; CIBA is the human-notification / decision envelope around it. A bare OP yes/no is a trusted single party — a FROST cosign is an unforgeable t-of-n signature — so PCA's step-up is cryptographically stronger; this just gives it the industry-standard async-approval + binding-message on-ramp.

**Risk-adaptive gating** is the point: if every action prompts, humans blanket-approve (Anthropic observed 93% blanket-approval under always-prompt). Only a tier-3 step-up (human-required, typically irreversible) is routed through CIBA; tier-2 (guardian auto-cosign) and tier-1 (`auto`) never interrupt a person.

## Install

```sh
npm i @atlasauth/pca-ciba
```

Depends on the core `@atlasauth/pca` (installed transitively).

## Usage

```ts
import { reviewAction } from '@atlasauth/pca';
import { requiresCiba, createCibaBroker, cibaDecisionToCosign } from '@atlasauth/pca-ciba';

const review = reviewAction(agent, 'stripe.refund', 'charge:ch_1', { amount: 480 }, { goal: 'reconcile October refunds' });

if (requiresCiba(review) && review.kind === 'step_up') {
  const broker = createCibaBroker({ onComplete: (s) => notify(s) }); // PING/PUSH; omit for POLL
  const ciba = broker.start(review.request, { actsFor: 'support-bot', loginHint: 'owner@acme' });
  // ciba.binding_message:
  //   "Approve stripe.refund $480 on charge:ch_1 — because you asked support-bot to 'reconcile October refunds'"

  // POLL: broker.poll(ciba.auth_req_id).status → 'pending' | 'approved' | 'denied' | 'expired'
  // The human acts out of band:
  const session = broker.resolve(ciba.auth_req_id, 'approve', 'owner@acme');

  // Fold the decision back into the trust budget (the real cryptographic cosign is FROST, separate):
  const { budget } = cibaDecisionToCosign(session.status === 'approved' ? 'approve' : 'deny', agent.budget, agent.policy.riskPolicy, Date.now());
}
```

`toCibaAuthRequest(stepUp, opts?)` is the pure mapping (step-up → CIBA request) if you want to drive your own broker or a real OP.

This computes approval envelopes and the derived trust budget; it authorises nothing on its own. The resource server's verifier and the FROST cosigners remain the authority at run time.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
