# @atlasauth/pca-authzen

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Proof-Carrying Authority (PCA) behind the OpenID AuthZEN Authorization API. It gives you a Policy Decision Point (PDP) so any AuthZEN-speaking Policy Enforcement Point (an API gateway, a service mesh sidecar, an MCP host) can ask "can this subject do this action on this resource?" and get a boolean decision backed by the PCA verifier and policy engine.

- If the request `context` carries a signed PCActn (key `pca_action`), the PDP verifies it and then runs the deterministic policy decision.
- Otherwise it evaluates the declared policy statically (exact admission via `@atlasauth/pca-analyzer`).
- Everything fails closed: an unresolved policy, a malformed or foreign PCActn, a verifier rejection, a policy denial or a thrown error all return `decision: false`.

It exposes Access Evaluation, Access Evaluations (batch), the COAZ profile for MCP tool authorization, and an approval-required reference (AARP style) when a step-up cosign is needed.

## Install

```sh
npm i @atlasauth/pca-authzen @atlasauth/pca @atlasauth/pca-analyzer
```

## Usage

```ts
import { agent, generateKeyPair } from '@atlasauth/pca';
import { authzenPdp, authzenHandler, PCA_ACTION_KEY, isApprovalRequired } from '@atlasauth/pca-authzen';

const a = agent({
  principal: generateKeyPair(),
  goal: 'reconcile october refunds',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500' },
  aud: 'rs_demo',
});

const pdp = authzenPdp({
  audience: 'rs_demo',
  // Look up the authority for each request. Return null to deny.
  resolve: () => ({ grant: a.grant, chain: a.chain, policy: a.policy, budget: a.budget }),
});

const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' });

const resp = await pdp.evaluate({
  subject: { type: 'agent', id: 'a1' },
  action: { name: 'stripe.refund', properties: { amount: 42, currency: 'usd' } },
  resource: { type: 'charge', id: 'ch_1' },
  context: { [PCA_ACTION_KEY]: encoded },
});
// resp.decision is a boolean; isApprovalRequired(resp) is true for a pending step-up

// Framework-agnostic HTTP handler for the standard AuthZEN paths:
const handle = authzenHandler(pdp); // handle({ path: '/access/v1/evaluation', body }) -> { status, body }
```

The signed PCActn must match the requested action, resource and parameters, otherwise the decision is false. If you omit `audience` and the PCActn carries an `aud`, the PDP fails closed.

## API

- `authzenPdp(config)` returns `{ evaluate, evaluations, evaluateTool }`
- `authzenHandler(pdp)`, with path constants `EVALUATION_PATH`, `EVALUATIONS_PATH`, `COAZ_TOOL_PATH`
- `approvalOf`, `isApprovalRequired`, `PCA_ACTION_KEY`, `PCA_APPROVAL_KEY`
- Request guards (`isAccessEvaluationRequest`, ...) and `defaultToAction` (override per request with `toAction`)

## Failure modes

Every row is a `200` with `decision: false` (a deny is not an HTTP error) unless a status is shown. The context carries `reason_admin` / `reason_user`; failures that are errors also carry an `error: { status, message }` member (AuthZEN section 7.2.1).

| Situation | Result |
| --- | --- |
| `resolve` returns nothing | deny |
| `resolve` or any step throws | deny, `error.status` 500 |
| `pca_action` present but not a string / not decodable | deny (malformed PCActn) |
| proof is for another verb, resource or params than the request | deny |
| proof fails verification (signature, chain, audience, expiry, wrong grant) | deny, `stage: verify` with the failing checks |
| audience omitted in config while the proof carries one | deny |
| policy does not permit | deny, `stage: policy` |
| policy needs a guardian or human co-sign | deny with an approval reference (`pca_approval`) |
| no `pca_action` and `requireProof: true` | deny |
| `requireAuthorizer: true` without an `authorizer` | deny |
| `authorizer` refuses (replay, revocation, budget) or throws | deny, `stage: authorize` |
| boxcar item missing subject, action or resource | that item denied, `error.status` 400 |
| unknown `evaluations_semantic`, or more items than `maxEvaluations` | every item denied, `error.status` 400 |
| malformed request body | HTTP 400 |
| unknown path (including the search endpoints, which are not implemented) | HTTP 404 |
| the PDP throws inside the handler | HTTP 500 |

## Replay, revocation and proof-only answers

Out of the box the PDP checks the proof but keeps no state, so the same valid PCActn can be accepted repeatedly, and a request with no PCActn is answered by static admission ("could this ever be allowed?"). For a PEP that enforces the answer:

```ts
import { createAuthorizer, memoryPcaStore } from '@atlasauth/pca';

const pdp = authzenPdp({
  audience: 'rs_demo',
  resolve,
  requireProof: true,          // no PCActn, no permit
  requireAuthorizer: true,     // no replay/revocation state, no permit
  authorizer: createAuthorizer({ audience: 'rs_demo', resolveGrant, budgetStore: sharedStore, hooks: { revocation }, plan: 'single-step' }),
});
```

`memoryPcaStore()` is a single-process store for tests; use a shared store in production.

## Limits

- Pinned to the OpenID AuthZEN Authorization API 1.0 (final, 11 January 2026): the Access Evaluation and Access Evaluations endpoints, including the three `evaluations_semantic` values and the rule that an absent or empty `evaluations` array is a single evaluation. The Search APIs and the PDP metadata document are not implemented; the COAZ and approval-required profiles are extensions of this package.
- The AuthZEN interoperability scenarios (a todo application decided by user and role policy) are not reproduced: this PDP decides by capability chain and policy, not by user records, so those expected decisions do not apply. The request and response shapes follow the specification examples.
- With `permit_on_first_permit` the response lists the earlier denies before the permit; `deny_on_first_deny` stops at and includes the first deny.
- A boxcar is unbounded unless `maxEvaluations` is set.

## Status

The PDP is only as strong as the `resolve` callback you provide: it decides against the grant, policy and budget you hand it, and it keeps no state of its own. Cryptography in the underlying PCA packages is unaudited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
