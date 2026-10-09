# @atlasauth/pca-authzen

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

## Status

The PDP is only as strong as the `resolve` callback you provide: it decides against the grant, policy and budget you hand it, and it keeps no state of its own. Cryptography in the underlying PCA packages is unaudited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
