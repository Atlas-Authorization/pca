---
title: PCA in front of an MCP server
order: 45
---

# PCA in front of an MCP server, and bringing your own policy engine

## One URL change

Put the PCA gateway in front of an existing MCP server or agent service and point clients at the gateway instead of the server. The server does not change. Each request reaches it only after the gateway has verified, offline, a proof-carrying action for its audience that carries the capability the route needs; in full-policy mode (the default) it also checks the grant's limits and caveats against the real request parameters, revocation and the replay counter. Anything without a valid proof is refused. See the `@atlasauth/pca-gateway` package for the route map and options, and the MCP quickstart for the client side.

What this gives you that a token or a hosted decision does not:

- **Delegation is a signed chain.** Each hop appends restrictions and signs them; nothing downstream can remove a restriction an earlier hop added. A trust ceiling is just a caveat.
- **The proof is checked offline**, by the gateway and again by any resource server behind it, with no call back to a policy service.
- **Every decision can be witnessed** in a transparency log.

## Bringing your own policy engine

If you already run a policy engine (OPA, Cedar, a ReBAC service, an AuthZEN endpoint), keep it, and let its answer be one more restriction, never the authority itself:

- **As a discharge.** Mint grants with a `needs_discharge` caveat naming your engine as an issuer of class `org`. Your engine evaluates the request and, on allow, signs a short-lived discharge bound to the hop (or to the exact action). The resource server checks the discharge against the key it pinned and still verifies the whole proof. A deny, or no answer, means no discharge, and the action is refused.
- **As a fact.** Feed the engine's answer into the verifier as a signed oracle fact read only by `tighten[]` rules, so it can add friction but never admit anything the grant does not allow.

In both cases the per-action proof stays the authority: an engine's allow cannot widen a grant, and an engine that is down cannot open anything.

The gateway accepts discharges in full-policy mode. Give the policy a `k1` member with your pins (or a function returning them); the client presents discharges in the `PCA-Discharges` header (base64url JSON array, as for `requirePCA` and the native guards) and a narrow block in `PCA-Narrow`. When the request body is not the signed params (function `params`), body members `pca_discharges` and `pca_narrow` also work. Without a `k1` configuration, a grant whose chain asks for a discharge is refused.

```ts
const gateway = createGateway({
  audience: 'ins_acme',
  routes: [{ method: 'POST', path: '/refunds/*', capability: { verb: 'stripe.refund' } }],
  resolveGrant,
  policy: { mode: 'full', params: 'body', state, isRevoked, k1: { pins: [{ label: 'opa', class: 'org', pk: OPA_DISCHARGE_KEY }] } },
});
```
