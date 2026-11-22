---
title: Refusal reasons and how to fix them
order: 5
---

# Refusal reasons and how to fix them

Every refusal names the check that failed, then says why: `<check>: <reason>`. The check name is stable across all ten
languages, so this table applies to a Python, Go or .NET server as much as to a TypeScript one. In TypeScript,
`explainRefusal(reason)` returns the entry for a reason: what it means, how to fix it, and the link to this page.

```ts
import { explainRefusal } from '@atlasauth/pca';

const h = explainRefusal('audience: the proof is for ins_a, this server is ins_b');
// { check: 'audience', meaning: '...', fix: '...', docs: '.../reference/refusals.md#audience' }
```

A refusal is the guard working. Most of these mean a misconfiguration the first time you wire PCA up, and a real
attempt that was stopped afterwards. The table says which.

## authorize_config

The guard was built without a component it needs, so it refuses every request (HTTP 403) and names what is missing:
`authorize_config: missing required component(s): state_store, is_revoked (fail closed)`.

Fix: supply the named components. They are the same in every language: your audience, a way to look up grants, a
replay store, and a revocation source. In TypeScript, `protect()` fills in safe defaults for all of them. The guard
never falls back to checking only the signature; that is an explicit opt-in (`signatureOnly`).

## operation

The signed action is not the operation this route executes: another verb, another resource, or other parameters.
First time: the agent and the server describe the action differently (a different verb string, a different resource
format). Fix by using one mapping on both sides; the server's mapping comes from its own routing, never from the proof.
Afterwards: a proof being used for something it was not signed for.

## audience

The proof was signed for a different server. First time: the agent's `aud` and the server's `audience` differ by a
character or a trailing slash. Afterwards: a proof stolen from another service.

## replay

The counter in the proof is not greater than the last one this server accepted for the grant and agent, or the same
proof was already used. First time: two servers share no store, or a test sends the same proof twice. Fix: one shared
replay store for all instances of the server, and a fresh proof for each action. A retry of an action that already
ran is answered from an operation record, not by sending the proof again.

## plan_root_authorized

The plan the action belongs to was not authorized by the principal. First time: you used a multi-step plan without
authorizing its root. Fix: use a single-step plan (the default in `protect()` and in every native `authorize`
option set), or have the principal authorize the committed plan.

## revocation

The grant was revoked, or no revocation source is configured. Configure one (`protect()` and the native options
require it) and revoke by grant id.

## validity

The proof is outside its validity window. Check that the two clocks agree, and request a fresh proof. `pca-doctor`
checks clock skew against a live deployment.

## grant_ref

The proof names a grant the server does not know. The grant comes from the server's own store, never from the request:
register the principal's grant with the server first.

## policy

The grant does not permit this action or these parameters: a predicate, a limit or a caveat failed. The reason names
the limit (`amount <= 500 not satisfied for stripe.refund on charge:ch_1`). If the action is legitimate, the principal
signs a wider grant; otherwise this is the system doing its job.

## risk_inputs

The server must supply a risk input and did not. Supply it in the `risk` option; the connector catalog derives the
common ones (`protect()` does this), or compute your own from data you trust. Inputs the agent claims never count.

## threshold

The risk of this action needs a co-signature from the principal (step-up). Collect it through the step-up flow; see
[Threshold and step-up](../concepts/threshold-and-step-up.md).

## chain

The delegation chain does not verify back to the grant, or the proof's signature does not verify. Rebuild the chain
with `delegate()` or `subAgent()`; a grant or hop edited after signing never verifies.

## freshness

The consistency token or revocation epoch is older than the server accepts. Refresh it from the guardian and retry.

## wire

The proof is not well-formed under the strict wire profile (padding in base64url, duplicate keys, wrong types). Send
it exactly as the library encodes it: header `PCA-Action`, or a JSON body `{ "pcactn": ... }`.
See [Wire formats](./wire-formats.md).
