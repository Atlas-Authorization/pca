---
title: What you see is what you sign
order: 42
---

# What you see is what you sign

An approval used to sign the digest of the action. What the human saw was whatever the wallet, the push or the chat message drew. This guide covers the three pieces that close that gap: the canonical approval render, the credential vault's proxy mode, and spend rails.

## 1. The canonical approval render

`renderApproval(def, params)` (in `@atlasauth/pca-actions`) builds `R`, a deterministic, locale-free list of **every** parameter of the action: id, role, value and resolved unit (money is an integer in minor units, with its currency code). It is made only from the action definition and the parameters that will run. A model never produces any part of it.

The approval is signed over:

```
challenge = SHA-256( "atlas-pca/approval-challenge/v1" 0x00 || action_digest || H(R) )
H(R)      = hashCanonical({ d: "atlas-pca/approval-render/v1", render: R })
```

- The approver client re-renders from its pinned definition (`approverRenderCheck`) and refuses to sign a digest it cannot reproduce.
- The resource server recomputes `H(R)` from the **executed** parameters and its own definition (`renderDigestForAction`, which also checks the parameters are the ones the PCActn signed) and passes it to the guard as `escalation.render`. An escalation answer carries `render_digest`; the guard refuses an answer for another render, an answer with none, and an answer that carries a render the guard did not recompute. **This is on by default**: a guard with no `escalation.render` refuses every escalation answer (reason `an approval render is required`). Set the explicit, documented `insecureUnboundApproval: true` only to keep the pre-render behaviour, where an answer binds the action digest alone and what the approver was shown is not committed.
- Nothing partial is rendered. A parameter the definition does not declare, a missing required parameter, a float, a `null`, a lone surrogate, a wrong type, an unresolved currency or a key containing a dot is a typed refusal.
- An action whose definition has no valid signed confirmation renders with `unreviewed: true` (a different digest). The approval screen must show every value raw and must not offer single-tap approval (`singleTapAllowed(render)`).
- `reviewAction` binds the render by default: without a `renderer` a step-up is a **deny** (`approval render required`), and a renderer that throws is a deny too. `renderersFromDefs(defs, review)` (`@atlasauth/pca-actions`) derives the renderer from the pinned action definitions, so `reviewAction(agent, verb, resource, params, { renderer: renderersFromDefs(defs, review) })` attaches the render and its digest to every request. The framework adapters (`pca-openai-agents`, `pca-vercel-ai`, `pca-mastra`) take the same `renderer` option. `insecureUnboundApproval: true` is the explicit, documented opt-out. Every channel (Slack, webhook, email, push, SMS) lists all fields and a match code made of six words of `H(R)`.

### Channels and profiles

| Surface | What carries the commitment |
|---|---|
| WebAuthn | `buildApprovalChallenge(pcactn, renderDigest)` is the challenge the passkey signs. |
| Secure Payment Confirmation | `verifyAssertion(..., { payment })`: the assertion must be `payment.get`, and the signed `clientData.payment` must equal `spcExpectation(render, topOrigin)` (total, payee, `topOrigin`, `rpId`). The challenge is the same approval challenge. Spec: <https://www.w3.org/TR/secure-payment-confirmation/>. |
| PSD2 RTS Article 5 (dynamic linking) | `psd2Linking(render)` extracts exactly one amount and one payee and refuses an unreviewed definition. `approvalBatch(items)` commits to the per-currency totals, the payee set and every item, for Article 5(3)(b). |
| CIBA | `toCibaAuthRequest` adds RFC 9396 `authorization_details` carrying the render, the digest, and a match code in the binding message. The binding message stays advisory text; the digest is what is signed. |

PSD2 text (Commission Delegated Regulation (EU) 2018/389, Article 5): 5(1)(a) the payer is made aware of the amount and the payee; (b) the authentication code is specific to them; (c) the accepted code corresponds to them; (d) any change invalidates it; 5(3)(b) for a batch the code is specific to the total amount and the payees. The text was checked against the UK-retained copy at legislation.gov.uk; the EUR-Lex original could not be fetched when this was written.

### In the native SDKs

Python, Go, Ruby, PHP, Rust, Java, Kotlin, .NET and Swift implement the render, `H(R)`, the challenge, the match code and the escalation binding, and replay the shared vectors byte for byte. Every native `authorize` entry point and guard takes the recomputation (`escalation_render`, `EscalationRender`, `escalationRender`, `with_escalation_render`) and applies the same default, with the same explicit opt-out.

## 2. The credential vault: proxy mode

`pca-connect` no longer hands an agent a bare bearer token for scoped use.

- **Scopes come from the action.** Give the vault `actions: (verb) => VaultAction`. An unknown verb, or an action whose definition is not confirmed, releases nothing. The scopes are the action's `scopes_min`, which must lie inside the grant and inside the stored connection.
- **Proxy mode.** `vault.proxyCall(pcActn, request, { provider })` makes the outbound call itself. The pinned extractor (`httpExtractor`) maps the request back to the action parameters (pinned origin and path template, allowed query keys, strict-JSON or form body members, fixed members), and the call is made only if their digest equals the PCActn's `params_digest`. Extra or repeated members, other hosts and agent-set `Authorization`, `Cookie` or `Host` headers are refused **before** the action is spent. Redirects are not followed, and a response that echoes the token is redacted.
- **Receipts.** With `receipts: { secretKey }` every release or call yields a signed `pca-release-receipt` (action digest, provider, scopes the token carried, request digest, HTTP status, outcome).
- **Plain release is an explicit, insecure opt-in.** `getConnectionToken` throws unless the vault was built with `insecureBearerRelease: true`. A bearer token is good for anything inside its scopes until it expires, so the holder can use it on a call other than the one authorized. With `actions` set, a bearer release also refuses a stored token that carries more scopes than the action needs and never outlives the PCActn.

## 3. Spend rails

`@atlasauth/pca-payments` mirrors a grant onto a payment instrument and answers its real-time authorization callback from `authorizeChargeAtomic`.

- `railLimits(mandate, now, { actionTraits })`: per-authorization ceiling = min(auto-approve threshold, remaining autonomous budget), total = remaining budget, categories = the mandate's allowlist narrowed by `mcc.cNNNN` traits (an empty intersection throws; a card with no category control is refused unless `allowAnyCategory`).
- `createRailAuthorizer`: approves only an `auto` decision. A step-up, a deny, an unknown card, a missing merchant id, a bad amount, an exception and a missed latency budget (default 1500 ms) all decline.
- `reconcileSettlement`: more than approved, another merchant or currency, or a second capture returns `freeze_grant`.
- Stripe Issuing (`@atlasauth/pca-payments/stripe-issuing`): `stripeCardParams` builds the card with `per_authorization` and `all_time` spending limits and `allowed_categories`; `createStripeIssuingWebhook` verifies `Stripe-Signature` over the raw body, answers the `issuing_authorization.request` event within the budget, and sends the `Stripe-Version` header the endpoint requires. **Set the Issuing timeout response to decline and turn Autopilot off**: if the endpoint is slow or down, Stripe applies those settings, not this code.

The rail is a second enforcement point. Its limits are an upper-bounded copy of the PCA limits; PCA never relaxes because the rail would have blocked.
