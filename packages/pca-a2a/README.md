# @atlasauth/pca-a2a

> Maturity: **production**. Breaking changes to APIs or defaults are never made in a patch release. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

A2A (Agent2Agent) adapter for Proof-Carrying Authority (PCA). A2A defines how agents discover each other and exchange tasks; it does not prove that a relayed request is authorized by the principal behind it. This package binds PCA proofs onto three A2A surfaces, failing closed throughout:

1. **Proof-carrying tasks** - attach a PCActn (a signed single-action proof with its capability chain) to a Task or Message under a namespaced `metadata` key, and verify it on receipt.
2. **Signed Agent Cards** - issue and validate an A2A `AgentCardSignature` (a detached JWS, via `jose`) whose protected header commits to the agent's PCA passport id.
3. **AP2 payment profile** - map a PCActn to an AP2-shaped Payment Mandate that carries its authority by reference to the proof.

## Install

```sh
npm i @atlasauth/pca-a2a
```

Depends on `@atlasauth/pca` and `jose` (installed transitively). For the full AP2 Intent/Cart/Payment chain and settlement hooks, see `@atlasauth/pca-ap2`.

## Usage

```ts
import { buildPCActn } from '@atlasauth/pca';
import {
  attachPcaToA2ATask, pcaA2AMiddleware,
  issueSignedAgentCard, verifyAgentCard,
  a2aPaymentMandateFromPca, verifyA2APaymentMandate,
} from '@atlasauth/pca-a2a';

// Sender: build a PCActn with @atlasauth/pca, then ride it on the task.
const pcActn = buildPCActn({ grant, chain: [grant], plan, nodeId: 'buy-1', counter: 1,
                             signerSecret: agentSecret, aud: 'my-rs' });
const task = attachPcaToA2ATask({ id: 't1', status: { state: 'submitted' } }, pcActn);

// Receiver: guard incoming tasks with the FULL verifier under an authority you trust: your stored `grant`, or the
// principal the chain must be rooted at (`expectedRootIssuer`). Supply your view of the action (plan, budget, risk)
// and a revocation hook; the grant's predicates, limits, budget and threshold decide.
const guard = pcaA2AMiddleware({
  aud: 'my-rs',
  expectedRootIssuer: principalPublicKey,
  allowedSuites: ['ed25519'],
  hooks: { revocation: ({ grant }) => ({ enforced: true, ok: !revoked.has(grant.id) }) },
  context: (p) => ({ params: paramsFor(p), plan: authorizedPlanFor(p), planAuthorized: true, budget: budgetFor(p) }),
});
const verdict = await guard(task);       // { ok: true, result, pcActn } | { ok: false, reason, result }

// Signed Agent Card (key is a jose KeyLike, Uint8Array or JWK).
const card = await issueSignedAgentCard({ name: 'Buyer', url: 'https://a.example' }, privateKey,
                                        { passport: { id: 'pp_1' } });
await verifyAgentCard(card, { key: publicKey });  // { ok: true, passportRef: 'pp_1', ... }

// Payment mandate that points at the PCActn. The PCActn's params must be { amount: 120, currency: 'USD', merchant: 'acme' }.
const mandate = a2aPaymentMandateFromPca(pcActn, {
  amount: { currency: 'USD', value: 120 }, paymentMethod: { type: 'card' }, merchant: 'acme',
});
// context.params (the params plaintext) is required: the mandate is checked against what the PCActn authorized.
await verifyA2APaymentMandate(mandate, pcActn, { aud: 'my-rs', grant: storedGrant, hooks, context });
```

**The mandate is bound field by field (breaking).** A Payment Mandate is unsigned, so `verifyA2APaymentMandate` refuses it
unless every field a payer acts on is what the PCActn authorized: the `x_pca` backreference (`pcactn_digest`, `aud`, `verb`,
`resource`, `params_digest`, `grant_ref`, `leaf_holder`) equals the PCActn's; `context.params` is required and must open
`action.params_digest`; `amount.value` / `amount.currency` equal the params' own `amount` / `currency` exactly; `merchant`
equals the params' `merchant` (or both are absent); a `payment_method` in the params must equal the mandate's; and
`human_present: true` needs `humanSignerSet` and a PCActn whose threshold shares verify at t=3.

By default a guard requires a proof (`require: true`); with `require: false` a task without a proof passes, but a proof that is present and invalid is still rejected.

**Authority is required (breaking).** Every verifier needs `grant` (from your store) or `expectedRootIssuer`; without
either it throws `A2AAuthorityError` (`code: 'authority_required'`): a chain is never its own authority. Without `grant`,
a post-quantum or hybrid root is admitted only under a server-side pin (`pqPins`, the `pq_pin` check).

**The decision is the full verifier (breaking).** `verifyA2ATask`, `verifyA2APaymentMandate` and the middleware run
`verifyPCActn` with `requireChecks` defaulting to `DEFAULT_REQUIRED_CHECKS` (default-deny): the grant's predicates,
limits and caveats, your plan authorization, revocation, the trust budget (absent: deny-metered) and the
server-derived threshold. `result` is the `PcaVerdict` (plus `reason`).

## API

- Tasks: `attachPcaToA2ATask`, `attachPcaToA2AMessage`, `extractPca`, `extractPcaFromMessage`, `verifyA2ATask`, `pcaA2AMiddleware`, `PCA_A2A_EXTENSION_URI`.
- Agent Cards: `issueSignedAgentCard`, `verifyAgentCard` (verify with a single `key` or a `jwks`).
- Payments: `a2aPaymentMandateFromPca`, `pcaBindingFromA2APaymentMandate`, `verifyA2APaymentMandate`, `A2A_AP2_CONTEXT`.
- `human_present` is `false` unless you pass `humanSignerSet` (the builder then verifies the principal co-signature at t=3) or assert `humanPresent: true` yourself. A `threshold` field alone is never trusted (breaking change).

## Failure modes

| Missing or wrong | Result |
|---|---|
| Card with no signatures, body mutated after signing, wrong key, unresolvable key, no key or JWKS supplied | `verifyAgentCard` `{ ok: false, reason }` |
| Card with no JSON form (NaN, lone surrogate, cycle) | `{ ok: false, reason: 'agent card has no canonical form: ...' }`; issuing throws |
| `schema: 'a2a-1.0'` and the card is missing a required A2A 1.0 field or has a wrongly typed one | `{ ok: false }` listing each path; issuing throws |
| `profile: 'a2a-1.0'` without a `kid` | issuing throws |
| Non-canonical JWS spelling | rejected before the signature is checked |
| Task has no proof (with `require: true`) | `ok: false` |
| Proof present but invalid, or the decision is not allow | `ok: false`, the verdict in `result` |
| No `grant` and no `expectedRootIssuer` | throws `A2AAuthorityError` (`authority_required`) |
| Mandate amount, currency, merchant, payment method or `x_pca` field differs from the PCActn's; params plaintext missing | `ok: false` |
| Float, negative or unsafe amount | refused when building and when verifying |
| `human_present: true` without a verified t=3 principal co-signature | refused |

## Limits

- The signed bytes are RFC 8785 canonical JSON. A card signed by an earlier 0.5 build over PCA canonical JSON differs only for keys that mix characters above U+FFFF with U+E000 to U+FFFF, and for floats; re-sign such a card.
- `validateAgentCard1` checks the A2A 1.0 `AgentCard` message (names in ProtoJSON camelCase), not the contents of security schemes. It is opt-in (`schema: 'a2a-1.0'`).
- A card proves who signed it; to trust the agent's authority, resolve the passport and verify a PCActn.

## Status

Production. Pinned to A2A 1.0.0 (Agent Card signing, section 8.4).

- Agent Card signatures: by default a detached JWS with an unencoded payload (`b64:false`). Pass `profile: 'a2a-1.0'` (and a `kid`) to `issueSignedAgentCard` to produce the A2A 1.0 form (`BASE64URL(header).BASE64URL(payload)`, `typ: "JOSE"`), which any A2A 1.0 verifier can check. `verifyAgentCard` accepts both forms. The signed bytes are the RFC 8785 canonical JSON of the card, checked against the RFC's examples and an independent reference.
- The A2A object model is structural and permissive, not a full A2A SDK.
- The payment mandate is a PCA-defined envelope, not an AP2 credential: AP2 mandates are SD-JWTs (use `@atlasauth/pca-ap2`) and AP2 defines no JSON-LD context, so `A2A_AP2_CONTEXT` is an identifier chosen here. Amounts are integers in minor units; a float, negative or unsafe amount is refused when building and when verifying. PCA fields live in the non-standard `x_pca` extension.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on each card signature's protected and signature segments: one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.
