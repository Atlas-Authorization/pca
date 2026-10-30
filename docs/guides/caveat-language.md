---
title: Caveat language
order: 46
---

# Caveat language

A grant carries caveats, and a caveat only ever removes authority. This guide covers the five caveats that need more
than the grant itself to decide: a **third-party caveat** (`needs_discharge`), a **seal** (`sealed`), a **narrow
block**, a **use counter** (`max_uses`) and a **derived check** (`derive`). You will write each one, evaluate it, and
see exactly when it refuses.

## The problem

The plain caveats (`expires`, `max_spend`, `reversibility_max` and friends) look at the action. Real policies also say:

- "only if the risk team approves" (a decision made by someone else),
- "and nobody below this agent may delegate further",
- "this one agent may tighten its own authority for the next five minutes",
- "at most two refunds, ever",
- "refund up to 100, unless there were already three refunds this hour".

Each of these is still a restriction. A verifier that does not know the caveat refuses the chain, so adding one can
never widen anything.

## Setup

```ts
import {
  InMemoryReplayStore, attenuate, b64u, boundCaveats, capHash, encodeKey, evaluateK1, generateKeyPair, mintRoot,
  reserveMaxUses, signDischarge, signNarrow, verifyChain, type Caveat, type DischargePin,
} from '@atlasauth/pca';

const NOW = Date.now();
const key = () => { const k = generateKeyPair(); return { sk: k.secretKey, pub: encodeKey(k.publicKey) }; };
const principal = key(), agent = key(), approver = key();
const root = (caveats: Caveat[]) =>
  mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats });
```

`evaluateK1(grant, chain, input, { now, action })` is the one call that evaluates all five. It returns
`{ ok, failed, reasons, plain, bound }`. `failed` lists the types that refused, `reasons` says why, `plain` carries any
ordinary caveats a narrow block added (you evaluate those with your usual evaluator), and `bound` is what
`max_uses` needs later. It never throws: a malformed caveat is a refusal.

## 1. Third-party caveats and discharges

The grant says "valid only with a discharge from `risk-team`, and only if `risk_score` is at most 30". The verifier,
not the token, decides which key is `risk-team`.

```ts
const pin: DischargePin = { label: 'risk-team', class: 'human', pk: approver.pub }; // your configuration
const grant = root([{
  type: 'needs_discharge', id: 'kyc', issuer: 'risk-team', issuer_class: 'human',
  bind: 'chain_hop', ttl_ms: 600_000, require: [{ claim: 'risk_score', op: 'lte', value: 30 }],
}]);

// the approver signs this after its own review; the agent carries it with the action
const discharge = signDischarge({
  v: 1, kind: 'pca-discharge', caveat_id: 'kyc', issuer: 'risk-team', cap_hash: capHash(grant), bind: 'chain_hop',
  claims: { risk_score: 20 }, iat: NOW - 1000, not_after: NOW + 1000, nonce: b64u(new Uint8Array(16).fill(5)),
}, approver.sk);

evaluateK1(grant, [grant], { pins: [pin], discharges: [discharge] }, { now: NOW }).ok; // true
evaluateK1(grant, [grant], { pins: [pin], discharges: [] }, { now: NOW }).failed;      // ['needs_discharge']
```

Expected: the first call is `true`; with no discharge, a discharge whose claim is 80, or a discharge signed by a key
nobody pinned, it is `['needs_discharge']`.

Things to know:

- The discharge is bound to the hop that carries the caveat (`cap_hash`). One lifted onto another hop or another
  grant does not verify.
- `bind: 'action'` binds it to a single action instead; pass the action's digest as `action_digest`.
- A discharge lives at most 24 hours (`ttl_ms` is capped at 86,400,000).
- `dischargeRequests(grant, chain, actionDigest)` lists what a holder still has to collect, one entry per
  undischarged caveat, so an agent can ask the right approver.
- A `class` mismatch is refused: a `model` pin cannot discharge a caveat that demands a `human`.

## 2. Seal

`sealed` means no hop may be appended below the hop that carries it.

```ts
const sealed = root([{ type: 'sealed' }]);
const below = attenuate(sealed, [], agent.sk);

verifyChain([sealed, below], principal.pub).ok;                // true: the chain is well formed
evaluateK1(sealed, [sealed, below], {}, { now: NOW }).failed;  // ['sealed']
evaluateK1(sealed, [sealed], {}, { now: NOW }).ok;             // true
```

A holder cannot remove a seal by re-signing: dropping or reordering an inherited caveat fails chain verification. A
seal placed by a sub-agent stops that sub-agent's own children, not its siblings.

## 3. Narrow block

A narrow block is a short-lived tightening the leaf holder signs, with no new hop. It is a prompt-injection firewall:
before an agent reads untrusted text it can narrow itself for five minutes, and the narrowing is checked even if the
text talks the agent into asking for more.

```ts
const open = root([]);
const narrow = signNarrow({
  v: 1, kind: 'pca-narrow', cap_hash: capHash(open), holder: agent.pub,
  caveats: [{ type: 'expires', at: NOW + 60_000 }], iat: NOW - 1, not_after: NOW + 60_000, nonce: b64u(new Uint8Array(16).fill(3)),
}, agent.sk);

const r = evaluateK1(open, [open], { narrow }, { now: NOW });
r.ok;     // true
r.plain;  // [{ type: 'expires', at: NOW + 60000 }]: evaluate these with your usual caveat evaluator
```

It must be signed by the leaf holder, bound to the leaf hop, and inside its window; anything else fails with
`failed: ['narrow']`. A narrow block can carry one to sixteen caveats and cannot carry structure that only a hop can
introduce (`envelope`, `sealed`, `budget_alloc`, `intent_session`): `signNarrow` throws for those.

## 4. `max_uses`

`max_uses` allows exactly `n` uses. Uses are counted in your replay store, so concurrent actions never share one, and
a durable shared store counts across processes.

```ts
const limited = root([{ type: 'max_uses', id: 'refunds', n: 2, until: NOW + 10_000 }]);
const store = new InMemoryReplayStore();
const bound = boundCaveats(limited, [limited]) ?? [];

for (let i = 0; i < 3; i++) console.log((await reserveMaxUses(store, bound, NOW)).ok);  // true, true, false
```

`evaluateK1` only checks that the caveat is well formed and not expired. Call `reserveMaxUses` once, after everything
else has allowed the action, because a use that is spent stays spent. If the store cannot answer, the result is a
refusal (`max_uses error (fail closed)`), never an allow. Use a durable store in production.

## 5. `derive`

`derive` computes a few facts and checks them. A fact can be an action parameter, the action's verb or resource, a
count of this holder's recent admitted actions (from your own history, never the request), or a claim from a
discharge that verified. The check is a small expression of comparisons and `and` / `or` / `not`.

```ts
const guard = root([{
  type: 'derive', id: 'refund-guard',
  defs: [
    { name: 'amount', kind: 'param', path: 'amount' },
    { name: 'recent', kind: 'count', window_ms: 3_600_000, verb: 'refund.issue' },
  ],
  check: { op: 'and', args: [
    { op: 'lte', a: { ref: 'amount' }, b: { const: 100 } },
    { op: 'lt',  a: { ref: 'recent' }, b: { const: 3 } },
  ] },
}]);
const action = (params: Record<string, number>) => ({ verb: 'refund.issue', resource: 'orders/1', params });
const history = [{ t: NOW - 1000, verb: 'refund.issue', resource: 'orders/1' }];  // your own record

evaluateK1(guard, [guard], { history }, { now: NOW, action: action({ amount: 50 }) }).ok;   // true
evaluateK1(guard, [guard], { history }, { now: NOW, action: action({ amount: 500 }) }).ok;  // false
evaluateK1(guard, [guard], { history }, { now: NOW, action: action({}) }).failed;           // ['derive']
```

The last call has no `amount`. A missing fact makes the check **unknown**, and unknown refuses (`reasons` says
`derive check is unknown (a fact is missing)`). Limits: at most 8 defs, 32 expression nodes, depth 4 and a 30 day
window; a def can only refer to defs before it, so there is no recursion.

## Failure modes

| You see | Cause |
|---|---|
| every caveat in this guide fails with "the caveat language is not configured" | you passed `undefined` instead of an input object. Pass `{}` at least. |
| `needs_discharge` fails with "signature invalid" | the pin's key is not the one that signed. The verifier never reads a key from the token. |
| `needs_discharge` fails with "bound to another hop" | the discharge was made for a different hop or grant. |
| `sealed` fails | a hop sits below the sealing hop. This is the intended refusal. |
| `max_uses` says "exhausted" | all `n` slots are spent. A slot taken by an action that a later check refused stays spent. |
| `derive` fails with "unknown" | a parameter, history or claim it reads is absent. Supply it or fix the check. |
| a caveat of an unfamiliar type fails | unknown caveat types are unsatisfied by design. |

## Run it

The `caveats` script of the `pca-guides-a` example runs every snippet above and prints each outcome. It ends with
`All outcomes as expected.` or exits non-zero.

## Next step

- Put the discharge flow behind a real route with [Add PCA to your framework](./framework-recipes.md).
- Decide who may approve what with [what you sign](./what-you-sign.md).
- Look up every refusal code in the [refusal reference](../reference/refusals.md).
