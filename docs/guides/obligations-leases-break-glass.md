---
title: Obligations, leases and break glass
order: 14
---

# Obligations, leases and break glass

Three ways to keep an "allow" on a short leash.

| You want | Use | What it guarantees |
|---|---|---|
| "Allow, but log it, tell finance and redact the SSN" | **Obligations** | An enforcement point that cannot do every duty turns the allow into a deny |
| "Access that expires unless someone renews it, and dies when revoked" | **Leases** | A hard cap that renewal can never pass, a fresh reason on every renewal, separation of duties |
| "In an emergency, one agent may do one risky thing, loudly, and a human reviews it after" | **Break glass** | 24 hours at most, 16 uses at most, every use announced, the holder frozen if no one reviews |

None of these decides policy by itself. They sit next to the decision you already get from [`protect()` or `authorize`](./framework-recipes.md) and make it harder to misuse.

You need Node.js 20 or later:

```bash
npm install @atlasauth/pca @atlasauth/pca-grants
```

## 1. Obligations: an allow that carries duties

An allow may carry **obligations**, things the enforcement point must do for the action to go ahead. The vocabulary is closed: `log`, `notify`, `redact`, `watermark` and `require_receipt`. Each can carry a `due` time (epoch milliseconds).

```ts
import { collectObligations, mergeObligations, pepObligationGate, obligationOutcome } from '@atlasauth/pca';

const rules = [
  { id: 'big', when: { field: 'action.params.amount', op: 'gt', value: 100 }, obligations: [{ kind: 'notify', params: { to: 'finance' } }] },
  { id: 'pii', when: { field: 'env.contains_pii', op: 'eq', value: true }, obligations: [{ kind: 'redact', params: { fields: ['ssn'] } }] },
];

// the duties of every rule that applies (or might: a missing value adds the duties, never removes them)
const collected = collectObligations(rules, { action: { params: { amount: 500 } }, env: { contains_pii: true } });
// add one that comes from somewhere else
const merged = mergeObligations(collected.ok ? collected.obligations : [], [{ kind: 'require_receipt', due: Date.now() + 60_000 }]);
if (!merged.ok) throw new Error(merged.reason);
const duties = merged.obligations;

// the rule of the enforcement point: it lists the kinds it can perform
const gate = pepObligationGate('allow', false, duties, ['notify', 'redact', 'require_receipt']);
// { decision: 'allow', perform: [...3 duties], unsupported: [] }
```

`pepObligationGate` is the one place that turns (decision, duties, supported kinds) into an outcome:

- A point that supports only `['notify']` gets `decision: 'deny'` and `unsupported: ['redact', 'require_receipt']`. It must not run the action.
- A `deny` stays a deny and an unanswered `escalate` stays an escalate. Duties never soften a refusal.
- A malformed duty list, an unknown kind or a malformed `supported` list is a deny.

After the action, report what you did. A duty past its `due` time that was not reported makes the outcome `escalate` (freeze the holder or ask for a step-up). It never turns into an allow and never rewrites the decision already made.

```ts
const receipt = duties.findIndex((o) => o.kind === 'require_receipt');
obligationOutcome(duties, [], Date.now() + 61_000);
// { outcome: 'escalate', overdue: [receipt], status: 'obligation_unmet' }
obligationOutcome(duties, [receipt], Date.now() + 61_000); // the receipt was reported
// { outcome: 'ok', overdue: [] }
```

`overdue` and the reported list are indexes into the duty list. The list is sorted into a fixed order, so look an index up as above instead of assuming it.

## 2. Leases: access that has to be renewed

A **lease** is a signed record from a lease authority: a path, the grant it comes from, a holder, an expiry and a `max_ttl`. The cap runs from the first issue (`issued_at + max_ttl`) and renewal cannot move it. The verifier keeps the newest record per lease in a registry.

```ts
import { b64u, generateKeyPair, publicKeyOf } from '@atlasauth/pca';
import { LeaseRegistry, checkLease, memoryLeaseKv, renewLease, signLease, signLeaseRevocation } from '@atlasauth/pca-grants';

const authority = generateKeyPair();
const registry = new LeaseRegistry({ authorities: [b64u(publicKeyOf(authority.secretKey))] }, memoryLeaseKv());

const HOUR = 3_600_000;
const t0 = Date.now();
const lease = signLease(authority.secretKey, {
  lease_id: 'db-ro-1', path: 'db/prod/ro', grant_ref: 'grant-1', holder: 'agent-a', requester: 'owner-a', approvers: ['alice'],
  justification_digest: 'reason-1', seq: 1, issued_at: t0, renewed_at: t0, expires_at: t0 + HOUR, max_ttl: 4 * HOUR,
});
await registry.accept(lease);                       // { ok: true, replaced: true, seq: 1 }
await checkLease(lease, registry, t0 + 5 * 60_000); // { decision: 'allow', ... }
```

`checkLease` only answers "is this lease alive?". It does not verify the grant or the action; run that check as well.

Renewal needs a **new reason**: the `justification_digest` must differ from the last record's, or the renewal is refused as `stale_justification`. Ask for more time than the cap allows and you get the cap:

```ts
const r = await renewLease(authority.secretKey, registry, 'db-ro-1', {
  now: t0 + 80 * 60_000, increment: 10 * HOUR, justification_digest: 'reason-3',
});
// r.record.expires_at === t0 + 4 * HOUR
```

A renewal can carry a `veto` function (for a behavioural signal, say). It can refuse a renewal. It can never lengthen one.

Revoke one lease, everything under a path prefix, or everything made from a grant. A prefix covers a whole segment (`db/prod` covers `db/prod/ro`, not `db/production`). A revoked lease is dead at once and cannot be renewed.

```ts
await registry.revoke(signLeaseRevocation(authority.secretKey, { target: 'prefix', value: 'db/prod', revoked_at: t0 + 90 * 60_000 }));
// { ok: true, revoked: 1 }
```

**Separation of duties** is checked on every issue and renewal: approvers must be distinct, must not be the requester or the holder, must not appear in the holder's delegation chain (pass it as `accept(record, chain)`), and there must be at least `minApprovals` of them. A lease approved by its own holder is refused with code `sod`.

The store behind the registry must be durable in production: it holds the revocations. `memoryLeaseKv()` is for tests and a single process.

## 3. Break glass: the emergency exit

A **break-glass grant** is pre-authorized and sealed. It has a small budget and a short life, and it makes noise.

```ts
import { BreakGlassRegistry, memoryLeaseKv, signBreakGlass, signBreakGlassReview } from '@atlasauth/pca-grants';

const reviewer = generateKeyPair();
const bg = new BreakGlassRegistry(
  { authorities: [b64u(publicKeyOf(authority.secretKey))], reviewers: [b64u(publicKeyOf(reviewer.secretKey))] },
  memoryLeaseKv(),
);

const grant = signBreakGlass(authority.secretKey, {
  id: 'bg-1', holder: 'agent-a', grant_ref: 'grant-oncall', reason_digest: 'reason-digest',
  max_uses: 2, issued_at: t0, expires_at: t0 + HOUR, review_within: 30 * 60_000, notify_to: 'oncall-channel',
});
await bg.accept(grant, t0);

// the enforcement point tells the on-call channel first, then records the use
await bg.use({ id: 'bg-1', holder: 'agent-a', action_digest: 'action-1', now: t0 + 1000, notified: true });
// { decision: 'allow', id: 'bg-1', use: 1, remaining: 1, review_due: ... }
```

The rules are fixed:

- A use is recorded only when `notified: true`. Without it the use is refused (`not_notified`).
- The window is at most 24 hours and `max_uses` is 1 to 16. A longer window or bigger budget is refused when you sign it.
- The first use starts a clock (`review_within`). If no signed review exists when it runs out, the **holder is frozen**: no use of any of their break-glass grants and no new one. A late review lifts the freeze.
- The reviewer is a key you pin, and it cannot be the holder or the issuing authority. The first review of a grant is final.
- An `unjustified` review freezes the holder for good.

```ts
const review = signBreakGlassReview(reviewer.secretKey, { id: 'bg-1', outcome: 'justified', notes_digest: 'notes-1', at: t0 + 40 * 60_000 });
await bg.review(review, 'agent-a', t0 + 41 * 60_000); // { ok: true, replaced: true }
await bg.frozen('agent-a', t0 + 42 * 60_000);         // false
```

## Run it

A complete script with every check on this page ships with the PCA examples as `pca-guides-b`. It uses a fixed clock, so the output is the same on every run:

```bash
npm run obligations-leases-break-glass
```

Abridged output:

```
ok   large, PII: two duties -> ["notify","redact"]
ok   a point that only notifies: deny -> ["deny",["redact","require_receipt"]]
ok   past the due time, no receipt: escalate -> ["escalate",["require_receipt"]]
ok   ask for ten more hours: capped at the 4 hour max -> 14400000
ok   revoke everything under db/prod -> {"ok":true,"revoked":1}
ok   use 3 is over the budget -> "deny:budget_exhausted"
ok   an unjustified review -> {"ok":true,"replaced":true}
ok   the holder is frozen for good -> true

All outcomes as expected.
```

## When it refuses

| Code | Meaning | Fix |
|---|---|---|
| `stale_justification` | A renewal reused the last reason | Give the renewal its own `justification_digest` |
| `sod` | An approver is the requester, the holder, in the holder's chain, ineligible, or there are too few | Fix the approver list |
| `superseded` | The presented lease is not the newest record | Fetch the current record from your registry |
| `revoked` | A revocation covers the lease | Issue a new lease (a lease issued after the revocation is a new lease) |
| `over_max_ttl`, `ttl_ceiling` | The record outlives its cap or your registry's ceiling | Shorten `expires_at` |
| `not_notified` | A break-glass use without the notification | Notify `notify_to`, then record the use |
| `holder_frozen` | An overdue or unjustified review | Sign the review; an unjustified one is final |
| `store_unreachable` | The key-value store failed | Fail closed and retry; do not allow |

## Next

- Add this to a real server: [Add PCA to your framework](./framework-recipes.md).
- See what the refusal reasons mean for callers: [Refusal reasons](../reference/refusals.md).
- Contain what a tool can do even when a check is bypassed: [Runtime containment](./runtime-containment.md).
