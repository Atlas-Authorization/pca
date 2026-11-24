---
title: Behavioural contracts
order: 6
---

# Behavioural contracts

A contract is a small, signed program of temporal rules that every action of an agent must satisfy. It extends the prohibition monitor (negative authority only) with positive and ordering rules over the same hash-chained action trace.

| Clause | Meaning |
|---|---|
| `always p` | every action satisfies `p` (an unresolvable predicate is a violation) |
| `never p` | no action satisfies `p` (an unresolvable predicate counts as matched) |
| `precedes` / `requires_prior` | `q` is admitted only after an earlier admitted `p` |
| `responds_within n` | after a `p`, a `q` must come within the next `n` actions; a missed deadline is a violation |
| `and` | all sub-clauses hold |

Contracts are bounded: at most 256 clauses and 16 levels of nesting, and an over-deep nest is refused without recursion. They are signed by the principal's key, content-addressed (`id`), and verified against a **pinned** principal.

## Fail-closed outcomes

| Input | Result |
|---|---|
| unknown clause kind, missing or duplicate id, bad `within` | contract refused at validation and at signing |
| wrong principal, tampered content, bad signature | `verifyContract` returns the exact reason; the enforcer will not open |
| stale, forged or rolled-back monitor state | action refused, state unchanged |
| clock that goes backwards | refused |
| unreadable store, corrupt or foreign state document | action denied (`store-error` / `state-error`) |
| a real violation | action denied, and with the default latch every later action is denied |

## Enforce it durably

`ContractEnforcer` keeps the monitor state in the durable state store. The read, check and advance run in one atomic update, so two processes can never both advance the same sequence number, and the state and the latch survive a restart. Pass your normal verifier's verdict as `permitted`: a contract can only add refusals. A latched enforcer is released only by a reset the principal signed for that contract at that sequence number (`signContractReset`).

```ts
const enforcer = ContractEnforcer.open(kv, signedContract, { principal });
const r = await enforcer.check({ action: { verb: 'deploy', resource: '/service' } }, permittedByVerifier);
if (!r.allow) refuse(r.reason, r.violated);
```

## What is and is not guaranteed

- These are **safety** properties over the actions that pass through `check`. Nothing is promised about actions that bypass it, and no liveness is promised: `responds_within` is a bounded safety obligation, and an obligation still open at the end of a trace is not a violation.
- Predicates are evaluated on the action fields the caller supplies. The contract proves the action matched the rules, not that the supplied fields are true.
- The module is production-tier (pending CI) in the product layer, under `@atlasauth/pca/ext/research`. `authorize({ contracts })` consults the enforcer before the replay counter is spent, so a contract refusal costs nothing.
