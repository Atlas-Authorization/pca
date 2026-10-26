---
title: Optimistic claims and bond settlement
order: 9
---

# Optimistic claims and bond settlement

**Internal accounting only. No money moves.** The bond ledger described here keeps numbers in your own books: a depositor, an escrow account, a challenger, a victim-compensation pool, a treasury. Opening a bond debits one number and credits another; slashing one divides it. Nothing is sent to a bank, a card network or a chain. If you want real custody, reconcile these books with your payment rail yourself. PCA gives you the protocol and a durable ledger of who owes what, not a payment system.

> **Status: experimental (hardened).** The engineering is finished and tested, but the extension has not had an independent audit. It lives under `@atlasauth/pca/ext/optimistic` and is not part of PCA Core. See [maturity tiers](../maturity.md).

## What it is for

A reversible action can run before the full policy check finishes. The agent signs a **claim** that the action complies, and posts a **bond**. A **challenge window** opens. Anyone can file a **fraud proof** during the window: evidence that the claim was false. The settlement layer re-derives the verdict itself (it never trusts the challenger's say-so); a proven fraud **slashes** the bond, and an unchallenged claim **releases** it when the window closes. Irreversible actions never take this path.

Effects are not rolled back for you. If a slashed claim's action must be undone, that is your application's job.

## Quick start

```ts
import { DEFAULT_RISK_POLICY, buildPCActn, encodeKey, generateKeyPair, mintGrant } from '@atlasauth/pca';
import { createMemoryDurableKv } from '@atlasauth/pca/durable-state';
import { KvBondStore, StoreBondLedger, openOptimistic } from '@atlasauth/pca/ext/optimistic';

const principal = generateKeyPair();
const agent = generateKeyPair();
const guardian = generateKeyPair(); // signs every settlement record
const agentPublic = encodeKey(agent.publicKey);

// a grant and one reversible action, as in the agent quickstart
const { grant } = mintGrant({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  holder: agentPublic,
  goal: 'tidy my account',
  envelope: {
    predicates: [{ verb: 'revoke_session', resource: '/acct/*' }],
    caveats: [{ type: 'expires', at: 9e15 }],
    agent_binding: {},
    risk_policy: DEFAULT_RISK_POLICY,
  },
});
const pcactn = buildPCActn({
  aud: 'my-api',
  grant,
  chain: [grant],
  plan: [{ id: 'n1', verb: 'revoke_session', resource: '/acct/1/s', reversibility_class: 'reversible' }],
  nodeId: 'n1',
  counter: 1,
  signerSecret: agent.secretKey,
});

// the book lives in a store. Use openDurableState({ dir }) from '@atlasauth/pca/durable-state' in production.
const now = Date.now();
const ledger = new StoreBondLedger({
  guardianSecret: guardian.secretKey,
  store: new KvBondStore(createMemoryDurableKv()),
  clock: () => now, // a clock you control; the default is Date.now
});
await ledger.deposit('alice', 1000); // credit the depositor's account in your books

// the agent signs a claim; the ledger verifies it, locks the bond and starts the window on ITS clock
const claim = openOptimistic(pcactn, { bondRef: 'bond-1', claimedR: 0.1, challengeWindowMs: 60_000, serverNow: now }, agent.secretKey);
const opened = await ledger.openClaim({ claim, pcactn, signerPublic: agentPublic, amount: 100, depositor: 'alice' });
console.log(opened.action, await ledger.balanceOf('alice'), await ledger.balanceOf('escrow')); // open 900 100

// inside the window the bond cannot be released
try {
  await ledger.release('bond-1');
} catch (e) {
  console.log((e as { code: string }).code); // window_open
}
```

The ledger signs every transition into a `SettlementRecord` with the guardian key. Anyone with the guardian's public key can check one with `verifySettlement`.

## The challenge-window clock

The window opens at the ledger's own time, `registeredAt`, when `openClaim` commits. It lasts the claim's `challenge_window_ms`. It is **never** derived from the claim's `issued_at` or from a time the caller passes in, so a claimant who backdates or forward-dates the claim, or who passes a convenient `at`, cannot move it. Three more rules close the remaining ways to cheat the clock:

- A claim whose window is shorter than the realistic floor (30 seconds, or the policy minimum if higher) is refused, and so is one whose `issued_at` is out of skew with the ledger's clock.
- The ledger's notion of "now" is the larger of its clock and the highest time the store has ever recorded. A clock that steps backwards, or a restart on a host with a slow clock, cannot reopen a closed window or release early.
- A fraud or dispute slash is accepted only while `now <= registeredAt + windowMs`; a release only after it. A slash for a revoked capability is derived from server state, not from a challenger, and is not window-gated.

The ledger remembers a digest of the exact claim it registered. A slash that names a different claim for the same bond is refused (`claim_mismatch`).

## Retries are safe

Every method is idempotent under retry. Repeating a call that already committed (after a timeout, a lost response, or a restart) returns the **stored** record and moves nothing. A conflicting transition (releasing a slashed bond, slashing twice with different evidence) is refused and the first outcome stands.

| Call | Repeated | Conflicting |
|---|---|---|
| `openClaim` / `openBond` | the original `open` record, collateral taken once | other terms for the same bond: `conflict` |
| `release` | the original `release` record | slash afterwards: refused, bond stays released |
| `slashBond` / `slashBondOnDispute` / `slashBondOnRevocation` | the original `slash` record | other evidence or a release: refused |
| `slashCounterBond` | the original `slash` record | refused once settled |

## The store contract

`StoreBondLedger` needs a `BondStore`. A store applies each transition **all or nothing**: the check on the bond's phase, every balance movement, the new phase and the signed record become visible together, and a crash leaves the state before or after, never between. It re-checks the per-depositor caps and overdrafts itself, because the ledger's read may be stale by the time it commits. Committing the same transition twice returns the stored record.

`KvBondStore` is the reference. Over `openDurableState({ dir })` it is crash-safe and multi-process safe on one host. It keeps the whole book in one document (about a thousand bonds per MiB); past the limit it refuses the write rather than losing data. For more, implement `BondStore` over a database transaction.

Test your own store with the conformance suite:

```ts
import { describeBondStoreConformance, durableBondStoreAdapter } from '@atlasauth/pca-store-conformance';
// registers one vitest/jest test per claim (atomic open, racing settles have one winner, a crash applies a transition whole or not at all)
describeBondStoreConformance(durableBondStoreAdapter());
```

## Failure modes

The ledger fails closed. Every refusal is a `BondStoreError` with a stable `code`, or the original plain error for a refused transition (`slashBond: refused ...`).

| If this is missing or wrong | Result |
|---|---|
| no store, or an object that is not a store | the constructor throws `store_missing`; there is no in-memory default |
| no guardian key | the constructor throws `guardian_key_missing` |
| the clock returns a non-finite number | the call throws `clock_invalid`; nothing is written |
| the store throws or is unreachable | `store_unavailable`; nothing is returned as committed. Retry: it is safe |
| the stored document is malformed | `store_corrupt` |
| the claim fails verification, or its window is below the floor | `invalid_claim` |
| release while the window is open | `window_open` |
| fraud or dispute slash after the window | `window_closed` |
| release or slash of a bond with no registered claim | `unregistered` (counter-bonds use `releaseUnregistered`) |
| a claim other than the registered one | `claim_mismatch` |
| a concurrent or conflicting transition | `conflict`; the winner's record stands |
| a fraud proof the ledger cannot re-verify | the slash is refused; the bond stands |

## Wire vectors

The claim, the fraud proof and the settlement record have shared test vectors in the conformance corpus (layer **extension**). The TypeScript, Go, Python and Rust verifiers agree on all of them. The shared check on a fraud proof is structural: it names this claim and bond, has a known kind, and carries the decision that kind requires. **Re-running the policy on the frozen open-time snapshot, which is what actually convicts, is done by the TypeScript settlement layer only.**

## Limits

- Internal accounting only. No payment rail, no custody, no on-chain escrow.
- Effects are not rolled back.
- A plain `bond_ref` with no ledger behind it reports `bond: not-enforced` in Core.
- The reference store is one document; it is for correctness, not scale.
- Post-quantum signature suites are supported by the TypeScript ledger; the other languages verify Ed25519 settlement records and refuse any other suite.
- Independent audit: not done.
