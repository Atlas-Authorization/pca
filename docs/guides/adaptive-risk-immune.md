---
title: Adaptive risk (behavioural tightening)
order: 20
---

# Adaptive risk: tighten the policy when behaviour drifts

> **Status: production (pending CI).** What is enforced is the tighten-only rule: the adapted policy can never be looser than your base policy, and a malformed state reads as the highest threat. The anomaly score that feeds it is an advisory heuristic by design and is never an authorization input. Lives under `@atlasauth/pca/ext/research`. Not part of PCA Core. See [maturity tiers](../maturity.md).

An agent's recent activity (risk values, step-ups, denials) is folded into a small state. From that state the library derives a threat level and, from your base risk policy, a **tightened** policy for the next epoch: a higher cost scale (`kappa`) and lower thresholds (`theta1`, `theta2`), so more actions need a human. When behaviour calms down, the policy returns to your base policy exactly.

A signed grant never changes. The tightened policy is something your control plane applies for the next epoch, and you apply it only through a signed proposal.

## What is guaranteed

- **Pure and deterministic.** The adapted policy is a function of your base policy and the state, nothing else. Same inputs, same output.
- **Only tightens.** The result never has a lower `kappa` or higher `theta` than the base, and never changes weights, `lambda`, `rho` or `bMax`. This is checked in code (`assertNoWiden`); a configuration that would loosen the policy is refused and the base is kept.
- **Reversible.** A threat score of 0 returns the base policy unchanged. The adaptation is computed from the base each time and never compounds.
- **Fails closed.** A malformed or out-of-range state, or a non-finite score, reads as the highest threat level, never as calm. The durable store refuses to fold into a corrupt state rather than resetting it.
- **Signed, bound, replay-safe.** A tightening proposal is signed by a guardian key you pin, binds the base policy and the state it came from, and carries an epoch. `applyTightening` refuses a wrong guardian, a bad signature, another base policy, a stale or future-dated proposal, an epoch that is not strictly higher than the last applied one, and anything that widens.

## What is not guaranteed

- The anomaly score is a heuristic (a moving average and a z-score over one agent's own history). A slow attacker who drifts the baseline upward gradually can avoid triggering it. A burst of high-risk actions from an agent with no history gives the baseline nothing to compare against.
- It does not prove an agent is compromised or benign. Treat a high reading as a reason to ask a human, which is what the tightened thresholds do.
- It does not move money or revoke anything. Revocation and budgets stay with their own features.

## Use

```ts
import { DEFAULT_RISK_POLICY, encodeKey, generateKeyPair } from '@atlasauth/pca';
import { createMemoryDurableKv } from '@atlasauth/pca/durable-state';
import { applyTightening, createImmuneStore, issueTighteningProposal } from '@atlasauth/pca/ext/research';

const guardian = generateKeyPair();
const store = createImmuneStore(createMemoryDurableKv(), 'agent-1'); // use a durable store in production

// 1. feed every decision
await store.observe({ r: 0.9, at: Date.now(), denied: true });

// 2. once per epoch, derive and sign
const proposal = issueTighteningProposal({
  base: DEFAULT_RISK_POLICY,
  state: await store.get(),
  epoch: (await store.lastEpoch()) + 1,
  now: Date.now(),
  guardianSecret: guardian.secretKey,
});

// 3. apply: verifies, then advances the epoch floor atomically
const out = await store.apply(DEFAULT_RISK_POLICY, proposal, {
  guardian: encodeKey(guardian.publicKey),
  now: Date.now(),
  maxAgeMs: 60_000,
});
const policy = out.ok ? out.policy : DEFAULT_RISK_POLICY; // a refusal leaves the base in force
```

Every refusal has its own reason: `malformed`, `guardian`, `signature`, `base`, `stale`, `replayed-epoch`, `widens`, `invalid-policy`, `state-mismatch`. Pass `state` to `applyTightening` to make it recompute the tightening from that state and require an exact match.
