/**
 * ADAPTIVE RISK EPOCH: the activity stream tightens the risk policy for the next epoch, under a guardian signature.
 *
 * Activity events -> immune state -> threat read -> signed tightening proposal -> `applyTightening` -> the
 * threshold the resource server enforces. The proposal can only tighten, binds the base policy and an epoch, and
 * a replay or a widening is refused.
 *
 * Used by examples/immune-epoch.ts and the immune tests.
 */
import { generateKeyPair } from '../keys';
import { encodeKey } from '../keys';
import { DEFAULT_RISK_POLICY, requiredThreshold } from '../risk';
import { createMemoryDurableKv } from '../durable-state';
import type { ActivityEvent } from '../console';
import { createImmuneStore, issueTighteningProposal } from '../immune';

export async function runImmuneEpoch(events: ActivityEvent[], now: number) {
  const guardian = generateKeyPair();
  const store = createImmuneStore(createMemoryDurableKv(), 'agent-1');
  for (const e of events) {
    await store.observe({ r: e.r ?? 0, at: e.at, stepUp: e.outcome === 'step_up', denied: e.outcome === 'deny' });
  }
  const proposal = issueTighteningProposal({
    base: DEFAULT_RISK_POLICY,
    state: await store.get(),
    epoch: (await store.lastEpoch()) + 1,
    now,
    guardianSecret: guardian.secretKey,
  });
  const applied = await store.apply(DEFAULT_RISK_POLICY, proposal, { guardian: encodeKey(guardian.publicKey), now, maxAgeMs: 60_000 });
  const policy = applied.ok ? applied.policy : DEFAULT_RISK_POLICY; // a refused proposal leaves the base in force
  const probe = 0.2;
  return {
    applied,
    replay: await store.apply(DEFAULT_RISK_POLICY, proposal, { guardian: encodeKey(guardian.publicKey), now, maxAgeMs: 60_000 }),
    before: requiredThreshold(probe, DEFAULT_RISK_POLICY).t,
    after: requiredThreshold(probe, policy).t,
  };
}
