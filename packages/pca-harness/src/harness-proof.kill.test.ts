/** The inclusion-proof builder is the one internal step a valid plan cannot make fail; here it is made to fail. */
import { describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({ breakProof: false }));
vi.mock('@atlasauth/pca', async (importOriginal) => {
  const real = await importOriginal<typeof import('@atlasauth/pca')>();
  return {
    ...real,
    commitPlan: (plan: Parameters<typeof real.commitPlan>[0]) => {
      const c = real.commitPlan(plan);
      return state.breakProof
        ? {
            ...c,
            proofFor: () => {
              throw new Error('proof store offline');
            },
          }
        : c;
    },
  };
});

import { type PlanNode, encodeKey, generateKeyPair, mintRoot } from '@atlasauth/pca';
import { Harness } from './harness';

describe('Harness.step when the inclusion proof cannot be built', () => {
  it('refuses as out_of_plan with the cause and signs nothing', async () => {
    const principal = generateKeyPair();
    const agent = generateKeyPair();
    const grant = mintRoot({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: encodeKey(agent.publicKey), caveats: [] });
    const plan: PlanNode[] = [{ id: 'n1', verb: 'read', resource: 'doc:1' }];
    state.breakProof = true;
    try {
      const h = new Harness({ grant, agentSecret: agent.secretKey, plan, audience: 'ins_kill', budget: { B: 1, tau: 1, asOf: 1 }, now: () => 1 });
      const r = await h.step(() => ({ verb: 'read', resource: 'doc:1', nodeId: 'n1' }));
      expect(r).toEqual({ ok: false, reason: 'out_of_plan', detail: "no inclusion proof for 'n1': proof store offline" });
      expect(h.counter).toBe(0);
    } finally {
      state.breakProof = false;
    }
  });
});
