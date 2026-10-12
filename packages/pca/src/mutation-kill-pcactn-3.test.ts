/** pcactn.ts residual mutants: the taint gate's own catch (computeTaint is total, so only the gate's policy read can throw). */
import { describe, expect, it } from 'vitest';
import { verifyPCActnCore, type PCActn } from './pcactn';
import { AUD, NOW, setup } from './server/fixture.test-util';
import { InMemoryTrustedInputRegistry } from './taint';

describe('verifyPCActnCore: taint gate error path', () => {
  it('a maxTaint whose comparison throws is a fail-closed taint_gate failure carrying the error message', async () => {
    const s = setup();
    const p = s.mk(s.plan[0]!, { extra: { provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] } } });
    const maxTaint = {
      valueOf(): number {
        throw new Error('policy read failed');
      },
    };
    const r = await verifyPCActnCore(p as PCActn, { grant: s.grant, nowEpoch: NOW, audience: AUD, enforce: { taint: { ctx: { registry: new InMemoryTrustedInputRegistry() }, maxTaint } } } as never);
    expect(r.allow).toBe(false);
    expect(r.checks.taint_gate).toBe('fail');
    expect(r.reason).toBe('taint_gate: taint gate error (fail closed): policy read failed');
  });
});
