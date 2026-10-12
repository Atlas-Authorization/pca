import { describe, expect, it } from 'vitest';
import { encodeKey } from '@atlasauth/pca';
import * as ap2 from './index';
import { NOW_MS, makeScenario, verifyScenario, type Scenario } from './testkit';

/**
 * verifyPcaBinding always runs the policy decision on the SERVER-HELD mandate state: without `mandate` it refuses with a
 * typed error (it used to skip the decision, so the cumulative budget and the charge-count rate limit went unchecked),
 * and a mandate with a charge-count limit needs the holder's recent charge times.
 */
const pubOf = (k: { publicKey: Uint8Array }): string => encodeKey(k.publicKey);
function base(s: Scenario) {
  const r = verifyScenario(s);
  if (!r.ok) throw new Error(r.reason);
  return { open: structuredClone(r.payment.open), closed: structuredClone(r.payment.closed), openHash: r.payment.openHash, expectedPrincipal: pubOf(s.principal), audience: s.pcaAudience, now: NOW_MS + 60_000 };
}
const codeOf = async (f: () => unknown): Promise<string | undefined> => {
  try {
    await f();
  } catch (e) {
    return (e as { code?: string }).code;
  }
  return undefined;
};

describe('verifyPcaBinding: the server-held mandate decision is mandatory', () => {
  const s = makeScenario();

  it('without a mandate: typed error mandate_required (no structural-only acceptance)', async () => {
    expect(await codeOf(() => ap2.verifyPcaBinding(base(s) as never))).toBe('mandate_required');
  });

  it('a charge-count limited mandate without recentChargeTimes: typed error charge_history_required', async () => {
    expect(await codeOf(() => ap2.verifyPcaBinding({ ...base(s), mandate: s.pca } as never))).toBe('charge_history_required');
  });

  it('the cumulative budget is enforced from the held mandate state', async () => {
    const spent = { ...s.pca, budget: { ...s.pca.budget, B: 0 } };
    const r = await ap2.verifyPcaBinding({ ...base(s), mandate: spent, recentChargeTimes: [] });
    expect(r.ok).toBe(false);
  });

  it('the charge-count rate limit is enforced from the held history', async () => {
    const recent = Array.from({ length: 10 }, (_, k) => NOW_MS - k * 1000);
    const r = await ap2.verifyPcaBinding({ ...base(s), mandate: s.pca, recentChargeTimes: recent });
    expect(r.ok).toBe(false);
    const ok = await ap2.verifyPcaBinding({ ...base(s), mandate: s.pca, recentChargeTimes: [] });
    expect(ok.ok, (ok as { reason?: string }).reason).toBe(true);
  });
});
