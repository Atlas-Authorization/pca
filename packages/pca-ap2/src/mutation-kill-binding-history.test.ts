/** verifyPcaBinding charge-history precondition: only required for a charge-count limited mandate; every entry must be a finite number. */
import { describe, expect, it } from 'vitest';
import { encodeKey } from '@atlasauth/pca';
import * as ap2 from './index';
import { NOW_MS, makeScenario, verifyScenario, type Scenario } from './testkit';

const pubOf = (k: { publicKey: Uint8Array }): string => encodeKey(k.publicKey);
function base(s: Scenario) {
  const r = verifyScenario(s);
  if (!r.ok) throw new Error(r.reason);
  return { open: structuredClone(r.payment.open), closed: structuredClone(r.payment.closed), openHash: r.payment.openHash, expectedPrincipal: pubOf(s.principal), audience: s.pcaAudience, now: NOW_MS + 60_000 };
}
const errOf = async (f: () => unknown): Promise<{ code?: string; message?: string } | undefined> => {
  try {
    await f();
  } catch (e) {
    return e as { code?: string; message?: string };
  }
  return undefined;
};

describe('verifyPcaBinding: recentChargeTimes', () => {
  const s = makeScenario();
  it('the typed error carries its exact message', async () => {
    const e = await errOf(() => ap2.verifyPcaBinding({ ...base(s), mandate: s.pca } as never));
    expect(e?.code).toBe('charge_history_required');
    expect(e?.message).toContain('the mandate limits the charge count: pass recentChargeTimes from your own records');
  });
  it('a non-finite or non-number entry is refused like a missing history', async () => {
    for (const bad of [[Number.NaN], [Number.POSITIVE_INFINITY], ['1'], [NOW_MS, null]]) {
      const e = await errOf(() => ap2.verifyPcaBinding({ ...base(s), mandate: s.pca, recentChargeTimes: bad } as never));
      expect(e?.code, JSON.stringify(bad)).toBe('charge_history_required');
    }
  });
  it('a mandate WITHOUT a charge-count limit needs no history', async () => {
    const terms = { ...s.pca.terms };
    delete terms.maxTransactionsPerPeriod;
    const e = await errOf(() => ap2.verifyPcaBinding({ ...base(s), mandate: { ...s.pca, terms } } as never));
    expect(e?.code).not.toBe('charge_history_required');
  });
  it('mandate_required: exact message and error name', async () => {
    const e = await errOf(() => ap2.verifyPcaBinding(base(s) as never));
    expect(e?.code).toBe('mandate_required');
    expect((e as { name?: string }).name).toBe('PcaBindingError');
    expect(e?.message).toContain('verifyPcaBinding needs the server-held PCA mandate (its live budget); the policy decision is never skipped');
  });
  it('a mandate record without terms is not a TypeError (no charge-count limit to enforce)', async () => {
    const e = await errOf(() => ap2.verifyPcaBinding({ ...base(s), mandate: {} } as never));
    expect(e instanceof TypeError).toBe(false);
  });
});
