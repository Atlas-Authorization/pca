import { describe, expect, it } from 'vitest';
import { cellRep, IntentLearner, rng, type Omega } from './index';

/** Intent Layer v2 §2.5: asymmetric answer noise (η⁺ false yes, η⁻ false no) and the §3.12 mixture-prior hook. */

const OM: Omega = {
  v: 1,
  approximate: [],
  verbs: [{ verb: 'pay', reversibility: 'irreversible', weight: 1, dims: [{ kind: 'num', path: 'action.params.amount', lo: 0, hi: 1000, cuts: [100, 200, 500], dist: 'uniform' }] }],
};
const VS = OM.verbs[0]!;
const at = (i: number) => cellRep(VS, [i]);
const ps = (l: IntentLearner) => l.cells().map((c) => c.p);

describe('asymmetric noise', () => {
  it('η⁺ = η⁻ = η is exactly v1 (same posterior and the same questions) (property)', () => {
    const r = rng(17);
    for (let t = 0; t < 30; t++) {
      const eta = r() * 0.4;
      const v1 = new IntentLearner(OM, { eta });
      const v2 = new IntentLearner(OM, { etaPos: eta, etaNeg: eta });
      for (let k = 0; k < 6; k++) {
        const i = Math.floor(r() * 7);
        const y = r() < 0.5 ? 1 : 0;
        v1.observe(at(i), y);
        v2.observe(at(i), y);
        expect(ps(v2)).toEqual(ps(v1));
        expect(v2.nextQuestion()).toEqual(v1.nextQuestion());
      }
      expect(v2.tau).toBe(v1.tau);
    }
  });
  it('a "yes" is more credible when false yeses are rare; a "no" is more credible when false noes are rare', () => {
    const lowPos = new IntentLearner(OM, { etaPos: 0.01, etaNeg: 0.3 });
    const highPos = new IntentLearner(OM, { etaPos: 0.3, etaNeg: 0.01 });
    const p0 = new IntentLearner(OM, { eta: 0.1 }).acceptance(at(3));
    lowPos.observe(at(3), 1);
    highPos.observe(at(3), 1);
    expect(lowPos.acceptance(at(3))).toBeGreaterThan(highPos.acceptance(at(3)));
    expect(highPos.acceptance(at(3))).toBeGreaterThan(p0 - 1e-12);
    const lowNeg = new IntentLearner(OM, { etaPos: 0.3, etaNeg: 0.01 });
    const highNeg = new IntentLearner(OM, { etaPos: 0.01, etaNeg: 0.3 });
    lowNeg.observe(at(3), 0);
    highNeg.observe(at(3), 0);
    expect(lowNeg.acceptance(at(3))).toBeLessThan(highNeg.acceptance(at(3)));
  });
  it('any noise makes the learner noisy: τ defaults to 0.95 and there is no hard version space', () => {
    const l = new IntentLearner(OM, { etaPos: 0.05 });
    expect(l.tau).toBe(0.95);
    expect(l.etaNeg).toBe(0);
    expect(l.metrics().log2VersionSpace).toBeNull();
    expect(new IntentLearner(OM, {}).metrics().log2VersionSpace).not.toBeNull();
    expect(() => new IntentLearner(OM, { etaPos: 0.5 })).toThrow(/etaPos/);
    expect(() => new IntentLearner(OM, { etaNeg: -0.1 })).toThrow(/etaNeg/);
    expect(() => new IntentLearner(OM, { etaPos: 0.1, agnosticSlack: 0 })).toThrow(/agnostic/);
  });
  it('with η⁺ = 0 a "yes" is certain (hypotheses rejecting the cell are eliminated) while a "no" stays soft', () => {
    const l = new IntentLearner(OM, { etaPos: 0, etaNeg: 0.2 });
    l.observe(at(2), 1);
    expect(l.acceptance(at(2))).toBeCloseTo(1, 12);
    expect(l.admitsOutcome(at(2))).toBe(true);
    l.observe(at(4), 0);
    expect(l.acceptance(at(4))).toBeGreaterThan(0);
    expect(l.isVetoed(at(4))).toBe(false);
  });
});

describe('mixture prior hook', () => {
  it('β = 0 is the base prior; β > 0 moves p but never the τ = 1 grant under noise-free answers', () => {
    const base = new IntentLearner(OM, {});
    const same = new IntentLearner(OM, { priorMix: { beta: 0, weight: (_vs, has) => (has(6) ? 1 : 0.01) } });
    expect(ps(same)).toEqual(ps(base));
    const mixed = new IntentLearner(OM, { priorMix: { beta: 0.8, weight: (_vs, has) => (has(6) ? 1 : 0.01) } });
    expect(ps(mixed)).not.toEqual(ps(base));
    for (const l of [base, mixed]) {
      l.observe(at(1), 1);
      l.observe(at(5), 0);
    }
    expect(mixed.cells().map((c) => c.inGrant)).toEqual(base.cells().map((c) => c.inGrant));
  });
});
