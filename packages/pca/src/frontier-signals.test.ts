import { describe, expect, it } from 'vitest';
import { meet, signalCeiling, tighten, type Decision, type ModelSignal } from './decision';
import { objectiveSignal, progressSignal, semanticSignal, tightenRiskInputs } from './frontier-signals';
import { riskScore, DEFAULT_RISK_POLICY } from './risk';

const DECISIONS: Decision[] = ['deny', 'escalate', 'allow'];
const SIGNALS: ModelSignal[] = ['ok', 'escalate', 'deny'];
const GARBAGE: unknown[] = [undefined, null, 0, 1, '', 'ok', 'allow', true, [], [{ ok: true }], () => ({ ok: true })];
const RANK: Record<Decision, number> = { deny: 0, escalate: 1, allow: 2 };

describe('semanticSignal: a judge ensemble result becomes ok / escalate / deny, never a grant', () => {
  it('exact outcomes', () => {
    expect(semanticSignal({ ok: true, agreeCount: 3, aggregateScore: 0.9 })).toBe('ok');
    expect(semanticSignal({ ok: false, agreeCount: 1, aggregateScore: 0.2, reason: 'quorum' })).toBe('escalate');
  });
  it('anything that is not a result object with a boolean ok is deny', () => {
    for (const g of GARBAGE) expect(semanticSignal(g as never)).toBe('deny');
    expect(semanticSignal({ ok: 'true' } as never)).toBe('deny');
    expect(semanticSignal({ ok: 1 } as never)).toBe('deny');
    expect(semanticSignal({} as never)).toBe('deny');
  });
});

describe('progressSignal: a proof-of-progress step', () => {
  it('exact outcomes: ok, budget exhaustion escalates, every other denial denies', () => {
    expect(progressSignal({ ok: true })).toBe('ok');
    expect(progressSignal({ ok: false, reason: 'exploration-exhausted' })).toBe('escalate');
    expect(progressSignal({ ok: false, reason: 'budget-exceeded' })).toBe('escalate');
    for (const reason of ['goal-mismatch', 'bad-signature', 'chain-break', 'malformed', 'prohibited', 'untrusted-state-source', 'attestation-failed', 'state-source-mismatch', 'holder-mismatch']) {
      expect(progressSignal({ ok: false, reason })).toBe('deny');
    }
    expect(progressSignal({ ok: false })).toBe('deny');
    expect(progressSignal({ ok: false, reason: 7 as never })).toBe('deny');
  });
  it('garbage is deny', () => {
    for (const g of GARBAGE) expect(progressSignal(g as never)).toBe('deny');
    expect(progressSignal({ ok: 'yes' } as never)).toBe('deny');
  });
});

describe('objectiveSignal: objective-risk resolution', () => {
  it('exact outcomes: nothing committed and a reproduced result are neutral; a mismatch denies unless the grant chose the heuristic', () => {
    expect(objectiveSignal({ mode: 'none' })).toBe('ok');
    expect(objectiveSignal({ mode: 'objective', inputs: { reversibility: 1, blastRadius: 0, semanticDistance: 0 }, r: 0, evidenceDigest: 'd' })).toBe('ok');
    expect(objectiveSignal({ mode: 'mismatch', reasons: ['x'], onMismatch: 'deny' })).toBe('deny');
    expect(objectiveSignal({ mode: 'mismatch', reasons: ['x'], onMismatch: 'heuristic' })).toBe('ok');
  });
  it('an unknown mode or garbage is deny', () => {
    for (const g of GARBAGE) expect(objectiveSignal(g as never)).toBe('deny');
    expect(objectiveSignal({ mode: 'other' } as never)).toBe('deny');
    expect(objectiveSignal({ mode: 'mismatch', reasons: [], onMismatch: 'allow' } as never)).toBe('deny');
  });
});

describe('G-T9 over the frontier signals: no result of any frontier module can widen a decision', () => {
  const results: unknown[] = [
    ...GARBAGE,
    { ok: true }, { ok: false }, { ok: false, reason: 'budget-exceeded' }, { ok: true, agreeCount: 99, aggregateScore: 1 },
    { mode: 'none' }, { mode: 'objective', r: 0 }, { mode: 'mismatch', onMismatch: 'heuristic' }, { mode: 'mismatch', onMismatch: 'deny' },
  ];
  it('for every result and every base decision, tighten(base, signal) <= base, and ok is exactly neutral', () => {
    for (const r of results) {
      for (const sig of [semanticSignal(r as never), progressSignal(r as never), objectiveSignal(r as never)]) {
        expect(SIGNALS).toContain(sig);
        for (const d of DECISIONS) {
          expect(RANK[tighten(d, sig)]).toBeLessThanOrEqual(RANK[d]);
          expect(tighten(d, sig)).toBe(meet(d, signalCeiling(sig)));
          if (sig === 'ok') expect(tighten(d, sig)).toBe(d);
        }
      }
    }
  });
  it('a deny base stays deny and an escalate base never becomes allow under any signal', () => {
    for (const s of SIGNALS) {
      expect(tighten('deny', s)).toBe('deny');
      expect(tighten('escalate', s)).not.toBe('allow');
    }
  });
});

describe('tightenRiskInputs: the objective path can only raise risk', () => {
  const base = { reversibility: 0.4, blastRadius: 0.5 };
  it('exact outcomes: the lower reversibility and the higher blast radius count, semanticDistance passes through', () => {
    expect(tightenRiskInputs(base, { reversibility: 1, blastRadius: 0.1, semanticDistance: 0.3 })).toEqual({ reversibility: 0.4, blastRadius: 0.5, semanticDistance: 0.3 });
    expect(tightenRiskInputs(base, { reversibility: 0, blastRadius: 0.9, semanticDistance: 0 })).toEqual({ reversibility: 0, blastRadius: 0.9, semanticDistance: 0 });
    expect(tightenRiskInputs(base, { reversibility: 0.4, blastRadius: 0.5, semanticDistance: 1 })).toEqual({ reversibility: 0.4, blastRadius: 0.5, semanticDistance: 1 });
  });
  it('a non-finite or non-numeric value on either side is the worst case', () => {
    const worst = { reversibility: 0, blastRadius: 1 };
    for (const bad of [NaN, Infinity, -Infinity, undefined, null, '0.1']) {
      expect(tightenRiskInputs(base, { reversibility: bad as never, blastRadius: 0.1, semanticDistance: 0.2 })).toMatchObject(worst);
      expect(tightenRiskInputs(base, { reversibility: 1, blastRadius: bad as never, semanticDistance: 0.2 })).toMatchObject(worst);
      expect(tightenRiskInputs({ reversibility: bad as never, blastRadius: 0.5 }, { reversibility: 1, blastRadius: 0.1, semanticDistance: 0.2 })).toMatchObject(worst);
      expect(tightenRiskInputs({ reversibility: 1, blastRadius: bad as never }, { reversibility: 1, blastRadius: 0.1, semanticDistance: 0.2 })).toMatchObject(worst);
      expect(tightenRiskInputs(base, { reversibility: 1, blastRadius: 0.1, semanticDistance: bad as never }).semanticDistance).toBe(1);
    }
  });
  it('monotone: r with the folded inputs is never below r with the baseline (property over a grid)', () => {
    const grid = [0, 0.1, 0.25, 0.4, 0.5, 0.75, 1];
    const rest = { taint: 0.2, confidence: 0.8, age: 0.1 };
    for (const br of grid) for (const bb of grid) for (const or of grid) for (const ob of grid) {
      const f = tightenRiskInputs({ reversibility: br, blastRadius: bb }, { reversibility: or, blastRadius: ob, semanticDistance: 0.3 });
      const rBase = riskScore({ semanticDistance: 0.3, reversibility: br, blastRadius: bb, ...rest }, DEFAULT_RISK_POLICY.weights);
      const rFold = riskScore({ semanticDistance: f.semanticDistance, reversibility: f.reversibility, blastRadius: f.blastRadius, ...rest }, DEFAULT_RISK_POLICY.weights);
      expect(rFold).toBeGreaterThanOrEqual(rBase);
    }
  });
});
