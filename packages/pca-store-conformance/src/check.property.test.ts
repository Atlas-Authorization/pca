// The checker against a brute-force reference on thousands of random small histories, legal AND illegal (the TypeScript
// counterpart of tools/pca-linearizability/main_test.go): the search, the exact procedure, the pruning step and the full
// per-key decision must all agree with brute force, and a counterexample must itself be illegal and 1-minimal.
import { describe, expect, it } from 'vitest';
import { checkKey, decideKey, deletion, minimize } from './check';
import { fastCheck, overlappingTrues, prune, type Op } from './model';
import { searchLinearizable } from './search';
import { bruteLinearizable, randomHistory, rng } from './test-support/brute';

const N = 4000;
const modes = ['legal', 'flip', 'random'] as const;

function corpus(seed: number): Op[][] {
  const r = rng(seed);
  return Array.from({ length: N }, (_, i) => randomHistory(r, modes[i % 3]!));
}

describe('checker vs brute force (random histories)', () => {
  const hs = corpus(20261012);
  const verdicts = hs.map((h) => bruteLinearizable(h));

  it('the corpus has plenty of legal and illegal histories, with and without unknown outcomes', () => {
    const legal = verdicts.filter(Boolean).length;
    expect(legal).toBeGreaterThan(N / 4);
    expect(N - legal).toBeGreaterThan(N / 5);
    expect(hs.filter((h) => h.some((o) => o.res === 'unknown')).length).toBeGreaterThan(N / 5);
    expect(hs.filter((h, i) => !verdicts[i] && h.some((o) => o.res === 'unknown')).length).toBeGreaterThan(50);
    // every legal-mode history is linearizable by construction (validates the brute force itself)
    hs.forEach((h, i) => {
      if (i % 3 === 0) expect(verdicts[i]).toBe(true);
    });
  });

  it('searchLinearizable agrees with brute force on every history', () => {
    hs.forEach((h, i) => expect(searchLinearizable(h), JSON.stringify(h)).toBe(verdicts[i] ? 'ok' : 'violation'));
  });

  it('fastCheck agrees with brute force whenever it applies (no unknown outcome), and abstains otherwise', () => {
    let applied = 0;
    hs.forEach((h, i) => {
      const f = fastCheck(h);
      if (h.some((o) => o.res === 'unknown')) expect(f).toBeUndefined();
      else {
        applied++;
        expect(f, JSON.stringify(h)).toBe(verdicts[i]);
      }
    });
    expect(applied).toBeGreaterThan(N / 3);
  });

  it('prune is verdict-preserving and only removes definite FALSE answers', () => {
    let removed = 0;
    hs.forEach((h, i) => {
      const p = prune(h);
      removed += h.length - p.length;
      for (const o of h) if (!p.includes(o)) expect(o.res).toBe('false');
      expect(bruteLinearizable(p), JSON.stringify(h)).toBe(verdicts[i]);
    });
    expect(removed).toBeGreaterThan(100);
  });

  it('overlappingTrues only ever reports an illegal pair', () => {
    let hits = 0;
    hs.forEach((h, i) => {
      const pair = overlappingTrues(h);
      if (pair) {
        hits++;
        expect(verdicts[i]).toBe(false);
        expect(bruteLinearizable(pair)).toBe(false);
      }
    });
    expect(hits).toBeGreaterThan(100);
  });

  it('decideKey / checkKey agree with brute force', () => {
    hs.forEach((h, i) => {
      expect(decideKey(h).verdict).toBe(verdicts[i] ? 'ok' : 'violation');
      expect(checkKey(h).verdict).toBe(verdicts[i] ? 'ok' : 'violation');
    });
  });

  it('every sound deletion keeps a legal history legal', () => {
    hs.forEach((h, i) => {
      if (!verdicts[i]) return;
      for (const o of h) expect(bruteLinearizable(deletion(h, o)), JSON.stringify({ h, o })).toBe(true);
    });
  });

  it('a counterexample is an illegal sub-history and 1-minimal under sound deletion', () => {
    hs.forEach((h, i) => {
      if (verdicts[i]) return;
      const r = checkKey(h);
      const cx = r.counterexample!;
      expect(cx.every((o) => h.includes(o))).toBe(true);
      expect(bruteLinearizable(cx)).toBe(false);
      if (!overlappingTrues(h)) for (const o of cx) expect(bruteLinearizable(deletion(cx, o))).toBe(true);
    });
  });

  it('minimize of an illegal history is illegal and no larger', () => {
    hs.forEach((h, i) => {
      if (verdicts[i]) return;
      const m = minimize(h);
      expect(m.length).toBeLessThanOrEqual(h.length);
      expect(bruteLinearizable(m)).toBe(false);
    });
  });
});
