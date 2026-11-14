import { describe, expect, it } from 'vitest';
import { IntentLearner, type HarmModel, type NumDim, type Omega, type VerbSpace } from './index';

// One-cell verbs whose prior puts exactly 1/2 on the cell: with no noise the information is exactly 1 bit, and under the
// `risk` strategy the score is mass * harm = 1 * harm, so each test picks the harm that makes a score an exact double.
const dim: NumDim = { kind: 'num', path: 'action.params.a', lo: 0, hi: 5, cuts: [], dist: 'uniform' };
const verbSpace = (verb: string): VerbSpace => ({ verb, reversibility: 'reversible', weight: 1, dims: [dim] });
const omegaOf = (...verbs: VerbSpace[]): Omega => ({ v: 1, verbs, approximate: [] });
const harmOf = (byVerb: Record<string, number>): HarmModel => ({ verb: (vs) => byVerb[vs.verb]!, dim: () => 1, dimMean: () => 1 });
const opts = (byVerb: Record<string, number>) => ({ nullMass: 0.5, strategy: 'risk' as const, harm: harmOf(byVerb) });

describe('nextQuestion score thresholds', () => {
  it('a score of exactly 1e-15 is too small to ask about; just above it is asked', () => {
    expect(new IntentLearner(omegaOf(verbSpace('v.a')), opts({ 'v.a': 1e-15 })).nextQuestion()).toBeNull();
    const q = new IntentLearner(omegaOf(verbSpace('v.a')), opts({ 'v.a': 2e-15 })).nextQuestion();
    expect(q?.verb).toBe('v.a');
    expect(q?.score).toBe(2e-15);
  });

  it('a later cell must beat the best score by more than 1e-12: a score exactly 1e-12 above does not replace it', () => {
    const first = 1e-3;
    const tie = first + 1e-12;
    const l = new IntentLearner(omegaOf(verbSpace('v.a'), verbSpace('v.b')), opts({ 'v.a': first, 'v.b': tie }));
    const q = l.nextQuestion();
    expect(q?.verb).toBe('v.a');
    expect(q?.score).toBe(first);
    const above = new IntentLearner(omegaOf(verbSpace('v.a'), verbSpace('v.b')), opts({ 'v.a': first, 'v.b': first + 2e-12 })).nextQuestion();
    expect(above?.verb).toBe('v.b');
  });
});
