import { describe, expect, it } from 'vitest';
import { evaluateDlp, type DlpPolicy } from './dlp';

// a ceiling of +Infinity is a legitimate "no limit"; a malformed (non-finite) taint must still never ride under it
const open: DlpPolicy = { classes: [{ name: 'open', resource: 'open:*', maxTaintForAuto: Number.POSITIVE_INFINITY, hardDenyAbove: Number.POSITIVE_INFINITY }], defaultMaxTaintForAuto: Number.POSITIVE_INFINITY };

describe('a non-finite taint never auto-allows (dlp)', () => {
  it('a finite taint under an unbounded ceiling still allows', () => {
    expect(evaluateDlp(open, { verb: 'read', resource: 'open:x', taint: 1e9 }).outcome).toBe('allow');
  });
  // old: taint became +Infinity, and `Infinity > Infinity` is false, so it fell through to allow
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('a taint of %s is denied under an unbounded hard ceiling', (taint) => {
    expect(evaluateDlp(open, { verb: 'read', resource: 'open:x', taint }).outcome).toBe('deny');
  });
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('a taint of %s needs a human under an unbounded auto ceiling', (taint) => {
    expect(evaluateDlp({ classes: [], defaultMaxTaintForAuto: Number.POSITIVE_INFINITY }, { verb: 'read', resource: 'x', taint }).outcome).toBe('step_up');
  });
});
