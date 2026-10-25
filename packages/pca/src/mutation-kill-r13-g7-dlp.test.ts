/**
 * r13 mutation kills for dlp.ts: exact evaluateDlp results (pattern matching, verb filters, most-specific class
 * selection between '*', prefixes and exact patterns, ceiling boundaries, labels and reasons) and defaultDlpPolicy.
 */
import { describe, expect, it } from 'vitest';
import { defaultDlpPolicy, evaluateDlp, type DataClass } from './dlp';

const C = (name: string, resource: string, extra: Partial<DataClass> = {}): DataClass => ({ name, resource, maxTaintForAuto: 1, ...extra });
const ev = (classes: DataClass[], resource: string, taint = 0, verb = 'read', def?: number) =>
  evaluateDlp({ classes, ...(def !== undefined ? { defaultMaxTaintForAuto: def } : {}) }, { verb, resource, taint });

describe('pattern matching', () => {
  it("'*' matches everything, a prefix matches by startsWith, otherwise exact", () => {
    expect(ev([C('all', '*')], 'x').class).toBe('all');
    expect(ev([C('p', 'db/*')], 'db/users').class).toBe('p');
    expect(ev([C('p', 'db/*')], 'dc/users').class).toBeUndefined();
    expect(ev([C('e', 'abc')], 'abc').class).toBe('e');
    expect(ev([C('e', 'abc')], 'abd').class).toBeUndefined();
    expect(ev([C('e', 'abc')], 'abcd').class).toBeUndefined();
    expect(ev([C('empty', '')], 'x').class).toBeUndefined();
    expect(ev([C('empty', '')], '').class).toBe('empty');
  });
  it('a verb list restricts the class', () => {
    expect(ev([C('w', '*', { verbs: ['write'] })], 'x', 0, 'read').class).toBeUndefined();
    expect(ev([C('w', '*', { verbs: ['write'] })], 'x', 0, 'write').class).toBe('w');
  });
});

describe('most specific class', () => {
  it('exact beats a longer matching prefix beats a shorter prefix beats *', () => {
    expect(ev([C('star', '*'), C('exact', 'abc'), C('long', 'abc*')], 'abc').class).toBe('exact');
    expect(ev([C('long', 'abc*'), C('exact', 'abc'), C('star', '*')], 'abc').class).toBe('exact');
    expect(ev([C('star', '*'), C('exact', 'abc')], 'abc').class).toBe('exact');
    expect(ev([C('exact', 'abc'), C('star', '*')], 'abc').class).toBe('exact');
    expect(ev([C('short', 'a*'), C('long', 'ab*'), C('star', '*')], 'abc').class).toBe('long');
    expect(ev([C('star', '*'), C('short', 'a*')], 'abc').class).toBe('short');
    expect(ev([C('star', '*'), C('empty', '')], '').class).toBe('empty');
  });
});

describe('ceilings', () => {
  it('no ceiling at all allows, naming the class when there is one', () => {
    expect(ev([], 'x', 99)).toStrictEqual({ outcome: 'allow' });
    expect(ev([C('c', '*', { maxTaintForAuto: undefined as never, hardDenyAbove: 1 })], 'x', 5)).toStrictEqual({ outcome: 'allow', class: 'c' });
  });
  it('hard ceiling is strict', () => {
    const cls = [C('pii', '*', { maxTaintForAuto: 0, hardDenyAbove: 2 })];
    expect(ev(cls, 'x', 3)).toStrictEqual({ outcome: 'deny', class: 'pii', reason: "taint 3 exceeds hard ceiling 2 for 'pii'" });
    expect(ev(cls, 'x', 2)).toStrictEqual({ outcome: 'step_up', class: 'pii', reason: "taint 2 > 0 for 'pii' — needs human review" });
    expect(ev(cls, 'x', 0)).toStrictEqual({ outcome: 'allow', class: 'pii' });
  });
  it('the default ceiling labels <default>', () => {
    expect(ev([], 'x', 2, 'read', 1)).toStrictEqual({ outcome: 'step_up', reason: "taint 2 > 1 for '<default>' — needs human review" });
    expect(ev([], 'x', 1, 'read', 1)).toStrictEqual({ outcome: 'allow' });
  });
});

describe('defaultDlpPolicy', () => {
  it('builds only the requested classes', () => {
    expect(defaultDlpPolicy()).toEqual({ classes: [] });
    expect(defaultDlpPolicy({ piiResource: 'pii/*', secretsResource: 'vault/*' })).toEqual({
      classes: [
        { name: 'pii', resource: 'pii/*', maxTaintForAuto: 0, hardDenyAbove: 2 },
        { name: 'secrets', resource: 'vault/*', maxTaintForAuto: 0, hardDenyAbove: 0 },
      ],
    });
    expect(defaultDlpPolicy({ secretsResource: 'vault/*' }).classes.map((c) => c.name)).toEqual(['secrets']);
    expect(defaultDlpPolicy({ piiResource: 'pii/*' }).classes.map((c) => c.name)).toEqual(['pii']);
  });
});
