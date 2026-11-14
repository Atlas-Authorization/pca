import { describe, expect, it } from 'vitest';
import type { ActionContext, Condition, Predicate } from '@atlasauth/pca';
import { collect, decisionAtContext, probeSet, search, toModel, vetoApplies, type Probes } from './enumerate';
import type { TightenLike, Veto } from './types';

const cond = (field: string, op: string, value?: unknown, extra: object = {}) => ({ field, op, value, ...extra }) as unknown as Condition;
const pred = (verb: string, where?: Condition[], resource?: string): Predicate => ({ verb, ...(resource !== undefined ? { resource } : {}), ...(where ? { where } : {}) }) as Predicate;

const ctxOf = (params: Record<string, unknown>, subject: Record<string, unknown> = {}): ActionContext =>
  ({ action: { verb: 'v', resource: '/r', params }, subject, env: {} }) as unknown as ActionContext;

describe('probeSet', () => {
  it('lists the permits, then each veto trigger, unless clause and over threshold, then each tighten trigger, then the meets', () => {
    const p = pred('p');
    const w1 = pred('w1');
    const w2 = pred('w2');
    const w3 = pred('w3');
    const u1 = cond('subject.a', 'eq', 1);
    const t = cond('subject.t', 'eq', 2);
    const q = pred('q');
    const vetoes: Veto[] = [
      { id: 'a', kind: 'deny', when: w1, unless: [u1], over: { path: 'action.params.n', threshold: 7 } },
      { id: 'b', kind: 'deny', when: w2, unless: [] },
      { id: 'c', kind: 'approval', when: w3 },
    ];
    const tighten: TightenLike[] = [{ id: 't', when: t, signal: 'escalate' }];
    const model = toModel({ predicates: [p], vetoes, tighten, meet: [{ predicates: [q] }] });
    expect(probeSet(model)).toEqual([
      p,
      w1,
      { verb: '*', where: [u1] },
      { verb: '*', where: [{ field: 'action.params.n', op: 'gt', value: 7 }] },
      w2,
      w3,
      { verb: '*', where: [t] },
      q,
    ]);
  });
});

describe('undecidable ordering operands', () => {
  const reasons = (c: Condition): string[] => toModel({ predicates: [pred('v', [c])] }).undecidable;
  it('a finite numeric threshold is decided; anything else is flagged with the exact reason', () => {
    for (const op of ['lt', 'lte', 'gt', 'gte']) {
      expect(reasons(cond('action.params.n', op, 5))).toEqual([]);
      const msg = `\`${op}\` against a non-numeric operand — string ordering is not enumerated exactly`;
      expect(reasons(cond('action.params.n', op, 'abc'))).toEqual([msg]);
      expect(reasons(cond('action.params.n', op, Infinity))).toEqual([msg]);
      expect(reasons(cond('action.params.n', op, NaN))).toEqual([msg]);
    }
  });
});

describe('toModel meets', () => {
  const plain = { predicates: [pred('a')] };
  const badMeet = { predicates: [pred('a')], caveats: [{ type: 'zzz' }] as never };
  const cap = (c: string) => ({ predicates: [pred('a')], caveats: [{ type: 'reversibility_max', class: c }] as never });

  it('reports the reason of the first unsatisfiable meet, not of a satisfiable one', () => {
    const m = toModel({ predicates: [pred('a')], meet: [plain, badMeet] });
    expect(m.caveatSat).toBe(false);
    expect(m.caveatReason).toBe("unknown caveat type 'zzz' (fail closed)");
    const ok = toModel({ predicates: [pred('a')], meet: [plain, plain] });
    expect(ok.caveatSat).toBe(true);
    expect(ok.caveatReason).toBeUndefined();
  });

  it('takes the strictest reversibility cap over the policy and its meets', () => {
    expect(toModel({ ...cap('irreversible'), meet: [cap('rate_limited')] }).revCap).toBe(1);
    expect(toModel({ predicates: [pred('a')], meet: [cap('rate_limited')] }).revCap).toBe(1);
    expect(toModel({ ...cap('reversible'), meet: [cap('irreversible')] }).revCap).toBe(0);
    expect(toModel({ ...cap('rate_limited'), meet: [plain] }).revCap).toBe(1);
    expect(toModel({ ...cap('reversible'), meet: [plain] }).revCap).toBe(0);
    expect(toModel({ ...cap('rate_limited'), meet: [cap('irreversible'), cap('reversible')] }).revCap).toBe(0);
    expect(toModel({ predicates: [pred('a')], meet: [plain] }).revCap).toBeUndefined();
  });

  it('collects the undecidable reasons of the meets without stray entries', () => {
    const re = { predicates: [pred('a', undefined, 're:a.*')] };
    const reason = 're: regex resource matcher — resource dimension cannot be soundly enumerated';
    expect(toModel({ predicates: [pred('a')], meet: [re] }).undecidable).toEqual([reason]);
    expect(toModel({ predicates: [pred('a')], meet: [plain] }).undecidable).toEqual([]);
  });
});

describe('vetoApplies', () => {
  const over: Veto = { id: 'o', kind: 'deny', when: pred('v'), over: { path: 'action.params.n', threshold: 100 } };

  it('the amount gate: only a finite non-negative amount at or under the threshold lets the veto stand down', () => {
    expect(vetoApplies(over, ctxOf({}))).toBe(true); // unresolved
    expect(vetoApplies(over, ctxOf({ n: '5' }))).toBe(true); // not a number
    expect(vetoApplies(over, ctxOf({ n: NaN }))).toBe(true);
    expect(vetoApplies(over, ctxOf({ n: Infinity }))).toBe(true);
    expect(vetoApplies(over, ctxOf({ n: -1 }))).toBe(true);
    expect(vetoApplies(over, ctxOf({ n: 101 }))).toBe(true);
    expect(vetoApplies(over, ctxOf({ n: 100 }))).toBe(false);
    expect(vetoApplies(over, ctxOf({ n: 50 }))).toBe(false);
    expect(vetoApplies(over, ctxOf({ n: 0 }))).toBe(false);
    expect(vetoApplies({ ...over, when: pred('other') }, ctxOf({}))).toBe(false);
  });

  it('unless: the veto stands down only when EVERY condition affirmatively holds', () => {
    const yes1 = cond('subject.a', 'eq', 1);
    const yes2 = cond('subject.b', 'eq', 2);
    const no = cond('subject.b', 'eq', 99);
    const ctx = ctxOf({}, { a: 1, b: 2 });
    const deny = (unless: Condition[]): Veto => ({ id: 'u', kind: 'deny', when: pred('v'), unless });
    expect(vetoApplies(deny([yes1, yes2]), ctx)).toBe(false);
    expect(vetoApplies(deny([yes1, no]), ctx)).toBe(true);
    expect(vetoApplies(deny([no, yes1]), ctx)).toBe(true);
    expect(vetoApplies(deny([no]), ctx)).toBe(true);
    // for an approval veto `unless` is the evidence a human approved: it never lets the action through autonomously
    expect(vetoApplies({ id: 'u', kind: 'approval', when: pred('v'), unless: [yes1, yes2] }, ctx)).toBe(true);
  });
});

describe('decisionAtContext', () => {
  const ctx = ctxOf({}, { a: 1 });
  const base = { predicates: [pred('v')] };
  const tighten = (when: Condition, signal: 'escalate' | 'deny'): TightenLike[] => [{ id: 't', when, signal }];

  it('a tighten rule that is decidedly false does not cap; true or undecidable caps at its signal', () => {
    const isFalse = cond('subject.a', 'eq', 2);
    const isTrue = cond('subject.a', 'eq', 1);
    const unknown = cond('subject.missing', 'eq', 1);
    expect(decisionAtContext(toModel({ ...base, tighten: tighten(isFalse, 'escalate') }), ctx)).toBe('allow');
    expect(decisionAtContext(toModel({ ...base, tighten: tighten(isFalse, 'deny') }), ctx)).toBe('allow');
    expect(decisionAtContext(toModel({ ...base, tighten: tighten(isTrue, 'escalate') }), ctx)).toBe('escalate');
    expect(decisionAtContext(toModel({ ...base, tighten: tighten(isTrue, 'deny') }), ctx)).toBe('deny');
    expect(decisionAtContext(toModel({ ...base, tighten: tighten(unknown, 'escalate') }), ctx)).toBe('escalate');
    expect(decisionAtContext(toModel({ ...base, tighten: tighten(unknown, 'deny') }), ctx)).toBe('deny');
  });

  it('a meet that escalates escalates the whole; one that denies denies it', () => {
    const meetWith = (kind: 'approval' | 'deny') => ({ predicates: [pred('v')], vetoes: [{ id: 'm', kind, when: pred('v') } as Veto] });
    expect(decisionAtContext(toModel({ ...base, meet: [meetWith('approval')] }), ctx)).toBe('escalate');
    expect(decisionAtContext(toModel({ ...base, meet: [meetWith('deny')] }), ctx)).toBe('deny');
    expect(decisionAtContext(toModel({ ...base, meet: [{ predicates: [pred('v')] }] }), ctx)).toBe('allow');
  });
});

describe('search and collect bounds', () => {
  const grid = (verbs: string[]): Probes => ({ verbs, resources: ['r'], revClasses: [undefined], fields: [] });

  it('a grid exactly at the bound is walked; one over it overflows with no hits', () => {
    const g = grid(['a', 'b', 'c', 'd']);
    expect(collect(g, () => true, 3, 2)).toEqual({ hits: [], overflow: true });
    expect(collect(g, () => true, 4, 4).overflow).toBe(false);
    expect(collect(g, () => true, 4, 4).hits.map((r) => r.verb)).toEqual(['a', 'b', 'c', 'd']);
    expect(search(g, () => false, 4)).toEqual({ overflow: false });
    expect(search(g, () => false, 3)).toEqual({ overflow: true });
  });

  it('collect stops at exactly `limit` hits', () => {
    const g = grid(['a', 'b', 'c', 'd']);
    expect(collect(g, () => true, 100, 2).hits.map((r) => r.verb)).toEqual(['a', 'b']);
    expect(collect(g, () => true, 100, 1).hits.map((r) => r.verb)).toEqual(['a']);
    expect(collect(g, () => true, 100, 3).hits.map((r) => r.verb)).toEqual(['a', 'b', 'c']);
    expect(collect(g, (r) => r.verb !== 'a', 100, 2).hits.map((r) => r.verb)).toEqual(['b', 'c']);
    expect(collect(g, () => true, 100, 9).hits).toHaveLength(4);
  });
});
