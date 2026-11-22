/**
 * Mutation kills for the 0.5.0 flagship gate survivors in missing-context.ts: the longest-prefix supplier lookup, the
 * anchored supplier-path pattern, the leaf flattening (depth cap, empty objects), the conflict order, writing under a
 * bound key whose value is undefined, the action.params bootstrap, the collector's null / depth / empty-group / decided
 * guards, the params-unavailable case of an `action.params` field, the regex-budget case with no missing path, the
 * untrusted-path list and the fail-closed catch.
 */
import { describe, expect, it } from 'vitest';
import { bindContext, decideWithMissing, supplierOf, supplierTableError } from './missing-context';
import type { ActionContext } from './predicates';

const A = { verb: 'v', resource: 'r' };
const MISSING = { field: 'subject.missing', op: 'eq' as const, value: 1 };
const ESC_MISSING = { decision: 'escalate', reason: 'escalate: missing_context principal:subject.missing', missing: [{ path: 'subject.missing', supplier: 'principal' }] };
const ILL = { decision: 'deny', reason: 'ill_typed_context', missing: [] };
const decide = (where: unknown, bound: unknown, extra: Record<string, unknown> = {}) => decideWithMissing({ where, bound: bound as ActionContext, ...extra } as never);

describe('supplierOf: the longest matching prefix wins in any key order', () => {
  it('a shorter key listed after the longer one does not override it', () => {
    expect(supplierOf('subject.a.b', { 'subject.a': 'rs_observation', subject: 'discharge_issuer' })).toBe('rs_observation');
    expect(supplierOf('subject.a.b', { subject: 'discharge_issuer', 'subject.a': 'rs_observation' })).toBe('rs_observation');
  });
});

describe('supplierTableError: the path pattern is anchored at both ends', () => {
  it('a prefix or a suffix outside the grammar is refused', () => {
    expect(supplierTableError({ xsubject: 'principal' })).toBe("bad supplier path 'xsubject'");
    expect(supplierTableError({ 'subject-x': 'principal' })).toBe("bad supplier path 'subject-x'");
    expect(supplierTableError({ 'subject.a': 'principal' })).toBeNull();
  });
});

describe('bindContext: flattening', () => {
  it('flattening stops 17 segments below the root: the conflict is reported at that path', () => {
    let supplied: unknown = 2;
    let bound: unknown = 1;
    for (let i = 19; i >= 0; i--) {
      supplied = { [`k${i}`]: supplied };
      bound = { [`k${i}`]: bound };
    }
    const r = bindContext({ action: A, subject: bound } as never, { subject: supplied as Record<string, unknown> });
    expect(r.conflicts).toEqual([`subject.${Array.from({ length: 17 }, (_, i) => `k${i}`).join('.')}`]);
  });
  it('an empty supplied object is a leaf and is written', () => {
    expect(bindContext({ action: A } as never, { subject: { a: {} } }).context).toEqual({ action: A, subject: { a: {} } });
  });
});

describe('bindContext: conflicts are reported in path order', () => {
  it('action.params before env before subject (supplied in another order)', () => {
    const r = bindContext({ action: { ...A, params: { x: 1 } }, subject: { a: 1 }, env: { b: 1 } } as never, { action: { params: { x: 2 } }, subject: { a: 2 }, env: { b: 2 } } as never);
    expect(r.conflicts).toEqual(['action.params.x', 'env.b', 'subject.a']);
  });
});

describe('bindContext: writing a supplied value', () => {
  it('a bound key whose value is undefined is replaced by the supplied subtree', () => {
    const r = bindContext({ action: A, subject: { a: undefined } } as never, { subject: { a: { b: 1 } } });
    expect(r).toEqual({ context: { action: A, subject: { a: { b: 1 } } }, conflicts: [], dropped: [] });
  });
  it('action.params is created with an empty verb and resource when the bound context has no action', () => {
    expect(bindContext({} as never, { action: { params: { x: 1 } } } as never).context).toEqual({ action: { verb: '', resource: '', params: { x: 1 } } });
  });
  it('bound params are kept when a new param is supplied', () => {
    expect(bindContext({ action: { ...A, params: { y: 1 } } } as never, { action: { params: { x: 1 } } } as never).context).toEqual({ action: { ...A, params: { y: 1, x: 1 } } });
  });
  it('a supplied subject value never touches the action', () => {
    expect(bindContext({ action: A } as never, { subject: { x: 1 } }).context).toEqual({ action: A, subject: { x: 1 } });
  });
});

describe('decideWithMissing: the collector', () => {
  const B = { action: A };
  it('a null or undefined condition (top level or under not) is ill typed, never an evaluation error', () => {
    expect(decide([null, MISSING], B)).toEqual(ILL);
    expect(decide([undefined, MISSING], B)).toEqual(ILL);
    expect(decide([{ not: undefined }, MISSING], B)).toEqual(ILL);
  });
  it('a condition 64 groups deep is collected; 65 deep is ill typed', () => {
    const nest = (n: number) => {
      let c: unknown = MISSING;
      for (let i = 0; i < n; i++) c = { not: c };
      return c;
    };
    expect(decide([nest(64)], B)).toEqual(ESC_MISSING);
    expect(decide([nest(65)], B)).toEqual(ILL);
  });
  it('all_of and any_of children are collected', () => {
    expect(decide([{ all_of: [MISSING] }], B)).toEqual(ESC_MISSING);
    expect(decide([{ any_of: [MISSING] }], B)).toEqual(ESC_MISSING);
  });
  it('an empty group is ill typed even next to a missing path', () => {
    expect(decide([{ all_of: [] }, MISSING], B)).toEqual(ILL);
    expect(decide([{ any_of: [] }, MISSING], B)).toEqual(ILL);
  });
  it('a decided condition next to a missing one is skipped', () => {
    expect(decide([{ field: 'subject.y', op: 'exists' }, MISSING], { action: A, subject: { y: 1 } })).toEqual(ESC_MISSING);
  });
  it('an empty ref is never reported as a missing path', () => {
    expect(decide([{ field: 'subject.missing', op: 'eq', ref: '' }], B)).toEqual(ESC_MISSING);
  });
  it('a non-string field is ill typed', () => {
    expect(decide([{ field: 5, op: 'eq', value: 1 }, MISSING], B)).toEqual(ILL);
    expect(decide([{ op: 'eq', value: 1 }, MISSING], B)).toEqual(ILL);
  });
  it('a present but ill-typed value is ill typed while params are absent', () => {
    expect(decide([{ field: 'subject.x', op: 'gt', value: 5 }], { action: A, subject: { x: 'str' } })).toEqual(ILL);
  });
});

describe('decideWithMissing: an action.params field when params are unavailable', () => {
  const ESC_P = { decision: 'escalate', reason: 'escalate: missing_context principal:action.params', missing: [{ path: 'action.params', supplier: 'principal' }] };
  it('null or non-object params are missing context; object params with an ill-typed comparison are not', () => {
    expect(decide([{ field: 'action.params', op: 'exists' }], { action: { ...A, params: null } })).toEqual(ESC_P);
    expect(decide([{ field: 'action.params', op: 'gt', value: 5 }], { action: { ...A, params: 5 } })).toEqual(ESC_P);
    expect(decide([{ field: 'action.params', op: 'gt', value: 5 }], { action: { ...A, params: {} } })).toEqual(ILL);
  });
  it('a present field that merely ends in action.params. is not a params-rooted field', () => {
    expect(decide([{ field: 'subject.action.params.', op: 'gt', value: 'x' }], { action: A, subject: { action: { params: { '': 5 } } } })).toEqual(ILL);
  });
});

describe('decideWithMissing: an undecided list with no missing path', () => {
  it('the 65th regex of one document is refused (unknown), yet each condition alone is decided: ill typed', () => {
    const where = Array.from({ length: 65 }, () => ({ field: 'subject.s', op: 'matches', value: 'a' }));
    expect(decide(where, { action: A, subject: { s: 'a' } })).toEqual(ILL);
    expect(decide(where.slice(0, 64), { action: A, subject: { s: 'a' } })).toEqual({ decision: 'allow', missing: [] });
  });
});

describe('decideWithMissing: reasons', () => {
  it('several untrusted paths are listed comma-separated', () => {
    expect(decide([MISSING, { field: 'subject.m2', op: 'eq', value: 1 }], { action: A }, { suppliers: { subject: 'agent_declared_untrusted' } })).toEqual({
      decision: 'deny',
      reason: 'missing_context_untrusted: subject.m2,subject.missing',
      missing: [{ path: 'subject.m2', supplier: 'agent_declared_untrusted' }, { path: 'subject.missing', supplier: 'agent_declared_untrusted' }],
    });
  });
  it('an internal error is the fail-closed deny', () => {
    expect(decideWithMissing(null as never)).toEqual({ decision: 'deny', reason: 'evaluation error (fail closed)', missing: [] });
  });
});
