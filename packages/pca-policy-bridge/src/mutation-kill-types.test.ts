import { describe, expect, it } from 'vitest';
import type { ActionContext, Predicate } from '@atlasauth/pca';
import { decide, type BridgeResult } from './types';

const ctx = (verb: string, resource = 'r', env: Record<string, unknown> = {}): ActionContext =>
  ({ action: { verb, resource, params: {} }, subject: {}, env }) as unknown as ActionContext;
const permitA: Predicate = { verb: 'a', resource: '*' };
const denyA: Predicate = { verb: 'a', resource: 'secret' };
const report = (errors: string[] = []) => ({ source: 'cedar' as const, translated: [], skipped: [], errors });

describe('decide (deny-overrides-permit)', () => {
  it('permits when no deny matches', () => {
    const r = decide({ predicates: [permitA], denies: [denyA] }, ctx('a', 'public'));
    expect(r).toEqual({ allowed: true, matched: permitA });
  });
  it('a matching deny wins, naming the deny predicate and a fixed reason', () => {
    const r = decide({ predicates: [permitA], denies: [denyA] }, ctx('a', 'secret'));
    expect(r).toEqual({ allowed: false, matched: denyA, reason: 'forbidden by deny policy' });
  });
  it('the first matching deny is reported', () => {
    const d2: Predicate = { verb: '*', resource: 'secret' };
    const r = decide({ predicates: [permitA], denies: [denyA, d2] }, ctx('a', 'secret'));
    expect(r.matched).toBe(denyA);
  });
  it('no denies: the permit set decides, including its default-deny reason', () => {
    expect(decide({ predicates: [permitA], denies: [] }, ctx('b'))).toEqual({ allowed: false, reason: 'no predicate permits b on r' });
    expect(decide({ predicates: [], denies: [] }, ctx('a'))).toEqual({ allowed: false, reason: 'envelope grants no predicates' });
  });
  it('a deny that does not match falls through to the permit result', () => {
    expect(decide({ predicates: [permitA], denies: [denyA] }, ctx('b', 'secret')).allowed).toBe(false);
    expect(decide({ predicates: [permitA], denies: [{ verb: 'zzz' }] }, ctx('a')).allowed).toBe(true);
  });
  it('a report with errors fails closed before anything else', () => {
    const res = { predicates: [permitA], denies: [], report: report(['boom']) } as Pick<BridgeResult, 'predicates' | 'denies' | 'report'>;
    expect(decide(res, ctx('a'))).toEqual({ allowed: false, reason: 'translation incomplete (fail closed)' });
    const both = { predicates: [permitA], denies: [denyA], report: report(['x', 'y']) };
    expect(decide(both, ctx('a', 'public'))).toEqual({ allowed: false, reason: 'translation incomplete (fail closed)' });
  });
  it('a clean report (or none) does not block', () => {
    expect(decide({ predicates: [permitA], denies: [], report: report([]) }, ctx('a')).allowed).toBe(true);
    expect(decide({ predicates: [permitA], denies: [] }, ctx('a')).allowed).toBe(true);
  });
  it('deny evaluation errors are not treated as a match', () => {
    const bad = { verb: 'a', resource: 'r', where: [{ field: 'env.x', op: 'zzz' }] } as unknown as Predicate;
    expect(decide({ predicates: [permitA], denies: [bad] }, ctx('a')).allowed).toBe(true);
  });
});
