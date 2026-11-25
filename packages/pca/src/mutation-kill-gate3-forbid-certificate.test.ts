/**
 * Mutation kills for the 0.5.0 flagship gate survivors in forbid-certificate.ts: signer ranking (an unsigned clause ranks
 * last even when the precedence list holds undefined; no precedence means no listed signer), permitSigners filtering only
 * permits, the id tie-break order of the certificate table, the malformed-certificate id rule, the default-deny winner,
 * the winner-kind comparison, the signer member of a certificate row, and both fail-closed catches.
 */
import { describe, expect, it } from 'vitest';
import { certificateConsistent, certify, checkForbidCertificate, decideClauses, type ForbidCertificate, type PolicyClause } from './forbid-certificate';
import type { ActionContext } from './predicates';

const ctx: ActionContext = { action: { verb: 'v', resource: '/r' } };
const F = (id: string, signer?: string): PolicyClause => ({ id, kind: 'forbid', ...(signer !== undefined ? { signer } : {}), when: { verb: 'v' } });
const winner = (cl: PolicyClause[], opts?: object) => decideClauses(cl, ctx, opts).witness.winner;
type Row = ForbidCertificate['clauses'][number];
const cert = (rows: Row[], decision: ForbidCertificate['decision'], w: ForbidCertificate['winner'], shadowed: string[]): ForbidCertificate => ({ v: 1, kind: 'forbid-wins', policy: 'p', action: 'a', decision, winner: w, shadowed, clauses: rows });
const row = (id: string, kind: Row['kind'], value: Row['value'] = 'true', signer?: string): Row => ({ id, kind, ...(signer !== undefined ? { signer } : {}), value });

describe('forbid-certificate.ts: decideClauses ranking', () => {
  it('an unsigned forbid ranks after every listed signer, also when the list holds undefined', () => {
    expect(winner([F('a'), F('b', 'c')], { precedence: ['x', 'y', 'c'] })).toEqual({ kind: 'forbid', id: 'b' });
    expect(winner([F('a'), F('b', 'x')], { precedence: [undefined, 'x'] as never })).toEqual({ kind: 'forbid', id: 'b' });
  });
  it('with no precedence every signer ranks equal and the smaller id wins', () => {
    expect(winner([F('b', 'Stryker was here'), F('a', 's')])).toEqual({ kind: 'forbid', id: 'a' });
  });
  it('permitSigners drops an unsigned permit even when the list holds undefined, and never drops a forbid', () => {
    const p: PolicyClause = { id: 'p', kind: 'permit', when: { verb: 'v' } };
    expect(decideClauses([p], ctx, { permitSigners: [undefined] as never }).decision).toBe('deny');
    expect(winner([F('f', 'x'), { ...p, signer: 'ok' }], { permitSigners: ['ok'] })).toEqual({ kind: 'forbid', id: 'f' });
  });
  it('a throw while reading the action is the malformed deny', () => {
    const bad = { get action(): never { throw new Error('boom'); } } as unknown as ActionContext;
    expect(decideClauses([], bad)).toEqual({ decision: 'deny', witness: { winner: { kind: 'malformed', id: null }, shadowed: [] }, values: [] });
  });
});

describe('forbid-certificate.ts: certify rows', () => {
  it('an unsigned clause has no signer member at all', () => {
    const c = certify([{ id: 'p', kind: 'permit', when: { verb: 'v' } }], ctx);
    expect(Object.keys(c.clauses[0]!)).toEqual(['id', 'kind', 'value']);
  });
  it('a row whose id no longer maps to a clause gets no signer (never a throw)', () => {
    let n = 0;
    const shifty = { kind: 'permit', signer: 's', when: { verb: 'v' }, get id() { n += 1; return `id${n}`; } } as unknown as PolicyClause;
    const c = certify([shifty], ctx);
    expect(c.clauses).toHaveLength(1);
    expect(Object.keys(c.clauses[0]!)).toEqual(['id', 'kind', 'value']);
  });
});

describe('forbid-certificate.ts: certificateConsistent', () => {
  it('forbid rows of equal rank sort by id, whatever order the table lists them in', () => {
    expect(certificateConsistent(cert([row('b', 'forbid'), row('a', 'forbid')], 'deny', { kind: 'forbid', id: 'a' }, ['b']))).toBe(true);
    expect(certificateConsistent(cert([row('a', 'forbid'), row('b', 'forbid')], 'deny', { kind: 'forbid', id: 'a' }, ['b']))).toBe(true);
    expect(certificateConsistent(cert([row('b', 'forbid'), row('a', 'forbid')], 'deny', { kind: 'forbid', id: 'b' }, ['a']))).toBe(false);
  });
  it('rank: unsigned last (also with undefined in the list), unlisted last, no precedence = all equal', () => {
    expect(certificateConsistent(cert([row('a', 'forbid'), row('b', 'forbid', 'true', 'c')], 'deny', { kind: 'forbid', id: 'b' }, ['a']), { precedence: ['x', 'y', 'c'] })).toBe(true);
    expect(certificateConsistent(cert([row('a', 'forbid'), row('b', 'forbid', 'true', 'x')], 'deny', { kind: 'forbid', id: 'b' }, ['a']), { precedence: [undefined, 'x'] as never })).toBe(true);
    expect(certificateConsistent(cert([row('a', 'forbid', 'true', 'q'), row('b', 'forbid', 'true', 'x')], 'deny', { kind: 'forbid', id: 'b' }, ['a']), { precedence: ['x'] })).toBe(true);
    expect(certificateConsistent(cert([row('b', 'forbid', 'true', 'Stryker was here'), row('a', 'forbid', 'true', 's')], 'deny', { kind: 'forbid', id: 'a' }, ['b']))).toBe(true);
  });
  it('a malformed certificate must name no clause', () => {
    expect(certificateConsistent(cert([], 'deny', { kind: 'malformed', id: null }, []))).toBe(true);
    expect(certificateConsistent(cert([], 'deny', { kind: 'malformed', id: 'x' }, []))).toBe(false);
  });
  it('with no permit the winner is none even when an escalate matched', () => {
    expect(certificateConsistent(cert([row('e', 'escalate')], 'deny', { kind: 'none', id: null }, ['e']))).toBe(true);
  });
  it('the winner kind must match', () => {
    expect(certificateConsistent(cert([row('p', 'permit')], 'allow', { kind: 'permit', id: 'p' }, []))).toBe(true);
    expect(certificateConsistent(cert([row('p', 'permit')], 'allow', { kind: 'escalate', id: 'p' }, []))).toBe(false);
  });
});

describe('forbid-certificate.ts: checkForbidCertificate', () => {
  it('a throw while recomputing is the fail-closed refusal', () => {
    const bad = { action: { verb: 'v', resource: '/r', params: { n: Number.NaN } } } as ActionContext;
    expect(checkForbidCertificate(cert([], 'deny', { kind: 'malformed', id: null }, []), [], bad)).toEqual({ ok: false, reason: 'certificate check error (fail closed)' });
  });
});
