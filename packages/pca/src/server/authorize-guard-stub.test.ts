/** The defensive paths of authorize() that a real guard cannot reach: a guard that throws, or that allows without an operation. */
import { describe, expect, it, vi } from 'vitest';

const state: { guard: (req: unknown) => unknown } = { guard: () => ({}) };
vi.mock('./require-pca', async (orig) => ({ ...(await orig<typeof import('./require-pca')>()), requirePCA: () => (req: unknown) => state.guard(req) }));

import { createAuthorizer } from './authorize';

const opts = { audience: 'rs', resolveGrant: async () => null, budgetStore: { get: () => undefined, put: () => undefined } as never, hooks: { revocation: () => ({ enforced: true, ok: true }) } };
const op = { verb: 'do', resource: 'r', params: {} };

describe('authorize: defensive paths', () => {
  it('an allow without a bound operation is refused', async () => {
    state.guard = () => ({ ok: true, verdict: { allow: true, r: 0, requiredThreshold: { t: 1, proof: 'claim', optimisticAllowed: true }, checks: {}, reasons: [] }, pcactn: {} });
    const r = await createAuthorizer(opts)({ operation: op });
    expect(r).toMatchObject({ allow: false, status: 403, reason: 'operation: the decision is not bound to an operation (fail closed)', assurance: { operation: { outcome: 'fail' } } });
    if (!r.allow) expect(r.verdict.checks).toEqual({ operation: 'fail' });
  });
  it('a guard that throws is a refusal with its message, or "unknown" for a non-Error', async () => {
    state.guard = () => { throw new Error('boom'); };
    const a = await createAuthorizer(opts)({ operation: op });
    expect(a).toMatchObject({ allow: false, status: 403, reason: 'authorize error (fail closed): boom', assurance: { authorize: { outcome: 'fail' } } });
    if (!a.allow) expect(a.verdict.checks).toEqual({ authorize: 'fail' });
    state.guard = () => { throw 'str'; };
    expect(await createAuthorizer(opts)({ operation: op })).toMatchObject({ allow: false, reason: 'authorize error (fail closed): unknown' });
  });
  it('a denial from the guard carries its challenge', async () => {
    state.guard = () => ({ ok: false, status: 401, verdict: { allow: false, r: 1, requiredThreshold: { t: 3, proof: 'strong', optimisticAllowed: false }, checks: { pcactn: 'fail' }, reasons: ['x'] }, wwwAuthenticate: 'PCA realm="x"' });
    expect(await createAuthorizer(opts)({ operation: op })).toMatchObject({ allow: false, status: 401, reason: 'x', wwwAuthenticate: 'PCA realm="x"' });
  });
  describe('the decisive reason', () => {
    const denial = (checks: Record<string, string>, reasons: string[]) => {
      state.guard = () => ({ ok: false, status: 403, verdict: { allow: false, r: 1, requiredThreshold: { t: 3, proof: 'strong', optimisticAllowed: false }, checks, reasons } });
      return createAuthorizer(opts)({ operation: op }).then((r) => (r.allow ? 'ALLOW' : r.reason));
    };
    it('the operation binding comes first, wherever it sits', async () => {
      expect(await denial({ a: 'fail', operation: 'fail', b: 'fail' }, ['a: x', 'operation: y', 'b: z'])).toBe('operation: y');
      expect(await denial({ x: 'fail', y: 'fail', z: 'fail', operation: 'fail' }, ['x: 1', 'y: 2', 'z: 3', 'operation: 4'])).toBe('operation: 4');
      expect(await denial({ operation: 'fail', x: 'fail' }, ['x: 1', 'operation: 2'])).toBe('operation: 2');
    });
    it('otherwise the first failing check in order, skipping passing checks and checks without a reason', async () => {
      expect(await denial({ x: 'fail', y: 'fail', z: 'fail' }, ['z: 3', 'y: 2', 'x: 1'])).toBe('x: 1');
      expect(await denial({ operation: 'pass', x: 'fail', y: 'fail' }, ['operation: not this', 'y: 2', 'x: 1'])).toBe('x: 1');
      expect(await denial({ a: 'pass', b: 'fail' }, ['a: not failing', 'b: 2'])).toBe('b: 2');
      expect(await denial({ a: 'fail', b: 'fail' }, ['zzz', 'b: q'])).toBe('b: q');
      expect(await denial({ a: 'fail' }, ['b says a:', 'a: real'])).toBe('a: real');
    });
    it('falls back to the first reason, then to "denied"', async () => {
      expect(await denial({ a: 'fail' }, ['no prefix', 'second'])).toBe('no prefix');
      expect(await denial({ a: 'pass' }, ['first', 'second'])).toBe('first');
      expect(await denial({}, [])).toBe('denied');
    });
  });
});
