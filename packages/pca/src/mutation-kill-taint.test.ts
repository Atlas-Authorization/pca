/** Mutation-kill tests for taint.ts: strict level names, registry admission, ref classification, and every fail-closed reason exactly. */
import { describe, expect, it } from 'vitest';
import { InMemoryTrustedInputRegistry, classifyRef, computeTaint, isTaintLevel, type TaintContext, type TaintLabel } from './taint';

/** The `id` a label carries (only tool/agent labels have one). */
const idOf = (l: TaintLabel): string | undefined => ('id' in l ? l.id : undefined);

const ctx = (): TaintContext => ({ registry: new InMemoryTrustedInputRegistry() });
const FAIL = (reason: string) => ({ taint: 1, label: { kind: 'agent' }, refs: [], valid: false, reason });

describe('isTaintLevel', () => {
  it('only real strings name a level (no ToPropertyKey coercion of arrays / objects)', () => {
    expect(isTaintLevel('web')).toBe(true);
    expect(isTaintLevel(['trusted'])).toBe(false);
    expect(isTaintLevel({ toString: () => 'web' })).toBe(false);
  });
});

describe('InMemoryTrustedInputRegistry.record', () => {
  it('admits only a non-empty string digest with a real level; never throws on a missing label', () => {
    const r = new InMemoryTrustedInputRegistry();
    r.record('', { kind: 'trusted' });
    r.record(['x'] as never, { kind: 'trusted' });
    r.record(5 as never, { kind: 'trusted' });
    expect(() => r.record('d', undefined as never)).not.toThrow();
    expect(r.size).toBe(0);
    r.record('d', { kind: 'web' });
    expect(r.size).toBe(1);
    expect(r.lookup('d')).toEqual({ kind: 'web' });
  });
});

describe('classifyRef', () => {
  it('a non-string ref is the worst label without consulting the registry', () => {
    const vouchesAll: TaintContext = { registry: { lookup: () => ({ kind: 'trusted' }) } };
    expect(classifyRef(5, vouchesAll)).toStrictEqual({ kind: 'agent' });
    expect(classifyRef('', vouchesAll)).toStrictEqual({ kind: 'agent' });
    expect(classifyRef('r', vouchesAll)).toEqual({ kind: 'trusted' });
  });
  it('an unverifiable ref keeps its id up to 128 chars inclusive', () => {
    const r128 = 'r'.repeat(128);
    const r129 = 'r'.repeat(129);
    expect(idOf(classifyRef(r128, ctx()))).toBe(r128);
    expect(classifyRef(r129, ctx())).toEqual({ kind: 'agent', id: undefined });
    expect((classifyRef(r129, ctx()) as { id?: string }).id).toBeUndefined();
  });
});

describe('computeTaint fail-closed reasons', () => {
  it('no registry lookup function', () => {
    expect(computeTaint({ trusted_refs: [] }, { registry: {} as never })).toEqual(FAIL('taint: no trusted-input registry'));
  });
  it('null / array / primitive provenance', () => {
    for (const p of [null, [], 'x', undefined]) expect(computeTaint(p, ctx())).toEqual(FAIL('taint: provenance is absent or malformed'));
  });
  it('trusted_refs present but not an array; absent is an empty lineage (valid, worst)', () => {
    expect(computeTaint({ trusted_refs: 'r' }, ctx())).toEqual(FAIL('taint: trusted_refs must be an array'));
    expect(computeTaint({}, ctx())).toEqual({ taint: 1, label: { kind: 'agent' }, refs: [], valid: true });
  });
  it('a non-string or empty ref', () => {
    expect(computeTaint({ trusted_refs: [''] }, ctx())).toEqual(FAIL('taint: trusted_refs must be non-empty strings'));
  });
  it('a registry throwing a non-Error is reported as unknown', () => {
    const c: TaintContext = {
      registry: {
        lookup: () => {
          throw 'down';
        },
      },
    };
    expect(computeTaint({ trusted_refs: ['r'] }, c)).toEqual(FAIL('taint: evaluation error (fail closed): unknown'));
  });
});
