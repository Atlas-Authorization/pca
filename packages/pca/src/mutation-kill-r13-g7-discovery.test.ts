/**
 * r13 mutation kills for discovery.ts: buildDiscoveryDocument / parseDiscoveryDocument / parseDiscoveryIntent exact
 * refusals and the optional-member narrowing (null, primitive and mixed-type look-alikes), and fetchDiscovery's URL,
 * request headers and missing-fetch error.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildDiscoveryDocument, fetchDiscovery, parseDiscoveryDocument, parseDiscoveryIntent } from './discovery';

/** Run f, capturing its value or its error (name + message), so a mutant that throws fails an assertion, not an error. */
const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};
/** Async form of settle. */
const settleAsync = async <T>(f: () => Promise<T>) => {
  try {
    return { ok: true as const, value: await f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};

afterEach(() => vi.unstubAllGlobals());

const base = { audience: 'rs', pca_versions: [2], signature_suites: ['ed25519'], action_header: 'PCA-Action' };
const parse = (over: Record<string, unknown>) => parseDiscoveryDocument({ ...base, ...over });

describe('buildDiscoveryDocument', () => {
  it('refuses a non-string audience even when it has a length', () => {
    expect(() => buildDiscoveryDocument({ audience: ['rs'] as unknown as string })).toThrow(new Error('buildDiscoveryDocument: audience is required'));
  });
  it('carries metadata through', () => {
    expect(settle(() => buildDiscoveryDocument({ audience: 'rs', metadata: { a: 1 } }).metadata)).toEqual({ ok: true, value: { a: 1 } });
  });
});

describe('parseDiscoveryDocument', () => {
  it('not an object', () => {
    for (const v of [null, 5, 'x', undefined]) expect(() => parseDiscoveryDocument(v)).toThrow(new Error('parseDiscoveryDocument: not an object'));
  });
  it('required members', () => {
    expect(() => parse({ audience: ['rs'] })).toThrow(new Error('parseDiscoveryDocument: missing audience'));
    expect(() => parse({ pca_versions: [2, 'x'] })).toThrow(new Error('parseDiscoveryDocument: pca_versions must be a number[]'));
    const SS = new Error('parseDiscoveryDocument: signature_suites must be a string[]');
    expect(() => parse({ signature_suites: ['a', 5] })).toThrow(SS);
    expect(() => parse({ signature_suites: [5] })).toThrow(SS);
    expect(() => parse({ signature_suites: undefined })).toThrow(SS);
    const AH = new Error('parseDiscoveryDocument: missing action_header');
    expect(() => parse({ action_header: '' })).toThrow(AH);
    expect(() => parse({ action_header: 5 })).toThrow(AH);
    expect(() => parse({ action_header: ['h'] })).toThrow(AH);
  });
  it('the minimal document has no optional members', () => {
    expect(settle(() => parseDiscoveryDocument(base))).toStrictEqual({ ok: true, value: base });
  });
  it('keeps well-formed optional members', () => {
    const d = parse({ required_checks: ['a'], endpoints: { stepup: 'u' }, trusted_roots: ['k'], metadata: { m: 1 } });
    expect(d).toStrictEqual({ ...base, required_checks: ['a'], endpoints: { stepup: 'u' }, trusted_roots: ['k'], metadata: { m: 1 } });
  });
  it('drops malformed optional members', () => {
    for (const bad of [null, 'x', 5, ['a', 5], [5]]) {
      const d = parse({ required_checks: bad, trusted_roots: bad });
      expect('required_checks' in d).toBe(false);
      expect('trusted_roots' in d).toBe(false);
    }
    for (const bad of [null, 'x', 5, undefined]) {
      const d = parse({ endpoints: bad, metadata: bad });
      expect('endpoints' in d).toBe(false);
      expect('metadata' in d).toBe(false);
    }
  });
  it('parses an intent block', () => {
    expect(settle(() => parse({ intent: { versions: [2] } }).intent)).toEqual({ ok: true, value: { versions: [2] } });
    expect(() => parse({ intent: null })).toThrow(new Error('parseDiscoveryDocument: intent must be an object'));
  });
});

describe('parseDiscoveryIntent', () => {
  it('versions must all be 1 or 2', () => {
    expect(() => parseDiscoveryIntent({ versions: [1, 3] })).toThrow(new Error('parseDiscoveryDocument: intent.versions must list 1 and/or 2'));
  });
  it('schema_keys entries', () => {
    const E = new Error('parseDiscoveryDocument: intent.schema_keys entries are {kid, alg, pk, pq_pk?}');
    const k = { kid: 'k', alg: 'ed25519', pk: 'p' };
    expect(settle(() => parseDiscoveryIntent({ versions: [2], schema_keys: [k, { ...k, pq_pk: 'q' }] }).schema_keys)).toStrictEqual({ ok: true, value: [k, { ...k, pq_pk: 'q' }] });
    expect(() => parseDiscoveryIntent({ versions: [2], schema_keys: [{ ...k, alg: 5 }] })).toThrow(E);
    expect(() => parseDiscoveryIntent({ versions: [2], schema_keys: [{ ...k, pk: 5 }] })).toThrow(E);
    expect(() => parseDiscoveryIntent({ versions: [2], schema_keys: [null] })).toThrow(E);
  });
  it('question_relay must be a boolean', () => {
    expect(settle(() => parseDiscoveryIntent({ versions: [2], question_relay: true }).question_relay)).toEqual({ ok: true, value: true });
    expect(settle(() => parseDiscoveryIntent({ versions: [2], question_relay: false }).question_relay)).toEqual({ ok: true, value: false });
    expect(() => parseDiscoveryIntent({ versions: [2], question_relay: 'yes' })).toThrow(new Error('parseDiscoveryDocument: intent.question_relay must be a boolean'));
  });
  it('tiers must be an object of integers 0..4', () => {
    const TO = new Error('parseDiscoveryDocument: intent.tiers must be an object');
    for (const tiers of [null, 5, 'x', []]) expect(() => parseDiscoveryIntent({ versions: [2], tiers })).toThrow(TO);
    const TV = new Error('parseDiscoveryDocument: intent.tiers values must be integers 0..4');
    for (const bad of [-1, 1.5, 5, '1']) expect(() => parseDiscoveryIntent({ versions: [2], tiers: { a: 1, b: bad } })).toThrow(TV);
    expect(settle(() => parseDiscoveryIntent({ versions: [2], tiers: { a: 0, b: 4 } }).tiers)).toEqual({ ok: true, value: { a: 0, b: 4 } });
  });
});

describe('fetchDiscovery', () => {
  it('strips every trailing slash and asks for JSON', async () => {
    const f = vi.fn(async () => ({ ok: true, status: 200, json: async () => base }));
    expect((await settleAsync(async () => await fetchDiscovery('https://api.example//', f)))).toStrictEqual({ ok: true, value: base });
    expect(f).toHaveBeenCalledWith('https://api.example/.well-known/pca-configuration', { headers: { accept: 'application/json' } });
  });
  it('uses the global fetch, and refuses when there is none', async () => {
    const g = vi.fn(async () => ({ ok: true, status: 200, json: async () => base }));
    vi.stubGlobal('fetch', g);
    expect((await settleAsync(async () => await fetchDiscovery('https://api.example')))).toStrictEqual({ ok: true, value: base });
    vi.stubGlobal('fetch', undefined);
    expect(await settleAsync(async () => fetchDiscovery('https://api.example'))).toEqual({ ok: false, error: { name: 'Error', message: 'fetchDiscovery: no fetch available — pass one explicitly' } });
  });
});
