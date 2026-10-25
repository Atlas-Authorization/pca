/** 0.4.2 mutation kills (rule 14): declaration boundary rules, signing / key shapes, verification error paths, value-domain bounds. */
import { describe, expect, it } from 'vitest';
import { actionSchemaKeyOf, actionSchemaShapeError, paramValueViolation, schemaVerb, signActionSchema, verifyActionSchema } from './action-schema';
import { generateKeyPair, mlDsa65Keygen } from './index';

const decl = (extra: Record<string, unknown> = {}, type = 'integer') => ({ type, semantic: 's', sensitivity: 'free', ...extra });
const doc = (params: Record<string, unknown>, verbExtra: Record<string, unknown> = {}, docExtra: Record<string, unknown> = {}) => ({
  v: 1, kind: 'pca-action-schema', site: 'https://s.example', aud: 's.example', version: '1',
  units: { u: { kind: 'count' } },
  verbs: [{ verb: 'a.b', kind: 'write', params, ...verbExtra }],
  ...docExtra,
});
const err = (params: Record<string, unknown>, verbExtra: Record<string, unknown> = {}) => actionSchemaShapeError(doc(params, verbExtra), { signed: false });
const P = 'action.params.x';

describe('parameter declaration rules', () => {
  it('min / max: a safe integer, never -0, and min <= max (equal is allowed)', () => {
    expect(err({ [P]: decl({ min: -0 }) })).toBe("verb 'a.b': action.params.x: min must be a safe integer on an integer parameter");
    expect(err({ [P]: decl({ max: -0 }) })).toBe("verb 'a.b': action.params.x: max must be a safe integer on an integer parameter");
    expect(err({ [P]: decl({ min: 5, max: 1 }) })).toBe("verb 'a.b': action.params.x: min > max");
    expect(err({ [P]: decl({ min: 2, max: 2 }) })).toBeNull();
    expect(err({ [P]: decl({ min: 2 }) })).toBeNull();
    expect(err({ [P]: decl({ max: 2 }) })).toBeNull();
    expect(err({ [P]: decl({ min: 1.5 }) })).toContain('min must be a safe integer');
    expect(err({ [P]: decl({ min: 1 }, 'string') })).toContain('min must be a safe integer');
  });
  it('unit: only on an integer parameter, a string, naming a declared unit; none declared at all is refused', () => {
    const msg = "verb 'a.b': action.params.x: unit must name a declared unit of an integer parameter";
    expect(err({ [P]: decl({ unit: 'u' }) })).toBeNull();
    expect(err({ [P]: decl({ unit: 'nope' }) })).toBe(msg);
    expect(err({ [P]: decl({ unit: 'u' }, 'string') })).toBe(msg);
    expect(err({ [P]: decl({ unit: 5 }) })).toBe(msg);
    expect(actionSchemaShapeError({ ...doc({ [P]: decl({ unit: 'u' }) }), units: undefined }, { signed: false })).toBe(msg);
    expect(err({ [P]: decl({ unit: 'toString' }) })).toBe(msg); // inherited names are not declared units
  });
  it('min_items / max_items: non-negative integers on a set or array, min_items <= max_items', () => {
    const set = (e: Record<string, unknown>) => ({ [P]: decl({ values: ['a', 'b'], ...e }, 'set') });
    expect(err(set({ min_items: 2, max_items: 1 }))).toBe("verb 'a.b': action.params.x: min_items > max_items");
    expect(err(set({ min_items: 1, max_items: 1 }))).toBeNull();
    expect(err(set({ min_items: 0 }))).toBeNull();
    expect(err(set({ min_items: -1 }))).toContain('min_items must be a non-negative safe integer');
    expect(err({ [P]: decl({ max_items: 1 }, 'string') })).toContain('max_items must be a non-negative safe integer');
  });
  it('accumulates_into: 1..8 distinct unit ids of at most 64 characters', () => {
    const acc = (a: unknown) => err({ [P]: decl({ accumulates_into: a }) });
    expect(acc(['u'])).toBeNull();
    expect(acc(['A'])).toBe("verb 'a.b': action.params.x: accumulates_into entries must be unit ids");
    expect(acc([5])).toBe("verb 'a.b': action.params.x: accumulates_into entries must be unit ids");
    expect(acc(['a'.repeat(64)])).toBeNull();
    expect(acc(['a'.repeat(65)])).toBe("verb 'a.b': action.params.x: accumulates_into entries must be unit ids");
    expect(acc([])).toBe("verb 'a.b': action.params.x: accumulates_into must be 1..8 unit ids");
    expect(acc('u')).toBe("verb 'a.b': action.params.x: accumulates_into must be 1..8 unit ids");
    expect(acc(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'])).toBeNull();
    expect(acc(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'])).toBe("verb 'a.b': action.params.x: accumulates_into must be 1..8 unit ids");
    expect(acc(['a', 'a'])).toBe("verb 'a.b': action.params.x: accumulates_into must be distinct");
  });
});

describe('verb declaration rules', () => {
  const D = { [P]: decl({}, 'string') };
  it('reversibility_by.param must be a string naming a declared parameter', () => {
    const msg = "verb 'a.b': reversibility_by.param must be a declared parameter";
    expect(err(D, { reversibility_by: { param: 5, map: { a: 'reversible' } } })).toBe(msg);
    expect(err(D, { reversibility_by: { param: 'action.params.nope', map: { a: 'reversible' } } })).toBe(msg);
    expect(err(D, { reversibility_by: { param: 'toString', map: { a: 'reversible' } } })).toBe(msg);
    expect(err(D, { reversibility_by: { param: P, map: { a: 'reversible' } } })).toBeNull();
  });
});

describe('document-level rules', () => {
  it('an unsigned schema must not carry sig', () => {
    expect(actionSchemaShapeError({ ...doc({ [P]: decl() }), sig: { alg: 'ed25519', kid: 'k', value: 'AA' } }, { signed: false })).toBe('an unsigned schema must not carry sig');
  });
  it('signActionSchema refuses a malformed document with the shape reason', () => {
    const { sig: _s, ...bad } = doc({ [P]: decl({ min: 5, max: 1 }) }) as never as Record<string, unknown>;
    void _s;
    expect(() => signActionSchema(bad as never, 'k', generateKeyPair().secretKey)).toThrow("signActionSchema: verb 'a.b': action.params.x: min > max");
  });
});

describe('signing and discovery keys', () => {
  const kp = generateKeyPair();
  const unsigned = (() => { const { ...d } = doc({ [P]: decl() }); return d as never; })();
  it('an ed25519 signature carries no pq_value and its key entry no pq_pk (exact keys)', () => {
    const s = signActionSchema(unsigned, 'k1', kp.secretKey);
    expect(Object.keys(s.sig).sort()).toEqual(['alg', 'kid', 'value']);
    expect(s.sig.alg).toBe('ed25519');
    expect(s.sig.kid).toBe('k1');
    const key = actionSchemaKeyOf('k1', kp.secretKey);
    expect(Object.keys(key).sort()).toEqual(['alg', 'kid', 'pk']);
    expect(key.alg).toBe('ed25519');
    expect(key.kid).toBe('k1');
    expect(key.pk.length).toBe(43);
    expect(verifyActionSchema(s, [key])).toEqual({ ok: true });
  });
  it('ML-DSA-65 and hybrid suites carry the PQ signature / public key', () => {
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(7));
    for (const alg of ['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'] as const) {
      const suite = { alg, mlDsa: ml } as never;
      const s = signActionSchema(unsigned, 'kq', kp.secretKey, suite);
      const key = actionSchemaKeyOf('kq', kp.secretKey, suite);
      expect(s.sig.alg).toBe(alg);
      expect(typeof key.pq_pk).toBe('string');
      expect(key.alg).toBe(alg);
      if (alg === 'hybrid-ed25519-ml-dsa-65') expect(typeof s.sig.pq_value).toBe('string');
      expect(verifyActionSchema(s, [key])).toEqual({ ok: true });
      // the PQ key is pinned: a different pq_pk is a different key, never a silent fallback to ed25519 alone
      const other = actionSchemaKeyOf('kq', kp.secretKey, { alg, mlDsa: mlDsa65Keygen(new Uint8Array(32).fill(9)) } as never);
      expect(verifyActionSchema(s, [other])).toEqual({ ok: false, reason: 'schema signature invalid' });
    }
  });
  it('sig.alg must match the key suite (and an ed25519 key does not verify an ML-DSA signature)', () => {
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(7));
    const s = signActionSchema(unsigned, 'kq', kp.secretKey, { alg: 'ml-dsa-65', mlDsa: ml } as never);
    expect(verifyActionSchema(s, [actionSchemaKeyOf('kq', kp.secretKey)])).toEqual({ ok: false, reason: 'sig.alg does not match the pinned key suite' });
  });
  it('a key whose members throw on access is an error reason, never an exception', () => {
    const s = signActionSchema(unsigned, 'k1', kp.secretKey);
    const boom = { kid: 'k1', alg: 'ed25519', get pk(): string { throw new Error('boom'); } };
    expect(verifyActionSchema(s, [boom as never])).toEqual({ ok: false, reason: 'schema verification error: boom' });
  });
  it('schemaVerb tolerates a hostile document', () => {
    expect(schemaVerb(undefined as never, 'a.b')).toBeUndefined();
    expect(schemaVerb({ verbs: 'x' } as never, 'a.b')).toBeUndefined();
    expect(schemaVerb(unsigned as never, 'a.b')?.verb).toBe('a.b');
    expect(schemaVerb(unsigned as never, 'zz')).toBeUndefined();
  });
});

describe('value domain bounds', () => {
  const int = (e: Record<string, unknown>) => decl(e) as never;
  it('integer min / max are inclusive and the reason quotes the bound', () => {
    const d = int({ min: 2, max: 4 });
    expect(paramValueViolation(d, 2)).toBeNull();
    expect(paramValueViolation(d, 4)).toBeNull();
    expect(paramValueViolation(d, 1)).toEqual({ code: 'out_of_domain', reason: 'below min 2' });
    expect(paramValueViolation(d, 5)).toEqual({ code: 'out_of_domain', reason: 'above max 4' });
    expect(paramValueViolation(int({ min: 0 }), -1)).toEqual({ code: 'out_of_domain', reason: 'below min 0' });
    expect(paramValueViolation(int({ max: 0 }), 1)).toEqual({ code: 'out_of_domain', reason: 'above max 0' });
    expect(paramValueViolation(int({ min: 0 }), 0)).toBeNull();
    expect(paramValueViolation(int({ max: 0 }), 0)).toBeNull();
  });
  it('array-of-integer items honour min / max (inclusive) and count bounds', () => {
    const d = decl({ items: 'integer', min: 1, max: 3, min_items: 1, max_items: 2 }, 'array') as never;
    expect(paramValueViolation(d, [1, 3])).toBeNull();
    expect(paramValueViolation(d, [0])).toEqual({ code: 'out_of_domain', reason: 'array item outside min/max' });
    expect(paramValueViolation(d, [4])).toEqual({ code: 'out_of_domain', reason: 'array item outside min/max' });
    expect(paramValueViolation(decl({ items: 'integer', min: 1 }, 'array') as never, [0])).toEqual({ code: 'out_of_domain', reason: 'array item outside min/max' });
    expect(paramValueViolation(decl({ items: 'integer', max: 1 }, 'array') as never, [2])).toEqual({ code: 'out_of_domain', reason: 'array item outside min/max' });
    expect(paramValueViolation(d, [])).toEqual({ code: 'out_of_domain', reason: 'array length outside the declared bounds' });
    expect(paramValueViolation(d, [1, 2, 3])).toEqual({ code: 'out_of_domain', reason: 'array length outside the declared bounds' });
  });
  it('dates: year 0, month 0 and day 0 are not calendar dates; year 1 is', () => {
    const d = decl({}, 'date') as never;
    for (const x of ['0000-01-01', '2024-00-10', '2024-01-00', '2024-13-01', '2024-02-30', '2023-02-29']) {
      expect(paramValueViolation(d, x), x).toEqual({ code: 'out_of_domain', reason: 'not a calendar date YYYY-MM-DD' });
    }
    for (const x of ['0001-01-01', '2024-02-29', '2000-02-29', '2024-12-31']) expect(paramValueViolation(d, x), x).toBeNull();
    expect(paramValueViolation(d, '1900-02-29')).toEqual({ code: 'out_of_domain', reason: 'not a calendar date YYYY-MM-DD' });
  });
});
