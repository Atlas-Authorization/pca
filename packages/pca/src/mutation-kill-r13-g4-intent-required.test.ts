/**
 * r13 mutation kills for intent-required.ts: every refusal of cellCoordsError / intentRequiredShapeError pinned to its
 * exact reason with the accepted boundary next to it, the site signature pinned against an independent construction of
 * the domain-separated message, key selection (null / primitive / other-kid entries before the right key), suite
 * pinning (ed25519 vs hybrid), expiry, the fail-closed catch, and the RFC 9457 response members. Fixtures are built
 * inside the tests.
 */
import { describe, expect, it, vi } from 'vitest';
import { b64u, canonicalBytesStrict, hashCanonical, sha256, utf8 } from './hash';
import { publicKeyOf, sign } from './keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';
import type { ActionSchemaKey } from './action-schema';
import {
  cellCoordsError as cellCoordsError0,
  intentProblem,
  intentRequiredShapeError as intentRequiredShapeError0,
  signIntentRequired,
  verifyIntentRequired,
  type IntentRequiredBody,
} from './intent-required';

/** Wraps a total function: a throw becomes the value 'THREW: <message>', so a mutant that makes it throw fails an assertion. */
const W =
  <A extends unknown[], R>(f: (...a: A) => R) =>
  (...a: A): R => {
    try {
      return f(...a);
    } catch (e) {
      return `THREW: ${(e as Error).message}` as unknown as R;
    }
  };
const cellCoordsError = W(cellCoordsError0);
const intentRequiredShapeError = W(intentRequiredShapeError0);
/** A call's outcome for toEqual: a throw becomes { ok: false, error: { name, message } }. */
const settle = <T>(f: () => T): { ok: true; value: T } | { ok: false; error: { name: string; message: string } } => {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return { ok: false, error: { name: (e as Error).name, message: (e as Error).message } };
  }
};
const seed = (l: string) => sha256(utf8('r13-g4-ireq/' + l));
const D32 = (l: string) => b64u(seed('d/' + l));
const SK = () => seed('site');
const PK = () => b64u(publicKeyOf(SK()));
const KEY = (): ActionSchemaKey => ({ kid: 'k1', alg: 'ed25519', pk: PK() });
const NOW = 1_800_000_000_000;
const BODY = (): IntentRequiredBody => ({
  v: 1,
  kind: 'pca-intent-required',
  session: D32('session'),
  map_digest: D32('map'),
  schema: D32('schema'),
  pcactn_digest: D32('pcactn'),
  action_digest: D32('action'),
  cell: { verb: 'air.book', coords: { 'env.acc.spend.post': [2, 3], 'env.canon.add_ons': ['none', 'bag'] } },
  reason: 'uncertain',
  question_id: 'q_7Hk2',
  friction: 'typed',
  delivered_to: 'wallet',
  expires_at: NOW + 1000,
});
const se = (b: unknown, opts?: { signed?: boolean }) => intentRequiredShapeError(b, opts);
const unsigned = (patch: Record<string, unknown>) => se({ ...BODY(), ...patch }, { signed: false });
const bad = (reason: string) => ({ ok: false, reason });

describe('cellCoordsError', () => {
  const dims = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`d${i}`, [0, 1]]));
  it('the dimension count', () => {
    for (const c of [null, undefined, 5, 'x', [], {}, dims(65)]) expect(cellCoordsError(c)).toBe('coords must be an object of 1..64 dimensions');
    expect(cellCoordsError(dims(64))).toBeNull();
    expect(cellCoordsError(dims(1))).toBeNull();
  });
  it('the path length', () => {
    expect(cellCoordsError({ '': [0, 1] })).toBe('a coordinate path must be 1..256 characters');
    expect(cellCoordsError({ ['p'.repeat(257)]: [0, 1] })).toBe('a coordinate path must be 1..256 characters');
    expect(cellCoordsError({ ['p'.repeat(256)]: [0, 1] })).toBeNull();
    expect(cellCoordsError({ p: [0, 1] })).toBeNull();
  });
  it('index ranges', () => {
    for (const r of [[0, 0], [3, 3], [1, 5], [0, 9007199254740991]]) expect(cellCoordsError({ k: r })).toBeNull();
    for (const r of [[5, 1], [-1, 2], [-2, -1]]) expect(cellCoordsError({ k: r })).toBe("coords 'k': need 0 <= lo <= hi");
    expect(cellCoordsError({ k: [1, 'a'] })).toBe("coords 'k': an index range [lo, hi] or a value set");
    expect(cellCoordsError({ k: [1, 2, 3] })).toBe("coords 'k': an index range [lo, hi] or a value set");
    expect(cellCoordsError({ k: [1.5, 2] })).toBe("coords 'k': an index range [lo, hi] or a value set");
    expect(cellCoordsError({ k: [-0, 2] })).toBe("coords 'k': an index range [lo, hi] or a value set");
  });
  it('value sets', () => {
    expect(cellCoordsError({ k: ['a'] })).toBeNull();
    expect(cellCoordsError({ k: ['a', 'b'] })).toBeNull();
    expect(cellCoordsError({ k: Array.from({ length: 256 }, (_, i) => `v${i}`) })).toBeNull();
    expect(cellCoordsError({ k: Array.from({ length: 257 }, (_, i) => `v${i}`) })).toBe("coords 'k': an index range [lo, hi] or a value set");
    for (const v of [[], ['a', 1], [1, 'a'], 'abc', 5, null, { 0: 'a' }, [null]]) expect(cellCoordsError({ k: v })).toBe("coords 'k': an index range [lo, hi] or a value set");
    expect(cellCoordsError({ k: ['a', 'a'] })).toBe("coords 'k': values must be distinct");
    expect(cellCoordsError({ ok: [0, 1], k: ['a', 'b', 'a'] })).toBe("coords 'k': values must be distinct");
  });
});

describe('intentRequiredShapeError (unsigned)', () => {
  it('the valid body and each delivered_to', () => {
    expect(unsigned({})).toBeNull();
    expect(unsigned({ delivered_to: 'agent' })).toBeNull();
    expect(unsigned({ expires_at: 0 })).toBeNull();
    expect(unsigned({ question_id: 'a'.repeat(64) })).toBeNull();
    expect(unsigned({ question_id: 'A-z_09' })).toBeNull();
    for (const friction of ['tap', 'hold', 'typed', 'device']) expect(unsigned({ friction })).toBeNull();
  });
  it('object, members, version', () => {
    for (const b of [null, undefined, 5, 'x', [], true]) expect(se(b)).toBe('not an object');
    expect(unsigned({ x: 1 })).toBe("unknown member 'x'");
    expect(unsigned({ v: 2 })).toBe('not a pca-intent-required v1');
    expect(unsigned({ kind: 'x' })).toBe('not a pca-intent-required v1');
  });
  it('each digest', () => {
    for (const k of ['session', 'map_digest', 'schema', 'pcactn_digest', 'action_digest']) expect(unsigned({ [k]: 'x' })).toBe(`${k} must be canonical base64url (32 bytes)`);
  });
  it('the cell', () => {
    const coords = BODY().cell.coords;
    for (const cell of [null, 5, [], { verb: 'a' }, { coords }, { verb: 'a', coords, x: 1 }, { verb: 5, coords }, { verb: '', coords }]) {
      expect(unsigned({ cell })).toBe('cell must be {verb, coords}');
    }
    expect(unsigned({ cell: { verb: 'a', coords: {} } })).toBe('coords must be an object of 1..64 dimensions');
    expect(unsigned({ cell: { verb: 'a', coords: { k: [2, 1] } } })).toBe("coords 'k': need 0 <= lo <= hi");
  });
  it('reason, question id, friction, delivered_to, expiry', () => {
    expect(unsigned({ reason: 'x' })).toBe("reason must be 'uncertain'");
    for (const q of [5, '', 'a b', 'a'.repeat(65), 'é', 'a.b', ' a', 'a ']) expect(unsigned({ question_id: q })).toBe('question_id must match [A-Za-z0-9_-]{1,64}');
    expect(unsigned({ friction: 'x' })).toBe('unknown friction tier');
    expect(unsigned({ delivered_to: 'x' })).toBe("delivered_to must be 'wallet' or 'agent'");
    for (const t of [-1, 1.5, '5', -0, null]) expect(unsigned({ expires_at: t })).toBe('expires_at must be a non-negative safe integer');
  });
  it('an unsigned body must not carry sig', () => {
    expect(unsigned({ sig: { alg: 'ed25519', kid: 'k', value: 'v' } })).toBe('an unsigned body must not carry sig');
  });
});

describe('intentRequiredShapeError (signed)', () => {
  const sig = (s: unknown) => se({ ...BODY(), sig: s });
  it('valid sig shapes (alg absent, ed25519, with pq_value)', () => {
    expect(sig({ alg: 'ed25519', kid: 'k', value: 'v' })).toBeNull();
    expect(sig({ kid: 'k', value: 'v' })).toBeNull();
    expect(sig({ alg: 'hybrid-ed25519-ml-dsa-65', kid: 'k', value: 'v', pq_value: 'p' })).toBeNull();
    expect(se({ ...BODY(), sig: { alg: 'ed25519', kid: 'k', value: 'v' } }, {})).toBeNull();
  });
  it('the suite capability reason', () => {
    expect(sig({ alg: 'bogus', kid: 'k', value: 'v' })).toBe("sig.alg: unsupported_suite: 'bogus'");
    expect(sig({ alg: 5, kid: 'k', value: 'v' })).toBe('sig.alg: alg must be a string');
  });
  it('pq_value', () => {
    expect(sig({ alg: 'ed25519', kid: 'k', value: 'v', pq_value: 5 })).toBe('sig.pq_value must be a string');
  });
  it('the sig object', () => {
    for (const s of [undefined, null, 5, [], { alg: 'ed25519', kid: 'k', value: 'v', x: 1 }, { alg: 'ed25519', kid: 5, value: 'v' }, { alg: 'ed25519', kid: 'k', value: 5 }, { alg: 'ed25519', value: 'v' }]) {
      expect(sig(s)).toBe('sig must be {alg, kid, value, pq_value?}');
    }
  });
});

describe('signIntentRequired', () => {
  it('the signature is over the domain tag || strict canonical body (sig excluded)', () => {
    const msg0 = utf8('atlas-pca/intent-required/v1\0');
    const b0 = canonicalBytesStrict(BODY());
    const m0 = new Uint8Array(msg0.length + b0.length);
    m0.set(msg0, 0);
    m0.set(b0, msg0.length);
    expect(settle(() => signIntentRequired(BODY(), 'k1', SK()).sig)).toEqual({ ok: true, value: { alg: 'ed25519', kid: 'k1', value: b64u(sign(SK(), m0)) } });
    const s = signIntentRequired(BODY(), 'k1', SK());
    const msg = utf8('atlas-pca/intent-required/v1\0');
    const b = canonicalBytesStrict(BODY());
    const m = new Uint8Array(msg.length + b.length);
    m.set(msg, 0);
    m.set(b, msg.length);
    expect(s.sig).toStrictEqual({ alg: 'ed25519', kid: 'k1', value: b64u(sign(SK(), m)) });
    expect(Object.keys(s.sig)).toEqual(['alg', 'kid', 'value']);
  });
  it('a hybrid signature carries pq_value', () => {
    const ml = mlDsa65Keygen(seed('ml'));
    const s = signIntentRequired(BODY(), 'h1', SK(), { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml });
    expect(s.sig.alg).toBe('hybrid-ed25519-ml-dsa-65');
    expect(typeof s.sig.pq_value).toBe('string');
    expect(s.sig.pq_value!.length).toBeGreaterThan(100);
  });
  it('a malformed body is refused with its reason', () => {
    expect(() => signIntentRequired({ ...BODY(), v: 2 as 1 }, 'k1', SK())).toThrow(new Error('signIntentRequired: not a pca-intent-required v1'));
  });
});

describe('verifyIntentRequired', () => {
  it('valid; key lookup skips null, primitives and other kids', () => {
    const s = signIntentRequired(BODY(), 'k1', SK());
    expect(verifyIntentRequired(s, [KEY()], NOW)).toEqual({ ok: true });
    expect(verifyIntentRequired(s, [KEY()] , undefined as never)).toEqual({ ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' });
    const other = { kid: 'k0', alg: 'ed25519' as const, pk: b64u(publicKeyOf(seed('other'))) };
    expect(verifyIntentRequired(s, [null, undefined, 5, 'k1', other, KEY()] as never, NOW)).toEqual({ ok: true });
  });
  it('expiry: now == expires_at is still valid', () => {
    const s = signIntentRequired(BODY(), 'k1', SK());
    expect(verifyIntentRequired(s, [KEY()], NOW + 1000)).toEqual({ ok: true });
    expect(verifyIntentRequired(s, [KEY()], NOW + 1001)).toEqual(bad('the question has expired'));
  });
  it('every refusal reason', () => {
    const s = signIntentRequired(BODY(), 'k1', SK());
    expect(verifyIntentRequired({ ...s, v: 2 }, [KEY()], NOW)).toEqual(bad('not a pca-intent-required v1'));
    expect(verifyIntentRequired(s, null as never, NOW)).toEqual(bad('the site keys must be an array'));
    expect(verifyIntentRequired(s, { find: () => KEY() } as never, NOW)).toEqual(bad('the site keys must be an array'));
    expect(verifyIntentRequired(s, [{ ...KEY(), kid: 'k2' }], NOW)).toEqual(bad("no site key with kid 'k1'"));
    expect(verifyIntentRequired(s, [{ ...KEY(), alg: 'bogus' as never }], NOW)).toEqual(bad("site key: unsupported_suite: 'bogus'"));
    expect(verifyIntentRequired(s, [{ ...KEY(), alg: 'hybrid-ed25519-ml-dsa-65' }], NOW)).toEqual(bad('sig.alg does not match the pinned key suite'));
    expect(verifyIntentRequired({ ...s, friction: 'tap' }, [KEY()], NOW)).toEqual(bad('site signature invalid'));
    expect(verifyIntentRequired(s, [{ ...KEY(), pk: b64u(publicKeyOf(seed('other'))) }], NOW)).toEqual(bad('site signature invalid'));
  });
  it('a hybrid key verifies only through its pinned pq_pk', () => {
    const ml = mlDsa65Keygen(seed('ml'));
    const s = signIntentRequired(BODY(), 'h1', SK(), { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml });
    const hk: ActionSchemaKey = { kid: 'h1', alg: 'hybrid-ed25519-ml-dsa-65', pk: PK(), pq_pk: encodeMlDsaPublicKey(ml.publicKey) };
    expect(verifyIntentRequired(s, [hk], NOW)).toEqual({ ok: true });
    const { pq_pk: _p, ...noPq } = hk;
    void _p;
    expect(verifyIntentRequired(s, [noPq as ActionSchemaKey], NOW)).toEqual(bad('site signature invalid'));
    const other = encodeMlDsaPublicKey(mlDsa65Keygen(seed('ml2')).publicKey);
    expect(verifyIntentRequired(s, [{ ...hk, pq_pk: other }], NOW)).toEqual(bad('site signature invalid'));
  });
  it('the catch fails closed', () => {
    const s = signIntentRequired(BODY(), 'k1', SK());
    const k = Object.defineProperty({}, 'kid', { get: () => { throw new Error('boom'); } });
    expect(verifyIntentRequired(s, [k] as never, NOW)).toEqual(bad('malformed intent_required: boom'));
  });
});

describe('intentProblem', () => {
  it('intent-required needs the signed body', () => {
    expect(() => intentProblem('intent-required')).toThrow(new Error('intentProblem: intent-required needs the signed body'));
  });
  it('headers and the optional members', () => {
    expect(settle(() => intentProblem('ceiling').status)).toEqual({ ok: true, value: 403 });
    const r = intentProblem('ceiling');
    expect(r).toStrictEqual({
      status: 403,
      headers: { 'WWW-Authenticate': 'PCA error="ceiling"', 'Content-Type': 'application/problem+json' },
      body: { type: 'https://atlasauth.net/pca/problems/ceiling', title: 'The action is outside a ceiling the principal cannot widen', status: 403 },
    });
    expect(Object.keys(r.body)).toEqual(['type', 'title', 'status']);
    const d = intentProblem('intent-denied', { detail: 'vetoed' });
    expect(d.body).toStrictEqual({ type: 'https://atlasauth.net/pca/problems/intent-denied', title: 'The principal does not intend this action', status: 403, detail: 'vetoed' });
    const s = signIntentRequired(BODY(), 'k1', SK());
    const q = intentProblem('intent-required', { body: s });
    expect(q.headers).toStrictEqual({ 'WWW-Authenticate': `PCA error="intent_required", session="${BODY().session}", question="q_7Hk2"`, 'Content-Type': 'application/problem+json' });
    expect(Object.keys(q.body)).toEqual(['type', 'title', 'status', 'pca']);
  });
});

describe('published constants, titles and error codes (fresh module)', () => {
  const fresh = async () => {
    vi.resetModules();
    return import('./intent-required');
  };
  it('constants', async () => {
    const m = await fresh();
    expect([m.PROBLEM_BASE, m.INTENT_REQUIRED_DOMAIN, m.INTENT_ACTION_DOMAIN]).toEqual(['https://atlasauth.net/pca/problems/', 'atlas-pca/intent-required/v1\0', 'atlas-pca/intent-action/v1']);
    expect(m.INTENT_PROBLEM_KINDS).toEqual(['intent-required', 'intent-denied', 'schema-violation', 'ceiling']);
    expect(m.FRICTIONS).toEqual(['tap', 'hold', 'typed', 'device']);
  });
  it('intentActionDigest is H({d, action}) over exactly the four action members', async () => {
    const m = await fresh();
    const a = { verb: 'v', resource: 'r', params_digest: D32('p'), reversibility_class: 'reversible' };
    expect(settle(() => m.intentActionDigest({ ...a, extra: 1 } as never))).toEqual({ ok: true, value: hashCanonical({ d: 'atlas-pca/intent-action/v1', action: a }) });
  });
  it('every problem kind: type, title, WWW-Authenticate error code', async () => {
    const m = await fresh();
    const s = m.signIntentRequired(BODY(), 'k1', SK());
    const want: [string, string, string][] = [
      ['intent-required', 'Principal confirmation required for this action', `PCA error="intent_required", session="${BODY().session}", question="q_7Hk2"`],
      ['intent-denied', 'The principal does not intend this action', 'PCA error="intent_denied"'],
      ['schema-violation', 'The action does not conform to the site action schema', 'PCA error="schema_violation"'],
      ['ceiling', 'The action is outside a ceiling the principal cannot widen', 'PCA error="ceiling"'],
    ];
    for (const [kind, title, www] of want) {
      const r = settle(() => m.intentProblem(kind as never, kind === 'intent-required' ? { body: s } : {}));
      expect(r).toEqual({
        ok: true,
        value: {
          status: 403,
          headers: { 'WWW-Authenticate': www, 'Content-Type': 'application/problem+json' },
          body: { type: `https://atlasauth.net/pca/problems/${kind}`, title, status: 403, ...(kind === 'intent-required' ? { pca: s } : {}) },
        },
      });
    }
  });
});
