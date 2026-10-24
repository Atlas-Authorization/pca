/**
 * r13 mutation kills for intent-artifacts.ts: the exact truth tables of the shared W-B predicates (path segments, bounded
 * strings, scalars, pin pq_pk, own-key lookup, param paths), closedMembers messages, artifactSuiteError reasons,
 * signArtifact suite members, verifyArtifactSig under string / ed25519 / hybrid pins, resolveParamPath and setNested.
 */
import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { generateKeyPair } from './keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';
import {
  artifactSuiteError,
  closedMembers,
  isBoundedString,
  isParamPath,
  isPathSegment,
  isScalar,
  ownGet,
  pinPqOk,
  resolveParamPath,
  setNested,
  signArtifact,
  verifyArtifactSig,
} from './intent-artifacts';

/** Capture an outcome so a thrown error is compared (name + message) instead of failing the test as an error. */
type Settled<T> = { ok: true; value: T } | { ok: false; error: { name: string; message: string } };
function settle<T>(f: () => T): Settled<T> {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    const x = e as Error;
    return { ok: false, error: { name: x?.name, message: x?.message } };
  }
}
const ok = <T>(value: T) => ({ ok: true as const, value });

const DOM = 'atlas-pca/r13-g6-test/v1\0';
const ED = generateKeyPair();
const ML = mlDsa65Keygen(new Uint8Array(32).fill(7));
const HYB = 'hybrid-ed25519-ml-dsa-65' as const;
const PIN = b64u(ED.publicKey);
const PQPIN = encodeMlDsaPublicKey(ML.publicKey);

describe('predicates: exact truth tables', () => {
  it('isPathSegment', () => {
    expect(isPathSegment('ok_1-x')).toBe(true);
    expect(isPathSegment('a b')).toBe(false);
    for (const s of ['__proto__', 'constructor', 'prototype']) expect(isPathSegment(s)).toBe(false);
  });
  it('isBoundedString', () => {
    expect(isBoundedString('abc', 3)).toBe(true);
    expect(isBoundedString('abcd', 3)).toBe(false);
    expect(isBoundedString('', 3)).toBe(false);
    expect(isBoundedString(5, 3)).toBe(false);
    expect(isBoundedString(['x'], 3)).toBe(false);
  });
  it('isScalar', () => {
    expect([isScalar('s'), isScalar(true), isScalar(3)]).toStrictEqual([true, true, true]);
    expect([isScalar(null), isScalar(1.5), isScalar({}), isScalar(-0)]).toStrictEqual([false, false, false, false]);
  });
  it('pinPqOk: absent or a non-empty string', () => {
    expect(pinPqOk(undefined)).toBe(true);
    expect(pinPqOk('x')).toBe(true);
    for (const v of [null, '', 5, ['x']]) expect(settle(() => pinPqOk(v))).toEqual(ok(false));
  });
  it('ownGet never reads inherited members and tolerates null / undefined', () => {
    expect(ownGet({ a: 1 }, 'a')).toBe(1);
    expect(settle(() => ownGet({} as Record<string, unknown>, 'toString'))).toEqual(ok(undefined));
    expect(settle(() => ownGet(null, 'a'))).toEqual(ok(undefined));
    expect(settle(() => ownGet(undefined, 'a'))).toEqual(ok(undefined));
  });
  it('isParamPath: action.params. + 1..8 valid segments', () => {
    expect(settle(() => isParamPath(5))).toEqual(ok(false));
    expect(isParamPath('action.params.')).toBe(false);
    expect(isParamPath('action.params.a.b.c.d.e.f.g')).toBe(true); // 7
    expect(isParamPath('action.params.a.b.c.d.e.f.g.h')).toBe(true); // 8
    expect(isParamPath('action.params.a.b.c.d.e.f.g.h.i')).toBe(false); // 9
    expect(isParamPath('action.params.a.__proto__')).toBe(false);
    expect(isParamPath('x.params.a')).toBe(false);
  });
});

describe('closedMembers', () => {
  it('names unknown and missing members under the given (or default) location', () => {
    expect(closedMembers({ 'Stryker was here': 1 }, [])).toBe("unknown member 'object.Stryker was here'");
    expect(closedMembers({ x: 1 }, [])).toBe("unknown member 'object.x'");
    expect(closedMembers({}, ['a'], [], 'w')).toBe("missing member 'w.a'");
    expect(closedMembers({ a: 1, b: 2 }, ['a'], ['b'])).toBeNull();
  });
});

describe('artifactSuiteError', () => {
  it('a non-object artifact', () => {
    expect(settle(() => artifactSuiteError(null as never))).toEqual(ok('artifact must be an object'));
    expect(settle(() => artifactSuiteError([] as never))).toEqual(ok('artifact must be an object'));
  });
  it('an implemented suite is usable; pq members must be strings', () => {
    expect(artifactSuiteError({ alg: HYB, pq_pk: 'p', pq_sig: 's' })).toBeNull();
    expect(artifactSuiteError({ alg: 'nope' })).toBe("unsupported_suite: 'nope'");
    expect(artifactSuiteError({ alg: HYB, pq_pk: 5 })).toBe('pq_pk must be a string');
    expect(artifactSuiteError({ alg: HYB, pq_pk: 'p', pq_sig: 5 })).toBe('pq_sig must be a string');
  });
  it('an ed25519 artifact carries neither pq_pk nor pq_sig', () => {
    const m = 'an ed25519 artifact must not carry pq_pk / pq_sig';
    expect(artifactSuiteError({ pq_pk: 'p' })).toBe(m);
    expect(artifactSuiteError({ pq_sig: 's' })).toBe(m);
    expect(artifactSuiteError({ alg: 'ed25519', pq_pk: 'p', pq_sig: 's' })).toBe(m);
    expect(artifactSuiteError({ alg: 'ed25519' })).toBeNull();
  });
});

describe('signArtifact / verifyArtifactSig', () => {
  it('an unknown suite is refused by name', () => {
    expect(() => signArtifact(DOM, { a: 1 }, ED.secretKey, { alg: 'bogus' as never })).toThrow(new Error("signArtifact: unknown signature alg 'bogus'"));
  });
  it('ed25519: no suite members; verifies under a string or object pin', () => {
    const s = signArtifact(DOM, { a: 1 }, ED.secretKey);
    expect(Object.keys(s).sort()).toStrictEqual(['a', 'sig']);
    expect(verifyArtifactSig(DOM, s, PIN)).toBe(true);
    expect(verifyArtifactSig(DOM, s, { pk: PIN })).toBe(true);
    expect(verifyArtifactSig(DOM, { a: 1 }, PIN)).toBe(false); // no sig
    expect(verifyArtifactSig(DOM, { ...s, a: 10n as never }, PIN)).toBe(false); // a body strict canonical JSON cannot encode: caught, false
  });
  it('hybrid: alg and pq_pk are signed; verifies only under the pinned PQ key', () => {
    const s = signArtifact(DOM, { a: 1 }, ED.secretKey, { alg: HYB, mlDsa: ML });
    expect(s.alg).toBe(HYB);
    expect(s.pq_pk).toBe(PQPIN);
    expect(typeof s.pq_sig).toBe('string');
    expect(verifyArtifactSig(DOM, s, { pk: PIN, pq_pk: PQPIN })).toBe(true);
    expect(verifyArtifactSig(DOM, s, { pk: PIN })).toBe(false);
  });
});

describe('resolveParamPath', () => {
  it('a non-string or non action.params. path is not found', () => {
    expect(settle(() => resolveParamPath({ a: 1 }, 5 as never))).toEqual(ok({ found: false }));
    expect(settle(() => resolveParamPath({ a: 1 }, 'xxxxxxxxxxxxxxa'))).toEqual(ok({ found: false }));
  });
  it('own members only, through plain objects only, never a forbidden segment', () => {
    expect(settle(() => resolveParamPath({ a: { b: 2 } }, 'action.params.a.b'))).toEqual(ok({ found: true, value: 2 }));
    expect(settle(() => resolveParamPath({ a: null }, 'action.params.a.b'))).toEqual(ok({ found: false }));
    expect(settle(() => resolveParamPath({ a: [5] }, 'action.params.a.0'))).toEqual(ok({ found: false }));
    expect(settle(() => resolveParamPath(JSON.parse('{"__proto__":1}'), 'action.params.__proto__'))).toEqual(ok({ found: false }));
  });
});

describe('setNested', () => {
  it('refuses a path through a leaf, and an existing leaf or subtree', () => {
    const root: Record<string, unknown> = Object.create(null);
    expect(setNested(root, 'a', 1)).toBe(true);
    expect(settle(() => setNested(root, 'a.b', 2))).toEqual(ok(false));
    expect(setNested(root, 'x.y', 1)).toBe(true);
    expect(setNested(root, 'x.y', 2)).toBe(false);
    expect(setNested(root, 'x', 3)).toBe(false);
    expect(JSON.parse(JSON.stringify(root))).toStrictEqual({ a: 1, x: { y: 1 } });
  });
});
