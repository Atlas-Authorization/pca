/**
 * Mutation-kill tests for safety-certificate.ts: exact statement / message layout, every claim field, optional-field
 * omission, every verifier reason string and its ordering, suite agility (hybrid / ml-dsa-65), decode guards + size bound.
 */
import { describe, expect, it, vi } from 'vitest';
import {
  SAFETY_CERT_DOMAIN,
  SAFETY_CERT_VERSION,
  decodeSafetyCertificate,
  encodeSafetyCertificate,
  issueSafetyCertificate,
  safetyCertificateBound,
  safetyCertificateMessage,
  safetyCertificateStatement,
  verifySafetyCertificate,
  type SafetyCertificate,
} from './safety-certificate';
import { b64u, canonicalBytesLenient, utf8 } from './hash';
import { encodeKey, generateKeyPair, sign } from './keys';
import { mlDsa65Keygen, pqPinFor } from './pq';
import { DEFAULT_RISK_POLICY, type RiskPolicy } from './risk';
import { MAX_JSON_BYTES } from './strict-json';

const G = generateKeyPair();
const pol = (over: Partial<RiskPolicy> = {}): RiskPolicy => ({ ...DEFAULT_RISK_POLICY, ...over });
const mk = (over: Partial<RiskPolicy> = {}, extra: Record<string, unknown> = {}) =>
  issueSafetyCertificate({ policy: pol({ bMax: 3, kappa: 2, ...over }), guardianSecret: G.secretKey, issuedAt: 5, ...extra });
/** A certificate with an arbitrary body re-signed by the guardian (so only the targeted guard can fire). */
const resign = (c: SafetyCertificate, over: Record<string, unknown>): SafetyCertificate => {
  const { sig: _s, pq_sig: _p, ...rest } = c;
  void _s;
  void _p;
  const body = { ...rest, ...over };
  return { ...body, sig: b64u(sign(G.secretKey, safetyCertificateMessage(body as never))) } as SafetyCertificate;
};

describe('constants / statement / bound', () => {
  it('exact constants', () => {
    expect(SAFETY_CERT_DOMAIN).toBe('atlas-pca/safety-cert/v1\0');
    expect(SAFETY_CERT_VERSION).toBe(1);
  });
  it('statement text is exact', () => {
    expect(safetyCertificateStatement(1.5)).toBe(
      'Arithmetic consequence of the signed risk parameters: between two consecutive human co-signs, the total risk of autonomous actions Σ r(Aᵢ) ≤ 1.5 (= B_max / κ). This is not a claim that the agent or the system is safe.',
    );
  });
  it('bound is bMax/kappa, 0 for kappa<=0, clamps negative bMax', () => {
    expect(safetyCertificateBound({ bMax: 3, kappa: 2 })).toBe(1.5);
    expect(safetyCertificateBound({ bMax: 3, kappa: 0 })).toBe(0);
    expect(safetyCertificateBound({ bMax: -3, kappa: 2 })).toBe(0);
  });
});

describe('issue', () => {
  it('every claim field is exact', () => {
    const p = pol({ bMax: 3, kappa: 2, theta1: 0.1, theta2: 0.7, lambda: 0.3, rho: 0.4 });
    const c = issueSafetyCertificate({ policy: p, guardianSecret: G.secretKey, issuedAt: 42, grantRef: 'g1', instance: 'i1' });
    expect(c.v).toBe(1);
    expect(c.statement).toBe(safetyCertificateStatement(1.5));
    expect(c.params).toEqual({ bMax: 3, kappa: 2, theta1: 0.1, theta2: 0.7, lambda: 0.3, rho: 0.4, weights: p.weights });
    expect(c.params.weights).not.toBe(p.weights);
    expect(c.bound).toBe(1.5);
    expect(c.blastRadiusPerCheckpoint).toBe(1.5);
    expect(c.grant_ref).toBe('g1');
    expect(c.instance).toBe('i1');
    expect(c.issued_at).toBe(42);
    expect(c.guardian).toBe(encodeKey(G.publicKey));
    expect('alg' in c).toBe(false);
    expect('pq_pk' in c).toBe(false);
    expect('pq_sig' in c).toBe(false);
    expect(Object.keys(c).sort()).toEqual(
      ['blastRadiusPerCheckpoint', 'bound', 'grant_ref', 'guardian', 'instance', 'issued_at', 'params', 'scope', 'sig', 'statement', 'v'].sort(),
    );
  });
  it('optional fields are ABSENT (not undefined) when not supplied; empty string is kept', () => {
    const c = mk();
    expect('grant_ref' in c).toBe(false);
    expect('instance' in c).toBe(false);
    const e = mk({}, { grantRef: '', instance: '' });
    expect(e.grant_ref).toBe('');
    expect(e.instance).toBe('');
    expect(verifySafetyCertificate(e).ok).toBe(true);
  });
  it('issuedAt 0 is kept; default is Date.now()', () => {
    expect(mk({}, { issuedAt: 0 }).issued_at).toBe(0);
    vi.useFakeTimers();
    vi.setSystemTime(123456);
    try {
      const c = issueSafetyCertificate({ policy: pol(), guardianSecret: G.secretKey });
      expect(c.issued_at).toBe(123456);
    } finally {
      vi.useRealTimers();
    }
  });
  it('throws with exact messages', () => {
    expect(() => issueSafetyCertificate({ policy: pol({ kappa: 0 }), guardianSecret: G.secretKey })).toThrow(
      'issueSafetyCertificate: risk_policy.kappa must be > 0',
    );
    expect(() => issueSafetyCertificate({ policy: pol(), guardianSecret: G.secretKey, suite: { alg: 'bogus' as never } })).toThrow(
      "issueSafetyCertificate: unknown signature alg 'bogus'",
    );
  });
  it('message layout is DOMAIN || canonical(claim without sig/pq_sig)', () => {
    const c = mk();
    const m = safetyCertificateMessage(c);
    const { sig: _s, ...claim } = c;
    void _s;
    const pre = utf8(SAFETY_CERT_DOMAIN);
    const body = canonicalBytesLenient(claim);
    expect(m.length).toBe(pre.length + body.length);
    expect(Array.from(m.slice(0, pre.length))).toEqual(Array.from(pre));
    expect(Array.from(m.slice(pre.length))).toEqual(Array.from(body));
    // pq_sig is excluded as well
    expect(Array.from(safetyCertificateMessage({ ...c, pq_sig: 'zzz' }))).toEqual(Array.from(m));
    expect(Array.from(safetyCertificateMessage({ ...c, sig: 'other' }))).toEqual(Array.from(m));
  });
});

describe('verify — reasons and order', () => {
  it('ok verdict carries the recomputed bound and no reason', () => {
    const v = verifySafetyCertificate(mk());
    expect(v).toEqual({ ok: true, recomputedBound: 1.5 });
  });
  it('malformed certificate: null, non-object, wrong v', () => {
    const exp = { ok: false, reason: 'malformed certificate' };
    expect(verifySafetyCertificate(null as never)).toEqual(exp);
    expect(verifySafetyCertificate(undefined as never)).toEqual(exp);
    expect(verifySafetyCertificate('x' as never)).toEqual(exp);
    expect(verifySafetyCertificate({ ...mk(), v: 2 } as never)).toEqual(exp);
    expect(verifySafetyCertificate({ ...mk(), v: undefined } as never)).toEqual(exp);
  });
  it('missing guardian/signature', () => {
    const exp = { ok: false, reason: 'missing guardian/signature' };
    expect(verifySafetyCertificate({ ...mk(), sig: 5 } as never)).toEqual(exp);
    expect(verifySafetyCertificate({ ...mk(), sig: undefined } as never)).toEqual(exp);
    expect(verifySafetyCertificate({ ...mk(), guardian: 5 } as never)).toEqual(exp);
    expect(verifySafetyCertificate({ ...mk(), guardian: undefined } as never)).toEqual(exp);
  });
  it('invalid parameters carries the policy message', () => {
    const c = mk();
    const v = verifySafetyCertificate({ ...c, params: { ...c.params, kappa: 0 } });
    expect(v).toEqual({ ok: false, reason: 'invalid parameters: risk_policy.kappa must be > 0' });
    // params precede bound: also tamper bound
    expect(verifySafetyCertificate({ ...c, bound: 99, params: { ...c.params, kappa: 0 } }).reason).toMatch(/^invalid parameters/);
  });
  it('stated bound mismatch / non-finite', () => {
    const c = mk();
    const r = 'stated bound does not equal B_max/κ recomputed from the parameters';
    expect(verifySafetyCertificate({ ...c, bound: 2 })).toEqual({ ok: false, reason: r, recomputedBound: 1.5 });
    expect(verifySafetyCertificate({ ...c, bound: NaN })).toEqual({ ok: false, reason: r, recomputedBound: 1.5 });
    expect(verifySafetyCertificate({ ...c, bound: Infinity })).toEqual({ ok: false, reason: r, recomputedBound: 1.5 });
    expect(verifySafetyCertificate({ ...c, bound: 1.5 + 1e-12 }).reason).toBe(r);
  });
  it('blastRadius mismatch', () => {
    const c = mk();
    expect(verifySafetyCertificate({ ...c, blastRadiusPerCheckpoint: 2 })).toEqual({
      ok: false,
      reason: 'blastRadiusPerCheckpoint does not equal the recomputed bound',
      recomputedBound: 1.5,
    });
    // bound check precedes blast radius
    expect(verifySafetyCertificate({ ...c, bound: 9, blastRadiusPerCheckpoint: 9 }).reason).toMatch(/^stated bound/);
  });
  it('guardian pin (checked before alg + signature)', () => {
    const c = mk();
    const other = encodeKey(generateKeyPair().publicKey);
    expect(verifySafetyCertificate(c, { guardian: other })).toEqual({
      ok: false,
      reason: 'guardian key is not the pinned key',
      recomputedBound: 1.5,
    });
    expect(verifySafetyCertificate({ ...c, alg: 'bogus' as never }, { guardian: other }).reason).toBe('guardian key is not the pinned key');
    expect(verifySafetyCertificate(c, { guardian: c.guardian })).toEqual({ ok: true, recomputedBound: 1.5 });
    expect(verifySafetyCertificate(c, { guardian: undefined }).ok).toBe(true);
  });
  it('unknown alg', () => {
    const c = resign(mk(), { alg: 'bogus' });
    expect(verifySafetyCertificate(c)).toEqual({ ok: false, reason: 'unknown signature alg', recomputedBound: 1.5 });
  });
  it('bad signature', () => {
    const c = mk();
    expect(verifySafetyCertificate({ ...c, issued_at: 6 })).toEqual({
      ok: false,
      reason: 'guardian signature does not verify',
      recomputedBound: 1.5,
    });
    expect(verifySafetyCertificate({ ...c, statement: 'x' }).reason).toBe('guardian signature does not verify');
    expect(verifySafetyCertificate({ ...c, sig: 'AAAA' }).reason).toBe('guardian signature does not verify');
  });
  it('signature covers grant_ref / instance / each param / weights', () => {
    const c = mk({}, { grantRef: 'g', instance: 'i' });
    expect(verifySafetyCertificate(c).ok).toBe(true);
    expect(verifySafetyCertificate({ ...c, grant_ref: 'h' }).ok).toBe(false);
    expect(verifySafetyCertificate({ ...c, instance: 'j' }).ok).toBe(false);
    for (const k of ['theta1', 'theta2', 'lambda', 'rho'] as const) {
      const v = verifySafetyCertificate({ ...c, params: { ...c.params, [k]: c.params[k] + 0.001 } });
      expect(v.ok).toBe(false);
    }
  });
  it('a getter that throws is reported as malformed certificate: <msg>; non-Error => unknown', () => {
    const c = mk();
    const bad = { ...c };
    Object.defineProperty(bad, 'params', {
      get() {
        throw new Error('boom');
      },
    });
    expect(verifySafetyCertificate(bad as never)).toEqual({ ok: false, reason: 'malformed certificate: boom' });
    const bad2 = { ...c };
    Object.defineProperty(bad2, 'params', {
      get() {
        throw 'str';
      },
    });
    expect(verifySafetyCertificate(bad2 as never)).toEqual({ ok: false, reason: 'malformed certificate: unknown' });
  });
  it('params missing entirely is reported (no throw)', () => {
    const v = verifySafetyCertificate({ ...mk(), params: undefined } as never);
    expect(v.ok).toBe(false);
    expect(v.reason).toBeDefined();
  });
});

describe('suite agility', () => {
  const ml = mlDsa65Keygen(new Uint8Array(32).fill(5));
  it('hybrid: both signatures required, alg/pq_pk bound', () => {
    const c = issueSafetyCertificate({ policy: pol(), guardianSecret: G.secretKey, issuedAt: 1, suite: { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml } });
    expect(c.alg).toBe('hybrid-ed25519-ml-dsa-65');
    expect(typeof c.pq_pk).toBe('string');
    expect(typeof c.pq_sig).toBe('string');
    const pins = { pqPins: { [c.guardian]: c.pq_pk! } };
    expect(verifySafetyCertificate(c, pins).ok).toBe(true);
    expect(verifySafetyCertificate(c, {}).ok).toBe(false); // unpinned PQ refused
    expect(verifySafetyCertificate(c, { allowUnboundPq: true }).ok).toBe(true);
    expect(verifySafetyCertificate({ ...c, pq_sig: undefined }, pins).ok).toBe(false);
    expect(verifySafetyCertificate({ ...c, alg: 'ml-dsa-65' }, pins).ok).toBe(false);
    expect(verifySafetyCertificate({ ...c, pq_sig: c.pq_sig!.slice(0, -2) + 'AA' }, pins).ok).toBe(false);
    // pq_sig is excluded from the signed message
    expect(Array.from(safetyCertificateMessage(c))).toEqual(Array.from(safetyCertificateMessage({ ...c, pq_sig: 'q' })));
  });
  it('pure ml-dsa-65', () => {
    const c = issueSafetyCertificate({ policy: pol(), guardianSecret: G.secretKey, issuedAt: 1, suite: { alg: 'ml-dsa-65', mlDsa: ml } });
    expect(c.alg).toBe('ml-dsa-65');
    expect('pq_sig' in c).toBe(false);
    expect(verifySafetyCertificate(c, { allowUnboundPq: true }).ok).toBe(true);
    expect(verifySafetyCertificate({ ...c, issued_at: 2 }, { allowUnboundPq: true }).ok).toBe(false);
  });
  void pqPinFor;
});

describe('encode / decode', () => {
  it('encode is the canonical JSON; decode round-trips', () => {
    const c = mk({}, { grantRef: 'g' });
    const s = encodeSafetyCertificate(c);
    expect(JSON.parse(s)).toEqual(c);
    expect(decodeSafetyCertificate(s)).toEqual(c);
  });
  it('decode rejects garbage, arrays, null, wrong v, non-string sig/guardian, bad params', () => {
    const c = mk();
    const j = (o: unknown) => JSON.stringify(o);
    expect(decodeSafetyCertificate(5 as never)).toBeNull();
    expect(decodeSafetyCertificate('')).toBeNull();
    expect(decodeSafetyCertificate('null')).toBeNull();
    expect(decodeSafetyCertificate('5')).toBeNull();
    expect(decodeSafetyCertificate('[]')).toBeNull();
    expect(decodeSafetyCertificate(j([c]))).toBeNull();
    expect(decodeSafetyCertificate(j({ ...c, v: 2 }))).toBeNull();
    expect(decodeSafetyCertificate(j({ ...c, sig: 1 }))).toBeNull();
    expect(decodeSafetyCertificate(j({ ...c, sig: undefined }))).toBeNull();
    expect(decodeSafetyCertificate(j({ ...c, guardian: 1 }))).toBeNull();
    expect(decodeSafetyCertificate(j({ ...c, guardian: undefined }))).toBeNull();
    expect(decodeSafetyCertificate(j({ ...c, params: null }))).toBeNull();
    expect(decodeSafetyCertificate(j({ ...c, params: undefined }))).toBeNull();
    expect(decodeSafetyCertificate(j({ ...c, params: 5 }))).toBeNull();
    expect(decodeSafetyCertificate(j({ ...c, params: 'x' }))).toBeNull();
    expect(decodeSafetyCertificate(j(c))).toEqual(c);
  });
  it('a non-string argument is rejected even when its string coercion is a valid certificate', () => {
    const c = mk();
    const s = encodeSafetyCertificate(c);
    expect(decodeSafetyCertificate(s)).toEqual(c);
    expect(decodeSafetyCertificate({ toString: () => s } as never)).toBeNull();
    expect(decodeSafetyCertificate([s] as never)).toBeNull();
  });
  it('size bound is on UTF-8 BYTES, inclusive at MAX_JSON_BYTES', () => {
    const c = mk();
    const pad = (n: number, ch: string) => {
      // statement is advisory; pad it to hit an exact byte length
      const base = JSON.stringify({ ...c, statement: '' });
      const bytes = new TextEncoder().encode(base).length;
      const need = n - bytes;
      const unit = new TextEncoder().encode(ch).length;
      return JSON.stringify({ ...c, statement: ch.repeat(need / unit) });
    };
    const at = pad(MAX_JSON_BYTES, 'a');
    expect(new TextEncoder().encode(at).length).toBe(MAX_JSON_BYTES);
    expect(decodeSafetyCertificate(at)).not.toBeNull();
    const over = pad(MAX_JSON_BYTES + 1, 'a');
    expect(decodeSafetyCertificate(over)).toBeNull();
    // multibyte: char count < limit but bytes > limit
    const mb = pad(MAX_JSON_BYTES + 2, 'é');
    expect(mb.length).toBeLessThan(MAX_JSON_BYTES + 2);
    expect(decodeSafetyCertificate(mb)).toBeNull();
  });
});
