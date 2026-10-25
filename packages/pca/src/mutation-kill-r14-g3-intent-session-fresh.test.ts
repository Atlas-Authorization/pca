/**
 * r14 (g3) static-mutant kills for intent-session.ts: its module-level helpers (suiteErr, isObj, isInt, isNonNeg, u8len,
 * b32, own, shortStr), constants (INTENT_SESSION_KIND and the two domain strings) and the ROOT_KEYS member list are built
 * once at import. Every test re-evaluates the module (vi.resetModules + dynamic import) and replays the pinned golden
 * tables (killSession, k042-sessrevoc-cases: wire and session-root shape / verify, exact reasons) through it, plus
 * targeted checks of the constants.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { assert, describe, expect, it, vi } from 'vitest';

const load = (f: string): any => JSON.parse(gunzipSync(readFileSync(resolve(__dirname, '..', 'testdata', f))).toString('utf8'));
const KS = load('killSession.json.gz');
const SR = load('k042-sessrevoc-cases.json.gz');
const toTs = (x: any): any => {
  if (Array.isArray(x)) return x.map(toTs);
  if (x && typeof x === 'object') { const o: any = {}; for (const [k, v] of Object.entries(x)) o[k] = toTs(v); return o; }
  return x;
};
const noThrow = <A extends unknown[], R>(name: string, f: (...a: A) => R) => (...a: A): R => {
  try { return f(...a); } catch (e) { return assert.fail(`${name} threw: ${(e as Error)?.message ?? String(e)}`); }
};
async function fresh() {
  vi.resetModules();
  const m = await import('./intent-session');
  const h = await import('./hash');
  return {
    m, h,
    wire: noThrow('validateIntentSessionWire', m.validateIntentSessionWire),
    shape: noThrow('sessionRootShapeError', m.sessionRootShapeError),
    verify: noThrow('verifySessionRoot', m.verifySessionRoot),
    digest: noThrow('sessionRootDigest', m.sessionRootDigest),
  };
}
const BASE = toTs(KS.root.find((r: any) => r.name === 'base').arg);

describe('intent-session.ts (fresh module): the golden tables', () => {
  it('wire: validateIntentSessionWire, exact reasons', async () => {
    const f = await fresh();
    for (const c of KS.wire) expect(f.wire(toTs(c.arg)), c.name).toBe(c.ts);
    for (const c of SR.wire) expect(f.wire(JSON.parse(c.v)), c.name).toBe(c.reason);
  });
  it('root: sessionRootShapeError and verifySessionRoot, exact reasons', async () => {
    const f = await fresh();
    for (const c of KS.root) {
      const t = toTs(c.arg);
      const v = f.verify(t, c.pins ? { pqPins: c.pins } : {});
      expect({ shape: f.shape(t), verify: v.ok ? null : v.reason }, c.name).toEqual({ shape: c.shape, verify: c.verify });
    }
    for (const c of SR.root) {
      const s = JSON.parse(c.s);
      const v = f.verify(s, c.pq_pins ? { pqPins: JSON.parse(c.pq_pins) } : {});
      expect({ shape: f.shape(s), verify: v.ok ? null : v.reason }, c.name).toEqual({ shape: c.shape, verify: c.verify });
    }
  });
});

describe('intent-session.ts (fresh module): constants and the member list', () => {
  it('the kind and the two domains', async () => {
    const f = await fresh();
    expect(f.m.INTENT_SESSION_KIND).toBe('pca-intent-session');
    expect(f.m.INTENT_SESSION_SIG_DOMAIN).toBe('atlas-pca/intent-session/v1\0');
    expect(f.m.INTENT_SESSION_REF_DOMAIN).toBe('atlas-pca/intent-session-ref/v1');
    // a root signed under the real signature domain verifies; its digest is over the real reference domain
    expect(f.shape(BASE)).toBeNull();
    expect(f.verify(BASE)).toEqual({ ok: true });
    expect(f.digest(BASE)).toBe(f.h.hashCanonical({ d: 'atlas-pca/intent-session-ref/v1', s: BASE }));
  });
  it('every root member is a known member (the closed member set)', async () => {
    const f = await fresh();
    const keys = ['v', 'kind', 'session', 'principals', 'intent_ref', 'schema', 'layers', 'accumulators', 'monitors', 'question_uri', 'revocation', 'flows', 'expires_at', 'signer', 'alg', 'pq_pk', 'sig', 'pq_sig'];
    const all: Record<string, unknown> = Object.fromEntries(keys.map((k) => [k, 'x']));
    all.v = 1;
    all.kind = 'pca-intent-session';
    expect(f.shape(all)).toBe('session and intent_ref must be canonical base64url (32 bytes)');
    expect(f.shape({ ...all, zz: 1 })).toBe("session root: unknown member 'zz'");
  });
  it('byte lengths are UTF-8 lengths (question_uri and the standing profile)', async () => {
    const f = await fresh();
    const S = { ...BASE, question_uri: 'https://q.example/' + 'x'.repeat(2048) };
    expect(f.shape(S)).toBe('question_uri must be a non-empty string');
    const std = (profile: string) => f.shape({ ...BASE, layers: { ...BASE.layers, std: { profile, version: 1, digest: BASE.session } } }, { signed: false });
    expect(std('p'.repeat(128))).toBeNull();
    expect(std('é'.repeat(65))).toBe('layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)');
  });
  it('a principal or root alg outside the suite registry is refused', async () => {
    const f = await fresh();
    expect(f.shape({ ...BASE, principals: [{ ...BASE.principals[0], alg: 'rot13' }] })).toMatch(/^principal alg: /);
    expect(f.shape({ ...BASE, alg: 'rot13' })).toMatch(/^alg: /);
  });
});
