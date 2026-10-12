import { afterEach, describe, expect, it, vi } from 'vitest';
import { FlattenedSign, importJWK } from 'jose';
import {
  type Capability,
  type Predicate,
  type Signer,
  DEFAULT_RISK_POLICY,
  b64u,
  buildPCActn,
  canonicalizeStrict,
  delegate,
  encodeMlDsaPublicKey,
  generateKeyPair,
  hashCanonical,
  mintGrant,
  mintRoot,
  mlDsa65Keygen,
  sha256,
  signShare,
  thresholdMessage,
  utf8,
  verifyChain,
} from '@atlasauth/pca';
import {
  type GnapGrantRequest,
  type GnapResourceAccess,
  type VerifyGnapRequestResult,
  AGENT_GNAP_PROFILE,
  GNAP_ACCESS_CAVEAT,
  GNAP_GRANT_CAVEAT,
  GnapError,
  accessContains,
  accessToPredicates,
  accessWithin,
  authorizeGnapAction,
  beginGnapContinuation,
  capabilityToGrantResponse,
  clampAccess,
  completeGnapContinuation,
  encodeBoundToken,
  gnapActionResource,
  gnapRequestRequiresStepUp,
  gnapStepUpShare,
  grantRequestToCapability,
  grantedAccessOf,
  holderJwk,
  normalizeAccess,
  resolveHolder,
  signGnapRequest,
  verifyGnapRequest,
  verifyGnapToken,
} from './index';

afterEach(() => vi.useRealTimers());

function kp() {
  const k = generateKeyPair();
  return { secretKey: k.secretKey, publicKey: k.publicKey, b64: b64u(k.publicKey) };
}
function req(pub: Uint8Array, access: unknown[], interact?: GnapGrantRequest['interact']): GnapGrantRequest {
  return {
    access_token: { access: access as never },
    client: { key: { proof: 'jwsd', jwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(pub) } } },
    ...(interact !== undefined ? { interact } : {}),
  };
}
const RW = { type: 'repo', actions: ['read', 'write'], locations: ['main'] };
const R = { type: 'repo', actions: ['read'], locations: ['main'] };
const RES = gnapActionResource('repo', 'main');

describe('GnapError', () => {
  it('is a named Error', () => {
    const e = new GnapError('boom');
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe('GnapError');
    expect(e.message).toBe('boom');
  });
});

describe('normalizeAccess', () => {
  it('rejects non-arrays and malformed entries with exact messages', () => {
    expect(() => normalizeAccess({} as never)).toThrow(new GnapError('access must be an array'));
    expect(() => normalizeAccess('x' as never)).toThrow('access must be an array');
    const m = 'malformed access item (needs a non-empty string `type`)';
    for (const bad of ['', null, undefined, 5, [], [1], {}, { type: '' }, { type: 5 }, true]) {
      expect(() => normalizeAccess([bad])).toThrow(new GnapError(m));
    }
    expect(() => normalizeAccess([{ type: 'a' }, null])).toThrow(m);
  });
  it('string and object forms', () => {
    expect(normalizeAccess(['repo'])).toStrictEqual([{ type: 'repo' }]);
    expect(normalizeAccess([])).toStrictEqual([]);
    expect(
      normalizeAccess([{ type: 't', actions: ['a', 1, 'b'], locations: ['l'], datatypes: ['d'], identifier: 'i', privileges: ['p'], junk: 1 }]),
    ).toStrictEqual([{ type: 't', actions: ['a', 'b'], locations: ['l'], datatypes: ['d'], identifier: 'i', privileges: ['p'] }]);
  });
  it('empty / non-array / all-non-string lists are omitted; empty identifier kept', () => {
    for (const k of ['actions', 'locations', 'datatypes', 'privileges']) {
      expect(normalizeAccess([{ type: 't', [k]: [] }])).toStrictEqual([{ type: 't' }]);
      expect(normalizeAccess([{ type: 't', [k]: [1, null] }])).toStrictEqual([{ type: 't' }]);
      expect(normalizeAccess([{ type: 't', [k]: 'str' }])).toStrictEqual([{ type: 't' }]);
      expect(normalizeAccess([{ type: 't', [k]: ['x'] }])).toStrictEqual([{ type: 't', [k]: ['x'] }]);
    }
    expect(normalizeAccess([{ type: 't', identifier: '' }])).toStrictEqual([{ type: 't', identifier: '' }]);
    expect(normalizeAccess([{ type: 't', identifier: 5 }])).toStrictEqual([{ type: 't' }]);
  });
});

describe('accessToPredicates', () => {
  it('defaults: any verb, any location, no where', () => {
    expect(accessToPredicates({ type: 't' })).toStrictEqual([{ verb: '*', resource: 'gnap:t:*' }]);
    expect(accessToPredicates({ type: 't', actions: [], locations: [], datatypes: [] })).toStrictEqual([{ verb: '*', resource: 'gnap:t:*' }]);
  });
  it('one predicate per location, verbs copied, where conditions ordered and cloned', () => {
    const a: GnapResourceAccess = { type: 't', actions: ['x', 'y'], locations: ['l1', 'l2'], datatypes: ['d1'], identifier: 'id' };
    const ps = accessToPredicates(a);
    expect(ps).toStrictEqual([
      { verb: ['x', 'y'], resource: 'gnap:t:l1', where: [{ field: 'action.params.datatype', op: 'in', value: ['d1'] }, { field: 'action.params.identifier', op: 'eq', value: 'id' }] },
      { verb: ['x', 'y'], resource: 'gnap:t:l2', where: [{ field: 'action.params.datatype', op: 'in', value: ['d1'] }, { field: 'action.params.identifier', op: 'eq', value: 'id' }] },
    ]);
    expect(ps[0]!.verb).not.toBe(a.actions);
    expect(ps[0]!.where![0]).not.toBe(ps[1]!.where![0]);
    expect(ps[0]!.where).not.toBe(ps[1]!.where);
    const cond = ps[0]!.where![0] as { value: string[] };
    expect(cond.value).not.toBe(a.datatypes);
  });
  it('identifier only (including empty string) and datatypes only', () => {
    expect(accessToPredicates({ type: 't', identifier: '' })[0]!.where).toStrictEqual([{ field: 'action.params.identifier', op: 'eq', value: '' }]);
    expect(accessToPredicates({ type: 't', datatypes: ['a'] })[0]!.where).toStrictEqual([{ field: 'action.params.datatype', op: 'in', value: ['a'] }]);
  });
  it('gnapActionResource', () => expect(gnapActionResource('a', 'b:c')).toBe('gnap:a:b:c'));
});

describe('accessContains / accessWithin / clampAccess', () => {
  it('type must be equal', () => {
    expect(accessContains({ type: 'a' }, { type: 'a' })).toBe(true);
    expect(accessContains({ type: 'a' }, { type: 'b' })).toBe(false);
  });
  it('actions / datatypes: undefined sup allows all; undefined sub needs undefined sup; subset', () => {
    for (const k of ['actions', 'datatypes'] as const) {
      expect(accessContains({ type: 't' }, { type: 't', [k]: ['x'] })).toBe(true);
      expect(accessContains({ type: 't', [k]: ['x'] }, { type: 't' })).toBe(false);
      expect(accessContains({ type: 't', [k]: ['x', 'y'] }, { type: 't', [k]: ['y'] })).toBe(true);
      expect(accessContains({ type: 't', [k]: ['x'] }, { type: 't', [k]: ['x', 'y'] })).toBe(false);
      expect(accessContains({ type: 't', [k]: ['x'] }, { type: 't', [k]: [] })).toBe(true);
      expect(accessContains({ type: 't', [k]: [] }, { type: 't', [k]: ['x'] })).toBe(false);
      expect(accessContains({ type: 't', [k]: ['x'] }, { type: 't', [k]: ['x'] })).toBe(true);
    }
  });
  it('locations: wildcards and prefixes', () => {
    const c = (sup: string[] | undefined, sub: string[] | undefined) => accessContains({ type: 't', locations: sup }, { type: 't', locations: sub });
    expect(c(undefined, ['a'])).toBe(true);
    expect(c(undefined, undefined)).toBe(true);
    expect(c(['a'], undefined)).toBe(false);
    expect(c(['a', '*'], undefined)).toBe(true);
    expect(c(['a*'], undefined)).toBe(false);
    expect(c(['a'], ['a'])).toBe(true);
    expect(c(['a'], ['b'])).toBe(false);
    expect(c(['*'], ['anything'])).toBe(true);
    expect(c(['a/*'], ['a/b'])).toBe(true);
    expect(c(['a/*'], ['a/'])).toBe(true);
    expect(c(['a/*'], ['a'])).toBe(false);
    expect(c(['a/*'], ['b/b'])).toBe(false);
    expect(c(['a/*'], ['a/*'])).toBe(true);
    expect(c(['ab'], ['abc'])).toBe(false);
    expect(c(['a', 'b'], ['a', 'b'])).toBe(true);
    expect(c(['a', 'b'], ['a', 'c'])).toBe(false);
    expect(c(['a/*', 'b'], ['a/x', 'b'])).toBe(true);
    expect(c(['a'], [])).toBe(true);
    expect(c([], ['a'])).toBe(false);
    expect(c(['*x'], ['*x'])).toBe(true);
    expect(c(['*x'], ['yx'])).toBe(false);
  });
  it('identifier only conflicts when both are set and differ', () => {
    const c = (g: string | undefined, r: string | undefined) =>
      accessContains({ type: 't', ...(g !== undefined ? { identifier: g } : {}) }, { type: 't', ...(r !== undefined ? { identifier: r } : {}) });
    expect(c(undefined, undefined)).toBe(true);
    expect(c('a', undefined)).toBe(true);
    expect(c(undefined, 'a')).toBe(true);
    expect(c('a', 'a')).toBe(true);
    expect(c('a', 'b')).toBe(false);
    expect(c('', 'a')).toBe(false);
    expect(c('a', '')).toBe(false);
  });
  it('accessWithin and clampAccess preserve order and split exactly', () => {
    expect(accessWithin([], { type: 't' })).toBe(false);
    expect(accessWithin([{ type: 'x' }, { type: 't' }], { type: 't' })).toBe(true);
    const r1 = { type: 'repo', actions: ['read'] };
    const r2 = { type: 'other' };
    const r3 = { type: 'repo', actions: ['write'] };
    const out = clampAccess([{ type: 'repo', actions: ['read', 'write'] }], [r1, r2, r3]);
    expect(out.granted).toStrictEqual([r1, r3]);
    expect(out.dropped).toStrictEqual([r2]);
    expect(clampAccess([], [])).toStrictEqual({ granted: [], dropped: [] });
  });
});

describe('resolveHolder / holderJwk', () => {
  const k = kp();
  it('override takes precedence and must be canonical', () => {
    const other = kp();
    expect(resolveHolder(req(k.publicKey, [R]), other.b64)).toBe(other.b64);
    const m = 'holder override is not a canonical base64url Ed25519 public key';
    for (const bad of ['', 'abc', k.b64 + '=', b64u(new Uint8Array(31)), b64u(new Uint8Array(33))]) {
      expect(() => resolveHolder(req(k.publicKey, [R]), bad)).toThrow(new GnapError(m));
    }
  });
  it('derives from client.key.jwk OKP/Ed25519 only', () => {
    expect(resolveHolder(req(k.publicKey, [R]))).toBe(k.b64);
    const m = 'cannot resolve holder: supply client.key.jwk (OKP/Ed25519) or a holder override';
    const mk = (client: unknown) => ({ access_token: { access: [R] }, client }) as never;
    const jwk = (o: Record<string, unknown>) => ({ key: { proof: 'jwsd', jwk: { kty: 'OKP', crv: 'Ed25519', x: k.b64, ...o } } });
    for (const bad of [
      'client-id-string', null, undefined, {}, { key: 'str' }, { key: { proof: 'jwsd' } }, { key: null }, jwk({ kty: 'EC' }), jwk({ crv: 'Ed448' }),
      jwk({ x: undefined }), jwk({ x: 5 }), jwk({ x: 'abc' }), jwk({ x: k.b64 + '=' }),
    ]) expect(() => resolveHolder(mk(bad))).toThrow(new GnapError(m));
  });
  it('holderJwk', () => {
    expect(holderJwk('abc')).toStrictEqual({ kty: 'OKP', crv: 'Ed25519', x: 'abc', use: 'sig', alg: 'EdDSA' });
  });
});

describe('grantRequestToCapability', () => {
  it('request shape errors', () => {
    const p = kp();
    const a = kp();
    const o = { issuerSecret: p.secretKey, issuerPublic: p.b64 };
    const m = 'grant request must carry access_token.access (single-token request)';
    for (const at of [null, undefined, 'x', [], {}, { access: 'x' }, { access: {} }]) {
      expect(() => grantRequestToCapability({ ...req(a.publicKey, [R]), access_token: at as never }, o)).toThrow(new GnapError(m));
    }
    expect(() => grantRequestToCapability(req(a.publicKey, [{ type: '' }]), o)).toThrow('malformed access item');
    // holder resolution runs first
    expect(() => grantRequestToCapability({ ...req(a.publicKey, [R]), client: 'x' }, o)).toThrow('cannot resolve holder');
    expect(() => grantRequestToCapability({ ...req(a.publicKey, [R]), client: 'x', access_token: null as never }, o)).toThrow('cannot resolve holder');
  });

  it('root grant: envelope, provenance, goal, defaults and overrides', () => {
    const p = kp();
    const a = kp();
    const r = req(a.publicKey, [RW, 'plain'], { start: ['redirect'] });
    const out = grantRequestToCapability(r, { issuerSecret: p.secretKey, issuerPublic: p.b64, now: 1234.9, interacted: true, goal: 'my goal', salt: b64u(new Uint8Array(16)) });
    expect(out.holder).toBe(a.b64);
    expect(out.chain).toStrictEqual([out.grant]);
    expect(out.droppedAccess).toStrictEqual([]);
    expect(out.grantedAccess).toStrictEqual([RW, { type: 'plain' }]);
    expect(out.provenance).toMatchObject({ type: GNAP_GRANT_CAVEAT, client_id: a.b64, interacted: true, ts: 1234, granted_access: [RW, { type: 'plain' }] });
    expect(typeof (out.provenance as { request_digest: string }).request_digest).toBe('string');
    expect(verifyChain(out.chain, p.b64).ok).toBe(true);
    expect(out.grant.issuer).toBe(p.b64);
    expect(out.grant.holder).toBe(a.b64);
    expect(grantedAccessOf(out.chain)).toStrictEqual([RW, { type: 'plain' }]);
    // deterministic goal commit differs by goal
    const same = grantRequestToCapability(r, { issuerSecret: p.secretKey, issuerPublic: p.b64, now: 1234.9, interacted: true, goal: 'my goal', salt: b64u(new Uint8Array(16)) });
    expect(same.grant.id).toBe(out.grant.id);
    const diffGoal = grantRequestToCapability(r, { issuerSecret: p.secretKey, issuerPublic: p.b64, now: 1234.9, interacted: true, goal: 'other', salt: b64u(new Uint8Array(16)) });
    expect(diffGoal.grant.id).not.toBe(out.grant.id);
    const noSalt = grantRequestToCapability(r, { issuerSecret: p.secretKey, issuerPublic: p.b64, now: 1234.9, interacted: true, goal: 'my goal' });
    expect(noSalt.grant.id).not.toBe(out.grant.id);
  });
  it('interacted is true only for exactly true; digest binds interact, access and client', () => {
    const p = kp();
    const a = kp();
    const o = { issuerSecret: p.secretKey, issuerPublic: p.b64, now: 5 };
    const base = grantRequestToCapability(req(a.publicKey, [R]), o);
    expect((base.provenance as { interacted: boolean }).interacted).toBe(false);
    expect((grantRequestToCapability(req(a.publicKey, [R]), { ...o, interacted: false }).provenance as { interacted: boolean }).interacted).toBe(false);
    expect((grantRequestToCapability(req(a.publicKey, [R]), { ...o, interacted: 1 as never }).provenance as { interacted: boolean }).interacted).toBe(false);
    const dig = (x: { provenance: unknown }) => (x.provenance as { request_digest: string }).request_digest;
    expect(dig(base)).toBe(dig(grantRequestToCapability(req(a.publicKey, [R]), { ...o, now: 99 })));
    expect(dig(grantRequestToCapability(req(a.publicKey, [R], { start: ['x'] }), o))).not.toBe(dig(base));
    expect(dig(grantRequestToCapability(req(a.publicKey, [RW]), o))).not.toBe(dig(base));
    expect(dig(grantRequestToCapability(req(kp().publicKey, [R]), o))).not.toBe(dig(base));
    // holder override changes client_id
    const ov = kp();
    const viaOverride = grantRequestToCapability(req(a.publicKey, [R]), { ...o, holder: ov.b64 });
    expect(viaOverride.holder).toBe(ov.b64);
    expect(viaOverride.grant.holder).toBe(ov.b64);
  });
  it('default goal and default time', () => {
    const p = kp();
    const a = kp();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(777_123);
    const out = grantRequestToCapability(req(a.publicKey, [R]), { issuerSecret: p.secretKey, issuerPublic: p.b64 });
    expect((out.provenance as { ts: number }).ts).toBe(777_123);
    // goal defaults to gnap:grant:<holder>: the commit is goalCommitOf(goal, salt)
    const salt = b64u(new Uint8Array(16).fill(3));
    const d = grantRequestToCapability(req(a.publicKey, [R]), { issuerSecret: p.secretKey, issuerPublic: p.b64, salt });
    const e = grantRequestToCapability(req(a.publicKey, [R]), { issuerSecret: p.secretKey, issuerPublic: p.b64, salt, goal: `gnap:grant:${a.b64}` });
    expect(d.grant.id).toBe(e.grant.id);
  });
  it('agentBinding and riskPolicy are written into the envelope', () => {
    const p = kp();
    const a = kp();
    const rp = { ...DEFAULT_RISK_POLICY, tier2: 0.123 } as never;
    const out = grantRequestToCapability(req(a.publicKey, [R]), { issuerSecret: p.secretKey, issuerPublic: p.b64, agentBinding: { model_id: 'm' } as never, riskPolicy: rp });
    const env = out.grant.caveats.find((c) => c.type === 'envelope' || (c as { risk_policy?: unknown }).risk_policy) as unknown as { risk_policy: unknown; agent_binding: unknown; predicates: unknown; caveats: unknown };
    expect(env.agent_binding).toStrictEqual({ model_id: 'm' });
    expect(env.risk_policy).toStrictEqual(rp);
    expect(env.predicates).toStrictEqual(accessToPredicates(RW).length === 2 ? [] : accessToPredicates(R));
    const dflt = grantRequestToCapability(req(a.publicKey, [R]), { issuerSecret: p.secretKey, issuerPublic: p.b64 });
    const env2 = dflt.grant.caveats.find((c) => (c as { risk_policy?: unknown }).risk_policy) as unknown as { risk_policy: unknown; agent_binding: unknown };
    expect(env2.agent_binding).toStrictEqual({});
    expect(env2.risk_policy).toStrictEqual(DEFAULT_RISK_POLICY);
  });

  it('delegation: clamp on by default, off with clampToIssuer:false, default issuerChain', () => {
    const p = kp();
    const A = kp();
    const B = kp();
    const hop0 = grantRequestToCapability(req(A.publicKey, [R]), { issuerSecret: p.secretKey, issuerPublic: p.b64, now: 1 });
    const widen = req(B.publicKey, [R, { type: 'repo', actions: ['write'], locations: ['main'] }]);
    const clamped = grantRequestToCapability(widen, { issuerSecret: A.secretKey, issuerPublic: A.b64, parent: hop0.grant, issuerChain: hop0.chain, now: 7 });
    expect(clamped.grantedAccess).toStrictEqual([R]);
    expect(clamped.droppedAccess).toStrictEqual([{ type: 'repo', actions: ['write'], locations: ['main'] }]);
    expect(clamped.chain).toStrictEqual([...hop0.chain, clamped.grant]);
    expect(clamped.grant.holder).toBe(B.b64);
    expect(clamped.grant.issuer).toBe(A.b64);
    expect(clamped.provenance).toMatchObject({ type: GNAP_ACCESS_CAVEAT, client_id: B.b64, ts: 7, access: [R], predicates: accessToPredicates(R) });
    expect(verifyChain(clamped.chain, p.b64).ok).toBe(true);
    // default issuerChain = [parent]
    const dflt = grantRequestToCapability(widen, { issuerSecret: A.secretKey, issuerPublic: A.b64, parent: hop0.grant, now: 7 });
    expect(dflt.chain).toStrictEqual([hop0.grant, dflt.grant]);
    expect(dflt.grantedAccess).toStrictEqual([R]);
    // clamp disabled keeps everything, dropped stays empty
    const off = grantRequestToCapability(widen, { issuerSecret: A.secretKey, issuerPublic: A.b64, parent: hop0.grant, issuerChain: hop0.chain, clampToIssuer: false });
    expect(off.grantedAccess).toHaveLength(2);
    expect(off.droppedAccess).toStrictEqual([]);
    // clampToIssuer:true explicitly clamps
    const on = grantRequestToCapability(widen, { issuerSecret: A.secretKey, issuerPublic: A.b64, parent: hop0.grant, clampToIssuer: true });
    expect(on.grantedAccess).toStrictEqual([R]);
    // everything dropped
    const none = grantRequestToCapability(req(B.publicKey, [{ type: 'zzz' }]), { issuerSecret: A.secretKey, issuerPublic: A.b64, parent: hop0.grant });
    expect(none.grantedAccess).toStrictEqual([]);
    expect(none.droppedAccess).toStrictEqual([{ type: 'zzz' }]);
  });
  it('a delegation without a parent grant records no root provenance on the child', () => {
    const p = kp();
    const A = kp();
    const B = kp();
    const hop0 = grantRequestToCapability(req(A.publicKey, [R]), { issuerSecret: p.secretKey, issuerPublic: p.b64 });
    const child = grantRequestToCapability(req(B.publicKey, [R]), { issuerSecret: A.secretKey, issuerPublic: A.b64, parent: hop0.grant });
    expect(child.grant.caveats.filter((c) => c.type === GNAP_ACCESS_CAVEAT)).toHaveLength(1);
    expect(child.grant.caveats.length).toBe(hop0.grant.caveats.length + 1);
  });
});

describe('grantedAccessOf and stored-access reading', () => {
  const p = kp();
  const a = kp();
  function root(gnapGrant: unknown): Capability {
    return mintGrant({
      principalSecret: p.secretKey,
      principalPublic: p.b64,
      holder: a.b64,
      goal: 'g',
      envelope: { predicates: [{ verb: '*', resource: '*' }], caveats: gnapGrant === undefined ? [] : [gnapGrant as never], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
    }).grant;
  }
  it('empty / non-array chains yield []', () => {
    expect(grantedAccessOf([])).toStrictEqual([]);
    expect(grantedAccessOf(null as never)).toStrictEqual([]);
    expect(grantedAccessOf({} as never)).toStrictEqual([]);
  });
  it('root-only: reads gnap_grant.granted_access, filtering malformed entries', () => {
    const g = root({ type: GNAP_GRANT_CAVEAT, client_id: a.b64, request_digest: 'd', granted_access: [R, { type: '' }, 'plain', 5], interacted: true, ts: 1 });
    expect(grantedAccessOf([g])).toStrictEqual([R, { type: 'plain' }]);
  });
  it('root without a usable gnap_grant yields []', () => {
    expect(grantedAccessOf([root(undefined)])).toStrictEqual([]);
    expect(grantedAccessOf([root({ type: GNAP_GRANT_CAVEAT, client_id: 5, request_digest: 'd', granted_access: [R] })])).toStrictEqual([]);
    expect(grantedAccessOf([root({ type: GNAP_GRANT_CAVEAT, client_id: 'c', request_digest: 5, granted_access: [R] })])).toStrictEqual([]);
    expect(grantedAccessOf([root({ type: GNAP_GRANT_CAVEAT, client_id: 'c', request_digest: 'd', granted_access: 'nope' })])).toStrictEqual([]);
    expect(grantedAccessOf([root({ type: GNAP_GRANT_CAVEAT, client_id: 'c', request_digest: 'd', granted_access: [R] })])).toStrictEqual([R]);
  });
  it('the LAST gnap_access caveat on the leaf wins; non-gnap caveats are ignored', () => {
    const g = root({ type: GNAP_GRANT_CAVEAT, client_id: a.b64, request_digest: 'd', granted_access: [RW] });
    const b = kp();
    const c1 = delegate(g, b.b64, [{ type: GNAP_ACCESS_CAVEAT, access: [R] }, { type: 'other', access: [{ type: 'zzz' }] }], a.secretKey);
    expect(grantedAccessOf([g, c1])).toStrictEqual([R]);
    const c2 = delegate(g, b.b64, [{ type: GNAP_ACCESS_CAVEAT, access: [R] }, { type: GNAP_ACCESS_CAVEAT, access: [{ type: 'last' }] }], a.secretKey);
    expect(grantedAccessOf([g, c2])).toStrictEqual([{ type: 'last' }]);
    // malformed stored access on the leaf: [] (does not fall back to the root)
    const c3 = delegate(g, b.b64, [{ type: GNAP_ACCESS_CAVEAT, access: 'bad' }], a.secretKey);
    expect(grantedAccessOf([g, c3])).toStrictEqual([]);
    // leaf without gnap_access (only the delegation's own non-gnap caveat) falls back to the root grant
    const c4 = delegate(g, b.b64, [{ type: 'other' }], a.secretKey);
    expect(grantedAccessOf([g, c4])).toStrictEqual([RW]);
    // non-array caveats on the leaf => fall back to the root
    expect(grantedAccessOf([g, { ...c4, caveats: 'x' as never }])).toStrictEqual([RW]);
  });
});

describe('authorizeGnapAction', () => {
  it('guards and reasons', () => {
    expect(authorizeGnapAction([], { verb: 'read', resource: RES })).toStrictEqual({ allowed: false, reason: 'empty chain' });
    expect(authorizeGnapAction(null as never, { verb: 'read', resource: RES })).toStrictEqual({ allowed: false, reason: 'empty chain' });
    const p = kp();
    const a = kp();
    const { chain } = grantRequestToCapability(req(a.publicKey, [R]), { issuerSecret: p.secretKey, issuerPublic: p.b64 });
    const bad = authorizeGnapAction(chain, { verb: 'read', resource: RES }, { expectedRootIssuer: kp().b64 });
    expect(bad.allowed).toBe(false);
    expect(bad.reason).toMatch(/^capability chain invalid: .+/);
    expect(bad.reason).not.toContain('undefined');
    const ok = authorizeGnapAction(chain, { verb: 'read', resource: RES }, { expectedRootIssuer: p.b64 });
    expect(ok).toStrictEqual({ allowed: true });
    const deny = authorizeGnapAction(chain, { verb: 'write', resource: RES });
    expect(deny).toStrictEqual({ allowed: false, reason: `root authority denies: no predicate permits write on ${RES}` });
  });
  it('root without envelope', () => {
    const p = kp();
    const a = kp();
    const root = mintRoot({ principalSecret: p.secretKey, principalPublic: p.b64, holder: a.b64, caveats: [] });
    expect(authorizeGnapAction([root], { verb: 'read', resource: RES })).toStrictEqual({ allowed: false, reason: 'root grant carries no policy envelope' });
  });
  it('every delegated hop gates, with the exact reason; params and reversibility_class reach the predicates', () => {
    const p = kp();
    const A = kp();
    const B = kp();
    const C = kp();
    const hop0 = grantRequestToCapability(req(A.publicKey, [RW]), { issuerSecret: p.secretKey, issuerPublic: p.b64 });
    // middle hop narrows to read, last hop un-clamped records read+write: intersection must still deny write
    const hop1 = grantRequestToCapability(req(B.publicKey, [R]), { issuerSecret: A.secretKey, issuerPublic: A.b64, parent: hop0.grant, issuerChain: hop0.chain });
    const hop2 = grantRequestToCapability(req(C.publicKey, [RW]), { issuerSecret: B.secretKey, issuerPublic: B.b64, parent: hop1.grant, issuerChain: hop1.chain, clampToIssuer: false });
    expect(authorizeGnapAction(hop2.chain, { verb: 'read', resource: RES })).toStrictEqual({ allowed: true });
    const w = authorizeGnapAction(hop2.chain, { verb: 'write', resource: RES });
    expect(w.allowed).toBe(false);
    expect(w.reason).toBe(`delegated hop denies: no predicate permits write on ${RES}`);
    // a hop whose stored access is unreadable denies everything (fail closed)
    const g = hop0.grant;
    const broken = delegate(g, B.b64, [{ type: GNAP_ACCESS_CAVEAT, access: 'garbage' }], A.secretKey);
    const r = authorizeGnapAction([g, broken], { verb: 'read', resource: RES });
    expect(r).toStrictEqual({ allowed: false, reason: 'delegated hop denies: envelope grants no predicates' });
    // non-gnap caveats on the leaf are skipped
    const other = delegate(g, B.b64, [{ type: 'unrelated' }], A.secretKey);
    expect(authorizeGnapAction([g, other], { verb: 'read', resource: RES })).toStrictEqual({ allowed: true });
  });
  it('params and reversibility_class are part of the evaluated context', () => {
    const p = kp();
    const a = kp();
    const preds: Predicate[] = [
      { verb: 'go', resource: 'r', where: [{ field: 'action.params.n', op: 'eq', value: 5 }] },
      { verb: 'rev', resource: 'r', where: [{ field: 'action.reversibility_class', op: 'eq', value: 'irreversible' }] },
    ];
    const g = mintGrant({
      principalSecret: p.secretKey, principalPublic: p.b64, holder: a.b64, goal: 'g',
      envelope: { predicates: preds, caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
    }).grant;
    expect(authorizeGnapAction([g], { verb: 'go', resource: 'r', params: { n: 5 } }).allowed).toBe(true);
    expect(authorizeGnapAction([g], { verb: 'go', resource: 'r', params: { n: 6 } }).allowed).toBe(false);
    expect(authorizeGnapAction([g], { verb: 'go', resource: 'r' }).allowed).toBe(false);
    expect(authorizeGnapAction([g], { verb: 'rev', resource: 'r', reversibility_class: 'irreversible' }).allowed).toBe(true);
    expect(authorizeGnapAction([g], { verb: 'rev', resource: 'r', reversibility_class: 'reversible' }).allowed).toBe(false);
    expect(authorizeGnapAction([g], { verb: 'rev', resource: 'r' }).allowed).toBe(false);
  });
});

describe('bound token', () => {
  const p = kp();
  const a = kp();
  const issued = grantRequestToCapability(req(a.publicKey, [R]), { issuerSecret: p.secretKey, issuerPublic: p.b64 });
  const chain = issued.chain;
  const enc = (v: unknown) => b64u(utf8(JSON.stringify(v)));

  it('encode is b64u(JSON(chain))', () => {
    expect(Buffer.from(encodeBoundToken(chain), 'base64url').toString('utf8')).toBe(JSON.stringify(chain));
  });
  it('verifyGnapToken success shape', () => {
    const r = verifyGnapToken(encodeBoundToken(chain), { expectedRootIssuer: p.b64 });
    expect(r).toStrictEqual({ ok: true, principal: p.b64, capability: chain[0], chain, access: [R] });
    const b = kp();
    const hop = grantRequestToCapability(req(b.publicKey, [R]), { issuerSecret: a.secretKey, issuerPublic: a.b64, parent: issued.grant, issuerChain: chain });
    const r2 = verifyGnapToken(encodeBoundToken(hop.chain));
    expect(r2.ok && r2.principal).toBe(p.b64);
    expect(r2.ok && r2.capability).toStrictEqual(hop.grant);
    expect(r2.ok && r2.chain).toHaveLength(2);
  });
  it('empty / undecodable', () => {
    expect(verifyGnapToken('')).toStrictEqual({ ok: false, reason: 'token value is empty' });
    expect(verifyGnapToken(5 as never)).toStrictEqual({ ok: false, reason: 'token value is empty' });
    const nd = { ok: false, reason: 'token is not a decodable PCA capability chain' };
    expect(verifyGnapToken('!!!')).toStrictEqual(nd);
    expect(verifyGnapToken(enc({ not: 'array' }))).toStrictEqual(nd);
    expect(verifyGnapToken(enc([]))).toStrictEqual(nd);
    expect(verifyGnapToken(enc('str'))).toStrictEqual(nd);
    expect(verifyGnapToken(enc([null]))).toStrictEqual(nd);
    expect(verifyGnapToken(enc([[]]))).toStrictEqual(nd);
    expect(verifyGnapToken(b64u(new Uint8Array([0xff, 0xfe, 0xfd])))).toStrictEqual(nd);
    expect(verifyGnapToken(b64u(utf8('{"a":1,"a":2}')))).toStrictEqual(nd);
    expect(verifyGnapToken(b64u(utf8('[')))).toStrictEqual(nd);
  });
  it('each required capability member is type-checked; optional ones too', () => {
    const nd = { ok: false, reason: 'token is not a decodable PCA capability chain' };
    const hop = chain[0] as unknown as Record<string, unknown>;
    for (const k of ['id', 'issuer', 'holder', 'body_digest', 'sig']) {
      expect(verifyGnapToken(enc([{ ...hop, [k]: 5 }]))).toStrictEqual(nd);
      const m = { ...hop };
      delete m[k];
      expect(verifyGnapToken(enc([m]))).toStrictEqual(nd);
    }
    expect(verifyGnapToken(enc([{ ...hop, caveats: 'x' }]))).toStrictEqual(nd);
    const m = { ...hop };
    delete m.caveats;
    expect(verifyGnapToken(enc([m]))).toStrictEqual(nd);
    for (const k of ['parent', 'alg', 'pq_pk', 'pq_sig']) {
      expect(verifyGnapToken(enc([{ ...hop, [k]: 5 }]))).toStrictEqual(nd);
      // a string value is structurally acceptable (decodes to a chain; crypto decides)
      const r = verifyGnapToken(enc([{ ...hop, [k]: 'x' }]));
      if (!r.ok) expect(r.reason).not.toBe(nd.reason);
    }
  });
  it('chain verification failures are reported with a prefix', () => {
    const r = verifyGnapToken(encodeBoundToken(chain), { expectedRootIssuer: kp().b64 });
    expect(r.ok).toBe(false);
    expect((r as { reason: string }).reason).toMatch(/^capability chain invalid: .+/);
    const t = verifyGnapToken(encodeBoundToken([{ ...chain[0]!, holder: kp().b64 }]));
    expect(t.ok).toBe(false);
    expect((t as { reason: string }).reason).toMatch(/^capability chain invalid: /);
  });
  it('pqPins are forwarded to chain verification', () => {
    const victim = kp();
    const atk = kp();
    const vMl = mlDsa65Keygen(new Uint8Array(32).fill(7));
    const aMl = mlDsa65Keygen(new Uint8Array(32).fill(9));
    const caveats = [{ type: 'allow', verbs: ['*'] }] as never;
    const forged = mintRoot({ principalSecret: atk.secretKey, principalPublic: victim.b64, holder: atk.b64, caveats, suite: { alg: 'ml-dsa-65', mlDsa: aMl } });
    const genuine = mintRoot({ principalSecret: victim.secretKey, principalPublic: victim.b64, holder: atk.b64, caveats, suite: { alg: 'ml-dsa-65', mlDsa: vMl } });
    const pins = { [victim.b64]: encodeMlDsaPublicKey(vMl.publicKey) };
    expect(verifyGnapToken(encodeBoundToken([genuine]), { expectedRootIssuer: victim.b64 }).ok).toBe(false);
    expect(verifyGnapToken(encodeBoundToken([genuine]), { expectedRootIssuer: victim.b64, pqPins: pins }).ok).toBe(true);
    expect(verifyGnapToken(encodeBoundToken([forged]), { expectedRootIssuer: victim.b64, pqPins: pins }).ok).toBe(false);
  });
});

describe('capabilityToGrantResponse', () => {
  const p = kp();
  const a = kp();
  const { chain } = grantRequestToCapability(req(a.publicKey, [R]), { issuerSecret: p.secretKey, issuerPublic: p.b64 });
  it('guards', () => {
    expect(() => capabilityToGrantResponse([])).toThrow(new GnapError('capabilityToGrantResponse: empty chain'));
    expect(() => capabilityToGrantResponse(null as never)).toThrow('empty chain');
  });
  it('minimal, bound by default', () => {
    expect(capabilityToGrantResponse(chain)).toStrictEqual({
      access_token: { value: encodeBoundToken(chain), access: [R], key: holderJwk(a.b64) },
    });
  });
  it('options', () => {
    const cont = { uri: 'u', access_token: { value: 'v' } };
    expect(capabilityToGrantResponse(chain, { bearer: true, expiresIn: 0, manageUri: 'm', continue: cont, instanceId: 'i' })).toStrictEqual({
      access_token: { value: encodeBoundToken(chain), access: [R], key: false, expires_in: 0, manage: { uri: 'm' } },
      continue: cont,
      instance_id: 'i',
    });
    expect(capabilityToGrantResponse(chain, { bearer: false }).access_token!.key).toStrictEqual(holderJwk(a.b64));
    expect(capabilityToGrantResponse(chain, { bearer: 1 as never }).access_token!.key).toStrictEqual(holderJwk(a.b64));
  });
  it('key is the LEAF holder', () => {
    const b = kp();
    const hop = grantRequestToCapability(req(b.publicKey, [R]), { issuerSecret: a.secretKey, issuerPublic: a.b64, parent: chain[0]!, issuerChain: chain });
    expect(capabilityToGrantResponse(hop.chain).access_token!.key).toStrictEqual(holderJwk(b.b64));
  });
});

describe('gnapRequestRequiresStepUp', () => {
  const p = kp();
  const a = kp();
  const { chain: issuerChain } = grantRequestToCapability(req(a.publicKey, [R]), { issuerSecret: p.secretKey, issuerPublic: p.b64 });
  const mk = (access: unknown[], interact?: GnapGrantRequest['interact']) => req(kp().publicKey, access, interact);

  it('nothing required', () => {
    expect(gnapRequestRequiresStepUp(mk([R]), { issuerChain })).toStrictEqual({ required: false, reason: 'no step-up required', beyond: [], tier: 2 });
    // without an issuer chain the access list is not even examined
    expect(gnapRequestRequiresStepUp(mk([{ type: '' }]))).toStrictEqual({ required: false, reason: 'no step-up required', beyond: [], tier: 2 });
    expect(gnapRequestRequiresStepUp(mk([R]), { tier: 1 as never })).toStrictEqual({ required: false, reason: 'no step-up required', beyond: [], tier: 1 });
  });
  it('beyond the issuer', () => {
    const w = { type: 'repo', actions: ['write'], locations: ['main'] };
    const x = { type: 'zzz' };
    const r = gnapRequestRequiresStepUp(mk([R, w, x]), { issuerChain });
    expect(r).toStrictEqual({ required: true, reason: "requested rights exceed the issuer's authority (2 right(s) beyond)", beyond: [w, x], tier: 3 });
    expect(gnapRequestRequiresStepUp(mk([w]), { issuerChain, tier: 2 }).tier).toBe(2);
    expect(gnapRequestRequiresStepUp(mk([w]), { issuerChain }).reason).toBe("requested rights exceed the issuer's authority (1 right(s) beyond)");
    // beyond wins over interaction in the reason
    expect(gnapRequestRequiresStepUp(mk([w], { start: ['redirect'] }), { issuerChain }).reason).toContain('exceed');
    // malformed access with a chain throws
    expect(() => gnapRequestRequiresStepUp(mk([{ type: '' }]), { issuerChain })).toThrow('malformed access item');
    expect(() => gnapRequestRequiresStepUp({ ...mk([R]), access_token: null as never }, { issuerChain })).toThrow('access_token.access');
  });
  it('interaction', () => {
    expect(gnapRequestRequiresStepUp(mk([R], { start: ['redirect'] }))).toStrictEqual({ required: true, reason: 'GNAP interaction requested', beyond: [], tier: 2 });
    expect(gnapRequestRequiresStepUp(mk([R], { start: [] })).required).toBe(false);
    expect(gnapRequestRequiresStepUp(mk([R], { start: 'redirect' as never })).required).toBe(false);
    expect(gnapRequestRequiresStepUp(mk([R], { start: ['redirect'] }), { tier: 3 })).toMatchObject({ reason: 'GNAP interaction requested', tier: 3 });
  });
  it('explicit tier', () => {
    expect(gnapRequestRequiresStepUp(mk([R]), { tier: 2 })).toStrictEqual({ required: true, reason: 'tier 2 step-up required', beyond: [], tier: 2 });
    expect(gnapRequestRequiresStepUp(mk([R]), { tier: 3 })).toStrictEqual({ required: true, reason: 'tier 3 step-up required', beyond: [], tier: 3 });
  });
});

describe('continuation', () => {
  const principal = kp();
  const agent = kp();
  const guardian = kp();
  const signerSet: Signer[] = [
    { role: 'agent', publicKey: agent.b64 },
    { role: 'guardian', publicKey: guardian.b64 },
    { role: 'principal', publicKey: principal.b64 },
  ];
  const { grant, chain } = grantRequestToCapability(req(agent.publicKey, [{ type: 'payments', actions: ['transfer'], locations: ['acct'] }]), {
    issuerSecret: principal.secretKey,
    issuerPublic: principal.b64,
  });
  const plan = [{ id: 'n1', verb: 'transfer', resource: gnapActionResource('payments', 'acct') }];

  it('beginGnapContinuation shapes', () => {
    const r = beginGnapContinuation({ signerSet, t: 2, tier: 3, continueUri: 'u', continueToken: 'tok' });
    expect(r).toStrictEqual({
      response: { continue: { uri: 'u', access_token: { value: 'tok', bound: true } } },
      stepUp: { tier: 3, t: 2, signerSet, reason: 'tier 3 co-signature required to continue', continueToken: 'tok' },
    });
    const w = beginGnapContinuation({ signerSet, t: 1, tier: 2, continueUri: 'u', continueToken: 'tok', wait: 0, reason: 'why' });
    expect(w.response.continue).toStrictEqual({ uri: 'u', access_token: { value: 'tok', bound: true }, wait: 0 });
    expect(w.stepUp.reason).toBe('why');
    expect(w.stepUp.signerSet).toBe(signerSet);
  });

  it('gnapStepUpShare signs the threshold message bound to signerSet and t', () => {
    const pc = buildPCActn({ grant, chain, plan, nodeId: 'n1', counter: 0, signerSecret: agent.secretKey, aud: 'rs' });
    const msg = thresholdMessage(pc);
    const s = gnapStepUpShare(pc, 'guardian', guardian.secretKey, signerSet, 2);
    expect(s).toStrictEqual(signShare('guardian', guardian.secretKey, msg, { signerSet, t: 2 }));
    expect(s.role).toBe('guardian');
    expect(gnapStepUpShare(pc, 'guardian', guardian.secretKey, signerSet, 3).sig).not.toBe(s.sig);
    expect(gnapStepUpShare(pc, 'principal', guardian.secretKey, signerSet, 2).sig).not.toBe(s.sig);
    expect(gnapStepUpShare(pc, 'guardian', guardian.secretKey, signerSet.slice(0, 2), 2).sig).not.toBe(s.sig);
  });

  it('completeGnapContinuation: guards, pass-through fields, verdicts', () => {
    expect(() => completeGnapContinuation({ grant, chain: [], plan, nodeId: 'n1', counter: 0, aud: 'rs', agentLeafSecret: agent.secretKey, signerSet, t: 2, cosignSecrets: [] })).toThrow(
      new GnapError('completeGnapContinuation: empty chain'),
    );
    expect(() => completeGnapContinuation({ grant, chain: null as never, plan, nodeId: 'n1', counter: 0, aud: 'rs', agentLeafSecret: agent.secretKey, signerSet, t: 2, cosignSecrets: [] })).toThrow('empty chain');
    const base = { grant, chain, plan, nodeId: 'n1', counter: 4, aud: 'rs-aud', agentLeafSecret: agent.secretKey, signerSet, t: 2 as const };
    const done = completeGnapContinuation({ ...base, now: 1_700_000_000_000, ttlMs: 5000, params: { a: 1 }, cosignSecrets: [{ role: 'guardian', secret: guardian.secretKey }] });
    expect(done.verdict.ok).toBe(true);
    expect(done.pcactn.threshold).toBe(done.threshold);
    expect(done.threshold.shares.map((s) => s.role)).toEqual(['agent', 'guardian']);
    expect(done.pcactn.iat).toBe(1_700_000_000_000);
    expect(done.pcactn.exp).toBe(1_700_000_005_000);
    expect(done.pcactn.aud).toBe('rs-aud');
    expect(done.pcactn.counter).toBe(4);
    expect(done.pcactn.action.verb).toBe('transfer');
    expect(done.pcactn.action.params_digest).not.toBe(buildPCActn({ ...base, grant, signerSecret: agent.secretKey, plan }).action.params_digest);
    // no optional fields: iat defaults to the clock
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(42_000);
    const d2 = completeGnapContinuation({ ...base, cosignSecrets: [] });
    expect(d2.pcactn.iat).toBe(42_000);
    expect(d2.verdict.ok).toBe(false);
    // t=3 with two shares fails; with all three passes
    const three = { ...base, t: 3 as const };
    expect(completeGnapContinuation({ ...three, cosignSecrets: [{ role: 'guardian', secret: guardian.secretKey }] }).verdict.ok).toBe(false);
    expect(
      completeGnapContinuation({ ...three, cosignSecrets: [{ role: 'guardian', secret: guardian.secretKey }, { role: 'principal', secret: principal.secretKey }] }).verdict.ok,
    ).toBe(true);
    // a co-signature by the wrong key for its role does not count
    expect(completeGnapContinuation({ ...base, cosignSecrets: [{ role: 'guardian', secret: kp().secretKey }] }).verdict.ok).toBe(false);
  });
});

// ---- jwsd -----------------------------------------------------------------------------------

describe('signGnapRequest', () => {
  const c = kp();
  const body = { b: 2, a: [1, { z: 1, y: undefined }] };
  it('header, holder and detached form', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(1_700_000_123_999);
    const s = await signGnapRequest({ body, key: c, htm: 'post', uri: 'https://as/tx' });
    expect(s.holder).toBe(c.b64);
    expect(s.header).toStrictEqual({ alg: 'EdDSA', typ: 'gnap-binding-jwsd', htm: 'POST', uri: 'https://as/tx', created: 1_700_000_123 });
    const [h, mid, sig] = s.detachedJws.split('.');
    expect(mid).toBe('');
    expect(sig!.length).toBeGreaterThan(80);
    expect(JSON.parse(Buffer.from(h!, 'base64url').toString())).toStrictEqual(s.header);
  });
  it('kid, ath and created are included when given', async () => {
    const s = await signGnapRequest({ body, key: c, htm: 'GET', uri: 'u', created: 0, kid: 'k1', accessTokenValue: 'tok' });
    expect(s.header).toStrictEqual({ alg: 'EdDSA', typ: 'gnap-binding-jwsd', htm: 'GET', uri: 'u', created: 0, kid: 'k1', ath: b64u(sha256(utf8('tok'))) });
    const prot = JSON.parse(Buffer.from(s.detachedJws.split('.')[0]!, 'base64url').toString());
    expect(prot).toStrictEqual(s.header);
    const empty = await signGnapRequest({ body, key: c, htm: 'GET', uri: 'u', created: 1, accessTokenValue: '' });
    expect(empty.header.ath).toBe(b64u(sha256(new Uint8Array(0))));
    expect(Object.keys((await signGnapRequest({ body, key: c, htm: 'GET', uri: 'u', created: 1 })).header)).not.toContain('kid');
  });
  it('the signature covers the canonical body (key order and undefined are irrelevant)', async () => {
    const s = await signGnapRequest({ body, key: c, htm: 'POST', uri: 'u', created: 1000 });
    const reordered = { a: [1, { z: 1 }], b: 2 };
    expect((await verifyGnapRequest({ detachedJws: s.detachedJws, body: reordered, holder: c.b64, htm: 'POST', uri: 'u', now: 1_000_000 })).ok).toBe(true);
    expect((await verifyGnapRequest({ detachedJws: s.detachedJws, body: { ...reordered, b: 3 }, holder: c.b64, htm: 'POST', uri: 'u', now: 1_000_000 })).ok).toBe(false);
  });
});

describe('verifyGnapRequest', () => {
  const c = kp();
  const body = { x: 1 };
  const NOW = 1_700_000_000;
  const base = { body, holder: c.b64, htm: 'POST', uri: 'https://as/tx', now: NOW * 1000 };
  /** The denial reason, or 'OK' for an accept (so an unexpected accept fails the reason assertion). */
  const reasonOf = (r: VerifyGnapRequestResult): string => (r.ok ? 'OK' : r.reason);

  /** Forge a detached JWS with an arbitrary protected header. */
  async function forge(header: Record<string, unknown>, forBody: unknown = body, key = c) {
    const k = await importJWK({ kty: 'OKP', crv: 'Ed25519', x: key.b64, d: b64u(key.secretKey) }, 'EdDSA');
    const payload = utf8(canonicalizeStrict(JSON.parse(JSON.stringify(forBody))));
    const jws = await new FlattenedSign(payload).setProtectedHeader(header as never).sign(k);
    return `${jws.protected}..${jws.signature}`;
  }
  const H = (o: Record<string, unknown> = {}) => ({ alg: 'EdDSA', typ: 'gnap-binding-jwsd', htm: 'POST', uri: 'https://as/tx', created: NOW, ...o });
  const check = async (jws: string, o: Record<string, unknown> = {}) => verifyGnapRequest({ ...base, detachedJws: jws, ...o });

  it('happy path returns holder and the normalised header', async () => {
    const r = await check(await forge(H({ kid: 'kk', ath: 'aa', extra: 1 })));
    expect(r).toStrictEqual({ ok: true, holder: c.b64, header: { alg: 'EdDSA', typ: 'gnap-binding-jwsd', htm: 'POST', uri: 'https://as/tx', created: NOW, kid: 'kk', ath: 'aa' } });
    const r2 = await check(await forge(H()));
    expect(r2).toStrictEqual({ ok: true, holder: c.b64, header: { alg: 'EdDSA', typ: 'gnap-binding-jwsd', htm: 'POST', uri: 'https://as/tx', created: NOW } });
    // non-string kid / ath are dropped
    const r3 = await check(await forge(H({ kid: 5, ath: 7 })));
    expect(r3).toStrictEqual(r2);
  });
  it('structure', async () => {
    expect(reasonOf(await check('a.b'))).toBe('not a compact JWS (expected three dot-separated parts)');
    expect(reasonOf(await check('a.b.c.d'))).toBe('not a compact JWS (expected three dot-separated parts)');
    expect(reasonOf(await check(''))).toBe('not a compact JWS (expected three dot-separated parts)');
    expect(reasonOf(await check('a.b.c'))).toBe('not a DETACHED compact JWS');
    expect(reasonOf(await check(null as never))).toBe('malformed jwsd request');
  });
  it('holder must be canonical', async () => {
    const j = await forge(H());
    for (const h of ['', 'abc', c.b64 + '=', b64u(new Uint8Array(31)), 5 as never, undefined as never]) {
      expect(reasonOf(await check(j, { holder: h }))).toBe('holder is not a canonical base64url Ed25519 public key');
    }
  });
  it('holder check happens before signature verification', async () => {
    expect(reasonOf(await check('a..b', { holder: 'bad' }))).toBe('holder is not a canonical base64url Ed25519 public key');
  });
  it('non-canonical spelling is refused with a prefixed reason', async () => {
    const j = await forge(H());
    const [h, , s] = j.split('.');
    expect(reasonOf(await check(`${h}..${s}=`))).toMatch(/^non-canonical detached JWS: .+/);
  });
  it('signature / body / holder binding', async () => {
    const sigMsg = 'jwsd signature does not verify under the holder key (or body was tampered)';
    const j = await forge(H());
    expect(reasonOf(await check(j, { body: { x: 2 } }))).toBe(sigMsg);
    expect(reasonOf(await check(j, { holder: kp().b64 }))).toBe(sigMsg);
    expect(reasonOf(await check(await forge(H(), body, kp())))).toBe(sigMsg);
  });
  it('typ / alg', async () => {
    expect(reasonOf(await check(await forge(H({ typ: 'JWT' }))))).toBe('unexpected typ (not gnap-binding-jwsd)');
    const { typ: _t, ...noTyp } = H();
    void _t;
    expect(reasonOf(await check(await forge(noTyp)))).toBe('unexpected typ (not gnap-binding-jwsd)');
  });
  it('htm', async () => {
    expect(reasonOf(await check(await forge(H({ htm: 'GET' }))))).toBe('htm does not match the request method');
    expect(reasonOf(await check(await forge(H({ htm: 5 }))))).toBe('htm does not match the request method');
    const { htm: _h, ...noHtm } = H();
    void _h;
    expect(reasonOf(await check(await forge(noHtm)))).toBe('htm does not match the request method');
    // case-insensitive both ways, and the header's own spelling is returned
    const lower = await check(await forge(H({ htm: 'post' })));
    expect(lower.ok && lower.header.htm).toBe('post');
    expect((await check(await forge(H()), { htm: 'post' })).ok).toBe(true);
  });
  it('uri', async () => {
    expect(reasonOf(await check(await forge(H({ uri: 'https://as/other' }))))).toBe('uri does not match the request target');
    expect(reasonOf(await check(await forge(H({ uri: 5 }))))).toBe('uri does not match the request target');
    expect(reasonOf(await check(await forge(H({ uri: 'HTTPS://AS/TX' }))))).toBe('uri does not match the request target');
    const { uri: _u, ...noUri } = H();
    void _u;
    expect(reasonOf(await check(await forge(noUri)))).toBe('uri does not match the request target');
  });
  it('created', async () => {
    for (const created of [undefined, 'x', null, true]) {
      expect(reasonOf(await check(await forge(H({ created }))))).toBe('missing or malformed created');
    }
    // htm is checked before uri before created
    expect(reasonOf(await check(await forge(H({ htm: 'GET', uri: 'x', created: 'x' }))))).toBe('htm does not match the request method');
    expect(reasonOf(await check(await forge(H({ uri: 'x', created: 'x' }))))).toBe('uri does not match the request target');
  });
  it('future boundary: up to 60 s ahead is fine', async () => {
    expect((await check(await forge(H({ created: NOW + 60 })))).ok).toBe(true);
    expect(reasonOf(await check(await forge(H({ created: NOW + 61 }))))).toBe('created is in the future');
    // now is floored to seconds
    expect((await check(await forge(H({ created: NOW + 60 })), { now: NOW * 1000 + 999 })).ok).toBe(true);
    expect(reasonOf(await check(await forge(H({ created: NOW + 61 })), { now: NOW * 1000 + 999 }))).toBe('created is in the future');
  });
  it('staleness boundary: default 300 s, configurable', async () => {
    expect((await check(await forge(H({ created: NOW - 300 })))).ok).toBe(true);
    expect(reasonOf(await check(await forge(H({ created: NOW - 301 }))))).toBe('jwsd proof is stale');
    expect((await check(await forge(H({ created: NOW - 10 })), { maxAgeSec: 10 })).ok).toBe(true);
    expect(reasonOf(await check(await forge(H({ created: NOW - 11 })), { maxAgeSec: 10 }))).toBe('jwsd proof is stale');
    expect((await check(await forge(H({ created: NOW - 301 })), { maxAgeSec: 301 })).ok).toBe(true);
    expect(reasonOf(await check(await forge(H({ created: NOW - 1 })), { maxAgeSec: 0 }))).toBe('jwsd proof is stale');
    expect((await check(await forge(H({ created: NOW })), { maxAgeSec: 0 })).ok).toBe(true);
  });
  it('default clock', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW * 1000);
    const { now: _n, ...noNow } = base;
    void _n;
    expect((await verifyGnapRequest({ ...noNow, detachedJws: await forge(H()) })).ok).toBe(true);
    expect((await verifyGnapRequest({ ...noNow, detachedJws: await forge(H({ created: NOW - 400 })) })).ok).toBe(false);
  });
  it('ath binding', async () => {
    const ath = b64u(sha256(utf8('tok')));
    const msg = 'ath does not bind the named access token';
    expect((await check(await forge(H({ ath })), { accessTokenValue: 'tok' })).ok).toBe(true);
    expect(reasonOf(await check(await forge(H({ ath })), { accessTokenValue: 'other' }))).toBe(msg);
    expect(reasonOf(await check(await forge(H()), { accessTokenValue: 'tok' }))).toBe(msg);
    expect(reasonOf(await check(await forge(H({ ath: 5 })), { accessTokenValue: 'tok' }))).toBe(msg);
    // empty access token value is still "named"
    expect(reasonOf(await check(await forge(H()), { accessTokenValue: '' }))).toBe(msg);
    // an ath in the proof is not enforced when no token is named, but is reported
    const r = await check(await forge(H({ ath: 'whatever' })));
    expect(r.ok && r.header.ath).toBe('whatever');
  });
});

describe('profile spec', () => {
  it('is exactly the documented object', () => {
    expect(AGENT_GNAP_PROFILE.name).toBe('agent-gnap');
    expect(AGENT_GNAP_PROFILE.version).toBe('1.0');
    expect(AGENT_GNAP_PROFILE.rfc).toBe('RFC 9635');
    expect(AGENT_GNAP_PROFILE.proofMethods).toStrictEqual(['jwsd']);
    expect(AGENT_GNAP_PROFILE.mapping).toHaveLength(10);
    for (const m of AGENT_GNAP_PROFILE.mapping) {
      expect(m.gnap.length).toBeGreaterThan(0);
      expect(m.pca.length).toBeGreaterThan(0);
      expect(m.note.length).toBeGreaterThan(0);
    }
    expect(AGENT_GNAP_PROFILE.security).toHaveLength(5);
    expect(AGENT_GNAP_PROFILE.summary).toContain('attenuated, key-bound PCA capability');
    expect(AGENT_GNAP_PROFILE.multiHop).toContain('gnap_access caveat');
    expect(AGENT_GNAP_PROFILE.stepUp).toContain('GNAP continue');
    expect(GNAP_GRANT_CAVEAT).toBe('gnap_grant');
    expect(GNAP_ACCESS_CAVEAT).toBe('gnap_access');
  });
});

describe('round-2 kills', () => {
  const p = kp();
  const a = kp();
  const b = kp();

  it('chain-invalid reasons carry the verifier reason verbatim', () => {
    const { chain } = grantRequestToCapability(req(a.publicKey, [R]), { issuerSecret: p.secretKey, issuerPublic: p.b64 });
    const wrong = kp().b64;
    const why = verifyChain(chain, wrong).reason!;
    expect(verifyGnapToken(encodeBoundToken(chain), { expectedRootIssuer: wrong })).toStrictEqual({ ok: false, reason: `capability chain invalid: ${why}` });
    expect(authorizeGnapAction(chain, { verb: 'read', resource: RES }, { expectedRootIssuer: wrong })).toStrictEqual({ allowed: false, reason: `capability chain invalid: ${why}` });
    const tampered = [{ ...chain[0]!, holder: kp().b64 }];
    const why2 = verifyChain(tampered).reason!;
    expect(verifyGnapToken(encodeBoundToken(tampered))).toStrictEqual({ ok: false, reason: `capability chain invalid: ${why2}` });
  });

  it('root gnap_grant lookup skips other caveats and tolerates null entries', () => {
    const decoy = { type: 'decoy', client_id: 'x', request_digest: 'd', granted_access: [RW] };
    const real = { type: GNAP_GRANT_CAVEAT, client_id: a.b64, request_digest: 'd', granted_access: [R] };
    const g = mintGrant({
      principalSecret: p.secretKey, principalPublic: p.b64, holder: a.b64, goal: 'g',
      envelope: { predicates: [], caveats: [null as never, decoy as never, real as never], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
    }).grant;
    expect(grantedAccessOf([g])).toStrictEqual([R]);
  });

  it('leaf caveat scan: index 0 counts, null entries are skipped', () => {
    const { grant } = grantRequestToCapability(req(a.publicKey, [RW]), { issuerSecret: p.secretKey, issuerPublic: p.b64 });
    const only0 = { ...grant, caveats: [{ type: GNAP_ACCESS_CAVEAT, access: [R] }] } as unknown as Capability;
    expect(grantedAccessOf([grant, only0])).toStrictEqual([R]);
    const withNull = { ...grant, caveats: [{ type: GNAP_ACCESS_CAVEAT, access: [R] }, null] } as unknown as Capability;
    expect(grantedAccessOf([grant, withNull])).toStrictEqual([R]);
  });

  it('a null caveat can never reach the leaf scan of a chain that verifies', () => {
    const { grant } = grantRequestToCapability(req(a.publicKey, [R]), { issuerSecret: p.secretKey, issuerPublic: p.b64 });
    let verifies = false;
    try {
      verifies = verifyChain([grant, delegate(grant, b.b64, [null as never], a.secretKey)]).ok;
    } catch {
      verifies = false; // refused at mint time
    }
    expect(verifies).toBe(false);
  });

  it('a bound token whose bytes are not valid UTF-8 is undecodable even if the lossy text would parse', () => {
    const { chain } = grantRequestToCapability(req(a.publicKey, [R]), { issuerSecret: p.secretKey, issuerPublic: p.b64 });
    const text = Buffer.from(JSON.stringify(chain), 'utf8');
    const at = text.indexOf(Buffer.from('"id":"')) + 6;
    const bad = Buffer.concat([text.subarray(0, at), Buffer.from([0xff]), text.subarray(at + 1)]);
    expect(verifyGnapToken(b64u(bad))).toStrictEqual({ ok: false, reason: 'token is not a decodable PCA capability chain' });
  });

  it('the jwsd uri comparison is strict even for non-string values', async () => {
    const c = kp();
    const body = { x: 1 };
    const k = await importJWK({ kty: 'OKP', crv: 'Ed25519', x: c.b64, d: b64u(c.secretKey) }, 'EdDSA');
    const jws = await new FlattenedSign(utf8(canonicalizeStrict(body))).setProtectedHeader({ alg: 'EdDSA', typ: 'gnap-binding-jwsd', htm: 'POST', uri: 5, created: 1000 } as never).sign(k);
    const r = await verifyGnapRequest({ detachedJws: `${jws.protected}..${jws.signature}`, body, holder: c.b64, htm: 'POST', uri: 5 as never, now: 1_000_000 });
    expect(r).toStrictEqual({ ok: false, reason: 'uri does not match the request target' });
  });

  it('the request digest is domain-separated and binds holder, granted access and interact', () => {
    const inter = { start: ['redirect'] };
    const out = grantRequestToCapability(req(a.publicKey, [R], inter), { issuerSecret: p.secretKey, issuerPublic: p.b64, now: 1 });
    expect((out.provenance as { request_digest: string }).request_digest).toBe(
      hashCanonical({ d: 'atlas-pca/gnap/request/v1', client_id: a.b64, access: [R], interact: inter }),
    );
    const none = grantRequestToCapability(req(a.publicKey, [R]), { issuerSecret: p.secretKey, issuerPublic: p.b64, now: 1 });
    expect((none.provenance as { request_digest: string }).request_digest).toBe(
      hashCanonical({ d: 'atlas-pca/gnap/request/v1', client_id: a.b64, access: [R], interact: null }),
    );
  });
});
