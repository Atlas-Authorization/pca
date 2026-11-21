// Oracle: @atlasauth/pca-idjag (ID-JAG verification over a local JWK Set, the principal / root-capability projection, the XAA request
// builders). Deterministic (Ed25519 from fixed seeds, far-future exp, past iat). Writes out/ref-idjag-java.json.gz.
//
// PORTING (fn(args) -> native entry point, comparison rule):
//   verifyIdJag(token, opts)      -> verifyIdJag; opts.jwks (a JWK Set) = the local JWK Set key resolver; opts.consume (absent | 'fresh' |
//                                    'seen' | 'throws' | 'truthy') = the consumeJti store (fresh: true, seen: false, throws: throws,
//                                    truthy: returns the non-boolean 1). Result {ok:true, grant, consumed:[[jti, exp]...]} or
//                                    {ok:false, code, consumed}: code = the IdJagVerificationError code (native: any other failure 'other').
//   idJagToPcaPrincipal(grant, opts?) -> idJagToPcaPrincipal (JSON compare; a throw requires a throw)
//   idJagToCapability(grant, opts)    -> idJagToCapability; opts.principalSecretLabel names the Ed25519 seed (sha256 of
//                                    "atlas-pca-conformance/<label>") the native derives the same way; the rest as the TS option names
//   isIdJagAuthorityCaveat / isIdJagProvenanceCaveat(cv), readIdJagAuthority / readIdJagProvenance(cap) -> same names
//   tokenExchangeRequest(opts), jwtBearerAssertion(opts) -> same names (JSON compare of the whole request)
import { createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';
import { createLocalJWKSet } from 'jose';
import * as M0 from '@atlasauth/pca-idjag';
import { Oracle, seed, refWrite } from './lib.mjs';

const M: any = (M0 as any).default ?? M0;
const o = new Oracle('idjag-java', 'tools/pca-audit/oracles/idjag-java.mts', 'TS-reference oracle for ID-JAG verification, projection and request builders.');

const b64u = (b: Uint8Array | Buffer | string) => Buffer.from(b as any).toString('base64url');
const PKCS8_ED = Buffer.from('302e020100300506032b657004220420', 'hex');
const priv = (l: string) => createPrivateKey({ key: Buffer.concat([PKCS8_ED, Buffer.from(seed(l))]), format: 'der', type: 'pkcs8' });
const edPriv = priv('idjag/ed');
const edJwk = { ...createPublicKey(edPriv).export({ format: 'jwk' }), kid: 'ed1' } as any;
const edPriv2 = priv('idjag/ed2');
const mk = (header: any, payload: any, k = edPriv) => {
  const h = b64u(JSON.stringify(header)), p = b64u(JSON.stringify(payload));
  return `${h}.${p}.${b64u(nodeSign(null, Buffer.from(`${h}.${p}`), k))}`;
};

const ISS = 'https://idp.example.com';
const AUD = 'https://rs.example.com';
const CLIENT = 'agent-app';
const HDR = { alg: 'EdDSA', typ: 'oauth-id-jag+jwt', kid: 'ed1' };
const PRINCIPAL_LABEL = 'idjag/principal';
const principalPub = createPublicKey(priv(PRINCIPAL_LABEL)).export({ format: 'jwk' }).x as string;
const CLAIMS: any = { iss: ISS, sub: 'alice', aud: AUD, iat: 1_700_000_000, exp: 4_000_000_000, jti: 'jti-1', client_id: CLIENT, act: { sub: 'agent-1', extra: 1 }, scope: 'read write', nonce: 'n1' };
const JWKS = { keys: [edJwk] };
const OPTS = { issuer: ISS, audience: AUD, clientId: CLIENT, jwks: JWKS, consume: 'fresh' };
const HOST: any[] = [null, true, false, 0, -1, 1.5, '', 'x', ' ', [], ['x'], {}, { x: 1 }];

const verify = async (token: any, opts: any) => {
  const consumed: any[] = [];
  try {
    if (opts === null) return { ok: true, grant: await M.verifyIdJag(token, null), consumed };
    const { jwks, consume, ...rest } = opts;
    const consumeJti = consume === undefined ? undefined : async (jti: string, exp: number) => {
      consumed.push([jti, exp]);
      if (consume === 'throws') throw new Error('store down');
      if (consume === 'seen') return false;
      if (consume === 'truthy') return 1 as any;
      return true;
    };
    const grant = await M.verifyIdJag(token, { ...rest, ...(jwks !== undefined ? { key: createLocalJWKSet(jwks) } : {}), ...(consumeJti ? { consumeJti } : {}) });
    return { ok: true, grant, consumed };
  } catch (e: any) {
    return { ok: false, code: e?.code ?? 'other', consumed };
  }
};
let n = 0;
const V = (label: string, token: any, opts: any = OPTS) => o.run('verifyIdJag', `${label}#${n++}`, verify, [token, opts]);

const tok = mk(HDR, CLAIMS);
await V('ok', tok);
await V('ok no nonce', tok, { ...OPTS, nonce: undefined });
for (const k of Object.keys(CLAIMS)) {
  const del = { ...CLAIMS }; delete del[k];
  await V(`claim ${k} deleted`, mk(HDR, del));
  for (const [i, h] of HOST.entries()) await V(`claim ${k} = host${i}`, mk(HDR, { ...CLAIMS, [k]: h }));
}
for (const [label, c] of Object.entries({
  'aud array one': { aud: [AUD] }, 'aud array two': { aud: [AUD, 'other'], azp: CLIENT }, 'aud other': { aud: 'https://other' }, 'scope array': { scope: ['a', 'b', '', 5] }, 'scope spaces': { scope: '  a \t b\n' },
  'scope empty': { scope: '' }, 'scopes array': { scope: undefined, scopes: ['r', 'w', 3] }, 'scope number + scopes': { scope: 5, scopes: ['r'] }, 'scope nbsp': { scope: 'a b' },
  'act extra': { act: { sub: 'a', nested: { sub: 'x' } } }, 'act array': { act: [] }, 'act empty sub': { act: { sub: '' } }, 'act null': { act: null },
  expired: { exp: 1 }, 'nbf future': { nbf: 4_000_000_000 }, 'cnf': { cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: edJwk.x } } }, 'extra': { foo: [1] },
} as Record<string, any>)) await V(`claims ${label}`, mk(HDR, { ...CLAIMS, ...c }));
for (const [label, h] of Object.entries({ 'typ missing': { alg: 'EdDSA', kid: 'ed1' }, 'typ JWT': { alg: 'EdDSA', typ: 'JWT', kid: 'ed1' }, 'typ upper': { ...HDR, typ: 'OAUTH-ID-JAG+JWT' }, 'typ app': { ...HDR, typ: 'application/oauth-id-jag+jwt' }, 'typ number': { ...HDR, typ: 5 }, 'alg none': { alg: 'none', typ: HDR.typ }, 'alg HS256': { ...HDR, alg: 'HS256' }, 'kid unknown': { ...HDR, kid: 'zz' } } as Record<string, any>)) {
  await V(`header ${label}`, mk(h, CLAIMS));
  await V(`header ${label} loose`, mk(h, CLAIMS), { ...OPTS, strictDraft: false, consume: undefined, clientId: undefined });
}
await V('signed by other key', mk(HDR, CLAIMS, edPriv2));
const [th, tp, ts] = tok.split('.');
for (const [label, t] of Object.entries({ empty: '', 'sig flipped': `${th}.${tp}.${ts.slice(0, -2)}${ts.at(-2) === 'A' ? 'B' : 'A'}${ts.at(-1)}`, two: `${th}.${tp}`, 'too long': 'a'.repeat(16385), 'at limit non-jwt': 'a'.repeat(16384), padded: `${th}=.${tp}.${ts}` } as Record<string, string>)) await V(`token ${label}`, t);
await o.run('verifyIdJag', 'token number', verify, [5, OPTS]);
const OV: Record<string, any> = {
  'strict default no consume': { consume: undefined }, 'strict false': { strictDraft: false, consume: undefined, clientId: undefined }, 'strict false with consume': { strictDraft: false, consume: 'fresh' }, 'strict true': { strictDraft: true },
  'no clientId': { clientId: undefined }, 'empty clientId': { clientId: '' }, 'wrong clientId': { clientId: 'other' }, 'consume seen': { consume: 'seen' }, 'consume throws': { consume: 'throws' }, 'consume truthy': { consume: 'truthy' },
  'issuer other': { issuer: 'https://evil' }, 'issuer empty': { issuer: '' }, 'issuer absent': { issuer: undefined }, 'audience other': { audience: 'https://other' }, 'audience empty': { audience: '' }, 'audience absent': { audience: undefined }, 'audience array': { audience: [AUD] },
  'required ok': { requiredScopes: ['read'] }, 'required both': { requiredScopes: ['read', 'write'] }, 'required missing': { requiredScopes: ['admin'] }, 'required empty': { requiredScopes: [] }, 'required not array': { requiredScopes: 'read' },
  'nonce wrong': { nonce: 'zz' }, 'tol': { clockToleranceSec: 5 }, 'age': { maxTokenAgeSec: 1 }, 'algs es': { algorithms: ['ES256'] }, 'algs ed': { algorithms: ['EdDSA'] },
  'no key': { jwks: undefined }, 'jwks other kid': { jwks: { keys: [{ ...edJwk, kid: 'q' }] } },
};
for (const [label, ov] of Object.entries(OV)) await V(`opts ${label}`, tok, { ...OPTS, ...ov });
await V('opts null', tok, null);

// ---- projection
const g = async (c: any, op: any = OPTS) => (await verify(mk(HDR, c), op) as any).grant;
const grants: any[] = [await g(CLAIMS), await g({ ...CLAIMS, jti: undefined }, { ...OPTS, strictDraft: false, consume: undefined }), await g({ ...CLAIMS, cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: edJwk.x } } }),
  await g({ ...CLAIMS, cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(Buffer.alloc(32, 9)) } } }), await g({ ...CLAIMS, scope: 'a b c' }), await g({ ...CLAIMS, email: 'a@x.example', email_verified: true, name: 'A', preferred_username: 'a', auth_time: 1_699_999_000 })];
const pops: any[] = [undefined, {}, { principalPublic: principalPub }, { principalPublic: edJwk.x }, { principalPublic: '' }, { principalPublic: 'zz' }];
for (const [i, gr] of [...grants, null, {}, { oidcClaims: {} }, { oidcClaims: { iss: 'a', sub: 'b' } }, 5].entries()) for (const [j, p] of pops.entries()) await o.run('idJagToPcaPrincipal', `g${i}p${j}`, M.idJagToPcaPrincipal, p === undefined ? [gr] : [gr, p]);

const HOLDER = createPublicKey(priv('idjag/holder')).export({ format: 'jwk' }).x as string;
const capw = (gr: any, op: any) => {
  const { principalSecretLabel, ...rest } = op ?? {};
  return M.idJagToCapability(gr, op === null ? null : { ...rest, ...(principalSecretLabel !== undefined ? { principalSecret: seed(principalSecretLabel) } : {}) });
};
const copts: any[] = [
  { principalSecretLabel: PRINCIPAL_LABEL, principalPublic: principalPub, holder: HOLDER },
  { principalSecretLabel: PRINCIPAL_LABEL, principalPublic: principalPub, holder: HOLDER, extraCaveats: [{ type: 'ttl', max_seconds: 60 }] },
  { principalSecretLabel: PRINCIPAL_LABEL, principalPublic: principalPub, holder: HOLDER, extraCaveats: [] },
  { principalSecretLabel: PRINCIPAL_LABEL, principalPublic: principalPub, holder: HOLDER, extraCaveats: 5 },
  { principalSecretLabel: PRINCIPAL_LABEL, principalPublic: principalPub, holder: HOLDER, extraCaveats: [{ type: 'x', n: 1.5 }] },
  { principalSecretLabel: PRINCIPAL_LABEL, principalPublic: principalPub, holder: '' }, { principalSecretLabel: PRINCIPAL_LABEL, principalPublic: principalPub },
  { principalSecretLabel: PRINCIPAL_LABEL, holder: HOLDER }, { principalSecretLabel: PRINCIPAL_LABEL, principalPublic: '', holder: HOLDER }, { principalPublic: principalPub, holder: HOLDER }, null,
];
for (const [i, gr] of [...grants, null].entries()) for (const [j, p] of copts.entries()) await o.run('idJagToCapability', `g${i}c${j}`, capw, [gr, p]);

const cavs: any[] = [
  { type: 'idjag_authority', scopes: ['a'], aud: 'x' }, { type: 'idjag_authority', scopes: [], aud: 'x' }, { type: 'idjag_authority', scopes: [1], aud: 'x' }, { type: 'idjag_authority', scopes: ['a'], aud: '' }, { type: 'idjag_authority', scopes: ['a'] }, { type: 'x', scopes: ['a'], aud: 'x' }, null, 'x', [], 5,
  { type: 'idjag_provenance', iss: 'a', sub: 'b', agent: 'c', aud: 'd', iat: 1, exp: 2 }, { type: 'idjag_provenance', iss: 'a', sub: 'b', agent: 'c', aud: 'd', iat: 1, exp: 2, jti: 'j' }, { type: 'idjag_provenance', iss: 'a', sub: 'b', agent: 'c', aud: 'd', iat: '1', exp: 2 },
  { type: 'idjag_provenance', iss: 'a', sub: 'b', agent: 'c', aud: 'd', iat: 1 }, { type: 'idjag_provenance', iss: 'a', sub: 'b', agent: 1, aud: 'd', iat: 1, exp: 2 }, { type: 'idjag_provenance', iss: '', sub: '', agent: '', aud: '', iat: 0, exp: 0 },
];
for (const [i, c] of cavs.entries()) { await o.run('isIdJagAuthorityCaveat', `c${i}`, M.isIdJagAuthorityCaveat, [c]); await o.run('isIdJagProvenanceCaveat', `c${i}`, M.isIdJagProvenanceCaveat, [c]); }
const caps: any[] = [{ caveats: [] }, { caveats: [cavs[0], cavs[10]] }, { caveats: [cavs[1], cavs[0]] }, { caveats: [cavs[2], cavs[0]] }, { caveats: [null, cavs[10]] }, { caveats: [cavs[11], cavs[10]] }, { caveats: [cavs[12]] }, {}, null, 5, { caveats: 'x' }, { caveats: [cavs[5], cavs[3]] }];
for (const [i, c] of caps.entries()) { await o.run('readIdJagAuthority', `c${i}`, M.readIdJagAuthority, [c]); await o.run('readIdJagProvenance', `c${i}`, M.readIdJagProvenance, [c]); }
const real = M.idJagToCapability(grants[0], { principalSecret: seed(PRINCIPAL_LABEL), principalPublic: principalPub, holder: HOLDER }).capability;
for (const [i, c] of [real, { ...real, caveats: [...real.caveats].reverse() }].entries()) { await o.run('readIdJagAuthority', `real${i}`, M.readIdJagAuthority, [c]); await o.run('readIdJagProvenance', `real${i}`, M.readIdJagProvenance, [c]); }

// ---- request builders
const te: any[] = [
  { tokenEndpoint: 'https://idp.example.com/token', subjectToken: 'st' },
  { tokenEndpoint: 'https://idp.example.com/token', subjectToken: 'st', subjectTokenType: 'urn:x', requestedTokenType: 'urn:y', audience: 'rs', resource: 'https://rs.example.com', scope: 'a b', clientId: 'c' },
  { tokenEndpoint: 'https://t', subjectToken: 'st', scope: ['a', 'b', '', 5], actorToken: 'at' }, { tokenEndpoint: 'https://t', subjectToken: 'st', actorToken: 'at', actorTokenType: 'urn:z' }, { tokenEndpoint: 'https://t', subjectToken: 'st', actorToken: '' },
  { tokenEndpoint: 'https://t', subjectToken: 'st', scope: '' }, { tokenEndpoint: 'https://t', subjectToken: 'st', scope: [] }, { tokenEndpoint: 'https://t', subjectToken: 'st', scope: '  a  b c ' }, { tokenEndpoint: 'https://t', subjectToken: 'st', scope: 5 },
  { tokenEndpoint: 'https://t', subjectToken: 'st', extra: { foo: 'bar', grant_type: 'override', n: 1, e: '', sp: 'a b&c=d' } }, { tokenEndpoint: 'https://t', subjectToken: 'st', audience: '', resource: '' },
  { tokenEndpoint: 'https://t', subjectToken: 'tok en+/=é~*()\'!', clientId: 'a b' }, { tokenEndpoint: 'https://t', subjectToken: 'st', extra: { 'k y': 'v&' } },
  { tokenEndpoint: '', subjectToken: 'st' }, { tokenEndpoint: 'https://t', subjectToken: '' }, { tokenEndpoint: 'https://t' }, { subjectToken: 'st' }, { tokenEndpoint: 5, subjectToken: 'st' }, null, {},
];
for (const [i, t] of te.entries()) await o.run('tokenExchangeRequest', `t${i}`, M.tokenExchangeRequest, [t]);
const jb: any[] = [
  { tokenEndpoint: 'https://rs.example.com/token', assertion: 'a.b.c' }, { tokenEndpoint: 'https://rs.example.com/token', assertion: 'a.b.c', scope: ['x', 'y'], clientId: 'c', clientAssertion: 'ca', extra: { z: '1' } },
  { tokenEndpoint: 'https://t', assertion: 'a', scope: 'p q' }, { tokenEndpoint: 'https://t', assertion: 'a', scope: '' }, { tokenEndpoint: 'https://t', assertion: 'a', clientAssertion: '' }, { tokenEndpoint: 'https://t', assertion: 'a', scope: 5 },
  { tokenEndpoint: 'https://t', assertion: 'a', extra: { assertion: 'override', grant_type: 'x' } }, { tokenEndpoint: '', assertion: 'a' }, { tokenEndpoint: 'https://t', assertion: '' }, { tokenEndpoint: 'https://t' }, null, {},
];
for (const [i, t] of jb.entries()) await o.run('jwtBearerAssertion', `t${i}`, M.jwtBearerAssertion, [t]);

refWrite(o, 'idjag-java');
