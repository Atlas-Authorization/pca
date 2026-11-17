// 0.6 oracle: @atlasauth/pca-oidc (discovery, ID-token verification, JWKS resolver, principal mapping) for the native ports.
// TS reference: packages/pca-oidc/src/{discovery,verify,jwks,principal}.ts. EdDSA / HS256 tokens use fixed seeds; the RSA / EC keys are generated
// when this file is run (node cannot seed them), so a regenerated corpus has different keys, never different behaviour. Times are far past / far
// future so the vectors do not age. Function-valued options travel as JSON specs the native test turns into the same callable:
//   key {jwks: <JWK Set>} -> a local JWK-Set resolver            key {resolver: {jwksUri, fetch, ...}} -> createOidcJwks(...)
//   fetch {responses: [{status, body, headers} | {throws: true}]} -> sequence of replies (the last repeats)
// Run: node node_modules/tsx/dist/cli.mjs --tsconfig tools/pca-audit/oracles/tsconfig.json tools/pca-audit/oracles/oidc.mts
import { createPrivateKey, createPublicKey, createHash, createHmac, generateKeyPairSync, sign as nodeSign, constants, type KeyObject } from 'node:crypto';
import { exportJWK, createLocalJWKSet } from 'jose';
import { Oracle, refWrite } from './lib.mjs';

const M: any = await import('../../../packages/pca-oidc/src/index.ts');
const o = new Oracle('oidc', 'tools/pca-audit/oracles/oidc.mts', 'TS-reference oracle for @atlasauth/pca-oidc (discovery, ID-token verification across algorithms, JWKS resolver caching, principal mapping).');

const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString('base64url');
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const edKey = (n: number): KeyObject => createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.alloc(32, n)]), format: 'der', type: 'pkcs8' });
const pubJwk = (priv: KeyObject, kid?: string): any => ({ ...(createPublicKey(priv).export({ format: 'jwk' }) as any), ...(kid ? { kid } : {}) });

const K1 = edKey(1), K2 = edKey(2);
const J1 = pubJwk(K1, 'k1'), J2 = pubJwk(K2, 'k2');
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }), rsa2 = generateKeyPairSync('rsa', { modulusLength: 2048 }), rsaSmall = generateKeyPairSync('rsa', { modulusLength: 1024 });
const ec: any = { 'P-256': generateKeyPairSync('ec', { namedCurve: 'P-256' }), 'P-384': generateKeyPairSync('ec', { namedCurve: 'P-384' }), 'P-521': generateKeyPairSync('ec', { namedCurve: 'P-521' }) };
const JR = pubJwk(rsa.privateKey, 'r1'), JR2 = pubJwk(rsa2.privateKey, 'r2'), JRS = pubJwk(rsaSmall.privateKey, 'rs');
const JE: any = Object.fromEntries(Object.entries(ec).map(([c, kp]: any) => [c, pubJwk(kp.privateKey, 'e-' + c)]));
const SECRET = new Uint8Array(Buffer.alloc(32, 0x5a));

const ALGS: Record<string, { priv: KeyObject | null; jwk: any }> = {
  EdDSA: { priv: K1, jwk: J1 }, RS256: { priv: rsa.privateKey, jwk: JR }, RS384: { priv: rsa.privateKey, jwk: JR }, RS512: { priv: rsa.privateKey, jwk: JR },
  PS256: { priv: rsa.privateKey, jwk: JR }, PS384: { priv: rsa.privateKey, jwk: JR }, PS512: { priv: rsa.privateKey, jwk: JR },
  ES256: { priv: ec['P-256'].privateKey, jwk: JE['P-256'] }, ES384: { priv: ec['P-384'].privateKey, jwk: JE['P-384'] }, ES512: { priv: ec['P-521'].privateKey, jwk: JE['P-521'] },
};
const signAlg = (alg: string, data: Buffer, priv: KeyObject | null): Buffer => {
  if (alg === 'EdDSA') return nodeSign(null, data, priv!);
  if (alg.startsWith('HS')) return createHmac('sha' + alg.slice(2), Buffer.from(SECRET)).update(data).digest();
  const h = 'sha' + alg.slice(2);
  if (alg.startsWith('RS')) return nodeSign(h, data, priv!);
  if (alg.startsWith('PS')) return nodeSign(h, data, { key: priv!, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST });
  return nodeSign(h, data, { key: priv!, dsaEncoding: 'ieee-p1363' });
};
const mk = (header: any, payload: any, priv: KeyObject | null = K1, alg: string = header.alg): string => {
  const h = b64u(Buffer.from(JSON.stringify(header))), p = b64u(Buffer.from(JSON.stringify(payload)));
  return `${h}.${p}.${b64u(signAlg(alg, Buffer.from(`${h}.${p}`), priv))}`;
};

const ISS = 'https://idp.example.com', AUD = 'client-1';
const PAY: any = { iss: ISS, sub: 'user-123', aud: AUD, iat: 1700000000, exp: 4102444800 };
const tok = (over: any = {}, hdr: any = { alg: 'EdDSA', kid: 'k1' }, priv: KeyObject | null = K1) => {
  const p = { ...PAY, ...over };
  for (const k of Object.keys(p)) if (p[k] === undefined) delete p[k];
  return mk(hdr, p, priv);
};
const tokAlg = (alg: string, over: any = {}, kidless = false) => {
  const p = { ...PAY, ...over };
  for (const k of Object.keys(p)) if (p[k] === undefined) delete p[k];
  return mk({ alg, ...(kidless ? {} : { kid: ALGS[alg]?.jwk?.kid ?? 'h' }) }, p, ALGS[alg]?.priv ?? null);
};
const OPTS: any = { issuer: ISS, audience: AUD, key: J1 };

// ---- spec -> callable adapters (mirrored by the native test) ------------------------------------------------------------------------------
const dec = (v: any): any => {
  if (Array.isArray(v)) return v.map(dec);
  if (v !== null && typeof v === 'object') {
    if (Object.keys(v).length === 1 && typeof v.$bytes === 'string') return new Uint8Array(Buffer.from(v.$bytes, 'base64url'));
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, dec(x)]));
  }
  return v;
};
const mkFetch = (spec: any, calls?: string[]) => {
  let i = 0;
  return async (url: string) => {
    calls?.push(url);
    const r = spec.responses[Math.min(i++, spec.responses.length - 1)];
    if (r.throws) throw new Error('boom');
    const h = Object.fromEntries(Object.entries(r.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    return { ok: r.status >= 200 && r.status <= 299, status: r.status, headers: { get: (k: string) => (h as any)[k.toLowerCase()] ?? null }, text: async () => r.body };
  };
};
const adapt = (opts: any): any => {
  if (opts === null || typeof opts !== 'object' || Array.isArray(opts)) return opts;
  const a = dec({ ...opts });
  const k = a.key;
  if (k && typeof k === 'object' && !(k instanceof Uint8Array)) {
    if ('jwks' in k) a.key = createLocalJWKSet(k.jwks);
    else if ('resolver' in k) a.key = M.createOidcJwks({ ...k.resolver, fetch: mkFetch(k.resolver.fetch) });
  }
  if (a.fetch && typeof a.fetch === 'object') a.fetch = mkFetch(a.fetch);
  return a;
};
const verify = (t: any, opts: any) => M.verifyIdToken(t, adapt(opts));

// ---- verifyIdToken -----------------------------------------------------------------------------------------------------------------
const V = (name: string, t: any, opts: any = OPTS) => o.run('verifyIdToken', name, verify, [t, opts]);
const T = tok();
await V('happy EdDSA', T);
for (const alg of Object.keys(ALGS)) {
  const { jwk } = ALGS[alg];
  await V(`happy ${alg} (jwk key)`, tokAlg(alg), { ...OPTS, key: jwk });
  await V(`happy ${alg} (key set)`, tokAlg(alg), { ...OPTS, key: { jwks: { keys: [J1, JR, JE['P-256'], JE['P-384'], JE['P-521']].filter((k) => k === jwk || k !== jwk) } }, algorithms: [alg] });
  await V(`${alg} tampered payload`, (() => { const [h, , s] = tokAlg(alg).split('.'); return `${h}.${b64u(Buffer.from(JSON.stringify({ ...PAY, sub: 'attacker' })))}.${s}`; })(), { ...OPTS, key: jwk });
  await V(`${alg} signature bit flipped`, (() => { const [h, p, s] = tokAlg(alg).split('.'); const b = Buffer.from(s, 'base64url'); b[b.length - 1] ^= 1; return `${h}.${p}.${b64u(b)}`; })(), { ...OPTS, key: jwk });
  await V(`${alg} wrong key of the same type`, tokAlg(alg), { ...OPTS, key: alg === 'EdDSA' ? J2 : alg.startsWith('ES') ? pubJwk(generateKeyPairSync('ec', { namedCurve: ALGS[alg].jwk.crv }).privateKey) : JR2 });
  await V(`${alg} alg not allowed`, tokAlg(alg), { ...OPTS, key: jwk, algorithms: ['HS256'] });
  await V(`${alg} jwk with the wrong alg member`, tokAlg(alg), { ...OPTS, key: { ...jwk, alg: 'HS512' } });
  await V(`${alg} jwk with the right alg member`, tokAlg(alg), { ...OPTS, key: { ...jwk, alg } });
}
for (const alg of ['ES256', 'ES384', 'ES512']) {
  await V(`${alg} signature too short`, (() => { const [h, p, s] = tokAlg(alg).split('.'); return `${h}.${p}.${s.slice(0, -4)}`; })(), { ...OPTS, key: ALGS[alg].jwk });
  await V(`${alg} signature too long`, (() => { const [h, p, s] = tokAlg(alg).split('.'); return `${h}.${p}.${s}AAAA`; })(), { ...OPTS, key: ALGS[alg].jwk });
  await V(`${alg} DER signature`, (() => { const [h, p] = tokAlg(alg).split('.'); const sig = nodeSign('sha' + alg.slice(2), Buffer.from(`${h}.${p}`), ec[ALGS[alg].jwk.crv].privateKey); return `${h}.${p}.${b64u(sig)}`; })(), { ...OPTS, key: ALGS[alg].jwk });
}
await V('ES256 token, P-384 key', tokAlg('ES256'), { ...OPTS, key: JE['P-384'] });
await V('ES256 token, RSA key', tokAlg('ES256'), { ...OPTS, key: JR });
await V('RS256 token, EC key', tokAlg('RS256'), { ...OPTS, key: JE['P-256'] });
await V('RS256 token, OKP key', tokAlg('RS256'), { ...OPTS, key: J1 });
await V('EdDSA token, RSA key', T, { ...OPTS, key: JR });
await V('EdDSA token, Ed448 jwk', T, { ...OPTS, key: { kty: 'OKP', crv: 'Ed448', x: b64u(Buffer.alloc(57, 1)) } });
await V('EdDSA token, X25519 jwk', T, { ...OPTS, key: { kty: 'OKP', crv: 'X25519', x: b64u(Buffer.alloc(32, 1)) } });
await V('RS256 with a 1024-bit key', mk({ alg: 'RS256', kid: 'rs' }, PAY, rsaSmall.privateKey), { ...OPTS, key: JRS });
await V('EC jwk off the curve', tokAlg('ES256'), { ...OPTS, key: { ...JE['P-256'], y: JE['P-256'].x } });
await V('EC jwk short coordinate', tokAlg('ES256'), { ...OPTS, key: { ...JE['P-256'], x: JE['P-256'].x.slice(2) } });
await V('RSA jwk without e', tokAlg('RS256'), { ...OPTS, key: { kty: 'RSA', n: JR.n } });
await V('jwk without kty', T, { ...OPTS, key: { crv: 'Ed25519', x: J1.x } });
await V('jwk with kty not a string', T, { ...OPTS, key: { kty: 5, crv: 'Ed25519', x: J1.x } });
await V('key an empty object', T, { ...OPTS, key: {} });
await V('key a string', T, { ...OPTS, key: 'secret' });
await V('key a number', T, { ...OPTS, key: 5 });
await V('HS256 with a secret', tokAlg('HS256'), { ...OPTS, key: { $bytes: b64u(SECRET) }, algorithms: ['HS256'] });
await V('HS256 default algorithms refuse it', tokAlg('HS256'), { ...OPTS, key: { $bytes: b64u(SECRET) } });
await V('HS256 with the wrong secret', tokAlg('HS256'), { ...OPTS, key: { $bytes: b64u(Buffer.alloc(32, 1)) }, algorithms: ['HS256'] });
await V('HS384 with a secret', tokAlg('HS384'), { ...OPTS, key: { $bytes: b64u(SECRET) }, algorithms: ['HS384'] });
await V('HS512 with a secret', tokAlg('HS512'), { ...OPTS, key: { $bytes: b64u(SECRET) }, algorithms: ['HS512'] });
await V('HS256 with an oct jwk', tokAlg('HS256'), { ...OPTS, key: { kty: 'oct', k: b64u(SECRET) }, algorithms: ['HS256'] });
await V('HS256 with a public jwk', tokAlg('HS256'), { ...OPTS, key: J1, algorithms: ['HS256'] });
await V('EdDSA with a secret', T, { ...OPTS, key: { $bytes: b64u(SECRET) } });
await V('ES256K is not supported', mk({ alg: 'ES256K', kid: 'e-P-256' }, PAY, ec['P-256'].privateKey, 'ES256'), { ...OPTS, key: JE['P-256'], algorithms: ['ES256K'] });
await V('alg PS384 header with RS384 allowed only', tokAlg('PS384'), { ...OPTS, key: JR, algorithms: ['RS384'] });
// key sets
const SET = { jwks: { keys: [J1, J2, JR, JR2, JE['P-256']] } };
await V('set: pick by kid', tok({}, { alg: 'EdDSA', kid: 'k2' }, K2), { ...OPTS, key: SET });
await V('set: kid selects the wrong key', tok({}, { alg: 'EdDSA', kid: 'k2' }, K1), { ...OPTS, key: SET });
await V('set: unknown kid', tok({}, { alg: 'EdDSA', kid: 'zz' }), { ...OPTS, key: SET });
await V('set: no kid, two OKP candidates', tok({}, { alg: 'EdDSA' }), { ...OPTS, key: SET });
await V('set: no kid, one OKP candidate', tok({}, { alg: 'EdDSA' }), { ...OPTS, key: { jwks: { keys: [J1, JR] } } });
await V('set: kid not a string in the header', tok({}, { alg: 'EdDSA', kid: 5 }), { ...OPTS, key: { jwks: { keys: [J1] } } });
await V('set: RS256 by kid', mk({ alg: 'RS256', kid: 'r2' }, PAY, rsa2.privateKey), { ...OPTS, key: SET });
await V('set: RS256 with two RSA keys and no kid', mk({ alg: 'RS256' }, PAY, rsa.privateKey), { ...OPTS, key: SET });
await V('set: ES256 picks the P-256 key', mk({ alg: 'ES256' }, PAY, ec['P-256'].privateKey), { ...OPTS, key: SET });
await V('set: ES384 with only a P-256 key', mk({ alg: 'ES384' }, PAY, ec['P-384'].privateKey), { ...OPTS, key: SET });
await V('set: member alg differs', tok(), { ...OPTS, key: { jwks: { keys: [{ ...J1, alg: 'RS256' }] } } });
await V('set: member alg equal', tok(), { ...OPTS, key: { jwks: { keys: [{ ...J1, alg: 'EdDSA' }] } } });
await V('set: member use enc', tok(), { ...OPTS, key: { jwks: { keys: [{ ...J1, use: 'enc' }] } } });
await V('set: member use sig', tok(), { ...OPTS, key: { jwks: { keys: [{ ...J1, use: 'sig' }] } } });
await V('set: member key_ops without verify', tok(), { ...OPTS, key: { jwks: { keys: [{ ...J1, key_ops: ['sign'] }] } } });
await V('set: member key_ops with verify', tok(), { ...OPTS, key: { jwks: { keys: [{ ...J1, key_ops: ['verify'] }] } } });
await V('set: private member', tok(), { ...OPTS, key: { jwks: { keys: [{ ...J1, d: b64u(Buffer.alloc(32, 1)) }] } } });
await V('set: invalid member key', tok(), { ...OPTS, key: { jwks: { keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'AAAA', kid: 'k1' }] } } });
await V('set: member crv Ed448', tok(), { ...OPTS, key: { jwks: { keys: [{ kty: 'OKP', crv: 'Ed448', x: b64u(Buffer.alloc(57, 1)), kid: 'k1' }] } } });
await V('set: empty', tok(), { ...OPTS, key: { jwks: { keys: [] } } });
await V('set: unsupported alg family', tokAlg('HS256'), { ...OPTS, key: SET, algorithms: ['HS256'] });
// claims
await V('claims: every projected member', tok({ nonce: 'n', azp: AUD, at_hash: 'ah', c_hash: 'ch', auth_time: 1700000001, email: 'a@b.c', email_verified: true, name: 'N', preferred_username: 'pu', given_name: 'G', family_name: 'F', picture: 'https://p', cnf: { jkt: 'x' }, extra: 1, locale: 'en' }));
await V('claims: email_verified not boolean', tok({ email_verified: 'true' }));
await V('claims: email_verified false', tok({ email_verified: false }));
await V('claims: empty and non-string profile members dropped', tok({ email: '', name: 5, preferred_username: '', given_name: [], family_name: null, picture: {} }));
await V('claims: auth_time string dropped', tok({ auth_time: '5' }));
await V('claims: cnf array dropped', tok({ cnf: [1] }));
await V('claims: cnf null dropped', tok({ cnf: null }));
await V('claims: cnf jwk kept', tok({ cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: J1.x } } }));
await V('claims: aud array with azp', tok({ aud: [AUD, 'b'], azp: AUD }));
await V('claims: aud array without azp', tok({ aud: [AUD, 'b'] }));
await V('claims: aud array azp wrong', tok({ aud: [AUD, 'b'], azp: 'b' }));
await V('claims: aud array of one', tok({ aud: [AUD] }));
await V('claims: aud array with a non-string', tok({ aud: [AUD, 5], azp: AUD }));
await V('claims: audience option an array', tok({ aud: 'b' }), { ...OPTS, audience: [AUD, 'b'] });
await V('claims: audience option an array, none present', tok({ aud: 'c' }), { ...OPTS, audience: [AUD, 'b'] });
await V('claims: audience option empty string skips the value check', tok({ aud: 'anything' }), { ...OPTS, audience: '' });
await V('claims: audience option empty string, aud missing', tok({ aud: undefined }), { ...OPTS, audience: '' });
await V('claims: audience option empty array', T, { ...OPTS, audience: [] });
await V('claims: azp with an array audience option and no authorizedParty', tok({ azp: 'zzz' }), { ...OPTS, audience: [AUD] });
await V('claims: authorizedParty option matches', tok({ azp: 'ap' }), { ...OPTS, authorizedParty: 'ap' });
await V('claims: authorizedParty option mismatches', tok({ azp: AUD }), { ...OPTS, authorizedParty: 'ap' });
await V('claims: aud number', tok({ aud: 5 }));
await V('claims: aud null', tok({ aud: null }));
await V('claims: iss number', tok({ iss: 5 }));
await V('claims: iss null', tok({ iss: null }));
await V('claims: sub missing', tok({ sub: undefined }));
await V('claims: sub number', tok({ sub: 5 }));
await V('claims: iat float', tok({ iat: 1700000000.5 }));
await V('claims: exp float', tok({ exp: 4102444800.5 }));
await V('claims: iat null', tok({ iat: null }));
await V('claims: exp null', tok({ exp: null }));
await V('claims: nbf null', tok({ nbf: null }));
await V('claims: nbf past', tok({ nbf: 1000 }));
await V('claims: nbf future', tok({ nbf: 4102444700 }));
await V('claims: nbf future, tolerated', tok({ nbf: 4102444700 }), { ...OPTS, clockToleranceSec: 1e10 });
await V('claims: exp expired', tok({ exp: 1000000000 }));
await V('claims: exp boundary far past', tok({ exp: 1 }));
await V('claims: exp zero', tok({ exp: 0 }));
await V('claims: exp negative', tok({ exp: -5 }));
await V('claims: exp string', tok({ exp: '1' }));
await V('claims: exp missing', tok({ exp: undefined }));
await V('claims: iat missing', tok({ iat: undefined }));
await V('claims: iat missing, exp missing', tok({ iat: undefined, exp: undefined }));
await V('claims: exp missing, iat in the future', tok({ exp: undefined, iat: 4102444700 }));
await V('claims: maxTokenAge exceeded', T, { ...OPTS, maxTokenAgeSec: 60 });
await V('claims: maxTokenAge exceeded but tolerated', T, { ...OPTS, maxTokenAgeSec: 60, clockToleranceSec: 1e10 });
await V('claims: maxTokenAge iat missing', tok({ iat: undefined }), { ...OPTS, maxTokenAgeSec: 60 });
await V('claims: maxTokenAge iat string', tok({ iat: 'x' }), { ...OPTS, maxTokenAgeSec: 60 });
await V('claims: maxTokenAge future iat', tok({ iat: 4102444700 }), { ...OPTS, maxTokenAgeSec: 1e10 });
await V('claims: maxTokenAge 0', T, { ...OPTS, maxTokenAgeSec: 0 });
await V('claims: nonce match', tok({ nonce: 'n1' }), { ...OPTS, nonce: 'n1' });
await V('claims: nonce mismatch', tok({ nonce: 'n2' }), { ...OPTS, nonce: 'n1' });
await V('claims: nonce missing', T, { ...OPTS, nonce: 'n1' });
await V('claims: nonce empty in token', tok({ nonce: '' }), { ...OPTS, nonce: 'n1' });
await V('claims: nonce expected empty string', tok({ nonce: 'n' }), { ...OPTS, nonce: '' });
await V('claims: nonce a number in token', tok({ nonce: 5 }), { ...OPTS, nonce: '5' });
// at_hash / c_hash
const half = (alg: string, v: string) => { const bits = alg === 'EdDSA' ? '512' : alg.slice(-3); const d = createHash('sha' + bits).update(v, 'ascii').digest(); return b64u(d.subarray(0, d.length / 2)); };
for (const alg of ['EdDSA', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']) {
  const jwk = ALGS[alg].jwk;
  await V(`at_hash ${alg}`, tokAlg(alg, { at_hash: half(alg, 'access-token-1') }), { ...OPTS, key: jwk, accessToken: 'access-token-1' });
  await V(`at_hash ${alg} mismatch`, tokAlg(alg, { at_hash: half(alg, 'access-token-1') }), { ...OPTS, key: jwk, accessToken: 'access-token-2' });
  await V(`c_hash ${alg}`, tokAlg(alg, { c_hash: half(alg, 'code-1') }), { ...OPTS, key: jwk, code: 'code-1' });
}
await V('at_hash HS256', tokAlg('HS256', { at_hash: half('HS256', 'tok') }), { ...OPTS, key: { $bytes: b64u(SECRET) }, algorithms: ['HS256'], accessToken: 'tok' });
await V('at_hash missing', T, { ...OPTS, accessToken: 'tok' });
await V('c_hash missing', T, { ...OPTS, code: 'tok' });
await V('at_hash and c_hash both', tok({ at_hash: half('EdDSA', 'a'), c_hash: half('EdDSA', 'c') }), { ...OPTS, accessToken: 'a', code: 'c' });
await V('at_hash ok, c_hash wrong', tok({ at_hash: half('EdDSA', 'a'), c_hash: half('EdDSA', 'c') }), { ...OPTS, accessToken: 'a', code: 'x' });
await V('at_hash empty access token', tok({ at_hash: half('EdDSA', '') }), { ...OPTS, accessToken: '' });
await V('at_hash latin1 characters', tok({ at_hash: half('EdDSA', 'toké€') }), { ...OPTS, accessToken: 'toké€' });
await V('at_hash astral character', tok({ at_hash: half('EdDSA', 'a\u{1F600}b') }), { ...OPTS, accessToken: 'a\u{1F600}b' });
await V('at_hash the ascii-masked variant is not accepted', tok({ at_hash: half('EdDSA', 'toke') }), { ...OPTS, accessToken: 'tokå' });
// token shape / canonical gate
const [H0, P0, S0] = T.split('.');
await V('shape: empty', '');
await V('shape: number', 5);
await V('shape: null', null);
await V('shape: one segment', 'abc');
await V('shape: two segments', `${H0}.${P0}`);
await V('shape: four segments', `${T}.x`);
await V('shape: empty signature', `${H0}.${P0}.`);
await V('shape: empty payload', `${H0}..${S0}`);
await V('shape: padded header', `${H0}=.${P0}.${S0}`);
await V('shape: standard alphabet', `${H0.replace(/-/g, '+')}+.${P0}.${S0}`);
await V('shape: whitespace', ` ${T}`);
await V('shape: newline inside', `${H0}\n.${P0}.${S0}`);
await V('shape: length 1 mod 4 segment', `${H0}A.${P0}.${S0}`);
await V('shape: header with a BOM', (() => { const h = b64u(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: 'k1' }))])); return `${h}.${P0}.${S0}`; })());
await V('shape: header invalid UTF-8', `${b64u(Buffer.from([0xff, 0xfe, 0x7b, 0x7d]))}.${P0}.${S0}`);
await V('shape: header an array', `${b64u(Buffer.from('[]'))}.${P0}.${S0}`);
await V('shape: header null', `${b64u(Buffer.from('null'))}.${P0}.${S0}`);
await V('shape: payload a string', `${H0}.${b64u(Buffer.from('"x"'))}.${S0}`);
await V('shape: payload not JSON', `${H0}.${b64u(Buffer.from('{x'))}.${S0}`);
await V('shape: payload with duplicate keys', (() => { const p = b64u(Buffer.from(JSON.stringify(PAY).replace('"sub":"user-123"', '"sub":"a","sub":"b"'))); return `${H0}.${p}.${b64u(nodeSign(null, Buffer.from(`${H0}.${p}`), K1))}`; })());
await V('shape: payload with NaN', (() => { const p = b64u(Buffer.from('{"iss":"x","exp":NaN}')); return `${H0}.${p}.${S0}`; })());
await V('shape: payload with trailing data', (() => { const p = b64u(Buffer.from(JSON.stringify(PAY) + ' x')); return `${H0}.${p}.${S0}`; })());
await V('shape: alg none', `${b64u(Buffer.from('{"alg":"none"}'))}.${P0}.${S0}`);
await V('shape: alg missing', `${b64u(Buffer.from('{"kid":"k1"}'))}.${P0}.${S0}`);
await V('shape: alg empty', `${b64u(Buffer.from('{"alg":""}'))}.${P0}.${S0}`);
await V('shape: alg an array', `${b64u(Buffer.from('{"alg":["EdDSA"]}'))}.${P0}.${S0}`);
await V('shape: crit unknown', tok({}, { alg: 'EdDSA', kid: 'k1', crit: ['foo'], foo: 1 }));
await V('shape: crit not an array', tok({}, { alg: 'EdDSA', kid: 'k1', crit: 'b64' }));
await V('shape: crit with an empty name', tok({}, { alg: 'EdDSA', kid: 'k1', crit: [''] }));
await V('shape: crit b64 true', tok({}, { alg: 'EdDSA', kid: 'k1', crit: ['b64'], b64: true }));
await V('shape: crit b64 false', tok({}, { alg: 'EdDSA', kid: 'k1', crit: ['b64'], b64: false }));
await V('shape: crit b64 string', tok({}, { alg: 'EdDSA', kid: 'k1', crit: ['b64'], b64: 'no' }));
await V('shape: crit b64 false and a bad signature', tok({}, { alg: 'EdDSA', kid: 'k1', crit: ['b64'], b64: false }, K2));
await V('shape: crit b64 absent member', tok({}, { alg: 'EdDSA', kid: 'k1', crit: ['b64'] }));
await V('shape: typ and cty headers are ignored', tok({}, { alg: 'EdDSA', kid: 'k1', typ: 'at+jwt', cty: 'x', jku: 'https://evil', x5u: 'https://evil' }));
await V('shape: 64 KiB token', 'a'.repeat(65536));
await V('shape: over 64 KiB', 'a'.repeat(65537));
await V('shape: just under the limit is still parsed', `${H0}.${b64u(Buffer.from(JSON.stringify({ ...PAY, pad: 'x'.repeat(40000) })))}.${S0}`);
await V('shape: over the limit through a long payload', `${H0}.${b64u(Buffer.from(JSON.stringify({ ...PAY, pad: 'x'.repeat(70000) })))}.${S0}`);
await V('shape: signature non-canonical padding', `${H0}.${P0}.${S0}=`);
// config and key sources
await V('config: opts null', T, null);
await V('config: opts string', T, 'x');
await V('config: issuer missing', T, { audience: AUD, key: J1 });
await V('config: issuer empty', T, { ...OPTS, issuer: '' });
await V('config: issuer number', T, { ...OPTS, issuer: 5 });
await V('config: audience missing', T, { issuer: ISS, key: J1 });
await V('config: audience number', T, { ...OPTS, audience: 5 });
await V('config: audience object', T, { ...OPTS, audience: {} });
await V('config: no key source', T, { issuer: ISS, audience: AUD });
await V('config: http jwksUri', T, { issuer: ISS, audience: AUD, jwksUri: 'http://idp.example.com/jwks' });
await V('config: HTTPS jwksUri in capitals passes the scheme check only with a fetch', T, { issuer: ISS, audience: AUD, jwksUri: 'HTTP://idp.example.com/jwks' });
await V('config: empty jwksUri', T, { issuer: ISS, audience: AUD, jwksUri: '' });
await V('config: jwksUri number', T, { issuer: ISS, audience: AUD, jwksUri: 5 });
await V('discover: server error', T, { issuer: ISS, audience: AUD, discover: true, fetch: { responses: [{ status: 500, body: '' }] } });
await V('discover: fetch throws', T, { issuer: ISS, audience: AUD, discover: true, fetch: { responses: [{ throws: true }] } });
await V('discover: issuer mismatch', T, { issuer: ISS, audience: AUD, discover: true, fetch: { responses: [{ status: 200, body: JSON.stringify({ issuer: 'https://other', jwks_uri: 'https://other/jwks' }) }] } });
await V('discover: http issuer', T, { issuer: 'http://idp.example.com', audience: AUD, discover: true, fetch: { responses: [{ status: 200, body: '{}' }] } });
await V('discover: jwks_uri over http', T, { issuer: ISS, audience: AUD, discover: true, fetch: { responses: [{ status: 200, body: JSON.stringify({ issuer: ISS, jwks_uri: 'http://idp.example.com/jwks' }) }] } });
await V('discover false is no key source', T, { issuer: ISS, audience: AUD, discover: false });
await V('discover "true" string is no key source', T, { issuer: ISS, audience: AUD, discover: 'true' });
await V('key wins over discover', T, { ...OPTS, discover: true });
await V('key wins over jwksUri', T, { ...OPTS, jwksUri: 'http://x' });
const JWKS_OK = JSON.stringify({ keys: [J1] });
const RS = (spec: any = {}) => ({ resolver: { jwksUri: 'https://idp.example.com/jwks', fetch: { responses: [{ status: 200, body: JWKS_OK }] }, ...spec } });
await V('resolver: fetches and verifies', T, { ...OPTS, key: RS() });
await V('resolver: http uri', T, { ...OPTS, key: RS({ jwksUri: 'http://idp.example.com/jwks' }) });
await V('resolver: http uri allowed', T, { ...OPTS, key: RS({ jwksUri: 'http://idp.example.com/jwks', requireHttps: false }) });
await V('resolver: HTTPS in capitals', T, { ...OPTS, key: RS({ jwksUri: 'HTTPS://idp.example.com/jwks' }) });
await V('resolver: HTTP status', T, { ...OPTS, key: RS({ fetch: { responses: [{ status: 404, body: '' }] } }) });
await V('resolver: fetch throws', T, { ...OPTS, key: RS({ fetch: { responses: [{ throws: true }] } }) });
await V('resolver: not json', T, { ...OPTS, key: RS({ fetch: { responses: [{ status: 200, body: 'nope' }] } }) });
await V('resolver: not a set', T, { ...OPTS, key: RS({ fetch: { responses: [{ status: 200, body: '{"keys":5}' }] } }) });
await V('resolver: an array body', T, { ...OPTS, key: RS({ fetch: { responses: [{ status: 200, body: '[]' }] } }) });
await V('resolver: a null body', T, { ...OPTS, key: RS({ fetch: { responses: [{ status: 200, body: 'null' }] } }) });
await V('resolver: member not an object', T, { ...OPTS, key: RS({ fetch: { responses: [{ status: 200, body: '{"keys":[5]}' }] } }) });
await V('resolver: too large', T, { ...OPTS, key: RS({ maxBytes: 10 }) });
await V('resolver: exactly the size limit', T, { ...OPTS, key: RS({ maxBytes: Buffer.byteLength(JWKS_OK) }) });
await V('resolver: one byte under the size limit', T, { ...OPTS, key: RS({ maxBytes: Buffer.byteLength(JWKS_OK) - 1 }) });
await V('resolver: wrong key in the set', T, { ...OPTS, key: RS({ fetch: { responses: [{ status: 200, body: JSON.stringify({ keys: [J2] }) }] } }) });
await V('resolver: bad option', T, { ...OPTS, key: RS({ cacheMaxAgeSec: -1 }) });
await V('resolver: string option', T, { ...OPTS, key: RS({ cooldownSec: '5' }) });
await V('resolver: option true', T, { ...OPTS, key: RS({ maxBytes: true }) });
const HOST: any[] = [true, false, 0, 1, -1, 1.5, '', 'x', [], ['x'], {}, { x: 1 }];
const TA = tok({ azp: AUD, at_hash: half('EdDSA', 'tok'), c_hash: half('EdDSA', 'cod'), nonce: 'n' });
for (const [i, h] of HOST.entries()) {
  for (const k of ['issuer', 'audience', 'nonce', 'authorizedParty', 'accessToken', 'code', 'algorithms', 'maxTokenAgeSec', 'clockToleranceSec', 'requireHttps', 'discover']) {
    await V(`hostile ${k} #${i}`, TA, { ...OPTS, [k]: h });
  }
}

// ---- discoveryUrl / discoverOidc --------------------------------------------------------------------------------------------------
for (const [i, v] of ['https://idp.example.com', 'https://idp.example.com/', 'https://idp.example.com//', 'https://idp.example.com/tenant/1', 'https://idp.example.com/tenant/1/', '', '/', 'x', 'https://idp.example.com/.well-known/openid-configuration', 'https://idp.example.com?x=1', 'https://idp.example.com/#frag', ' '].entries()) {
  await o.run('discoveryUrl', `value #${i}`, M.discoveryUrl, [v]);
}
for (const [i, v] of [5, null, true, [], {}].entries()) await o.run('discoveryUrl', `hostile #${i}`, M.discoveryUrl, [v]);
const META = { issuer: ISS, jwks_uri: 'https://idp.example.com/jwks', authorization_endpoint: 'https://idp.example.com/auth', token_endpoint: 'https://idp.example.com/token', id_token_signing_alg_values_supported: ['EdDSA'], extra: { a: [1, 2] } };
const reply = (body: any, status = 200, headers: any = {}) => ({ responses: [{ status, body: typeof body === 'string' ? body : JSON.stringify(body), headers }] });
const D = (name: string, issuer: any, opts: any = {}) => o.run('discoverOidc', name, (i: any, op: any) => M.discoverOidc(i, adaptD(op)), [issuer, opts]);
const adaptD = (op: any) => (op && typeof op === 'object' && !Array.isArray(op) && op.fetch && typeof op.fetch === 'object' ? { ...op, fetch: mkFetch(op.fetch) } : op);
await D('ok', ISS, { fetch: reply(META) });
await D('trailing slash issuer', ISS + '/', { fetch: reply({ ...META, issuer: ISS + '/' }) });
await D('trailing slash issuer, doc without the slash', ISS + '/', { fetch: reply(META) });
await D('path issuer', ISS + '/t/1', { fetch: reply({ ...META, issuer: ISS + '/t/1' }) });
await D('members are preserved', ISS, { fetch: reply({ ...META, issuer: ISS, null_member: null, n: 1.5 }) });
await D('minimal document', ISS, { fetch: reply({ issuer: ISS, jwks_uri: 'https://x/jwks' }) });
await D('non-2xx', ISS, { fetch: reply(META, 500) });
await D('301', ISS, { fetch: reply(META, 301) });
await D('299 is ok', ISS, { fetch: reply(META, 299) });
await D('300 is not', ISS, { fetch: reply(META, 300) });
await D('199', ISS, { fetch: reply(META, 199) });
await D('fetch throws', ISS, { fetch: { responses: [{ throws: true }] } });
await D('not json', ISS, { fetch: reply('nope') });
await D('empty body', ISS, { fetch: reply('') });
await D('json with a trailing comma', ISS, { fetch: reply('{"issuer":"x",}') });
await D('array body', ISS, { fetch: reply('[]') });
await D('null body', ISS, { fetch: reply('null') });
await D('string body', ISS, { fetch: reply('"x"') });
await D('issuer missing', ISS, { fetch: reply({ jwks_uri: 'https://x/jwks' }) });
await D('issuer empty', ISS, { fetch: reply({ issuer: '', jwks_uri: 'https://x/jwks' }) });
await D('issuer number', ISS, { fetch: reply({ issuer: 5, jwks_uri: 'https://x/jwks' }) });
await D('jwks_uri missing', ISS, { fetch: reply({ issuer: ISS }) });
await D('jwks_uri empty', ISS, { fetch: reply({ issuer: ISS, jwks_uri: '' }) });
await D('jwks_uri number', ISS, { fetch: reply({ issuer: ISS, jwks_uri: 5 }) });
await D('issuer mismatch', ISS, { fetch: reply({ ...META, issuer: 'https://other' }) });
await D('issuer mismatch by trailing slash', ISS, { fetch: reply({ ...META, issuer: ISS + '/' }) });
await D('issuer mismatch by case', ISS, { fetch: reply({ ...META, issuer: ISS.toUpperCase() }) });
await D('jwks_uri over http', ISS, { fetch: reply({ ...META, jwks_uri: 'http://idp.example.com/jwks' }) });
await D('jwks_uri over http allowed', ISS, { fetch: reply({ ...META, jwks_uri: 'http://idp.example.com/jwks' }), requireHttps: false });
await D('jwks_uri not a URL', ISS, { fetch: reply({ ...META, jwks_uri: 'nope' }) });
await D('jwks_uri with a space', ISS, { fetch: reply({ ...META, jwks_uri: 'https://idp example.com/jwks' }) });
await D('jwks_uri https without a host', ISS, { fetch: reply({ ...META, jwks_uri: 'https://' }) });
await D('jwks_uri ftp', ISS, { fetch: reply({ ...META, jwks_uri: 'ftp://idp.example.com/jwks' }) });
await D('jwks_uri HTTPS capitals', ISS, { fetch: reply({ ...META, jwks_uri: 'HTTPS://IDP.example.com/jwks' }) });
await D('jwks_uri with port and path', ISS, { fetch: reply({ ...META, jwks_uri: 'https://idp.example.com:8443/a/b?c=d' }) });
await D('issuer http', 'http://idp.example.com', { fetch: reply({ ...META, issuer: 'http://idp.example.com' }) });
await D('issuer http allowed', 'http://idp.example.com', { fetch: reply({ ...META, issuer: 'http://idp.example.com', jwks_uri: 'http://idp.example.com/jwks' }), requireHttps: false });
await D('issuer not a URL', 'nope', { fetch: reply(META) });
await D('issuer not a URL, https not required', 'nope', { fetch: reply({ issuer: 'nope', jwks_uri: 'x' }), requireHttps: false });
await D('issuer argument empty', '', { fetch: reply(META) });
await D('issuer argument number', 5, { fetch: reply(META) });
await D('issuer argument null', null, { fetch: reply(META) });
await D('issuer with a space', 'https://idp example.com', { fetch: reply(META) });
await D('issuer https without a host', 'https://', { fetch: reply(META) });
await D('issuer https capitals', 'HTTPS://idp.example.com', { fetch: reply({ ...META, issuer: 'HTTPS://idp.example.com' }) });
await D('requireHttps false only', ISS, { fetch: reply(META), requireHttps: false });
await D('requireHttps hostile 0 still requires', 'http://idp.example.com', { fetch: reply({ ...META, issuer: 'http://idp.example.com' }), requireHttps: 0 });
await D('requireHttps hostile string', 'http://idp.example.com', { fetch: reply({ ...META, issuer: 'http://idp.example.com' }), requireHttps: 'false' });
await D('content-length over the cap', ISS, { fetch: reply(META, 200, { 'Content-Length': '2000000' }) });
await D('content-length at the cap', ISS, { fetch: reply(META, 200, { 'content-length': '1048576' }) });
await D('content-length just over the cap', ISS, { fetch: reply(META, 200, { 'content-length': '1048577' }) });
await D('content-length garbage is ignored', ISS, { fetch: reply(META, 200, { 'content-length': 'abc' }) });
await D('content-length empty is ignored', ISS, { fetch: reply(META, 200, { 'content-length': '' }) });
await D('content-length hex', ISS, { fetch: reply(META, 200, { 'content-length': '0x200000' }) });
await D('content-length negative', ISS, { fetch: reply(META, 200, { 'content-length': '-5' }) });
await D('content-length infinity', ISS, { fetch: reply(META, 200, { 'content-length': 'Infinity' }) });
await D('content-length with spaces', ISS, { fetch: reply(META, 200, { 'content-length': ' 2000000 ' }) });
await D('maxBytes small and content-length over', ISS, { fetch: reply(META, 200, { 'content-length': '100' }), maxBytes: 10 });
await D('maxBytes small and body over', ISS, { fetch: reply(META), maxBytes: 10 });
await D('maxBytes exactly the body size', ISS, { fetch: reply(META), maxBytes: Buffer.byteLength(JSON.stringify(META)) });
await D('maxBytes one under the body size', ISS, { fetch: reply(META), maxBytes: Buffer.byteLength(JSON.stringify(META)) - 1 });
await D('maxBytes counts UTF-8 bytes', ISS, { fetch: reply({ ...META, n: 'é'.repeat(10) }), maxBytes: Buffer.byteLength(JSON.stringify({ ...META, n: 'é'.repeat(10) })) - 1 });
await D('maxBytes 0', ISS, { fetch: reply(META), maxBytes: 0 });
await D('opts null', ISS, null);
for (const [i, h] of HOST.entries()) await D(`hostile maxBytes #${i}`, ISS, { fetch: reply(META), maxBytes: h });
// calls made
const calls = (name: string, issuer: any, opts: any) => o.run('discoverOidcCalls', name, async (i: any, op: any) => {
  const urls: string[] = [];
  const f = mkFetch(op.fetch, urls);
  let outcome = 'ok';
  try { await M.discoverOidc(i, { ...op, fetch: f }); } catch { outcome = 'error'; }
  return { urls, outcome };
}, [issuer, opts]);
await calls('plain', ISS, { fetch: reply(META) });
await calls('trailing slash', ISS + '/', { fetch: reply({ ...META, issuer: ISS + '/' }) });
await calls('path', ISS + '/t/1/', { fetch: reply({ ...META, issuer: ISS + '/t/1/' }) });
await calls('refused before any request (http issuer)', 'http://x', { fetch: reply(META) });
await calls('refused before any request (empty issuer)', '', { fetch: reply(META) });

// ---- createOidcJwks: caching, staleness, cooldown ---------------------------------------------------------------------------------
const pick = (j: any) => Object.fromEntries(['kty', 'crv', 'x', 'y', 'n', 'e'].filter((k) => k in j).map((k) => [k, j[k]]));
const seq = (name: string, spec: any) => o.run('createOidcJwks', name, async (s: any) => {
  let clock = 0;
  let fetches = 0;
  const f = mkFetch(s.fetch);
  const r = M.createOidcJwks({ jwksUri: s.jwksUri, ...(s.opts ?? {}), fetch: async (u: string, init: any) => { fetches++; return f(u); }, now: () => clock });
  const steps: any[] = [];
  for (const st of s.steps) {
    clock = st.atMs;
    try { steps.push({ ok: pick(await exportJWK((await r(st.header, {})) as any)) }); } catch (e: any) { steps.push({ err: e && e.name === 'OidcVerificationError' && e.code === 'keys' ? 'keys' : 'other' }); }
  }
  return { steps, fetches };
}, [spec]);
const URI = 'https://idp.example.com/jwks';
const SET1 = { status: 200, body: JSON.stringify({ keys: [J1] }) }, SET2 = { status: 200, body: JSON.stringify({ keys: [J1, J2] }) }, BAD = { status: 500, body: '' };
const H1 = { alg: 'EdDSA', kid: 'k1' }, H2 = { alg: 'EdDSA', kid: 'k2' };
await seq('cached within the max age', { jwksUri: URI, fetch: { responses: [SET1] }, steps: [{ atMs: 0, header: H1 }, { atMs: 599999, header: H1 }] });
await seq('stale at exactly the max age', { jwksUri: URI, fetch: { responses: [SET1] }, steps: [{ atMs: 0, header: H1 }, { atMs: 600000, header: H1 }] });
await seq('custom max age', { jwksUri: URI, opts: { cacheMaxAgeSec: 5 }, fetch: { responses: [SET1] }, steps: [{ atMs: 0, header: H1 }, { atMs: 4999, header: H1 }, { atMs: 5000, header: H1 }] });
await seq('max age 0 refetches every call', { jwksUri: URI, opts: { cacheMaxAgeSec: 0 }, fetch: { responses: [SET1] }, steps: [{ atMs: 0, header: H1 }, { atMs: 0, header: H1 }, { atMs: 1, header: H1 }] });
await seq('stale set never served when the refetch fails', { jwksUri: URI, fetch: { responses: [SET1, BAD] }, steps: [{ atMs: 0, header: H1 }, { atMs: 700000, header: H1 }, { atMs: 700001, header: H1 }] });
await seq('first fetch fails then recovers', { jwksUri: URI, fetch: { responses: [BAD, SET1] }, steps: [{ atMs: 0, header: H1 }, { atMs: 1, header: H1 }] });
await seq('fetch throws', { jwksUri: URI, fetch: { responses: [{ throws: true }] }, steps: [{ atMs: 0, header: H1 }] });
await seq('unknown kid inside the cooldown', { jwksUri: URI, fetch: { responses: [SET1, SET2] }, steps: [{ atMs: 0, header: H1 }, { atMs: 29999, header: H2 }] });
await seq('unknown kid after the cooldown picks up a rotated key', { jwksUri: URI, fetch: { responses: [SET1, SET2] }, steps: [{ atMs: 0, header: H1 }, { atMs: 30000, header: H2 }, { atMs: 30001, header: H2 }] });
await seq('unknown kid after the cooldown but the key is still absent', { jwksUri: URI, fetch: { responses: [SET1] }, steps: [{ atMs: 0, header: H1 }, { atMs: 30000, header: H2 }, { atMs: 30001, header: H2 }, { atMs: 60000, header: H2 }] });
await seq('cooldown 0', { jwksUri: URI, opts: { cooldownSec: 0 }, fetch: { responses: [SET1, SET2] }, steps: [{ atMs: 0, header: H1 }, { atMs: 0, header: H2 }] });
await seq('custom cooldown', { jwksUri: URI, opts: { cooldownSec: 5 }, fetch: { responses: [SET1, SET2] }, steps: [{ atMs: 0, header: H1 }, { atMs: 4999, header: H2 }, { atMs: 5000, header: H2 }] });
await seq('the cooldown counts from the last fetch, successful or not', { jwksUri: URI, fetch: { responses: [SET1, BAD, SET2] }, steps: [{ atMs: 0, header: H1 }, { atMs: 30000, header: H2 }, { atMs: 40000, header: H2 }, { atMs: 60000, header: H2 }] });
await seq('no kid in the header never refetches', { jwksUri: URI, fetch: { responses: [SET1, SET2] }, steps: [{ atMs: 0, header: { alg: 'EdDSA' } }, { atMs: 100000, header: { alg: 'EdDSA' } }] });
await seq('kid not a string never refetches', { jwksUri: URI, fetch: { responses: [SET1, SET2] }, steps: [{ atMs: 0, header: H1 }, { atMs: 100000, header: { alg: 'EdDSA', kid: 5 } }] });
await seq('two keys without a kid are ambiguous', { jwksUri: URI, fetch: { responses: [SET2] }, steps: [{ atMs: 0, header: { alg: 'EdDSA' } }] });
await seq('a set with a rotated-out key', { jwksUri: URI, fetch: { responses: [SET2, SET1] }, steps: [{ atMs: 0, header: H2 }, { atMs: 700000, header: H2 }] });
await seq('rsa and ec members', { jwksUri: URI, fetch: { responses: [{ status: 200, body: JSON.stringify({ keys: [JR, JE['P-256'], J1] }) }] }, steps: [{ atMs: 0, header: { alg: 'RS256', kid: 'r1' } }, { atMs: 1, header: { alg: 'ES256', kid: 'e-P-256' } }, { atMs: 2, header: { alg: 'ES384', kid: 'e-P-256' } }, { atMs: 3, header: { alg: 'HS256' } }] });
await seq('private member', { jwksUri: URI, fetch: { responses: [{ status: 200, body: JSON.stringify({ keys: [{ ...J1, d: b64u(Buffer.alloc(32, 1)) }] }) }] }, steps: [{ atMs: 0, header: H1 }] });
await seq('not a set', { jwksUri: URI, fetch: { responses: [{ status: 200, body: '{"keys":"x"}' }] }, steps: [{ atMs: 0, header: H1 }] });
await seq('member not an object', { jwksUri: URI, fetch: { responses: [{ status: 200, body: '{"keys":[1]}' }] }, steps: [{ atMs: 0, header: H1 }] });
await seq('too large', { jwksUri: URI, opts: { maxBytes: 5 }, fetch: { responses: [SET1] }, steps: [{ atMs: 0, header: H1 }] });
await seq('http uri allowed', { jwksUri: 'http://idp.example.com/jwks', opts: { requireHttps: false }, fetch: { responses: [SET1] }, steps: [{ atMs: 0, header: H1 }] });
await seq('a time before zero', { jwksUri: URI, fetch: { responses: [SET1] }, steps: [{ atMs: -5, header: H1 }, { atMs: -4, header: H1 }] });
await seq('http uri refused', { jwksUri: 'http://idp.example.com/jwks', fetch: { responses: [SET1] }, steps: [] });
await seq('uri missing', { fetch: { responses: [SET1] }, steps: [] });
await seq('uri empty', { jwksUri: '', fetch: { responses: [SET1] }, steps: [] });
await seq('uri number', { jwksUri: 5, fetch: { responses: [SET1] }, steps: [] });
for (const k of ['cacheMaxAgeSec', 'cooldownSec', 'maxBytes', 'timeoutMs']) {
  for (const [i, h] of [-1, 'x', true, [], {}, 0, 1.5].entries()) await seq(`option ${k} hostile #${i}`, { jwksUri: URI, opts: { [k]: h }, fetch: { responses: [SET1] }, steps: [{ atMs: 0, header: H1 }] });
}
const fromIssuer = (name: string, spec: any) => o.run('createOidcJwksFromIssuer', name, async (s: any) => {
  const urls: string[] = [];
  const r = await M.createOidcJwksFromIssuer(s.issuer, { ...(s.opts ?? {}), fetch: mkFetch(s.fetch, urls) });
  let out: any;
  try { out = { ok: pick(await exportJWK((await r(s.header, {})) as any)) }; } catch (e: any) { out = { err: e && e.name === 'OidcVerificationError' && e.code === 'keys' ? 'keys' : 'other' }; }
  return { out, urls };
}, [spec]);
const DOC = { status: 200, body: JSON.stringify({ issuer: ISS, jwks_uri: URI }) };
await fromIssuer('discovers then fetches', { issuer: ISS, header: H1, fetch: { responses: [DOC, SET1] } });
await fromIssuer('jwks fetch fails', { issuer: ISS, header: H1, fetch: { responses: [DOC, BAD] } });
await fromIssuer('discovery fails', { issuer: ISS, header: H1, fetch: { responses: [BAD] } });
await fromIssuer('http issuer', { issuer: 'http://idp.example.com', header: H1, fetch: { responses: [DOC, SET1] } });
await fromIssuer('http issuer allowed', { issuer: 'http://idp.example.com', opts: { requireHttps: false }, header: H1, fetch: { responses: [{ status: 200, body: JSON.stringify({ issuer: 'http://idp.example.com', jwks_uri: 'http://idp.example.com/jwks' }) }, SET1] } });
await fromIssuer('jwks_uri over http', { issuer: ISS, header: H1, fetch: { responses: [{ status: 200, body: JSON.stringify({ issuer: ISS, jwks_uri: 'http://idp.example.com/jwks' }) }, SET1] } });
await fromIssuer('options reach the resolver', { issuer: ISS, opts: { maxBytes: 5 }, header: H1, fetch: { responses: [DOC, SET1] } });

// ---- oidcPrincipal / isOidcSubjectCaveat -------------------------------------------------------------------------------------------
const baseClaims: any = { iss: ISS, sub: 'user-123', aud: AUD, iat: 1700000000, exp: 4102444800 };
const PUB_X: string = J1.x;
const cnfOf = (x: any) => ({ ...baseClaims, cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x } } });
const P = (name: string, c: any, opts?: any) => o.run('oidcPrincipal', name, M.oidcPrincipal, opts === undefined ? [c] : [c, opts]);
await P('plain', baseClaims);
await P('cnf key', cnfOf(PUB_X));
await P('cnf key plus the same principalPublic', cnfOf(PUB_X), { principalPublic: PUB_X });
await P('cnf key plus a different principalPublic', cnfOf(PUB_X), { principalPublic: J2.x });
await P('principalPublic only', baseClaims, { principalPublic: PUB_X });
await P('principalPublic padded', baseClaims, { principalPublic: PUB_X + '=' });
await P('principalPublic standard alphabet', baseClaims, { principalPublic: b64u(Buffer.alloc(32, 0xfb)).replace(/-/g, '+').replace(/_/g, '/') });
await P('principalPublic 31 bytes', baseClaims, { principalPublic: b64u(Buffer.alloc(31, 5)) });
await P('principalPublic 33 bytes', baseClaims, { principalPublic: b64u(Buffer.alloc(33, 5)) });
await P('principalPublic empty', baseClaims, { principalPublic: '' });
await P('principalPublic number', baseClaims, { principalPublic: 5 });
await P('principalPublic non-canonical last character', baseClaims, { principalPublic: PUB_X.slice(0, -1) + (PUB_X.endsWith('A') ? 'B' : 'A') });
await P('principalPublic whitespace', baseClaims, { principalPublic: ' ' + PUB_X });
await P('opts empty', baseClaims, {});
await P('opts null', baseClaims, null);
await P('profile members', { ...baseClaims, email: 'a@b.c', email_verified: false, name: 'N', preferred_username: 'pu', auth_time: 1700000001, given_name: 'G' });
await P('profile members present but null', { ...baseClaims, email: null, email_verified: null, name: null, preferred_username: null, auth_time: null });
await P('profile members with odd types', { ...baseClaims, email: 5, email_verified: 'no', name: [], auth_time: '1' });
await P('cnf jwk Ed448', { ...baseClaims, cnf: { jwk: { kty: 'OKP', crv: 'Ed448', x: PUB_X } } });
await P('cnf jwk EC', { ...baseClaims, cnf: { jwk: { kty: 'EC', crv: 'Ed25519', x: PUB_X } } });
await P('cnf jwk x not a string', cnfOf(5));
await P('cnf jwk x padded', cnfOf(PUB_X + '='));
await P('cnf jwk x too short', cnfOf(b64u(Buffer.alloc(16, 1))));
await P('cnf jwk x empty', cnfOf(''));
await P('cnf jwk null', { ...baseClaims, cnf: { jwk: null } });
await P('cnf jwk array', { ...baseClaims, cnf: { jwk: [PUB_X] } });
await P('cnf jwk string', { ...baseClaims, cnf: { jwk: PUB_X } });
await P('cnf jkt only', { ...baseClaims, cnf: { jkt: 'abc' } });
await P('cnf string', { ...baseClaims, cnf: 'x' });
await P('cnf array', { ...baseClaims, cnf: [1] });
await P('cnf null', { ...baseClaims, cnf: null });
await P('iss missing', { ...baseClaims, iss: undefined });
await P('iss empty', { ...baseClaims, iss: '' });
await P('iss number', { ...baseClaims, iss: 5 });
await P('sub missing', { ...baseClaims, sub: undefined });
await P('sub empty', { ...baseClaims, sub: '' });
await P('sub null', { ...baseClaims, sub: null });
await P('iss with a hash', { ...baseClaims, iss: 'https://a#b', sub: 'c#d' });
await P('claims null', null);
await P('claims string', 'x');
await P('claims number', 5);
await P('claims array', []);
await P('claims empty', {});
const SUBJ = { type: 'oidc_subject', iss: ISS, sub: 's' };
const subjVariants: any[] = [SUBJ, { ...SUBJ, extra: 1 }, { ...SUBJ, iss: '' }, { ...SUBJ, iss: 5 }, { ...SUBJ, sub: '' }, { ...SUBJ, sub: null }, { ...SUBJ, type: 'x' }, { iss: ISS, sub: 's' }, { type: 'oidc_subject' }, null, undefined, 5, 'x', [], [SUBJ], true];
for (const [i, v] of subjVariants.entries()) await o.run('isOidcSubjectCaveat', `variant #${i}`, M.isOidcSubjectCaveat, [v]);

await o.run('constants', 'all', () => ({ DEFAULT_ID_TOKEN_ALGS: [...M.DEFAULT_ID_TOKEN_ALGS], DEFAULT_MAX_DISCOVERY_BYTES: M.DEFAULT_MAX_DISCOVERY_BYTES, DEFAULT_JWKS_TIMEOUT_MS: M.DEFAULT_JWKS_TIMEOUT_MS, OIDC_SUBJECT_CAVEAT: M.OIDC_SUBJECT_CAVEAT }), []);

refWrite(o, 'oidc');
