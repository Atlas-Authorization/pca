// Oracle: @atlasauth/pca-sdjwt (SD-JWT serialization of a PCActn: issue / present / verify / verifyRecovered). Writes out/ref-sdjwt.json.gz.
// Every fn takes JSON args. Keys are passed as seeds / raw public bytes ({"$bytes"}); an options object uses snake_case names
// (issuer_seed, expected_audience, ...) that the wrappers below map to the reference's camelCase options. Salts are made
// deterministic (randomBytes is replaced before the reference loads). issuePcaSdJwt output carries random-looking salts in a
// native, so its case compares a normalized form (header, clear payload, [name, value] disclosures, digest agreement, verify).
// A throw only requires the native to refuse; a verify {ok:false} compares `reason` only when the reason is this package's own.
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { Oracle, refWrite } from './lib.mjs';
import { ecKit } from './idkit.mjs';

// ---- deterministic salts (must run before the reference is imported) ----
let ctr = 0;
(crypto as any).randomBytes = (n: number) => crypto.createHash('sha256').update('sdjwt-oracle-salt/' + ctr++).digest().subarray(0, n);
syncBuiltinESMExports();

const M: any = await import('../../../packages/pca-sdjwt/src/index.ts');
const P: any = await import('@atlasauth/pca');
const J: any = await import('jose');
const sha = (s: string) => crypto.createHash('sha256').update(s, 'ascii').digest('base64url');
const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64url');

const o = new Oracle('sdjwt', 'tools/pca-audit/oracles/sdjwt.mts', 'TS-reference oracle for @atlasauth/pca-sdjwt.');

const seed = (n: number) => new Uint8Array(32).fill(n);
const pubOf = (s: Uint8Array) => new Uint8Array(P.publicKeyOf(s));
const S_ISS = seed(1), S_HOLD = seed(2), S_OTHER = seed(3);
const PUB_ISS = pubOf(S_ISS), PUB_HOLD = pubOf(S_HOLD), PUB_OTHER = pubOf(S_OTHER);
const NOW = 1_700_000_000_000;

// ---- JSON <-> reference value mapping ----
const fromJ = (v: any): any => {
  if (v === null || typeof v !== 'object' || v instanceof Uint8Array) return v;
  if (Array.isArray(v)) return v.map(fromJ);
  const ks = Object.keys(v);
  if (ks.length === 1 && ks[0] === '$bytes') return new Uint8Array(Buffer.from(v.$bytes, 'base64url'));
  return Object.fromEntries(ks.map((k) => [k, fromJ(v[k])]));
};
const CAMEL: Record<string, string> = {
  required_disclosures: 'requiredDisclosures', expected_audience: 'expectedAudience', expected_kb_audience: 'expectedKbAudience',
  expected_nonce: 'expectedNonce', require_key_binding: 'requireKeyBinding', algorithms: 'algorithms', kb_algorithms: 'kbAlgorithms',
  now: 'now', kb_max_age_sec: 'kbMaxAgeSec', clock_tolerance_sec: 'clockToleranceSec', key_binding_key: 'keyBindingKey',
};

async function normalizeIssued(sd: string, issuerSeed: Uint8Array) {
  const parts = sd.split('~');
  const ds = parts.slice(1, -1);
  const dec = (x: string) => JSON.parse(Buffer.from(x, 'base64url').toString('utf8'));
  const [h, p] = parts[0].split('.').slice(0, 2).map(dec);
  const disc = ds.map(dec) as any[];
  const dig = ds.map(sha).sort();
  const { _sd, ...rest } = p;
  const sdl = [...(_sd ?? [])].sort();
  const ver = await M.verifyPcaSdJwt(sd, { issuerKey: M.importEd25519PublicKey(pubOf(issuerSeed)), now: p.iat * 1000 });
  return {
    end: parts[parts.length - 1], header: h, payload: rest, n: ds.length, digestsOk: JSON.stringify(dig) === JSON.stringify(sdl),
    disclosures: disc.map((d) => [d[1], d[2]]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)), verified: ver.ok,
  };
}
async function issueW(pc: any, opt: any) {
  const m: any = { issuerKey: M.importEd25519PrivateKey(fromJ(opt.issuer_seed)) };
  for (const k of ['disclosable', 'iss', 'sub', 'typ']) if (k in opt) m[k] = opt[k];
  if ('signing_alg' in opt) m.signingAlg = opt.signing_alg;
  if ('key_binding' in opt) {
    const kb = opt.key_binding;
    m.keyBinding = kb !== null && typeof kb === 'object' && !Array.isArray(kb) && 'holder_public_key' in kb ? { holderPublicKey: fromJ(kb.holder_public_key) } : kb;
  }
  return normalizeIssued(await M.issuePcaSdJwt(pc, m), fromJ(opt.issuer_seed));
}
async function presentW(sd: string, sel: any, opt?: any) {
  const m: any = {};
  if (opt && 'key_binding' in opt) {
    const kb = opt.key_binding;
    const k: any = { holderKey: M.importEd25519PrivateKey(fromJ(kb.holder_seed)) };
    for (const [a, b] of [['audience', 'audience'], ['nonce', 'nonce'], ['iat', 'iat'], ['alg', 'alg']]) if (a in kb) k[b] = kb[a];
    m.keyBinding = k;
  }
  return M.present(sd, sel, m);
}
async function verifyW(sd: any, opt: any) {
  const m: any = {};
  const ik = fromJ(opt.issuer_key);
  m.issuerKey = ik instanceof Uint8Array ? M.importEd25519PublicKey(ik) : await J.importJWK(ik, opt.issuer_jwk_alg ?? 'ES256');
  for (const [k, c] of Object.entries(CAMEL)) if (k in opt) m[c] = fromJ(opt[k]);
  return M.verifyPcaSdJwt(sd, m);
}
async function recoveredW(res: any, opt: any) {
  const c: any = { grant: opt.grant };
  if ('audience' in opt) c.audience = opt.audience;
  if ('now' in opt) c.nowEpoch = opt.now;
  if ('insecure_skip_plan_root_check' in opt) c.insecureSkipPlanRootCheck = opt.insecure_skip_plan_root_check;
  const r = await M.verifyRecovered(res, c);
  return { allow: r.allow, reason: r.reason };
}

// ---- a real, signed PCActn (principal -> agent delegation + a committed plan) ----
function fixture(sPrin: Uint8Array, sAgent: Uint8Array, over: { ttlMs?: number; aud?: string } = {}) {
  const pp = P.encodeKey(pubOf(sPrin)), ap = P.encodeKey(pubOf(sAgent));
  const { grant } = P.mintGrant({
    principalSecret: sPrin, principalPublic: pp, holder: pp, goal: 'secure my account',
    envelope: { predicates: [{ verb: 'revoke_session', resource: 'session:*' }], caveats: [{ type: 'expires', at: NOW + 3_600_000 }], agent_binding: {}, risk_policy: P.DEFAULT_RISK_POLICY },
  });
  const chain = [grant, P.delegate(grant, ap, [{ type: 'expires', at: NOW + 600_000 }], sPrin)];
  const plan = [{ id: 'n1', verb: 'revoke_session', resource: 'session:s2', params_digest: undefined, reversibility_class: 'reversible' }];
  const pcActn = P.buildPCActn({ grant, chain, plan, nodeId: 'n1', counter: 1, signerSecret: sAgent, aud: over.aud ?? 'atlas-rs-prod', now: NOW, ttlMs: over.ttlMs ?? 600_000, nonce: 'nonce-xyz', caution: 0.2 });
  return { grant, pcActn, pp, ap };
}
const F = fixture(S_ISS, S_HOLD);
const F2 = fixture(S_ISS, S_HOLD, { ttlMs: 600_001 });
const OTHER = fixture(S_OTHER, S_HOLD);
const J_ = (x: any) => JSON.parse(JSON.stringify(x));
const PC = J_(F.pcActn);
const iss = M.importEd25519PrivateKey(S_ISS);
const issued = async (pc: any, opt: any = {}) => M.issuePcaSdJwt(pc, { issuerKey: iss, ...opt });
const SD_FULL: string = await issued(PC);
const SD_KB: string = await issued(PC, { keyBinding: {} });
const KBP = (extra: any = {}) => ({ key_binding: { holder_seed: S_HOLD, audience: 'atlas-rs-prod', nonce: 'n1', iat: 1_700_000_050, ...extra } });
const SD_KB_PRES: string = await presentW(SD_KB, ['action', 'cap_chain'], KBP());

// ---- constants + key helpers ----
await o.run('constants', 'all', () => ({ SD_ALG: M.SD_ALG, PCA_SD_JWT_TYP: M.PCA_SD_JWT_TYP, KB_JWT_TYP: M.KB_JWT_TYP, DEFAULT_SIGNING_ALG: M.DEFAULT_SIGNING_ALG, PCA_CAPABILITY_CLAIMS: [...M.PCA_CAPABILITY_CLAIMS] }), []);
for (const [n, raw] of [['32', PUB_ISS], ['31', new Uint8Array(31)], ['33', new Uint8Array(33)], ['0', new Uint8Array(0)]] as const) {
  await o.run('ed25519PublicJwk', n, (r: any) => M.ed25519PublicJwk(fromJ(r)), [raw]);
  await o.run('importEd25519PrivateKey', n, (r: any) => (M.importEd25519PrivateKey(fromJ(r)), 'ok'), [raw]);
  await o.run('importEd25519PublicKey', n, (r: any) => (M.importEd25519PublicKey(fromJ(r)), 'ok'), [raw]);
}

// ---- issuePcaSdJwt ----
const OPT = { issuer_seed: S_ISS };
const issue = (name: string, pc: any, opt: any = {}) => o.run('issuePcaSdJwt', name, issueW, [pc, { ...OPT, ...opt }]);
await issue('real default', PC);
await issue('real sub-second lifetime', J_(F2.pcActn));
await issue('disclosable none', PC, { disclosable: [] });
await issue('disclosable subset', PC, { disclosable: ['action', 'sig', 'nonexistent'] });
await issue('disclosable explicit all', PC, { disclosable: [...M.PCA_CAPABILITY_CLAIMS] });
await issue('disclosable null', PC, { disclosable: null });
await issue('key_binding empty (leaf holder)', PC, { key_binding: {} });
await issue('key_binding holder bytes', PC, { key_binding: { holder_public_key: PUB_HOLD } });
await issue('key_binding holder jwk', PC, { key_binding: { holder_public_key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(PUB_HOLD).toString('base64url') } } });
await issue('key_binding holder ec jwk', PC, { key_binding: { holder_public_key: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' } } });
await issue('key_binding holder bytes 31', PC, { key_binding: { holder_public_key: new Uint8Array(31) } });
await issue('key_binding holder string', PC, { key_binding: { holder_public_key: 'abc' } });
await issue('key_binding holder null', PC, { key_binding: { holder_public_key: null } });
await issue('key_binding false', PC, { key_binding: false });
await issue('key_binding null', PC, { key_binding: null });
await issue('iss/sub override', PC, { iss: 'did:example:issuer', sub: 'did:example:subject' });
await issue('iss/sub null', PC, { iss: null, sub: null });
await issue('typ override', PC, { typ: 'vc+sd-jwt' });
await issue('signing_alg EdDSA', PC, { signing_alg: 'EdDSA' });
for (const a of ['ES256', 'HS256', 'none', 'RS256', '', 5]) await issue(`signing_alg ${JSON.stringify(a)}`, PC, { signing_alg: a });
const with_ = (patch: any) => ({ ...PC, ...patch });
const without = (k: string) => { const c = { ...PC }; delete c[k]; return c; };
for (const bad of [null, 5, 'x', [], true]) await issue(`pcActn ${JSON.stringify(bad)}`, bad);
for (const [n, v] of Object.entries({ 'cap_chain empty': [], 'cap_chain object': {}, 'cap_chain string': 'x', 'cap_chain [null]': [null], 'cap_chain [{}]': [{}], 'cap_chain [5]': [5], 'root issuer number': [{ issuer: 5, holder: 'a' }],
  'leaf holder number': [{ issuer: 'a', holder: 5 }], 'leaf holder empty string': [{ issuer: 'a', holder: '' }] })) await issue(n, with_({ cap_chain: v }));
await issue('cap_chain missing', without('cap_chain'));
for (const [n, v] of Object.entries({ 'aud empty': '', 'aud number': 5, 'aud null': null, 'aud array': ['x'] })) await issue(n, with_({ aud: v }));
await issue('aud missing', without('aud'));
for (const [n, v] of [['iat string', '1'], ['iat null', null], ['iat true', true], ['iat 1.5', 1.5], ['iat 0', 0], ['iat -0', -0], ['iat negative', -5000], ['iat 2^53', 2 ** 53], ['iat 1e21', 1e21], ['iat array', []]] as const) await issue(n, with_({ iat: v }));
await issue('iat missing', without('iat'));
for (const [n, v] of [['exp string', '1'], ['exp null', null], ['exp equals iat', PC.iat], ['exp iat+1ms', PC.iat + 1], ['exp before iat', PC.iat - 5000], ['exp 1.5', PC.iat + 1500.5], ['exp 1e21', 1e21], ['exp 0', 0]] as const) await issue(n, with_({ exp: v }));
await issue('exp missing', without('exp'));
await issue('ver missing', without('ver'));
await issue('ver number', with_({ ver: 3 }));
await issue('ver null', with_({ ver: null }));
await issue('clear unknown claim', with_({ foo: { bar: [1, 2, 3] } }));
await issue('clear claim named iss', with_({ iss: 'forged' }));
await issue('claim names reserved', with_({ _sd: ['x'], cnf: { jwk: { kty: 'OKP' } } }));
await issue('claim cnf disclosable', with_({ cnf: { x: 1 } }), { disclosable: ['cnf', 'action'] });
await issue('unicode + escapes', with_({ action: { verb: 'dé ü😀"\\\n\t\u0001', n: [1e21, 1e-7, 0.1, -0, 123456789012345680000, 5e-324, 1.7976931348623157e308, 100, 2 ** 53] } }));
await issue('lone surrogate', with_({ action: { verb: '\ud800x', k: '\udc00' } }));
await issue('null values', with_({ plan: null, attestation: null, provenance: [null], caution: null }));
await issue('empty values', with_({ action: {}, plan: [], nonce: '' }));
await issue('extra capability claims', with_({ alg: 'ed25519', pq_pk: 'pk', pq_sig: 'sg', threshold: { t: 2 }, zk_compliance: { p: 1 }, bond_ref: 'b', tool_binding: 'tb', rationale_commitment: 'rc', progress_step: 3, prohibition_evidence: [] }));

// ---- hand-built tokens (fixed salts) ----
const mkKey = (s: Uint8Array) => M.importEd25519PrivateKey(s);
const disc = (salt: string, name: string | null, value: any) => b64(JSON.stringify(name === null ? [salt, value] : [salt, name, value]));
async function jwt(payload: any, header: any = { alg: 'EdDSA', typ: 'pca+sd-jwt' }, key: any = iss) {
  const data = `${b64(JSON.stringify(header))}.${b64(JSON.stringify(payload))}`;
  return `${data}.${crypto.sign(null, Buffer.from(data), key).toString('base64url')}`; // hand-rolled so crit / odd headers can be signed
}
const joinSd = (j: string, ds: string[], kb = '') => [j, ...ds].join('~') + '~' + kb;
const BASE = { iss: 'i', sub: 's', aud: 'rs', iat: 1_700_000_000, exp: 1_700_000_600, _sd_alg: 'sha-256' };
async function build(extra: any, ds: string[], over: { sd?: string[]; header?: any; key?: any } = {}) {
  const sd = over.sd ?? ds.map(sha);
  const payload = { ...BASE, ...extra, ...(sd.length ? { _sd: sd } : {}) };
  return joinSd(await jwt(payload, over.header, over.key), ds);
}
const D = (n: number, name: string, v: any) => disc('salt' + n, name, v);
const dA = D(1, 'a', 1), dB = D(2, 'b', { nested: true }), dC = D(3, 'c', 'x');
const TOK = {
  basic: await build({}, [dA, dB]),
  none: await build({}, []),
  decoys: await build({}, [dA], { sd: [sha(dA), sha('decoy1'), sha('decoy2')] }),
  nestedObj: await build({ box: { _sd: [sha(D(4, 'inner', 7))] } }, [D(4, 'inner', 7)], { sd: [] }),
  arrayEls: await build({ list: [{ '...': sha(disc('s5', null, 'one')) }, 'plain', { '...': sha(disc('s6', null, { k: 1 })) }] }, [disc('s5', null, 'one'), disc('s6', null, { k: 1 })], { sd: [] }),
  arrayBadDigest: await build({ list: [{ '...': 5 }] }, [], { sd: [] }),
  arrayWrongShape: await build({ list: [{ '...': sha(D(7, 'x', 1)) }] }, [D(7, 'x', 1)], { sd: [] }),
  objWrongShape: await build({}, [disc('s8', null, 1)], { sd: [sha(disc('s8', null, 1))] }),
  reservedSd: await build({}, [D(9, '_sd', 1)]),
  reservedDots: await build({}, [D(10, '...', 1)]),
  collide: await build({ a: 'clear' }, [dA]),
  criticalIss: await build({}, [D(11, 'iss', 'evil')]),
  criticalAud: await build({}, [D(12, 'aud', 'evil')]),
  criticalExp: await build({}, [D(13, 'exp', 9e9)]),
  criticalCnf: await build({}, [D(14, 'cnf', { jwk: {} })]),
  criticalStatus: await build({}, [D(15, 'status', 1)]),
  nestedCritical: await build({ box: { _sd: [sha(D(16, 'iss', 'x'))] } }, [D(16, 'iss', 'x')], { sd: [] }),
  nameNotString: await build({}, [disc('s17', 5 as any, 1)]),
  saltNotString: await build({}, [JSON.stringify([5, 'a', 1])].map(b64)),
  dupDigest: await build({}, [dA], { sd: [sha(dA), sha(dA)] }),
  sdNotArray: await build({ _sd: 'x' } as any, [], { sd: [] }),
  sdNonStrings: await build({}, [dA], { sd: [sha(dA), 5 as any] }),
  badAlg: await build({ _sd_alg: 'sha-512' }, [dA]),
  algNull: await build({ _sd_alg: null }, [dA]),
  noAlg: await jwt({ iss: 'i', aud: 'rs', iat: 1_700_000_000, exp: 1_700_000_600, _sd: [sha(dA)] }).then((j) => joinSd(j, [dA])),
  topOpaque: await build({ n: 1, o: { p: [1, { q: 2 }] } }, []),
  longName: await build({}, [D(18, 'x'.repeat(200), 'y'.repeat(300))]),
};
const issuerOpt = { issuer_key: PUB_ISS, now: NOW + 100_000 };
const ver = (name: string, sd: any, opt: any = {}) => o.run('verifyPcaSdJwt', name, verifyW, [sd, { ...issuerOpt, ...opt }]);
for (const [n, t] of Object.entries(TOK)) await ver(`token ${n}`, t);
await ver('real full', SD_FULL);
await ver('real full aud ok', SD_FULL, { expected_audience: 'atlas-rs-prod' });
await ver('real full aud wrong', SD_FULL, { expected_audience: 'other' });
await ver('real full aud empty string', SD_FULL, { expected_audience: '' });
await ver('real full aud null', SD_FULL, { expected_audience: null });
await ver('real full aud array', SD_FULL, { expected_audience: ['x', 'atlas-rs-prod'] });
await ver('real full aud number', SD_FULL, { expected_audience: 5 });
await ver('real wrong key', SD_FULL, { issuer_key: PUB_OTHER });
await ver('real key 31 bytes', SD_FULL, { issuer_key: new Uint8Array(31) });
await ver('real expired', SD_FULL, { now: PC.exp + 600_000 });
await ver('real at exp boundary', SD_FULL, { now: Math.ceil(PC.exp / 1000) * 1000 });
await ver('real just before exp', SD_FULL, { now: Math.ceil(PC.exp / 1000) * 1000 - 1 });
await ver('real clock tolerance rescues', SD_FULL, { now: Math.ceil(PC.exp / 1000) * 1000 + 5000, clock_tolerance_sec: 10 });
await ver('real clock tolerance string', SD_FULL, { now: Math.ceil(PC.exp / 1000) * 1000 + 5000, clock_tolerance_sec: '10 seconds' });
await ver('real clock tolerance bad string', SD_FULL, { clock_tolerance_sec: 'ten' });
await ver('real clock tolerance null', SD_FULL, { clock_tolerance_sec: null });
await ver('real clock tolerance object', SD_FULL, { clock_tolerance_sec: {} });
await ver('real now invalid date', SD_FULL, { now: 1e300 });
await ver('real now negative', SD_FULL, { now: -1 });
await ver('real algorithms ES256', SD_FULL, { algorithms: ['ES256'] });
await ver('real algorithms both', SD_FULL, { algorithms: ['ES256', 'EdDSA'] });
await ver('real algorithms empty', SD_FULL, { algorithms: [] });
await ver('real algorithms null', SD_FULL, { algorithms: null });
await ver('real algorithms bad type', SD_FULL, { algorithms: 'EdDSA' });
await ver('real algorithms non-string', SD_FULL, { algorithms: [5] });
await ver('real required present', SD_FULL, { required_disclosures: ['action', 'sig'] });
await ver('real required missing', SD_FULL, { required_disclosures: ['nope'] });
await ver('real required null', SD_FULL, { required_disclosures: null });
await ver('real required non-string', SD_FULL, { required_disclosures: [5] });
await ver('real require_key_binding', SD_FULL, { require_key_binding: true });
await ver('real require_key_binding 0', SD_FULL, { require_key_binding: 0 });
await ver('real key_binding_key without kb', SD_FULL, { key_binding_key: PUB_HOLD });
await ver('real key_binding_key null', SD_FULL, { key_binding_key: null });
await ver('real, presented subsets', await presentW(SD_FULL, ['action', 'grant_ref']));
await ver('real, presented none', await presentW(SD_FULL, []));
await ver('real, presented required missing', await presentW(SD_FULL, ['action']), { required_disclosures: ['cap_chain'] });
// canonical-spelling gate
const aliases = (await import('@atlasauth/pca/strict-jws') as any).compactJwsAliases(SD_FULL.split('~')[0]) as Array<{ name: string; token: string }>;
for (const a of aliases) await ver(`alias ${a.name}`, [a.token, ...SD_FULL.split('~').slice(1)].join('~'));
const [fh, fp, fs] = SD_FULL.split('~')[0].split('.');
const flip = (s: string) => s.slice(0, -2) + (s.at(-2) === 'A' ? 'B' : 'A') + s.at(-1);
await ver('tampered signature', [fh, fp, flip(fs)].join('.') + '~' + SD_FULL.split('~').slice(1).join('~'));
await ver('tampered payload', [fh, flip(fp), fs].join('.') + '~' + SD_FULL.split('~').slice(1).join('~'));
await ver('tampered header', [flip(fh), fp, fs].join('.') + '~' + SD_FULL.split('~').slice(1).join('~'));
const ds_ = SD_FULL.split('~').slice(1, -1);
await ver('disclosure reordered', joinSd(SD_FULL.split('~')[0], [...ds_].reverse()));
await ver('disclosure dropped', joinSd(SD_FULL.split('~')[0], ds_.slice(1)));
await ver('disclosure duplicated', joinSd(SD_FULL.split('~')[0], [...ds_, ds_[0]]));
await ver('disclosure forged', joinSd(SD_FULL.split('~')[0], [disc('forged-salt', 'counter', 9999)]));
await ver('disclosure garbage', joinSd(SD_FULL.split('~')[0], ['!!!']));
await ver('disclosure not json', joinSd(SD_FULL.split('~')[0], [b64('not json')]));
await ver('disclosure wrong arity', joinSd(SD_FULL.split('~')[0], [b64(JSON.stringify(['a']))]));
await ver('disclosure object', joinSd(SD_FULL.split('~')[0], [b64(JSON.stringify({ a: 1 }))]));
await ver('disclosure duplicate keys', joinSd(SD_FULL.split('~')[0], [b64('["s","a",1,"a"]')]));
await ver('disclosure padded', joinSd(SD_FULL.split('~')[0], [ds_[0] + '=']));
await ver('empty disclosure segment', SD_FULL.replace('~', '~~'));
await ver('empty string', '');
await ver('not a string', 5);
await ver('null', null);
await ver('no tilde', SD_FULL.split('~')[0]);
await ver('only tilde', '~');
await ver('empty jwt', '~' + ds_.join('~') + '~');
await ver('three segments no tilde end', SD_FULL.slice(0, -1));
await ver('kb segment garbage', SD_FULL + 'garbage');
await ver('kb segment empty parts', SD_FULL + '..');
// non-EdDSA header, typ, crit
for (const [n, h] of Object.entries({ 'typ other': { alg: 'EdDSA', typ: 'JWT' }, 'no typ': { alg: 'EdDSA' }, 'alg none': { alg: 'none' } })) {
  if (n === 'alg none') continue;
  await ver(`header ${n}`, await build({}, [dA], { header: h }));
}
const unsignedNone = `${b64(JSON.stringify({ alg: 'none' }))}.${b64(JSON.stringify({ ...BASE }))}.`;
await ver('alg none unsigned', joinSd(unsignedNone, []));
await ver('alg HS256 token', joinSd(`${b64(JSON.stringify({ alg: 'HS256' }))}.${b64(JSON.stringify({ ...BASE }))}.${b64('x')}`, []), { algorithms: ['HS256'] });
await ver('crit b64 true', await build({}, [dA], { header: { alg: 'EdDSA', crit: ['b64'], b64: true } }));
await ver('crit unknown', await build({}, [dA], { header: { alg: 'EdDSA', crit: ['zzz'], zzz: 1 } }));
await ver('crit empty', await build({}, [dA], { header: { alg: 'EdDSA', crit: [] } }));
await ver('crit not array', await build({}, [dA], { header: { alg: 'EdDSA', crit: 'b64' } }));
await ver('crit b64 false', await build({}, [dA], { header: { alg: 'EdDSA', crit: ['b64'], b64: false } }));
await ver('crit b64 missing', await build({}, [dA], { header: { alg: 'EdDSA', crit: ['b64'] } }));
await ver('crit b64 non-boolean', await build({}, [dA], { header: { alg: 'EdDSA', crit: ['b64'], b64: 'x' } }));
await ver('header alg missing', joinSd(`${b64(JSON.stringify({ typ: 'x' }))}.${b64(JSON.stringify(BASE))}.${b64('x'.repeat(64))}`, []));
// claim checks
const claimTok = (c: any, ds: string[] = []) => build(c, ds);
await ver('exp past', await claimTok({ exp: 1_699_999_999 }));
await ver('exp string', await claimTok({ exp: '1700000600' }));
await ver('exp null', await claimTok({ exp: null }));
await ver('exp absent', await jwt({ iss: 'i', aud: 'rs', iat: 1_700_000_000 }).then((j) => joinSd(j, [])));
await ver('nbf future', await claimTok({ nbf: 1_700_999_999 }));
await ver('nbf past', await claimTok({ nbf: 1_600_000_000 }));
await ver('nbf string', await claimTok({ nbf: '1' }));
await ver('iat string', await claimTok({ iat: '1' }));
await ver('iat null', await claimTok({ iat: null }));
await ver('aud array', await claimTok({ aud: ['rs', 'x'] }), { expected_audience: 'rs' });
await ver('aud array miss', await claimTok({ aud: ['y', 'x'] }), { expected_audience: 'rs' });
await ver('aud number', await claimTok({ aud: 5 }), { expected_audience: 'rs' });
await ver('aud absent', await jwt({ iss: 'i', iat: 1_700_000_000, exp: 1_700_000_600 }).then((j) => joinSd(j, [])), { expected_audience: 'rs' });
await ver('aud absent no expectation', await jwt({ iss: 'i', iat: 1_700_000_000, exp: 1_700_000_600 }).then((j) => joinSd(j, [])));
await ver('payload array', joinSd(`${b64(JSON.stringify({ alg: 'EdDSA' }))}.${b64('[]')}.${b64('x'.repeat(64))}`, []));

// ---- key binding ----
const HOLD_JWK = M.ed25519PublicJwk(PUB_HOLD);
const kbTok = await issued(PC, { keyBinding: { holderPublicKey: PUB_HOLD } });
const pres = (opt: any, sel: string[] = ['action', 'cap_chain'], base = kbTok) => presentW(base, sel, opt);
const kbOpt = (x: any = {}) => ({ expected_audience: 'atlas-rs-prod', key_binding_key: PUB_HOLD, expected_nonce: 'n1', ...x });
await ver('kb ok', SD_KB_PRES, kbOpt());
await ver('kb ok key as jwk', SD_KB_PRES, kbOpt({ key_binding_key: HOLD_JWK }));
await ver('kb ok no expectations', SD_KB_PRES);
await ver('kb ok require', SD_KB_PRES, { require_key_binding: true });
await ver('kb wrong key expectation', SD_KB_PRES, kbOpt({ key_binding_key: PUB_OTHER }));
await ver('kb key expectation jwk without x', SD_KB_PRES, kbOpt({ key_binding_key: { kty: 'OKP' } }));
await ver('kb wrong nonce', SD_KB_PRES, kbOpt({ expected_nonce: 'zzz' }));
await ver('kb nonce null', SD_KB_PRES, kbOpt({ expected_nonce: null }));
await ver('kb wrong audience', SD_KB_PRES, kbOpt({ expected_audience: 'other' }));
await ver('kb audience only for kb', SD_KB_PRES, { expected_kb_audience: 'atlas-rs-prod' });
await ver('kb audience kb differs', SD_KB_PRES, { expected_audience: 'atlas-rs-prod', expected_kb_audience: 'other' });
await ver('kb audience kb null', SD_KB_PRES, { expected_kb_audience: null });
await ver('kb audience null', SD_KB_PRES, { expected_audience: null });
await ver('kb no nonce signed', await pres({ key_binding: { holder_seed: S_HOLD, audience: 'atlas-rs-prod', iat: 1_700_000_050 } }), kbOpt({ expected_nonce: undefined }));
await ver('kb no nonce signed but expected', await pres({ key_binding: { holder_seed: S_HOLD, audience: 'atlas-rs-prod', iat: 1_700_000_050 } }), kbOpt());
await ver('kb wrong holder key', await pres(KBP({ holder_seed: S_OTHER })), kbOpt({ key_binding_key: undefined }));
await ver('kb aud array not allowed? (string only)', await pres({ key_binding: { holder_seed: S_HOLD, audience: ['atlas-rs-prod'], iat: 1_700_000_050 } }), { expected_audience: 'atlas-rs-prod' });
await ver('kb aud missing', await pres({ key_binding: { holder_seed: S_HOLD, iat: 1_700_000_050 } }));
await ver('kb aud number', await pres({ key_binding: { holder_seed: S_HOLD, audience: 5, iat: 1_700_000_050 } }));
await ver('kb iat string', await pres({ key_binding: { holder_seed: S_HOLD, audience: 'x', iat: '5' } }));
await ver('kb iat old', await pres(KBP({ iat: 1_600_000_000 })), { kb_max_age_sec: 60 });
await ver('kb iat old within window', await pres(KBP({ iat: 1_699_999_990 })), { kb_max_age_sec: 60 });
await ver('kb iat future', await pres(KBP({ iat: 1_700_001_000 })), { kb_max_age_sec: 60 });
await ver('kb iat future with tolerance', await pres(KBP({ iat: 1_700_000_105 })), { kb_max_age_sec: 60, clock_tolerance_sec: 10 });
await ver('kb iat future no maxage', await pres(KBP({ iat: 1_700_001_000 })));
await ver('kb max age null', SD_KB_PRES, { kb_max_age_sec: null });
await ver('kb max age zero', SD_KB_PRES, { kb_max_age_sec: 0 });
await ver('kb with kb_algorithms ES256', SD_KB_PRES, { kb_algorithms: ['ES256'] });
await ver('kb with kb_algorithms empty', SD_KB_PRES, { kb_algorithms: [] });
await ver('kb with kb_algorithms EdDSA/ES256', SD_KB_PRES, { kb_algorithms: ['EdDSA', 'ES256'] });
await ver('kb without cnf', await presentW(SD_FULL, ['action'], KBP()));
await ver('kb sd_hash for other presentation', joinSd(kbTok.split('~')[0], [], SD_KB_PRES.split('~').pop()));
{
  const hd = (await presentW(kbTok, ['action'])).split('~');
  const kbjwt = await jwt({ iat: 1_700_000_050, aud: 'atlas-rs-prod', sd_hash: sha(hd.join('~')) }, { alg: 'EdDSA', typ: 'kb+jwt' }, mkKey(S_HOLD));
  await ver('kb handmade ok', hd.join('~') + kbjwt);
  const noTyp = await jwt({ iat: 1_700_000_050, aud: 'atlas-rs-prod', sd_hash: sha(hd.join('~')) }, { alg: 'EdDSA' }, mkKey(S_HOLD));
  await ver('kb typ missing', hd.join('~') + noTyp);
  const badTyp = await jwt({ iat: 1_700_000_050, aud: 'atlas-rs-prod', sd_hash: sha(hd.join('~')) }, { alg: 'EdDSA', typ: 'JWT' }, mkKey(S_HOLD));
  await ver('kb typ JWT', hd.join('~') + badTyp);
  const noHash = await jwt({ iat: 1_700_000_050, aud: 'atlas-rs-prod' }, { alg: 'EdDSA', typ: 'kb+jwt' }, mkKey(S_HOLD));
  await ver('kb sd_hash missing', hd.join('~') + noHash);
  const exp = await jwt({ iat: 1_700_000_050, exp: 1_600_000_000, aud: 'atlas-rs-prod', sd_hash: sha(hd.join('~')) }, { alg: 'EdDSA', typ: 'kb+jwt' }, mkKey(S_HOLD));
  await ver('kb expired', hd.join('~') + exp);
  const noIat = await jwt({ aud: 'atlas-rs-prod', sd_hash: sha(hd.join('~')) }, { alg: 'EdDSA', typ: 'kb+jwt' }, mkKey(S_HOLD));
  await ver('kb iat missing', hd.join('~') + noIat);
}
// cnf shapes
for (const [n, cnf] of Object.entries({ 'cnf not object': 5, 'cnf no jwk': {}, 'cnf jwk no kty': { jwk: { x: 'a' } }, 'cnf jwk RSA junk': { jwk: { kty: 'RSA', n: 'a', e: 'AQAB' } }, 'cnf jwk oct': { jwk: { kty: 'oct', k: 'a' } }, 'cnf jwk with d': { jwk: { ...HOLD_JWK, d: Buffer.from(S_HOLD).toString('base64url') } },
  'cnf jwk wrong crv': { jwk: { kty: 'OKP', crv: 'Ed448', x: HOLD_JWK.x } }, 'cnf jwk short x': { jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' } }, 'cnf jwk x number': { jwk: { kty: 'OKP', crv: 'Ed25519', x: 5 } } })) {
  const t = await build({ cnf }, [dA]);
  const withKb = async () => { const head = joinSd(t.split('~')[0], [dA]); const k = await jwt({ iat: 1_700_000_050, aud: 'rs', sd_hash: sha(head) }, { alg: 'EdDSA', typ: 'kb+jwt' }, mkKey(S_HOLD)); return head + k; };
  await ver(n, await withKb());
}

// ---- ES256 (ECDSA signatures are randomized: the case replays verification, the signature bytes are not compared) ----
const EC_PRIV: any = ecKit('P-256', 'sdjwt/ec').priv; // label-derived (sha256 of the label, top bit of byte 0 cleared)
const { d: _d, ...EC_PUB } = EC_PRIV;
const ecKey = await J.importJWK(EC_PRIV, 'ES256');
const ecIssued = await new J.SignJWT({ ...BASE, _sd: [sha(dA)], cnf: { jwk: EC_PUB } }).setProtectedHeader({ alg: 'ES256', typ: 'pca+sd-jwt' }).sign(ecKey);
const ecSd = joinSd(ecIssued, [dA]);
await ver('es256 ok', ecSd, { issuer_key: EC_PUB, issuer_jwk_alg: 'ES256', algorithms: ['ES256'] });
await ver('es256 default algorithms refuses', ecSd, { issuer_key: EC_PUB, issuer_jwk_alg: 'ES256' });
await ver('es256 wrong key type', ecSd, { issuer_key: PUB_ISS, algorithms: ['ES256'] });
await ver('es256 jwk with d refused', ecSd, { issuer_key: EC_PRIV, issuer_jwk_alg: 'ES256', algorithms: ['ES256'] });
await ver('es256 jwk alg mismatch', ecSd, { issuer_key: { ...EC_PUB, alg: 'ES384' }, issuer_jwk_alg: 'ES256', algorithms: ['ES256'] });
{
  const head = joinSd(ecIssued, [dA]);
  const kbj = await new J.SignJWT({ iat: 1_700_000_050, aud: 'rs', sd_hash: sha(head) }).setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' }).sign(ecKey);
  await ver('es256 kb ok', head + kbj, { issuer_key: EC_PUB, issuer_jwk_alg: 'ES256', algorithms: ['ES256'], kb_algorithms: ['ES256'], expected_audience: 'rs' });
  await ver('es256 kb default alg refuses', head + kbj, { issuer_key: EC_PUB, issuer_jwk_alg: 'ES256', algorithms: ['ES256'] });
  await ver('es256 kb key expectation x', head + kbj, { issuer_key: EC_PUB, issuer_jwk_alg: 'ES256', algorithms: ['ES256'], kb_algorithms: ['ES256'], key_binding_key: EC_PUB });
}

// ---- present ----
const pr = (name: string, sd: any, sel: any, opt?: any) => o.run('present', name, presentW, opt === undefined ? [sd, sel] : [sd, sel, opt]);
const NESTED = TOK.arrayEls, OBJ = TOK.nestedObj;
for (const [n, sel] of Object.entries({ 'none': [], 'action': ['action'], 'two': ['action', 'grant_ref'], 'chain+plan': ['cap_chain', 'plan'], 'all': [...M.PCA_CAPABILITY_CLAIMS], 'unknown': ['nope'], 'with non-strings': [5, null, 'action', ['action']], 'dupes': ['action', 'action'], 'null': null, 'string': 'action', 'sd claim name': ['_sd'] })) await pr(`real ${n}`, SD_FULL, sel);
await pr('real number selector', SD_FULL, 5);
await pr('real object selector', SD_FULL, {});
await pr('real kb', SD_KB, ['action', 'cap_chain'], KBP());
await pr('real kb no nonce', SD_KB, ['action'], { key_binding: { holder_seed: S_HOLD, audience: 'a', iat: 5 } });
await pr('real kb nonce null', SD_KB, ['action'], { key_binding: { holder_seed: S_HOLD, audience: 'a', iat: 5, nonce: null } });
await pr('real kb nonce empty', SD_KB, ['action'], { key_binding: { holder_seed: S_HOLD, audience: 'a', iat: 5, nonce: '' } });
await pr('real kb alg EdDSA', SD_KB, ['action'], KBP({ alg: 'EdDSA' }));
await pr('real kb alg ES256 refused', SD_KB, ['action'], KBP({ alg: 'ES256' }));
await pr('real kb alg HS256 refused', SD_KB, ['action'], KBP({ alg: 'HS256' }));
await pr('real kb audience missing', SD_KB, ['action'], { key_binding: { holder_seed: S_HOLD, iat: 5 } });
await pr('real kb iat 0', SD_KB, ['action'], KBP({ iat: 0 }));
await pr('real kb iat fraction', SD_KB, ['action'], KBP({ iat: 1.5 }));
await pr('real kb on kb-bearing input (stripped)', SD_KB_PRES, ['action'], KBP({ nonce: 'n2' }));
await pr('real kb-bearing input, no new kb', SD_KB_PRES, ['action', 'plan']);
await pr('real options empty', SD_FULL, ['action'], {});
await pr('nested array select list', NESTED, ['list']);
await pr('nested array select none', NESTED, []);
await pr('nested object select box', OBJ, ['box']);
await pr('nested object select inner', OBJ, ['inner']);
await pr('basic select a', TOK.basic, ['a']);
await pr('basic select b', TOK.basic, ['b']);
await pr('decoys select a', TOK.decoys, ['a']);
await pr('dup digest select a', TOK.dupDigest, ['a']);
await pr('collide select a', TOK.collide, ['a']);
await pr('arrayBadDigest select list', TOK.arrayBadDigest, ['list']);
await pr('arrayWrongShape select list', TOK.arrayWrongShape, ['list']);
await pr('objWrongShape select x', TOK.objWrongShape, ['x']);
await pr('saltNotString select', TOK.saltNotString, ['a']);
await pr('no disclosures', TOK.none, ['a']);
await pr('garbage disclosure unselected is dropped', joinSd(TOK.basic.split('~')[0], ['!!!', ...TOK.basic.split('~').slice(1, -1)]), ['a']);
await pr('garbage disclosure referenced by nothing', joinSd(TOK.none.split('~')[0], ['garbage']), []);
await pr('same digest twice in input', joinSd(TOK.basic.split('~')[0], [dA, dA, dB]), ['a', 'b']);
for (const [n, sd] of Object.entries({ 'empty': '', 'not a string': 5, 'null': null, 'no tilde': TOK.basic.split('~')[0], 'only tilde': '~', 'empty disclosure seg': TOK.basic.replace('~', '~~'), 'bad jwt': 'a.b.c~', 'jwt 2 parts': 'a.b~', 'trailing garbage kb': TOK.basic + 'garbage', 'alias padded': TOK.basic.replace('.', '=.') })) await pr(`input ${n}`, sd, ['a']);
{
  const [h, p, s] = TOK.basic.split('~')[0].split('.');
  const badPayload = `${h}.${b64('not json')}.${s}~`;
  await pr('payload not json', badPayload, ['a']);
  await pr('payload array', `${h}.${b64('[1]')}.${s}~`, ['a']);
  await pr('payload string', `${h}.${b64('"x"')}.${s}~`, ['a']);
}

// ---- verifyRecovered ----
const vOk = async (sd: string, key = PUB_ISS) => { const r = await verifyW(sd, { issuer_key: key, now: NOW + 100_000 }); if (!r.ok) throw new Error('fixture: ' + r.reason); return J_(r); };
const rec = (name: string, res: any, opt: any) => o.run('verifyRecovered', name, recoveredW, [res, opt]);
const CORE = { grant: J_(F.grant), audience: 'atlas-rs-prod', now: NOW + 100_000, insecure_skip_plan_root_check: true };
const vFull = await vOk(SD_FULL);
await rec('accepts untouched', vFull, CORE);
await rec('accepts sub-second lifetime', await vOk(await issued(J_(F2.pcActn))), { ...CORE, grant: J_(F2.grant) });
await rec('accepts presented minimal claims', await vOk(await presentW(SD_FULL, ['action', 'cap_chain', 'plan', 'sig', 'grant_ref', 'counter'])), CORE);
await rec('sig withheld', await vOk(await presentW(SD_FULL, ['action', 'cap_chain', 'plan', 'grant_ref', 'counter'])), CORE);
for (const k of ['action', 'cap_chain', 'plan', 'grant_ref', 'counter']) await rec(`${k} withheld`, await vOk(await presentW(SD_FULL, ['action', 'cap_chain', 'plan', 'sig', 'grant_ref', 'counter'].filter((x) => x !== k))), CORE);
await rec('wrong audience', vFull, { ...CORE, audience: 'other' });
await rec('audience omitted', vFull, { grant: CORE.grant, now: CORE.now, insecure_skip_plan_root_check: true });
await rec('audience null', vFull, { ...CORE, audience: null });
await rec('wrong stored grant', vFull, { ...CORE, grant: J_(OTHER.grant) });
await rec('plan root not authorized (no opt-out)', vFull, { grant: CORE.grant, audience: CORE.audience, now: CORE.now });
await rec('plan root opt-out false', vFull, { ...CORE, insecure_skip_plan_root_check: false });
await rec('expired by core clock', vFull, { ...CORE, now: PC.exp + 10_000_000 });
await rec('tampered action re-signed', await vOk(await issued({ ...PC, action: { ...PC.action, resource: 'session:other' } })), CORE);
const claimsMinus = (k: string) => { const c = { ...vFull.claims }; delete c[k]; return { ...vFull, claims: c }; };
await rec('iat_ms missing', claimsMinus('iat_ms'), CORE);
await rec('exp_ms missing', claimsMinus('exp_ms'), CORE);
await rec('iat_ms string', { ...vFull, claims: { ...vFull.claims, iat_ms: '1' } }, CORE);
await rec('iat_ms skew', { ...vFull, claims: { ...vFull.claims, iat_ms: vFull.claims.iat_ms + 5000 } }, CORE);
await rec('exp_ms skew', { ...vFull, claims: { ...vFull.claims, exp_ms: vFull.claims.exp_ms + 5000 } }, CORE);
await rec('exp_ms within same second', { ...vFull, claims: { ...vFull.claims, exp_ms: vFull.claims.exp_ms - 1 } }, CORE);
await rec('aud not a string', { ...vFull, processed: { ...vFull.processed, aud: ['a'] } }, CORE);
await rec('cap_chain not array', { ...vFull, claims: { ...vFull.claims, cap_chain: {} } }, CORE);
await rec('cap_chain empty', { ...vFull, claims: { ...vFull.claims, cap_chain: [] } }, CORE);
await rec('iss mismatch', await vOk(await issued(PC, { iss: 'someone-else' })), CORE);
await rec('sub mismatch', await vOk(await issued(PC, { sub: 'someone-else' })), CORE);
await rec('claims tampered action', { ...vFull, claims: { ...vFull.claims, action: { ...vFull.claims.action, resource: 'session:x' } } }, CORE);
await rec('claims tampered sig', { ...vFull, claims: { ...vFull.claims, sig: 'AAAA' } }, CORE);
await rec('ver tampered', { ...vFull, processed: { ...vFull.processed, ver: '99' } }, CORE);

refWrite(o, 'sdjwt');
