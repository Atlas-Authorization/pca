// Oracle: @atlasauth/pca-vc (did:key + base58btc, the agent-passport SD-JWT VC, RFC 9421 / Web Bot Auth request signatures).
// Writes out/ref-vc.json.gz. Keys are passed as seeds / raw public bytes ({"$bytes"}); salts and the clock are deterministic
// (randomBytes replaced, `Date` pinned to NOW before the reference loads), so passportToVC output is compared after a
// normalization (header, payload without the digest list, [name, value] disclosures, digest agreement, verify result).
// A throw only requires the native to refuse.
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { Oracle, refWrite } from './lib.mjs';

const NOW = 1_700_000_100_000;
let ctr = 0;
(crypto as any).randomBytes = (n: number) => crypto.createHash('sha256').update('vc-oracle-salt/' + ctr++).digest().subarray(0, n);
syncBuiltinESMExports();
const RealDate = Date;
class FakeDate extends RealDate {
  constructor(...a: any[]) { if (a.length === 0) super(NOW); else super(...(a as [any])); }
  static now() { return NOW; }
}
(globalThis as any).Date = FakeDate;

const M: any = await import('../../../packages/pca-vc/src/index.ts');
const SJ: any = await import('@atlasauth/pca/strict-jws');
const o = new Oracle('vc', 'tools/pca-audit/oracles/vc.mts', 'TS-reference oracle for @atlasauth/pca-vc.');

const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const privOf = (seed: Uint8Array) => crypto.createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
const pubKeyOf = (raw: Uint8Array) => crypto.createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(raw)]), format: 'der', type: 'spki' });
const rawPub = (seed: Uint8Array) => new Uint8Array(crypto.createPublicKey(privOf(seed)).export({ format: 'der', type: 'spki' }).subarray(12));
const seed = (n: number) => new Uint8Array(32).fill(n);
const S1 = seed(1), S2 = seed(2);
const P1 = rawPub(S1), P2 = rawPub(S2);
const fromJ = (v: any): any => {
  if (v === null || typeof v !== 'object' || v instanceof Uint8Array) return v;
  if (Array.isArray(v)) return v.map(fromJ);
  const ks = Object.keys(v);
  if (ks.length === 1 && ks[0] === '$bytes') return new Uint8Array(Buffer.from(v.$bytes, 'base64url'));
  return Object.fromEntries(ks.map((k) => [k, fromJ(v[k])]));
};
const sha = (s: string) => crypto.createHash('sha256').update(s, 'ascii').digest('base64url');
const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64url');

// ---- base58btc / did:key ----
const hex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));
const ascii = (s: string) => new Uint8Array(Buffer.from(s, 'latin1'));
const BYTES: Record<string, Uint8Array> = {
  empty: new Uint8Array(0), zero: Uint8Array.of(0), zeros2: Uint8Array.of(0, 0), 'yes mani': ascii('yes mani !'), 'lead zero': Uint8Array.from([0, ...ascii('yes mani !')]),
  'lead zeros2': Uint8Array.from([0, 0, ...ascii('yes mani !')]), ff: Uint8Array.of(0xff), '0x00ff': Uint8Array.of(0, 0xff), key32: P1, key32b: P2, 'ed multicodec': Uint8Array.from([0xed, 1, ...P1]),
  long: new Uint8Array(200).map((_, i) => (i * 7 + 3) & 0xff), 'all 0xff 32': new Uint8Array(32).fill(0xff), 'zeros 32': new Uint8Array(32),
};
for (const [n, b] of Object.entries(BYTES)) {
  await o.run('base58btcEncode', n, (x: any) => M.base58btcEncode(fromJ(x)), [b]);
  await o.run('base58btcDecode', `roundtrip ${n}`, M.base58btcDecode, [M.base58btcEncode(b)]);
}
for (const [n, s] of Object.entries({ 'zero char': '0abc', 'O': 'Oabc', 'I': 'Iabc', 'l': 'labc', space: 'ab c', plus: 'ab+c', empty: '', ones: '111', 'one char': '1', 'z': 'z', 'unicode': 'é', 'max len': '2'.repeat(1024), 'over max': '2'.repeat(1025), 'max ones': '1'.repeat(1024),
  'padding': 'abc=', 'newline': 'abc\n' })) await o.run('base58btcDecode', n, M.base58btcDecode, [s]);
await o.run('base58btcDecode', 'type null', M.base58btcDecode, [null]);
for (const [n, b] of Object.entries({ key1: P1, key2: P2, zeros: new Uint8Array(32), ff: new Uint8Array(32).fill(0xff), 'len 31': new Uint8Array(31), 'len 33': new Uint8Array(33), empty: new Uint8Array(0) })) await o.run('didKeyFromEd25519', n, (x: any) => M.didKeyFromEd25519(fromJ(x)), [b]);
const DIDS = [M.didKeyFromEd25519(P1), M.didKeyFromEd25519(P2), M.didKeyFromEd25519(new Uint8Array(32)), M.didKeyFromEd25519(new Uint8Array(32).fill(0xff)),
  'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', 'did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP'];
for (const [i, d] of DIDS.entries()) await o.run('ed25519FromDidKey', `valid ${i}`, M.ed25519FromDidKey, [d]);
const D0 = DIDS[0];
for (const [n, d] of Object.entries({ 'wrong prefix': 'did:web:example.com', 'no z': 'did:key:6Mk', 'empty body': 'did:key:z', 'uppercase prefix': 'DID:KEY:z6Mk', 'too long': D0 + 'a'.repeat(30), 'exactly 64 body': 'did:key:z' + '2'.repeat(64), 'bad char': D0.slice(0, -1) + '0',
  'secp256k1': 'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme', 'p256': 'did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169', 'short': 'did:key:z6Mk', 'trailing space': D0 + ' ', 'empty': '', 'method only': 'did:key:', 'wrong multicodec': 'did:key:z' + M.base58btcEncode(Uint8Array.from([0xed, 0x02, ...P1])), 'wrong len 33': 'did:key:z' + M.base58btcEncode(Uint8Array.from([0xed, 0x01, ...P1.slice(1)])), 'len 35': 'did:key:z' + M.base58btcEncode(Uint8Array.from([0xed, 0x01, ...P1, 0])) }))
  await o.run('ed25519FromDidKey', n, M.ed25519FromDidKey, [d]);
for (const bad of [null, 5, [], {}]) await o.run('ed25519FromDidKey', `type ${JSON.stringify(bad)}`, M.ed25519FromDidKey, [bad]);

// ---- constants + context ----
await o.run('constants', 'all', () => ({ VC_CONTEXT: M.VC_CONTEXT, AGENT_PASSPORT_CONTEXT: M.AGENT_PASSPORT_CONTEXT, AGENT_PASSPORT_VC_TYPE: M.AGENT_PASSPORT_VC_TYPE, AGENT_PASSPORT_CONTEXT_DIGEST: M.AGENT_PASSPORT_CONTEXT_DIGEST, AGENT_PASSPORT_CONTEXT_DOC: M.AGENT_PASSPORT_CONTEXT_DOC }), []);
for (const [n, i] of Object.entries({ iri: M.AGENT_PASSPORT_CONTEXT, 'iri slash': M.AGENT_PASSPORT_CONTEXT + '/', other: 'https://example.com/x', vc: M.VC_CONTEXT, empty: '', upper: M.AGENT_PASSPORT_CONTEXT.toUpperCase(), 'null': null, number: 5 }))
  await o.run('resolveAgentPassportContext', n, M.resolveAgentPassportContext, [i]);

// ---- passportToVC (normalized) ----
const PASSPORT = { id: 'passport-1', model_id: 'model-x', operator: 'acme', hardware_rooted: true, issued_at: 1_700_000_000, weights_measured: true, weights_digest: 'sha256:aa', system_prompt_digest: 'sha256:bb', tool_manifest_digest: 'sha256:cc', runtime_measurement: 'sha256:dd' };
const dec = (x: string) => JSON.parse(Buffer.from(x, 'base64url').toString('utf8'));
async function normVc(sd: string) {
  const parts = sd.split('~'), ds = parts.slice(1, -1);
  const [h, p] = parts[0].split('.').slice(0, 2).map(dec);
  const sdl = [...(p.vc?.credentialSubject?._sd ?? [])].sort();
  const cs = p.vc?.credentialSubject;
  if (cs) delete cs._sd;
  let verified = false;
  try { await M.verifyPassportVC(sd, pubKeyOf(P1)); verified = true; } catch { /* stays false */ }
  const disc = ds.map(dec) as any[];
  return { end: parts[parts.length - 1], header: h, payload: p, n: ds.length, digestsOk: JSON.stringify(ds.map(sha).sort()) === JSON.stringify(sdl), disclosures: disc.map((d) => [d[1], d[2]]).sort((a, b) => (a[0] < b[0] ? -1 : 1)), verified };
}
async function pvcW(passport: any, a: any) {
  const m: any = { issuerKey: privOf(fromJ(a.issuer_seed)) };
  if ('issuer_did' in a) m.issuerDid = a.issuer_did;
  if ('subject_did' in a) m.subjectDid = a.subject_did;
  if ('ttl_sec' in a) m.ttlSec = a.ttl_sec;
  return normVc(await M.passportToVC(passport, m));
}
const pvc = (n: string, p: any, a: any = {}) => o.run('passportToVC', n, pvcW, [p, { issuer_seed: S1, issuer_did: D0, subject_did: DIDS[1], ...a }]);
const wo = (k: string) => { const c: any = { ...PASSPORT }; delete c[k]; return c; };
await pvc('full', PASSPORT);
await pvc('ttl', PASSPORT, { ttl_sec: 600 });
await pvc('ttl zero', PASSPORT, { ttl_sec: 0 });
await pvc('ttl negative', PASSPORT, { ttl_sec: -5 });
await pvc('ttl fraction', PASSPORT, { ttl_sec: 1.5 });
await pvc('ttl null', PASSPORT, { ttl_sec: null });
await pvc('ttl string refused', PASSPORT, { ttl_sec: 'x' });
await pvc('ttl true', PASSPORT, { ttl_sec: true });
for (const f of ['weights_digest', 'system_prompt_digest', 'tool_manifest_digest', 'runtime_measurement', 'weights_measured']) await pvc(`without ${f}`, wo(f));
await pvc('no digests', { id: 'p', model_id: 'm', operator: 'o', hardware_rooted: false, issued_at: 5 });
await pvc('null digest', { ...PASSPORT, weights_digest: null });
await pvc('numeric digest', { ...PASSPORT, weights_digest: 5 });
await pvc('unicode', { ...PASSPORT, operator: 'ac meé', weights_digest: 'x"\\\n\ud800' });
await pvc('extra passport fields ignored', { ...PASSPORT, extra: 1, attestation: { a: 1 } });
await pvc('missing id', wo('id'));
await pvc('missing issued_at', wo('issued_at'));
await pvc('bool as number', { ...PASSPORT, issued_at: true });
await pvc('no dids', PASSPORT, { issuer_did: undefined, subject_did: undefined });
await pvc('issuer did only', PASSPORT, { subject_did: undefined });
await pvc('passport null', null);
await pvc('passport array', []);
await pvc('bad seed', PASSPORT, { issuer_seed: new Uint8Array(31) });

// ---- verifyPassportVC (hand-built + issued tokens) ----
async function rawJwt(payload: any, header: any = { alg: 'EdDSA', typ: 'vc+sd-jwt' }, seedKey: Uint8Array = S1) {
  const data = `${b64(JSON.stringify(header))}.${b64(JSON.stringify(payload))}`;
  return `${data}.${crypto.sign(null, Buffer.from(data), privOf(seedKey)).toString('base64url')}`;
}
const disc = (salt: string, name: any, value: any) => b64(JSON.stringify([salt, name, value]));
const DW = disc('s1', 'weights_digest', 'sha256:aa'), DS = disc('s2', 'system_prompt_digest', 'sha256:bb'), DT = disc('s3', 'tool_manifest_digest', 'sha256:cc'), DR = disc('s4', 'runtime_measurement', 'sha256:dd');
const CS = { id: DIDS[1], passport_id: 'passport-1', model_id: 'model-x', operator: 'acme', hardware_rooted: true, issued_at: 1_700_000_000, weights_measured: false };
const CTX = [M.VC_CONTEXT, M.AGENT_PASSPORT_CONTEXT], TYPES = ['VerifiableCredential', 'AgentPassportCredential'];
async function tok(opt: { cs?: any; vc?: any; top?: any; ds?: string[]; sd?: string[] | null; header?: any; key?: Uint8Array; sdAlg?: any } = {}) {
  const ds = opt.ds ?? [DW, DS, DT, DR];
  const sd = opt.sd === undefined ? ds.map(sha) : opt.sd;
  const cs = { ...CS, ...(sd === null ? {} : { _sd: sd }), ...(opt.cs ?? {}) };
  for (const k of Object.keys(cs)) if (cs[k] === undefined) delete cs[k];
  const vc = { '@context': CTX, type: TYPES, credentialSubject: cs, ...(opt.vc ?? {}) };
  const payload: any = { vc, _sd_alg: opt.sdAlg === undefined ? 'sha-256' : opt.sdAlg, iss: DIDS[0], sub: DIDS[1], iat: 1_700_000_000, exp: 1_700_000_100 + 1000, ...(opt.top ?? {}) };
  for (const k of Object.keys(payload)) if (payload[k] === undefined) delete payload[k];
  return [await rawJwt(payload, opt.header, opt.key), ...ds].join('~') + '~';
}
const vpw = (vc: any, key: any, opt?: any) => M.verifyPassportVC(vc, pubKeyOf(fromJ(key)), opt);
const vp = (n: string, vc: any, opt?: any, key: Uint8Array = P1) => o.run('verifyPassportVC', n, vpw, opt === undefined ? [vc, key] : [vc, key, opt]);
const ISSUED = await M.passportToVC(PASSPORT, { issuerKey: privOf(S1), issuerDid: DIDS[0], subjectDid: DIDS[1], ttlSec: 3600 });
const ISSUED_NOTTL = await M.passportToVC(PASSPORT, { issuerKey: privOf(S1), issuerDid: DIDS[0], subjectDid: DIDS[1] });
await vp('issued ttl', ISSUED);
await vp('issued no ttl', ISSUED_NOTTL);
await vp('issued expected issuer ok', ISSUED, { expectedIssuerDid: DIDS[0] });
await vp('issued expected issuer wrong', ISSUED, { expectedIssuerDid: DIDS[1] });
await vp('issued expected issuer null', ISSUED, { expectedIssuerDid: null });
await vp('issued expected issuer empty', ISSUED, { expectedIssuerDid: '' });
await vp('issued wrong key', ISSUED, undefined, P2);
await vp('issued no digests', await M.passportToVC({ id: 'p', model_id: 'm', operator: 'o', hardware_rooted: false, issued_at: 5 }, { issuerKey: privOf(S1), issuerDid: DIDS[0], subjectDid: DIDS[1] }));
await vp('basic', await tok());
await vp('expired by one second', await tok({ top: { exp: 1_700_000_100 } }));
await vp('exp just in future', await tok({ top: { exp: 1_700_000_101 } }));
await vp('exp past', await tok({ top: { exp: 1_600_000_000 } }));
await vp('nbf future', await tok({ top: { nbf: 1_700_000_200 } }));
await vp('no exp', await tok({ top: { exp: undefined } }));
for (const k of [[], [DW], [DS, DR], [DR, DT, DS, DW]]) await vp(`disclosures ${k.length} ${k.map((x) => x.slice(0, 4)).join('')}`, await tok({ ds: k, sd: [DW, DS, DT, DR].map(sha) }));
await vp('forged disclosure', await tok({ ds: [disc('x', 'weights_digest', 'EVIL')], sd: [DW, DS, DT, DR].map(sha) }));
await vp('duplicate disclosure', await tok({ ds: [DW, DW] }));
await vp('two disclosures same name', await tok({ ds: [DW, disc('s9', 'weights_digest', 'other')], sd: [sha(DW), sha(disc('s9', 'weights_digest', 'other'))] }));
await vp('unexpected claim name', await tok({ ds: [disc('s', 'operator', 'evil')], sd: [sha(disc('s', 'operator', 'evil'))] }));
await vp('name not a string', await tok({ ds: [disc('s', 5, 'x')], sd: [sha(disc('s', 5, 'x'))] }));
await vp('value not a string', await tok({ ds: [disc('s', 'weights_digest', 5)], sd: [sha(disc('s', 'weights_digest', 5))] }));
await vp('wrong arity', await tok({ ds: [b64(JSON.stringify(['s', 'weights_digest']))], sd: [sha(b64(JSON.stringify(['s', 'weights_digest'])))] }));
await vp('disclosure not json', await tok({ ds: [b64('nope')], sd: [sha(b64('nope'))] }));
await vp('disclosure object', await tok({ ds: [b64('{"a":1}')], sd: [sha(b64('{"a":1}'))] }));
await vp('disclosure padded', await tok({ ds: [DW + '='], sd: [sha(DW + '=')] }));
await vp('disclosure garbage chars', await tok({ ds: ['!!'] }));
await vp('disclosure alias std alphabet', await tok({ ds: [disc('s?>', 'weights_digest', 'sha256:~~').replace(/-/g, '+').replace(/_/g, '/')] }));
await vp('disclosure lenient json (nan)', await tok({ ds: [b64('["s","weights_digest",NaN]')], sd: [sha(b64('["s","weights_digest",NaN]'))] }));
await vp('disclosure duplicate keys array', await tok({ ds: [b64('["s","weights_digest","a","b"]')], sd: [sha(b64('["s","weights_digest","a","b"]'))] }));
await vp('sd not array', await tok({ cs: { _sd: 'x' }, ds: [DW] }));
await vp('sd with non-strings', await tok({ ds: [DW], sd: [5 as any, sha(DW)] as any }));
await vp('sd absent no disclosures', await tok({ ds: [], sd: null }));
await vp('sd absent with disclosure', await tok({ ds: [DW], sd: null }));
await vp('empty segments tolerated', (await tok()).replace('~', '~~'));
await vp('empty segment middle', (await tok()).replace(/~/g, '~~'));
await vp('trailing no tilde', (await tok()).slice(0, -1));
await vp('empty string', '');
await vp('not a string', 5);
await vp('just tilde', '~');
await vp('wrong typ', await tok({ header: { alg: 'EdDSA', typ: 'JWT' } }));
await vp('no typ', await tok({ header: { alg: 'EdDSA' } }));
await vp('alg ES256 header', await tok({ header: { alg: 'ES256', typ: 'vc+sd-jwt' } }));
await vp('alg none', `${b64(JSON.stringify({ alg: 'none', typ: 'vc+sd-jwt' }))}.${b64(JSON.stringify({ vc: {} }))}.${DW}~`);
await vp('crit header', await tok({ header: { alg: 'EdDSA', typ: 'vc+sd-jwt', crit: ['b64'], b64: true } }));
await vp('missing vc', await tok({ vc: { '@context': undefined, type: undefined, credentialSubject: undefined } }));
for (const [n, vc] of Object.entries({
  'ctx missing': { '@context': undefined }, 'ctx not array': { '@context': 'x' }, 'ctx empty': { '@context': [] }, 'ctx one': { '@context': [M.VC_CONTEXT] }, 'ctx swapped': { '@context': [M.AGENT_PASSPORT_CONTEXT, M.VC_CONTEXT] },
  'ctx three': { '@context': [M.VC_CONTEXT, M.AGENT_PASSPORT_CONTEXT, 'https://evil.example/ctx'] }, 'ctx unknown second': { '@context': [M.VC_CONTEXT, 'https://evil.example/ctx'] }, 'ctx object second': { '@context': [M.VC_CONTEXT, { x: 1 }] },
  'type missing': { type: undefined }, 'type not array': { type: 'AgentPassportCredential' }, 'type lacks passport': { type: ['VerifiableCredential'] }, 'type lacks vc': { type: ['AgentPassportCredential'] }, 'type extra ok': { type: [...TYPES, 'Extra'] },
  'subject missing': { credentialSubject: undefined }, 'subject array': { credentialSubject: [] }, 'subject null': { credentialSubject: null },
})) await vp(`vc ${n}`, await tok({ vc: vc as any }));
for (const [n, cs] of Object.entries({ 'sd_alg inside subject': { _sd_alg: 'sha-256' }, 'no passport_id': { passport_id: undefined }, 'passport_id number': { passport_id: 5 }, 'no model_id': { model_id: undefined }, 'no operator': { operator: undefined }, 'operator null': { operator: null },
  'hardware_rooted string': { hardware_rooted: 'true' }, 'no hardware_rooted': { hardware_rooted: undefined }, 'issued_at string': { issued_at: '1' }, 'issued_at bool': { issued_at: true }, 'no issued_at': { issued_at: undefined }, 'weights_measured string': { weights_measured: 'x' }, 'weights_measured null': { weights_measured: null }, 'no weights_measured': { weights_measured: undefined },
  'no id': { id: undefined }, 'id number': { id: 5 }, 'id differs from sub': { id: 'did:other' } })) await vp(`subject ${n}`, await tok({ cs: cs as any }));
for (const [n, top] of Object.entries({ 'vc string': { vc: 'x' }, 'vc array': { vc: [] }, 'vc null': { vc: null }, 'vc absent': { vc: undefined }, 'sd_alg sha-512': { _sd_alg: 'sha-512' }, 'sd_alg null': { _sd_alg: null }, 'sd_alg absent': { _sd_alg: undefined }, 'iss missing': { iss: undefined }, 'iss number': { iss: 5 }, 'sub missing': { sub: undefined }, 'sub differs': { sub: 'did:other' }, 'sub number': { sub: 5 }, 'iat string': { iat: 'x' }, 'exp string': { exp: 'x' } })) await vp(`top ${n}`, await tok({ top: top as any }));
// canonical gate on the jwt
const T0 = await tok();
for (const a of SJ.compactJwsAliases(T0.split('~')[0]) as Array<{ name: string; token: string }>) await vp(`alias ${a.name}`, [a.token, ...T0.split('~').slice(1)].join('~'));
{
  const [h, p, s] = T0.split('~')[0].split('.');
  const flip = (x: string) => x.slice(0, -2) + (x.at(-2) === 'A' ? 'B' : 'A') + x.at(-1);
  await vp('tampered signature', [h, p, flip(s)].join('.') + '~' + T0.split('~').slice(1).join('~'));
  await vp('tampered payload', [h, flip(p), s].join('.') + '~' + T0.split('~').slice(1).join('~'));
  await vp('empty signature segment', [h, p, ''].join('.') + '~' + T0.split('~').slice(1).join('~'));
}

// ---- RFC 9421 ----
const REQ = { method: 'POST', url: 'https://api.acme.com/v1/orders?ref=42', headers: { host: 'api.acme.com', 'content-type': 'application/json' } };
async function signW(a: any) {
  const m: any = { method: a.method, url: a.url, headers: a.headers, key: privOf(fromJ(a.key)), keyid: a.keyid };
  if ('created' in a) m.created = a.created;
  if ('signature_agent' in a) m.signatureAgent = a.signature_agent;
  return M.signRequestMessage(m);
}
const sg = (n: string, a: any) => o.run('signRequestMessage', n, signW, [{ ...REQ, key: S1, keyid: 'k1', created: 1_700_000_000, ...a }]);
await sg('basic', {});
await sg('method lower', { method: 'post' });
await sg('get no headers', { method: 'GET', headers: {} });
await sg('host derived', { headers: { 'content-type': 'x' } });
await sg('host explicit differs', { headers: { host: 'proxy.internal' } });
await sg('header case + trim', { headers: { 'X-B': ' b ', 'x-a': 'a', Host: 'API.acme.com' } });
await sg('header case collision', { headers: { 'X-A': '1', 'x-a': '2' } });
await sg('header value tabs', { headers: { 'x-a': '\t a  ' } });
await sg('header sort order', { headers: { b: '1', a: '2', B: '3', _x: '4', 'x-y': '5', '1': '6' } });
await sg('signature agent', { signature_agent: 'https://agent.example/.well-known/keys' });
await sg('signature agent empty', { signature_agent: '' });
await sg('signature agent null', { signature_agent: null });
await sg('signature agent number', { signature_agent: 5 });
await sg('signature agent overrides header', { signature_agent: 'https://a.example', headers: { 'signature-agent': '"https://other"' } });
await sg('created zero', { created: 0 });
await sg('created fraction', { created: 1.5 });
await sg('created large', { created: 1e21 });
await sg('created null falls back to clock', { created: null });
await sg('created negative', { created: -5 });
await sg('created string', { created: '5' });
await sg('keyid quotes', { keyid: 'a"b' });
await sg('keyid did', { keyid: D0 });
await sg('keyid empty', { keyid: '' });
await sg('unicode value', { headers: { 'x-u': 'café 😀' } });
await sg('lone surrogate value', { headers: { 'x-u': 'a\ud800b' } });
await sg('header value non-string', { headers: { 'x-n': 5 } });
await sg('header value null', { headers: { 'x-n': null } });
await sg('headers null', { headers: null });
await sg('seed 31 bytes', { key: new Uint8Array(31) });
for (const [n, u] of Object.entries({ 'port default dropped': 'https://API.Example.com:443/p', 'port http default': 'http://a.example:80/p', 'port non default': 'https://a.example:8443/p', 'userinfo': 'https://u:p@a.example/p', 'ipv4': 'https://1.2.3.4:8080/p', 'ipv6': 'https://[::1]:8443/p',
  'ipv6 default port': 'https://[2001:DB8::1]:443/p', 'upper scheme': 'HTTPS://A.B/p', 'trailing dot': 'https://a.example./p', 'idn': 'https://münchen.de/p', 'query only': 'https://a.example?x=1', 'fragment': 'https://a.example/p#f', 'ws': 'ws://a.example:80/p', 'ftp': 'ftp://a.example:21/p',
  'custom scheme': 'foo://Host:99/p', 'port zero': 'https://a.example:0/p', 'port leading zeros': 'https://a.example:0443/p', 'port too big': 'https://a.example:65536/p', 'port empty': 'https://a.example:/p', 'port letters': 'https://a.example:x/p', 'no scheme': 'a.example/p', 'empty': '', 'no host': 'https://',
  'space host': 'https://a b.example/p', 'extra slashes': 'https:///a.example/p', 'no slashes': 'https:a.example/p' }))
  await sg(`url ${n}`, { url: u, headers: { 'x-a': '1' } });

// verifyRequestSignature
const keyOf = (s: Uint8Array) => ({ priv: privOf(s), pub: rawPub(s) });
async function verW(a: any, key: any) {
  const m: any = {};
  const map: Record<string, string> = { method: 'method', url: 'url', headers: 'headers', signature_input: 'signatureInput', signature: 'signature', signature_agent: 'signatureAgent', required_components: 'requiredComponents', max_age_sec: 'maxAgeSec', now_sec: 'nowSec' };
  for (const [k, c] of Object.entries(map)) if (k in a) m[c] = a[k];
  return M.verifyRequestSignature(m, pubKeyOf(fromJ(key)));
}
const sign = (extra: any = {}) => M.signRequestMessage({ ...REQ, key: privOf(S1), keyid: 'k1', created: 1_700_000_000, ...extra });
const vr = (n: string, a: any, key: Uint8Array = P1) => o.run('verifyRequestSignature', n, verW, [a, key]);
const base = (s: any, over: any = {}) => ({ method: REQ.method, url: REQ.url, headers: REQ.headers, signature_input: s.signatureInput, signature: s.signature, ...over });
const S_BASIC = sign();
const S_AGENT = sign({ signatureAgent: 'https://agent.example/keys' });
await vr('basic', base(S_BASIC));
await vr('wrong key', base(S_BASIC), P2);
await vr('method changed', base(S_BASIC, { method: 'GET' }));
await vr('method case', base(S_BASIC, { method: 'post' }));
await vr('url changed', base(S_BASIC, { url: REQ.url + '2' }));
await vr('header changed', base(S_BASIC, { headers: { ...REQ.headers, 'content-type': 'text/plain' } }));
await vr('header added', base(S_BASIC, { headers: { ...REQ.headers, extra: '1' } }));
await vr('header missing', base(S_BASIC, { headers: { host: 'api.acme.com' } }));
await vr('header case', base(S_BASIC, { headers: { Host: 'api.acme.com', 'Content-Type': 'application/json' } }));
await vr('host derived from url', base(S_BASIC, { headers: { 'content-type': 'application/json' } }));
await vr('host mismatch', base(S_BASIC, { headers: { host: 'evil.example', 'content-type': 'application/json' } }));
await vr('signature tampered', base(S_BASIC, { signature: S_BASIC.signature.replace(/.$/, (c: string) => (c === ':' ? ':' : c)).replace('sig1=:A', 'sig1=:B') }));
await vr('signature bytes flipped', base(S_BASIC, { signature: 'sig1=:' + Buffer.from(Buffer.from(S_BASIC.signature.slice(6, -1), 'base64').map((b, i) => (i === 3 ? b ^ 1 : b))).toString('base64') + ':' }));
await vr('signature wrong length', base(S_BASIC, { signature: 'sig1=:AAAA:' }));
await vr('signature no colons', base(S_BASIC, { signature: 'sig1=' + S_BASIC.signature.slice(6, -1) }));
await vr('signature no label', base(S_BASIC, { signature: S_BASIC.signature.slice(5) }));
await vr('signature whitespace around', base(S_BASIC, { signature: S_BASIC.signature.replace('sig1=', 'sig1=  ') + ' ' }));
await vr('signature label differs', base(S_BASIC, { signature: S_BASIC.signature.replace('sig1', 'other') }));
await vr('signature url-safe alphabet', base(S_BASIC, { signature: 'sig1=:' + Buffer.from(S_BASIC.signature.slice(6, -1), 'base64').toString('base64url') + ':' }));
await vr('signature newline inside', base(S_BASIC, { signature: S_BASIC.signature.replace(':', ':\n') }));
await vr('signature not a string', base(S_BASIC, { signature: 5 }));
await vr('input no equals', base(S_BASIC, { signature_input: 'noequals' }));
await vr('input label differs ok', base(S_BASIC, { signature_input: S_BASIC.signatureInput.replace('sig1', 'zzz') }));
await vr('input not a string', base(S_BASIC, { signature_input: null }));
await vr('input no paren', base(S_BASIC, { signature_input: 'sig1=;created=1' }));
await vr('input unclosed', base(S_BASIC, { signature_input: 'sig1=("@method"' }));
await vr('input empty components', base(S_BASIC, { signature_input: 'sig1=();created=1700000000;keyid="k1";alg="ed25519"' }));
await vr('input bad component token', base(S_BASIC, { signature_input: 'sig1=(@method);created=1' }));
await vr('input component with newline', base(S_BASIC, { signature_input: 'sig1=("a\nb");created=1' }));
await vr('input params tampered', base(S_BASIC, { signature_input: S_BASIC.signatureInput.replace('created=1700000000', 'created=1700000001') }));
await vr('input keyid tampered', base(S_BASIC, { signature_input: S_BASIC.signatureInput.replace('keyid="k1"', 'keyid="k2"') }));
await vr('input components reordered', base(S_BASIC, { signature_input: S_BASIC.signatureInput.replace('"@method" "@target-uri"', '"@target-uri" "@method"') }));
await vr('input extra spaces between components', base(S_BASIC, { signature_input: S_BASIC.signatureInput.replace('"@method" "@target-uri"', '"@method"   "@target-uri"') }));
await vr('input tabs between components', base(S_BASIC, { signature_input: S_BASIC.signatureInput.replace('"@method" "@target-uri"', '"@method"\t"@target-uri"') }));
await vr('required components ok', base(S_BASIC, { required_components: ['@method', '@target-uri', 'host'] }));
await vr('required components missing', base(S_BASIC, { required_components: ['@method', 'x-nope'] }));
await vr('required components empty', base(S_BASIC, { required_components: [] }));
await vr('required components null', base(S_BASIC, { required_components: null }));
await vr('required components authority missing', base(S_BASIC, { required_components: ['@authority'] }));
await vr('max age fresh', base(S_BASIC, { max_age_sec: 60, now_sec: 1_700_000_030 }));
await vr('max age boundary', base(S_BASIC, { max_age_sec: 60, now_sec: 1_700_000_060 }));
await vr('max age one over', base(S_BASIC, { max_age_sec: 60, now_sec: 1_700_000_061 }));
await vr('max age future within skew', base(S_BASIC, { max_age_sec: 60, now_sec: 1_699_999_995 }));
await vr('max age future beyond skew', base(S_BASIC, { max_age_sec: 60, now_sec: 1_699_999_994 }));
await vr('max age zero', base(S_BASIC, { max_age_sec: 0, now_sec: 1_700_000_000 }));
await vr('max age null', base(S_BASIC, { max_age_sec: null, now_sec: 1_700_000_000 }));
await vr('max age without created', base(S_BASIC, { signature_input: 'sig1=("@method");keyid="k"', max_age_sec: 60, now_sec: 1 }));
await vr('max age huge created', base(S_BASIC, { signature_input: S_BASIC.signatureInput.replace('created=1700000000', 'created=' + '9'.repeat(400)), max_age_sec: 60, now_sec: 1 }));
await vr('max age created leading zeros', base(S_BASIC, { signature_input: S_BASIC.signatureInput.replace('created=1700000000', 'created=01700000000'), max_age_sec: 60, now_sec: 1_700_000_030 }));
await vr('no max age old created', base(S_BASIC));
await vr('alg param other', base(S_BASIC, { signature_input: S_BASIC.signatureInput.replace('alg="ed25519"', 'alg="rsa-v1_5-sha256"') }));
await vr('alg param absent', base(S_BASIC, { signature_input: S_BASIC.signatureInput.replace(';alg="ed25519"', '') }));
await vr('alg param empty', base(S_BASIC, { signature_input: S_BASIC.signatureInput.replace('alg="ed25519"', 'alg=""') }));
await vr('agent ok (as covered header)', base(S_AGENT, { headers: { ...REQ.headers, 'signature-agent': '"https://agent.example/keys"' } }));
await vr('agent via argument', base(S_AGENT, { signature_agent: '"https://agent.example/keys"' }));
await vr('agent via argument wrong', base(S_AGENT, { signature_agent: '"https://evil.example/keys"' }));
await vr('agent absent', base(S_AGENT));
await vr('agent argument number', base(S_AGENT, { signature_agent: 5 }));
await vr('agent header wins over argument', base(S_AGENT, { headers: { ...REQ.headers, 'signature-agent': '"https://agent.example/keys"' }, signature_agent: '"x"' }));
await vr('agent tag in params', base(S_AGENT, { headers: { ...REQ.headers, 'signature-agent': '"https://agent.example/keys"' }, required_components: ['signature-agent'] }));
// hand-built bases (@authority, odd covered values)
function handSigned(components: string[], params: string, lines: string[], seedKey = S1) {
  const base = [...lines, `"@signature-params": ${params}`].join('\n');
  return { input: `sig1=${params}`, sig: `sig1=:${crypto.sign(null, Buffer.from(base), privOf(seedKey)).toString('base64')}:` };
}
{
  const params = '("@method" "@authority" "@target-uri");created=1700000000;keyid="k";alg="ed25519"';
  const hs = handSigned([], params, ['"@method": POST', '"@authority": api.acme.com', `"@target-uri": ${REQ.url}`]);
  await vr('authority component', { ...REQ, signature_input: hs.input, signature: hs.sig });
  await vr('authority component host differs', { ...REQ, url: 'https://other.example/v1/orders?ref=42', signature_input: hs.input, signature: hs.sig });
  const p2 = '("x-a" "x-b");created=1700000000;keyid="k"';
  const h2 = handSigned([], p2, ['"x-a": one two', '"x-b": 2']);
  await vr('covered value trimmed', { ...REQ, headers: { 'X-A': '  one two  ', 'x-b': '2' }, signature_input: h2.input, signature: h2.sig });
  await vr('covered value inner spaces kept', { ...REQ, headers: { 'x-a': 'one  two', 'x-b': '2' }, signature_input: h2.input, signature: h2.sig });
  const p3 = '();created=1700000000;keyid="k"';
  const h3 = handSigned([], p3, []);
  await vr('no components signature', { ...REQ, signature_input: h3.input, signature: h3.sig });
  const p4 = '("@method" "@method");created=1700000000;keyid="k"';
  const h4 = handSigned([], p4, ['"@method": POST', '"@method": POST']);
  await vr('duplicate component', { ...REQ, signature_input: h4.input, signature: h4.sig });
  const p5 = '("@method");created=1700000000;keyid="k"';
  const h5 = handSigned([], p5, ['"@method": POST'], S2);
  await vr('signed by other key', { ...REQ, signature_input: h5.input, signature: h5.sig });
  await vr('signed by other key verified with it', { ...REQ, signature_input: h5.input, signature: h5.sig }, P2);
}

void keyOf;
refWrite(o, 'vc');
