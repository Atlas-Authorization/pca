// Oracle: @atlasauth/pca-notary. Writes out/ref-notary.json.gz. Salts are deterministic: randomBytes is replaced by a counter hash and
// every notarizeResponse case resets the counter to 0 (a native replays with salt_i = sha256("notary-oracle-salt/" + i)[:16]).
// Keys are Ed25519 seeds ({"$bytes"}); attestations/witnesses/disclosures used as inputs are produced here and embedded as JSON.
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { Oracle, refWrite, variants } from './lib.mjs';

let ctr = 0;
(crypto as any).randomBytes = (n: number) => crypto.createHash('sha256').update('notary-oracle-salt/' + ctr++).digest().subarray(0, n);
syncBuiltinESMExports();

const M: any = await import('../../../packages/pca-notary/src/index.ts');
const P: any = await import('@atlasauth/pca');
const o = new Oracle('notary', 'tools/pca-audit/oracles/notary.mts', 'TS-reference oracle for @atlasauth/pca-notary.');

const fromJ = (v: any): any => {
  if (v === null || typeof v !== 'object' || v instanceof Uint8Array) return v;
  if (Array.isArray(v)) return v.map(fromJ);
  const ks = Object.keys(v);
  if (ks.length === 1 && ks[0] === '$bytes') return new Uint8Array(Buffer.from(v.$bytes, 'base64url'));
  return Object.fromEntries(ks.map((k) => [k, fromJ(v[k])]));
};
const W = (f: any) => (...a: any[]) => f(...a.map(fromJ));
const seed = (n: number) => new Uint8Array(32).fill(n);
const kp = (n: number) => ({ secretKey: seed(n), publicKey: P.publicKeyOf(seed(n)) });
const K1 = kp(1), K2 = kp(2);
const PUB1 = P.b64u(K1.publicKey), PUB2 = P.b64u(K2.publicKey);
const T0 = 1_700_000_000_000;

const notarize = (input: any, opts: any) => { ctr = 0; return M.notarizeResponse(input, opts); };
const rawKp = (k: any) => ({ secretKey: { $bytes: P.b64u(k.secretKey) }, publicKey: { $bytes: P.b64u(k.publicKey) } });
const REQ = { method: 'get', url: 'https://api.example.com/orders/1', headers: { Authorization: 'Bearer x', 'X-Trace': ['a', 'b'] } };
const BODY = { order: { status: 'shipped', items: [{ sku: 'a1', qty: 2 }, { sku: 'b2', qty: 1 }], paid: true }, id: 'o-1', note: null, tags: [], meta: {} };
const nz = (input: any, opts: any = {}) => [input, { notaryKey: rawKp(K1), observedAt: T0, ...opts }];

// ---- notaryMessage + constants ----
await o.run('constants', 'all', () => ({ BODY_COMMIT_ALG: M.BODY_COMMIT_ALG, ATTESTED_FACT_CAVEAT: M.ATTESTED_FACT_CAVEAT }), []);
const sess = notarize({ request: REQ, response: { status: 200, body: BODY } }, { notaryKey: K1, observedAt: T0 }).attestation.session;
await o.run('notaryMessage', 'valid session', M.notaryMessage, [sess]);
await o.run('notaryMessage', 'empty object', M.notaryMessage, [{}]);
await o.run('notaryMessage', 'unicode', M.notaryMessage, [{ ...sess, url: 'https://é.example/ü' }]);
await o.run('notaryMessage', 'null', M.notaryMessage, [null]);
await o.run('notaryMessage', 'unsafe number', M.notaryMessage, [{ n: 2 ** 53 }]);

// ---- notarizeResponse ----
const NR = async (n: string, input: any, opts: any = {}) => o.run('notarizeResponse', n, W(notarize), nz(input, opts));
await NR('object body', { request: REQ, response: { status: 200, body: BODY } });
await NR('array body', { request: REQ, response: { status: 200, body: [1, 'two', [3], { four: 4 }] } });
await NR('empty object', { request: REQ, response: { status: 204, body: {} } });
await NR('empty array', { request: REQ, response: { status: 200, body: [] } });
await NR('null body', { request: REQ, response: { status: 200, body: null } });
await NR('absent body', { request: REQ, response: { status: 200 } });
await NR('number body', { request: REQ, response: { status: 200, body: 5 } });
await NR('bool body', { request: REQ, response: { status: 200, body: false } });
await NR('string body whole', { request: REQ, response: { status: 200, body: 'hello world' } });
await NR('string chunk 3', { request: REQ, response: { status: 200, body: 'hello world' } }, { textChunkSize: 3 });
await NR('string chunk 1', { request: REQ, response: { status: 200, body: 'abc' } }, { textChunkSize: 1 });
await NR('string chunk 2.5', { request: REQ, response: { status: 200, body: 'abcdefg' } }, { textChunkSize: 2.5 });
await NR('string chunk huge', { request: REQ, response: { status: 200, body: 'abcdefg' } }, { textChunkSize: 1e9 });
await NR('string chunk 0 is whole', { request: REQ, response: { status: 200, body: 'abc' } }, { textChunkSize: 0 });
await NR('string chunk negative is whole', { request: REQ, response: { status: 200, body: 'abc' } }, { textChunkSize: -2 });
await NR('string chunk 0.5 is whole', { request: REQ, response: { status: 200, body: 'abc' } }, { textChunkSize: 0.5 });
await NR('string chunk bool is whole', { request: REQ, response: { status: 200, body: 'abc' } }, { textChunkSize: true });
await NR('string chunk text is whole', { request: REQ, response: { status: 200, body: 'abc' } }, { textChunkSize: '3' });
await NR('empty string chunked', { request: REQ, response: { status: 200, body: '' } }, { textChunkSize: 4 });
await NR('emoji chunk 1', { request: REQ, response: { status: 200, body: 'a\u{1F600}b\u{1F600}' } }, { textChunkSize: 1 });
await NR('emoji chunk 2', { request: REQ, response: { status: 200, body: 'a\u{1F600}b\u{1F600}' } }, { textChunkSize: 2 });
await NR('chunk on object body ignored', { request: REQ, response: { status: 200, body: { a: 1 } } }, { textChunkSize: 2 });
await NR('key order', { request: REQ, response: { status: 200, body: { b: 1, a: 2, '10': 3, '2': 4, é: 5, z: { y: 1, x: 2 } } } });
await NR('unicode keys', { request: REQ, response: { status: 200, body: { '\u{1F600}': 1, '￿': 2, 'a': 3 } } });
await NR('nested empties', { request: REQ, response: { status: 200, body: { a: [], b: {}, c: [[], {}] } } });
await NR('no headers', { request: { method: 'POST', url: 'https://x.test/' }, response: { status: 201, body: { ok: true } } });
await NR('mixed-case headers', { request: { method: 'Put', url: 'https://x.test/', headers: { 'Content-Type': 'a', 'content-type': 'b', X: ['2', '1'] } }, response: { status: 200, body: 1 } });
await NR('no observedAt value', { request: REQ, response: { status: 200, body: 1 } }, { observedAt: 5 });
await NR('negative status', { request: REQ, response: { status: -1, body: 1 } });
await NR('status 0', { request: REQ, response: { status: 0, body: 1 } });
await NR('status max safe', { request: REQ, response: { status: 2 ** 53 - 1, body: 1 } });
await NR('status unsafe', { request: REQ, response: { status: 2 ** 53, body: 1 } });
await NR('status fraction', { request: REQ, response: { status: 200.5, body: 1 } });
await NR('status string', { request: REQ, response: { status: '200', body: 1 } });
await NR('status missing', { request: REQ, response: { body: 1 } });
await NR('status null', { request: REQ, response: { status: null, body: 1 } });
await NR('method empty', { request: { ...REQ, method: '' }, response: { status: 200, body: 1 } });
await NR('method number', { request: { ...REQ, method: 5 }, response: { status: 200, body: 1 } });
await NR('url empty', { request: { ...REQ, url: '' }, response: { status: 200, body: 1 } });
await NR('url missing', { request: { method: 'GET' }, response: { status: 200, body: 1 } });
await NR('request null', { request: null, response: { status: 200, body: 1 } });
await NR('response null', { request: REQ, response: null });
await NR('input null', null);
await NR('body out of profile (unsafe int)', { request: REQ, response: { status: 200, body: { n: 2 ** 53 + 2 } } });
await NR('body fraction', { request: REQ, response: { status: 200, body: { n: 1.5 } } });
await NR('observedAt unsafe', { request: REQ, response: { status: 200, body: 1 } }, { observedAt: 2 ** 53 });
await NR('observedAt 0', { request: REQ, response: { status: 200, body: 1 } }, { observedAt: 0 });

// ---- shared valid material ----
const NOTE = notarize({ request: REQ, response: { status: 200, body: BODY } }, { notaryKey: K1, observedAt: T0 });
const ATT = NOTE.attestation, WIT = NOTE.witness;
const TXT = notarize({ request: REQ, response: { status: 200, body: 'hello world' } }, { notaryKey: K1, observedAt: T0, textChunkSize: 4 });
const ONE = notarize({ request: REQ, response: { status: 200, body: 5 } }, { notaryKey: K1, observedAt: T0 });
const j = (x: any) => JSON.parse(JSON.stringify(x));

// ---- discloseField ----
const DF = (n: string, att: any, wit: any, path: any) => o.run('discloseField', n, M.discloseField, [att, wit, path]);
for (const p of [['order', 'status'], ['order', 'items', 0, 'sku'], ['order', 'items', 1, 'qty'], ['order', 'paid'], ['id'], ['note'], ['tags'], ['meta'], 'id'])
  await DF(`path ${JSON.stringify(p)}`, ATT, WIT, p);
for (const p of [['order'], ['nope'], [], ['order', 'items', 2, 'sku'], ['order', 'status', 'x'], ['order', 'items', '0', 'sku'], ['ID'], 'order', 'nope', null, 5, { a: 1 }, ['id', null]])
  await DF(`refused ${JSON.stringify(p)}`, ATT, WIT, p);
for (let i = 0; i < 3; i++) await DF(`chunk ${i}`, TXT.attestation, TXT.witness, ['#chunk', i]);
await DF('chunk out of range', TXT.attestation, TXT.witness, ['#chunk', 3]);
await DF('single leaf', ONE.attestation, ONE.witness, []);
await DF('witness null', ATT, null, ['id']);
await DF('witness no leaves', ATT, { session: ATT.session }, ['id']);
await DF('witness empty leaves', ATT, { session: ATT.session, leaves: [] }, ['id']);
await DF('attestation ignored', null, WIT, ['id']);

// ---- verifyNotaryAttestation ----
const VN = (n: string, att: any, key: any) => o.run('verifyNotaryAttestation', n, W((a: any, k: any) => M.verifyNotaryAttestation(a, { notaryKey: k })), [att, key]);
await VN('valid string key', ATT, PUB1);
await VN('valid bytes key', ATT, K1.publicKey);
await VN('valid keypair', ATT, rawKp(K1));
await VN('wrong key', ATT, PUB2);
await VN('wrong keypair', ATT, rawKp(K2));
await VN('other notary signed', notarize({ request: REQ, response: { status: 200, body: BODY } }, { notaryKey: K2, observedAt: T0 }).attestation, PUB1);
for (const k of [null, 5, [], {}, '', { publicKey: 5 }, { publicKey: 'abc' }]) await VN(`key ${JSON.stringify(k)}`, ATT, k);
for (const [lab, v] of variants(j(ATT), { depth: 4, maxPaths: 80 })) await VN(`variant ${lab}`, v, PUB1);
for (const a of [null, 5, 'x', [], {}]) await VN(`attestation ${JSON.stringify(a)}`, a, PUB1);
await VN('session retargeted', { ...j(ATT), session: { ...j(ATT).session, url: 'https://evil.example/' } }, PUB1);
await VN('sig swapped from other message', { ...j(ATT), sig: notarize({ request: REQ, response: { status: 200, body: 1 } }, { notaryKey: K1, observedAt: T0 }).attestation.sig }, PUB1);
await VN('fact_binding ignored by signature', { ...j(ATT), fact_binding: { pcactn_digest: 'x' } }, PUB1);
await VN('responseStatus -0', { ...j(ATT), session: { ...j(ATT).session, responseStatus: -0 } }, PUB1);
await VN('observedAt -0', { ...j(ATT), session: { ...j(ATT).session, observedAt: -0 } }, PUB1);
await VN('size 0', { ...j(ATT), session: { ...j(ATT).session, responseBodyCommit: { ...j(ATT).session.responseBodyCommit, size: 0 } } }, PUB1);
await VN('root not 32 bytes', { ...j(ATT), session: { ...j(ATT).session, responseBodyCommit: { ...j(ATT).session.responseBodyCommit, root: 'AAAA' } } }, PUB1);
await VN('alg other', { ...j(ATT), session: { ...j(ATT).session, responseBodyCommit: { ...j(ATT).session.responseBodyCommit, alg: 'x' } } }, PUB1);

// ---- verifyDisclosedField ----
const VD = (n: string, att: any, d: any, key: any = PUB1) => o.run('verifyDisclosedField', n, W((a: any, dd: any, k: any) => M.verifyDisclosedField(a, dd, { notaryKey: k })), [att, d, key]);
const D_STATUS = M.discloseField(ATT, WIT, ['order', 'status']);
await VD('valid', ATT, D_STATUS);
await VD('valid bytes key', ATT, D_STATUS, K1.publicKey);
await VD('wrong key', ATT, D_STATUS, PUB2);
for (const p of [['order', 'items', 0, 'sku'], ['order', 'paid'], ['id'], ['note'], ['tags'], ['meta']]) await VD(`valid ${JSON.stringify(p)}`, ATT, M.discloseField(ATT, WIT, p));
for (let i = 0; i < 3; i++) await VD(`valid chunk ${i}`, TXT.attestation, M.discloseField(TXT.attestation, TXT.witness, ['#chunk', i]));
await VD('valid single leaf', ONE.attestation, M.discloseField(ONE.attestation, ONE.witness, []));
await VD('lie about value', ATT, { ...D_STATUS, value: 'cancelled' });
await VD('lie about path', ATT, { ...D_STATUS, path: ['order', 'paid'] });
await VD('lie about salt', ATT, { ...D_STATUS, salt: P.b64u(new Uint8Array(16)) });
await VD('proof size mismatch', ATT, { ...D_STATUS, proof: { ...D_STATUS.proof, size: D_STATUS.proof.size + 1 } });
await VD('proof index moved', ATT, { ...D_STATUS, proof: { ...D_STATUS.proof, index: 0 } });
await VD('proof of other tree', ATT, M.discloseField(ONE.attestation, ONE.witness, []));
await VD('disclosure of other attestation', ONE.attestation, D_STATUS);
await VD('tampered attestation', { ...j(ATT), notary: PUB2 }, D_STATUS);
await VD('disclosure null', ATT, null);
await VD('disclosure array', ATT, []);
await VD('disclosure without proof', ATT, { path: D_STATUS.path, value: D_STATUS.value, salt: D_STATUS.salt });
await VD('proof null', ATT, { ...D_STATUS, proof: null });
await VD('proof path not array', ATT, { ...D_STATUS, proof: { ...D_STATUS.proof, path: 'x' } });
for (const [lab, v] of variants(j(D_STATUS), { depth: 4, maxPaths: 60 })) await VD(`variant ${lab}`, ATT, v);

// ---- binding ----
const PCA_A = { v: 2, action: { verb: 'refund', resource: 'orders/1' }, nonce: 'n1', provenance: { trusted_refs: [] as string[] } };
const BOUND = M.bindFactToPcActn(ATT, PCA_A);
const PCA_B = { ...PCA_A, provenance: { trusted_refs: [M.factRef(BOUND)] } };
const BOUND_B = M.bindFactToPcActn(ATT, PCA_B);
await o.run('factRef', 'attestation', M.factRef, [ATT]);
await o.run('factRef', 'bound ignores binding', M.factRef, [BOUND]);
await o.run('factRef', 'other attestation', M.factRef, [ONE.attestation]);
await o.run('factRef', 'null', M.factRef, [null]);
await o.run('factRef', 'empty', M.factRef, [{}]);
await o.run('bindFactToPcActn', 'a', M.bindFactToPcActn, [ATT, PCA_A]);
await o.run('bindFactToPcActn', 'b', M.bindFactToPcActn, [ATT, PCA_B]);
await o.run('bindFactToPcActn', 'rebind replaces', M.bindFactToPcActn, [BOUND, PCA_B]);
await o.run('bindFactToPcActn', 'pcactn null', M.bindFactToPcActn, [ATT, null]);
await o.run('bindFactToPcActn', 'pcactn unsafe number', M.bindFactToPcActn, [ATT, { n: 2 ** 53 }]);
const FM = (n: string, a: any, p: any) => o.run('factMatchesPcActn', n, M.factMatchesPcActn, [a, p]);
await FM('both directions', BOUND_B, PCA_B);
await FM('unbound', ATT, PCA_B);
await FM('action does not commit to fact', BOUND, PCA_A);
await FM('bound to other action', BOUND_B, { ...PCA_B, nonce: 'n2' });
await FM('fact swapped', M.bindFactToPcActn(ONE.attestation, PCA_B), PCA_B);
await FM('refs other value', BOUND_B, { ...PCA_B, provenance: { trusted_refs: ['x'] } });
await FM('refs not array', BOUND_B, { ...PCA_B, provenance: { trusted_refs: 'x' } });
await FM('no provenance', BOUND_B, { v: 2 });
await FM('provenance null', BOUND_B, { ...PCA_B, provenance: null });
await FM('binding digest not string', { ...j(ATT), fact_binding: { pcactn_digest: 5 } }, PCA_B);
await FM('binding empty', { ...j(ATT), fact_binding: {} }, PCA_B);
await FM('binding null', { ...j(ATT), fact_binding: null }, PCA_B);
await FM('attestation null', null, PCA_B);
await FM('pcactn null', BOUND_B, null);
await FM('refs with extra', BOUND_B, { ...PCA_B, provenance: { trusted_refs: ['a', M.factRef(BOUND_B), 'b'] } });

// ---- caveats ----
const RA = (n: string, opts: any) => o.run('requireAttestedFact', n, W((x: any) => M.requireAttestedFact(x)), [opts]);
await RA('string notary', { notary: PUB1, path: ['order', 'status'], equals: 'shipped' });
await RA('bytes notary', { notary: K1.publicKey, path: ['id'], equals: 'o-1' });
await RA('keypair notary', { notary: rawKp(K1), path: ['id'], equals: 'o-1' });
await RA('with url', { notary: PUB1, path: ['id'], equals: 'o-1', url: 'https://api.example.com/orders/1' });
await RA('with bind true', { notary: PUB1, path: ['id'], equals: 'o-1', bindToPcActn: true });
await RA('with bind false', { notary: PUB1, path: ['id'], equals: 'o-1', bindToPcActn: false });
await RA('all', { notary: PUB1, path: ['id'], equals: null, url: 'u', bindToPcActn: true });
await RA('object equals', { notary: PUB1, path: ['order'], equals: { a: [1] } });
await RA('notary number refused', { notary: 5, path: ['id'], equals: 1 });
await RA('path not array refused', { notary: PUB1, path: 'id', equals: 1 });
const CV = M.requireAttestedFact({ notary: PUB1, path: ['order', 'status'], equals: 'shipped' });
const CVB = M.requireAttestedFact({ notary: PUB1, path: ['order', 'status'], equals: 'shipped', bindToPcActn: true });
for (const [n, c] of Object.entries({ valid: CV, 'wrong type': { ...CV, type: 'x' }, 'no notary': { type: 'attested_fact', path: [] }, 'no path': { type: 'attested_fact', notary: PUB1 }, 'path string': { ...CV, path: 'id' }, null: null, array: [], string: 'x', 'extra': { ...CV, z: 1 } }))
  await o.run('isAttestedFactCaveat', n, M.isAttestedFactCaveat, [c]);

// ---- notaryKeyUsable ----
const NK = (n: string, ring: any, key: any, at: any) => o.run('notaryKeyUsable', n, M.notaryKeyUsable, [ring, key, at]);
await NK('listed', [{ key: PUB1 }], PUB1, T0);
await NK('not listed', [{ key: PUB2 }], PUB1, T0);
await NK('empty ring', [], PUB1, T0);
await NK('ring not array', { key: PUB1 }, PUB1, T0);
await NK('ring null', null, PUB1, T0);
await NK('revoked', [{ key: PUB1, revoked: true }], PUB1, T0);
await NK('revoked false', [{ key: PUB1, revoked: false }], PUB1, T0);
await NK('revoked string is not revoked', [{ key: PUB1, revoked: 'true' }], PUB1, T0);
await NK('one entry revoked of two', [{ key: PUB1 }, { key: PUB1, revoked: true }], PUB1, T0);
await NK('before notBefore', [{ key: PUB1, notBefore: T0 + 1 }], PUB1, T0);
await NK('at notBefore', [{ key: PUB1, notBefore: T0 }], PUB1, T0);
await NK('at notAfter', [{ key: PUB1, notAfter: T0 }], PUB1, T0);
await NK('just before notAfter', [{ key: PUB1, notAfter: T0 + 1 }], PUB1, T0);
await NK('window', [{ key: PUB1, notBefore: T0 - 10, notAfter: T0 + 10 }], PUB1, T0);
await NK('rotation: old then new', [{ key: PUB1, notAfter: T0 }, { key: PUB1, notBefore: T0 }], PUB1, T0);
await NK('rotation gap', [{ key: PUB1, notAfter: T0 - 5 }, { key: PUB1, notBefore: T0 + 5 }], PUB1, T0);
await NK('observedAt fraction', [{ key: PUB1 }], PUB1, 1.5);
await NK('observedAt unsafe', [{ key: PUB1 }], PUB1, 2 ** 53);
await NK('observedAt string', [{ key: PUB1 }], PUB1, '5');
await NK('observedAt null', [{ key: PUB1 }], PUB1, null);
await NK('observedAt negative', [{ key: PUB1 }], PUB1, -5);
await NK('null entries', [null, 0, '', { key: PUB1 }], PUB1, T0);
await NK('only null entries', [null, 0, ''], PUB1, T0);
await NK('notBefore null', [{ key: PUB1, notBefore: null }], PUB1, T0);
await NK('notBefore null negative at', [{ key: PUB1, notBefore: null }], PUB1, -1);
await NK('notAfter null', [{ key: PUB1, notAfter: null }], PUB1, T0);
await NK('notAfter null at zero', [{ key: PUB1, notAfter: null }], PUB1, 0);
await NK('notBefore string number', [{ key: PUB1, notBefore: String(T0) }], PUB1, T0);
await NK('notBefore string junk', [{ key: PUB1, notBefore: 'abc' }], PUB1, T0);
await NK('notAfter string junk', [{ key: PUB1, notAfter: 'abc' }], PUB1, T0);
await NK('notBefore true', [{ key: PUB1, notBefore: true }], PUB1, T0);
await NK('notBefore empty string', [{ key: PUB1, notBefore: '' }], PUB1, T0);
await NK('key not string', [{ key: 5 }], 5, T0);

// ---- evaluateAttestedFactCaveat ----
const EV = (n: string, c: any, e: any, p?: any) => o.run('evaluateAttestedFactCaveat', n, M.evaluateAttestedFactCaveat, p === undefined ? [c, e] : [c, e, p]);
const EVD = { attestation: ATT, disclosure: D_STATUS };
await EV('ok', CV, EVD);
await EV('ok bound', CVB, { ...EVD, attestation: BOUND_B, pcActn: PCA_B });
await EV('bound but no pcactn', CVB, { ...EVD, attestation: BOUND_B });
await EV('bound but pcactn empty object', CVB, { ...EVD, attestation: BOUND_B, pcActn: {} });
await EV('bound but pcactn changed', CVB, { ...EVD, attestation: BOUND_B, pcActn: { ...PCA_B, nonce: 'n2' } });
await EV('bound but unbound attestation', CVB, { ...EVD, pcActn: PCA_B });
await EV('bindToPcActn truthy string', { ...CV, bindToPcActn: 'yes' }, { ...EVD, pcActn: PCA_B });
await EV('bindToPcActn zero is falsy', { ...CV, bindToPcActn: 0 }, EVD);
await EV('bindToPcActn empty array is truthy', { ...CV, bindToPcActn: [] }, EVD);
await EV('bindToPcActn empty string is falsy', { ...CV, bindToPcActn: '' }, EVD);
await EV('not a caveat', { ...CV, type: 'x' }, EVD);
await EV('caveat null', null, EVD);
await EV('caveat array', [], EVD);
await EV('malformed notary', { ...CV, notary: 5 }, EVD);
await EV('malformed path', { ...CV, path: 'x' }, EVD);
await EV('wrong notary', { ...CV, notary: PUB2 }, EVD);
await EV('evidence null', CV, null);
await EV('evidence empty', CV, {});
await EV('evidence array', CV, []);
await EV('evidence string', CV, 'x');
await EV('no disclosure', CV, { attestation: ATT });
await EV('url match', { ...CV, url: REQ.url }, EVD);
await EV('url mismatch', { ...CV, url: 'https://evil/' }, EVD);
await EV('url null', { ...CV, url: null }, EVD);
await EV('wrong path', { ...CV, path: ['order', 'paid'], equals: true }, EVD);
await EV('wrong value', { ...CV, equals: 'cancelled' }, EVD);
await EV('equals absent', (({ equals, ...r }) => r)(CV as any), EVD);
await EV('equals object canonical', M.requireAttestedFact({ notary: PUB1, path: ['order', 'items', 0, 'sku'], equals: 'a1' }), { attestation: ATT, disclosure: M.discloseField(ATT, WIT, ['order', 'items', 0, 'sku']) });
await EV('equals empty array', M.requireAttestedFact({ notary: PUB1, path: ['tags'], equals: [] }), { attestation: ATT, disclosure: M.discloseField(ATT, WIT, ['tags']) });
await EV('equals empty array vs object', M.requireAttestedFact({ notary: PUB1, path: ['tags'], equals: {} }), { attestation: ATT, disclosure: M.discloseField(ATT, WIT, ['tags']) });
await EV('equals null', M.requireAttestedFact({ notary: PUB1, path: ['note'], equals: null }), { attestation: ATT, disclosure: M.discloseField(ATT, WIT, ['note']) });
await EV('lying disclosure', CV, { attestation: ATT, disclosure: { ...D_STATUS, value: 'cancelled' } });
await EV('lying disclosure meets caveat', { ...CV, equals: 'cancelled' }, { attestation: ATT, disclosure: { ...D_STATUS, value: 'cancelled' } });
// policy: keyring + freshness
await EV('keyring ok', CV, EVD, { keyring: [{ key: PUB1 }] });
await EV('keyring unlisted', CV, EVD, { keyring: [{ key: PUB2 }] });
await EV('keyring revoked', CV, EVD, { keyring: [{ key: PUB1, revoked: true }] });
await EV('keyring window ok', CV, EVD, { keyring: [{ key: PUB1, notBefore: T0, notAfter: T0 + 1 }] });
await EV('keyring window out', CV, EVD, { keyring: [{ key: PUB1, notAfter: T0 }] });
await EV('keyring null', CV, EVD, { keyring: null });
await EV('keyring empty', CV, EVD, { keyring: [] });
await EV('maxAge fresh', CV, EVD, { maxAgeMs: 1000, now: T0 + 1000 });
await EV('maxAge stale by 1', CV, EVD, { maxAgeMs: 1000, now: T0 + 1001 });
await EV('maxAge zero at', CV, EVD, { maxAgeMs: 0, now: T0 });
await EV('maxAge from future', CV, EVD, { maxAgeMs: 1000, now: T0 - 1 });
await EV('maxAge negative', CV, EVD, { maxAgeMs: -1, now: T0 });
await EV('maxAge null', CV, EVD, { maxAgeMs: null, now: T0 });
await EV('maxAge string', CV, EVD, { maxAgeMs: '1000', now: T0 });
await EV('maxAge true', CV, EVD, { maxAgeMs: true, now: T0 });
await EV('maxAge huge', CV, EVD, { maxAgeMs: 1e300, now: T0 });
await EV('now string', CV, EVD, { maxAgeMs: 1000, now: String(T0) });
await EV('now fraction', CV, EVD, { maxAgeMs: 1000, now: T0 + 0.5 });
await EV('maxAge with clock default and huge window', CV, EVD, { maxAgeMs: 1e15 });
await EV('maxAge with future observation', CV, { attestation: notarize({ request: REQ, response: { status: 200, body: BODY } }, { notaryKey: K1, observedAt: 9_000_000_000_000_000 }).attestation, disclosure: M.discloseField(ATT, WIT, ['order', 'status']) }, { maxAgeMs: 1e15 });
await EV('policy null', CV, EVD, null);
await EV('policy empty', CV, EVD, {});
await EV('policy unknown keys', CV, EVD, { x: 1 });
await EV('keyring checked before maxAge', CV, EVD, { keyring: [{ key: PUB2 }], maxAgeMs: 1, now: T0 + 5 });
await EV('maxAge checked before url', { ...CV, url: 'x' }, EVD, { maxAgeMs: 1, now: T0 + 5 });
await EV('url checked before disclosure', { ...CV, url: 'x' }, { attestation: ATT, disclosure: null });
await EV('disclosure null', CV, { attestation: ATT, disclosure: null });
for (const [lab, v] of variants(j(EVD), { depth: 3, maxPaths: 50 })) await EV(`variant ${lab}`, CV, v);

refWrite(o, 'notary');
