// Oracle: @atlasauth/pca-signals (SET build / verify, revocation state, replay store, receiveSET, standard revocations, authorize()
// adapters, snapshot / restore, SSF stream health + verification + poll queue, SSF management API). Deterministic: Ed25519 tokens are minted
// here with fixed claims; a SET built by the reference (random jti, wall-clock iat) is compared after decoding, jti -> "<uuid>" and an iat
// within two minutes of now -> "<now>", plus a signature check under the public key. Keys cross as JWK objects (private: {kty,crv,d,x}).
// Function-valued options cross by NAME: mapper (standardRevocations.subjectToAgent): default | email | throws | empty | num | id | prefixed;
// agentOf: leaf | throws | empty | num | grantId | const:<x>. Native stores / sinks are scripted: replay store mem | mem1 | throws | false.
// PORTING (fn(args) -> native entry point; all compared by JSON value; a throw requires the native to refuse, an error `code` compared when both carry one):
//   constants()                    Signals.SET_TYP / SET_ALG / EVENT_TYPES / RISC_EVENT_TYPES / SET_INMEMORY_MAX_ENTRIES, SsfStream.DELIVERY_* / STREAM_STATUSES
//   verifySET(set, pubJwk, opts)   Signals.verifySET (opts.currentDate is epoch ms); ParsedSet.toMap()
//   buildSETShape(a)               Signals.buildSET({events, issuer, audience, subject?, key: jwk}) then decode + normalise + signature check
//   stateScenario(spec)            ops over a RevocationState: apply | applyStd | plan | isRevoked | isIntentRevoked | stream | snapshot | restore
//   replayScenario(spec)           Signals.createInMemorySetReplayStore(opts) then addIfAbsent ops; replayConformance(spec) -> failure list
//   receiveScenario(spec)          Signals.receiveSET over scripted deliveries and a store; reasons of verify_failed print "<jose>" unless "SET invalid:"
//   adapterScenario(spec)          Signals.createRevocationHook / createIsRevoked over a restored state
//   validateStreamConfig(c)        SsfStream.validateStreamConfig
//   healthScenario(spec)           SsfStream.StreamHealth ops (a verification state prints "<state:N>" by issue order; ack {ref: N} acks the Nth state)
//   verificationScenario(spec)     SsfStream.handleVerificationRequest over a streams map; 204 prints the decoded SET shape
//   pollScenario(spec)             SsfStream.PollQueue ops
//   pushResponse(r)                SsfStream.pushResponse
//   caepSET(a)                     SsfStream.riskLevelChangeSET / assuranceLevelChangeSET (a.kind) then decode + normalise
//   transmitterMetadata(o, base, jwks)   SsfManage.transmitterMetadata
//   manageScenario(spec)           SsfManage.ssfManagementHandler over scripted requests, receivers and a MemoryStreamStore; deliveries print the decoded SET
// Not generated: a non-string jti in a replay store, a string `ack` / `setErrs`, fractional clocks, issuer / audience values that are not strings or string lists,
// hostile ParsedSet in applySET beyond null / non-object event payloads.
import * as S0 from '@atlasauth/pca-signals';
import crypto from 'node:crypto';
import { Oracle, refWrite, variants, seed } from './lib.mjs';

const S: any = (S0 as any).default ?? S0;
const o = new Oracle('signals', 'tools/pca-audit/oracles/signals.mts', 'TS-reference oracle for SSF / CAEP signals.');
const T = 1_800_000_000;
const ET = S.EVENT_TYPES;
let n = 0;
const nm = (s: string) => `${s}#${n++}`;
const add = (fn: string, name: string, ref: Function, args: any[]) => o.run(fn, nm(name), ref, args);

// ---- keys, tokens ---------------------------------------------------------------------------------------------------------------------
const edKey = (label: string) => {
  const priv = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed(label))]), format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(priv);
  return { priv, pub, privJwk: priv.export({ format: 'jwk' }) as any, pubJwk: pub.export({ format: 'jwk' }) as any };
};
const K1 = edKey('ref-signals/tx'), K2 = edKey('ref-signals/other');
const kPriv = (j: any) => (j && typeof j === 'object' ? crypto.createPrivateKey({ key: j, format: 'jwk' }) : j);
const kPub = (j: any) => (j && typeof j === 'object' ? crypto.createPublicKey({ key: j, format: 'jwk' }) : j);
const b64 = (x: any) => Buffer.from(typeof x === 'string' ? x : JSON.stringify(x)).toString('base64url');
const mint = (payload: any, op: any = {}) => {
  const h = b64(op.header ?? { alg: 'EdDSA', typ: 'secevent+jwt' }), p = b64(payload);
  return `${h}.${p}.${crypto.sign(null, Buffer.from(`${h}.${p}`), (op.key ?? K1).priv).toString('base64url')}`;
};
const claims = (events: any, extra: any = {}) => ({ iss: 'https://tx.example', aud: 'rx', iat: T, jti: 'jti-1', events, ...extra });
const E_GRANT = { [ET.grantRevoked]: { grant_ref: 'g1', reason: 'r', event_timestamp: 100 } };
const E_KILL = { [ET.killSwitch]: { agent: 'a1', grant_ref: 'g2', reason: 'k', event_timestamp: 200 } };
const E_INTENT = { [ET.intentRevoked]: { ids: ['pca-intent:session:s1', 'other', 'pca-intent:map:m1', 5], event_timestamp: 300 } };
const E_SESS = { [ET.sessionRevoked]: { subject: { format: 'opaque', id: 'agentX' }, event_timestamp: 400 } };
const E_CRED = (ct: any) => ({ [ET.credentialChange]: { subject: { format: 'opaque', id: 'agentY' }, ...(ct === undefined ? {} : { change_type: ct }), event_timestamp: 500 } });
const E_RISC = { [S.RISC_EVENT_TYPES.accountDisabled]: { subject: { format: 'opaque', id: 'agentZ' }, event_timestamp: 600 } };
const dec = (set: string) => {
  const [h, p] = set.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url').toString()), payload = JSON.parse(Buffer.from(p, 'base64url').toString());
  if (typeof payload.iat === 'number' && Math.abs(payload.iat * 1000 - Date.now()) < 120_000) payload.iat = '<now>';
  if (typeof payload.jti === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(payload.jti)) payload.jti = '<uuid>';
  return { header, payload };
};
const shape = (set: string) => ({ ...dec(set), sigOk: (() => { const [h, p, s] = set.split('.'); return crypto.verify(null, Buffer.from(`${h}.${p}`), K1.pub, Buffer.from(s, 'base64url')); })() });
const state = (st: any) => ({ grants: [...st.revokedGrants], agents: [...st.killedAgents], intents: st.revokedIntentIds ? [...st.revokedIntentIds] : null });
const jsonOf = (v: any) => JSON.parse(JSON.stringify(v === undefined ? null : v));
const errOut = (e: any) => ({ $err: true, ...(e && typeof e.code === 'string' && !e.code.startsWith('ERR_') && !e.code.startsWith('N') ? { code: e.code } : {}) });
const MAPPERS: Record<string, any> = {
  email: (s: any) => (s.format === 'email' && typeof s.email === 'string' ? s.email : undefined), throws: () => { throw new Error('x'); }, empty: () => '', num: () => 5,
  id: (s: any) => (typeof s.id === 'string' ? s.id : undefined), prefixed: (s: any) => (typeof s.id === 'string' ? `agent:${s.id}` : undefined),
};
const stdOpts = (sp: any) => (sp === undefined ? undefined : { ...(sp.mapper && sp.mapper !== 'default' ? { subjectToAgent: MAPPERS[sp.mapper] } : {}), ...(sp.fail !== undefined ? { failOnUnmapped: sp.fail } : {}) });
const AGENTS: Record<string, any> = { throws: () => { throw new Error('x'); }, empty: () => '', num: () => 5, grantId: (ctx: any) => ctx.grant?.id };
const agentOf = (nmn: any) => (nmn === undefined || nmn === 'leaf' ? undefined : typeof nmn === 'string' && nmn.startsWith('const:') ? () => nmn.slice(6) : AGENTS[nmn]);

// ---- constants -------------------------------------------------------------------------------------------------------------------------
await add('constants', 'all', () => ({ SET_TYP: S.SET_TYP, SET_ALG: S.SET_ALG, EVENT_TYPES: S.EVENT_TYPES, RISC_EVENT_TYPES: S.RISC_EVENT_TYPES, SET_INMEMORY_MAX_ENTRIES: S.SET_INMEMORY_MAX_ENTRIES, DELIVERY_PUSH: S.DELIVERY_PUSH, DELIVERY_POLL: S.DELIVERY_POLL, STREAM_STATUSES: S.STREAM_STATUSES }), []);

// ---- verifySET -------------------------------------------------------------------------------------------------------------------------
const verifyW = async (set: any, key: any, op: any) => {
  const opts = op && typeof op === 'object' ? { ...op } : op;
  if (opts && opts.currentDate !== undefined) opts.currentDate = new Date(opts.currentDate);
  const r = await S.verifySET(set, kPub(key), opts);
  return { events: r.events, iss: r.iss, jti: r.jti, ...(r.sub !== undefined ? { sub: r.sub } : {}), payload: r.payload };
};
const toks: Array<[string, string]> = [
  ['grant', mint(claims(E_GRANT))], ['grant+sub', mint(claims(E_GRANT, { sub: 'subj', sub_id: { format: 'opaque', id: 'subj' } }))], ['aud-array', mint(claims(E_GRANT, { aud: ['rx', 'ry'] }))],
  ['kill', mint(claims(E_KILL))], ['intent', mint(claims(E_INTENT))], ['session', mint(claims(E_SESS))], ['cred', mint(claims(E_CRED('revoke')))], ['risc', mint(claims(E_RISC))],
  ['multi', mint(claims({ ...E_GRANT, ...E_KILL, ...E_SESS }))], ['unknown-type', mint(claims({ 'https://example.test/x': { a: 1 } }))],
  ['events-payload-string', mint(claims({ [ET.grantRevoked]: 'x' }))], ['events-payload-null', mint(claims({ [ET.grantRevoked]: null }))], ['events-payload-array', mint(claims({ [ET.grantRevoked]: [] }))],
  ['events-empty', mint(claims({}))], ['events-null', mint(claims(null))], ['events-array', mint(claims([{}]))], ['events-string', mint(claims('x'))], ['events-missing', mint({ iss: 'https://tx.example', aud: 'rx', iat: T, jti: 'j' })],
  ['iss-missing', mint({ aud: 'rx', iat: T, jti: 'j', events: E_GRANT })], ['iss-number', mint(claims(E_GRANT, { iss: 5 }))], ['jti-missing', mint({ iss: 'https://tx.example', aud: 'rx', iat: T, events: E_GRANT })], ['jti-number', mint(claims(E_GRANT, { jti: 5 }))],
  ['iat-string', mint(claims(E_GRANT, { iat: '5' }))], ['iat-missing', mint({ iss: 'https://tx.example', aud: 'rx', jti: 'j', events: E_GRANT })], ['aud-missing', mint({ iss: 'https://tx.example', iat: T, jti: 'j', events: E_GRANT })],
  ['exp-past', mint(claims(E_GRANT, { exp: T - 100 }))], ['exp-future', mint(claims(E_GRANT, { exp: T + 100 }))], ['exp-now', mint(claims(E_GRANT, { exp: T }))], ['exp-string', mint(claims(E_GRANT, { exp: 'x' }))], ['nbf-future', mint(claims(E_GRANT, { nbf: T + 100 }))], ['nbf-past', mint(claims(E_GRANT, { nbf: T - 100 }))],
  ['typ-absent', mint(claims(E_GRANT), { header: { alg: 'EdDSA' } })], ['typ-JWT', mint(claims(E_GRANT), { header: { alg: 'EdDSA', typ: 'JWT' } })], ['typ-upper', mint(claims(E_GRANT), { header: { alg: 'EdDSA', typ: 'SECEVENT+JWT' } })],
  ['typ-app', mint(claims(E_GRANT), { header: { alg: 'EdDSA', typ: 'application/secevent+jwt' } })], ['typ-app-JWT', mint(claims(E_GRANT), { header: { alg: 'EdDSA', typ: 'application/JWT' } })], ['typ-number', mint(claims(E_GRANT), { header: { alg: 'EdDSA', typ: 5 } })],
  ['alg-ES256', mint(claims(E_GRANT), { header: { alg: 'ES256', typ: 'secevent+jwt' } })], ['alg-none', `${b64({ alg: 'none', typ: 'secevent+jwt' })}.${b64(claims(E_GRANT))}.`], ['alg-missing', mint(claims(E_GRANT), { header: { typ: 'secevent+jwt' } })],
  ['extra-header', mint(claims(E_GRANT), { header: { alg: 'EdDSA', typ: 'secevent+jwt', kid: 'k1', x: [1] } })], ['crit', mint(claims(E_GRANT), { header: { alg: 'EdDSA', typ: 'secevent+jwt', crit: ['x'], x: 1 } })],
  ['wrong-key', mint(claims(E_GRANT), { key: K2 })], ['payload-array', mint('[1]')], ['payload-number', mint('5')], ['payload-null', mint('null')], ['payload-dup-key', mint('{"iss":"https://tx.example","iss":"b","aud":"rx","iat":1800000000,"jti":"j","events":{}}')],
];
const good = toks[0][1];
const [gh, gp, gs] = good.split('.');
const flip = (s: string) => s.slice(0, -2) + (s.slice(-2, -1) === 'A' ? 'B' : 'A') + s.slice(-1);
toks.push(['tampered-payload', `${gh}.${b64(claims(E_KILL))}.${gs}`], ['tampered-sig', `${gh}.${gp}.${flip(gs)}`], ['padded', `${gh}=.${gp}.${gs}`], ['padded-sig', `${gh}.${gp}.${gs}==`], ['spaces', ` ${good}`], ['trailing-space', `${good} `], ['newline', `${gh}.${gp}\n.${gs}`], ['two-segments', `${gh}.${gp}`], ['four-segments', `${good}.x`],
  ['empty', ''], ['junk', 'x'], ['dots', '..'], ['std-b64', `${gh}.${gp.replace(/-/g, '+')}.${gs}`], ['long', `${gh}.${b64('x'.repeat(70000))}.${gs}`], ['bom-payload', mint('﻿' + JSON.stringify(claims(E_GRANT)))], ['non-canonical-last-char', `${gh}.${gp.slice(0, -1)}${gp.slice(-1) === 'A' ? 'B' : 'A'}.${gs}`]);
const vopts: any[] = [undefined, {}, { issuer: 'https://tx.example' }, { issuer: 'x' }, { issuer: ['a', 'https://tx.example'] }, { issuer: ['a'] }, { issuer: [] }, { audience: 'rx' }, { audience: ['rx', 'y'] }, { audience: 'z' }, { audience: [] },
  { currentDate: (T + 1000) * 1000 }, { currentDate: (T + 50) * 1000, clockTolerance: 60 }, { currentDate: (T + 100) * 1000, clockTolerance: 0 }, { currentDate: (T - 200) * 1000 }, { typ: 'other' }, { typ: 'secevent+jwt' }, { typ: '' }, { requireTyp: false }, { requireTyp: true, typ: 'JWT' }, { currentDate: T * 1000 }];
// No case reads the wall clock: an options object without currentDate gets one fixed just after the tokens' iat (a token whose exp / nbf is
// compared with the real clock would flip the day that clock passes it). Two tokens far from any real date keep the no-options path covered.
// (undefined and {} stay two different cases: their pinned dates differ by a second, which changes nothing the tokens are checked against; the shared date would make
// their arguments identical and the collector drops a case whose (fn, args) it already holds)
const pinned = (op: any) => (op === undefined ? { currentDate: (T + 10) * 1000 } : op && typeof op === 'object' && op.currentDate === undefined ? { ...op, currentDate: (T + (Object.keys(op).length === 0 ? 11 : 10)) * 1000 } : op);
for (const [i, [name, t]] of toks.entries()) for (const [j, op] of vopts.entries()) await add('verifySET', `${name}/o${j}`, verifyW, [t, K1.pubJwk, pinned(op)]);
for (const [name, t] of [['exp-far-past', mint(claims(E_GRANT, { exp: 1_000_000_000 }))], ['exp-far-future', mint(claims(E_GRANT, { exp: 4_000_000_000 }))], ['nbf-far-future', mint(claims(E_GRANT, { nbf: 4_000_000_000 }))]] as Array<[string, string]>) {
  await add('verifySET', `${name}/real-clock`, verifyW, [t, K1.pubJwk, undefined]);
  await add('verifySET', `${name}/real-clock-empty`, verifyW, [t, K1.pubJwk, {}]);
}
for (const [name, t] of toks.slice(0, 12)) await add('verifySET', `${name}/wrongkey`, verifyW, [t, K2.pubJwk, undefined]);
for (const k of [null, 5, 'x', {}, { kty: 'OKP' }]) await add('verifySET', `badkey/${JSON.stringify(k)?.slice(0, 20)}`, verifyW, [good, k, undefined]);
for (const x of [null, 5, [], {}]) await add('verifySET', `nonstring/${JSON.stringify(x)}`, verifyW, [x, K1.pubJwk, undefined]);
const palette = [null, 0, -0, 1, 1.5, '', 'x', [], {}, true, '\ud800'];
for (const [name, v] of variants(claims({ ...E_GRANT, ...E_KILL }, { sub: 's' }), { hostile: palette, maxPaths: 40 })) await add('verifySET', `var/${name}`, verifyW, [mint(v), K1.pubJwk, { currentDate: T * 1000 }]);

// ---- buildSET (shape) --------------------------------------------------------------------------------------------------------------------------
const buildW = async (a: any) => shape(await S.buildSET({ ...a, key: kPriv(a.keyJwk), keyJwk: undefined }));
const bargs = (extra: any) => ({ events: E_GRANT, issuer: 'https://tx.example', audience: 'rx', keyJwk: K1.privJwk, ...extra });
const bcases: any[] = [bargs({}), bargs({ audience: ['rx', 'ry'] }), bargs({ subject: 'subj' }), bargs({ subject: '' }), bargs({ events: E_KILL }), bargs({ events: { ...E_GRANT, ...E_INTENT } }), bargs({ events: E_SESS, subject: 's' }), bargs({ events: { 'https://example.test/x': { a: [1, 2.5, null] } } }),
  bargs({ events: {} }), bargs({ events: null }), bargs({ events: [] }), bargs({ events: 'x' }), bargs({ events: 5 }), bargs({ issuer: '' }), bargs({ audience: [] }), bargs({ keyJwk: null }), bargs({ keyJwk: K1.pubJwk }), bargs({ keyJwk: {} })];
for (const [i, a] of bcases.entries()) await add('buildSETShape', `c${i}`, buildW, [a]);

// ---- state ------------------------------------------------------------------------------------------------------------------------------------
async function stateScenario(spec: any) {
  let st = S.createRevocationState();
  const out: any[] = [];
  for (const s of spec.ops) {
    try {
      let r: any;
      const target = s.badState ? {} : st;
      switch (s.op) {
        case 'apply': S.applySET(st, s.parsed); r = state(st); break;
        case 'applyStd': r = { plan: S.applyStandardRevocations(target, s.parsed, stdOpts(s.std)), state: state(st) }; break;
        case 'plan': r = S.planStandardRevocations(s.parsed, stdOpts(s.std)); break;
        case 'isRevoked': r = S.isRevoked(st, s.grant, s.agent); break;
        case 'isIntentRevoked': r = S.isIntentRevoked(st, s.id); break;
        case 'stream': { const res = S.streamProcessor(s.sets, s.useState ? st : undefined); r = state(res); break; }
        case 'snapshot': r = S.snapshotRevocationState(target); break;
        case 'restore': { const res = S.restoreRevocationState(s.snapshot, s.fresh ? undefined : s.nullInto ? null : target); r = state(res); break; }
        default: throw new Error('bad op');
      }
      out.push(jsonOf(r));
    } catch (e) { out.push(errOut(e)); }
  }
  out.push(state(st));
  return out;
}
const P = (events: any, extra: any = {}) => ({ events, iss: 'https://tx.example', jti: 'j', payload: { iss: 'https://tx.example', jti: 'j', ...extra } });
const evGrant = (ref: any, ts: any) => ({ [ET.grantRevoked]: { grant_ref: ref, ...(ts === undefined ? {} : { event_timestamp: ts }) } });
const parsedSets: any[] = [
  P(E_GRANT), P(E_KILL), P(E_INTENT), P(E_SESS), P(E_CRED('revoke')), P(E_CRED('create')), P(E_CRED('update')), P(E_CRED(undefined)), P(E_CRED(5)), P(E_RISC), P({ ...E_GRANT, ...E_KILL, ...E_INTENT, ...E_SESS }),
  P(evGrant('g1', 50)), P(evGrant('g1', 150)), P(evGrant('g1', undefined)), P(evGrant('', 5)), P(evGrant(5, 5)), P(evGrant('g9', -5)), P(evGrant('g9', 1.5)), P(evGrant('g9', 1e21)),
  P({ [ET.killSwitch]: { agent: '', grant_ref: '', event_timestamp: 5 } }), P({ [ET.killSwitch]: { agent: 'a', event_timestamp: 'x' } }), P({ [ET.intentRevoked]: { ids: 'pca-intent:x', event_timestamp: 5 } }), P({ [ET.intentRevoked]: { ids: ['pca-intent:', 'pca-intent', 'PCA-INTENT:x'] } }), P({ [ET.intentRevoked]: { ids: ['other'] } }),
  P({ [ET.sessionRevoked]: { subject: { format: 'email', email: 'a@b' }, event_timestamp: 7 } }), P({ [ET.sessionRevoked]: { event_timestamp: 7 } }, { sub_id: { format: 'opaque', id: 'setSubj' } }), P({ [ET.sessionRevoked]: {} }, { sub_id: { format: 'email', email: 'e@x' } }),
  P({ [ET.sessionRevoked]: { subject: 'str', event_timestamp: 7 } }, { sub_id: { format: 'opaque', id: 'setSubj' } }), P({ [ET.sessionRevoked]: { subject: { format: 'opaque', id: '' } } }), P({ [ET.sessionRevoked]: { subject: { id: 'noformat' } } }), P({ [ET.sessionRevoked]: { subject: { format: 5, id: 'x' } } }),
  P({ [ET.credentialChange]: {}, [S.RISC_EVENT_TYPES.sessionsRevoked]: { subject: { format: 'opaque', id: 'r1' }, event_timestamp: 3 }, [S.RISC_EVENT_TYPES.accountPurged]: { subject: { format: 'opaque', id: 'r2' }, event_timestamp: 4 }, [S.RISC_EVENT_TYPES.credentialCompromise]: { subject: { format: 'opaque', id: 'r3' } } }),
  P({ 'https://example.test/x': { subject: { format: 'opaque', id: 'u' } } }), P({}), P({ [ET.grantRevoked]: 'x' }), P({ [ET.grantRevoked]: 5, [ET.killSwitch]: [] }), P({ [ET.grantRevoked]: null }), P({ [ET.sessionRevoked]: null }), P({ [ET.credentialChange]: null }),
  { events: null, payload: {} }, { events: 'abc', payload: {} }, { events: 5, payload: {} }, { events: [], payload: {} }, { events: E_GRANT }, { payload: {} }, null, 5, 'x', {}, { events: E_SESS, payload: null }, { events: E_SESS, payload: 'str' },
];
const mappers = ['default', 'email', 'throws', 'empty', 'num', 'id', 'prefixed'];
for (const [i, p] of parsedSets.entries()) {
  await add('stateScenario', `apply/${i}`, stateScenario, [{ ops: [{ op: 'apply', parsed: p }, { op: 'apply', parsed: p }, { op: 'isRevoked', grant: 'g1', agent: 'a1' }, { op: 'isRevoked', grant: 'g2' }, { op: 'isRevoked', grant: 'x', agent: 'a1' }, { op: 'isIntentRevoked', id: 'pca-intent:session:s1' }, { op: 'snapshot' }] }]);
  await add('stateScenario', `plan/${i}`, stateScenario, [{ ops: [{ op: 'plan', parsed: p }, { op: 'plan', parsed: p, std: { fail: true } }, { op: 'plan', parsed: p, std: { fail: false } }, { op: 'plan', parsed: p, std: { mapper: 'email' } }, { op: 'plan', parsed: p, std: { mapper: 'throws', fail: true } }, { op: 'plan', parsed: p, std: { mapper: 'prefixed' } }] }]);
  for (const mp of ['default', 'id', 'num']) await add('stateScenario', `applyStd/${i}/${mp}`, stateScenario, [{ ops: [{ op: 'applyStd', parsed: p, std: { mapper: mp } }, { op: 'applyStd', parsed: p, std: { mapper: mp, fail: true } }, { op: 'applyStd', parsed: p }] }]);
}
await add('stateScenario', 'order', stateScenario, [{ ops: [{ op: 'apply', parsed: P(evGrant('g1', 100)) }, { op: 'apply', parsed: P(evGrant('g1', 50)) }, { op: 'apply', parsed: P(evGrant('g2', 10)) }, { op: 'apply', parsed: P(evGrant('g1', 200)) }, { op: 'apply', parsed: P(E_KILL) }, { op: 'apply', parsed: P(E_INTENT) }, { op: 'apply', parsed: P({ [ET.intentRevoked]: { ids: ['pca-intent:session:s1'], event_timestamp: 999 } }) }] }]);
await add('stateScenario', 'stream-order', stateScenario, [{ ops: [{ op: 'stream', sets: [P(evGrant('a', 300)), P(evGrant('b', 100)), P(evGrant('a', 200)), P({}), P(E_KILL)] }, { op: 'stream', sets: [], useState: true }, { op: 'stream', sets: [P(evGrant('z', 1))], useState: true }, { op: 'stream', sets: [P(E_INTENT), P(evGrant('q', -5))], useState: true }] }]);
for (const bad of [null, 'x', {}, [null], [{ events: null }], [P(E_GRANT), 5]]) await add('stateScenario', `stream-bad/${JSON.stringify(bad)}`, stateScenario, [{ ops: [{ op: 'stream', sets: bad }] }]);
const SNAPS: any[] = [{ v: 1, grants: [['g1', 5], ['g2', 7]], agents: [['a', 1]], intents: [['pca-intent:x', 3]] }, { v: 1, grants: [], agents: [], intents: [] }, { v: 1, grants: [['g1', 1], ['g1', 9], ['g1', 4]], agents: [], intents: [] }, { v: 2, grants: [], agents: [], intents: [] },
  { v: 1, grants: [], agents: [], intents: [], extra: 1 }, { v: 1, grants: [], agents: [] }, { v: 1, grants: {}, agents: [], intents: [] }, { v: 1, grants: [['', 1]], agents: [], intents: [] }, { v: 1, grants: [['g', 'x']], agents: [], intents: [] }, { v: 1, grants: [['g']], agents: [], intents: [] },
  { v: 1, grants: [['g', 1, 2]], agents: [], intents: [] }, { v: 1, grants: [[5, 1]], agents: [], intents: [] }, { v: 1, grants: ['gx'], agents: [], intents: [] }, { v: 1, grants: [null], agents: [], intents: [] }, { v: '1', grants: [], agents: [], intents: [] }, { v: 1.0, grants: [['g', -0]], agents: [], intents: [] },
  { v: 1, grants: [['g', 1e21]], agents: [['a', -3.5]], intents: [['i', 0]] }, null, 'x', 5, [], {}, { v: 1, grants: [['ok', 1]], agents: [['bad']], intents: [] }, { v: 1, grants: [['ok', 1]], agents: [], intents: [], '1': 2 }];
for (const [i, sn] of SNAPS.entries()) {
  await add('stateScenario', `restore/${i}`, stateScenario, [{ ops: [{ op: 'apply', parsed: P(evGrant('pre', 2)) }, { op: 'restore', snapshot: sn }, { op: 'restore', snapshot: sn, fresh: true }, { op: 'restore', snapshot: sn, nullInto: true }, { op: 'restore', snapshot: sn, badState: true }, { op: 'snapshot' }, { op: 'snapshot', badState: true }] }]);
}

// ---- replay store -------------------------------------------------------------------------------------------------------------------------------
async function replayScenario(spec: any) {
  const out: any[] = [];
  let store: any;
  try { store = S.createInMemorySetReplayStore(spec.opts); } catch (e) { return [errOut(e)]; }
  for (const [jti, exp, now] of spec.ops) { try { out.push(await store.addIfAbsent(jti, exp, now)); } catch { out.push({ $err: true }); } }
  return out;
}
for (const [i, op] of ([undefined, {}, { maxEntries: 1 }, { maxEntries: 2 }, { maxEntries: 0 }, { maxEntries: -1 }, { maxEntries: 1.5 }, { maxEntries: '5' }, { maxEntries: null }, { maxEntries: 1e21 }, { maxEntries: 3.0 }, { maxEntries: true }] as any[]).entries()) {
  await add('replayScenario', `o${i}`, replayScenario, [{ opts: op, ops: [['a', 200, 100], ['a', 200, 101], ['b', 200, 101], ['c', 300, 150], ['a', 200, 199], ['a', 400, 200], ['d', 100, 100], ['b', 90, 95], ['e', 500, 500], ['c', 900, 301], ['f', 1000, 301], ['g', 1000, 301]] }]);
}
await add('replayScenario', 'expiry-boundary', replayScenario, [{ opts: { maxEntries: 1 }, ops: [['a', 200, 100], ['b', 300, 199], ['b', 300, 200], ['c', 400, 200], ['c', 400, 201]] }]);
async function replayConformance(spec: any) {
  const mk = () => {
    if (spec.store === 'alwaysTrue') return { addIfAbsent: () => true };
    if (spec.store === 'alwaysFalse') return { addIfAbsent: () => false };
    if (spec.store === 'noExpiry') { const seen = new Set<string>(); return { addIfAbsent: (j: string) => { if (seen.has(j)) return false; seen.add(j); return true; } }; }
    return S.createInMemorySetReplayStore(spec.opts);
  };
  return S.runSetReplayStoreConformance(mk);
}
for (const [i, sp] of ([{ store: 'mem' }, { store: 'alwaysTrue' }, { store: 'alwaysFalse' }, { store: 'noExpiry' }, { store: 'mem', opts: { maxEntries: 1 } }, { store: 'mem', opts: { maxEntries: 5 } }] as any[]).entries()) await add('replayConformance', `s${i}`, replayConformance, [sp]);

// ---- receiveSET ----------------------------------------------------------------------------------------------------------------------------------
async function receiveScenario(spec: any) {
  const st = S.createRevocationState();
  const store = spec.store === 'throws' ? { addIfAbsent: () => { throw new Error('boom'); } } : spec.store === 'false' ? { addIfAbsent: () => false } : spec.store === 'mem1' ? S.createInMemorySetReplayStore({ maxEntries: 1 }) : S.createInMemorySetReplayStore();
  const out: any[] = [];
  for (const d of spec.deliveries) {
    const op: any = { ...d.opts };
    if (!d.noStore) op.replayStore = store;
    if (!d.noState) op.state = st;
    if (d.std !== undefined) op.standardRevocations = stdOpts(d.std);
    let r: any;
    try { r = await S.receiveSET(d.set, kPub(d.key === undefined ? K1.pubJwk : d.key), d.noOpts ? undefined : op); } catch { r = { $err: true }; }
    if (r && r.ok === false && r.code === 'verify_failed' && !String(r.reason).startsWith('SET invalid:')) r = { ...r, reason: '<jose>' };
    out.push(jsonOf(r.ok === true ? { ok: true, parsed: { events: r.parsed.events, iss: r.parsed.iss, jti: r.parsed.jti, ...(r.parsed.sub !== undefined ? { sub: r.parsed.sub } : {}), payload: r.parsed.payload } } : r));
  }
  out.push(state(st));
  return out;
}
const ro = (x: any = {}) => ({ issuer: 'https://tx.example', audience: 'rx', maxAgeSec: 300, nowSec: T + 10, ...x });
const dv = (set: string, opts: any = ro(), extra: any = {}) => ({ set, opts, ...extra });
const mk2 = (jti: string, events: any, extra: any = {}) => mint(claims(events, { jti, ...extra }));
const rdeliveries: any[][] = [
  [dv(mk2('r1', E_GRANT))], [dv(mk2('r1', E_GRANT)), dv(mk2('r1', E_GRANT))], [dv(mk2('r1', E_GRANT)), dv(mk2('r2', E_KILL)), dv(mk2('r3', E_INTENT))], [dv(mk2('r1', E_GRANT), ro({ issuer: 'other' }))], [dv(mk2('r1', E_GRANT), ro({ audience: 'other' }))],
  [dv(mk2('r1', E_GRANT), ro({ issuer: ['x', 'https://tx.example'], audience: ['rx', 'z'] }))], [dv(mk2('r1', E_GRANT), ro({ maxAgeSec: 5 }))], [dv(mk2('r1', E_GRANT), ro({ maxAgeSec: 10 }))], [dv(mk2('r1', E_GRANT), ro({ nowSec: T - 61 }))], [dv(mk2('r1', E_GRANT), ro({ nowSec: T - 60 }))],
  [dv(mk2('r1', E_GRANT), ro({ nowSec: T - 100, clockSkewSec: 100 }))], [dv(mk2('r1', E_GRANT), ro({ nowSec: T + 301 }))], [dv(mk2('r1', E_GRANT), ro({ nowSec: T + 300 }))], [dv(mint({ iss: 'https://tx.example', aud: 'rx', jti: 'j', events: E_GRANT }))],
  [dv(mk2('r1', E_GRANT, { iat: '5' }))], [dv(mk2('r1', E_GRANT, { exp: T }))], [dv(mk2('r1', E_GRANT, { nbf: T + 1000 }))], [dv(mk2('r1', E_GRANT), ro({ maxBytes: 10 }))], [dv(mk2('r1', E_GRANT), ro({ maxBytes: 100000 }))], [dv(mk2('r1', E_GRANT), ro({ maxBytes: 0 }))],
  [dv(mk2('r1', E_GRANT), {}, { noOpts: true })], [dv(mk2('r1', E_GRANT), ro(), { noStore: true })], [dv(mk2('r1', E_GRANT), ro(), { noState: true })], [dv(mk2('r1', E_GRANT), { audience: 'rx', maxAgeSec: 300 })], [dv(mk2('r1', E_GRANT), { issuer: 'https://tx.example', maxAgeSec: 300 })],
  ...[0, -1, 'x', null, undefined, Number.MAX_SAFE_INTEGER].map((m) => [dv(mk2('r1', E_GRANT), { issuer: 'https://tx.example', audience: 'rx', ...(m === undefined ? {} : { maxAgeSec: m }), nowSec: T + 10 })]),
  [dv('x')], [dv(''), dv(good.replace(/\./, '=.'))], [dv(mk2('r1', E_GRANT), ro(), { key: K2.pubJwk })], [dv(mint(claims(E_GRANT, { jti: 'r9' }), { key: K2 }))], [dv(mk2('r1', {}))], [dv(mk2('r1', E_GRANT, { iss: undefined }))],
  [dv(mk2('s1', E_SESS), ro(), { std: { mapper: 'default' } })], [dv(mk2('s1', E_SESS), ro(), { std: { mapper: 'email' } })], [dv(mk2('s1', E_SESS), ro(), { std: { mapper: 'email', fail: true } }), dv(mk2('s1', E_SESS), ro(), { std: { mapper: 'default', fail: true } })],
  [dv(mk2('s1', E_CRED('revoke')), ro(), { std: {} }), dv(mk2('s2', E_CRED('create')), ro(), { std: {} }), dv(mk2('s3', E_RISC), ro(), { std: {} }), dv(mk2('s4', { ...E_GRANT, ...E_SESS }), ro(), { std: { fail: true } })],
  [dv(mk2('s1', E_SESS, { sub_id: { format: 'opaque', id: 'setSubj' } }), ro(), { std: {} }), dv(mk2('s2', { [ET.sessionRevoked]: {} }, { sub_id: { format: 'opaque', id: 'setSubj2' } }), ro(), { std: {} })],
  [dv(mk2('s1', E_SESS), ro(), { std: { mapper: 'throws', fail: false } }), dv(mk2('s2', E_SESS), ro(), { std: { mapper: 'empty', fail: true } })], [dv(mk2('s1', E_SESS), ro(), { std: { mapper: 'num', fail: true } })],
  [dv(mk2('s1', E_SESS), ro(), { std: { fail: true } }), dv(mk2('s1', E_SESS), ro(), { std: { mapper: 'id' } })],
];
for (const [i, ds] of rdeliveries.entries()) for (const store of ['mem', 'mem1', 'throws', 'false']) { if (store !== 'mem' && i > 6) continue; await add('receiveScenario', `d${i}/${store}`, receiveScenario, [{ store, deliveries: ds }]); }
await add('receiveScenario', 'mem1-full', receiveScenario, [{ store: 'mem1', deliveries: [dv(mk2('a', E_GRANT)), dv(mk2('b', E_KILL)), dv(mk2('a', E_GRANT)), dv(mk2('c', E_INTENT), ro({ nowSec: T + 1000, maxAgeSec: 100000 }))] }]);

// ---- adapters --------------------------------------------------------------------------------------------------------------------------------------
async function adapterScenario(spec: any) {
  const out: any[] = [];
  let hook: any, isRev: any;
  try {
    const st = spec.badState ? (spec.badState === 'null' ? null : {}) : S.restoreRevocationState({ v: 1, grants: spec.grants ?? [], agents: spec.agents ?? [], intents: [] });
    hook = S.createRevocationHook(st, { agentOf: agentOf(spec.agentOf) });
    isRev = S.createIsRevoked(st, { agentOf: agentOf(spec.agentOf) });
  } catch (e) { return [errOut(e)]; }
  for (const c of spec.calls) {
    let a: any, b: any;
    try { a = await hook({ pcactn: c.pcactn, grant: c.grant }); } catch { a = { $err: true }; }
    try { b = isRev(c.grant, c.pcactn); } catch { b = { $err: true }; }
    out.push({ hook: jsonOf(a), isRevoked: b });
  }
  return out;
}
const pc = (ref: any, holder: any = 'hAgent', chain?: any) => ({ grant_ref: ref, cap_chain: chain ?? [{ id: 'root', holder: 'hRoot' }, { id: 'leaf', holder }] });
const calls: any[] = [
  { pcactn: pc('g1'), grant: { id: 'gid' } }, { pcactn: pc('g2'), grant: { id: 'gid' } }, { pcactn: pc('gX'), grant: { id: 'gidRevoked' } }, { pcactn: pc('gX', 'killedAgent'), grant: { id: 'gid' } }, { pcactn: pc('gX', 'killedAgent'), grant: {} }, { pcactn: pc('gX'), grant: null },
  { pcactn: pc(''), grant: { id: 'gid' } }, { pcactn: pc(5), grant: { id: 'gid' } }, { pcactn: { cap_chain: [] }, grant: {} }, { pcactn: pc('gX', 'x', []), grant: {} }, { pcactn: pc('gX', 'x', 'str'), grant: {} }, { pcactn: pc('gX', 'x', 5), grant: {} }, { pcactn: pc('gX', 'x', null), grant: {} },
  { pcactn: pc('gX', 'x', [null]), grant: {} }, { pcactn: pc('gX', 'x', [{ holder: 5 }]), grant: {} }, { pcactn: pc('gX', '', [{ holder: '' }]), grant: {} }, { pcactn: { grant_ref: 'gX' }, grant: {} }, { pcactn: null, grant: {} }, { pcactn: 5, grant: {} }, { pcactn: {}, grant: {} }, {},
  { pcactn: pc('gX', 'killedAgent', [{ holder: 'a' }, { holder: 'killedAgent' }, { holder: 'other' }]), grant: { id: 'gid' } },
];
for (const ag of [undefined, 'leaf', 'throws', 'empty', 'num', 'grantId', 'const:killedAgent', 'const:fine']) {
  await add('adapterScenario', `agent/${ag}`, adapterScenario, [{ grants: [['g1', 5], ['gidRevoked', 7]], agents: [['killedAgent', 9], ['gid', 1]], agentOf: ag, calls }]);
}
await add('adapterScenario', 'empty-state', adapterScenario, [{ calls }]);
await add('adapterScenario', 'bad-state', adapterScenario, [{ badState: {}, calls: [] }]);
await add('adapterScenario', 'null-state', adapterScenario, [{ badState: 'null', calls: [] }]);

// ---- stream: validateStreamConfig / health / verification / poll / push / CAEP ---------------------------------------------------------------------------
const CFG = { stream_id: 's1', iss: 'https://tx.example', aud: 'rx', events_supported: [ET.grantRevoked, ET.killSwitch], events_delivered: [ET.grantRevoked], delivery: { method: S.DELIVERY_POLL, endpoint_url: 'https://tx.example/poll/s1' }, min_verification_interval: 30, description: 'd' };
await add('validateStreamConfig', 'valid', S.validateStreamConfig, [CFG]);
for (const x of [null, 5, 'x', [], true, {}]) await add('validateStreamConfig', `scalar/${JSON.stringify(x)}`, S.validateStreamConfig, [x]);
for (const [name, v] of variants(CFG, { hostile: [null, 0, -0, 1, 1.5, 2 ** 53, '', 'x', ' ', [], [''], [5], {}, true, 'https://', 'https://a b', 'http://x', 'https://x y', 'https://x/﻿'] })) await add('validateStreamConfig', `var/${name}`, S.validateStreamConfig, [v]);
for (const u of ['https://x', 'https://x/a?b#c', 'https://', 'https:/x', 'HTTPS://x', 'https://x y', 'https://x\ty', 'https://x\n', 'https:// ', 'https://x　', 'https://é', 'ftp://x', '', ' https://x']) await add('validateStreamConfig', `url/${JSON.stringify(u)}`, S.validateStreamConfig, [{ ...CFG, delivery: { method: S.DELIVERY_PUSH, endpoint_url: u } }]);

async function healthScenario(spec: any) {
  const h = new S.StreamHealth(spec.config ?? CFG, spec.opts);
  const issued: string[] = [];
  const out: any[] = [];
  const label = (s: any) => (typeof s === 'string' && issued.includes(s) ? `<state:${issued.indexOf(s)}>` : s);
  for (const s of spec.ops) {
    try {
      let r: any;
      switch (s.op) {
        case 'status': h.setStatus(s.v); r = null; break;
        case 'event': h.recordEvent(s.now); r = null; break;
        case 'request': r = h.requestVerification(s.now); if (typeof r === 'string') { issued.push(r); r = `<state:${issued.length - 1}>`; } break;
        case 'ack': r = h.ackVerification(s.ref !== undefined ? issued[s.ref] : s.state, s.now); break;
        case 'report': r = h.report(s.now); break;
        case 'fresh': r = h.revocationFreshWithin(s.max, s.now); break;
        default: throw new Error('bad op');
      }
      out.push(jsonOf(r));
    } catch { out.push({ $err: true }); }
  }
  return out;
}
const hs: any[] = [
  { ops: [{ op: 'report', now: 0 }, { op: 'fresh', max: 10, now: 0 }, { op: 'request', now: 100 }, { op: 'request', now: 110 }, { op: 'request', now: 131 }, { op: 'report', now: 131 }, { op: 'ack', ref: 0, now: 140 }, { op: 'ack', ref: 0, now: 141 }, { op: 'ack', ref: 1, now: 142 }, { op: 'report', now: 142 }, { op: 'fresh', max: 10, now: 150 }, { op: 'fresh', max: 10, now: 153 }, { op: 'fresh', max: 10, now: 152 }, { op: 'report', now: 700 }] },
  { ops: [{ op: 'request', now: 0 }, { op: 'report', now: 61 }, { op: 'request', now: 100 }, { op: 'report', now: 200 }, { op: 'request', now: 300 }, { op: 'report', now: 400 }, { op: 'request', now: 500 }, { op: 'report', now: 600 }, { op: 'ack', state: 'x', now: 601 }, { op: 'ack', state: 5, now: 601 }, { op: 'ack', state: null, now: 601 }, { op: 'report', now: 601 }] },
  { config: { ...CFG, min_verification_interval: undefined }, opts: { maxPending: 2, verifyTimeoutSec: 10 }, ops: [{ op: 'request', now: 0 }, { op: 'request', now: 0 }, { op: 'request', now: 0 }, { op: 'request', now: 11 }, { op: 'report', now: 11 }, { op: 'ack', ref: 2, now: 11 }, { op: 'ack', ref: 3, now: 12 }, { op: 'report', now: 12 }] },
  { opts: { verifiedWithinSec: 50, failAfter: 1 }, ops: [{ op: 'request', now: 0 }, { op: 'ack', ref: 0, now: 5 }, { op: 'report', now: 55 }, { op: 'report', now: 56 }, { op: 'request', now: 60 }, { op: 'report', now: 200 }, { op: 'report', now: 201 }] },
  { ops: [{ op: 'status', v: 'paused' }, { op: 'request', now: 0 }, { op: 'report', now: 0 }, { op: 'fresh', max: 100, now: 0 }, { op: 'status', v: 'disabled' }, { op: 'report', now: 0 }, { op: 'status', v: 'enabled' }, { op: 'request', now: 0 }, { op: 'ack', ref: 0, now: 1 }, { op: 'status', v: 'paused' }, { op: 'fresh', max: 100, now: 2 }, { op: 'report', now: 2 }] },
  { ops: [{ op: 'status', v: 'bogus' }, { op: 'status', v: null }, { op: 'status', v: 5 }, { op: 'status', v: '' }, { op: 'report', now: 0 }] },
  { ops: [{ op: 'event', now: 10 }, { op: 'event', now: 5 }, { op: 'report', now: 10 }, { op: 'event', now: 50 }, { op: 'report', now: 50 }, { op: 'request', now: 50 }, { op: 'ack', ref: 0, now: 40 }, { op: 'report', now: 60 }] },
  { opts: { failAfter: 2, verifyTimeoutSec: 5 }, ops: [{ op: 'request', now: 0 }, { op: 'request', now: 100 }, { op: 'request', now: 200 }, { op: 'report', now: 300 }, { op: 'request', now: 400 }, { op: 'ack', ref: 3, now: 401 }, { op: 'report', now: 401 }] },
];
for (const [i, sp] of hs.entries()) await add('healthScenario', `s${i}`, healthScenario, [sp]);

async function verificationScenario(spec: any) {
  const streams = new Map<string, any>(Object.entries(spec.streams ?? {}).map(([k, v]: any) => [k, structuredClone(v)]));
  const out: any[] = [];
  for (const s of spec.ops) {
    let r: any;
    try {
      r = await S.handleVerificationRequest(streams, s.req, s.now, kPriv(s.noKey ? null : K1.privJwk));
      if (r.status === 204) r = { status: 204, set: shape(r.set) };
    } catch { r = { $err: true }; }
    out.push(jsonOf(r));
  }
  out.push(jsonOf(Object.fromEntries([...streams].map(([k, v]) => [k, v.lastVerification ?? null]))));
  return out;
}
const vcfg = (extra: any = {}) => ({ ...CFG, ...extra });
const vreqs: any[] = [{ stream_id: 's1' }, { stream_id: 's1', state: 'abc' }, { stream_id: 's1', state: '' }, { stream_id: 's1', state: 5 }, { stream_id: 's1', state: null }, { stream_id: 'nope' }, { stream_id: 5 }, {}, null, 'x', 5, [], { state: 'x' }, { stream_id: 's2' }];
for (const [i, rq] of vreqs.entries()) await add('verificationScenario', `req${i}`, verificationScenario, [{ streams: { s1: { config: vcfg() }, s2: { config: vcfg({ stream_id: 's2', min_verification_interval: undefined }), lastVerification: 5 } }, ops: [{ req: rq, now: 100 }, { req: rq, now: 110 }, { req: rq, now: 131 }] }]);
await add('verificationScenario', 'min-interval', verificationScenario, [{ streams: { s1: { config: vcfg(), lastVerification: 100 } }, ops: [{ req: { stream_id: 's1' }, now: 129 }, { req: { stream_id: 's1' }, now: 130 }, { req: { stream_id: 's1', state: 'q' }, now: 150 }, { req: { stream_id: 's1' }, now: 160 }] }]);
await add('verificationScenario', 'aud-array', verificationScenario, [{ streams: { s1: { config: vcfg({ aud: ['a', 'b'] }) } }, ops: [{ req: { stream_id: 's1' }, now: 1 }] }]);
await add('verificationScenario', 'no-config', verificationScenario, [{ streams: { s1: {} }, ops: [{ req: { stream_id: 's1' }, now: 1 }] }]);
await add('verificationScenario', 'bad-key', verificationScenario, [{ streams: { s1: { config: vcfg() } }, ops: [{ req: { stream_id: 's1' }, now: 1, noKey: true }, { req: { stream_id: 's1' }, now: 100 }] }]);

async function pollScenario(spec: any) {
  const q = new S.PollQueue();
  const out: any[] = [];
  for (const s of spec.ops) {
    try {
      let r: any;
      if (s.enqueue) { q.enqueue(s.enqueue[0], s.enqueue[1]); r = null; } else if (s.depth) r = q.depth; else r = q.poll(s.poll);
      out.push(jsonOf(r));
    } catch { out.push({ $err: true }); }
  }
  out.push(jsonOf({ depth: q.depth, errors: q.errors }));
  return out;
}
const enq = [['j1', 's1'], ['j2', 's2'], ['j3', 's3'], ['j4', 's4']].map((e) => ({ enqueue: e }));
const polls: any[] = [{}, { maxEvents: 0 }, { maxEvents: 2 }, { maxEvents: 10 }, { maxEvents: -1 }, { maxEvents: 1.5 }, { maxEvents: -0 }, { maxEvents: '2' }, { maxEvents: null }, { maxEvents: 2 ** 53 }, { ack: ['j1'] }, { ack: ['j1', 'j9', 'j3'], maxEvents: 1 }, { ack: [] }, { ack: null }, { ack: [5, null] },
  { setErrs: { j2: { err: 'invalid_key', description: 'bad' } } }, { setErrs: { j9: { err: 'x', description: 'y' } } }, { setErrs: { j2: { err: 'a' }, j4: {} } }, { setErrs: { j2: null } }, { setErrs: {} }, { ack: ['j1'], setErrs: { j1: { err: 'e', description: 'd' }, j2: { err: 'f', description: 'g' } }, maxEvents: 1 },
  { returnImmediately: true }, null, 5, 'x', [], { ack: {} }, { setErrs: null }];
for (const [i, p] of polls.entries()) await add('pollScenario', `p${i}`, pollScenario, [{ ops: [...enq, { poll: p }, { poll: {} }, { depth: true }, { poll: { maxEvents: 1 } }, { enqueue: ['j1', 'again'] }, { poll: {} }] }]);
await add('pollScenario', 'empty', pollScenario, [{ ops: [{ poll: {} }, { poll: { ack: ['x'] } }, { poll: { maxEvents: 0 } }] }]);
await add('pollScenario', 'more', pollScenario, [{ ops: [...enq, { poll: { maxEvents: 3 } }, { poll: { maxEvents: 3, ack: ['j1', 'j2', 'j3'] } }, { poll: { ack: ['j4'] } }, { poll: { maxEvents: 0 } }] }]);
const rs: any[] = [{ ok: true }, { ok: false, code: 'verify_failed', reason: 'r' }, { ok: false, code: 'malformed', reason: 'r' }, { ok: false, code: 'oversize', reason: 'r' }, { ok: false, code: 'misconfigured', reason: 'r' }, { ok: false, code: 'replay_store_error', reason: 'r' },
  { ok: false, code: 'replay', reason: 'r' }, { ok: false, code: 'iat_stale', reason: 'r' }, { ok: false, code: 'other', reason: 'r' }, { ok: false }, { ok: false, code: 5, reason: 5 }, { ok: 1 }, { ok: 0 }, { ok: 'yes' }, { ok: '' }, { ok: null }, {}, null, 5, 'x', [], { code: 'verify_failed' }, { ok: true, parsed: {} }];
for (const [i, r] of rs.entries()) await add('pushResponse', `r${i}`, S.pushResponse, [r]);

const caepW = async (a: any) => shape(a.kind === 'risk' ? await S.riskLevelChangeSET({ ...a, key: kPriv(a.keyJwk), keyJwk: undefined, kind: undefined }) : await S.assuranceLevelChangeSET({ ...a, key: kPriv(a.keyJwk), keyJwk: undefined, kind: undefined }));
const cb = (extra: any) => ({ issuer: 'https://tx.example', audience: 'rx', keyJwk: K1.privJwk, ...extra });
const caeps: any[] = [
  cb({ kind: 'risk', event: { principal: 'USER', current_level: 'HIGH', previous_level: 'LOW', risk_reason: 'x', event_timestamp: 5 } }), cb({ kind: 'risk', event: { principal: 'USER', current_level: 'LOW', event_timestamp: 5 }, audience: ['a', 'b'] }),
  cb({ kind: 'assurance', event: { namespace: 'nist-aal', current_level: 'aal3', previous_level: 'aal1', event_timestamp: 5 }, order: ['aal1', 'aal2', 'aal3'] }),
  cb({ kind: 'assurance', event: { namespace: 'nist-aal', current_level: 'aal1', previous_level: 'aal3', event_timestamp: 5 }, order: ['aal1', 'aal2', 'aal3'] }),
  cb({ kind: 'assurance', event: { namespace: 'n', current_level: 'aal2', previous_level: 'aal2', event_timestamp: 5 }, order: ['aal1', 'aal2'] }), cb({ kind: 'assurance', event: { namespace: 'n', current_level: 'x', previous_level: 'aal2', event_timestamp: 5 }, order: ['aal1', 'aal2'] }),
  cb({ kind: 'assurance', event: { namespace: 'n', current_level: 'aal2', previous_level: 'aal1', change_direction: 'decrease', event_timestamp: 5 }, order: ['aal1', 'aal2'] }), cb({ kind: 'assurance', event: { namespace: 'n', current_level: 'aal2', event_timestamp: 5 }, order: ['aal1', 'aal2'] }),
  cb({ kind: 'assurance', event: { namespace: 'n', current_level: 'aal2', previous_level: 'aal1', event_timestamp: 5 } }), cb({ kind: 'assurance', event: { namespace: 'n', current_level: 'aal2', previous_level: 'aal1', event_timestamp: 5 }, order: [] }),
  cb({ kind: 'assurance', event: { namespace: 'n', current_level: 'aal2', previous_level: null, event_timestamp: 5 }, order: ['aal1', 'aal2'] }), cb({ kind: 'assurance', event: { namespace: 'n', current_level: 'aal2', previous_level: 'aal1', change_direction: null }, order: ['aal1', 'aal2'] }),
  cb({ kind: 'risk', event: {} }), cb({ kind: 'assurance', event: {} }), cb({ kind: 'risk', keyJwk: null, event: { a: 1 } }),
];
for (const [i, a] of caeps.entries()) await add('caepSET', `c${i}`, caepW, [a]);

// ---- management API ---------------------------------------------------------------------------------------------------------------------------------------
async function manageScenario(spec: any) {
  const store = new S.MemoryStreamStore();
  const delivered: any[] = [];
  let ids = 0;
  let cur: any = {};
  const so = spec.options ?? {};
  const h = S.ssfManagementHandler({
    store, issuer: 'https://tx.example', eventsSupported: spec.eventsSupported ?? [ET.grantRevoked, ET.killSwitch, ET.sessionRevoked], pollEndpoint: (id: string) => `https://tx.example/poll/${id}`, signingKey: K1.priv,
    deliver: (stream: any, set: string) => { delivered.push({ stream: structuredClone(stream), set: shape(set) }); }, now: () => cur.now, newId: () => `s${++ids}`, ...so,
  }, (req: any) => { if (cur.rcv === 'throws') throw new Error('auth'); return cur.rcv; });
  const out: any[] = [];
  for (const st of spec.steps) {
    cur = { now: st.now ?? 1000, rcv: st.rcv === undefined ? { id: 'rx1', aud: 'rx' } : st.rcv };
    let r: any;
    try { r = await h(st.req); } catch { r = { $err: true }; }
    out.push(jsonOf(r));
  }
  const dump: any = {};
  for (const rid of spec.receivers ?? ['rx1', 'rx2']) dump[rid] = jsonOf(await store.listByReceiver(rid));
  out.push({ delivered: jsonOf(delivered), store: dump });
  return out;
}
const rq = (method: string, path: string, body?: any, query?: any) => ({ method, path, ...(body !== undefined ? { body } : {}), ...(query !== undefined ? { query } : {}) });
const CREATE = rq('POST', '/ssf/configuration', {});
const mkS = (steps: any[], extra: any = {}) => ({ steps: [{ req: CREATE }, ...steps], ...extra });
const sid = (q: any = {}) => ({ stream_id: 's1', ...q });
const msteps: any[] = [];
const pushD = { method: S.DELIVERY_PUSH, endpoint_url: 'https://rx.example/push' };
for (const body of [{}, { events_requested: [ET.grantRevoked] }, { events_requested: [ET.grantRevoked, 'https://x.test/unknown'] }, { events_requested: ['https://x.test/unknown'] }, { events_requested: [] }, { events_requested: 'x' }, { events_requested: [''] }, { events_requested: [5] }, { events_requested: null },
  { delivery: pushD }, { delivery: { method: S.DELIVERY_PUSH, endpoint_url: 'http://rx.example' } }, { delivery: { method: S.DELIVERY_PUSH } }, { delivery: { method: S.DELIVERY_POLL, endpoint_url: 'https://ignored.example' } }, { delivery: { method: 'other' } }, { delivery: {} }, { delivery: null }, { delivery: 'x' }, { delivery: [] },
  { description: 'hello' }, { description: 'é'.repeat(300) }, { description: '' }, { description: 5 }, { description: null }, { stream_id: 'x' }, { iss: 'x' }, { unknown: 1 }, { events_requested: [ET.grantRevoked], delivery: pushD, description: 'all' }, { 'z': 1, '1': 2 }, null, 'x', 5, []])
  msteps.push(mkS([{ req: rq('GET', '/ssf/configuration', undefined, { stream_id: 's1' }) }, { req: rq('GET', '/ssf/configuration') }], {}) , { steps: [{ req: rq('POST', '/ssf/configuration', body) }, { req: rq('GET', '/ssf/configuration') }] });
// the rest of the CRUD surface over one created stream
const after: any[][] = [
  [{ req: rq('POST', '/ssf/configuration', {}) }], [{ req: rq('POST', '/ssf/configuration', {}), rcv: { id: 'rx2', aud: 'ry' } }, { req: rq('GET', '/ssf/configuration') }, { req: rq('GET', '/ssf/configuration'), rcv: { id: 'rx2', aud: 'ry' } }],
  [{ req: rq('GET', '/ssf/configuration', undefined, { stream_id: 's1' }), rcv: { id: 'rx2', aud: 'ry' } }, { req: rq('GET', '/ssf/configuration', undefined, { stream_id: 'nope' }) }, { req: rq('GET', '/ssf/configuration', undefined, { stream_id: '' }) }],
  [{ req: rq('PATCH', '/ssf/configuration', sid({ description: 'new' })) }, { req: rq('PATCH', '/ssf/configuration', sid({ events_requested: [ET.killSwitch] })) }, { req: rq('GET', '/ssf/configuration', undefined, { stream_id: 's1' }) }, { req: rq('PATCH', '/ssf/configuration', sid({})) }],
  [{ req: rq('PATCH', '/ssf/configuration', sid({ events_requested: [ET.killSwitch] })) }, { req: rq('PATCH', '/ssf/configuration', sid({ description: 'x' })) }, { req: rq('PATCH', '/ssf/configuration', sid({ events_requested: [ET.grantRevoked] })) }],
  [{ req: rq('PATCH', '/ssf/configuration', sid({ delivery: pushD })) }, { req: rq('PATCH', '/ssf/configuration', sid({ delivery: { method: S.DELIVERY_POLL } })) }, { req: rq('PATCH', '/ssf/configuration', sid({ delivery: null })) }, { req: rq('PATCH', '/ssf/configuration', sid({ delivery: {} })) }],
  [{ req: rq('PATCH', '/ssf/configuration', sid({ iss: 'other' })) }, { req: rq('PATCH', '/ssf/configuration', sid({ iss: 'https://tx.example' })) }, { req: rq('PATCH', '/ssf/configuration', sid({ aud: 'rx' })) }, { req: rq('PATCH', '/ssf/configuration', sid({ aud: 'z' })) }, { req: rq('PATCH', '/ssf/configuration', sid({ events_supported: [ET.grantRevoked] })) },
    { req: rq('PATCH', '/ssf/configuration', sid({ events_delivered: [ET.grantRevoked, ET.killSwitch, ET.sessionRevoked] })) }, { req: rq('PATCH', '/ssf/configuration', sid({ events_delivered: [ET.killSwitch, ET.grantRevoked, ET.sessionRevoked] })) }, { req: rq('PATCH', '/ssf/configuration', sid({ min_verification_interval: 5 })) }, { req: rq('PATCH', '/ssf/configuration', sid({ stream_id: 's1' })) }],
  [{ req: rq('PATCH', '/ssf/configuration', { description: 'x' }) }, { req: rq('PATCH', '/ssf/configuration', { stream_id: 5 }) }, { req: rq('PATCH', '/ssf/configuration', { stream_id: 'nope' }) }, { req: rq('PATCH', '/ssf/configuration', sid({ extra: 1 })) }, { req: rq('PATCH', '/ssf/configuration') }, { req: rq('PATCH', '/ssf/configuration', null) }, { req: rq('PATCH', '/ssf/configuration', [1]) }, { req: rq('PATCH', '/ssf/configuration', sid({ description: 5 })) }, { req: rq('PATCH', '/ssf/configuration', sid({ events_requested: [] })) }, { req: rq('PATCH', '/ssf/configuration', sid({ events_requested: ['https://x.test/u'] })) }],
  [{ req: rq('PUT', '/ssf/configuration', sid({ description: 'p' })) }, { req: rq('GET', '/ssf/configuration', undefined, { stream_id: 's1' }) }, { req: rq('PUT', '/ssf/configuration', sid({ events_requested: [ET.sessionRevoked], delivery: { method: S.DELIVERY_POLL } })) }, { req: rq('PUT', '/ssf/configuration', sid({ delivery: pushD })) }, { req: rq('PUT', '/ssf/configuration', sid({ events_requested: ['https://x.test/u'] })) }, { req: rq('PUT', '/ssf/configuration', sid({ description: 5 })) }],
  [{ req: rq('DELETE', '/ssf/configuration', undefined, { stream_id: 's1' }), rcv: { id: 'rx2', aud: 'ry' } }, { req: rq('DELETE', '/ssf/configuration', undefined, { stream_id: 's1' }) }, { req: rq('DELETE', '/ssf/configuration', undefined, { stream_id: 's1' }) }, { req: rq('GET', '/ssf/configuration') }, { req: rq('DELETE', '/ssf/configuration') }, { req: rq('POST', '/ssf/configuration', {}) }],
  [{ req: rq('GET', '/ssf/status', undefined, { stream_id: 's1' }) }, { req: rq('GET', '/ssf/status') }, { req: rq('GET', '/ssf/status', undefined, { stream_id: 'nope' }) }, { req: rq('POST', '/ssf/status', { stream_id: 's1', status: 'paused', reason: 'maint' }) }, { req: rq('GET', '/ssf/status', undefined, { stream_id: 's1' }) }, { req: rq('POST', '/ssf/status', { stream_id: 's1', status: 'enabled' }) }, { req: rq('GET', '/ssf/status', undefined, { stream_id: 's1' }) }],
  [{ req: rq('POST', '/ssf/status', { stream_id: 's1', status: 'bogus' }) }, { req: rq('POST', '/ssf/status', { stream_id: 's1' }) }, { req: rq('POST', '/ssf/status', { stream_id: 's1', status: null }) }, { req: rq('POST', '/ssf/status', { status: 'paused' }) }, { req: rq('POST', '/ssf/status', { stream_id: 's1', status: 'paused', reason: 5 }) }, { req: rq('POST', '/ssf/status', { stream_id: 'nope', status: 'paused' }) }, { req: rq('POST', '/ssf/status') }, { req: rq('POST', '/ssf/status', { stream_id: 's1', status: 'disabled', reason: '' }) }, { req: rq('GET', '/ssf/status', undefined, { stream_id: 's1' }) }, { req: rq('PUT', '/ssf/status', {}) }, { req: rq('DELETE', '/ssf/status') }],
  [{ req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { format: 'email', email: 'a@b' } }) }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { email: 'a@b', format: 'email' }, verified: false }) }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { format: 'opaque', id: 'x' } }) }, { req: rq('GET', '/ssf/configuration', undefined, { stream_id: 's1' }) },
    { req: rq('POST', '/ssf/remove_subject', { stream_id: 's1', subject: { format: 'email', email: 'a@b' } }) }, { req: rq('POST', '/ssf/remove_subject', { stream_id: 's1', subject: { format: 'email', email: 'zz' } }) }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { format: 'opaque', id: 'x' }, verified: null }) }],
  [{ req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { format: 'email', email: 'a@b' } }) }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { format: 'email', email: 'c@d' } }) }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { format: 'email', email: 'a@b' } }) }, { req: rq('POST', '/ssf/remove_subject', { stream_id: 's1', subject: { format: 'email', email: 'a@b' } }) }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { format: 'email', email: 'c@d' } }) }],
  [{ req: rq('POST', '/ssf/add_subject', { stream_id: 's1' }) }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: null }) }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: [] }) }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { format: '' } }) }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { format: 5 } }) }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { format: 'email' }, verified: 'yes' }) },
    { req: rq('POST', '/ssf/add_subject', { subject: { format: 'email' } }) }, { req: rq('POST', '/ssf/add_subject', { stream_id: 'nope', subject: { format: 'email' } }) }, { req: rq('GET', '/ssf/add_subject') }, { req: rq('POST', '/ssf/remove_subject') }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { '10': 'a', '2': 'b', format: 'x', zz: [1, { b: 1, a: 2 }] } }) }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { format: 'x', 'é': 1, 'z': 2, 'Z': 3 } }) }],
  [{ req: rq('POST', '/ssf/verification', { stream_id: 's1' }) }, { req: rq('POST', '/ssf/verification', { stream_id: 's1', state: 'abc' }), now: 2000 }, { req: rq('POST', '/ssf/verification', { stream_id: 's1', state: 5 }) }, { req: rq('POST', '/ssf/verification', { stream_id: 'nope' }) }, { req: rq('POST', '/ssf/verification', {}) }, { req: rq('POST', '/ssf/verification', { stream_id: 5 }) }, { req: rq('POST', '/ssf/verification') }, { req: rq('GET', '/ssf/verification') },
    { req: rq('POST', '/ssf/status', { stream_id: 's1', status: 'disabled' }) }, { req: rq('POST', '/ssf/verification', { stream_id: 's1' }) }, { req: rq('POST', '/ssf/status', { stream_id: 's1', status: 'paused' }) }, { req: rq('POST', '/ssf/verification', { stream_id: 's1', state: 'p' }) }],
  [{ req: rq('GET', '/ssf/unknown') }, { req: rq('GET', '/') }, { req: rq('GET', '') }, { req: rq('GET', '/ssf/configuration/') }, { req: rq('GET', '//ssf//status//') }, { req: rq('GET', 'status') }, { req: rq('get', '/ssf/status', undefined, { stream_id: 's1' }) }, { req: rq('Patch', '/ssf/configuration', sid({ description: 'lc' })) }, { req: rq('OPTIONS', '/ssf/status') }, { req: rq('HEAD', '/ssf/configuration') },
    { req: { method: 'GET', path: 5 } }, { req: { method: 5, path: '/ssf/status' } }, { req: { path: '/ssf/status' } }, { req: { method: 'GET' } }, { req: {} }, { req: null }, { req: 'x' }, { req: rq('GET', '/ssf/status', undefined, null) }, { req: rq('GET', '/ssf/status', undefined, 'x') }, { req: { method: 'GET', path: '/ssf/status', query: { stream_id: 5 } } }],
  [{ req: rq('GET', '/ssf/configuration'), rcv: null }, { req: rq('GET', '/ssf/configuration'), rcv: 'throws' }, { req: rq('GET', '/ssf/configuration'), rcv: { id: 'nobody', aud: 'x' } }, { req: rq('POST', '/ssf/configuration', {}), rcv: { id: 'rx2', aud: ['a', 'b'] } }, { req: rq('GET', '/ssf/configuration', undefined, { stream_id: 's2' }), rcv: { id: 'rx2', aud: ['a', 'b'] } }],
];
for (const [i, a] of after.entries()) msteps.push(mkS(a, i === 0 ? {} : {}));
msteps.push(mkS([{ req: rq('POST', '/ssf/configuration', {}) }], { options: { maxStreamsPerReceiver: 2 } }), { options: { maxStreamsPerReceiver: 2 }, steps: [{ req: CREATE }, { req: CREATE }, { req: CREATE }, { req: rq('GET', '/ssf/configuration') }] });
msteps.push({ options: { maxSubjectsPerStream: 1 }, steps: [{ req: CREATE }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { format: 'email', email: 'a@b' } }) }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { format: 'email', email: 'c@d' } }) }, { req: rq('POST', '/ssf/add_subject', { stream_id: 's1', subject: { format: 'email', email: 'a@b' } }) }] });
msteps.push({ options: { deliveryMethods: [S.DELIVERY_PUSH] }, steps: [{ req: CREATE }, { req: rq('POST', '/ssf/configuration', { delivery: pushD }) }, { req: rq('POST', '/ssf/configuration', { delivery: { method: S.DELIVERY_POLL } }) }] });
msteps.push({ options: { deliveryMethods: [S.DELIVERY_POLL] }, steps: [{ req: rq('POST', '/ssf/configuration', { delivery: pushD }) }, { req: CREATE }, { req: rq('PATCH', '/ssf/configuration', { stream_id: 's2', delivery: pushD }) }] });
msteps.push({ eventsSupported: [], steps: [{ req: CREATE }] }, { eventsSupported: [ET.grantRevoked], steps: [{ req: CREATE }, { req: rq('PATCH', '/ssf/configuration', sid({ events_requested: [ET.killSwitch] })) }] });
msteps.push({ steps: [{ req: CREATE }, { req: rq('POST', '/ssf/verification', { stream_id: 's1' }), now: 100 }, { req: rq('POST', '/ssf/verification', { stream_id: 's1' }), now: 100 }, { req: rq('GET', '/ssf/configuration', undefined, { stream_id: 's1' }) }] });
msteps.push({ steps: [{ req: rq('POST', '/ssf/configuration', {}), now: 5 }, { req: rq('DELETE', '/ssf/configuration', undefined, { stream_id: 's1' }), now: 6 }, { req: rq('POST', '/ssf/configuration', { delivery: pushD }), now: 7 }, { req: rq('GET', '/ssf/status', undefined, { stream_id: 's2' }) }] });
for (const [i, sp] of msteps.entries()) await add('manageScenario', `m${i}`, manageScenario, [sp]);
for (const [name, base] of Object.entries({ plain: 'https://tx.example', slash: 'https://tx.example/', empty: '' }) as any[]) for (const jw of [undefined, 'https://tx.example/jwks', '']) for (const dm of [undefined, [S.DELIVERY_PUSH], []])
  await add('transmitterMetadata', `${name}/${jw}/${JSON.stringify(dm)}`, (op: any, b: any, j: any) => S.transmitterMetadata(op, b, j), [{ issuer: 'https://tx.example', ...(dm === undefined ? {} : { deliveryMethods: dm }) }, base, jw]);

refWrite(o, 'signals');
