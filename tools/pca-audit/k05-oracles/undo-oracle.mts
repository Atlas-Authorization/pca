// k05 oracle: undo windows, the pure layer (Java Undo and every native port). TS reference: packages/pca/src/undo.ts.
// Extends conformance/undo-vectors.json with generated, boundary-heavy inputs: every token member retyped / deleted / tampered,
// the full state x event x clock product of the state machine (plus malformed records and events), receipt chains with every
// link broken, hostile token strings, and the window clamp grid. Secrets are deterministic seeds passed as base64url.
// Writes tools/pca-audit/k05-oracles/out/k05-undo.json.gz. Deterministic (Ed25519 is deterministic).
// PORTING (fn -> Java; other natives use their twin). Secrets are args as base64url of the 32-byte Ed25519 seed.
//   compensationDigest(c)               Undo.compensationDigest(c)                    exact digest; {$throws} -> must throw
//   signUndoToken(rec, sk)              Undo.signToken(rec, Keys.edFromSeed(b64u(sk)))              canonical-JSON equality; {$throws} -> must throw
//   undoTokenCheck(t, signer, rec, now) Undo.tokenCheck(t, signer, rec, now)          exact code string (ok|malformed|signer|signature|record|binding|expired)
//   encodeUndoToken / undoTokenDigest   Undo.encodeToken / Undo.tokenDigest           exact string
//   decodeUndoToken(s)                  Undo.decodeToken(s)                           null <-> null; else canonical-JSON equality. Since 0.5 the token is
//                                       parsed in the strict JSON profile (no BOM, duplicate member, -0, exponent, lone surrogate)
//   signUndoReceipt(body, sk)           Undo.signReceipt(body, Keys.edFromSeed(b64u(sk)))           canonical-JSON equality
//   undoReceiptDigest / verifyUndoReceipt   Undo.receiptDigest / Undo.verifyReceipt   exact
//   undoReceiptChainError(rec, signer)  Undo.receiptChainError(rec, signer)           exact string | null
//   undoTransition(rec, ev, now)        Undo.transition(rec, ev, now)                 outcome + code + reason exact; applied/replayed: record canonical-JSON
//                                       equal, receipt {event, note} exact (note/reason truncation is in UTF-16 code units)
//   resolveUndoWindow(req, policy)      Undo.resolveWindow(req, policy.minMs, policy.maxMs, policy.defaultMs)   exact integer (req null = absent)
import * as P from '../../../packages/pca/src/index.ts';
import { Oracle, variants, rng, seed, ser } from './lib.mjs';

const pca: any = (P as any).undoTransition ? P : (P as any).default;
const o = new Oracle('undo', 'tools/pca-audit/k05-oracles/undo-oracle.mts', 'TS-reference oracle for undo windows (pure layer): compensation digest, token sign/check/encode/decode/digest, receipts and chains, the state machine, the window clamp.');
const fromB64u = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const SK = pca.b64u(seed('k05-undo/signer'));
const SK2 = pca.b64u(seed('k05-undo/other'));
const SIGNER = pca.b64u(pca.publicKeyOf(fromB64u(SK)));
const OTHER = pca.b64u(pca.publicKeyOf(fromB64u(SK2)));
const D = (l: string) => pca.b64u(seed(`k05-undo/${l}`));
const T0 = 1_800_000_000_000;
const END = T0 + 900_000;
const r = rng(0x0d0);

// ---- compensation digest ----------------------------------------------------------------------------------------------
const C1 = { verb: 'drafts.delete', resource: 'drafts:box1', params: { box: 'box1', n: 3, tags: ['a', 'b'], nested: { z: 1, a: [true, null] } }, undo_of: 'op_1', def_digest: D('def'), target_param: 'draft' };
const cd = (n: string, c: unknown) => o.run('compensationDigest', n, pca.compensationDigest, [c]);
await cd('full', C1);
for (const [n, c] of variants(C1, { hostile: [null, 0, -0, 1.5, '', 'x', [], {}, '\ud800', 2 ** 53] })) await cd(n, c);

// ---- tokens -----------------------------------------------------------------------------------------------------------
const REC = { id: 'op_1', aud: 'drafts-rs', principal: D('principal'), compensation_digest: pca.compensationDigest(C1), render_digest: D('render'), window_end: END };
const signTok = (rec: unknown, sk: string) => pca.signUndoToken(rec, fromB64u(sk));
const st = (n: string, rec: unknown, sk: string) => o.run('signUndoToken', n, (a: unknown, b: string) => (typeof b === 'string' ? signTok(a, b) : pca.signUndoToken(a, b)), [rec, sk]);
await st('base', REC, SK);
await st('other key', REC, SK2);
await st('no render', { ...REC, render_digest: undefined }, SK);
await st('short key', REC, pca.b64u(seed('x').subarray(0, 31)));
await st('long key', REC, pca.b64u(new Uint8Array(33)));
for (const [n, v] of variants(REC, { hostile: [null, '', 'x', 0, -0, 1.5, 2 ** 53, '\ud800', 'a\u0000b'] })) await st(n, v, SK);

const TOK = signTok(REC, SK);
const check = (n: string, t: unknown, signer: unknown, rec: unknown, now: unknown) => o.run('undoTokenCheck', n, pca.undoTokenCheck, [t, signer, rec, now]);
for (const now of [T0, END - 1, END, END + 1, 0, -1, 1.5, 2 ** 53, -0, null, '1'])
  await check(`valid now=${ser(now)}`, TOK, SIGNER, REC, now);
await check('other signer pinned', TOK, OTHER, REC, T0);
await check('signer pinned empty', TOK, '', REC, T0);
// every token member: deleted, retyped (the token is NOT re-signed: shape, then signer, then signature fail in order)
for (const [n, t] of variants(TOK, { lens: [0, 1, 255, 256, 257] })) await check('tok ' + n, t, SIGNER, REC, T0);
// re-signed tokens whose body differs from the record (binding / record / expiry), and from the other key (signer)
const resign = (patch: Record<string, unknown>, sk = SK) => signTok({ ...REC, ...patch }, sk);
await check('record differs', resign({ id: 'op_2' }), SIGNER, REC, T0);
await check('aud differs', resign({ aud: 'x' }), SIGNER, REC, T0);
await check('principal differs', resign({ principal: D('p2') }), SIGNER, REC, T0);
await check('compensation differs', resign({ compensation_digest: D('c2') }), SIGNER, REC, T0);
await check('render differs', resign({ render_digest: D('r2') }), SIGNER, REC, T0);
await check('render empty vs record render', resign({ render_digest: undefined }), SIGNER, REC, T0);
await check('render empty vs record none', resign({ render_digest: undefined }), SIGNER, { ...REC, render_digest: undefined }, T0);
await check('render vs record none', TOK, SIGNER, { ...REC, render_digest: undefined }, T0);
await check('window end differs +1', resign({ window_end: END + 1 }), SIGNER, REC, T0);
await check('window end differs -1', resign({ window_end: END - 1 }), SIGNER, REC, T0);
await check('expired via binding window', resign({ window_end: T0 - 1 }), SIGNER, { ...REC, window_end: T0 - 1 }, T0);
await check('other key, pinned other', resign({}, SK2), OTHER, REC, T0);
await check('other key, pinned signer', resign({}, SK2), SIGNER, REC, T0);
await check('id 256', resign({ id: 'a'.repeat(256) }), SIGNER, { ...REC, id: 'a'.repeat(256) }, T0);
await check('id control char', { ...TOK, record: 'a\u001fb' }, SIGNER, REC, T0);
await check('id DEL char ok', resign({ id: 'a\u007fb' }), SIGNER, { ...REC, id: 'a\u007fb' }, T0);
// record side malformed
for (const [n, rec] of variants(REC, { hostile: [null, '', 0, 1.5, -0, 'x', 2 ** 53] })) await check('rec ' + n, TOK, SIGNER, rec, T0);
// signature bytes
for (let i = 0; i < 64; i += 7) {
  const b = fromB64u(TOK.sig);
  b[i] ^= 1;
  await check(`sig byte ${i} flipped`, { ...TOK, sig: pca.b64u(b) }, SIGNER, REC, T0);
}
await check('sig 63 bytes', { ...TOK, sig: pca.b64u(fromB64u(TOK.sig).subarray(0, 63)) }, SIGNER, REC, T0);
await check('sig padded', { ...TOK, sig: TOK.sig + '=' }, SIGNER, REC, T0);
await check('sig non-canonical tail', { ...TOK, sig: TOK.sig.slice(0, -1) + (TOK.sig.endsWith('A') ? 'B' : 'A') }, SIGNER, REC, T0);
await check('member order changed', Object.fromEntries(Object.entries(TOK).reverse()), SIGNER, REC, T0);
await check('v 1.0 text', { ...TOK, v: 1.0 }, SIGNER, REC, T0);

// encode / decode / digest
await o.run('encodeUndoToken', 'base', pca.encodeUndoToken, [TOK]);
await o.run('undoTokenDigest', 'base', pca.undoTokenDigest, [TOK]);
await o.run('encodeUndoToken', 'reordered', pca.encodeUndoToken, [Object.fromEntries(Object.entries(TOK).reverse())]);
await o.run('undoTokenDigest', 'reordered', pca.undoTokenDigest, [Object.fromEntries(Object.entries(TOK).reverse())]);
const ENC = pca.encodeUndoToken(TOK);
const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
const dec = (n: string, s: unknown) => o.run('decodeUndoToken', n, pca.decodeUndoToken, [s]);
await dec('round trip', ENC);
for (const [i, s] of [
  '', 'A', 'AA', 'AAA', ENC + '=', ENC.slice(0, -1), ENC + 'A', ENC.replace(/-/g, '+'), ENC.replace(/_/g, '/'), b64('{}'), b64('[]'), b64('null'), b64('1'), b64('"x"'),
  b64('{"a":1}'), b64('{"a":1} '), b64(' {"a":1}'), b64('{"a":1,}'), b64('{"a":-0}'), b64('{"a":1e400}'), b64('{"a":"\\ud800"}'), b64('{"a":1,"a":2}'),
  Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]).toString('base64url'), Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]).toString('base64url'),
  'A'.repeat(4096), 'A'.repeat(4097), b64('{"a":"' + 'x'.repeat(3000) + '"}').slice(0, 4096), b64('{"a":"' + 'x'.repeat(3000) + '"}'), 7, null, [ENC], { t: ENC },
].entries()) await dec(`hostile #${i}`, s);
for (const k of [3063, 3064, 3065]) { const t = b64(`{"a":"${'x'.repeat(k)}"}`); await dec(`length ${t.length}`, t); } // 4095 / 4096 / 4098 chars

// ---- receipts and chains ----------------------------------------------------------------------------------------------
const sr = (body: Record<string, unknown>, sk = SK) => pca.signUndoReceipt(body, fromB64u(sk));
const RB = { record: 'op_1', event: 'opened', state: 'open', at: T0, compensation_digest: REC.compensation_digest, prev: '', note: '' };
await o.run('signUndoReceipt', 'base', (b: unknown, k: string) => sr(b as any, k), [RB, SK]);
await o.run('signUndoReceipt', 'note+prev', (b: unknown, k: string) => sr(b as any, k), [{ ...RB, event: 'vetoed', state: 'vetoed', prev: D('prev'), note: 'token' }, SK]);
const R1 = sr(RB);
await o.run('undoReceiptDigest', 'base', pca.undoReceiptDigest, [R1]);
const vr = (n: string, x: unknown, s: unknown) => o.run('verifyUndoReceipt', n, pca.verifyUndoReceipt, [x, s]);
await vr('base', R1, SIGNER);
await vr('other pin', R1, OTHER);
await vr('null pin', R1, null);
for (const [n, x] of variants(R1, { lens: [0, 256, 257] })) await vr(n, x, SIGNER);
for (const ev of [...pca.UNDO_EVENTS, 'nope', 'Opened'])
  for (const s of [...pca.UNDO_STATES, 'closed']) await vr(`signed ${ev}/${s}`, sr({ ...RB, event: ev, state: s }), SIGNER);
for (const at of [0, -1, 2 ** 53 - 1, 2 ** 53, 1.5, -0]) await vr(`signed at ${ser(at)}`, (() => { try { return sr({ ...RB, at }); } catch { return { ...R1, at }; } })(), SIGNER);

// a full chain: opened -> vetoed -> compensation_failed -> retried -> compensated
const chainOf = (steps: [string, string, number, string][]) => {
  const out: any[] = [];
  for (const [event, state, at, note] of steps) out.push(sr({ ...RB, event, state, at, note, prev: out.length ? pca.undoReceiptDigest(out[out.length - 1]) : '' }));
  return out;
};
const CH = chainOf([['opened', 'open', T0, ''], ['vetoed', 'vetoed', T0 + 5, 'token'], ['compensation_failed', 'compensation_failed', T0 + 6, 'boom'], ['retried', 'vetoed', T0 + 6, ''], ['compensated', 'compensated', T0 + 9, '']]);
const chain = (n: string, receipts: unknown, state = 'compensated', id = 'op_1', cdig = REC.compensation_digest, signer: unknown = SIGNER) =>
  o.run('undoReceiptChainError', n, pca.undoReceiptChainError, [{ id, compensation_digest: cdig, state, receipts }, signer]);
await chain('full', CH);
for (let k = 1; k <= CH.length; k++) for (const s of pca.UNDO_STATES) await chain(`prefix ${k} state ${s}`, CH.slice(0, k), s);
await chain('empty', []);
await chain('not array', {});
await chain('null', null);
await chain('other record id', CH, 'compensated', 'op_2');
await chain('other compensation', CH, 'compensated', 'op_1', D('c2'));
await chain('other signer', CH, 'compensated', 'op_1', REC.compensation_digest, OTHER);
await chain('dropped middle', [CH[0], CH[2], CH[3], CH[4]]);
await chain('swapped', [CH[0], CH[2], CH[1], CH[3], CH[4]]);
await chain('first not opened', chainOf([['vetoed', 'vetoed', T0, '']]), 'vetoed');
await chain('time back', chainOf([['opened', 'open', T0, ''], ['vetoed', 'vetoed', T0 - 1, '']]), 'vetoed');
await chain('time equal', chainOf([['opened', 'open', T0, ''], ['vetoed', 'vetoed', T0, '']]), 'vetoed');
await chain('first prev not empty', [sr({ ...RB, prev: D('x') })], 'open');
await chain('second other record', [CH[0], sr({ ...RB, record: 'op_2', event: 'vetoed', state: 'vetoed', prev: pca.undoReceiptDigest(CH[0]) })], 'vetoed');
await chain('second other compensation', [CH[0], sr({ ...RB, compensation_digest: D('c3'), event: 'vetoed', state: 'vetoed', prev: pca.undoReceiptDigest(CH[0]) })], 'vetoed');
for (const [n, x] of variants(CH[1], { hostile: [null, '', 0, 'x'] })) await chain('r1 ' + n, [CH[0], x, CH[2], CH[3], CH[4]]);
for (let i = 0; i < 40; i++) {
  const len = r.int(1, 6);
  const steps: [string, string, number, string][] = [];
  let at = T0;
  for (let j = 0; j < len; j++) { at += r.int(-1, 3); steps.push([j === 0 && r.next() < 0.8 ? 'opened' : r.pick(pca.UNDO_EVENTS), r.pick(pca.UNDO_STATES), at, r.pick(['', 'x'])]); }
  await chain(`random #${i}`, chainOf(steps), r.pick(pca.UNDO_STATES));
}

// ---- the state machine: every state x event x clock, plus malformed inputs -------------------------------------------
const BASE_REC = { v: 1, id: 'op_1', aud: 'drafts-rs', grant_ref: D('g'), holder: D('h'), principal: REC.principal, action: { verb: 'drafts.create', resource: 'drafts:box1', params_digest: D('pd'), def_digest: D('dd') }, compensation: C1, compensation_digest: REC.compensation_digest, render_digest: REC.render_digest, opened_at: T0, window_end: END, converted: true, state: 'open', ver: 3, pcactn: 'x', attempt: 0, receipts: [] };
const VETO = { at: T0 + 1, via: 'token', by: REC.principal, evidence: D('ev') };
const EVENTS: [string, unknown][] = [
  ['veto', { kind: 'veto', veto: VETO }], ['veto no evidence', { kind: 'veto', veto: { at: T0, via: 'operator', by: 'op' } }],
  ['finalize', { kind: 'finalize' }], ['abort', { kind: 'abort', reason: 'never ran' }], ['abort no reason', { kind: 'abort' }],
  ['abort long reason', { kind: 'abort', reason: 'é'.repeat(600) }], ['abort astral reason', { kind: 'abort', reason: 'a' + '😀'.repeat(300) }],
  ['abort number reason', { kind: 'abort', reason: 5 }], ['abort null reason', { kind: 'abort', reason: null }], ['abort object reason', { kind: 'abort', reason: { a: 1 } }], ['abort array reason', { kind: 'abort', reason: ['a', 'b'] }],
  ['effect', { kind: 'effect' }], ['effect result', { kind: 'effect', result: { id: 'd1', n: [1, 2] } }], ['effect null result', { kind: 'effect', result: null }],
  ['compensated', { kind: 'compensated' }], ['compensated result', { kind: 'compensated', result: { ok: true } }], ['compensated null result', { kind: 'compensated', result: null }],
  ['compensation_failed', { kind: 'compensation_failed', reason: 'boom' }], ['compensation_failed 129', { kind: 'compensation_failed', reason: 'x'.repeat(129) }],
  ['compensation_failed 513', { kind: 'compensation_failed', reason: 'y'.repeat(513) }], ['compensation_failed no reason', { kind: 'compensation_failed' }], ['compensation_failed astral reason', { kind: 'compensation_failed', reason: 'a' + '😀'.repeat(300) }],
  ['retry', { kind: 'retry' }], ['unknown', { kind: 'nope' }], ['no kind', {}], ['null event', null], ['string event', 'veto'], ['array event', [{ kind: 'retry' }]],
];
const tr = (n: string, rec: unknown, ev: unknown, now: unknown) => o.run('undoTransition', n, pca.undoTransition, [rec, ev, now]);
const STATE_EXTRAS: [string, Record<string, unknown>][] = [
  ['', {}], [' +effect', { effect: { at: T0 } }], [' +aborted', { outcome: { at: T0, status: 'aborted' } }], [' +veto', { veto: VETO }],
  [' attempt 2', { attempt: 2 }], [' attempt -1', { attempt: -1 }], [' attempt 1.5', { attempt: 1.5 }], [' attempt missing', { attempt: undefined }], [' attempt 2^53-1', { attempt: 2 ** 53 - 1 }],
];
for (const s of pca.UNDO_STATES)
  for (const [xn, extra] of STATE_EXTRAS)
    for (const [en, ev] of EVENTS)
      for (const now of [T0, END, END + 1])
        await tr(`${s}${xn} / ${en} / now ${now === T0 ? 'T0' : now === END ? 'END' : 'END+1'}`, { ...BASE_REC, state: s, ...extra }, ev, now);
for (const [n, v] of variants(VETO, { hostile: [null, '', 0, -0, 1.5, 'x', 2 ** 53, [], {}] })) await tr('veto ' + n, BASE_REC, { kind: 'veto', veto: v }, T0);
for (const via of [...pca.VETO_VIAS, 'Token', 'email']) await tr(`veto via ${via}`, BASE_REC, { kind: 'veto', veto: { ...VETO, via } }, T0);
for (const now of [0, -1, 1.5, -0, 2 ** 53, 2 ** 53 - 1, null, '1', END - 1]) await tr(`now ${ser(now)}`, BASE_REC, { kind: 'veto', veto: VETO }, now);
for (const [n, rec] of variants(BASE_REC, { depth: 1, hostile: [null, '', 0, -0, 1.5, 'x', 2 ** 53, 2 ** 53 - 1, -1, [], {}] })) {
  await tr('rec ' + n + ' / veto', rec, { kind: 'veto', veto: VETO }, T0);
  await tr('rec ' + n + ' / finalize', rec, { kind: 'finalize' }, END + 1);
}
for (const ver of [0, 2 ** 53 - 1, 2 ** 53 - 2]) await tr(`ver ${ver}`, { ...BASE_REC, ver }, { kind: 'veto', veto: VETO }, T0);
await tr('record null', null, { kind: 'finalize' }, T0);
await tr('record array', [], { kind: 'finalize' }, T0);

// ---- window clamp -----------------------------------------------------------------------------------------------------
const W = [undefined, 0, 1, 29_999, 30_000, 30_001, 900_000, 86_399_999, 86_400_000, 86_400_001, 1e15, -5, 1.5, 30_000.7, 2 ** 53];
for (const req of W)
  for (const pol of [{}, { minMs: 60_000 }, { minMs: 1 }, { maxMs: 40_000 }, { maxMs: 1 }, { maxMs: 1e12 }, { defaultMs: 10 }, { defaultMs: 100_000 }, { minMs: 100_000, maxMs: 50_000 }, { minMs: 45_000.5, maxMs: 45_000.9, defaultMs: 1 }])
    await o.run('resolveUndoWindow', `${ser(req ?? null)} ${ser(pol)}`, pca.resolveUndoWindow, [req ?? null, pol]);
o.write();
