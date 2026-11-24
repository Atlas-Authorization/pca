// k05 differential oracle: provenance by default (packages/pca/src/arg-provenance.ts + server/require-pca.ts defaultProvenanceBundle).
// Natives: Java ArgProvenance.java (and every port). See README.md for the per-fn porting note.
//   packages/pca/node_modules/tsx/dist/cli.mjs --tsconfig tools/pca-audit/k05-oracles/tsconfig.json tools/pca-audit/k05-oracles/argprov-oracle.mts
// Deterministic: seeded Ed25519 keys, fixed sessions and clocks.
import * as P from '../../../packages/pca/src/index.ts';
import { Oracle, variants, rng, seed, reparse, clone, around, setAt, DEL, HOSTILE } from './lib.mjs';

const p: any = (P as any).decideArgProvenance ? P : (P as any).default;
const O = new Oracle('argprov', 'tools/pca-audit/k05-oracles/argprov-oracle.mts', 'TS-reference oracle for ArgProvenance (provenance by default): receipt/pin/action-info/envelope wire checks, token matching, leaves, the decision, the recorder and the request reader.');

const used = new Map<string, number>();
/** O.run with a unique name (generated labels may collide after truncation). */
const run = (fn: string, n: string, ref: any, a: any[]) => { const k = `${fn}/${n}`; const c = used.get(k) ?? 0; used.set(k, c + 1); return O.run(fn, c ? `${n} #${c}` : n, ref, a); };
const sk = (l: string) => seed(`k05argprov/${l}`);
const SK = sk('mediator');
const SK2 = sk('other');
const SESSION = p.b64u(seed('k05argprov/session'));
const SESSION2 = p.b64u(seed('k05argprov/session2'));
const T0 = 1_792_929_600_000;
const D = (l: string) => p.b64u(seed(`k05argprov/d/${l}`));

type Step = [string, ...any[]];
/** Build a recorder session; returns {rec, outs}. */
function session(steps: Step[], o: any = {}) {
  let t = o.t0 ?? T0;
  const clock = o.clock ?? (() => (t += 1000));
  const rec = p.createProvenanceRecorder({ mediator: o.mediator ?? 'harness', kid: o.kid ?? 'k1', secretKey: o.sk ?? SK, session: o.session ?? SESSION, now: clock });
  let bundle: any;
  for (const s of steps) {
    if (s[0] === 'principal') rec.principal(s[1]);
    else if (s[0] === 'tool') rec.tool(s[1], s[2]);
    else if (s[0] === 'retrieval') rec.retrieval(s[1], s[2]);
    else if (s[0] === 'web') rec.web(s[1], s[2]);
    else if (s[0] === 'action') bundle = rec.forAction(s[1]);
  }
  return { rec, bundle, pin: rec.pin };
}
const OP = { verb: 'payments.send', resource: 'payments/acme', params: { amount: 50, payee: 'acme-ltd', memo: 'invoice 42' } };
const S0 = session([['principal', 'please pay acme-ltd 50 for invoice 42'], ['action', OP]]);
const PIN = S0.pin;
const PIN2 = { mediator: 'harness', kid: 'k1', pk: p.b64u(p.publicKeyOf(SK2)) };
const R0 = S0.bundle.receipts[0];

// ---------------------------------------------------------------- receipt wire
run('provReceiptWireError', 'valid principal', p.provReceiptWireError, [R0]);
run('provReceiptWireError', 'valid action', p.provReceiptWireError, [S0.bundle.receipts[1]]);
for (const [l, v] of variants(R0, { lens: [64, 65, 256, 257, 255] })) await run('provReceiptWireError', l, p.provReceiptWireError, [v]);
for (const [k, n] of [['mediator', 256], ['kid', 64], ['source', 256]] as const) for (const s of around(n)) await run('provReceiptWireError', `${k} bytes ${Buffer.byteLength(s)} len ${s.length}`, p.provReceiptWireError, [{ ...R0, [k]: s }]);
for (const o of ['principal', 'tool', 'retrieval', 'web', 'action', 'Principal', 'agent', 'system']) await run('provReceiptWireError', `origin ${o}`, p.provReceiptWireError, [{ ...R0, origin: o }]);
for (const seq of [0, 1, -1, 1.5, -0, 2 ** 53 - 1, 2 ** 53, '0', null]) await run('provReceiptWireError', `seq ${JSON.stringify(seq)}`, p.provReceiptWireError, [{ ...R0, seq }]);
for (const ia of [0, 1, -1, 1.5, 2 ** 53 - 1, 2 ** 53, '1']) await run('provReceiptWireError', `issued_at ${JSON.stringify(ia)}`, p.provReceiptWireError, [{ ...R0, issued_at: ia }]);
for (const [l, x] of [['alg ed25519', { alg: 'ed25519' }], ['alg ml-dsa-65', { alg: 'ml-dsa-65' }], ['alg hybrid', { alg: 'ed25519+ml-dsa-65' }], ['alg rsa', { alg: 'rsa' }], ['alg num', { alg: 1 }], ['pq_pk on ed', { pq_pk: 'AAAA' }], ['pq_sig on ed', { pq_sig: 'AAAA' }], ['pq_pk num', { pq_pk: 5 }], ['alg null', { alg: null }]] as const)
  await run('provReceiptWireError', `suite ${l}`, p.provReceiptWireError, [{ ...R0, ...x }]);
for (const prev of [null, D('p'), D('p') + 'A', D('p').slice(0, -1), 'AAAA', '', 0]) await run('provReceiptWireError', `prev ${JSON.stringify(prev).slice(0, 20)}`, p.provReceiptWireError, [{ ...R0, prev }]);
for (const v of [1, 1.0, 2, '1', true]) await run('provReceiptWireError', `v ${JSON.stringify(v)}`, p.provReceiptWireError, [{ ...R0, v }]);

// ---------------------------------------------------------------- pins
for (const [l, v] of variants(PIN, { lens: [64, 65, 256, 257] })) await run('isProvMediatorPin', l, p.isProvMediatorPin, [v]);
for (const pq of ['x', '', null, 1, 'AAAA']) await run('isProvMediatorPin', `pq_pk ${JSON.stringify(pq)}`, p.isProvMediatorPin, [{ ...PIN, pq_pk: pq }]);
for (const [k, n] of [['mediator', 256], ['kid', 64]] as const) for (const s of around(n)) await run('isProvMediatorPin', `${k} bytes ${Buffer.byteLength(s)}`, p.isProvMediatorPin, [{ ...PIN, [k]: s }]);

// ---------------------------------------------------------------- action info
const AI = { effects: ['read'], traits: ['pca.pii_access'], params: { amount: 'tool', payee: 'first_party', memo: 'agent' } };
for (const [l, v] of variants(AI, { lens: [128, 129] })) await run('provActionInfoError', l, p.provActionInfoError, [v]);
for (const n of [0, 1, 64, 65]) {
  await run('provActionInfoError', `effects ${n}`, p.provActionInfoError, [{ effects: Array.from({ length: n }, (_, i) => `e${i}`) }]);
  await run('provActionInfoError', `traits ${n}`, p.provActionInfoError, [{ traits: Array.from({ length: n }, (_, i) => `t${i}`) }]);
}
for (const s of around(128)) {
  await run('provActionInfoError', `effect bytes ${Buffer.byteLength(s)}`, p.provActionInfoError, [{ effects: ['read', s] }]);
  await run('provActionInfoError', `param key bytes ${Buffer.byteLength(s)}`, p.provActionInfoError, [{ params: { [s]: 'tool' } }]);
}
for (const f of ['first_party', 'tool', 'agent', 'trusted', 'web', 'Tool', '', null, 1]) await run('provActionInfoError', `floor ${JSON.stringify(f)}`, p.provActionInfoError, [{ params: { a: f } }]);
await run('provActionInfoError', 'params empty key', p.provActionInfoError, [{ params: { '': 'tool' } }]);
await run('provActionInfoError', 'empty', p.provActionInfoError, [{}]);

// isReadOnlyAction: only on well-formed action info (the reference reads it after provActionInfoError; a malformed one throws in TS)
const roInfos: any[] = [
  {}, { effects: [] }, { effects: ['read'] }, { effects: ['read', 'read'] }, { effects: ['read', 'write'] }, { effects: ['write'] }, { effects: ['Read'] },
  { effects: ['read'], traits: [] }, { effects: ['read'], traits: ['pca.financial_data_read'] }, { effects: ['read'], traits: ['pca.pii_access', 'pca.regulated_data'] },
  { effects: ['read'], traits: ['pca.pii_access', 'pca.money_moving'] }, { effects: ['read'], traits: ['pca.money_moving'] }, { traits: ['pca.pii_access'] }, { effects: ['read'], params: { a: 'tool' } },
];
for (const [i, a] of roInfos.entries()) if (p.provActionInfoError(a) === null) await run('isReadOnlyAction', `info ${i} ${JSON.stringify(a)}`, p.isReadOnlyAction, [a]);

// ---------------------------------------------------------------- envelope
const ENV = { mode: 'enforce', mediators: [PIN] };
for (const [l, v] of variants(ENV)) await run('provEnvelopeError', l, p.provEnvelopeError, [v]);
for (const n of [0, 1, 15, 16, 17]) await run('provEnvelopeError', `mediators ${n}`, p.provEnvelopeError, [{ mediators: Array.from({ length: n }, () => PIN) }]);
for (const m of ['enforce', 'insecure_off', 'off', 'Enforce', '', null]) await run('provEnvelopeError', `mode ${JSON.stringify(m)}`, p.provEnvelopeError, [{ mode: m }]);
await run('provEnvelopeError', 'empty', p.provEnvelopeError, [{}]);
await run('provEnvelopeError', 'bad pin second', p.provEnvelopeError, [{ mediators: [PIN, { ...PIN, pk: 'x' }] }]);

// ---------------------------------------------------------------- tokens
const R = rng(0x05a49);
const ALPH = ['a', 'b', 'Z', '0', '9', '_', ' ', '-', '.', '@', 'é', '中', '😀', '\n', '$', '/'];
const rs = (n: number) => Array.from({ length: n }, () => R.pick(ALPH)).join('');
const tokCases: [string, string][] = [
  ['pay acme 50', 'acme'], ['pay acme50', 'acme'], ['payacme 50', 'acme'], ['acme', 'acme'], ['acme!', 'acme'], ['_acme', 'acme'], ['acme_', 'acme'], ['éacme', 'acme'], ['acmeé', 'acme'],
  ['x -50 y', '-50'], ['x a-50 y', '-50'], ['x -50a y', '-50'], ['x-50', '-50'], ['a@b.c', '@b'], ['a@b.c', 'b.c'], ['', 'a'], ['a', ''], ['aaa', 'aa'], ['aa aa', 'aa'], ['aaa aa', 'aa'],
  ['acme acme1', 'acme'], ['1acme acme', 'acme'], ['x中y', '中'], ['x 中 y', '中'], ['😀', '😀'], ['a😀', '😀'], ['$5', '5'], ['$5', '$5'], ['5$', '5'],
  ['AcMe', 'acme'], ['acme.', 'acme.'], ['acme.x', 'acme.'], ['/a/', '/a/'], ['x/a/y', '/a/'], ['ab', 'b'], ['a b', 'b'], ['\nb\n', 'b'], ['b', 'b b'],
];
for (const [t, n] of tokCases) await run('occursAsToken', `${JSON.stringify(t)} ${JSON.stringify(n)}`, p.occursAsToken, [t, n]);
for (let i = 0; i < 1500; i++) {
  const t = rs(R.int(0, 14));
  const n = R.next() < 0.5 && t.length > 0 ? t.slice(R.int(0, t.length - 1), R.int(1, t.length)) : rs(R.int(0, 3));
  if (/[\ud800-\udbff]$|^[\udc00-\udfff]/.test(n) || /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(t)) continue; // halves of a pair: JSON transport keeps them, fine either way, but keep inputs well-formed
  await run('occursAsToken', `gen ${i}`, p.occursAsToken, [t, n]);
}

// ---------------------------------------------------------------- leaves
const deep = (n: number): any => (n === 0 ? 'x' : [deep(n - 1)]);
const deepObj = (n: number): any => (n === 0 ? 1 : { k: deepObj(n - 1) });
const leafCases: [string, any][] = [
  ['string', 'abc'], ['int', 50], ['neg', -7], ['zero', 0], ['negzero', -0], ['fraction', 1.5], ['big', 2 ** 53], ['bigger', 1e21], ['true', true], ['false', false], ['null', null],
  ['array', ['a', 1, true, null]], ['object', { b: 'x', a: 2 }], ['nested', { a: [{ b: 'c' }], d: { e: [1, 2] } }], ['empty array', []], ['empty object', {}], ['key only', { k: {} }],
  ['depth 31', deep(31)], ['depth 32', deep(32)], ['depth 33', deep(33)], ['obj depth 32', deepObj(32)], ['obj depth 33', deepObj(33)],
  ['4096 leaves', Array.from({ length: 4096 }, () => 'a')], ['4097 leaves', Array.from({ length: 4097 }, () => 'a')], ['2048 kv', Object.fromEntries(Array.from({ length: 2048 }, (_, i) => [`k${i}`, 1]))],
  ['2049 kv', Object.fromEntries(Array.from({ length: 2049 }, (_, i) => [`k${i}`, 1]))], ['fraction deep', [[1, [2.5]]]], ['nested big int', { a: [2 ** 53 - 1] }],
];
for (const [l, v] of leafCases) await run('provLeaves', l, p.provLeaves, [v]);

// ---------------------------------------------------------------- decision
const decide = p.decideArgProvenance;
const IN = (o: any = {}) => ({ bundle: S0.bundle, operation: OP, mediators: [PIN], ...o });
await run('decideArgProvenance', 'principal direct pinned', decide, [IN()]);
// structural variants of the whole input (skip `action: null` / non-boolean flags: the native Input types have no such state)
const INPUT = IN({ action: { effects: ['write'], params: { memo: 'agent' } }, observed: [], principalPlan: false, principalControl: false });
for (const [l, v] of variants(INPUT, { lens: [256, 257], maxPaths: 400, depth: 5 })) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) { await run('decideArgProvenance', l, decide, [v]); continue; }
  if ('action' in v && v.action === null) continue;
  if (('principalPlan' in v && typeof v.principalPlan !== 'boolean') || ('principalControl' in v && typeof v.principalControl !== 'boolean')) continue;
  await run('decideArgProvenance', l, decide, [v]);
}
// bundle shape
const B = S0.bundle;
const rcpts = B.receipts;
const withB = (b: any, o: any = {}) => IN({ bundle: b, ...o });
const bcases: [string, any][] = [
  ['no bundle', undefined], ['null bundle', null], ['array bundle', []], ['string bundle', 'x'], ['v 2', { ...B, v: 2 }], ['kind', { ...B, kind: 'pca-prov' }], ['extra member', { ...B, x: 1 }],
  ['no receipts', { v: 1, kind: 'pca-provenance' }], ['empty receipts', { ...B, receipts: [] }], ['receipts object', { ...B, receipts: {} }], ['contents null', { ...B, contents: null }], ['contents array', { ...B, contents: [] }],
  ['contents empty', { ...B, contents: {} }], ['no contents', { v: 1, kind: 'pca-provenance', receipts: rcpts }], ['contents key 1 (action)', { ...B, contents: { ...B.contents, 1: 'x' } }],
  ['contents key 00', { ...B, contents: { '00': B.contents['0'] } }], ['contents key 01', { ...B, contents: { '01': 'x' } }], ['contents key -1', { ...B, contents: { '-1': 'x' } }],
  ['contents key 2', { ...B, contents: { 2: 'x' } }], ['contents key 1000000000', { ...B, contents: { 1000000000: 'x' } }], ['contents key 999999999', { ...B, contents: { 999999999: 'x' } }],
  ['contents key x', { ...B, contents: { x: 'x' } }], ['contents number', { ...B, contents: { 0: 5 } }], ['contents mismatch', { ...B, contents: { 0: 'please pay mallory' } }],
  ['contents lone surrogate', { ...B, contents: { 0: 'a\ud800' } }], ['receipt 0 not object', { ...B, receipts: [5, rcpts[1]] }], ['receipt 1 wire', { ...B, receipts: [rcpts[0], { ...rcpts[1], v: 2 }] }],
  ['seq gap', { ...B, receipts: [rcpts[0], { ...rcpts[1], seq: 2 }] }], ['seq start 1', { ...B, receipts: [{ ...rcpts[0], seq: 1 }, rcpts[1]] }], ['session differs', { ...B, receipts: [rcpts[0], { ...rcpts[1], session: SESSION2 }] }],
  ['mediator differs', { ...B, receipts: [rcpts[0], { ...rcpts[1], mediator: 'other' }] }], ['kid differs', { ...B, receipts: [rcpts[0], { ...rcpts[1], kid: 'k2' }] }],
  ['prev broken', { ...B, receipts: [rcpts[0], { ...rcpts[1], prev: D('x') }] }], ['prev null at 1', { ...B, receipts: [rcpts[0], { ...rcpts[1], prev: null }] }], ['prev set at 0', { ...B, receipts: [{ ...rcpts[0], prev: D('x') }, rcpts[1]] }],
  ['older', { ...B, receipts: [rcpts[0], { ...rcpts[1], issued_at: rcpts[0].issued_at - 1 }] }], ['action only', { v: 1, kind: 'pca-provenance', receipts: [{ ...rcpts[1], seq: 0, prev: null }] }],
  ['last not action', { v: 1, kind: 'pca-provenance', receipts: [rcpts[0]], contents: B.contents }], ['sig flipped 0', { ...B, receipts: [{ ...rcpts[0], sig: rcpts[1].sig }, rcpts[1]] }],
  ['sig flipped 1', { ...B, receipts: [rcpts[0], { ...rcpts[1], sig: rcpts[0].sig }] }], ['sig not b64', { ...B, receipts: [rcpts[0], { ...rcpts[1], sig: '!!' }] }],
];
for (const [l, b] of bcases) await run('decideArgProvenance', `bundle ${l}`, decide, [withB(b)]);
for (const n of [255, 256, 257]) {
  const steps: Step[] = [['principal', 'hello']];
  for (let i = 1; i < Math.min(n, 256) - 1; i++) steps.push(['tool', 't', 'x']);
  const s = session([...steps, ['action', OP]]);
  let b = s.bundle;
  if (n === 257) b = { ...b, receipts: [...b.receipts, b.receipts[b.receipts.length - 1]] };
  await run('decideArgProvenance', `receipts ${n === 257 ? 257 : b.receipts.length}`, decide, [withB(b, { mediators: [s.pin] })]);
}
// operation binding
for (const [l, op] of [['other verb', { ...OP, verb: 'payments.refund' }], ['other resource', { ...OP, resource: 'payments/x' }], ['other params', { ...OP, params: { ...OP.params, amount: 51 } }], ['params extra', { ...OP, params: { ...OP.params, x: 1 } }]] as const)
  await run('decideArgProvenance', `bound to ${l}`, decide, [IN({ operation: op })]);
for (const [l, op] of [['verb empty', { ...OP, verb: '' }], ['verb 256', { ...OP, verb: 'v'.repeat(256) }], ['verb 257', { ...OP, verb: 'v'.repeat(257) }], ['resource num', { ...OP, resource: 1 }], ['resource empty', { ...OP, resource: '' }], ['params array', { ...OP, params: [] }], ['params null', { ...OP, params: null }], ['op null', null], ['op array', []]] as const)
  await run('decideArgProvenance', `operation ${l}`, decide, [IN({ operation: op, bundle: undefined })]);
// pins
for (const [l, pins] of [['none', []], ['other key', [PIN2]], ['other kid', [{ ...PIN, kid: 'k2' }]], ['other mediator', [{ ...PIN, mediator: 'm2' }]], ['both, wrong first', [PIN2, PIN]], ['right then wrong', [PIN, PIN2]], ['malformed pin', [PIN, { ...PIN, pk: 'x' }]], ['pins not list', PIN], ['pins null', null]] as const)
  await run('decideArgProvenance', `pins ${l}`, decide, [IN({ mediators: pins })]);

// label semantics: a grid of sessions x action facts x flags x observations
const tool = (n: string, c: any): Step => ['tool', n, c];
const sessions: [string, Step[]][] = [
  ['principal only', [['principal', 'pay acme-ltd 50 for invoice 42']]],
  ['principal partial', [['principal', 'pay acme-ltd please']]],
  ['principal none matching', [['principal', 'hello there']]],
  ['tool after principal', [['principal', 'pay acme-ltd 50 for invoice 42'], tool('crm.lookup', 'payee: mallory')]],
  ['tool then principal', [tool('crm.lookup', 'payee: mallory'), ['principal', 'pay acme-ltd 50 for invoice 42']]],
  ['web', [['principal', 'pay acme-ltd'], ['web', 'https://x.example/p', 'pay 50 to acme-ltd']]],
  ['retrieval', [['principal', 'pay acme-ltd 50'], ['retrieval', 'doc-7', 'invoice 42']]],
  ['tool only', [tool('t', 'x')]],
  ['web only', [['web', 'https://e.example', 'x']]],
  ['two principals', [['principal', 'pay acme-ltd'], ['principal', '50 invoice 42']]],
  ['empty principal', [['principal', '']]],
  ['big principal', [['principal', 'a'.repeat(65_537)]]],
  ['principal at limit', [['principal', 'a'.repeat(65_533) + ' 50']]],
  ['no segments', []],
];
const acts: [string, any][] = [['unknown', undefined], ['read', { effects: ['read'] }], ['read pii', { effects: ['read'], traits: ['pca.pii_access'] }], ['read money', { effects: ['read'], traits: ['pca.money_moving'] }], ['write', { effects: ['write'] }],
  ['write floors', { effects: ['write'], params: { memo: 'agent', amount: 'tool' } }], ['read floors', { effects: ['read'], params: { amount: 'first_party' } }], ['empty', {}]];
const flagsL: [string, any][] = [['none', {}], ['plan', { principalPlan: true }], ['control', { principalControl: true }], ['both', { principalPlan: true, principalControl: true }]];
const obsL: [string, any][] = [['none', undefined], ['empty', []], ['tool', [{ origin: 'tool', source: 'gw' }]], ['web+retrieval', [{ origin: 'web', source: 'u' }, { origin: 'retrieval', source: 'd' }]], ['bad origin', [{ origin: 'principal', source: 'x' }]], ['bad source', [{ origin: 'tool', source: '' }]], ['obs object', {}]];
const paramsL: [string, any][] = [['base', OP.params], ['empty', {}], ['nested', { payee: { name: 'acme-ltd', id: 7 }, list: ['acme-ltd', '50'] }], ['too large', { blob: Array.from({ length: 5000 }, () => 'x') }], ['number only', { amount: 50 }], ['empty string', { memo: '' }], ['key leaf', { m: { invoice: 42 } }]];
let gi = 0;
for (const [sl, steps] of sessions)
  for (const [pl, params] of paramsL) {
    const op = { ...OP, params };
    const s = session([...steps, ['action', op]]);
    for (const [al, action] of acts)
      for (const [fl, flags] of flagsL)
        for (const [ol, observed] of obsL) {
          // full grid is large: keep every combination for the base params, a seeded sample otherwise
          if (pl !== 'base' && R.next() > 0.18) continue;
          if (sl.startsWith('big') || sl.includes('at limit')) { if (pl !== 'base' || al !== 'unknown' || fl !== 'none' || ol !== 'none') continue; } // 64 KiB args: once
          await run('decideArgProvenance', `grid ${gi++} [${sl}|${pl}|${al}|${fl}|${ol}]`, decide, [{ bundle: s.bundle, operation: op, mediators: [s.pin], ...(action !== undefined ? { action } : {}), ...flags, ...(observed !== undefined ? { observed } : {}) }]);
        }
  }
// unverified bundle (unpinned) + same grid head
for (const [al, action] of acts) await run('decideArgProvenance', `unpinned ${al}`, decide, [IN({ mediators: [PIN2], ...(action ? { action } : {}) })]);

// ---------------------------------------------------------------- recorder (mediator side)
// spec: {mediator, kid, sk (b64u), session, clock: [ms per append], steps}; out: {pin, outs: [receipt | bundle | {$throws}]}
function recorder(spec: any) {
  const clock = [...spec.clock];
  let last = 0;
  const rec = p.createProvenanceRecorder({ mediator: spec.mediator, kid: spec.kid, secretKey: Buffer.from(spec.sk, 'base64url'), session: spec.session, now: () => (clock.length ? (last = clock.shift()) : last) });
  const outs: any[] = [];
  for (const s of spec.steps) {
    try {
      if (s[0] === 'principal') outs.push(rec.principal(s[1]));
      else if (s[0] === 'tool') outs.push(rec.tool(s[1], s[2]));
      else if (s[0] === 'retrieval') outs.push(rec.retrieval(s[1], s[2]));
      else if (s[0] === 'web') outs.push(rec.web(s[1], s[2]));
      else if (s[0] === 'action') outs.push(rec.forAction(s[1]));
      else if (s[0] === 'direct') outs.push(p.principalDirectProvenance(rec, s[1]));
    } catch (e) {
      outs.push({ $throws: (e as Error).message });
    }
  }
  return { pin: rec.pin, outs };
}
const SKB = Buffer.from(SK).toString('base64url');
const spec = (steps: any[], o: any = {}) => ({ mediator: 'harness', kid: 'k1', sk: SKB, session: SESSION, clock: [T0, T0 + 5, T0 + 5, T0 + 1, T0 + 9, T0 + 9], steps, ...o });
// non-string tool/retrieval/web content is hashed over its canonical JSON text (0.5: key order independent, as Java)
const recCases: [string, any][] = [
  ['principal then action', spec([['principal', 'pay acme 50'], ['action', OP]])],
  ['clock goes backwards', spec([['principal', 'a'], ['tool', 't', 'x'], ['web', 'https://w', 'y'], ['action', OP]], { clock: [T0 + 100, T0, T0 + 50, T0 + 200] })],
  ['clock 1.7 truncates', spec([['principal', 'a'], ['action', OP]], { clock: [T0 + 0.7, T0 + 1.9] })],
  ['non-string content (canonical)', spec([['tool', 'lookup', { a: 1, b: [true, null, 'x'] }], ['retrieval', 'doc', 7], ['web', 'u', null], ['action', OP]])],
  ['principal > 65536 bytes not in contents', spec([['principal', 'é'.repeat(32_768) + 'a'], ['action', OP]])],
  ['principal exactly 65536 bytes', spec([['principal', 'é'.repeat(32_768)], ['action', OP]])],
  ['source clip ascii 256', spec([['tool', 'a'.repeat(256), 'x'], ['action', OP]])],
  ['source clip ascii 257', spec([['tool', 'a'.repeat(257), 'x'], ['action', OP]])],
  ['source clip ascii 1000', spec([['tool', 'b'.repeat(1000), 'x'], ['action', OP]])],
  ['source clip multibyte', spec([['tool', 'é'.repeat(200), 'x'], ['action', OP]])],
  ['source clip 4-byte even', spec([['tool', '😀'.repeat(100), 'x'], ['action', OP]])],
  ['source clip 4-byte odd (cut lands inside a pair)', spec([['tool', 'x' + '😀'.repeat(100), 'x'], ['action', OP]])],
  ['source clip 4-byte odd, twice', spec([['tool', 'x' + '😀'.repeat(400), 'x'], ['web', 'yz' + '😀'.repeat(150), 'y'], ['action', OP]])],
  ['non-string content, keys out of order', spec([['tool', 'lookup', { b: 2, a: 1, c: { z: 1, y: [{ q: 1, p: 2 }] } }], ['retrieval', 'doc', { 'é': 1, e: 2, 'É': 3 }], ['action', OP]])],
  ['non-string content, number forms', spec([['tool', 'n', { x: 1.5, w: 0.1, v: 100, u: -7 }], ['action', OP]])],
  ['source empty -> dash', spec([['tool', '', 'x'], ['action', OP]])],
  ['action verb long (clipped source)', spec([['principal', 'x'], ['action', { ...OP, verb: 'v'.repeat(300) }]])],
  ['direct', spec([['direct', OP]])],
  ['direct then action again', spec([['direct', OP], ['action', OP]])],
  ['no principal', spec([['action', OP]])],
  ['two actions', spec([['principal', 'a'], ['action', OP], ['action', { ...OP, params: {} }]])],
  ['other session/key', spec([['principal', 'a'], ['action', OP]], { session: SESSION2, sk: Buffer.from(SK2).toString('base64url'), mediator: 'gw', kid: 'k9' })],
];
for (const [l, sp] of recCases) await run('recorder', l, recorder, [sp]);
{ // the 256-receipt cap of forAction
  const steps: any[] = Array.from({ length: 255 }, (_, i) => ['tool', 't', String(i)]);
  await run('recorder', 'cap 255 then action ok', recorder, [spec([...steps, ['action', OP], ['action', OP]])]);
}
for (const [l, o] of [['mediator empty', { mediator: '' }], ['kid 65', { kid: 'k'.repeat(65) }], ['mediator 257', { mediator: 'm'.repeat(257) }], ['session bad', { session: 'AAAA' }], ['kid 64', { kid: 'k'.repeat(64) }]] as const)
  await run('recorder', `ctor ${l}`, (sp: any) => { try { return recorder(sp); } catch (e) { return { $throws: (e as Error).message }; } }, [spec([['principal', 'a'], ['action', OP]], o)]);

// ---------------------------------------------------------------- digests
for (const [l, op] of [['base', OP], ['empty params', { ...OP, params: {} }], ['nested', { ...OP, params: { a: [1, { b: 'c' }] } }]] as const) await run('provActionDigest', l, p.provActionDigest, [op]);
for (const [i, r] of rcpts.entries()) await run('provReceiptRef', `receipt ${i}`, p.provReceiptRef, [r]);

// ---------------------------------------------------------------- request reader (header PCA-Provenance, else body.pca_provenance)
const hdr = (x: any) => Buffer.from(typeof x === 'string' ? x : JSON.stringify(x), 'utf8').toString('base64url');
function readBundle(a: { header?: string; body?: string }) {
  const req: any = { headers: a.header !== undefined ? { 'pca-provenance': a.header } : {}, ...(a.body !== undefined ? { body: a.body } : {}) };
  return p.defaultProvenanceBundle(req);
}
const rb: [string, any][] = [
  ['header bundle', { header: hdr(B) }], ['header empty -> body', { header: '', body: JSON.stringify({ pca_provenance: B }) }], ['header padded', { header: hdr(B) + '=' }], ['header not b64', { header: '***' }],
  ['header not json', { header: hdr('{x') }], ['header json number', { header: hdr('5') }], ['header dup key', { header: hdr('{"a":1,"a":2}') }], ['header bad utf8', { header: Buffer.from([0xff, 0xfe]).toString('base64url') }],
  ['header wins over body', { header: hdr({ v: 1 }), body: JSON.stringify({ pca_provenance: B }) }], ['body member', { body: JSON.stringify({ pca_provenance: { v: 1 } }) }], ['body no member', { body: '{"x":1}' }],
  ['body array', { body: '[1]' }], ['body number', { body: '5' }], ['body bad json', { body: '{' }], ['body empty', { body: '' }], ['none', {}], ['body member null', { body: '{"pca_provenance":null}' }],
  ['body dup key', { body: '{"pca_provenance":1,"pca_provenance":2}' }], ['header json -0', { header: hdr('{"a":-0}') }], ['header lone surrogate escape', { header: hdr('{"a":"\\ud800"}') }],
];
for (const [l, a] of rb) await run('defaultProvenanceBundle', l, readBundle, [a]);

O.write();
