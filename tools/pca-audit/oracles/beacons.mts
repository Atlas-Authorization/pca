// Oracle: packages/pca/src/beacons.ts (signed liveness beacons: issue, message, ref, verify, replay acceptance, the frozen-liveness check, the durable acceptor), TS reference.
// Writes out/ref-beacons.json.gz. Deterministic: Ed25519 / ML-DSA-65 keys from seed(label); every clock is an argument.
// PORTING (fn(args) -> native entry point; compared by JSON value; a throw = the native throws; {"$num":..} non-finite doubles; {"$bytes":{"$seed":label}} = the 32-byte Ed25519 secret; suite = {alg, pqSeed} -> ML-DSA-65 key from the seed)
//   issueLivenessBeacon [{issuerSecret, instance, scope?, seq, issuedAt, validityMs?, suite?}] -> LivenessBeacon | throws        (scope absent / null = "*"; validityMs absent / null = 300000)
//   livenessBeaconMessage [body] -> {"$bytes": "atlas-pca/beacon/v2\0" || canonical JSON of {v, instance, scope, epoch, seq, issued_at, not_after, issuer} (+ alg, pq_pk for a non-ed25519 suite)}
//   beaconRef [beacon] -> string (b64u SHA-256 of the canonical JSON of the WHOLE beacon incl. sig)
//   verifyLivenessBeacon [beacon, check] -> {ok, reason?} (reason strings compared exactly; never throws)   check {issuers, now, instance, scope?, pqPins?, allowUnboundPq?}
//   acceptBeacon [prev|null, next] -> {ok, reason?}      isFrozenLiveness [beacons, check] -> bool
//   acceptor [ops] -> per op, ONE fresh in-memory durable kv:  ["accept", beacon, check] -> {ok, reason?}   ["raw", b, value] writes `value` straight into the sequence slot of beacon b's (instance, scope, issuer) (junk / negative / fractional / object; a stored -0 or null is kv-specific and NOT in the corpus) -> null
//                     ["fail"] makes the NEXT accept's kv.update throw (-> reason "beacon state unavailable") -> null ; a throw from the constructor with a bad kv is case acceptor/ctor-* (args [null, kv-spec]).
//   ctor [kv-spec] -> {built}: createBeaconAcceptor over "ok" (a memory kv) | null | {} | {update: 5} | {update: "fn"} (an object whose update is a function)
//   constants [] -> {GLOBAL_SCOPE, BEACON_EPOCH_MS, BEACON_MAX_VALIDITY_MS, BEACON_CLOCK_SKEW_MS}
import { Oracle, refWrite, seed } from './lib.mjs';
import { adder } from './foundation.mjs';
const B: any = await import('../../../packages/pca/src/beacons.ts');
const PQ: any = await import('../../../packages/pca/src/pq.ts');
const { createMemoryDurableKv }: any = await import('../../../packages/pca/src/durable-state.ts');
const { publicKeyOf } = await import('../../../packages/pca/src/keys.ts') as any;
const { b64u } = await import('../../../packages/pca/src/hash.ts') as any;
const o = new Oracle('beacons', 'tools/pca-audit/oracles/beacons.mts', 'TS-reference oracle for packages/pca/src/beacons.ts.');
const suiteOf = (s: any) => (s == null ? undefined : s.alg === 'ed25519' ? { alg: s.alg } : { alg: s.alg, mlDsa: PQ.mlDsa65Keygen(s.pqSeed) });
const REF: Record<string, (...a: any[]) => any> = {
  issueLivenessBeacon: (a) => B.issueLivenessBeacon({ ...a, ...(a.scope === null ? { scope: undefined } : {}), ...(a.validityMs === null ? { validityMs: undefined } : {}), suite: suiteOf(a.suite) }),
  livenessBeaconMessage: (b) => B.livenessBeaconMessage(b), beaconRef: (b) => B.beaconRef(b), verifyLivenessBeacon: (b, c) => B.verifyLivenessBeacon(b, c),
  acceptBeacon: (p, n) => B.acceptBeacon(p === null ? undefined : p, n), isFrozenLiveness: (bs, c) => B.isFrozenLiveness(bs, c),
  acceptor: async (ops) => { const kv = createMemoryDurableKv(); let fail = false; const real = kv.update.bind(kv); kv.update = (k: string, f: any) => { if (fail) { fail = false; return Promise.reject(new Error('kv down')); } return real(k, f); }; const acc = B.createBeaconAcceptor(kv); const out: any[] = [];
    for (const op of ops) { if (op[0] === 'accept') out.push(await acc.accept(op[1], op[2])); else if (op[0] === 'fail') { fail = true; out.push(null); } else if (op[0] === 'raw') { const b = op[1]; await kv.set(`beacon-seq/v1/${JSON.stringify([b.instance, b.scope, b.issuer])}`, op[2]); out.push(null); } else out.push({ $err: 'op' }); } return out; },
  ctor: (kv) => { try { B.createBeaconAcceptor(kv === 'ok' ? createMemoryDurableKv() : kv && kv.update === 'fn' ? { update: () => 0 } : kv); return { built: true }; } catch { return { built: false }; } },
  constants: () => ({ GLOBAL_SCOPE: B.GLOBAL_SCOPE, BEACON_EPOCH_MS: B.BEACON_EPOCH_MS, BEACON_MAX_VALIDITY_MS: B.BEACON_MAX_VALIDITY_MS, BEACON_CLOCK_SKEW_MS: B.BEACON_CLOCK_SKEW_MS }),
};
const add = adder(o, REF);
const IS = seed('bc/issuer'), IS2 = seed('bc/issuer2'), PQS = seed('bc/pq');
const ISPK = b64u(publicKeyOf(IS)), IS2PK = b64u(publicKeyOf(IS2));
const J = (x: any) => JSON.parse(JSON.stringify(x));
const T0 = 1_800_000_000_000; // a multiple of 60000? keep as is: epoch = floor(T0/60000)
const flip = (s: string) => s.slice(0, -2) + (s.slice(-2) === 'AA' ? 'BB' : 'AA');
const IA = (over: any = {}) => ({ issuerSecret: IS, instance: 'ins_1', seq: 1, issuedAt: T0, ...over });
const ISS: [string, any][] = [['ok', IA()], ['scope', IA({ scope: 'sess-1' })], ['scope-null', IA({ scope: null })], ['scope-empty', IA({ scope: '' })], ['scope-num', IA({ scope: 5 })], ['seq-0', IA({ seq: 0 })], ['seq-big', IA({ seq: 2 ** 53 })], ['seq-neg', IA({ seq: -1 })], ['seq-frac', IA({ seq: 1.5 })], ['seq-nan', IA({ seq: { $num: 'NaN' } })], ['seq-str', IA({ seq: '1' })], ['seq-negzero', IA({ seq: -0 })],
  ['issued-0', IA({ issuedAt: 0 })], ['issued-neg', IA({ issuedAt: -1 })], ['issued-frac', IA({ issuedAt: 1.5 })], ['issued-nan', IA({ issuedAt: { $num: 'NaN' } })], ['issued-epoch-edge', IA({ issuedAt: 119_999 })], ['issued-epoch-next', IA({ issuedAt: 120_000 })], ['issued-big-int', IA({ issuedAt: 2 ** 53 - 1 })],
  ['validity-1', IA({ validityMs: 1 })], ['validity-max', IA({ validityMs: 3_600_000 })], ['validity-over', IA({ validityMs: 3_600_001 })], ['validity-0', IA({ validityMs: 0 })], ['validity-neg', IA({ validityMs: -5 })], ['validity-frac', IA({ validityMs: 1.5 })], ['validity-null', IA({ validityMs: null })], ['validity-nan', IA({ validityMs: { $num: 'NaN' } })], ['validity-str', IA({ validityMs: '5' })],
  ['instance-empty', IA({ instance: '' })], ['instance-unicode', IA({ instance: 'ïns😀' })], ['instance-num', IA({ instance: 5 })], ['instance-missing', IA({ instance: undefined })],
  ['suite-ed', IA({ suite: { alg: 'ed25519' } })], ['suite-ml-dsa', IA({ suite: { alg: 'ml-dsa-65', pqSeed: PQS } })], ['suite-hybrid', IA({ suite: { alg: 'hybrid-ed25519-ml-dsa-65', pqSeed: PQS } })], ['suite-unknown', IA({ suite: { alg: 'rot13' } })]];
for (const [n, a] of ISS) await add('issueLivenessBeacon', n, [a]);
const mk = (over: any = {}) => J(B.issueLivenessBeacon({ ...IA(), ...over, suite: suiteOf(over.suite) }));
const BC = mk(), BS = mk({ scope: 'sess-1' }), BPQ = mk({ suite: { alg: 'ml-dsa-65', pqSeed: PQS } }), BHY = mk({ suite: { alg: 'hybrid-ed25519-ml-dsa-65', pqSeed: PQS } });
const body = (b: any) => (({ sig, pq_sig, ...r }: any) => r)(b);
for (const [n, b] of [['global', body(BC)], ['scoped', body(BS)], ['pq', body(BPQ)], ['hybrid', body(BHY)], ['with-sig-members-included', BC], ['extra-members-ignored', { ...body(BC), extra: 1 }], ['member-order', { issuer: BC.issuer, not_after: BC.not_after, issued_at: BC.issued_at, seq: BC.seq, epoch: BC.epoch, scope: BC.scope, instance: BC.instance, v: 2 }], ['alg-ed-explicit', { ...body(BC), alg: 'ed25519', pq_pk: undefined }], ['pq-pk-without-alg-ignored', { ...body(BC), pq_pk: 'AAAA' }], ['missing-scope', (({ scope, ...r }: any) => r)(body(BC))], ['nan-epoch', { ...body(BC), epoch: { $num: 'NaN' } }], ['unicode', { ...body(BC), instance: 'é😀\u0000' }]] as any[]) await add('livenessBeaconMessage', n, [b]);
for (const [n, b] of [['ed', BC], ['scoped', BS], ['pq', BPQ], ['hybrid', BHY], ['member-order', { sig: BC.sig, ...BC }], ['extra', { ...BC, extra: [1, { z: 1, a: 2 }] }], ['empty', {}], ['nan', { ...BC, seq: { $num: 'NaN' } }]] as any[]) await add('beaconRef', n, [b]);
// verify
const CK = (over: any = {}) => ({ issuers: [ISPK], now: T0 + 1000, instance: 'ins_1', ...over });
const VB = (n: string, b: any, over: any = {}) => add('verifyLivenessBeacon', n, [b, CK(over)]);
await VB('ok', BC); await VB('ok-scope-global-any', BC, { scope: 'sess-9' }); await VB('ok-scoped', BS, { scope: 'sess-1' }); await VB('scope-not-covered', BS, { scope: 'sess-2' }); await VB('scoped-no-scope-check', BS); await VB('scope-empty-check', BS, { scope: '' });
for (const [n, now] of [['at-issued', T0], ['skew-before-edge', T0 - 30_000], ['skew-before-over', T0 - 30_001], ['at-not-after', T0 + 300_000], ['after-not-after', T0 + 300_001], ['now-nan', { $num: 'NaN' }], ['now-inf', { $num: 'Infinity' }], ['now-neg-inf', { $num: '-Infinity' }], ['now-str', String(T0)], ['now-missing', undefined]] as any[]) await VB('time/' + n, BC, { now });
await VB('wrong-instance', BC, { instance: 'other' }); await VB('instance-missing', BC, { instance: undefined }); await VB('issuer-not-pinned', BC, { issuers: [IS2PK] }); await VB('issuers-empty', BC, { issuers: [] }); await VB('issuers-two', BC, { issuers: [IS2PK, ISPK] }); await VB('issuer-swapped', mk({ issuerSecret: IS2 }), { issuers: [ISPK] }); await VB('issuer-swapped-pinned', mk({ issuerSecret: IS2 }), { issuers: [IS2PK] });
for (const [n, b] of [['null', null], ['string', 'x'], ['number', 5], ['array', []], ['empty', {}], ['v-1', { ...BC, v: 1 }], ['v-str', { ...BC, v: '2' }], ['v-missing', (({ v, ...r }: any) => r)(BC)], ['alg-unknown', { ...BC, alg: 'rot13' }], ['alg-num', { ...BC, alg: 5 }], ['alg-ed-breaks-sig', { ...BC, alg: 'ed25519' }], ['sig-flip', { ...BC, sig: flip(BC.sig) }], ['sig-missing', (({ sig, ...r }: any) => r)(BC)], ['sig-num', { ...BC, sig: 5 }], ['sig-empty', { ...BC, sig: '' }], ['seq-tampered', { ...BC, seq: 2 }], ['scope-tampered', { ...BC, scope: '*x' }], ['extra-member-ignored-by-sig', { ...BC, extra: 1 }], ['instance-tampered', { ...BC, instance: 'other' }]] as any[]) await VB('shape/' + n, b);
const bad = (over: any) => { const x = { ...body(BC), ...over }; const m = B.livenessBeaconMessage(x); return J({ ...x, sig: b64u(sig(m)) }); };
const { sign: edSign } = await import('../../../packages/pca/src/keys.ts') as any;
function sig(m: Uint8Array) { return edSign(IS, m); }
for (const [n, over] of [['not-after-before-issued', { not_after: T0 - 1 }], ['not-after-equals-issued', { not_after: T0 }], ['validity-over-max', { not_after: T0 + 3_600_001 }], ['validity-max', { not_after: T0 + 3_600_000 }], ['epoch-wrong', { epoch: 5 }], ['epoch-frac', { epoch: Math.floor(T0 / 60000) + 0.5 }], ['seq-neg', { seq: -1 }], ['seq-frac', { seq: 1.5 }], ['seq-str', { seq: '1' }], ['seq-null', { seq: null }], ['issued-str', { issued_at: String(T0) }], ['issued-frac', { issued_at: T0 + 0.5 }], ['not-after-frac', { not_after: T0 + 300000.5 }], ['issued-nan', { issued_at: { $num: 'NaN' } }], ['seq-big', { seq: 2 ** 60 }]] as any[]) { try { await VB('signed-bad/' + n, bad(over)); } catch { /* generator cannot sign non-finite */ } }
await VB('pq-no-pin', BPQ); await VB('pq-pinned', BPQ, { pqPins: { [BPQ.issuer]: BPQ.pq_pk } }); await VB('pq-unbound', BPQ, { allowUnboundPq: true }); await VB('pq-wrong-pin', BPQ, { pqPins: { [BPQ.issuer]: BHY.pq_pk.slice(0, -4) + 'AAAA' } }); await VB('pq-missing-pq-pk', (({ pq_pk, ...r }: any) => r)(BPQ), { allowUnboundPq: true });
await VB('hybrid-pinned', BHY, { pqPins: { [BHY.issuer]: BHY.pq_pk } }); await VB('hybrid-pq-sig-flip', { ...BHY, pq_sig: flip(BHY.pq_sig) }, { pqPins: { [BHY.issuer]: BHY.pq_pk } }); await VB('hybrid-pq-sig-missing', (({ pq_sig, ...r }: any) => r)(BHY), { pqPins: { [BHY.issuer]: BHY.pq_pk } }); await VB('hybrid-downgrade-strip', (({ alg, pq_pk, pq_sig, ...r }: any) => r)(BHY), { pqPins: { [BHY.issuer]: BHY.pq_pk } });
await VB('check-null-issuers', BC, { issuers: null }); await VB('check-issuers-string', BC, { issuers: ISPK });
// accept / frozen
for (const [n, p, nx] of [['no-prev', null, BC], ['higher', { seq: 0 }, BC], ['equal', { seq: 1 }, BC], ['lower', { seq: 5 }, BC], ['prev-nan', { seq: { $num: 'NaN' } }, BC], ['prev-str', { seq: '0' }, BC], ['prev-missing-seq', {}, BC], ['next-seq-0', { seq: -1 }, mk({ seq: 0 })], ['next-neg', null, { ...BC, seq: -1 }], ['next-frac', null, { ...BC, seq: 1.5 }], ['next-negzero', null, { ...BC, seq: -0 }], ['next-big-unsafe', null, { ...BC, seq: 2 ** 53 }], ['next-safe-max', { seq: 2 ** 53 - 2 }, { ...BC, seq: 2 ** 53 - 1 }], ['next-str', null, { ...BC, seq: '1' }], ['next-null', null, null], ['next-string', null, 'x'], ['next-no-seq', null, {}], ['prev-big', { seq: 2 ** 53 - 1 }, { ...BC, seq: 2 ** 53 - 1 }]] as any[]) await add('acceptBeacon', n, [p, nx]);
const F = (n: string, bs: any, over: any = {}) => add('isFrozenLiveness', n, [bs, CK(over)]);
await F('one-valid', [BC]); await F('none', []); await F('all-expired', [BC], { now: T0 + 400_000 }); await F('one-of-many-valid', [mk({ issuedAt: T0 - 900_000 }), BC]); await F('all-invalid', [{ ...BC, sig: flip(BC.sig) }, null, 5]); await F('wrong-instance', [BC], { instance: 'x' }); await F('scope-uncovered', [BS], { scope: 'zz' }); await F('scope-covered-global', [BC], { scope: 'zz' });
// acceptor
const AC = (n: string, ops: any[]) => add('acceptor', n, [ops]);
const bseq = (seq: number, over: any = {}) => mk({ seq, ...over });
await AC('replay', [['accept', bseq(1), CK()], ['accept', bseq(1), CK()], ['accept', bseq(2), CK()], ['accept', bseq(1), CK()], ['accept', bseq(5), CK()], ['accept', bseq(3), CK()]]);
await AC('invalid-first', [['accept', { ...BC, sig: flip(BC.sig) }, CK()], ['accept', bseq(1), CK()]]); await AC('expired-not-recorded', [['accept', bseq(9), CK({ now: T0 + 999_999 })], ['accept', bseq(1), CK()]]);
await AC('per-scope-independent', [['accept', bseq(5), CK()], ['accept', bseq(1, { scope: 'sess-1' }), CK()], ['accept', bseq(5, { scope: 'sess-1' }), CK()], ['accept', bseq(5), CK()]]);
await AC('per-issuer-independent', [['accept', bseq(5), CK({ issuers: [ISPK, IS2PK] })], ['accept', bseq(1, { issuerSecret: IS2 }), CK({ issuers: [ISPK, IS2PK] })], ['accept', bseq(1, { issuerSecret: IS2 }), CK({ issuers: [ISPK, IS2PK] })]]);
await AC('per-instance-independent', [['accept', bseq(5), CK()], ['accept', bseq(1, { instance: 'ins_2' }), CK({ instance: 'ins_2' })]]);
await AC('seq-0', [['accept', bseq(0), CK()], ['accept', bseq(0), CK()], ['accept', bseq(1), CK()]]);
await AC('kv-down', [['fail'], ['accept', bseq(1), CK()], ['accept', bseq(1), CK()]]); await AC('kv-down-after-verify-failure-not-reached', [['fail'], ['accept', { ...BC, sig: flip(BC.sig) }, CK()], ['accept', bseq(1), CK()]]);
for (const [n, v] of [['junk-string', 'x'], ['negative', -1], ['fractional', 1.5], ['unsafe', 2 ** 53], ['object', {}], ['valid-higher', 7], ['valid-equal', 1], ['valid-lower', 0]] as any[]) await AC('raw-' + n, [['raw', BC, v], ['accept', bseq(1), CK()], ['accept', bseq(8), CK()]]);
await AC('pq-beacons', [['accept', BPQ, CK({ pqPins: { [BPQ.issuer]: BPQ.pq_pk } })], ['accept', BPQ, CK({ pqPins: { [BPQ.issuer]: BPQ.pq_pk } })]]); await AC('bad-op', [['bogus']]);
await add('ctor', 'ok', ['ok']); await add('ctor', 'null', [null]); await add('ctor', 'empty-object', [{}]); await add('ctor', 'update-not-fn', [{ update: 5 }]); await add('ctor', 'only-update', [{ update: 'fn' }]);
await add('constants', 'all', []);
refWrite(o, 'beacons');
