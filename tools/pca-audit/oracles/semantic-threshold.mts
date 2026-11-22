// Oracle: the parts of packages/pca/src/semantic-threshold.ts that ref-intent-routing does not exercise: statementOf, the signed judge message, verdictDigest,
// signJudgeVerdict (Ed25519 / ML-DSA-65 / hybrid, all deterministic), verifyJudgeAttestation, verifySemanticThreshold WITH the hardware-attestation gate and PQ pins,
// the hook createSemanticVerifier and semanticRiskContribution. (quantizeScore, verifyJudgeVerdict, conformalThreshold, empiricalFalseAllowRate and the plain
// verifySemanticThreshold are in ref-intent-routing, which every lane has; the quantizeScore / verifyJudgeVerdict cases are repeated here with the suite edges.)
// Writes out/ref-semantic-threshold.json.gz. Deterministic: judge keys from seed(label); no clock.
// PORTING (fn(args) -> native entry point; compared by JSON value; a throw = the native throws; {"$num":"NaN"|"Infinity"|"-Infinity"}; {"$bytes":{"$seed":label}} = the 32-byte Ed25519 secret)
//   suite arg = {alg, pqSeed: {"$bytes"...}} -> mlDsa65Keygen(pqSeed)
//   quantizeScore [x] -> int            statementOf [v] -> JudgeStatement {v:1, actionDigest, goalCommitment, faithful (=== true), score_ppm, judgeMeasurement (String(x ?? "")), alg?, pq_pk?}
//   semanticJudgeMessage [statement] -> {"$bytes": SEMANTIC_JUDGE_DOMAIN || strict canonical JSON(statement)} (throws on a non-integer / negative-zero / non-finite member)
//   verdictDigest [verdict] -> string        signJudgeVerdict [secret, v, suite|null] -> JudgeVerdict (throws on an unknown alg)
//   verifyJudgeVerdict [verdict, {actionDigest, goalCommitment}, pin|null] -> bool
//   verifyJudgeAttestation [judgeMeasurement, attestation|null, approved|null] -> {ok, reason?, measured?}
//   verifySemanticThreshold [verdicts, opts] -> {ok, agreeCount, aggregateScore, cutoff?, reason?}; opts as the reference (judgeKeys, k, goalCommitment, actionDigest, calibration?, pqPins?, allowUnboundPq?)
//        plus attestation?: {require, approved?, byJudge: {<judge pubkey>: HardwareAttestationResult}} (resolve = lookup by verdict.judge, a missing member = undefined). Infinity cutoff is {"$num":"Infinity"}.
//   semanticVerifier [opts, ctxs] -> per ctx {enforced, ok?, reason?}: opts {judgeKeys, k, calibration?, optionalWhenAbsent?, actionDigestMode: "default"|"fixed:<d>"}; ctx {pcactn:{action}, verdicts?, goal?, attestation?: as above}
//        verdicts(ctx) = ctx.verdicts, goalCommitment(ctx) = ctx.goal, default actionDigest = hashCanonical(ctx.pcactn.action)
//   semanticRiskContribution [x] -> number      constants [] -> {SEMANTIC_JUDGE_DOMAIN, SCORE_SCALE}
import { Oracle, refWrite, seed } from './lib.mjs';
import { adder } from './foundation.mjs';
const S: any = await import('../../../packages/pca/src/semantic-threshold.ts');
const PQ: any = await import('../../../packages/pca/src/pq.ts');
const { publicKeyOf } = await import('../../../packages/pca/src/keys.ts') as any;
const { b64u, hashCanonical } = await import('../../../packages/pca/src/hash.ts') as any;
const o = new Oracle('semantic-threshold', 'tools/pca-audit/oracles/semantic-threshold.mts', 'TS-reference oracle for packages/pca/src/semantic-threshold.ts (the parts beyond ref-intent-routing).');
const suiteOf = (s: any) => (s == null ? undefined : s.alg === 'ed25519' ? { alg: s.alg } : { alg: s.alg, mlDsa: PQ.mlDsa65Keygen(s.pqSeed) });
const attOf = (a: any) => (a ? { require: a.require, ...(a.approved !== undefined ? { approved: a.approved } : {}), resolve: (v: any) => a.byJudge?.[v.judge] } : undefined);
const REF: Record<string, (...a: any[]) => any> = {
  quantizeScore: (x) => S.quantizeScore(x), statementOf: (v) => S.statementOf(v), semanticJudgeMessage: (s) => S.semanticJudgeMessage(s), verdictDigest: (v) => S.verdictDigest(v),
  signJudgeVerdict: (sk, v, su) => S.signJudgeVerdict(sk, v, suiteOf(su)), verifyJudgeVerdict: (v, e, p) => S.verifyJudgeVerdict(v, e, p === null ? undefined : p),
  verifyJudgeAttestation: (m, a, ap) => S.verifyJudgeAttestation(m, a === null ? undefined : a, ap === null ? undefined : ap),
  verifySemanticThreshold: (vs, op) => { const { attestation, ...r } = op; return S.verifySemanticThreshold(vs, { ...r, ...(attestation ? { attestation: attOf(attestation) } : {}) }); },
  semanticVerifier: (op, ctxs) => { const { actionDigestMode, ...r } = op; const h = S.createSemanticVerifier({ ...r, verdicts: (c: any) => c.verdicts, goalCommitment: (c: any) => c.goal, ...(actionDigestMode?.startsWith('fixed:') ? { actionDigest: () => actionDigestMode.slice(6) } : {}), attestation: (c: any) => attOf(c.attestation) }); return ctxs.map((c: any) => h(c)); },
  semanticRiskContribution: (x) => S.semanticRiskContribution(x),
  constants: () => ({ SEMANTIC_JUDGE_DOMAIN: S.SEMANTIC_JUDGE_DOMAIN, SCORE_SCALE: S.SCORE_SCALE }),
};
const add = adder(o, REF);
const J = [0, 1, 2, 3].map((i) => seed('st/judge' + i)), JPK = J.map((k) => b64u(publicKeyOf(k))); const PQS = seed('st/pq');
const AD = hashCanonical({ verb: 'pay', resource: 'a', params: { amount: 5 } }), GC = hashCanonical('goal-commitment'), AD2 = hashCanonical('other');
const V = (over: any = {}) => ({ actionDigest: AD, goalCommitment: GC, faithful: true, score: 0.9, judgeMeasurement: 'm', ...over });
const sign = (i: number, v: any = {}, su: any = null) => JSON.parse(JSON.stringify(S.signJudgeVerdict(J[i], V(v), suiteOf(su))));
const flip = (s: string) => s.slice(0, -2) + (s.slice(-2) === 'AA' ? 'BB' : 'AA');

for (const [i, x] of [0, 1, 0.5, 0.0000004, 0.0000005, 0.0000006, 0.9999995, 0.9999996, 1.0000004, 1.5, -0.0000004, -0, -1, 0.3333333, 0.1 + 0.2, 1e-300, 5e-324, 1e21, { $num: 'NaN' }, { $num: 'Infinity' }, { $num: '-Infinity' }, 0.2345675, 0.2345665, '0.5', null, true].entries()) await add('quantizeScore', 'x' + i, [x]);
const SV: [string, any][] = [['ok', V()], ['unfaithful', V({ faithful: false })], ['faithful-truthy', V({ faithful: 1 })], ['faithful-str', V({ faithful: 'true' })], ['score-round-up', V({ score: 0.1234565 })], ['score-1', V({ score: 1 })], ['score-0', V({ score: 0 })], ['score-neg', V({ score: -0.5 })], ['score-big', V({ score: 7 })], ['score-nan', V({ score: { $num: 'NaN' } })], ['score-tiny-neg', V({ score: -0.0000001 })],
  ['measurement-missing', V({ judgeMeasurement: undefined })], ['measurement-null', V({ judgeMeasurement: null })], ['measurement-num', V({ judgeMeasurement: 5 })], ['measurement-empty', V({ judgeMeasurement: '' })], ['alg-only', V({ alg: 'ml-dsa-65' })], ['alg-pq', V({ alg: 'ml-dsa-65', pq_pk: 'PK' })], ['pq-without-alg', V({ pq_pk: 'PK' })], ['alg-ed', V({ alg: 'ed25519', pq_pk: 'PK' })], ['alg-unknown', V({ alg: 'rot13', pq_pk: 'PK' })], ['extra-dropped', V({ extra: 1 })]];
for (const [n, v] of SV) await add('statementOf', n, [v]);
const MSGS: [string, any][] = [['canonical', S.statementOf(V())], ['unfaithful', S.statementOf(V({ faithful: false, score: 0.5 }))], ['member-order', { judgeMeasurement: 'm', score_ppm: 5, faithful: true, goalCommitment: GC, actionDigest: AD, v: 1 }], ['neg-zero-ppm', { ...S.statementOf(V()), score_ppm: -0 }], ['frac-ppm', { ...S.statementOf(V()), score_ppm: 1.5 }], ['nan-ppm', { ...S.statementOf(V()), score_ppm: { $num: 'NaN' } }], ['big-ppm', { ...S.statementOf(V()), score_ppm: 2 ** 53 }], ['unicode-measurement', S.statementOf(V({ judgeMeasurement: 'é😀\u0000' }))], ['pq', S.statementOf(V({ alg: 'ml-dsa-65', pq_pk: 'AAAA' }))], ['empty', {}], ['null', null]];
for (const [n, s] of MSGS) await add('semanticJudgeMessage', n, [s]);
// signing
const SG: [string, any, any][] = [['ok', V(), null], ['unfaithful', V({ faithful: false, score: 0.2 }), null], ['score-rounding', V({ score: 0.1234565 }), null], ['no-measurement', { actionDigest: AD, goalCommitment: GC, faithful: true, score: 0.5 }, null], ['faithful-truthy', V({ faithful: 'yes' }), null], ['score-nan', V({ score: { $num: 'NaN' } }), null], ['score-out-of-range', V({ score: 3 }), null], ['score-neg', V({ score: -2 }), null],
  ['ed-explicit', V(), { alg: 'ed25519' }], ['ml-dsa', V(), { alg: 'ml-dsa-65', pqSeed: PQS }], ['hybrid', V(), { alg: 'hybrid-ed25519-ml-dsa-65', pqSeed: PQS }], ['unknown-alg', V(), { alg: 'rot13' }], ['digest-nonstring', V({ actionDigest: 5 }), null]];
for (const [n, v, su] of SG) await add('signJudgeVerdict', n, [J[0], v, su]);
const G0 = sign(0), G1 = sign(1), G2 = sign(2), G3 = sign(3);
await add('verdictDigest', 'plain', [G0]); await add('verdictDigest', 'member-order', [{ sig: G0.sig, ...G0 }]); await add('verdictDigest', 'empty', [{}]); await add('verdictDigest', 'nan', [{ ...G0, score: { $num: 'NaN' } }]);
// verify verdict (suite edges)
const PQV = sign(0, {}, { alg: 'ml-dsa-65', pqSeed: PQS }), HYV = sign(0, {}, { alg: 'hybrid-ed25519-ml-dsa-65', pqSeed: PQS });
const EXP = { actionDigest: AD, goalCommitment: GC };
for (const [n, v, e, p] of [['ok', G0, EXP, null], ['other-action', G0, { ...EXP, actionDigest: AD2 }, null], ['other-goal', G0, { ...EXP, goalCommitment: AD2 }, null], ['sig-flip', { ...G0, sig: flip(G0.sig) }, EXP, null], ['score-tampered', { ...G0, score: 0.1 }, EXP, null], ['faithful-tampered', { ...G0, faithful: false }, EXP, null], ['score-same-ppm-different-float', { ...G0, score: 0.9000000001 }, EXP, null], ['measurement-tampered', { ...G0, judgeMeasurement: 'x' }, EXP, null],
  ['judge-short', { ...G0, judge: 'abc' }, EXP, null], ['judge-num', { ...G0, judge: 5 }, EXP, null], ['score-over', { ...G0, score: 1.5 }, EXP, null], ['score-nan', { ...G0, score: { $num: 'NaN' } }, EXP, null], ['faithful-str', { ...G0, faithful: 'true' }, EXP, null], ['measurement-num', { ...G0, judgeMeasurement: 5 }, EXP, null], ['sig-num', { ...G0, sig: 5 }, EXP, null],
  ['pq-no-pin', PQV, EXP, null], ['pq-pinned', PQV, EXP, { pqPins: { [PQV.judge]: PQV.pq_pk } }], ['pq-unbound', PQV, EXP, { allowUnboundPq: true }], ['pq-missing-pq-pk', (({ pq_pk, ...r }: any) => r)(PQV), EXP, { allowUnboundPq: true }], ['hybrid-pinned', HYV, EXP, { pqPins: { [HYV.judge]: HYV.pq_pk } }], ['hybrid-pq-sig-flip', { ...HYV, pq_sig: flip(HYV.pq_sig) }, EXP, { pqPins: { [HYV.judge]: HYV.pq_pk } }], ['hybrid-no-pq-sig', (({ pq_sig, ...r }: any) => r)(HYV), EXP, { pqPins: { [HYV.judge]: HYV.pq_pk } }],
  ['unknown-alg', { ...G0, alg: 'rot13' }, EXP, null], ['null', null, EXP, null], ['string', 'x', EXP, null], ['array', [], EXP, null], ['extra-member-ok', { ...G0, extra: 1 }, EXP, null]] as any[]) await add('verifyJudgeVerdict', n, [v, e, p]);
// attestation
const MI = (over: any = {}) => ({ model_id: 'judge-1', weights_digest: 'w', runtime_measurement: 'm', operator: 'op', ...over });
const OKA = { ok: true, bound: true, measured: MI() };
for (const [n, m, a, ap] of [['ok', 'm', OKA, null], ['missing', 'm', null, null], ['not-ok', 'm', { ok: false, reason: 'bad quote' }, null], ['not-ok-noreason', 'm', { ok: false }, null], ['ok-truthy', 'm', { ok: 1, bound: true, measured: MI() }, null], ['unbound', 'm', { ok: true, bound: false, measured: MI() }, null], ['bound-truthy', 'm', { ok: true, bound: 1, measured: MI() }, null], ['no-measured', 'm', { ok: true, bound: true }, null], ['measured-null', 'm', { ok: true, bound: true, measured: null }, null], ['measured-string', 'm', { ok: true, bound: true, measured: 'x' }, null],
  ['no-judge-measurement', '', OKA, null], ['judge-measurement-num', 5, OKA, null], ['mismatch', 'other', OKA, null], ['approved-ok', 'm', OKA, { model_allowlist: ['judge-1'] }], ['approved-bad-model', 'm', OKA, { model_allowlist: ['zz'] }], ['approved-operator-bad', 'm', OKA, { operator: 'evil' }], ['approved-svn-ok', 'm', { ok: true, bound: true, measured: MI({ runtime_measurement: '7' }) }, { min_measurement: { svn: 5 } }], ['approved-empty', 'm', OKA, {}]] as any[]) await add('verifyJudgeAttestation', n, [m, a, ap]);
// threshold with attestation / pins
const KEYS = JPK.slice(0, 3);
const TO = (over: any = {}) => ({ judgeKeys: KEYS, k: 2, goalCommitment: GC, actionDigest: AD, ...over });
const ATT_ALL = { require: true, byJudge: { [JPK[0]]: OKA, [JPK[1]]: OKA, [JPK[2]]: OKA } };
const VT = (n: string, vs: any[], over: any = {}) => add('verifySemanticThreshold', n, [vs, TO(over)]);
await VT('plain-ok', [G0, G1]); await VT('plain-one-short', [G0]); await VT('att-ok', [G0, G1], { attestation: ATT_ALL }); await VT('att-not-required', [G0, G1], { attestation: { ...ATT_ALL, require: false, byJudge: {} } }); await VT('att-required-missing', [G0, G1], { attestation: { require: true, byJudge: {} } });
await VT('att-one-unattested', [G0, G1], { attestation: { require: true, byJudge: { [JPK[0]]: OKA } } }); await VT('att-one-wrong-measurement', [G0, G1, G2], { attestation: { require: true, byJudge: { [JPK[0]]: OKA, [JPK[1]]: { ok: true, bound: true, measured: MI({ runtime_measurement: 'zz' }) }, [JPK[2]]: OKA } } });
await VT('att-approved-gate', [G0, G1], { attestation: { ...ATT_ALL, approved: { model_allowlist: ['nope'] } } }); await VT('att-approved-ok', [G0, G1], { attestation: { ...ATT_ALL, approved: { model_allowlist: ['judge-1'] } } }); await VT('att-require-str-not-true', [G0, G1], { attestation: { require: 'yes', byJudge: {} } });
await VT('k-0', [G0], { k: 0 }); await VT('k-frac', [G0], { k: 1.5 }); await VT('k-str', [G0], { k: '1' }); await VT('k-nan', [G0], { k: { $num: 'NaN' } }); await VT('k-missing', [G0], { k: undefined }); await VT('no-action', [G0], { actionDigest: undefined }); await VT('no-goal', [G0], { goalCommitment: undefined });
await VT('untrusted-judge', [G0, G3], { k: 2 }); await VT('duplicate-judge-counts-once', [G0, G0], { k: 2 }); await VT('same-judge-conflicting', [G0, sign(0, { faithful: false })], { k: 1 }); await VT('same-judge-conflicting-score', [G0, sign(0, { score: 0.5 })], { k: 1 });
await VT('same-judge-same-ppm', [G0, sign(0, { score: 0.9000000001 })], { k: 1 }); await VT('judge-keys-junk', [G0], { k: 1, judgeKeys: [5, 'short', JPK[0], null] }); await VT('no-judge-keys', [G0], { k: 1, judgeKeys: [] }); await VT('verdicts-not-array', 'x' as any, { k: 1 }); await VT('verdicts-junk-elements', [null, 5, 'x', G0], { k: 1 });
await VT('agree-mean', [sign(0, { score: 0.8 }), sign(1, { score: 0.6 }), sign(2, { score: 0.4 })], { k: 3 }); await VT('agree-excludes-unfaithful', [sign(0, { score: 0.8 }), sign(1, { faithful: false, score: 0.1 }), sign(2, { score: 0.4 })], { k: 2 });
const CAL = { alpha: 0.1, samples: Array.from({ length: 30 }, (_, i) => ({ score: i / 30, faithful: i % 3 === 0 })) };
await VT('cal-pass', [sign(0, { score: 0.99 }), sign(1, { score: 0.98 })], { calibration: CAL }); await VT('cal-fail', [sign(0, { score: 0.1 }), sign(1, { score: 0.2 })], { calibration: CAL }); await VT('cal-no-negatives', [G0, G1], { calibration: { alpha: 0.1, samples: [{ score: 0.9, faithful: true }] } }); await VT('cal-equal-not-exceed', [sign(0, { score: 0.5 }), sign(1, { score: 0.5 })], { calibration: { alpha: 0.5, samples: [{ score: 0.5, faithful: false }, { score: 0.5, faithful: false }] } });
await VT('cal-alpha-0', [G0, G1], { calibration: { ...CAL, alpha: 0 } }); await VT('cal-alpha-nan', [G0, G1], { calibration: { ...CAL, alpha: { $num: 'NaN' } } }); await VT('cal-junk-samples', [G0, G1], { calibration: { alpha: 0.5, samples: [null, 5, { score: 'x', faithful: false }, { score: { $num: 'NaN' }, faithful: false }, { score: 0.1, faithful: false }] } });
await VT('pq-pinned', [PQV, sign(1, {}, { alg: 'ml-dsa-65', pqSeed: seed('st/pq1') })], { k: 1, pqPins: { [PQV.judge]: PQV.pq_pk } }); await VT('pq-no-pin', [PQV], { k: 1 }); await VT('pq-unbound', [PQV], { k: 1, allowUnboundPq: true }); await VT('hybrid-pinned-with-att', [HYV], { k: 1, pqPins: { [HYV.judge]: HYV.pq_pk }, attestation: ATT_ALL });
// hook
const SVx = (n: string, op: any, ctxs: any[]) => add('semanticVerifier', n, [{ judgeKeys: KEYS, k: 2, ...op }, ctxs]);
const ACT = { verb: 'pay', resource: 'a', params: { amount: 5 } }, ADV = hashCanonical(ACT);
const sg = (i: number, v: any = {}) => sign(i, { actionDigest: ADV, ...v });
await SVx('ok', {}, [{ pcactn: { action: ACT }, verdicts: [sg(0), sg(1)], goal: GC }]);
await SVx('short', {}, [{ pcactn: { action: ACT }, verdicts: [sg(0)], goal: GC }]); await SVx('other-action', {}, [{ pcactn: { action: { ...ACT, resource: 'b' } }, verdicts: [sg(0), sg(1)], goal: GC }]);
await SVx('absent-verdicts', {}, [{ pcactn: { action: ACT }, goal: GC }]); await SVx('absent-goal', {}, [{ pcactn: { action: ACT }, verdicts: [sg(0), sg(1)] }]); await SVx('absent-optional', { optionalWhenAbsent: true }, [{ pcactn: { action: ACT }, goal: GC }, { pcactn: { action: ACT }, verdicts: [sg(0), sg(1)] }]);
await SVx('absent-optional-false', { optionalWhenAbsent: false }, [{ pcactn: { action: ACT }, goal: GC }]); await SVx('goal-non-string', {}, [{ pcactn: { action: ACT }, verdicts: [sg(0), sg(1)], goal: 5 }]);
await SVx('fixed-digest', { actionDigestMode: 'fixed:' + AD }, [{ pcactn: { action: ACT }, verdicts: [G0, G1], goal: GC }]); await SVx('calibration-fail', { calibration: CAL }, [{ pcactn: { action: ACT }, verdicts: [sg(0, { score: 0.1 }), sg(1, { score: 0.1 })], goal: GC }]);
await SVx('attestation-per-ctx', {}, [{ pcactn: { action: ACT }, verdicts: [sg(0), sg(1)], goal: GC, attestation: ATT_ALL }, { pcactn: { action: ACT }, verdicts: [sg(0), sg(1)], goal: GC, attestation: { require: true, byJudge: {} } }]);
await SVx('k-invalid', { k: 0 }, [{ pcactn: { action: ACT }, verdicts: [sg(0)], goal: GC }]);
for (const [i, x] of [0, 1, 0.5, 0.9, 0.123456, -0.1, 1.5, { $num: 'NaN' }, { $num: 'Infinity' }, { $num: '-Infinity' }, '0.5', null, 1e-9, 0.9999999].entries()) await add('semanticRiskContribution', 'x' + i, [x]);
await add('constants', 'all', []);
refWrite(o, 'semantic-threshold');
