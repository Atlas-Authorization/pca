// Oracle: @atlasauth/pca-wallet (the wallet side of the PCA Intent Layer v2: signed answers, friction tiers, noise numerics, canaries,
// approval fatigue, risk-priced escalation, cell coordinates over the outcome space, the trusted question card, clarification planning,
// population priors and the question channel). Deterministic: fixed seeds, fixed clock T0, scripted randomness; Ed25519 signs
// deterministically. Writes out/ref-wallet.json.gz.
//
// PLACEHOLDERS in args (replace before the call, in every language): {"$omega": "A"|"B"} -> the outcome space from the case
//   `omegas` (fn "omegas", out = {A, B}); {"$seed": label} -> the 32-byte Ed25519 seed sha256("atlas-pca-conformance/<label>").
//
// PORTING (fn(args) -> native entry point, comparison rule: JSON equality, numbers by IEEE-754 value; a reference throw requires a throw):
//   constants()                          -> the exported constants as one object (see the generator for the member list)
//   isFrictionTier / frictionRank / maxFriction(...tiers) / satisfiesTier / isProvenanceLevel / worstProvenance / frictionFor(inp, th?)
//   pcaActionDigest(a) / actionValuesOf(a) / isB64u32(v) / isObj(v) / coordsError(c)
//   answerShapeError / signIntentAnswer(a, {$seed}) / verifyIntentAnswer(a, principals?) (reason "malformed answer: ..." compared as the
//       prefix only) / answerRef / typedDigest(q, v) / deviceChallenge({questionId, renderedDigest, y, actionDigest?})
//   lnGamma / betacf / betaInc / betaQuantile / clopperPearsonUpper / binEnt (exact doubles; fdlibm transcendental functions)
//   recordCanary / estimateNoise / cellKey / boundaryNeighbours(omega, confirmed) / pickCanary(ctx) with ctx = {omega, confirmed, knownNo:
//       {cellKey: why}, knownYes, exclude: [keys], rands: [..] (a draw past the end throws), rho?, lowHarmSession, canariesSoFar}
//   etaUnderLoad / noiseState(counts, nRecent, model?) / admissionPolicy(state, model?) / doubleConfirmed
//   slidingWindow(windowMs|null, ops) with ops [["count", now] | ["tryAdd", now, cap]] -> one entry per op ({v} or {err})
//   signPricingConfig(body, {$seed}) / pricingConfigError / decideEscalation / signAnswer / updateCalibration(config, cal, answers, risks
//       object digest -> risk) / signAutonomyRaise / applyAutonomyRaise(config, raise, {$seed}) / freshCalibration
//   coordKeyOf / catLabel(omegaId, verb, dim, i) / resolveCoords(omega, verb, coords) -> {ok, verb, box} | {ok:false, reason} /
//       coordsOfBox(omegaId, verb, box) / coordsOfCell(omegaId, verb, idx) / cellInBox / boxCells / boxSize / cellOfAction(omegaId, a) ->
//       {verb, idx} | null / flatIndex(omegaId, verb, idx)
//   cleanText / last4 / formatNumber(x, unit?) / renderCard({omegaId, ...input}) / cardDigest / cardDigestMatches / cardText / partialError /
//       normalizeTyped / expectedTyped
//   parseClarifyRequest / informationGain / planClarification({omegaId, view: {p: {cellKey: p}, vetoed: [keys], ceiling: [keys]}, candidates,
//       asked: [keys], etaPos, etaNeg})
//   gaussianSigma / gaussian(rands) / rrKeepProbability / randomizedResponse(y, eps, r) / debiasRandomizedResponse / populationCellKey(schema, omegaId, verb, idx)
//   aggregate(schema, period, {maxCellsPerPrincipal?}, votes, {epsilon, delta, qMin?, minCount?}, rands) -> {votes: [contribute results], release | {err:true}}
//       (a draw past the end of rands throws; the constructor failing makes the whole case a throw)
//   populationPrior(release, beta, omegaId, verb, containedCells) -> {beta, weight} (weight of the hypothesis holding exactly those flat cells)
//   siteQuestionNotice(ir, keys, site, now, inbox?) / clarificationNotice(session, qid, inbox?) / questionText(notice, siteName)
//   webhookChannel(cfg {url?, headers?}, script [{ok,status} | {throw}], notices) / textChannel(kind, siteName, script|null, notices) / dispatcher(cfgs, notice):
//       a channel is driven with a scripted transport; the output carries the deliveries and the recorded calls (url, method, headers, body = JSON text)
//   channel(spec): one session of the question channel. spec = {omega, session, mapDigest, principal (seed label), site {origin, name, keys}, statementText?,
//       units?, sensitivity?, identityPaths?, lift {add: values merged into the lifted action}, liftCand {add}, view {p: {cellKey: p}, vetoed, ceiling,
//       confirmed: [{verb, idx}]}, caps?, rho, fatigue?, maxPerScreen?, maxBoxCells?, noise (counts), hourlyPre [timestamps], windowMs?, rands, t0, device?
//       {rpId, origins, credentials, signCounts}, steps}. Steps: {op: time|receive|next|answer|clarify|hQuestion|hClarify|summary|state|noise|challenge, ...};
//       q = index into the question ids shown so far by `next`, qid = a literal id; a device-tier answer carries its generated WebAuthn assertion (already
//       in the recorded args). Output {steps: [{op, r}] (r = {"$err": true} when the call threw), noise: final counts, signCounts}. The clock is the last `time` step.
//       Operations are replayed in order; randomness is the `rands` list (a draw past the end throws, leaving the partial state in place).
//   omega.* (the private outcome-space port): numCells(omegaId, verb, dim) / cellCount / verbCellCount / decodeCell / cellOf(omegaId,
//       verb, outcome) / cellRep / cellStats(omegaId, verb, idx) -> {mass, harm} / labelOf
import { createHash, createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';
import { Oracle, seed, rng, variants as variants0, reparse, capture, ser, refWrite } from './lib.mjs';

// Variants of a valid value, without replacing the ROOT by a hostile scalar (the roots are probed by the HOSTILE loops where the natives agree).
function* variants(v: any, opts: any = {}): Generator<[string, any]> {
  for (const [l, x] of variants0(v, { hostile: [null, true, 0, -0, 1.5, '', 'x', [], {}], ...opts })) if (!l.startsWith('/ = hostile#')) yield [l, x];
}

const W0: any = await import('../../../packages/pca-wallet/src/index.ts');
const I0: any = await import('../../../packages/pca-intent/src/index.ts');
const P0: any = await import('../../../packages/pca/src/index.ts');
const W: any = W0.default ?? W0;
const I: any = I0.default ?? I0;
const { hashCanonical, publicKeyOf } = P0.default ?? P0;
const o = new Oracle('wallet', 'tools/pca-audit/oracles/wallet.mts', 'TS-reference oracle for the wallet side of the PCA Intent Layer v2.');
const T0 = 1_800_000_000_000;
const b64u = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const dig = (l: string) => hashCanonical({ wallet: l });
const pubOf = (l: string) => b64u(publicKeyOf(seed(l)));

// ---- the outcome spaces -----------------------------------------------------------------------------------------------
const OTHER = '⊥';
const ex = (value: string) => ({ kind: 'exact', value });
const pre = (value: string) => ({ kind: 'prefix', value });
const oth = { kind: 'other', value: OTHER };
const OM: Record<string, any> = {
  A: {
    v: 1,
    approximate: [],
    verbs: [
      {
        verb: 'stripe.refund', reversibility: 'irreversible', weight: 0.5,
        dims: [
          { kind: 'num', path: 'action.params.amount', lo: 0, hi: 100000, cuts: [100, 1000, 10000], dist: 'loguniform' },
          { kind: 'cat', path: 'action.resource', values: [ex('charge:ch_1'), ex('charge:ch_2'), pre('charge:'), oth] },
          { kind: 'num', path: 'env.acc.spend.post', lo: 0, hi: 5000, cuts: [1000], dist: 'uniform' },
          { kind: 'cat', path: 'env.prov.recipient', values: [ex('agent'), ex('first_party'), ex('tool|web'), ex('trusted'), oth] },
        ],
      },
      {
        verb: 'files.read', reversibility: 'reversible', weight: 0.3,
        dims: [{ kind: 'cat', path: 'action.resource', values: [ex('file:a'), ex('file:b'), pre('file:'), oth] }],
      },
      {
        verb: 'http.post', reversibility: 'rate_limited', weight: 0.2,
        dims: [
          { kind: 'num', path: 'action.params.count', lo: 0, hi: 1000, cuts: [10, 100], dist: 'loguniform' },
          { kind: 'cat', path: 'env.world.region', values: [ex('eu'), ex('us'), oth] },
        ],
      },
    ],
  },
  B: {
    v: 1,
    approximate: [],
    verbs: [
      {
        verb: 'ledger.post', reversibility: 'irreversible', weight: 1,
        dims: [
          { kind: 'num', path: 'action.params.amount', lo: 0, hi: 1_000_000_000, cuts: [1000, 1_000_000, 500_000_000], dist: 'loguniform' },
          { kind: 'cat', path: 'action.params.account', values: [ex('acct_main'), ex('acct_savings'), oth] },
        ],
      },
    ],
  },
};

const sub = (x: any): any => {
  if (x === null || typeof x !== 'object') return x;
  if (Array.isArray(x)) return x.map(sub);
  const ks = Object.keys(x);
  if (ks.length === 1 && ks[0] === '$omega') return OM[x.$omega];
  if (ks.length === 1 && ks[0] === '$seed') return new Uint8Array(seed(x.$seed));
  return Object.fromEntries(ks.map((k) => [k, sub(x[k])]));
};
const run = async (fn: string, name: string, ref: (...a: any[]) => any, args: any[]) => {
  const a = reparse(args);
  o.add(fn, name, a, await capture(ref, a.map(sub)));
};
const SEEDL = (l: string) => ({ $seed: l });
const vsOf = (id: string, verb: string) => OM[id].verbs.find((v: any) => v.verb === verb);

o.add('omegas', 'both', [], reparse(OM));

o.add('constants', 'all', [], reparse({
  FRICTION_ORDER: W.FRICTION_ORDER, INTENT_ANSWER_SIG_DOMAIN: W.INTENT_ANSWER_SIG_DOMAIN, INTENT_ANSWER_REF_DOMAIN: W.INTENT_ANSWER_REF_DOMAIN,
  INTENT_TYPED_DOMAIN: W.INTENT_TYPED_DOMAIN, INTENT_DEVICE_CHALLENGE_DOMAIN: W.INTENT_DEVICE_CHALLENGE_DOMAIN, MIN_HOLD_MS: W.MIN_HOLD_MS,
  PROVENANCE_ORDER: W.PROVENANCE_ORDER, DEFAULT_FRICTION_THRESHOLDS: W.DEFAULT_FRICTION_THRESHOLDS, CARD_DOMAIN: W.CARD_DOMAIN,
  CLARIFY_REASONS: W.CLARIFY_REASONS, REASON_LABELS: W.REASON_LABELS, MAX_CANDIDATES: W.MAX_CANDIDATES, EMPTY_NOISE: W.EMPTY_NOISE,
  NOISE_PRIOR: W.NOISE_PRIOR, DEFAULT_FATIGUE: W.DEFAULT_FATIGUE, PPM: W.PPM, MAX_MULTIPLIER_PPM: W.MAX_MULTIPLIER_PPM,
  POPULATION_VOTE_DOMAIN: W.POPULATION_VOTE_DOMAIN, BETA_MAX: W.BETA_MAX,
}));

const HOSTILE = [null, true, false, 0, -0, 1, -1, 1.5, '', 'x', 'tap', 'hold', 'typed', 'device', [], ['tap'], {}, { x: 1 }];

// ---- friction -------------------------------------------------------------------------------------------------------
for (const [i, h] of HOSTILE.entries()) {
  await run('isFrictionTier', `h${i}`, W.isFrictionTier, [h]);
  await run('frictionRank', `h${i}`, W.frictionRank, [h]);
  await run('isProvenanceLevel', `h${i}`, W.isProvenanceLevel, [h]);
  await run('worstProvenance', `h${i}`, W.worstProvenance, [h]);
}
const TIERS = ['tap', 'hold', 'typed', 'device'];
for (const a of TIERS) for (const b of TIERS) {
  await run('satisfiesTier', `${a}-${b}`, W.satisfiesTier, [a, b]);
  await run('maxFriction', `${a}-${b}`, W.maxFriction, [a, b]);
}
await run('maxFriction', 'none', W.maxFriction, []);
await run('maxFriction', 'unknown', W.maxFriction, ['bogus', 'tap']);
await run('maxFriction', 'three', W.maxFriction, ['hold', 'tap', 'typed']);
const LEVELS = ['trusted', 'first_party', 'tool', 'web', 'agent'];
for (const l of LEVELS) await run('worstProvenance', `one-${l}`, W.worstProvenance, [[l]]);
await run('worstProvenance', 'empty', W.worstProvenance, [[]]);
await run('worstProvenance', 'mixed', W.worstProvenance, [['trusted', 'tool', 'first_party']]);
await run('worstProvenance', 'unknown-member', W.worstProvenance, [['trusted', 'bogus']]);
for (const rev of ['reversible', 'rate_limited', 'irreversible', 'bogus'])
  for (const harm of [0, 5, 99999, 100000, -1, 'x'])
    for (const prov of [undefined, [], [{ path: 'p', sensitivity: 'critical', levels: ['web'] }], [{ path: 'p', sensitivity: 'critical', levels: ['trusted'] }], [{ path: 'p', sensitivity: 'material', levels: ['agent'] }], [{ path: 'p', sensitivity: 'critical', levels: [] }]])
      for (const extra of [{}, { widensCriticalIdentity: true }, { singleSource: true }, { siteMin: 'device' }, { siteMin: 'hold', singleSource: true, widensCriticalIdentity: true }])
        await run('frictionFor', `${rev}-${harm}-${JSON.stringify(prov)}-${JSON.stringify(extra)}`, W.frictionFor, [{ reversibility: rev, expectedHarm: harm, ...(prov ? { provenance: prov } : {}), ...extra }]);
await run('frictionFor', 'custom-thresholds', W.frictionFor, [{ reversibility: 'reversible', expectedHarm: 2 }, { hTap: 1, hDevice: 3 }]);
await run('frictionFor', 'custom-thresholds-device', W.frictionFor, [{ reversibility: 'reversible', expectedHarm: 3 }, { hTap: 1, hDevice: 3 }]);
await run('frictionFor', 'site-min-up', W.frictionFor, [{ reversibility: 'reversible', expectedHarm: 1, siteMin: 'typed' }]);
await run('frictionFor', 'single-source-cap', W.frictionFor, [{ reversibility: 'irreversible', expectedHarm: 200000, singleSource: true }]);

// ---- the action and its digest ------------------------------------------------------------------------------------------
const ACT = { verb: 'stripe.refund', resource: 'charge:ch_1', params: { amount: 500, currency: 'usd', note: 'x' }, reversibility_class: 'irreversible' };
await run('pcaActionDigest', 'base', W.pcaActionDigest, [ACT]);
await run('actionValuesOf', 'base', W.actionValuesOf, [ACT]);
for (const [l, v] of variants(ACT, { maxPaths: 40 })) {
  await run('pcaActionDigest', l, W.pcaActionDigest, [v]);
  await run('actionValuesOf', l, W.actionValuesOf, [v]);
}
for (const [i, h] of HOSTILE.entries()) {
  await run('isB64u32', `h${i}`, W.isB64u32, [h]);
  await run('isObj', `h${i}`, W.isObj, [h]);
  await run('coordsError', `h${i}`, W.coordsError, [h]);
}
// the hostile palette holds no provenance level and no 32-byte value: without these both predicates only ever answer false
for (const v of [...W.PROVENANCE_ORDER, 'Agent', 'agent ', 'first-party', 'firstParty', 'unknown']) await run('isProvenanceLevel', `v ${JSON.stringify(v)}`, W.isProvenanceLevel, [v]);
const b32s = (fill: number, len = 32) => Buffer.alloc(len, fill).toString('base64url');
for (const [n, v] of [['zero', b32s(0)], ['ff', b32s(255)], ['mixed', b32s(0x5a)], ['31 bytes', b32s(1, 31)], ['33 bytes', b32s(1, 33)], ['padded', b32s(1) + '='], ['std alphabet', Buffer.alloc(32, 255).toString('base64')],
  ['trailing bits', b32s(0).slice(0, -1) + 'B'], ['space', b32s(1) + ' '], ['42 chars', b32s(1).slice(0, 42)], ['44 chars', b32s(1) + 'A']] as [string, string][]) await run('isB64u32', n, W.isB64u32, [v]);
const COORDS = { 'action.params.amount': [0, 2], 'action.resource': ['charge:ch_1', 'charge:ch_2'] };
await run('coordsError', 'ok', W.coordsError, [COORDS]);
for (const [l, v] of variants(COORDS, { maxPaths: 30 })) await run('coordsError', l, W.coordsError, [v]);
await run('coordsError', 'empty', W.coordsError, [{}]);
await run('coordsError', 'dup', W.coordsError, [{ a: ['x', 'x'] }]);
await run('coordsError', 'range-reversed', W.coordsError, [{ a: [3, 2] }]);

// ---- M6: the signed answer ------------------------------------------------------------------------------------------------
const ANS = {
  map_digest: dig('map'), session: dig('session'), question_id: 'q_abc123', verb: 'stripe.refund',
  cell: { 'action.params.amount': [1, 2], 'action.resource': ['charge:ch_1'] }, y: 1, source: 'elicitation', observed_at: T0,
  ux: { tier: 'tap', rendered_digest: dig('card'), canary: false },
};
const FULL = (x: any) => ({ v: 2, kind: 'pca-intent-observation', ...x, signer: pubOf('wallet/principal'), alg: 'ed25519' });
const tierUx = (tier: string, extra: any = {}) => ({ tier, rendered_digest: dig('card'), canary: false, ...extra });
const WA = { credential_id: 'cred1', authenticator_data: 'AAAA', client_data_json: 'AAAA', signature: 'AAAA' };
const answers: [string, any][] = [
  ['tap', ANS], ['no', { ...ANS, y: 0 }], ['hold', { ...ANS, ux: tierUx('hold', { hold_ms: 2500 }) }], ['hold-short', { ...ANS, ux: tierUx('hold', { hold_ms: 1999 }) }],
  ['typed', { ...ANS, ux: tierUx('typed', { typed_digest: dig('typed') }) }], ['typed-missing', { ...ANS, ux: tierUx('typed') }],
  ['device', { ...ANS, ux: tierUx('device', { webauthn: WA }) }], ['device-missing', { ...ANS, ux: tierUx('device') }],
  ['partial-upto', { ...ANS, partial: { path: 'action.params.amount', upTo: 1 } }], ['partial-from', { ...ANS, partial: { path: 'action.params.amount', from: 1 } }],
  ['partial-except', { ...ANS, partial: { path: 'action.params.amount', except: [1, 2] } }], ['partial-notfor', { ...ANS, partial: { path: 'action.resource', notFor: ['charge:ch_2'] } }],
  ['partial-no', { ...ANS, y: 0, partial: { path: 'action.params.amount', upTo: 1 } }], ['partial-two', { ...ANS, partial: { path: 'a', upTo: 1, from: 2 } }],
  ['partial-bad-kind', { ...ANS, partial: { path: 'a', upTo: 1.5 } }], ['partial-empty-except', { ...ANS, partial: { path: 'a', except: [] } }],
  ['partial-bad-notfor', { ...ANS, partial: { path: 'a', notFor: [''] } }], ['partial-unknown', { ...ANS, partial: { path: 'a', between: 1 } }],
  ['consent', { ...ANS, ux: tierUx('typed', { typed_digest: dig('typed'), action_digest: dig('action'), consent_for_action: true }) }],
  ['consent-no-digest', { ...ANS, ux: tierUx('typed', { typed_digest: dig('typed'), consent_for_action: true }) }],
  ['consent-canary', { ...ANS, ux: tierUx('typed', { typed_digest: dig('typed'), action_digest: dig('action'), consent_for_action: true, canary: true }) }],
  ['consent-partial', { ...ANS, partial: { path: 'action.params.amount', upTo: 1 }, ux: tierUx('typed', { typed_digest: dig('typed'), action_digest: dig('action'), consent_for_action: true }) }],
  ['canary-hold-short', { ...ANS, ux: tierUx('hold', { hold_ms: 5, canary: true }) }], ['clarification', { ...ANS, source: 'clarification' }],
  ['bad-source', { ...ANS, source: 'x' }], ['bad-obs', { ...ANS, observed_at: -1 }], ['bad-qid', { ...ANS, question_id: 'has space' }], ['long-qid', { ...ANS, question_id: 'q'.repeat(65) }],
  ['ux-unknown', { ...ANS, ux: { ...ANS.ux, extra: 1 } }], ['wa-extra', { ...ANS, ux: tierUx('device', { webauthn: { ...WA, extra: 'x' } }) }], ['wa-nonstring', { ...ANS, ux: tierUx('device', { webauthn: { ...WA, signature: 5 } }) }],
];
const sigs: Record<string, any> = {};
for (const [l, a] of answers) {
  await run('answerShapeError', `${l}-unsigned`, W.answerShapeError, [FULL(a)]);
  await run('signIntentAnswer', l, (x: any, k: any) => W.signIntentAnswer(x, k), [a, SEEDL('wallet/principal')]);
  try { sigs[l] = W.signIntentAnswer(reparse(a), seed('wallet/principal')); } catch { /* refused: no signed form */ }
}
await run('signIntentAnswer', 'signer-override', (x: any, k: any) => W.signIntentAnswer(x, k), [{ ...ANS, signer: 'x', alg: 'x', v: 9, kind: 'x' }, SEEDL('wallet/principal')]);
await run('signIntentAnswer', 'other-seed', (x: any, k: any) => W.signIntentAnswer(x, k), [ANS, SEEDL('wallet/other')]);
const vWrap = (a: any, p?: any) => {
  const r = W.verifyIntentAnswer(a, p);
  return r.ok === false && typeof r.reason === 'string' && r.reason.startsWith('malformed answer:') ? { ok: false, reason: 'malformed answer' } : r;
};
for (const [l, s] of Object.entries(sigs)) {
  await run('answerShapeError', `${l}-signed`, W.answerShapeError, [s]);
  await run('verifyIntentAnswer', l, vWrap, [s]);
  await run('answerRef', l, W.answerRef, [s]);
}
const SIGNED = sigs['tap'];
await run('verifyIntentAnswer', 'principals-ok', vWrap, [SIGNED, [pubOf('wallet/principal')]]);
await run('verifyIntentAnswer', 'principals-other', vWrap, [SIGNED, [pubOf('wallet/other')]]);
await run('verifyIntentAnswer', 'principals-empty', vWrap, [SIGNED, []]);
for (const [l, v] of variants(SIGNED, { maxPaths: 36 })) {
  await run('answerShapeError', l, W.answerShapeError, [v]);
  await run('verifyIntentAnswer', l, vWrap, [v]);
}
for (const [i, h] of HOSTILE.entries()) {
  await run('answerShapeError', `h${i}`, W.answerShapeError, [h]);
  await run('verifyIntentAnswer', `h${i}`, vWrap, [h]);
}
const forged = { ...SIGNED, y: 0 };
await run('verifyIntentAnswer', 'tampered-y', vWrap, [forged]);
await run('verifyIntentAnswer', 'sig-not-string', vWrap, [{ ...SIGNED, sig: 5 }]);
await run('typedDigest', 'a', W.typedDigest, ['q_1', '500']);
await run('typedDigest', 'b', W.typedDigest, ['q_1', '501']);
await run('typedDigest', 'unicode', W.typedDigest, ['q_é', '5é0']);
for (const y of [0, 1]) for (const ad of [undefined, dig('action')])
  await run('deviceChallenge', `y${y}-${ad ? 'a' : 'n'}`, W.deviceChallenge, [{ questionId: 'q_1', renderedDigest: dig('card'), y, ...(ad ? { actionDigest: ad } : {}) }]);

// ---- numerics -------------------------------------------------------------------------------------------------------------
const R = rng(0x57a75);
const GX = [1e-8, 0.001, 0.1, 0.49999, 0.5, 0.75, 1, 1.5, 2, 3.7, 7.5, 10, 25.25, 50, 100, 170, 1000, 12345.678];
for (const x of GX) await run('lnGamma', `g${x}`, W.lnGamma, [x]);
for (let i = 0; i < 150; i++) { const x = R.next() * (i % 3 === 0 ? 1 : i % 3 === 1 ? 20 : 400) + 1e-6; await run('lnGamma', `r${i}`, W.lnGamma, [x]); }
const AB = [0.5, 1, 2, 3.5, 5, 10.5, 30, 120];
const XS = [0, 0.001, 0.05, 0.1, 0.3, 0.5, 0.7, 0.9, 0.99, 0.999, 1];
for (const a of AB) for (const b of AB) for (const x of XS) await run('betaInc', `${x}-${a}-${b}`, W.betaInc, [x, a, b]);
for (const x of [0.2, 0.5, 0.8]) for (const [a, b] of [[0.5, 0.5], [2, 3], [10, 1], [1.2, 40]]) await run('betacf', `${x}-${a}-${b}`, W.betacf, [a, b, x]);
for (const [a, b] of [[0, 1], [1, 0], [-1, 2], [NaN, 1]].map(([a, b]) => [Number.isNaN(a) ? 'nan' : a, b])) await run('betaInc', `bad-${a}-${b}`, W.betaInc, [0.5, a, b]);
for (const q of [0, 0.001, 0.05, 0.25, 0.5, 0.75, 0.95, 0.99, 0.999, 1]) for (const [a, b] of [[1, 9], [2, 9], [1, 10], [5, 20], [0.5, 0.5], [30, 3]]) await run('betaQuantile', `${q}-${a}-${b}`, W.betaQuantile, [q, a, b]);
for (const q of [-0.1, 1.1]) await run('betaQuantile', `bad-${q}`, W.betaQuantile, [q, 1, 1]);
for (const n of [0, 1, 2, 3, 5, 8, 12, 20, 40]) for (let k = 0; k <= n; k += n > 12 ? 3 : 1) for (const d of [0.05, 0.01, 0.2, 0.5, 1e-6])
  await run('clopperPearsonUpper', `${k}-${n}-${d}`, W.clopperPearsonUpper, [k, n, d]);
for (const bad of [[-1, 5, 0.05], [6, 5, 0.05], [1.5, 5, 0.05], [1, 5, 0], [1, 5, 1], [1, 5, 1.5], [0, -1, 0.05]]) await run('clopperPearsonUpper', `bad-${bad}`, W.clopperPearsonUpper, bad);
await run('clopperPearsonUpper', 'big-n', W.clopperPearsonUpper, [3, 100, 0.05]);
for (const p of [-1, 0, 1e-9, 0.001, 0.1, 0.25, 0.5, 0.75, 0.9, 0.999, 1 - 1e-9, 1, 2]) await run('binEnt', `p${p}`, W.binEnt, [p]);
for (let i = 0; i < 300; i++) await run('binEnt', `r${i}`, W.binEnt, [R.next()]);

// ---- canaries -----------------------------------------------------------------------------------------------------------------
const N0 = { falseYes: 0, correctNo: 0, falseNo: 0, correctYes: 0 };
for (const e of [0, 1]) for (const y of [0, 1]) for (const n of [N0, { falseYes: 2, correctNo: 5, falseNo: 1, correctYes: 7 }]) await run('recordCanary', `${e}${y}-${n.falseYes}`, W.recordCanary, [n, e, y]);
await run('recordCanary', 'extra-member', W.recordCanary, [{ ...N0, tag: 'x' }, 0, 1]);
for (const n of [N0, { falseYes: 1, correctNo: 0, falseNo: 0, correctYes: 0 }, { falseYes: 0, correctNo: 20, falseNo: 0, correctYes: 20 }, { falseYes: 3, correctNo: 17, falseNo: 2, correctYes: 11 }, { falseYes: 10, correctNo: 10, falseNo: 10, correctYes: 10 }])
  for (const d of [undefined, 0.05, 0.01, 0.2]) await run('estimateNoise', `${JSON.stringify(n)}-${d}`, W.estimateNoise, d === undefined ? [n] : [n, d]);
for (const d of [0, 1, -1, 2]) await run('estimateNoise', `bad-${d}`, W.estimateNoise, [N0, d]);
await run('cellKey', 'a', W.cellKey, ['stripe.refund', [1, 2, 0, 3]]);
await run('cellKey', 'empty', W.cellKey, ['v', []]);
const CONF1 = [{ verb: 'stripe.refund', idx: [1, 0, 0, 3] }, { verb: 'files.read', idx: [0] }];
await run('boundaryNeighbours', 'a', (om: any, c: any) => W.boundaryNeighbours(om, c), [{ $omega: 'A' }, CONF1]);
await run('boundaryNeighbours', 'unknown-verb', (om: any, c: any) => W.boundaryNeighbours(om, c), [{ $omega: 'A' }, [{ verb: 'nope', idx: [0] }]]);
await run('boundaryNeighbours', 'http', (om: any, c: any) => W.boundaryNeighbours(om, c), [{ $omega: 'A' }, [{ verb: 'http.post', idx: [1, 0] }, { verb: 'http.post', idx: [1, 1] }]]);
await run('boundaryNeighbours', 'empty', (om: any, c: any) => W.boundaryNeighbours(om, c), [{ $omega: 'A' }, []]);
const pick = (ctx: any) => {
  let i = 0;
  return W.pickCanary({
    omega: ctx.omega, confirmed: ctx.confirmed, knownNo: (v: string, idx: number[]) => ctx.knownNo[W.cellKey(v, idx)] ?? null, knownYes: ctx.knownYes, exclude: new Set(ctx.exclude),
    rand: () => { if (i >= ctx.rands.length) throw new Error('rand exhausted'); return ctx.rands[i++]; }, ...(ctx.rho !== undefined ? { rho: ctx.rho } : {}),
    lowHarmSession: ctx.lowHarmSession, canariesSoFar: ctx.canariesSoFar,
  });
};
const KN: Record<string, string> = {};
{
  const vs = vsOf('A', 'stripe.refund');
  void vs;
  for (const k of ['stripe.refund|0,0,0,3', 'stripe.refund|2,0,0,3', 'stripe.refund|1,1,0,3', 'stripe.refund|1,2,0,3', 'files.read|1', 'files.read|2']) KN[k] = k.length % 2 ? 'ceiling' : 'veto';
}
let ci = 0;
for (const rho of [undefined, 0, 0.1, 0.5, 1]) for (const low of [false, true]) for (const used of [0, 1])
  for (const [kl, kn, ky] of [['both', KN, [{ verb: 'stripe.refund', idx: [3, 1, 0, 3] }]], ['no-only', KN, []], ['yes-only', {}, [{ verb: 'files.read', idx: [2] }, { verb: 'stripe.refund', idx: [1, 0, 0, 3] }]], ['none', {}, []]] as [string, any, any[]][])
    for (const rands of [[0.01, 0.2, 0.3], [0.01, 0.9, 0.5], [0.9, 0.1, 0.1], [0.05, 0.7, 0.99], [0.01]])
      await run('pickCanary', `${ci++}-${rho}-${low}-${used}-${kl}`, pick, [{ omega: { $omega: 'A' }, confirmed: CONF1, knownNo: kn, knownYes: ky, exclude: ci % 3 === 0 ? ['files.read|1'] : [], rands, ...(rho !== undefined ? { rho } : {}), lowHarmSession: low, canariesSoFar: used }]);
await run('pickCanary', 'rho-bad', pick, [{ omega: { $omega: 'A' }, confirmed: CONF1, knownNo: KN, knownYes: [], exclude: [], rands: [0.1], rho: 2, lowHarmSession: false, canariesSoFar: 0 }]);

// ---- fatigue -------------------------------------------------------------------------------------------------------------------
for (const base of [0, 0.1, 0.3, 0.5, 0.9]) for (const bf of [0, 0.005, 0.1]) for (const n of [0, 1, 12, 100]) await run('etaUnderLoad', `${base}-${bf}-${n}`, W.etaUnderLoad, [base, bf, n]);
for (const bad of [[-1, 0, 0], [0, -1, 0], [0, 0, -1], [0, 0, 1.5]]) await run('etaUnderLoad', `bad-${bad}`, W.etaUnderLoad, bad);
const COUNTS = [N0, { falseYes: 1, correctNo: 4, falseNo: 0, correctYes: 3 }, { falseYes: 4, correctNo: 4, falseNo: 1, correctYes: 9 }, { falseYes: 0, correctNo: 30, falseNo: 0, correctYes: 30 }];
const MODELS: any[] = [undefined, { ...W.DEFAULT_FATIGUE, freezeOn: 'upper' }, { ...W.DEFAULT_FATIGUE, assumeNoiseFree: true }, { ...W.DEFAULT_FATIGUE, betaF: 0.05, etaStop: 0.3 }, { ...W.DEFAULT_FATIGUE, delta: 0.2 }, { ...W.DEFAULT_FATIGUE, delta: 0 }];
for (const [ci2, c] of COUNTS.entries()) for (const n of [0, 5, 40]) for (const [mi, m] of MODELS.entries()) {
  await run('noiseState', `${ci2}-${n}-${mi}`, W.noiseState, m ? [c, n, m] : [c, n]);
  let st: any = null;
  try { st = W.noiseState(c, n, m); } catch { st = null; }
  if (st) await run('admissionPolicy', `${ci2}-${n}-${mi}`, W.admissionPolicy, m ? [st, m] : [st]);
}
for (const recs of [[], [{ screen: 1, tier: 'typed' }], [{ screen: 1, tier: 'typed' }, { screen: 2, tier: 'device' }], [{ screen: 1, tier: 'typed' }, { screen: 3, tier: 'device' }], [{ screen: 5, tier: 'device' }, { screen: 1, tier: 'typed' }],
  [{ screen: 1, tier: 'tap' }, { screen: 9, tier: 'hold' }], [{ screen: 1, tier: 'typed' }, { screen: 1, tier: 'typed' }], [{ screen: 1, tier: 'typed' }, { screen: 3, tier: 'tap' }, { screen: 4, tier: 'device' }]])
  await run('doubleConfirmed', JSON.stringify(recs), W.doubleConfirmed, [recs]);
const slide = (windowMs: any, ops: any[]) => {
  const c = windowMs === null ? new W.SlidingWindowCounter() : new W.SlidingWindowCounter(windowMs);
  return ops.map((op) => { try { return { v: op[0] === 'count' ? c.count(op[1]) : c.tryAdd(op[1], op[2]) }; } catch { return { err: true }; } });
};
await run('slidingWindow', 'basic', slide, [null, [['tryAdd', 0, 2], ['tryAdd', 1000, 2], ['tryAdd', 2000, 2], ['count', 2000], ['count', 3_600_000], ['tryAdd', 3_600_001, 2], ['count', 3_600_001], ['tryAdd', 7_300_000, 2]]]);
await run('slidingWindow', 'backwards', slide, [1000, [['tryAdd', 500, 5], ['tryAdd', 400, 5], ['count', 400]]]);
await run('slidingWindow', 'window-edge', slide, [1000, [['tryAdd', 0, 5], ['count', 999], ['count', 1000], ['tryAdd', 1000, 5], ['count', 1000]]]);
for (const w of [0, -1, 1.5, 'x']) await run('slidingWindow', `bad-window-${w}`, slide, [w, []]);
await run('slidingWindow', 'cap-zero', slide, [1000, [['tryAdd', 0, 0], ['count', 0]]]);

// ---- risk-priced escalation ---------------------------------------------------------------------------------------------------
const PP = pubOf('wallet/pricing');
const CFG_BODY = { v: 1, principal: PP, currency: 'USD', interruptionCost: 500, maxInterruptionCost: 5000, hardCeilingLoss: 1_000_000, tightenStepPpm: 100_000, epoch: 1 };
const sign = (b: any, k: any) => W.signPricingConfig(b, k);
await run('signPricingConfig', 'base', sign, [CFG_BODY, SEEDL('wallet/pricing')]);
await run('signPricingConfig', 'other-seed', sign, [CFG_BODY, SEEDL('wallet/other')]);
const CFG = sign(CFG_BODY, seed('wallet/pricing'));
await run('pricingConfigError', 'valid', W.pricingConfigError, [CFG]);
for (const [l, v] of variants(CFG, { maxPaths: 40 })) await run('pricingConfigError', l, W.pricingConfigError, [v]);
for (const [i, h] of HOSTILE.entries()) await run('pricingConfigError', `h${i}`, W.pricingConfigError, [h]);
await run('pricingConfigError', 'cost-above-max', W.pricingConfigError, [sign({ ...CFG_BODY, interruptionCost: 6000 }, seed('wallet/pricing'))]);
await run('pricingConfigError', 'step-too-big', W.pricingConfigError, [sign({ ...CFG_BODY, tightenStepPpm: 200_000_000 }, seed('wallet/pricing'))]);
await run('pricingConfigError', 'wrong-signer', W.pricingConfigError, [sign(CFG_BODY, seed('wallet/other'))]);
await run('pricingConfigError', 'extra-member', W.pricingConfigError, [sign({ ...CFG_BODY, note: 'n' }, seed('wallet/pricing'))]);
await run('freshCalibration', 'a', W.freshCalibration, []);
const CAL = { multiplierPpm: 1_000_000, seen: [] };
for (const loss of [0, 1, 999, 1000, 5000, 1_000_000, 1_000_001]) for (const p of [0, 1, 1000, 100_000, 500_000, 1_000_000, 1_000_001]) for (const m of [1_000_000, 2_500_000, 100_000_000, 999_999, 100_000_001])
  await run('decideEscalation', `${loss}-${p}-${m}`, W.decideEscalation, [CFG, { multiplierPpm: m, seen: [] }, { currency: 'USD', loss, pBadUpperPpm: p }]);
await run('decideEscalation', 'currency', W.decideEscalation, [CFG, CAL, { currency: 'EUR', loss: 1, pBadUpperPpm: 1 }]);
await run('decideEscalation', 'null-risk', W.decideEscalation, [CFG, CAL, null]);
await run('decideEscalation', 'null-cal', W.decideEscalation, [CFG, null, { currency: 'USD', loss: 1, pBadUpperPpm: 1 }]);
await run('decideEscalation', 'bad-config', W.decideEscalation, [{ ...CFG, sig: 'x' }, CAL, { currency: 'USD', loss: 1, pBadUpperPpm: 1 }]);
await run('decideEscalation', 'neg-zero-loss', W.decideEscalation, [CFG, CAL, { currency: 'USD', loss: -0, pBadUpperPpm: 1 }]);
await run('decideEscalation', 'fractional', W.decideEscalation, [CFG, CAL, { currency: 'USD', loss: 1.5, pBadUpperPpm: 1 }]);
for (const [l, v] of variants({ currency: 'USD', loss: 5000, pBadUpperPpm: 300_000 }, { maxPaths: 20 })) await run('decideEscalation', `risk-${l}`, W.decideEscalation, [CFG, CAL, v]);
const AB1 = { v: 1, principal: PP, nonce: 'nonce-0001', action_digest: dig('act1'), answer: 'deny' };
const sAns = (b: any, l = 'wallet/pricing') => W.signAnswer(b, seed(l));
await run('signAnswer', 'deny', (b: any, k: any) => W.signAnswer(b, k), [AB1, SEEDL('wallet/pricing')]);
await run('signAnswer', 'approve', (b: any, k: any) => W.signAnswer(b, k), [{ ...AB1, answer: 'approve' }, SEEDL('wallet/pricing')]);
const RISKS = { [dig('act1')]: { currency: 'USD', loss: 5000, pBadUpperPpm: 10_000 }, [dig('act2')]: { currency: 'USD', loss: 100_000, pBadUpperPpm: 900_000 }, [dig('act3')]: null };
const upd = (c: any, cal: any, ans: any, risks: any) => W.updateCalibration(c, cal, ans, new Map(Object.entries(risks)));
const A1 = sAns(AB1), A2 = sAns({ ...AB1, nonce: 'nonce-0002', action_digest: dig('act2') }), A3 = sAns({ ...AB1, nonce: 'nonce-0003', action_digest: dig('act3') });
const A4 = sAns({ ...AB1, nonce: 'nonce-0004', answer: 'approve' }), A5 = sAns({ ...AB1, nonce: 'short' }), A6 = sAns({ ...AB1, nonce: 'nonce-0006', action_digest: dig('unknown') });
const A7 = sAns({ ...AB1, nonce: 'nonce-0007' }, 'wallet/other');
for (const [l, ans] of [['one', [A1]], ['replay', [A1, A1]], ['mixed', [A1, A2, A3, A4, A5, A6, A7]], ['forged', [A7]], ['approve-only', [A4]], ['none', []], ['garbage', [null, 5, 'x', { v: 1 }]], ['two-misses', [A1, sAns({ ...AB1, nonce: 'nonce-0008' })]]] as [string, any[]][])
  for (const cal of [CAL, { multiplierPpm: 5_000_000, seen: ['nonce-0001'] }, { multiplierPpm: 99_950_000, seen: [] }])
    await run('updateCalibration', `${l}-${cal.multiplierPpm}`, upd, [CFG, cal, ans, RISKS]);
await run('updateCalibration', 'bad-config', upd, [{ ...CFG, sig: 'x' }, CAL, [A1], RISKS]);
const RB = { v: 1, principal: PP, epoch: 2, newInterruptionCost: 1000 };
await run('signAutonomyRaise', 'a', (b: any, k: any) => W.signAutonomyRaise(b, k), [RB, SEEDL('wallet/pricing')]);
const raise = (c: any, r: any, k: any) => W.applyAutonomyRaise(c, r, k);
const R1 = W.signAutonomyRaise(RB, seed('wallet/pricing'));
await run('applyAutonomyRaise', 'ok', raise, [CFG, R1, SEEDL('wallet/pricing')]);
for (const [l, r] of [['epoch-same', W.signAutonomyRaise({ ...RB, epoch: 1 }, seed('wallet/pricing'))], ['above-max', W.signAutonomyRaise({ ...RB, newInterruptionCost: 5001 }, seed('wallet/pricing'))],
  ['at-max', W.signAutonomyRaise({ ...RB, newInterruptionCost: 5000 }, seed('wallet/pricing'))], ['wrong-signer', W.signAutonomyRaise(RB, seed('wallet/other'))], ['other-principal', W.signAutonomyRaise({ ...RB, principal: pubOf('wallet/other') }, seed('wallet/other'))],
  ['bad-version', W.signAutonomyRaise({ ...RB, v: 2 }, seed('wallet/pricing'))], ['negative', W.signAutonomyRaise({ ...RB, newInterruptionCost: -1 }, seed('wallet/pricing'))]] as [string, any][])
  await run('applyAutonomyRaise', l, raise, [CFG, r, SEEDL('wallet/pricing')]);
for (const [l, v] of variants(R1, { maxPaths: 30 })) await run('applyAutonomyRaise', l, raise, [CFG, v, SEEDL('wallet/pricing')]);

// ---- the outcome space (the private port) -----------------------------------------------------------------------------
const dimOf = (id: string, verb: string, k: number) => vsOf(id, verb).dims[k];
for (const id of ['A', 'B']) for (const vs of OM[id].verbs) {
  await run('omega.verbCellCount', `${id}-${vs.verb}`, (i: string, v: string) => I.verbCellCount(vsOf(i, v)), [id, vs.verb]);
  for (const [k, d] of vs.dims.entries()) {
    await run('omega.cellCount', `${id}-${vs.verb}-${k}`, (i: string, v: string, kk: number) => I.cellCount(dimOf(i, v, kk)), [id, vs.verb, k]);
    if (d.kind === 'num') await run('omega.numCells', `${id}-${vs.verb}-${k}`, (i: string, v: string, kk: number) => I.numCells(dimOf(i, v, kk)), [id, vs.verb, k]);
    await run('omega.labelOf', `${id}-${vs.verb}-${k}`, I.labelOf, [d.path]);
  }
  const total = I.verbCellCount(vs);
  for (const flat of [0, 1, Math.floor(total / 2), total - 1, total]) {
    await run('omega.decodeCell', `${id}-${vs.verb}-${flat}`, (i: string, v: string, f: number) => I.decodeCell(vsOf(i, v), f), [id, vs.verb, flat]);
  }
  for (let flat = 0; flat < Math.min(total, 120); flat++) {
    const idx = I.decodeCell(vs, flat);
    await run('omega.cellStats', `${id}-${vs.verb}-${flat}`, (i: string, v: string, ix: number[]) => I.cellStats(vsOf(i, v), ix), [id, vs.verb, idx]);
    await run('omega.cellRep', `${id}-${vs.verb}-${flat}`, (i: string, v: string, ix: number[]) => I.cellRep(vsOf(i, v), ix), [id, vs.verb, idx]);
    await run('omega.cellOf', `${id}-${vs.verb}-${flat}`, (i: string, v: string, oc: any) => I.cellOf(vsOf(i, v), oc), [id, vs.verb, I.cellRep(vs, idx)]);
  }
}
for (const [oi, oc] of [{ verb: 'stripe.refund', values: { 'action.params.amount': 100, 'action.resource': 'charge:zzz', 'env.acc.spend.post': 2000, 'env.prov.recipient': 'web' } },
  { verb: 'stripe.refund', values: { 'action.params.amount': -1, 'action.resource': 'charge:ch_1', 'env.acc.spend.post': 2000, 'env.prov.recipient': 'agent' } },
  { verb: 'stripe.refund', values: { 'action.params.amount': 1.5, 'action.resource': 'charge:ch_1', 'env.acc.spend.post': 0, 'env.prov.recipient': 'agent' } },
  { verb: 'stripe.refund', values: { 'action.params.amount': '5', 'action.resource': 'charge:ch_1', 'env.acc.spend.post': 0, 'env.prov.recipient': 'agent' } },
  { verb: 'stripe.refund', values: { 'action.params.amount': 100001, 'action.resource': 'charge:ch_1', 'env.acc.spend.post': 0, 'env.prov.recipient': 'agent' } },
  { verb: 'stripe.refund', values: { 'action.params.amount': 5, 'action.resource': 7, 'env.acc.spend.post': 0, 'env.prov.recipient': 'agent' } },
  { verb: 'files.read', values: { 'action.resource': 'file:zz' } }, { verb: 'files.read', values: { 'action.resource': 'other' } }, { verb: 'files.read', values: {} }].entries())
  await run('omega.cellOf', `outcome-${oi}`, (i: string, v: string, x: any) => I.cellOf(vsOf(i, v), x), ['A', oc.verb, oc]);
await run('omega.cellStats', 'B-long-cells', (i: string, v: string, ix: number[]) => I.cellStats(vsOf(i, v), ix), ['B', 'ledger.post', [2, 1]]);
await run('omega.cellStats', 'B-long-cells-last', (i: string, v: string, ix: number[]) => I.cellStats(vsOf(i, v), ix), ['B', 'ledger.post', [3, 0]]);
await run('omega.cellStats', 'B-first', (i: string, v: string, ix: number[]) => I.cellStats(vsOf(i, v), ix), ['B', 'ledger.post', [0, 2]]);

// ---- cell coordinates -----------------------------------------------------------------------------------------------------
for (const p of ['action.params.amount', 'env.acc.spend.post', 'env.acc.a.b-c_d.post', 'env.acc.post', 'env.mon.fraud.state', 'env.prov.recipient', 'env.prov.a.b', 'env.prov.', 'env.world.region', 'env.world.', 'env.world.a b', 'action.resource', '', 'env.acc.x.post.extra'])
  await run('coordKeyOf', p, W.coordKeyOf, [p]);
const resolve = (om: any, verb: any, coords: any) => { const r = W.resolveCoords(om, verb, coords); return r.ok ? { ok: true, verb: r.vs.verb, box: r.box } : r; };
const RC_OK = { 'action.params.amount': [0, 2], 'action.resource': ['charge:ch_1', 'charge:ch_2'], 'spend': [0, 1], 'prov:recipient': ['trusted'] };
const RC_FULL = { 'action.params.amount': [0, 2], 'action.resource': ['charge:ch_1'], 'env.acc.spend.post': [2, 2], 'env.prov.recipient': ['trusted', 'agent'] };
await run('resolveCoords', 'ok-alias', resolve, [{ $omega: 'A' }, 'stripe.refund', RC_OK]);
await run('resolveCoords', 'ok-full', resolve, [{ $omega: 'A' }, 'stripe.refund', RC_FULL]);
await run('resolveCoords', 'unknown-verb', resolve, [{ $omega: 'A' }, 'nope', RC_OK]);
await run('resolveCoords', 'dup-dim', resolve, [{ $omega: 'A' }, 'stripe.refund', { ...RC_FULL, spend: [0, 1] }]);
await run('resolveCoords', 'dup-value-set', resolve, [{ $omega: 'A' }, 'stripe.refund', { ...RC_FULL, 'action.resource': ['charge:ch_1', 'charge:ch_1'] }]);
await run('resolveCoords', 'unknown-value', resolve, [{ $omega: 'A' }, 'stripe.refund', { ...RC_FULL, 'action.resource': ['nope'] }]);
await run('resolveCoords', 'unknown-value-quote', resolve, [{ $omega: 'A' }, 'stripe.refund', { ...RC_FULL, 'action.resource': ['a"b\n\u0001\ud800'] }]);
await run('resolveCoords', 'other-value', resolve, [{ $omega: 'A' }, 'stripe.refund', { ...RC_FULL, 'action.resource': [OTHER] }]);
await run('resolveCoords', 'prefix-value', resolve, [{ $omega: 'A' }, 'stripe.refund', { ...RC_FULL, 'action.resource': ['charge:'] }]);
await run('resolveCoords', 'missing-dim', resolve, [{ $omega: 'A' }, 'stripe.refund', { 'action.params.amount': [0, 2] }]);
await run('resolveCoords', 'unknown-dim', resolve, [{ $omega: 'A' }, 'stripe.refund', { ...RC_FULL, 'action.params.bogus': [0, 1] }]);
await run('resolveCoords', 'range-out', resolve, [{ $omega: 'A' }, 'stripe.refund', { ...RC_FULL, 'action.params.amount': [0, 7] }]);
await run('resolveCoords', 'range-reversed', resolve, [{ $omega: 'A' }, 'stripe.refund', { ...RC_FULL, 'action.params.amount': [3, 2] }]);
await run('resolveCoords', 'range-neg', resolve, [{ $omega: 'A' }, 'stripe.refund', { ...RC_FULL, 'action.params.amount': [-1, 2] }]);
await run('resolveCoords', 'range-frac', resolve, [{ $omega: 'A' }, 'stripe.refund', { ...RC_FULL, 'action.params.amount': [0, 1.5] }]);
await run('resolveCoords', 'range-negzero', resolve, [{ $omega: 'A' }, 'stripe.refund', { ...RC_FULL, 'action.params.amount': [-0, 1] }]);
await run('resolveCoords', 'range-as-set', resolve, [{ $omega: 'A' }, 'stripe.refund', { ...RC_FULL, 'action.params.amount': ['a', 'b'] }]);
await run('resolveCoords', 'set-as-range', resolve, [{ $omega: 'A' }, 'stripe.refund', { ...RC_FULL, 'action.resource': [0, 1] }]);
await run('resolveCoords', 'range-3', resolve, [{ $omega: 'A' }, 'stripe.refund', { ...RC_FULL, 'action.params.amount': [0, 1, 2] }]);
await run('resolveCoords', 'files', resolve, [{ $omega: 'A' }, 'files.read', { 'action.resource': ['file:b', 'file:a'] }]);
await run('resolveCoords', 'http', resolve, [{ $omega: 'A' }, 'http.post', { 'action.params.count': [1, 2], region: ['us'] }]);
await run('resolveCoords', 'null-dim', resolve, [{ $omega: 'A' }, 'files.read', { 'action.resource': null }]);
await run('resolveCoords', 'null-then-alias', resolve, [{ $omega: 'A' }, 'http.post', { 'action.params.count': [0, 0], 'env.world.region': null, region: ['eu'] }]);
for (const [l, v] of variants(RC_FULL, { maxPaths: 30 })) await run('resolveCoords', l, resolve, [{ $omega: 'A' }, 'stripe.refund', v]);
const BOX = [[0, 1, 2], [0, 1], [2], [0, 3]];
await run('coordsOfBox', 'ok', (i: string, v: string, b: any) => W.coordsOfBox(vsOf(i, v), b), ['A', 'stripe.refund', [[0, 1, 2], [0, 1], [2], [0, 3]]]);
await run('coordsOfBox', 'gap', (i: string, v: string, b: any) => W.coordsOfBox(vsOf(i, v), b), ['A', 'stripe.refund', [[0, 2], [0], [2], [0]]]);
await run('coordsOfBox', 'single', (i: string, v: string, b: any) => W.coordsOfBox(vsOf(i, v), b), ['A', 'files.read', [[3, 1]]]);
for (const idx of [[0, 0, 0, 0], [6, 3, 2, 4], [1, 2, 1, 1]]) await run('coordsOfCell', `${idx}`, (i: string, v: string, x: any) => W.coordsOfCell(vsOf(i, v), x), ['A', 'stripe.refund', idx]);
for (const idx of [[0, 1, 2, 0], [0, 1, 2, 1], [3, 1, 2, 0], [0, 1, 2], [0, 1, 2, 0, 1], []]) await run('cellInBox', `${idx}`, W.cellInBox, [BOX, idx]);
await run('boxCells', 'a', W.boxCells, [[[0, 1], [2], [3, 4]]]);
await run('boxCells', 'empty', W.boxCells, [[]]);
await run('boxCells', 'empty-dim', W.boxCells, [[[0], []]]);
await run('boxSize', 'a', W.boxSize, [BOX]);
await run('boxSize', 'empty', W.boxSize, [[]]);
const ofAct = (id: string, a: any) => { const r = W.cellOfAction(OM[id], a); return r ? { verb: r.vs.verb, idx: r.idx } : null; };
const AV = { verb: 'stripe.refund', values: { 'action.params.amount': 500, 'action.resource': 'charge:ch_1', 'env.acc.spend.post': 1000, 'env.prov.recipient': 'trusted' } };
await run('cellOfAction', 'ok', ofAct, ['A', AV]);
await run('cellOfAction', 'unknown-verb', ofAct, ['A', { ...AV, verb: 'nope' }]);
await run('cellOfAction', 'missing-dim', ofAct, ['A', { verb: 'stripe.refund', values: { 'action.params.amount': 500 } }]);
await run('cellOfAction', 'outside', ofAct, ['A', { ...AV, values: { ...AV.values, 'action.params.amount': 200000 } }]);
await run('cellOfAction', 'null-value', ofAct, ['A', { ...AV, values: { ...AV.values, 'action.resource': null } }]);
await run('cellOfAction', 'extra-value', ofAct, ['A', { ...AV, values: { ...AV.values, 'x.y': 1 } }]);
for (const [l, v] of variants(AV, { maxPaths: 30 })) await run('cellOfAction', l, ofAct, ['A', v]);
for (const idx of [[0, 0, 0, 0], [6, 3, 2, 4], [1, 2, 1, 1]]) await run('flatIndex', `${idx}`, (i: string, v: string, x: any) => W.flatIndex(vsOf(i, v), x), ['A', 'stripe.refund', idx]);

// ---- the card ---------------------------------------------------------------------------------------------------------------------
for (const [si, s] of ['plain', '  spaced   out  ', 'tab\tand\nnewline', 'ctrl\u0001\u007f\u0085x', 'zw​sp‏', 'bidi‮⁦x', 'nbsp x', 'lsep x', '﻿trimmed﻿', '　x　', '', '   ', 'é'.repeat(70), 'x'.repeat(64), 'x'.repeat(65), 'ab😀cd'.repeat(30)].entries())
  for (const max of [8, 64, 280]) await run('cleanText', `s${si}-${max}`, W.cleanText, [s, max]);
for (const s of ['ch_ABCDEF123', 'abc', 'ab-cd', '', 'x'.repeat(10), 'éé12', 'a1b2c3d4e5']) await run('last4', s, W.last4, [s]);
const MONEY = { kind: 'money', currency: 'USD', exponent: 2 };
for (const x of [0, 5, 99, 100, 12345, 1234567, 123456789, -5, -12345, 1e9, 2 ** 53 - 1, 1.9, -1.9])
  for (const u of [undefined, MONEY, { kind: 'money', currency: 'JPY', exponent: 0 }, { kind: 'money', currency: 'EUR', exponent: 3 }, { kind: 'money', currency: 'XYZ', exponent: 9 }, { kind: 'money', currency: 'GBP', exponent: -2 }, { kind: 'count' }])
    await run('formatNumber', `${x}-${JSON.stringify(u)}`, W.formatNumber, u === undefined ? [x] : [x, u]);
const CARD_IN = {
  omegaId: 'A', verb: 'stripe.refund', coords: RC_FULL, site: { origin: 'https://shop.example.com', name: 'Example Shop' }, statementText: 'refund my last order',
  units: { 'action.params.amount': MONEY }, action: AV, friction: 'typed', kind: 'question',
};
const rcard = (x: any) => { const { omegaId, ...rest } = x; return W.renderCard({ omega: OM[omegaId], ...rest }); };
const filterVar = (l: string) => !/^\/(verb|coords|action|units|site|reversibility|omegaId) = hostile#/.test(l);
await run('renderCard', 'base', rcard, [CARD_IN]);
for (const friction of ['tap', 'hold', 'typed', 'device'])
  for (const [vname, extra] of [
    ['refund', {}],
    ['clar', { kind: 'clarification', reason: 'price_changed' }],
    ['clar-noreason', { kind: 'clarification' }],
    ['no-action', { action: undefined }],
    ['no-statement', { statementText: undefined }],
    ['coords-prov', { coords: { ...RC_FULL, 'env.prov.recipient': ['tool|web', 'agent'] } }],
    ['coords-web', { coords: { ...RC_FULL, 'env.prov.recipient': ['tool|web'] } }],
    ['coords-first', { coords: { ...RC_FULL, 'env.prov.recipient': ['first_party'] } }],
    ['coords-any', { coords: { ...RC_FULL, 'action.params.amount': [0, 6], 'env.acc.spend.post': [0, 2] } }],
    ['coords-up-to', { coords: { ...RC_FULL, 'action.params.amount': [0, 3] } }],
    ['coords-or-more', { coords: { ...RC_FULL, 'action.params.amount': [3, 6] } }],
    ['coords-exact', { coords: { ...RC_FULL, 'action.params.amount': [1, 1] } }],
    ['coords-cat3', { coords: { ...RC_FULL, 'action.resource': ['charge:ch_1', 'charge:ch_2', 'charge:'] } }],
    ['coords-cat-other', { coords: { ...RC_FULL, 'action.resource': [OTHER] } }],
    ['action-other-resource', { action: { ...AV, values: { ...AV.values, 'action.resource': 'charge:ch_999' } } }],
    ['action-wrong-verb', { action: { ...AV, verb: 'files.read' } }],
    ['action-string-number', { action: { ...AV, values: { ...AV.values, 'action.params.amount': 'x' } } }],
    ['no-units', { units: undefined }],
    ['count-unit', { units: { 'action.params.amount': { kind: 'count' } } }],
    ['reversible', { reversibility: 'reversible' }], ['rate-limited', { reversibility: 'rate_limited' }], ['bogus-rev', { reversibility: 'bogus' }],
    ['locale-fr', { locale: 'fr' }], ['locale-en', { locale: 'en' }], ['bad-reason', { kind: 'clarification', reason: 'free text' }],
    ['messy-site', { site: { origin: 'https://x.example\u0001', name: '  Evil‮  Shop \n ' + 'z'.repeat(80) } }],
    ['empty-site-name', { site: { origin: 'https://o.example', name: '   ' } }],
    ['long-statement', { statementText: 'w '.repeat(200) }],
  ] as [string, any][])
    await run('renderCard', `${friction}-${vname}`, rcard, [{ ...CARD_IN, friction, ...extra }]);
for (const [vname, input] of [
  ['files', { omegaId: 'A', verb: 'files.read', coords: { 'action.resource': ['file:a', 'file:b'] }, site: CARD_IN.site, friction: 'tap', kind: 'question', action: { verb: 'files.read', values: { 'action.resource': 'file:a' } } }],
  ['files-typed-last4', { omegaId: 'A', verb: 'files.read', coords: { 'action.resource': ['file:a'] }, site: CARD_IN.site, friction: 'typed', kind: 'question', action: { verb: 'files.read', values: { 'action.resource': 'file:a1b2' } } }],
  ['files-typed-no-last4', { omegaId: 'A', verb: 'files.read', coords: { 'action.resource': ['file:a'] }, site: CARD_IN.site, friction: 'typed', kind: 'question', action: { verb: 'files.read', values: { 'action.resource': 'a' } } }],
  ['http', { omegaId: 'A', verb: 'http.post', coords: { 'action.params.count': [0, 3], region: ['eu', 'us'] }, site: CARD_IN.site, friction: 'hold', kind: 'question' }],
  ['ledger', { omegaId: 'B', verb: 'ledger.post', coords: { 'action.params.amount': [1, 2], 'action.params.account': ['acct_main'] }, site: CARD_IN.site, friction: 'typed', kind: 'question', action: { verb: 'ledger.post', values: { 'action.params.amount': 5000, 'action.params.account': 'acct_main' } } }],
  ['unknown-verb', { omegaId: 'A', verb: 'nope', coords: {}, site: CARD_IN.site, friction: 'tap', kind: 'question' }],
] as [string, any][]) await run('renderCard', vname, rcard, [input]);
for (const [l, v] of variants(CARD_IN, { maxPaths: 26 })) if (filterVar(l)) await run('renderCard', `var-${l}`, rcard, [v]);
const okCard = (extra: any = {}) => W.renderCard({ omega: OM.A, ...CARD_IN, omegaId: undefined, ...extra }).card;
const CARDS: Record<string, any> = { typed: okCard(), tap: okCard({ friction: 'tap' }), clar: okCard({ kind: 'clarification', reason: 'multiple_options', friction: 'hold' }), files: okCard({ verb: 'files.read', coords: { 'action.resource': ['file:a', 'file:b'] }, action: { verb: 'files.read', values: { 'action.resource': 'file:a' } }, units: undefined, friction: 'tap' }) };
for (const [l, c] of Object.entries(CARDS)) {
  await run('cardDigestMatches', l, W.cardDigestMatches, [c]);
  await run('cardText', l, W.cardText, [c]);
  const { rendered_digest, ...body } = c;
  await run('cardDigest', l, W.cardDigest, [body]);
  void rendered_digest;
}
await run('cardDigestMatches', 'tampered', W.cardDigestMatches, [{ ...CARDS.typed, header: 'other' }]);
await run('cardDigestMatches', 'tampered-digest', W.cardDigestMatches, [{ ...CARDS.typed, rendered_digest: dig('x') }]);
for (const [l, v] of variants(CARDS.tap, { maxPaths: 12 })) await run('cardDigestMatches', l, W.cardDigestMatches, [v]);
const PS: any[] = [
  { path: 'action.params.amount', upTo: 0 }, { path: 'action.params.amount', upTo: 6 }, { path: 'action.params.amount', upTo: 5 }, { path: 'action.params.amount', upTo: 5.5 }, { path: 'action.params.amount', upTo: -0 }, { path: 'action.params.amount', upTo: 7 },
  { path: 'action.params.amount', from: 0 }, { path: 'action.params.amount', from: 1 }, { path: 'action.params.amount', from: 6 }, { path: 'action.params.amount', from: 7 },
  { path: 'action.params.amount', except: [1] }, { path: 'action.params.amount', except: [1, 9] }, { path: 'action.params.amount', except: [] },
  { path: 'action.params.amount', notFor: ['x'] }, { path: 'action.params.amount' }, { path: 'nope', upTo: 1 },
  { path: 'action.resource', notFor: ['charge:ch_1'] }, { path: 'action.resource', notFor: ['charge:ch_1', 'charge:ch_1'] }, { path: 'action.resource', notFor: ['charge:ch_1', 'charge:ch_2'] }, { path: 'action.resource', notFor: ['zzz'] }, { path: 'action.resource', notFor: [] }, { path: 'action.resource', upTo: 1 },
];
const WIDE = okCard({ coords: { ...RC_FULL, 'action.params.amount': [0, 6], 'action.resource': ['charge:ch_1', 'charge:ch_2'] } });
await run('renderCard', 'wide', rcard, [{ ...CARD_IN, coords: { ...RC_FULL, 'action.params.amount': [0, 6], 'action.resource': ['charge:ch_1', 'charge:ch_2'] } }]);
for (const [i, p] of PS.entries()) await run('partialError', `p${i}`, W.partialError, [WIDE, p]);
for (const t of ['500', '5,000', '$1,234.50', 'USD 12.5', 'usd12.50', '1.234', '-0', '-5', '-0.00', '0012', '12.', '.5', 'abc', '', ' 7 ', '€9', '12.345', '1 000', '1e3'])
  for (const [mode, u] of [['number', undefined], ['number', MONEY], ['number', { kind: 'money', currency: 'JPY', exponent: 0 }], ['last4', undefined]] as [string, any][])
    await run('normalizeTyped', `${JSON.stringify(t)}-${mode}-${u?.exponent}`, W.normalizeTyped, u === undefined ? [t, mode] : [t, mode, u]);
await run('normalizeTyped', 'last4-ok', W.normalizeTyped, ['ab-12', 'last4']);
await run('normalizeTyped', 'last4-long', W.normalizeTyped, ['abcde', 'last4']);
for (const [l, a] of [['ok', AV], ['float', { ...AV, values: { ...AV.values, 'action.params.amount': 1.5 } }], ['negzero', { ...AV, values: { ...AV.values, 'action.params.amount': -0 } }], ['string', { ...AV, values: { ...AV.values, 'action.params.amount': '500' } }],
  ['absent', { verb: 'stripe.refund', values: {} }], ['big', { ...AV, values: { ...AV.values, 'action.params.amount': 2 ** 53 } }]] as [string, any][])
  await run('expectedTyped', l, W.expectedTyped, [CARDS.typed, a]);
await run('expectedTyped', 'no-typed', W.expectedTyped, [CARDS.tap, AV]);
const L4 = W.renderCard({ omega: OM.A, verb: 'files.read', coords: { 'action.resource': ['file:a'] }, site: CARD_IN.site, friction: 'typed', kind: 'question', action: { verb: 'files.read', values: { 'action.resource': 'file:a1b2' } } }).card;
await run('expectedTyped', 'last4', W.expectedTyped, [L4, { verb: 'files.read', values: { 'action.resource': 'file:a1b2' } }]);
await run('expectedTyped', 'last4-short', W.expectedTyped, [L4, { verb: 'files.read', values: { 'action.resource': 'a' } }]);
await run('expectedTyped', 'last4-number', W.expectedTyped, [L4, { verb: 'files.read', values: { 'action.resource': 5 } }]);

// ---- clarification ----------------------------------------------------------------------------------------------------------------
const CLAR = { reason: 'multiple_options', candidates: [{ verb: 'stripe.refund', values: { 'action.params.amount': 500, 'action.resource': 'charge:ch_1' } }, { verb: 'files.read', values: { 'action.resource': 'file:a' } }] };
await run('parseClarifyRequest', 'ok', W.parseClarifyRequest, [CLAR]);
for (const [l, v] of variants(CLAR, { maxPaths: 60 })) await run('parseClarifyRequest', l, W.parseClarifyRequest, [v]);
for (const [i, h] of HOSTILE.entries()) await run('parseClarifyRequest', `h${i}`, W.parseClarifyRequest, [h]);
await run('parseClarifyRequest', 'nine', W.parseClarifyRequest, [{ ...CLAR, candidates: Array.from({ length: 9 }, () => CLAR.candidates[0]) }]);
await run('parseClarifyRequest', 'eight', W.parseClarifyRequest, [{ ...CLAR, candidates: Array.from({ length: 8 }, () => CLAR.candidates[0]) }]);
for (const [p, v] of [['action.params.amount', 1.5], ['action.params.amount', -0], ['action.params.amount', 2 ** 53], ['action.params.x', 'y'.repeat(256)], ['action.params.x', 'y'.repeat(257)], ['env.hour', 3], ['1bad', 1], ['a..b', 1], ['action.params.', 1], ['action.params.Ok_9', 1], ['action.resource', null], ['action.resource', true], ['action.resource', 'é']] as [string, any][])
  await run('parseClarifyRequest', `value-${p}-${String(v).length}-${String(v).slice(0, 12)}`, W.parseClarifyRequest, [{ reason: 'other', candidates: [{ verb: 'files.read', values: { [p]: v } }] }]);
await run('parseClarifyRequest', 'verb-129', W.parseClarifyRequest, [{ reason: 'other', candidates: [{ verb: 'v'.repeat(129), values: {} }] }]);
await run('parseClarifyRequest', 'values-65', W.parseClarifyRequest, [{ reason: 'other', candidates: [{ verb: 'v', values: Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`action.params.p${i}`, i])) }] }]);
for (const p of [0, 0.01, 0.25, 0.5, 0.9, 0.99, 1])
  for (const [ep, en] of [[0, 0], [0.1, 0.1], [0.05, 0.2], [0.49, 0.49], [0.3, 0]]) await run('informationGain', `${p}-${ep}-${en}`, W.informationGain, [p, ep, en]);
const plan = (x: any) => {
  const view = { p: (v: string, i: number[]) => x.view.p[W.cellKey(v, i)] ?? 0, vetoed: (v: string, i: number[]) => x.view.vetoed.includes(W.cellKey(v, i)), outsideCeiling: (v: string, i: number[]) => x.view.ceiling.includes(W.cellKey(v, i)) };
  return W.planClarification({ omega: x.omega, view, candidates: x.candidates, asked: new Set(x.asked), etaPos: x.etaPos, etaNeg: x.etaNeg, harm: I.DEFAULT_HARM });
};
const C = (verb: string, values: any) => ({ verb, values });
const RC = (amount: number, res = 'charge:ch_1') => C('stripe.refund', { 'action.params.amount': amount, 'action.resource': res, 'env.acc.spend.post': 0, 'env.prov.recipient': 'agent' });
const cellK = (c: any) => { const at = W.cellOfAction(OM.A, c); return W.cellKey(at.vs.verb, at.idx); };
const cands = [RC(50), RC(500), RC(5000), RC(50000), RC(500, 'charge:ch_2'), C('files.read', { 'action.resource': 'file:a' }), C('nope', {}), C('files.read', { 'action.resource': 'file:zzz' }), C('files.read', {})];
const ks = cands.map((c) => { try { return cellK(c); } catch { return null; } });
let pi = 0;
for (const [pl, pv] of [['mixed', ks.map((k, i) => [k, [0.5, 0.3, 0.9, 1, 0.5, 0, 0, 0.2, 0.5][i]])], ['all-half', ks.map((k) => [k, 0.5])], ['skewed', ks.map((k, i) => [k, 0.05 + 0.1 * i])], ['none', []]] as [string, any[]][])
  for (const [en, ep] of [[0, 0], [0.1, 0.1], [0.2, 0.05]]) for (const sel of [cands, cands.slice(0, 5), cands.slice(1, 2), [cands[1], cands[1]], [cands[2], cands[3]]])
    for (const extra of [{}, { vetoed: [ks[1]] }, { ceiling: [ks[2]] }, { asked: [ks[1]] }, { asked: ks.filter((k) => k) }]) {
      const view = { p: Object.fromEntries(pv.filter(([k]: any) => k)), vetoed: [], ceiling: [], ...extra };
      const asked = (extra as any).asked ?? [];
      const { asked: _a, ...viewExtra } = extra as any;
      void _a;
      await run('planClarification', `${pl}-${en}-${ep}-${pi++}`, plan, [{ omega: { $omega: 'A' }, view: { ...view, ...viewExtra }, candidates: sel, asked, etaPos: ep, etaNeg: en }]);
    }


// ---- population priors ----------------------------------------------------------------------------------------------------------------
const SCHEMA = dig('schema');
const seq = (xs: number[]) => { let i = 0; return () => { if (i >= xs.length) throw new Error('rand exhausted'); return xs[i++]!; }; };
for (const e of [0.1, 0.5, 0.9, 0.99, 1, 0, -1, 2]) for (const d of [1e-5, 1e-3, 0.5, 0, 1]) for (const s2 of [1, 2.5, 8, 0])
  await run('gaussianSigma', `${e}-${d}-${s2}`, W.gaussianSigma, [e, d, s2]);
for (const rs of [[0.5, 0.25], [0.001, 0.9], [0, 0.5, 0.5], [0, 0, 0.1, 0.7], [1, 0], [0.9999999, 0.9999999], [0.3]]) await run('gaussian', JSON.stringify(rs), (xs: number[]) => W.gaussian(seq(xs)), [rs]);
for (const e of [0.01, 0.5, 1, 2, 5, 20, 0, -1, 'inf']) await run('rrKeepProbability', `e${e}`, W.rrKeepProbability, [e === 'inf' ? 'x' : e]);
for (const y of [0, 1]) for (const e of [0.5, 2]) for (const r of [0, 0.5, 0.62, 0.63, 0.9, 0.999]) await run('randomizedResponse', `${y}-${e}-${r}`, (yy: number, ee: number, rr: number) => W.randomizedResponse(yy, ee, () => rr), [y, e, r]);
for (const [yes, total, e] of [[0, 10, 1], [5, 10, 1], [10, 10, 1], [7, 10, 0.5], [3, 3, 2], [0, 0, 1], [11, 10, 1], [-1, 10, 1], [1.5, 10, 1], [1, 10, 0], [4, 10, 5]]) await run('debiasRandomizedResponse', `${yes}-${total}-${e}`, W.debiasRandomizedResponse, [yes, total, e]);
const vsR = vsOf('A', 'stripe.refund');
for (const idx of [[0, 0, 0, 0], [2, 0, 1, 3], [6, 3, 2, 4]]) await run('populationCellKey', `${idx}`, (sch: string, i: string, v: string, ix: number[]) => W.populationCellKey(sch, vsOf(i, v), ix), [SCHEMA, 'A', 'stripe.refund', idx]);
await run('populationCellKey', 'files', (sch: string, i: string, v: string, ix: number[]) => W.populationCellKey(sch, vsOf(i, v), ix), [SCHEMA, 'A', 'files.read', [1]]);
const cellK2 = (verbName: string, idx: number[]) => W.populationCellKey(SCHEMA, vsOf('A', verbName), idx);
const vote = (principal: string, key: string, y: number, over: any = {}) => ({ principal, schemaDigest: SCHEMA, cellKey: key, y, period: 7, ...over });
const K1 = cellK2('files.read', [0]), K2 = cellK2('files.read', [1]), K3 = cellK2('files.read', [2]);
const agg = (schema: string, period: number, opts: any, votes: any[], rel: any, rands: number[]) => {
  const a = new W.PopulationAggregator(schema, period, { ...(opts.maxCellsPerPrincipal !== undefined ? { maxCellsPerPrincipal: opts.maxCellsPerPrincipal } : {}), rand: seq(rands) });
  const vr = votes.map((v) => a.contribute(v));
  let release: any;
  try { release = a.release(rel); } catch { release = { err: true }; }
  return { votes: vr, release };
};
const manyVotes: any[] = [];
for (let i = 0; i < 40; i++) manyVotes.push(vote(`p${i}`, K1, i % 3 === 0 ? 0 : 1), vote(`p${i}`, K2, i % 2), vote(`p${i}`, K3, 1));
const gr = rng(0x90b0);
const noiseSeq = Array.from({ length: 12 }, () => gr.next());
await run('aggregate', 'basic', agg, [SCHEMA, 7, {}, manyVotes, { epsilon: 0.9, delta: 1e-5 }, noiseSeq]);
await run('aggregate', 'high-min-count', agg, [SCHEMA, 7, {}, manyVotes, { epsilon: 0.9, delta: 1e-5, minCount: 5, qMin: 0.1 }, noiseSeq]);
await run('aggregate', 'low-eps', agg, [SCHEMA, 7, {}, manyVotes, { epsilon: 0.1, delta: 1e-6 }, noiseSeq]);
await run('aggregate', 'rand-exhausted', agg, [SCHEMA, 7, {}, manyVotes, { epsilon: 0.9, delta: 1e-5 }, [0.5, 0.5, 0.5]]);
await run('aggregate', 'bad-eps', agg, [SCHEMA, 7, {}, manyVotes, { epsilon: 1.5, delta: 1e-5 }, noiseSeq]);
await run('aggregate', 'bad-qmin', agg, [SCHEMA, 7, {}, manyVotes, { epsilon: 0.5, delta: 1e-5, qMin: 0.5 }, noiseSeq]);
await run('aggregate', 'cap-2', agg, [SCHEMA, 7, { maxCellsPerPrincipal: 2 }, manyVotes, { epsilon: 0.9, delta: 1e-5 }, noiseSeq]);
await run('aggregate', 'cap-bad', agg, [SCHEMA, 7, { maxCellsPerPrincipal: 0 }, [], { epsilon: 0.9, delta: 1e-5 }, noiseSeq]);
await run('aggregate', 'cap-frac', agg, [SCHEMA, 7, { maxCellsPerPrincipal: 1.5 }, [], { epsilon: 0.9, delta: 1e-5 }, noiseSeq]);
await run('aggregate', 'bad-schema-arg', agg, ['nope', 7, {}, [], { epsilon: 0.9, delta: 1e-5 }, noiseSeq]);
await run('aggregate', 'vote-gauntlet', agg, [SCHEMA, 7, { maxCellsPerPrincipal: 2 }, [vote('a', K1, 1), vote('a', K1, 0), vote('a', K2, 1), vote('a', K3, 1), vote('b', K1, 2), vote('', K1, 1), vote('c', K1, 1, { schemaDigest: dig('other') }),
  vote('c', K1, 1, { period: 8 }), vote('c', K1, 1, { period: '7' }), vote('d', K1, -0), vote('e', K1, 1, { principal: 5 }), vote('f', K1, 1.5), vote('g', K1, null), vote('h', K2, 1)], { epsilon: 0.9, delta: 1e-5 }, noiseSeq]);
await run('aggregate', 'empty', agg, [SCHEMA, 7, {}, [], { epsilon: 0.9, delta: 1e-5 }, []]);
const REL = (() => {
  const a = new W.PopulationAggregator(SCHEMA, 7, { rand: seq(noiseSeq) });
  for (const v of manyVotes) a.contribute(v);
  return a.release({ epsilon: 0.9, delta: 1e-5, minCount: 1 });
})();
const prior = (rel: any, beta: number, id: string, verb: string, contained: number[]) => {
  const pm = W.populationPrior(rel, beta);
  return { beta: pm.beta, weight: pm.weight(vsOf(id, verb), (c: number) => contained.includes(c)) };
};
// a release over the stripe.refund cells that actually exist (cell keys of the first cells), for the weight table
const RELV = (() => {
  const cells: any = {};
  for (let c = 0; c < 12; c++) cells[W.populationCellKey(SCHEMA, vsR, I.decodeCell(vsR, c))] = { q: 0.05 + 0.07 * c, n: 100 };
  return { v: 1, kind: 'pca-intent-population-prior', schema: SCHEMA, period: 7, epsilon: 0.9, delta: 1e-5, sigma: 1, sensitivity: 8, cells };
})();
for (const beta of [0, 0.3, 0.9, 0.91, 1, -0.1, 2]) for (const contained of [[], [0], [0, 1, 2], [3, 5, 11, 400], Array.from({ length: 12 }, (_, i) => i)])
  await run('populationPrior', `${beta}-${contained.length}-${contained[0] ?? 'x'}`, prior, [RELV, beta, 'A', 'stripe.refund', contained]);
await run('populationPrior', 'sparse-release', prior, [REL, 0.5, 'A', 'files.read', [0, 1]]);
await run('populationPrior', 'empty-cells', prior, [{ ...RELV, cells: {} }, 0.5, 'A', 'stripe.refund', [1]]);

// ---- delivery ------------------------------------------------------------------------------------------------------------------------------
const ACT_REFUND = { verb: 'stripe.refund', resource: 'charge:ch_1', params: { amount: 500, currency: 'usd' }, reversibility_class: 'irreversible' };
const ACT_FILE = { verb: 'files.read', resource: 'file:a', params: {}, reversibility_class: 'reversible' };
const P2: any = await import('../../../packages/pca/src/ext/intent.ts');
const P: any = P2.default ?? P2;
const SITE_KID = 'site-k1';
const SITE_KEYS = [{ kid: SITE_KID, alg: 'ed25519', pk: pubOf('wallet/site') }];
const COORDS_REFUND = { 'action.params.amount': [1, 3], 'action.resource': ['charge:ch_1'], 'env.acc.spend.post': [1, 1], 'env.prov.recipient': ['trusted'] };
const signIR = (over: any = {}, action: any = ACT_REFUND) => P.signIntentRequired({
  v: 1, kind: 'pca-intent-required', session: dig('session'), map_digest: dig('map'), schema: dig('schema'), pcactn_digest: dig('pcactn'), action_digest: W.pcaActionDigest(action),
  cell: { verb: action.verb, coords: action === ACT_REFUND ? COORDS_REFUND : { 'action.resource': ['file:a', 'file:b'] } }, reason: 'uncertain', question_id: 'q_site0001', friction: 'tap', delivered_to: 'wallet', expires_at: T0 + 60_000, ...over,
}, SITE_KID, seed('wallet/site'));
const IR1 = signIR();
const notice = (ir: any, keys: any, site: any, now: any, inbox?: any) => W.siteQuestionNotice(ir, { keys, site, now, ...(inbox !== undefined ? { inboxUrl: inbox } : {}) });
await run('siteQuestionNotice', 'ok', notice, [IR1, SITE_KEYS, 'https://shop.example.com', T0]);
await run('siteQuestionNotice', 'ok-inbox', notice, [IR1, SITE_KEYS, 'https://shop.example.com', T0, 'https://wallet.example.com/inbox']);
await run('siteQuestionNotice', 'ok-empty-inbox', notice, [IR1, SITE_KEYS, 'https://shop.example.com', T0, '']);
await run('siteQuestionNotice', 'expired', notice, [IR1, SITE_KEYS, 'https://shop.example.com', T0 + 60_001]);
await run('siteQuestionNotice', 'at-expiry', notice, [IR1, SITE_KEYS, 'https://shop.example.com', T0 + 60_000]);
await run('siteQuestionNotice', 'wrong-key', notice, [IR1, [{ kid: SITE_KID, alg: 'ed25519', pk: pubOf('wallet/other') }], 'https://shop.example.com', T0]);
await run('siteQuestionNotice', 'unknown-kid', notice, [IR1, [{ kid: 'zz', alg: 'ed25519', pk: pubOf('wallet/site') }], 'https://shop.example.com', T0]);
await run('siteQuestionNotice', 'no-keys', notice, [IR1, [], 'https://shop.example.com', T0]);
await run('siteQuestionNotice', 'keys-not-array', notice, [IR1, {}, 'https://shop.example.com', T0]);
await run('siteQuestionNotice', 'now-fraction', notice, [IR1, SITE_KEYS, 'https://shop.example.com', 1.5]);
await run('siteQuestionNotice', 'now-string', notice, [IR1, SITE_KEYS, 'https://shop.example.com', 'x']);
await run('siteQuestionNotice', 'tampered', notice, [{ ...IR1, friction: 'device' }, SITE_KEYS, 'https://shop.example.com', T0]);
await run('siteQuestionNotice', 'alg-mismatch', notice, [IR1, [{ kid: SITE_KID, alg: 'ml-dsa-65', pk: pubOf('wallet/site') }], 'https://shop.example.com', T0]);
for (const [l, v] of variants(IR1, { maxPaths: 14 })) await run('siteQuestionNotice', `var-${l}`, notice, [v, SITE_KEYS, 'https://shop.example.com', T0]);
await run('clarificationNotice', 'a', W.clarificationNotice, [dig('session'), 'q_abc']);
await run('clarificationNotice', 'inbox', W.clarificationNotice, [dig('session'), 'q_abc', 'https://w.example/inbox']);
const NOTICES = [W.siteQuestionNotice(IR1, { keys: SITE_KEYS, site: 'https://shop.example.com', now: T0 }), W.siteQuestionNotice(IR1, { keys: SITE_KEYS, site: 'https://shop.example.com', now: T0, inboxUrl: 'https://wallet.example.com/inbox?x=1' }),
  W.clarificationNotice(dig('session'), 'q_abc'), W.clarificationNotice(dig('session'), 'q é/?&', 'https://w.example/inbox')];
for (const [i, n] of NOTICES.entries()) for (const site of ['Example Shop', '', '  ', 'Evil\u0001 Shop ' + 'x'.repeat(80), 'Café ☕']) await run('questionText', `n${i}-${JSON.stringify(site).slice(0, 14)}-${site.length}`, W.questionText, [n, site]);
const hook = (cfg: any, script: any[], notices: any[]) => {
  const calls: any[] = [];
  let i = 0;
  const ch = W.questionWebhookChannel({ ...(cfg.url !== undefined ? { url: cfg.url } : {}), ...(cfg.headers ? { headers: cfg.headers } : {}), fetch: async (url: string, init: any) => {
    calls.push({ url, method: init.method, headers: init.headers, body: init.body });
    const step = script[i++] ?? { ok: true, status: 200 };
    if (step.throw) throw new Error(step.throw);
    return { ok: step.ok, status: step.status };
  } });
  return Promise.all(notices.map((n: any) => ch.notify(n))).then((deliveries) => ({ kind: ch.kind, enabled: ch.enabled, deliveries, calls }));
};
await run('webhookChannel', 'ok', hook, [{ url: 'https://hook.example/x' }, [], [NOTICES[0], NOTICES[2]]]);
await run('webhookChannel', 'headers', hook, [{ url: 'https://hook.example/x', headers: { 'x-sig': 'abc', 'content-type': 'application/vnd.q+json' } }, [{ ok: true, status: 201 }], [NOTICES[1]]]);
await run('webhookChannel', 'non-2xx', hook, [{ url: 'https://hook.example/x' }, [{ ok: false, status: 503 }, { ok: false, status: 404 }], [NOTICES[0], NOTICES[3]]]);
await run('webhookChannel', 'throws', hook, [{ url: 'https://hook.example/x' }, [{ throw: 'boom' }, { ok: true, status: 200 }], [NOTICES[0], NOTICES[2]]]);
await run('webhookChannel', 'no-url', hook, [{}, [], [NOTICES[0]]]);
await run('webhookChannel', 'empty-url', hook, [{ url: '' }, [], [NOTICES[2]]]);
const tchan = (kind: string, name: string, script: any[], notices: any[]) => {
  const sent: any[] = [];
  let i = 0;
  const cfg: any = { siteName: name };
  if (script !== null) cfg.send = async (b: any) => { sent.push(b); const st = script[i++]; if (st?.throw) throw new Error(st.throw); };
  const ch = W.questionTextChannel(kind, cfg);
  return Promise.all(notices.map((n: any) => ch.notify(n))).then((deliveries) => ({ kind: ch.kind, enabled: ch.enabled, deliveries, sent }));
};
for (const kind of ['email', 'sms', 'push']) {
  await run('textChannel', `${kind}-ok`, tchan, [kind, 'Example Shop', [{}, {}, {}, {}], NOTICES]);
  await run('textChannel', `${kind}-throws`, tchan, [kind, 'Example Shop', [{ throw: 'smtp down' }, {}], [NOTICES[0], NOTICES[2]]]);
  await run('textChannel', `${kind}-disabled`, tchan, [kind, 'Example Shop', null, [NOTICES[0]]]);
}
const dispatch = (cfgs: any[], notice: any) => {
  const chans = cfgs.map((c: any) => (c.type === 'webhook' ? W.questionWebhookChannel({ ...(c.url !== undefined ? { url: c.url } : {}), fetch: async () => ({ ok: true, status: 200 }) }) : W.questionTextChannel(c.type, { siteName: 'S', ...(c.enabled ? { send: async () => undefined } : {}) })));
  const d = W.createQuestionDispatcher(chans);
  return d.notifyAll(notice).then((r: any) => ({ n: d.channels.length, deliveries: r }));
};
await run('dispatcher', 'mixed', dispatch, [[{ type: 'webhook', url: 'https://h.example' }, { type: 'email', enabled: true }, { type: 'sms', enabled: false }, { type: 'push', enabled: true }], NOTICES[0]]);
await run('dispatcher', 'none', dispatch, [[], NOTICES[0]]);
await run('dispatcher', 'all-disabled', dispatch, [[{ type: 'webhook' }, { type: 'sms', enabled: false }], NOTICES[2]]);

// ---- the question channel (scenarios) ----------------------------------------------------------------------------------------------------
const PKCS8_ED = Buffer.from('302e020100300506032b657004220420', 'hex');
const edPriv = (l: string) => createPrivateKey({ key: Buffer.concat([PKCS8_ED, Buffer.from(seed(l))]), format: 'der', type: 'pkcs8' });
const edX = (l: string) => String(createPublicKey(edPriv(l)).export({ format: 'jwk' }).x);
const mkAssertion = (l: string, rpId: string, origin: string, challenge: string, signCount: number, flags = 0x05) => {
  const ad = Buffer.concat([createHash('sha256').update(rpId).digest(), Buffer.from([flags]), Buffer.from([(signCount >>> 24) & 255, (signCount >>> 16) & 255, (signCount >>> 8) & 255, signCount & 255])]);
  const cd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }));
  const sg = nodeSign(null, Buffer.concat([ad, createHash('sha256').update(cd).digest()]), edPriv(l));
  return { credential_id: 'cred1', authenticator_data: b64u(ad), client_data_json: b64u(cd), signature: b64u(sg) };
};
const DEVICE = { rpId: 'wallet.example.com', origins: ['https://wallet.example.com'], credentials: { cred1: { kty: 'OKP', crv: 'Ed25519', x: edX('wallet/device') } }, signCounts: {} };
const AV_LIFT = { 'env.acc.spend.post': 1000, 'env.prov.recipient': 'trusted' };
const VIEW_REFUND = (extra: any = {}) => ({ p: { 'stripe.refund|2,0,1,3': 0.5, 'files.read|0': 0.5, 'files.read|1': 0.5, 'stripe.refund|1,0,1,3': 0.5, 'stripe.refund|3,0,1,3': 0.5 }, vetoed: [], ceiling: [], confirmed: [{ verb: 'stripe.refund', idx: [4, 0, 1, 3] }, { verb: 'files.read', idx: [2] }], ...extra });
const gen = rng(0xc4a77e);
const RANDS = Array.from({ length: 400 }, () => gen.next());
const BASE = (over: any = {}) => ({
  omega: { $omega: 'A' }, session: dig('session'), mapDigest: dig('map'), principal: 'wallet/principal', site: { origin: 'https://shop.example.com', name: 'Example Shop', keys: SITE_KEYS },
  statementText: 'refund my last order', units: { 'action.params.amount': MONEY }, lift: { add: AV_LIFT }, liftCand: AV_LIFT, view: VIEW_REFUND(), rho: 0, noise: N0, hourlyPre: [], rands: RANDS, t0: T0, steps: [], ...over,
});
const FREE = { ...W.DEFAULT_FATIGUE, assumeNoiseFree: true };
function runScenario(spec0: any): { rec: any; out: any } {
  const rec = JSON.parse(JSON.stringify(spec0));
  const spec = sub(JSON.parse(JSON.stringify(spec0)));
  let t = spec.t0;
  let counts = spec.noise;
  const hourly = new W.SlidingWindowCounter(...(spec.windowMs !== undefined ? [spec.windowMs] : []));
  for (const ts of spec.hourlyPre) hourly.tryAdd(ts, Number.MAX_SAFE_INTEGER);
  let ri = 0;
  const rand = () => { if (ri >= spec.rands.length) throw new Error('rand exhausted'); return spec.rands[ri++]; };
  const V = spec.view;
  const view = { p: (v: string, i: number[]) => V.p[W.cellKey(v, i)] ?? 0, vetoed: (v: string, i: number[]) => V.vetoed.includes(W.cellKey(v, i)), outsideCeiling: (v: string, i: number[]) => V.ceiling.includes(W.cellKey(v, i)), confirmed: () => V.confirmed };
  const opts: any = {
    omega: spec.omega, session: spec.session, mapDigest: () => spec.mapDigest, principalSecret: seed(spec.principal), site: spec.site, view, hourly, noise: () => counts, onNoise: (n: any) => { counts = n; }, rand, now: () => t,
    ...(spec.statementText !== undefined ? { statementText: spec.statementText } : {}), ...(spec.units ? { units: spec.units } : {}), ...(spec.sensitivity ? { sensitivity: spec.sensitivity } : {}), ...(spec.identityPaths ? { identityPaths: spec.identityPaths } : {}),
    ...(spec.caps ? { caps: spec.caps } : {}), ...(spec.rho !== undefined ? { rho: spec.rho } : {}), ...(spec.fatigue ? { fatigue: spec.fatigue } : {}), ...(spec.maxPerScreen !== undefined ? { maxPerScreen: spec.maxPerScreen } : {}),
    ...(spec.maxBoxCells !== undefined ? { maxBoxCells: spec.maxBoxCells } : {}), ...(spec.device ? { device: JSON.parse(JSON.stringify(spec.device)) } : {}),
    ...(spec.liftCand ? { liftCandidate: (a: any) => ({ verb: a.verb, values: { ...a.values, ...spec.liftCand } }) } : {}),
    ...(spec.lift ? { lift: (a: any) => { const v = W.actionValuesOf(a); return { verb: v.verb, values: { ...v.values, ...spec.lift.add } }; } } : {}),
  };
  const ch = new W.TrustedChannel(opts);
  const seen: string[] = [];
  const steps: any[] = [];
  const resolver = (sid: string) => (sid === spec.session ? ch : undefined);
  for (const [si, st] of spec.steps.entries()) {
    let r: any;
    try {
      const qid = st.q !== undefined ? seen[st.q] : st.qid;
      switch (st.op) {
        case 'time': t = st.t; r = { t }; break;
        case 'receive': r = ch.receive(st.ir, { action: st.action }); break;
        case 'next': { r = ch.nextScreen(); for (const q of r?.questions ?? []) seen.push(q.questionId); break; }
        case 'answer': {
          if (st.device) {
            const chal = ch.deviceChallengeFor(qid);
            const dc = opts.device;
            const wa = mkAssertion(st.device.label ?? 'wallet/device', dc.rpId, st.device.origin ?? dc.origins[0], chal ?? 'AAAA', st.device.signCount ?? 1, st.device.flags ?? 0x05);
            st.response = { ...st.response, webauthn: wa };
            rec.steps[si].response = { ...rec.steps[si].response, webauthn: wa };
          }
          r = ch.answer(qid, st.response);
          break;
        }
        case 'clarify': r = ch.clarify(st.body); break;
        case 'hQuestion': r = W.questionHandler(resolver)(st.sid ?? spec.session, st.body); break;
        case 'hClarify': r = W.clarifyHandler(resolver)(st.sid ?? spec.session, st.body); break;
        case 'summary': r = ch.summary(); break;
        case 'state': r = { digest: ch.stateDigest(), asked: ch.questionsAsked() }; break;
        case 'noise': r = { noise: ch.noise(), admission: ch.admission() }; break;
        case 'challenge': r = ch.deviceChallengeFor(qid); break;
        default: throw new Error('bad op ' + st.op);
      }
    } catch (e: any) {
      r = { $err: true };
    }
    steps.push({ op: st.op, r });
  }
  return { rec, out: jsonOutOf({ steps, noise: counts, signCounts: opts.device?.signCounts ?? null }) };
}
const jsonOutOf = (x: any) => JSON.parse(ser(x));
let scN = 0;
const scenario = (name: string, spec: any) => {
  const { rec, out } = runScenario(spec);
  o.add('channel', `${String(scN++).padStart(2, '0')}-${name}`, reparse([rec]), out);
};
const REF_ACT = ACT_REFUND, FILE_ACT = ACT_FILE;
const IRs = (over: any = {}, action: any = ACT_REFUND) => signIR(over, action);
// 1. an irreversible question under noise-free answers: typed tier (harm), JIT consent bound to the action
scenario('typed-yes-noise-free', BASE({ fatigue: FREE, steps: [{ op: 'receive', ir: IRs(), action: REF_ACT }, { op: 'noise' }, { op: 'next' }, { op: 'answer', q: 0, response: { answer: 'yes', typed: '5.00' } }, { op: 'state' }, { op: 'summary' }] }));
scenario('typed-wrong-value', BASE({ fatigue: FREE, steps: [{ op: 'receive', ir: IRs(), action: REF_ACT }, { op: 'next' }, { op: 'answer', q: 0, response: { answer: 'yes', typed: '6.00' } }, { op: 'answer', q: 0, response: { answer: 'yes' } }, { op: 'answer', q: 0, response: { answer: 'yes', typed: 5 } },
  { op: 'answer', q: 0, response: { answer: 'yes', typed: '5.00' } }] }));
scenario('veto-no', BASE({ fatigue: FREE, steps: [{ op: 'receive', ir: IRs(), action: REF_ACT }, { op: 'next' }, { op: 'answer', q: 0, response: { answer: 'no' } }, { op: 'answer', q: 0, response: { answer: 'no' } }, { op: 'summary' }] }));
scenario('partly-answers', BASE({ fatigue: FREE, steps: [{ op: 'receive', ir: IRs(), action: REF_ACT }, { op: 'next' }, { op: 'answer', q: 0, response: { answer: 'partly', partial: { path: 'action.params.amount', upTo: 100 }, typed: '5.00' } },
  { op: 'answer', q: 0, response: { answer: 'partly', partial: { path: 'nope', upTo: 1 } } }, { op: 'answer', q: 0, response: { answer: 'partly', partial: { path: 'action.params.amount', from: 1002 }, typed: '5.00' } }] }));
// double confirmation under estimated noise (the default model): the first yes schedules a second, two screens later
scenario('double-confirmation', BASE({ rands: RANDS, steps: [{ op: 'receive', ir: IRs(), action: REF_ACT }, { op: 'noise' }, { op: 'next' }, { op: 'answer', q: 0, response: { answer: 'yes', typed: '5.00' } }, { op: 'next' }, { op: 'next' }, { op: 'next' }, { op: 'state' },
  { op: 'answer', q: 1, response: { answer: 'yes', typed: '5.00' } }, { op: 'summary' }, { op: 'next' }] }));
scenario('double-confirmation-expires', BASE({ steps: [{ op: 'receive', ir: IRs(), action: REF_ACT }, { op: 'next' }, { op: 'answer', q: 0, response: { answer: 'yes', typed: '5.00' } }, { op: 'time', t: T0 + 70_000 }, { op: 'next' }, { op: 'state' }] }));
// device tier: an identity widened beyond the confirmed values, a WebAuthn assertion bound to the card and the action
const COORDS_ID = { 'action.params.amount': [1, 3], 'action.resource': ['charge:ch_1', 'charge:'], 'env.acc.spend.post': [1, 1], 'env.prov.recipient': ['trusted'] };
scenario('device-yes', BASE({ fatigue: FREE, identityPaths: ['action.resource'], device: DEVICE, steps: [{ op: 'receive', ir: IRs({ cell: { verb: 'stripe.refund', coords: COORDS_ID } }), action: REF_ACT }, { op: 'next' }, { op: 'challenge', q: 0 },
  { op: 'answer', q: 0, response: { answer: 'yes' }, device: { signCount: 1 } }, { op: 'noise' }] }));
scenario('device-bad', BASE({ fatigue: FREE, identityPaths: ['action.resource'], device: DEVICE, steps: [{ op: 'receive', ir: IRs({ cell: { verb: 'stripe.refund', coords: COORDS_ID } }), action: REF_ACT }, { op: 'next' }, { op: 'answer', q: 0, response: { answer: 'yes' } },
  { op: 'answer', q: 0, response: { answer: 'yes', webauthn: { credential_id: 'nope', authenticator_data: 'AAAA', client_data_json: 'AAAA', signature: 'AAAA' } } },
  { op: 'answer', q: 0, response: { answer: 'yes', webauthn: { credential_id: 'cred1', authenticator_data: '!!', client_data_json: 'AAAA', signature: 'AAAA' } } },
  { op: 'answer', q: 0, response: { answer: 'yes' }, device: { origin: 'https://evil.example' } }, { op: 'answer', q: 0, response: { answer: 'yes' }, device: { flags: 0x01 } }, { op: 'answer', q: 0, response: { answer: 'yes' }, device: { label: 'wallet/other-device' } },
  { op: 'answer', q: 0, response: { answer: 'yes' }, device: { signCount: 5 } }, { op: 'answer', q: 0, response: { answer: 'yes' }, device: { signCount: 6 } }] }));
scenario('device-no-trust', BASE({ fatigue: FREE, identityPaths: ['action.resource'], steps: [{ op: 'receive', ir: IRs({ cell: { verb: 'stripe.refund', coords: COORDS_ID } }), action: REF_ACT }, { op: 'next' }, { op: 'answer', q: 0, response: { answer: 'yes' } }, { op: 'challenge', q: 0 }] }));
// tap and hold questions share a screen; a typed one is alone
const CANARY_VIEW = { p: { 'files.read|0': 0.5, 'files.read|1': 0.5 }, vetoed: ['files.read|1'], ceiling: ['files.read|3'], confirmed: [{ verb: 'files.read', idx: [2] }] };
const FILE_VIEW = { p: { 'files.read|0': 0.5, 'files.read|1': 0.5, 'files.read|2': 0.4 }, vetoed: [], ceiling: [], confirmed: [{ verb: 'files.read', idx: [3] }] };
const ACT_FILE_B = { ...ACT_FILE, resource: 'file:b' }, ACT_FILE_ZZ = { ...ACT_FILE, resource: 'file:zz' };
const IRF = (qid: string, coordsOver?: any, over: any = {}, act: any = FILE_ACT) => IRs({ question_id: qid, ...(coordsOver ? { cell: { verb: 'files.read', coords: coordsOver } } : {}), ...over }, act);
const IRFB = (qid: string, over: any = {}) => IRF(qid, { 'action.resource': ['file:b'] }, over, ACT_FILE_B);
const IRFP = (qid: string, over: any = {}) => IRF(qid, { 'action.resource': ['file:'] }, over, ACT_FILE_ZZ);
scenario('tap-shared-screen', BASE({ fatigue: FREE, view: FILE_VIEW, maxPerScreen: 2, caps: { perSession: 10, perHour: 20 }, steps: [
  { op: 'receive', ir: IRF('q_f1', { 'action.resource': ['file:a'] }), action: FILE_ACT }, { op: 'receive', ir: IRFB('q_f2'), action: ACT_FILE_B },
  { op: 'receive', ir: IRFP('q_f3'), action: ACT_FILE_ZZ }, { op: 'next' }, { op: 'next' }, { op: 'answer', q: 0, response: { answer: 'yes' } }, { op: 'answer', q: 1, response: { answer: 'no' } }, { op: 'next' }, { op: 'state' }] }));
scenario('hold-evidence', BASE({ fatigue: FREE, view: FILE_VIEW, steps: [{ op: 'receive', ir: IRF('q_f1', undefined, { friction: 'hold' }), action: FILE_ACT }, { op: 'next' }, { op: 'answer', q: 0, response: { answer: 'yes' } },
  { op: 'answer', q: 0, response: { answer: 'yes', holdMs: 1999 } }, { op: 'answer', q: 0, response: { answer: 'yes', holdMs: 2000.5 } }, { op: 'answer', q: 0, response: { answer: 'yes', holdMs: 2500 } }] }));
scenario('typed-last4', BASE({ fatigue: FREE, view: FILE_VIEW, steps: [{ op: 'receive', ir: IRF('q_f1', undefined, { friction: 'typed' }), action: { ...FILE_ACT, resource: 'file:a' } }, { op: 'next' }, { op: 'answer', q: 0, response: { answer: 'yes', typed: 'x' } }] }));
// refusals
const REFUSALS: [string, any, any, any][] = [
  ['wrong-session', IRs({ session: dig('other-session') }), {}, REF_ACT], ['stale-map', IRs({ map_digest: dig('other-map') }), {}, REF_ACT], ['bad-sig', { ...IRs(), friction: 'device' }, {}, REF_ACT],
  ['action-digest', IRs(), {}, { ...REF_ACT, params: { amount: 501 } }], ['action-verb', IRs(), {}, { ...REF_ACT, verb: 'files.read' }], ['cell-mismatch', IRs({ cell: { verb: 'stripe.refund', coords: { ...COORDS_REFUND, 'action.params.amount': [4, 5] } } }), {}, REF_ACT],
  ['cell-bad-coords', IRs({ cell: { verb: 'stripe.refund', coords: { ...COORDS_REFUND, 'action.params.amount': [0, 99] } } }), {}, REF_ACT],
  ['p-one', IRs(), { view: VIEW_REFUND({ p: { 'stripe.refund|2,0,1,3': 1 } }) }, REF_ACT], ['p-zero', IRs(), { view: VIEW_REFUND({ p: { 'stripe.refund|2,0,1,3': 0 } }) }, REF_ACT],
  ['vetoed-neighbour', IRs(), { view: VIEW_REFUND({ vetoed: ['stripe.refund|1,0,1,3'] }) }, REF_ACT], ['ceiling-neighbour', IRs(), { view: VIEW_REFUND({ ceiling: ['stripe.refund|3,0,1,3'] }) }, REF_ACT],
  ['too-large', IRs(), { maxBoxCells: 2 }, REF_ACT], ['cap-session-zero', IRs(), { caps: { perSession: 0 } }, REF_ACT], ['cap-hour-full', IRs(), { caps: { perHour: 2 }, hourlyPre: [T0 - 1000, T0 - 500] }, REF_ACT],
  ['hour-expired-ok', IRs(), { caps: { perHour: 2 }, hourlyPre: [T0 - 4_000_000, T0 - 3_700_000] }, REF_ACT],
  ['frozen', IRs(), { noise: { falseYes: 6, correctNo: 2, falseNo: 0, correctYes: 0 } }, REF_ACT], ['expired-ir', IRs({ expires_at: T0 - 1 }), {}, REF_ACT], ['unknown-verb', IRs({ cell: { verb: 'nope', coords: COORDS_REFUND } }), {}, { ...REF_ACT, verb: 'nope' }],
];
for (const [name, ir, over, act] of REFUSALS) scenario(`refuse-${name}`, BASE({ fatigue: FREE, ...over, steps: [{ op: 'receive', ir, action: act }, { op: 'summary' }, { op: 'state' }] }));
scenario('refuse-already-asked', BASE({ fatigue: FREE, steps: [{ op: 'receive', ir: IRs(), action: REF_ACT }, { op: 'receive', ir: IRs({ question_id: 'q_site0002' }), action: REF_ACT }, { op: 'receive', ir: IRs(), action: REF_ACT }, { op: 'state' }] }));
scenario('refuse-duplicate-id', BASE({ fatigue: FREE, view: FILE_VIEW, steps: [{ op: 'receive', ir: IRF('q_dup'), action: FILE_ACT }, { op: 'receive', ir: IRFP('q_dup'), action: ACT_FILE_ZZ }, { op: 'state' }] }));
scenario('cap-session-second', BASE({ fatigue: FREE, view: FILE_VIEW, caps: { perSession: 1 }, steps: [{ op: 'receive', ir: IRF('q_f1'), action: FILE_ACT }, { op: 'receive', ir: IRFP('q_f2'), action: ACT_FILE_ZZ }] }));
scenario('frozen-then-summary', BASE({ noise: { falseYes: 6, correctNo: 2, falseNo: 0, correctYes: 0 }, steps: [{ op: 'receive', ir: IRs(), action: REF_ACT }, { op: 'noise' }, { op: 'summary' }, { op: 'clarify', body: { reason: 'other', candidates: [{ verb: 'files.read', values: { 'action.resource': 'file:a' } }] } }] }));
scenario('rand-exhausted', BASE({ fatigue: FREE, rands: [0.5], view: CANARY_VIEW, rho: 1, steps: [{ op: 'receive', ir: IRF('q_f1', { 'action.resource': ['file:a'] }), action: FILE_ACT }, { op: 'state' }] }));
scenario('expiry-on-next', BASE({ fatigue: FREE, view: FILE_VIEW, steps: [{ op: 'receive', ir: IRF('q_f1'), action: FILE_ACT }, { op: 'time', t: T0 + 60_001 }, { op: 'next' }, { op: 'answer', qid: 'q_f1', response: { answer: 'yes' } }, { op: 'state' }] }));
scenario('answer-expired', BASE({ fatigue: FREE, view: FILE_VIEW, steps: [{ op: 'receive', ir: IRF('q_f1'), action: FILE_ACT }, { op: 'next' }, { op: 'time', t: T0 + 60_001 }, { op: 'answer', q: 0, response: { answer: 'yes' } }, { op: 'answer', q: 0, response: { answer: 'yes' } }] }));
scenario('unknown-and-unshown', BASE({ fatigue: FREE, view: FILE_VIEW, steps: [{ op: 'receive', ir: IRF('q_f1'), action: FILE_ACT }, { op: 'answer', qid: 'q_f1', response: { answer: 'yes' } }, { op: 'answer', qid: 'q_none', response: { answer: 'yes' } }, { op: 'challenge', qid: 'q_f1' }, { op: 'next' }, { op: 'next' }] }));
scenario('shifted-clock-hourly', BASE({ fatigue: FREE, view: FILE_VIEW, hourlyPre: [T0 - 100], windowMs: 1000, steps: [{ op: 'receive', ir: IRF('q_f1'), action: FILE_ACT }, { op: 'time', t: T0 - 5000 }, { op: 'receive', ir: IRFP('q_f2'), action: ACT_FILE_ZZ }, { op: 'summary' }] }));
// clarification
const CAND = (amount: number, res = 'charge:ch_1') => ({ verb: 'stripe.refund', values: { 'action.params.amount': amount, 'action.resource': res } });
const CVIEW = VIEW_REFUND({ p: { 'stripe.refund|2,0,1,3': 0.5, 'stripe.refund|4,0,1,3': 0.3, 'stripe.refund|6,0,1,3': 1, 'stripe.refund|0,0,1,3': 0.2, 'files.read|0': 0.5 }, vetoed: ['stripe.refund|1,0,1,3'], ceiling: ['stripe.refund|3,0,1,3'] });
const CLAR_BODY = { reason: 'multiple_options', candidates: [CAND(500), CAND(5000), CAND(100000), CAND(50), CAND(100), CAND(1000), { verb: 'files.read', values: { 'action.resource': 'file:a' } }, { verb: 'nope', values: {} }] };
scenario('clarify-ask', BASE({ fatigue: FREE, view: CVIEW, steps: [{ op: 'clarify', body: CLAR_BODY }, { op: 'next' }, { op: 'answer', q: 0, response: { answer: 'yes', typed: '5.00' } }, { op: 'clarify', body: CLAR_BODY }, { op: 'state' }] }));
scenario('clarify-noisy', BASE({ view: CVIEW, noise: { falseYes: 1, correctNo: 4, falseNo: 1, correctYes: 3 }, steps: [{ op: 'clarify', body: CLAR_BODY }, { op: 'noise' }, { op: 'next' }, { op: 'summary' }] }));
scenario('clarify-dry', BASE({ fatigue: FREE, view: CVIEW, steps: [{ op: 'clarify', body: { reason: 'other', candidates: [CAND(100000), CAND(100), CAND(1000), { verb: 'nope', values: {} }] } }, { op: 'state' }] }));
scenario('clarify-bad-bodies', BASE({ fatigue: FREE, view: CVIEW, steps: [{ op: 'clarify', body: null }, { op: 'clarify', body: { reason: 'x', candidates: [] } }, { op: 'clarify', body: { reason: 'other', candidates: [{ verb: 'v', values: { 'env.hour': 3 } }] } }, { op: 'clarify', body: { reason: 'other', candidates: [], extra: 1 } }, { op: 'state' }] }));
scenario('clarify-caps', BASE({ fatigue: FREE, view: CVIEW, caps: { perSession: 1 }, steps: [{ op: 'clarify', body: { reason: 'other', candidates: [CAND(500)] } }, { op: 'clarify', body: { reason: 'other', candidates: [CAND(5000)] } }, { op: 'summary' }] }));
scenario('clarify-hold-tap', BASE({ fatigue: FREE, view: { ...FILE_VIEW, p: { 'files.read|0': 0.5 } }, steps: [{ op: 'clarify', body: { reason: 'price_changed', candidates: [{ verb: 'files.read', values: { 'action.resource': 'file:a' } }] } }, { op: 'next' }, { op: 'answer', q: 0, response: { answer: 'yes' } }] }));
// canaries (rho = 1): inserted next to the real question, answered like it, and only the noise counts move
const FQ = IRF('q_f1', { 'action.resource': ['file:a'] });
scenario('canary-no-ceiling', BASE({ fatigue: FREE, view: CANARY_VIEW, rho: 1, rands: [0.01, 0.2, 0.3, ...RANDS], caps: { perSession: 10 }, steps: [{ op: 'receive', ir: FQ, action: FILE_ACT }, { op: 'state' }, { op: 'next' }, { op: 'next' },
  { op: 'answer', q: 1, response: { answer: 'yes' } }, { op: 'noise' }, { op: 'answer', q: 0, response: { answer: 'yes' } }, { op: 'summary' }] }));
scenario('canary-correct-no', BASE({ fatigue: FREE, view: CANARY_VIEW, rho: 1, rands: [0.01, 0.2, 0.3, ...RANDS], caps: { perSession: 10 }, steps: [{ op: 'receive', ir: FQ, action: FILE_ACT }, { op: 'next' }, { op: 'answer', q: 1, response: { answer: 'no' } }, { op: 'noise' }] }));
scenario('canary-low-harm-once', BASE({ fatigue: FREE, view: CANARY_VIEW, rho: 1, rands: RANDS, caps: { perSession: 10 }, steps: [{ op: 'receive', ir: FQ, action: FILE_ACT }, { op: 'receive', ir: IRFB('q_f2'), action: ACT_FILE_B }, { op: 'state' }, { op: 'next' }, { op: 'summary' }] }));
scenario('canary-rho-quarter', BASE({ fatigue: FREE, view: CANARY_VIEW, rho: 0.25, rands: [0.2, 0.9, 0.1, 0.4, 0.3, ...RANDS], caps: { perSession: 10 }, steps: [{ op: 'receive', ir: FQ, action: FILE_ACT }, { op: 'state' }, { op: 'next' }] }));
scenario('canary-known-yes', BASE({ fatigue: FREE, view: FILE_VIEW, rho: 1, rands: RANDS, caps: { perSession: 10 },
  steps: [{ op: 'receive', ir: IRF('q_f1', { 'action.resource': ['file:a'] }, { friction: 'typed' }), action: FILE_ACT }, { op: 'next' }, { op: 'answer', q: 0, response: { answer: 'yes', typed: 'ILEA' } },
    { op: 'receive', ir: IRFB('q_f2'), action: ACT_FILE_B }, { op: 'next' }, { op: 'next' }, { op: 'answer', q: 1, response: { answer: 'no' } }, { op: 'noise' }, { op: 'state' }] }));
// handlers
const HB = (ir: any, action: any) => ({ intent_required: ir, action });
scenario('handlers-question', BASE({ fatigue: FREE, steps: [{ op: 'hQuestion', body: HB(IRs(), REF_ACT) }, { op: 'hQuestion', sid: 'nope', body: HB(IRs(), REF_ACT) }, { op: 'hQuestion', body: null }, { op: 'hQuestion', body: [] }, { op: 'hQuestion', body: { ...HB(IRs(), REF_ACT), extra: 1 } },
  { op: 'hQuestion', body: { intent_required: IRs() } }, { op: 'hQuestion', body: { action: REF_ACT } }, { op: 'hQuestion', body: HB(IRs(), { ...REF_ACT, extra: 1 }) }, { op: 'hQuestion', body: HB(IRs(), { ...REF_ACT, params: [] }) }, { op: 'hQuestion', body: HB(IRs(), { verb: 'x' }) },
  { op: 'hQuestion', body: HB(IRs({ session: dig('zz') }), REF_ACT) }, { op: 'hQuestion', body: HB(IRs({ map_digest: dig('zz') }), REF_ACT) }, { op: 'hQuestion', body: HB({ ...IRs(), sig: 5 }, REF_ACT) }, { op: 'hQuestion', body: HB(IRs(), { ...REF_ACT, params: { amount: 9 } }) },
  { op: 'hQuestion', body: HB(IRs(), REF_ACT) }, { op: 'state' }] }));
scenario('handlers-question-states', BASE({ fatigue: FREE, steps: [{ op: 'hQuestion', body: HB(IRs({ cell: { verb: 'stripe.refund', coords: { ...COORDS_REFUND, 'action.params.amount': [4, 5] } } }), REF_ACT) }, { op: 'hQuestion', body: HB(IRs({ cell: { verb: 'stripe.refund', coords: { ...COORDS_REFUND, 'action.params.amount': [0, 99] } } }), REF_ACT) }] }));
scenario('handlers-question-limits', BASE({ fatigue: FREE, caps: { perSession: 0 }, steps: [{ op: 'hQuestion', body: HB(IRs(), REF_ACT) }] }));
scenario('handlers-question-frozen', BASE({ noise: { falseYes: 6, correctNo: 2, falseNo: 0, correctYes: 0 }, steps: [{ op: 'hQuestion', body: HB(IRs(), REF_ACT) }] }));
scenario('handlers-clarify', BASE({ fatigue: FREE, view: CVIEW, steps: [{ op: 'hClarify', body: CLAR_BODY }, { op: 'hClarify', sid: 'nope', body: CLAR_BODY }, { op: 'hClarify', body: { reason: 'x' } }, { op: 'hClarify', body: { reason: 'other', candidates: [CAND(100000)] } }, { op: 'hClarify', body: { reason: 'other', candidates: [CAND(500)] } }, { op: 'state' }] }));
scenario('handlers-clarify-capped', BASE({ fatigue: FREE, view: CVIEW, caps: { perSession: 0 }, steps: [{ op: 'hClarify', body: { reason: 'other', candidates: [CAND(500)] } }] }));
scenario('handlers-clarify-frozen', BASE({ view: CVIEW, noise: { falseYes: 6, correctNo: 2, falseNo: 0, correctYes: 0 }, steps: [{ op: 'hClarify', body: { reason: 'other', candidates: [CAND(500)] } }] }));
// statement and unit variations
scenario('no-statement-no-units', BASE({ fatigue: FREE, statementText: undefined, units: undefined, steps: [{ op: 'receive', ir: IRs(), action: REF_ACT }, { op: 'next' }, { op: 'answer', q: 0, response: { answer: 'yes', typed: '500' } }] }));
scenario('sensitivity-critical-web', BASE({ fatigue: FREE, lift: { add: { ...AV_LIFT, 'env.prov.recipient': 'tool|web' } }, view: { p: { 'stripe.refund|2,0,1,2': 0.5 }, vetoed: [], ceiling: [], confirmed: [] }, sensitivity: { recipient: 'critical' }, rho: 0,
  steps: [{ op: 'receive', ir: IRs({ cell: { verb: 'stripe.refund', coords: { ...COORDS_REFUND, 'env.prov.recipient': ['tool|web'] } } }), action: REF_ACT }, { op: 'next' }] }));

if (process.env.WALLET_SIZES) { const m: Record<string, number> = {}; for (const c of o.cases) m[c.fn] = (m[c.fn] ?? 0) + JSON.stringify(c).length; console.log(Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 8), Object.values(m).reduce((x, y) => x + y, 0)); }
refWrite(o, 'wallet');
