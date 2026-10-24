// Stage of the conformance pipeline for Intent Layer v2 wire batch W-B (run AFTER gen-conformance-intent.mjs; idempotent):
// normative rules 16-18 (conformance/README.md), as function-level PRIMITIVES so every native can mirror them before the
// `intent_session` PCActn member (rule 13) carries them on the wire:
//
//   primitives.intent_world[]       rule 16: oracle facts (pinned keys, freshness, distinct oracles, lower median, string
//                                   agreement), relational dimensions (sub, ratio_ppm) and the signed offer set
//                                   (coverage / search-not-narrowed, completeness, excess). Reference: src/oracle-facts.ts
//                                   `decideIntentWorld`, src/offer-set.ts.
//   primitives.intent_provenance[]  rule 17: per-parameter provenance with an injected registry, label receipt refs and
//                                   flow rules. Reference: src/param-provenance.ts `decideParamProvenance`.
//   primitives.intent_classifier[]  rule 18: classifier verdicts (allowlist, signature, session and content binding, label
//                                   set, measurement pins, k-of-n). Reference: src/intent-classifier.ts.
//   primitives.intent_wb_active[]   which of the three checks a verifier reports (strict array / string / object typing).
//                                   Reference: src/intent-env.ts `intentWBActive`.
//
// Entry: { name, description, input, expect }. A runner calls the rule's function on `input` and compares:
//   rule 16: expect { ok } and, when ok, `world` and `single_source` exactly;
//   rule 17: expect { outcome } and, unless outcome == "deny", `friction` (question only), `labels` and `classes` exactly;
//   rule 18: expect { ok } and, when ok, `classes` exactly;
//   activity: expect { facts, provenance, classes } exactly.
// Reason strings are not compared.
//
//     node packages/pca/scripts/gen-conformance-intent-wb.mjs            (reads ../dist, like every stage)
//     PCA_SRC=1 packages/pca/node_modules/.bin/tsx packages/pca/scripts/gen-conformance-intent-wb.mjs   (reads ../src)
import { createHash } from 'node:crypto';
import { cloneJson, readCore, writeCore } from './conformance-io.mjs';

const pca = process.env.PCA_SRC ? await import('../src/index.ts') : await import('../dist/index.js');

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pk: pca.b64u(pca.publicKeyOf(sk)) }; };
const clone = cloneJson; // JSON deep copy that keeps -0 (conformance-io.mjs)
const NOW = 1_800_000_000_000;
const AUD = 'skyair.example';
const SESSION = pca.b64u(seed('wb/session'));
const OTHER_SESSION = pca.b64u(seed('wb/other-session'));
const O = [mk('wb/oracle-1'), mk('wb/oracle-2'), mk('wb/oracle-3')];
const ROGUE = mk('wb/rogue');
const SITE = mk('wb/site');
const GOV = mk('wb/gov');
const J = [mk('wb/judge-1'), mk('wb/judge-2'), mk('wb/judge-3')];
// Post-quantum signers for the `requires_suite` vectors (ML-DSA-65 and its Ed25519 hybrid). PCA_WB_SKIP_PQ=1 omits
// them (only for a reference build without the PQ suites; the release corpus always carries them).
const SKIP_PQ = process.env.PCA_WB_SKIP_PQ === '1';
const ML = SKIP_PQ ? null : pca.mlDsa65Keygen(seed('wb/mldsa65'));
const ML_PK = SKIP_PQ ? null : pca.encodeMlDsaPublicKey(ML.publicKey);
const ML_OTHER_PK = SKIP_PQ ? null : pca.encodeMlDsaPublicKey(pca.mlDsa65Keygen(seed('wb/mldsa65-other')).publicKey);
// REPRODUCIBLE PQ VECTORS: ML-DSA-65 in its FIPS 204 DETERMINISTIC variant (rnd = 0^32, empty context), so regenerating
// gives byte-identical vectors.json. Every ML-DSA verifier accepts a deterministic signature (it is an ordinary one).
const mlDsaDet = SKIP_PQ ? null : await (async () => {
  const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
  const ZERO = new Uint8Array(32);
  const probe = pca.utf8('atlas-pca-conformance/wb/mldsa-probe');
  const attempts = [(sk, m) => ml_dsa65.sign(sk, m, new Uint8Array(0), ZERO), (sk, m) => ml_dsa65.sign(sk, m, ZERO), (sk, m) => ml_dsa65.sign(sk, m, { extraEntropy: false })];
  for (const f of attempts) {
    try {
      const a = f(ML.secretKey, probe);
      const b = f(ML.secretKey, probe);
      if (pca.b64u(a) === pca.b64u(b) && pca.mlDsa65Verify(ML.publicKey, probe, a)) return f;
    } catch { /* try the next calling convention of the library */ }
  }
  throw new Error('gen-conformance-intent-wb: no deterministic ML-DSA-65 signing available');
})();
/** Sign an artifact body under ML-DSA-65 or its Ed25519 hybrid, deterministically (same layout as signArtifact). */
const signPq = (domain, body, edSk, alg) => {
  const full = { ...body, alg, pq_pk: ML_PK };
  const msg = pca.artifactMessage(domain, full);
  if (alg === 'ml-dsa-65') return { ...full, sig: pca.b64u(mlDsaDet(ML.secretKey, msg)) };
  if (alg === 'hybrid-ed25519-ml-dsa-65') return { ...full, sig: pca.b64u(pca.sign(edSk, msg)), pq_sig: pca.b64u(mlDsaDet(ML.secretKey, msg)) };
  throw new Error(`signPq: ${alg}`);
};
const UNSUPPORTED = 'no-such-suite';
const withAlg = (artifact, alg) => ({ ...artifact, alg });

// ------------------------------------------------------------------ rule 16: primitives.intent_world
const world = [];
// meta: { requires_suite?, reason_contains? } (README "suite capability"): a runner without the suite must fail the vector
// with `unsupported_suite`; `reason_contains` must appear in every runner's reason.
const metaOf = (name, r, meta) => {
  if (meta.reason_contains && !(r.reason ?? '').includes(meta.reason_contains)) throw new Error(`${name}: reason ${JSON.stringify(r.reason)} lacks ${meta.reason_contains}`);
  return { top: meta.requires_suite ? { requires_suite: meta.requires_suite } : {}, exp: meta.reason_contains ? { reason_contains: meta.reason_contains } : {} };
};
function addWorld(name, description, input, must, meta = {}) {
  const r = pca.decideIntentWorld(clone(input));
  const m = metaOf('wb16-' + name, r, meta);
  const expect = r.ok ? { ok: true, world: r.world, single_source: r.single_source } : { ok: false, ...m.exp };
  const okIntent = must === 'deny' ? r.ok === false : r.ok === true && JSON.stringify(r.world) === JSON.stringify(must.world ?? r.world);
  if (!okIntent) throw new Error(`intent_world wb16-${name}: reference ${JSON.stringify(r)} does not meet ${JSON.stringify(must)}`);
  world.push({ name: 'wb16-' + name, description, ...m.top, input: clone(input), expect });
}
const fact = (i, name, value, t_obs = NOW - 1_000, subject = 'OF-2', kid = `o${i + 1}`, key = O[i]) => pca.signFact({ name, subject, value, t_obs, oracle: kid }, key.sk);
const oracles = () => O.map((o, i) => ({ kid: `o${i + 1}`, pk: o.pk }));
const fareWorld = (over = {}) => ({ name: 'fare', subject_path: 'action.params.offer_id', oracles: oracles(), freshness_ms: 60_000, min_oracles: 3, max_faulty: 1, ...over });
const ACTION = { verb: 'air.book', resource: 'skyair.example/bookings', params: { offer_id: 'OF-2', total: 77_800, quote: 38_900, pax: 2 } };
const W = (facts, policy, over = {}) => ({ now: NOW, aud: AUD, session: SESSION, action: ACTION, committed: { facts: facts.map(pca.factRef) }, facts, policy, ...over });
const three = () => [fact(0, 'fare', 39_800), fact(1, 'fare', 39_900), fact(2, 'fare', 1)];

addWorld('empty', 'No commitment, empty policy: ok with an empty world (an inactive check).', { now: NOW, aud: AUD, session: SESSION, action: ACTION, committed: {}, policy: {} }, { world: {} });
addWorld('median-3', 'Three fresh facts from three pinned oracles (f = 1): the lower median 39800 (one liar says 1).', W(three(), { worlds: [fareWorld()] }), { world: { fare: 39_800 } });
addWorld('median-even', 'Four fresh facts (min_oracles 4, f = 1, four pinned): the LOWER median, index floor((n-1)/2) = 1 of [10, 20, 30, 40] = 20.', (() => {
  const O4 = mk('wb/oracle-4');
  const pol = { worlds: [fareWorld({ oracles: [...oracles(), { kid: 'o4', pk: O4.pk }], min_oracles: 4 })] };
  return W([fact(0, 'fare', 40), fact(1, 'fare', 10), fact(2, 'fare', 30), fact(3, 'fare', 20, NOW - 1_000, 'OF-2', 'o4', O4)], pol);
})(), { world: { fare: 20 } });
addWorld('single-source', 'min_oracles 1, max_faulty 0: one fact suffices; the world is reported as single_source.', W([fact(0, 'fare', 5)], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0 })] }), { world: { fare: 5 } });
addWorld('strings-agree', 'Three string facts that agree: the world value is the string.', W([fact(0, 'fare', 'gold'), fact(1, 'fare', 'gold'), fact(2, 'fare', 'gold')], { worlds: [fareWorld()] }), { world: { fare: 'gold' } });
addWorld('fresh-boundaries', 'now - t_obs == freshness_ms and t_obs == now + skew (default 60000) are both fresh (inclusive bounds).', W([fact(0, 'fare', 5, NOW - 60_000), fact(1, 'fare', 6, NOW + 60_000), fact(2, 'fare', 7)], { worlds: [fareWorld()] }), { world: { fare: 6 } });
addWorld('skew-policy', 'skew_ms 0: a fact 1 ms in the future is not fresh; the remaining two satisfy min_oracles 2 (max_faulty 0).', W([fact(0, 'fare', 5, NOW + 1), fact(1, 'fare', 6), fact(2, 'fare', 7)], { skew_ms: 0, worlds: [fareWorld({ min_oracles: 2, max_faulty: 0 })] }), { world: { fare: 6 } });
addWorld('stale-not-counted', 'One stale fact is not counted (never an error); two fresh satisfy min_oracles 2.', W([fact(0, 'fare', 5, NOW - 60_001), fact(1, 'fare', 6), fact(2, 'fare', 9)], { worlds: [fareWorld({ min_oracles: 2, max_faulty: 0 })] }), { world: { fare: 6 } });
addWorld('uncommitted-ignored', 'A supplied fact nobody committed (here forged) is ignored.', { ...W(three(), { worlds: [fareWorld()] }), facts: [...three(), fact(0, 'fare', 999_999, NOW - 1_000, 'OF-2', 'o1', ROGUE)] }, { world: { fare: 39_800 } });
addWorld('relational', 'sub and ratio_ppm over parameters and earlier world values: total-quote = 38900, quote-fare = 0, ratio = floor(77800*1e6/38900) = 2000000, third = floor(pax*1e6/ratio) = floor(2e6/2e6) = 1.', W([fact(0, 'fare', 38_900)], {
  worlds: [fareWorld({ min_oracles: 1, max_faulty: 0 })],
  relational: [
    { name: 'excess_vs_quote', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' },
    { name: 'vs_fare', fn: 'sub', a: 'action.params.quote', b: 'env.world.fare' },
    { name: 'ratio', fn: 'ratio_ppm', a: 'action.params.total', b: 'env.world.fare' },
    { name: 'third', fn: 'ratio_ppm', a: 'action.params.pax', b: 'env.world.ratio' },
  ],
}), { world: { fare: 38_900, excess_vs_quote: 38_900, vs_fare: 0, ratio: 2_000_000, third: 1 } });
addWorld('relational-negative', 'sub may be negative: quote - total = -38900.', W([], { relational: [{ name: 'd', fn: 'sub', a: 'action.params.quote', b: 'action.params.total' }] }), { world: { d: -38_900 } });

const D = (name, description, input, meta) => addWorld(name, description + ' Refused (fail closed).', input, 'deny', meta);
D('too-few-fresh', 'Only one of three facts is fresh (one stale, one beyond the skew) with min_oracles 3.', W([fact(0, 'fare', 1, NOW - 60_001), fact(1, 'fare', 2, NOW + 60_001), fact(2, 'fare', 3)], { worlds: [fareWorld()] }));
D('no-facts', 'A declared world with no committed fact.', W([], { worlds: [fareWorld()] }));
D('unpinned-oracle', 'A committed fact signed by a kid that is not pinned for the world.', W([fact(0, 'fare', 1), fact(1, 'fare', 2), fact(2, 'fare', 3, NOW - 1_000, 'OF-2', 'o9')], { worlds: [fareWorld()] }));
D('wrong-key', 'A fact claiming oracle o3 but signed by another key.', W([fact(0, 'fare', 1), fact(1, 'fare', 2), fact(2, 'fare', 3, NOW - 1_000, 'OF-2', 'o3', ROGUE)], { worlds: [fareWorld()] }));
D('subject-mismatch', 'A fact about another subject (OF-1) than the action names (OF-2).', W([fact(0, 'fare', 1), fact(1, 'fare', 2), fact(2, 'fare', 3, NOW - 1_000, 'OF-1')], { worlds: [fareWorld()] }));
D('duplicate-oracle', 'Two committed facts from oracle o1 for the same world.', W([...three(), fact(0, 'fare', 5, NOW - 2_000)], { worlds: [fareWorld()] }));
D('undeclared-world', 'A committed fact for a world the policy does not declare.', W([...three(), fact(0, 'tier', 'gold')], { worlds: [fareWorld()] }));
D('committed-not-supplied', 'Three digests committed, two facts supplied.', { ...W(three(), { worlds: [fareWorld()] }), facts: three().slice(0, 2) });
D('duplicate-commitment', 'The same digest committed twice.', { ...W(three(), { worlds: [fareWorld()] }), committed: { facts: [pca.factRef(three()[0]), pca.factRef(three()[0]), pca.factRef(three()[1])] } });
D('commitment-not-digest', 'A committed digest that is not canonical base64url of 32 bytes.', { ...W(three(), { worlds: [fareWorld()] }), committed: { facts: ['abc'] } });
D('commitments-not-list', 'committed.facts is an object.', { ...W(three(), { worlds: [fareWorld()] }), committed: { facts: {} } });
D('tampered-value', 'A fact whose value was changed after signing (the commitment covers the tampered bytes): the signature fails.', (() => {
  const f = three();
  f[2] = { ...f[2], value: 39_850 };
  return W(f, { worlds: [fareWorld()] });
})());
D('mixed-types', 'Integer and string facts for one world.', W([fact(0, 'fare', 1), fact(1, 'fare', 'x'), fact(2, 'fare', 3)], { worlds: [fareWorld()] }));
D('strings-disagree', 'String facts that disagree.', W([fact(0, 'fare', 'gold'), fact(1, 'fare', 'gold'), fact(2, 'fare', 'silver')], { worlds: [fareWorld()] }));
D('fact-unknown-member', 'A committed fact with an unknown member (closed set): malformed, so the commitment is unmatched.', (() => {
  const f = three();
  f[0] = { ...f[0], note: 'x' };
  return W(f, { worlds: [fareWorld()] });
})());
D('fact-negative-t-obs', 'A committed fact with t_obs = -1.', (() => {
  const f = three();
  f[0] = pca.signFact({ name: 'fare', subject: 'OF-2', value: 1, t_obs: -1, oracle: 'o1' }, O[0].sk);
  return W(f, { worlds: [fareWorld()] });
})());
D('policy-min-oracles', 'min_oracles 2 < 2*max_faulty+1 = 3: misconfigured.', W(three(), { worlds: [fareWorld({ min_oracles: 2 })] }));
D('policy-few-pins', 'min_oracles 3 with two pinned oracles: misconfigured.', W(three().slice(0, 2), { worlds: [fareWorld({ oracles: oracles().slice(0, 2) })] }));
D('policy-bad-name', 'A world name with an upper-case letter: misconfigured.', W([], { relational: [{ name: 'Fare', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }] }));
D('policy-forward-ref', 'A relational operand naming a LATER dimension: misconfigured.', W([], { relational: [{ name: 'a', fn: 'sub', a: 'env.world.b', b: 'action.params.quote' }, { name: 'b', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }] }));
D('policy-duplicate-name', 'A relational dimension reusing a world name: misconfigured.', W(three(), { worlds: [fareWorld()], relational: [{ name: 'fare', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }] }));
D('ratio-zero', 'ratio_ppm with b = 0.', W([], { relational: [{ name: 'r', fn: 'ratio_ppm', a: 'action.params.total', b: 'action.params.zero' }] }, { action: { ...ACTION, params: { ...ACTION.params, zero: 0 } } }));
D('ratio-negative-a', 'ratio_ppm with a < 0.', W([], { relational: [{ name: 'r', fn: 'ratio_ppm', a: 'action.params.neg', b: 'action.params.total' }] }, { action: { ...ACTION, params: { ...ACTION.params, neg: -5 } } }));
D('ratio-overflow', 'ratio_ppm whose exact result 9007199255000000 exceeds 2^53-1.', W([], { relational: [{ name: 'r', fn: 'ratio_ppm', a: 'action.params.big', b: 'action.params.one' }] }, { action: { ...ACTION, params: { ...ACTION.params, big: 9_007_199_255, one: 1 } } }));
D('sub-overflow', 'sub whose result leaves the safe integer range.', W([], { relational: [{ name: 'r', fn: 'sub', a: 'action.params.big', b: 'action.params.small' }] }, { action: { ...ACTION, params: { ...ACTION.params, big: 9_007_199_254_740_991, small: -1 } } }));
D('operand-missing', 'A relational operand the action does not carry.', W([], { relational: [{ name: 'r', fn: 'sub', a: 'action.params.total', b: 'action.params.nope' }] }));
D('operand-string', 'A relational operand that is a string.', W([], { relational: [{ name: 'r', fn: 'sub', a: 'action.params.offer_id', b: 'action.params.total' }] }));

// prototype-named dimensions (every keyed lookup and tally must treat these as ordinary keys)
addWorld('proto-names', 'Worlds named constructor and valueof, relational dimensions named tostring and hasownproperty: ordinary names (no inherited member is ever read).', W([fact(0, 'constructor', 7), fact(1, 'valueof', 'gold')], {
  worlds: [fareWorld({ name: 'constructor', min_oracles: 1, max_faulty: 0 }), fareWorld({ name: 'valueof', min_oracles: 1, max_faulty: 0 })],
  relational: [{ name: 'tostring', fn: 'sub', a: 'action.params.pax', b: 'env.world.constructor' }, { name: 'hasownproperty', fn: 'sub', a: 'env.world.tostring', b: 'action.params.pax' }],
}), { world: { constructor: 7, valueof: 'gold', tostring: -5, hasownproperty: -7 } });
D('proto-operand-undeclared', 'A relational operand env.world.constructor when no dimension is named constructor (an inherited member must not count as a declared world).', W([], { relational: [{ name: 'r', fn: 'sub', a: 'action.params.total', b: 'env.world.constructor' }] }));
// a clock that is not a safe integer: every fact and every offer set is stale (fail closed, never coerced)
D('now-string', 'now is the string "1800000000000": no usable clock, every fact is stale (never coerced to a number).', { ...W(three(), { worlds: [fareWorld()] }), now: String(NOW) });
D('now-float', 'now is 1800000000000.5: not a safe integer, every fact is stale.', { ...W(three(), { worlds: [fareWorld()] }), now: NOW + 0.5 });
D('now-null', 'now is null: every fact is stale.', { ...W(three(), { worlds: [fareWorld()] }), now: null });
addWorld('now-string-no-clock-needed', 'now is a string but no world or offer set needs a clock: relational dimensions are still computed.', { ...W([], { relational: [{ name: 'd', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }] }), now: String(NOW) }, { world: { d: 38_900 } });

// offer sets (rule 16 step 6)
const OFFERS = [
  { offer_id: 'OF-1', price: 38_900, stops: 1, refundable: false },
  { offer_id: 'OF-2', price: 39_800, stops: 0, refundable: false },
  { offer_id: 'OF-3', price: 41_200, stops: 0, refundable: true },
];
const QUERY = { from: 'SFO', to: 'JFK', date: '2026-11-20', pax: 2 };
const offerSet = (over = {}, key = SITE) => pca.signOfferSet({ v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: QUERY, rank: 'price_asc', complete: true, offers: OFFERS, issued_at: NOW - 10_000, kid: 'skyair-2026', ...over }, key.sk);
const offerPolicy = (over = {}) => ({ name: 'excess_cents', site_keys: [{ kid: 'skyair-2026', pk: SITE.pk }], max_age_ms: 600_000, offer_param: 'action.params.offer_id', filter: { query: QUERY, offer: { refundable: false } }, ...over });
const OS = (os, policy = offerPolicy(), over = {}) => ({ now: NOW, aud: AUD, session: SESSION, action: ACTION, committed: { offer_set: pca.offerSetRef(os) }, offer_set: os, policy: { offers: policy }, ...over });
const withOffer = (id) => ({ action: { ...ACTION, params: { ...ACTION.params, offer_id: id } } });

addWorld('offers-excess', 'Excess = 39800 - 38900 = 900 (site-signed prices; OF-3 does not satisfy the filter and is ignored for the minimum).', OS(offerSet()), { world: { excess_cents: 900 } });
addWorld('offers-cheapest', 'Choosing the cheapest matching offer: excess 0.', OS(offerSet(), offerPolicy(), withOffer('OF-1')), { world: { excess_cents: 0 } });
addWorld('offers-broader-query', 'A query BROADER than the filter (no date, no pax) passes coverage.', OS(offerSet({ query: { from: 'SFO', to: 'JFK' } })), { world: { excess_cents: 900 } });
addWorld('offers-empty-query', 'An empty query passes coverage.', OS(offerSet({ query: {} })), { world: { excess_cents: 900 } });
addWorld('offers-age-boundary', 'now - issued_at == max_age_ms is fresh (inclusive).', OS(offerSet({ issued_at: NOW - 600_000 })), { world: { excess_cents: 900 } });
addWorld('offers-with-facts', 'Facts, a relational dimension and an offer set together.', { ...W([fact(0, 'fare', 38_900)], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0 })], relational: [{ name: 'd', fn: 'sub', a: 'action.params.total', b: 'env.world.fare' }], offers: offerPolicy() }), committed: { facts: [pca.factRef(fact(0, 'fare', 38_900))], offer_set: pca.offerSetRef(offerSet()) }, offer_set: offerSet() }, { world: { fare: 38_900, d: 38_900, excess_cents: 900 } });

D('offers-narrowed-extra-key', 'The query constrains stops = 0, which the intent filter does not (search narrowed).', OS(offerSet({ query: { ...QUERY, stops: 0 } })));
D('offers-narrowed-value', 'The query asks for another date than the filter.', OS(offerSet({ query: { ...QUERY, date: '2026-11-21' } })));
D('offers-narrowed-type', 'The query has pax "2" (a string) where the filter has 2 (scalar equality is typed).', OS(offerSet({ query: { ...QUERY, pax: '2' } })));
D('offers-incomplete', 'complete: false.', OS(offerSet({ complete: false })));
D('offers-unpinned-kid', 'Signed under a kid that is not pinned.', OS(offerSet({ kid: 'other' })));
D('offers-wrong-key', 'Signed by another key under the pinned kid.', OS(offerSet({}, ROGUE)));
D('offers-other-site', 'Issued for another audience.', OS(offerSet({ site: 'evil.example' })));
D('offers-other-session', 'Bound to another session.', OS(offerSet({ session: OTHER_SESSION })));
D('offers-stale', 'now - issued_at = max_age_ms + 1.', OS(offerSet({ issued_at: NOW - 600_001 })));
D('offers-future', 'issued_at = now + skew + 1.', OS(offerSet({ issued_at: NOW + 60_001 })));
D('offers-chosen-missing', 'The action names an offer that is not in the set.', OS(offerSet(), offerPolicy(), withOffer('OF-9')));
D('offers-chosen-filtered', 'The chosen offer does not satisfy the intent filter (refundable).', OS(offerSet(), offerPolicy(), withOffer('OF-3')));
D('offers-chosen-not-string', 'The offer parameter is a number.', OS(offerSet(), offerPolicy(), { action: { ...ACTION, params: { ...ACTION.params, offer_id: 2 } } }));
D('offers-not-committed', 'The policy requires an offer set but the PCActn commits none.', { ...OS(offerSet()), committed: {} });
D('offers-ref-mismatch', 'The supplied offer set is not the committed one.', { ...OS(offerSet()), committed: { offer_set: pca.offerSetRef(offerSet({ issued_at: NOW - 9_000 })) } });
D('offers-not-supplied', 'Committed but not supplied.', { ...OS(offerSet()), offer_set: undefined });
D('offers-duplicate-ids', 'Two offers with the same offer_id (wire).', OS(offerSet({ offers: [OFFERS[0], OFFERS[0]] })));
D('offers-negative-price', 'A negative price (wire).', OS(offerSet({ offers: [{ offer_id: 'OF-2', price: -1 }] })));
D('offers-rank', 'rank other than price_asc (wire).', OS(offerSet({ rank: 'price_desc' })));
D('offers-empty', 'No offers (wire).', OS(offerSet({ offers: [] })));
D('offers-attr-object', 'An offer attribute that is an object (wire).', OS(offerSet({ offers: [{ offer_id: 'OF-2', price: 1, x: { y: 1 } }] })));
D('offers-policy-no-keys', 'An offers policy without pinned keys: misconfigured.', OS(offerSet(), offerPolicy({ site_keys: [] })));

D('offers-now-string', 'An offer set judged with now as a string: no usable clock, the offer set is stale.', { ...OS(offerSet()), now: String(NOW) });

// ---- absent vs null (README "absent vs null"): an absent optional member is empty / default, a present null is malformed
addWorld('absent-policy', 'No policy member at all: absent = {} (an inactive world check, empty world).', { now: NOW, aud: AUD, session: SESSION, action: ACTION, committed: {} }, { world: {} });
addWorld('absent-committed', 'No committed member: absent = {} (no facts committed); a relational dimension is still computed.', { now: NOW, aud: AUD, session: SESSION, action: ACTION, policy: { relational: [{ name: 'd', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }] } }, { world: { d: 38_900 } });
addWorld('absent-params', 'An action without params: absent = {} (nothing reads them).', { now: NOW, aud: AUD, session: SESSION, action: { verb: 'air.book', resource: 'r' }, committed: {}, policy: {} }, { world: {} });
D('null-policy', 'policy is null.', { now: NOW, aud: AUD, session: SESSION, action: ACTION, committed: {}, policy: null });
D('null-committed', 'committed is null.', { now: NOW, aud: AUD, session: SESSION, action: ACTION, committed: null, policy: {} });
D('null-committed-facts', 'committed.facts is null.', { ...W(three(), { worlds: [fareWorld()] }), committed: { facts: null } });
D('null-committed-offer-set', 'committed.offer_set is null.', { ...W(three(), { worlds: [fareWorld()] }), committed: { facts: three().map(pca.factRef), offer_set: null } });
D('null-facts', 'facts (the supplied list) is null.', { ...W(three(), { worlds: [fareWorld()] }), facts: null });
D('null-offer-set', 'offer_set (supplied) is null, even without an offers policy.', { ...W(three(), { worlds: [fareWorld()] }), offer_set: null });
D('string-facts', 'facts is a string (never iterated).', { ...W(three(), { worlds: [fareWorld()] }), facts: 'abc' });
D('null-params', 'action.params is null.', { ...W(three(), { worlds: [fareWorld()] }), action: { ...ACTION, params: null } });
for (const k of ['worlds', 'relational', 'offers', 'skew_ms']) D(`null-policy-${k.replace('_', '-')}`, `policy.${k} is null.`, W(three(), { worlds: [fareWorld()], [k]: null }));
D('null-oracle-pq-pk', 'An oracle pin with pq_pk null.', W(three(), { worlds: [fareWorld({ oracles: oracles().map((o, i) => (i === 0 ? { ...o, pq_pk: null } : o)) })] }));
D('null-fact-alg', 'A committed fact whose alg is null (malformed; not ed25519 by default).', (() => { const f = three(); f[0] = { ...f[0], alg: null }; return W(f, { worlds: [fareWorld()] }); })());

// ---- suite capability
addWorld('fact-alg-ed25519', 'A fact that names alg "ed25519" explicitly (signed with alg in the body): the default suite.', W([pca.signArtifact(pca.FACT_DOMAIN, { v: 1, kind: 'pca-fact', name: 'fare', subject: 'OF-2', value: 5, t_obs: NOW, oracle: 'o1', alg: 'ed25519' }, O[0].sk), fact(1, 'fare', 6), fact(2, 'fare', 7)], { worlds: [fareWorld()] }), { world: { fare: 6 } });
D('fact-alg-unsupported', `A committed fact naming the suite "${UNSUPPORTED}" that no verifier implements.`, (() => { const f = three(); f[0] = withAlg(f[0], UNSUPPORTED); return W(f, { worlds: [fareWorld()] }); })(), { reason_contains: 'unsupported_suite' });
D('fact-alg-number', 'A committed fact whose alg is a number (malformed).', (() => { const f = three(); f[0] = withAlg(f[0], 7); return W(f, { worlds: [fareWorld()] }); })());
D('fact-ed25519-pq-sig', 'An ed25519 fact that carries pq_sig (malformed).', (() => { const f = three(); f[0] = { ...f[0], pq_sig: 'AAAA' }; return W(f, { worlds: [fareWorld()] }); })());
D('offers-alg-unsupported', `An offer set naming the suite "${UNSUPPORTED}".`, (() => { const os = withAlg(offerSet(), UNSUPPORTED); return OS(os); })(), { reason_contains: 'unsupported_suite' });
if (!SKIP_PQ) {
  const pqFact = (alg, pin) => {
    const f = signPq(pca.FACT_DOMAIN, { v: 1, kind: 'pca-fact', name: 'fare', subject: 'OF-2', value: 39_800, t_obs: NOW - 1_000, oracle: 'o1' }, O[0].sk, alg);
    return W([f], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0, oracles: [{ kid: 'o1', pk: O[0].pk, ...(pin ? { pq_pk: pin } : {}) }] })] });
  };
  for (const alg of ['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65']) {
    addWorld(`fact-${alg}`, `A ${alg} fact under the PQ key the oracle pin names.`, pqFact(alg, ML_PK), { world: { fare: 39_800 } }, { requires_suite: alg });
    D(`fact-${alg}-unpinned`, `A ${alg} fact whose oracle pin names no PQ key (the fact's own pq_pk proves nothing).`, pqFact(alg, null), { requires_suite: alg });
    D(`fact-${alg}-other-pin`, `A ${alg} fact whose pq_pk differs from the PQ key the pin names.`, pqFact(alg, ML_OTHER_PK), { requires_suite: alg });
  }
  const pqOffers = signPq(pca.OFFER_SET_DOMAIN, { v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: QUERY, rank: 'price_asc', complete: true, offers: OFFERS, issued_at: NOW - 10_000, kid: 'skyair-2026' }, SITE.sk, 'ml-dsa-65');
  addWorld('offers-ml-dsa-65', 'An ML-DSA-65 offer set under the pinned site PQ key.', OS(pqOffers, offerPolicy({ site_keys: [{ kid: 'skyair-2026', pk: SITE.pk, pq_pk: ML_PK }] })), { world: { excess_cents: 900 } }, { requires_suite: 'ml-dsa-65' });
  D('offers-ml-dsa-65-unpinned', 'An ML-DSA-65 offer set whose site key pins no PQ key.', OS(pqOffers), { requires_suite: 'ml-dsa-65' });
}

// ---- closed and typed policies (README "closed and typed"): unknown members, numeric strings and fractions are malformed
D('policy-unknown-member', 'The world policy carries an unknown member.', W(three(), { worlds: [fareWorld()], extra: true }));
D('world-unknown-member', 'A world entry carries an unknown member.', W(three(), { worlds: [{ ...fareWorld(), note: 'x' }] }));
D('oracle-pin-unknown-member', 'An oracle pin carries an unknown member.', W(three(), { worlds: [fareWorld({ oracles: oracles().map((o, i) => (i === 0 ? { ...o, alg: 'ed25519' } : o)) })] }));
D('relational-unknown-member', 'A relational entry carries an unknown member.', W([], { relational: [{ name: 'd', fn: 'sub', a: 'action.params.total', b: 'action.params.quote', unit: 'usd' }] }));
D('offers-unknown-member', 'The offers policy carries an unknown member.', OS(offerSet(), offerPolicy({ rank: 'price_asc' })));
D('site-key-unknown-member', 'A site key carries an unknown member.', OS(offerSet(), offerPolicy({ site_keys: [{ kid: 'skyair-2026', pk: SITE.pk, site: AUD }] })));
D('filter-unknown-member', 'The intent filter carries a member other than query / offer.', OS(offerSet(), offerPolicy({ filter: { query: QUERY, offer: { refundable: false }, sort: 'price' } })));
D('freshness-string', 'freshness_ms is the numeric string "60000".', W(three(), { worlds: [fareWorld({ freshness_ms: '60000' })] }));
D('min-oracles-fraction', 'min_oracles is 3.5.', W(three(), { worlds: [fareWorld({ min_oracles: 3.5 })] }));
D('skew-fraction', 'skew_ms is 1.5.', W(three(), { worlds: [fareWorld()], skew_ms: 1.5 }));
D('max-age-string', 'max_age_ms is the string "600000".', OS(offerSet(), offerPolicy({ max_age_ms: '600000' })));

// ------------------------------------------------------------------ rule 17: primitives.intent_provenance
const prov = [];
function addProv(name, description, input, must, meta = {}) {
  const r = pca.decideParamProvenance(clone(input));
  const m = metaOf('wb17-' + name, r, meta);
  const expect = r.outcome === 'deny' ? { outcome: 'deny', ...m.exp } : { outcome: r.outcome, ...(r.outcome === 'question' ? { friction: r.friction } : {}), labels: r.labels, classes: r.classes };
  const want = typeof must === 'string' ? { outcome: must } : must;
  const ok = r.outcome === want.outcome && (!want.labels || JSON.stringify(sortKeys(r.labels)) === JSON.stringify(sortKeys(want.labels))) && (!want.friction || r.friction === want.friction);
  if (!ok) throw new Error(`intent_provenance wb17-${name}: reference ${JSON.stringify(r)} does not meet ${JSON.stringify(want)}`);
  prov.push({ name: 'wb17-' + name, description, ...m.top, input: clone(input), expect });
}
const sortKeys = (o) => Object.fromEntries(Object.entries(o).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
const PARAMS = { offer_id: 'OF-1', payment_ref: 'pm_ana_visa', add_ons: 'tripshield', passport: 'X1234567', note: 'hi', pax: { lead: 'px_ana' } };
const POLICY = {
  params: { 'action.params.offer_id': 'material', 'action.params.add_ons': 'material', 'action.params.payment_ref': 'critical', 'action.params.passport': 'critical' },
  registry: { 'skyair:offer_set:1': 'first_party', 'wallet:profile:ana': 'trusted', 'web:skyair.example/results#ad-3': 'web', 'tool:fx': 'tool', 'agent:planner': 'agent' },
  label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk }, { site: 'gov.example', kid: 'g1', pk: GOV.pk }],
};
const CLEAN = { 'action.params.offer_id': ['skyair:offer_set:1'], 'action.params.payment_ref': ['wallet:profile:ana'], 'action.params.add_ons': ['wallet:profile:ana'], 'action.params.passport': ['wallet:profile:ana'] };
const P = (provOver = {}, policyOver = {}, over = {}) => ({ aud: AUD, session: SESSION, action: { params: PARAMS }, prov: { ...CLEAN, ...provOver }, policy: { ...POLICY, ...policyOver }, ...over });
const receipt = (site, key, kid, fields, session = SESSION) => pca.signLabels({ site, session, response_digest: pca.b64u(seed('wb/response')), fields, issued_at: NOW - 5_000, kid }, key.sk);
const PASSPORT = receipt(AUD, SITE, 'k1', { 'travellers[0].passport': { class: 'pii.identity', value_digest: pca.hashCanonical('X1234567') } });
const GOVR = receipt('gov.example', GOV, 'g1', { passport: { class: 'pii.identity', value_digest: pca.hashCanonical('X1234567') }, name: { class: 'pii.identity', value_digest: pca.hashCanonical('Ana') } });
const lref = (r, f) => `pca-labels:${pca.labelsRef(r)}#${f}`;
const withLabel = (r, f, extra = {}) => ({ committed_labels: [pca.labelsRef(r)], labels: [r], ...extra, prov: { ...CLEAN, 'action.params.passport': [lref(r, f)] } });
const T = { 'action.params.add_ons': 'trusted', 'action.params.offer_id': 'first_party', 'action.params.passport': 'trusted', 'action.params.payment_ref': 'trusted' };

addProv('clean', 'Every declared ref is server-vouched (first_party / trusted): pass.', P(), { outcome: 'pass', labels: T });
addProv('join', 'offer_id declared from a first-party and a web ref: the join is web (the least trusted wins); a tainted material value is a tap-tier question.', P({ 'action.params.offer_id': ['skyair:offer_set:1', 'web:skyair.example/results#ad-3'] }), { outcome: 'question', friction: 'tap', labels: { ...T, 'action.params.offer_id': 'web' } });
addProv('unknown-ref', 'A ref the registry does not vouch for is agent.', P({ 'action.params.offer_id': ['made-up'] }), { outcome: 'question', labels: { ...T, 'action.params.offer_id': 'agent' } });
addProv('proto-ref', 'Refs named "__proto__" / "constructor" / "toString" are not registry entries (own entries only): agent.', P({ 'action.params.offer_id': ['__proto__', 'constructor', 'toString'] }), { outcome: 'question', labels: { ...T, 'action.params.offer_id': 'agent' } });
addProv('undeclared-critical', 'A critical parameter the action carries but prov omits is agent: a typed-tier question by default.', (() => { const p = P(); delete p.prov['action.params.payment_ref']; return p; })(), { outcome: 'question', friction: 'typed', labels: { ...T, 'action.params.payment_ref': 'agent' } });
addProv('no-prov', 'No prov member at all: every material and critical parameter the action carries is agent.', { ...P(), prov: undefined }, { outcome: 'question', friction: 'typed', labels: { 'action.params.add_ons': 'agent', 'action.params.offer_id': 'agent', 'action.params.passport': 'agent', 'action.params.payment_ref': 'agent' } });
addProv('undeclared-absent-param', 'A policy parameter the action does not carry is not classified.', P({}, { params: { ...POLICY.params, 'action.params.seat': 'material' } }), { outcome: 'pass', labels: T });
addProv('free-param-declared', 'A declared parameter that is not material or critical is classified but never gates.', P({ 'action.params.note': ['web:skyair.example/results#ad-3'] }), { outcome: 'pass', labels: { ...T, 'action.params.note': 'web' } });
addProv('object-param', 'A parameter whose value is an object (action.params.pax) is classified like any other.', P({ 'action.params.pax': ['wallet:profile:ana'] }), { outcome: 'pass', labels: { ...T, 'action.params.pax': 'trusted' } });
addProv('material-question-typed', 'material_tainted question_typed: a web add-on is a typed-tier question.', P({ 'action.params.add_ons': ['web:skyair.example/results#ad-3'] }, { material_tainted: 'question_typed' }), { outcome: 'question', friction: 'typed' });
addProv('material-allow', 'material_tainted allow: a web add-on passes.', P({ 'action.params.add_ons': ['web:skyair.example/results#ad-3'] }, { material_tainted: 'allow' }), { outcome: 'pass' });
addProv('critical-question', 'critical_tainted question: a tool payment_ref is a tap-tier question.', P({ 'action.params.payment_ref': ['tool:fx'] }, { critical_tainted: 'question' }), { outcome: 'question', friction: 'tap' });
addProv('critical-max-within', 'critical_max tool: a tool payment_ref is within the cap (still a tainted-value question).', P({ 'action.params.payment_ref': ['tool:fx'] }, { critical_max: 'tool' }), { outcome: 'question', friction: 'typed' });
addProv('label-first-party', 'A committed receipt from this site whose value digest matches: first_party; the class attaches; flowing back to its origin is allowed.', P({}, {}, withLabel(PASSPORT, 'travellers[0].passport')), { outcome: 'pass', labels: { ...T, 'action.params.passport': 'first_party' } });
addProv('label-mismatch', 'The value is not the labelled value: agent (the receipt does not vouch for it), but the class still attaches.', { ...P({}, {}, withLabel(PASSPORT, 'travellers[0].passport')), action: { params: { ...PARAMS, passport: 'Y7654321' } } }, { outcome: 'question', labels: { ...T, 'action.params.passport': 'agent' } });
addProv('label-foreign-flow-allowed', 'A receipt from another site (tool level); a flow rule pii.* lists this audience.', P({}, { flows: { 'pii.*': [AUD] } }, withLabel(GOVR, 'passport')), { outcome: 'question', friction: 'typed', labels: { ...T, 'action.params.passport': 'tool' } });
addProv('label-foreign-public', 'A public-class field may flow anywhere without a rule.', (() => {
  const pub = receipt('gov.example', GOV, 'g1', { passport: { class: 'public', value_digest: pca.hashCanonical('X1234567') } });
  return P({}, {}, withLabel(pub, 'passport'));
})(), { outcome: 'question', labels: { ...T, 'action.params.passport': 'tool' } });
addProv('label-flow-star', 'A "*" flow rule listing this audience allows any class.', P({}, { flows: { '*': [AUD] } }, withLabel(GOVR, 'passport')), { outcome: 'question' });
addProv('label-and-ref', 'A label ref joined with a trusted registry ref: the join of first_party and trusted is first_party.', { ...P({}, {}, withLabel(PASSPORT, 'travellers[0].passport')), prov: { ...CLEAN, 'action.params.passport': [lref(PASSPORT, 'travellers[0].passport'), 'wallet:profile:ana'] } }, { outcome: 'pass', labels: { ...T, 'action.params.passport': 'first_party' } });

const PD = (name, description, input, meta) => addProv(name, description + ' Denied.', input, 'deny', meta);
PD('critical-max', 'critical_max first_party: a tool payment_ref is a hard deny.', P({ 'action.params.payment_ref': ['tool:fx'] }, { critical_max: 'first_party' }));
PD('critical-max-agent', 'critical_max trusted: an undeclared (agent) passport is a hard deny.', (() => { const p = P({}, { critical_max: 'trusted' }); delete p.prov['action.params.passport']; return p; })());
PD('material-deny', 'material_tainted deny: a web add-on is denied.', P({ 'action.params.add_ons': ['web:skyair.example/results#ad-3'] }, { material_tainted: 'deny' }));
PD('critical-deny', 'critical_tainted deny: a tool payment_ref is denied.', P({ 'action.params.payment_ref': ['tool:fx'] }, { critical_tainted: 'deny' }));
PD('flow-no-rule', 'A pii.identity value labelled by gov.example may not reach skyair.example without a flow rule.', P({}, {}, withLabel(GOVR, 'passport')));
PD('flow-most-specific', 'pii.* lists this audience but the more specific pii.identity rule does not.', P({}, { flows: { 'pii.*': [AUD], 'pii.identity': ['elsewhere.example'] } }, withLabel(GOVR, 'passport')));
PD('label-uncommitted', 'A label ref whose receipt the PCActn does not commit.', { ...P({}, {}, withLabel(PASSPORT, 'travellers[0].passport')), committed_labels: [] });
PD('label-not-supplied', 'A committed receipt that was not supplied.', { ...P({}, {}, withLabel(PASSPORT, 'travellers[0].passport')), labels: [] });
PD('label-bad-signature', 'A receipt signed by another key under a pinned (site, kid).', (() => { const bad = receipt(AUD, ROGUE, 'k1', PASSPORT.fields); return P({}, {}, withLabel(bad, 'travellers[0].passport')); })());
PD('label-unpinned', 'A receipt whose (site, kid) is not pinned.', (() => { const r = receipt(AUD, SITE, 'k9', PASSPORT.fields); return P({}, {}, withLabel(r, 'travellers[0].passport')); })());
PD('label-other-session', 'A receipt bound to another session.', (() => { const r = receipt(AUD, SITE, 'k1', PASSPORT.fields, OTHER_SESSION); return P({}, {}, withLabel(r, 'travellers[0].passport')); })());
PD('label-unknown-field', 'A label ref naming a field the receipt does not contain.', P({}, {}, withLabel(PASSPORT, 'travellers[1].passport')));
PD('label-ref-malformed', 'A pca-labels: ref whose receipt part is not a 32-byte digest.', P({ 'action.params.passport': ['pca-labels:abc#passport'] }));
PD('label-ref-no-field', 'A pca-labels: ref without "#field".', P({ 'action.params.passport': [`pca-labels:${pca.labelsRef(PASSPORT)}`] }, {}, { committed_labels: [pca.labelsRef(PASSPORT)], labels: [PASSPORT] }));
PD('label-receipt-extra-member', 'A receipt with an unknown member (closed set): malformed, unmatched.', (() => { const r = { ...PASSPORT, note: 'x' }; return { ...P({}, {}, { committed_labels: [pca.labelsRef(r)], labels: [r] }), prov: { ...CLEAN, 'action.params.passport': [lref(r, 'travellers[0].passport')] } }; })());
PD('prov-not-carried', 'prov names a parameter the action does not carry.', P({ 'action.params.seat': ['wallet:profile:ana'] }));
PD('prov-nested-path', 'A prov key with two segments (action.params.pax.lead): only action.params.<name> is allowed.', P({ 'action.params.pax.lead': ['wallet:profile:ana'] }));
PD('prov-hyphen', 'A prov key with a hyphen in the name.', P({ 'action.params.add-ons': ['wallet:profile:ana'] }, {}, { action: { params: { ...PARAMS, 'add-ons': 'x' } } }));
PD('prov-empty-refs', 'A prov path with no refs.', P({ 'action.params.offer_id': [] }));
PD('prov-nine-refs', 'A prov path with 9 refs (max 8).', P({ 'action.params.offer_id': Array.from({ length: 9 }, (_, i) => `r${i}`) }));
PD('prov-ref-empty-string', 'An empty ref.', P({ 'action.params.offer_id': [''] }));
PD('prov-ref-257-bytes', 'A ref of 257 UTF-8 bytes.', P({ 'action.params.offer_id': ['x'.repeat(257)] }));
PD('prov-not-param-path', 'A prov key outside action.params.', P({ 'env.world.x': ['wallet:profile:ana'] }));
PD('prov-proto-name', 'A prov key action.params.__proto__ (a prototype name is refused even though it matches the character class).', P({ 'action.params.__proto__': ['wallet:profile:ana'] }));
PD('prov-constructor-name', 'A prov key action.params.constructor, with the action carrying an own "constructor" parameter.', P({ 'action.params.constructor': ['wallet:profile:ana'] }, {}, { action: { params: { ...PARAMS, constructor: 'x' } } }));
PD('prov-not-object', 'prov is an array.', { ...P(), prov: [] });
PD('prov-33-paths', 'prov with 33 paths (max 32).', { ...P(), action: { params: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`p${i}`, i])) }, prov: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`action.params.p${i}`, ['x']])), policy: { params: {} } });
PD('labels-duplicate', 'The same receipt digest committed twice.', { ...P({}, {}, withLabel(PASSPORT, 'travellers[0].passport')), committed_labels: [pca.labelsRef(PASSPORT), pca.labelsRef(PASSPORT)] });
PD('policy-bad-level', 'A registry entry with an unknown level: misconfigured.', P({}, { registry: { x: 'super' } }));
PD('policy-bad-critical-max', 'critical_max is not a level: misconfigured.', P({}, { critical_max: 'none' }));
PD('policy-critical-allow', 'critical_tainted allow is not a valid mode: misconfigured.', P({}, { critical_tainted: 'allow' }));
PD('policy-bad-flow', 'A flow pattern that is not a class: misconfigured.', P({}, { flows: { 'PII!': [AUD] } }));

// prototype-named parameters, label fields and data classes
addProv('proto-param', 'A parameter named valueOf (a legal name): classified like any other.', P({ 'action.params.valueOf': ['wallet:profile:ana'] }, {}, { action: { params: { ...PARAMS, valueOf: 'x' } } }), { outcome: 'pass', labels: { ...T, 'action.params.valueOf': 'trusted' } });
const PROTO_FIELD = receipt(AUD, SITE, 'k1', { ['__proto__']: { class: 'constructor', value_digest: pca.hashCanonical('X1234567') } });
addProv('proto-label-field', 'A receipt field named __proto__ with class constructor (an own key; the value flows back to its origin): first_party.', P({}, {}, withLabel(PROTO_FIELD, '__proto__')), { outcome: 'pass', labels: { ...T, 'action.params.passport': 'first_party' } });
const GOV_PROTO = receipt('gov.example', GOV, 'g1', { passport: { class: 'constructor', value_digest: pca.hashCanonical('X1234567') } });
PD('proto-class-no-rule', 'A foreign value of class constructor with no flow rule: denied (no inherited member may act as a rule).', P({}, {}, withLabel(GOV_PROTO, 'passport')));
addProv('proto-class-rule', 'A foreign value of class constructor with a flow rule named constructor listing this audience: allowed (tool, question).', P({}, { flows: { constructor: [AUD] } }, withLabel(GOV_PROTO, 'passport')), { outcome: 'question', labels: { ...T, 'action.params.passport': 'tool' } });
PD('proto-field-missing', 'A label ref naming field toString, which the receipt does not own.', P({}, {}, withLabel(PASSPORT, 'toString')));

// ---- absent vs null
for (const k of ['prov', 'committed_labels', 'labels']) PD(`null-${k.replace('_', '-')}`, `${k} is null.`, { ...P(), [k]: null });
PD('null-params', 'action.params is null.', { ...P(), action: { params: null } });
PD('null-policy', 'policy is null.', { ...P(), policy: null });
for (const k of ['registry', 'label_keys', 'critical_max', 'material_tainted', 'critical_tainted', 'flows']) PD(`null-policy-${k.replace(/_/g, '-')}`, `policy.${k} is null.`, P({}, { [k]: null }));
PD('null-label-key-pq-pk', 'A pinned label key with pq_pk null.', P({}, { label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk, pq_pk: null }] }));
PD('string-labels', 'labels (the supplied list) is a string.', { ...P(), labels: 'abc' });
addProv('absent-policy-members', 'A policy with only params: every other member absent = default (no registry: every ref is agent).', P({}, {}, { policy: { params: POLICY.params } }), { outcome: 'question', friction: 'typed', labels: { 'action.params.add_ons': 'agent', 'action.params.offer_id': 'agent', 'action.params.passport': 'agent', 'action.params.payment_ref': 'agent' } });
// ---- suite capability
PD('label-alg-unsupported', `A committed receipt naming the suite "${UNSUPPORTED}".`, (() => { const r = withAlg(PASSPORT, UNSUPPORTED); return P({}, {}, withLabel(r, 'travellers[0].passport')); })(), { reason_contains: 'unsupported_suite' });
PD('label-alg-null', 'A committed receipt whose alg is null (malformed).', (() => { const r = withAlg(PASSPORT, null); return P({}, {}, withLabel(r, 'travellers[0].passport')); })());
if (!SKIP_PQ) {
  const pqReceipt = signPq(pca.LABELS_DOMAIN, { v: 1, kind: 'pca-labels', site: AUD, session: SESSION, response_digest: pca.b64u(seed('wb/response')), fields: PASSPORT.fields, issued_at: NOW - 5_000, kid: 'k1' }, SITE.sk, 'ml-dsa-65');
  addProv('label-ml-dsa-65', 'An ML-DSA-65 receipt under the pinned PQ key: first_party.', P({}, { label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk, pq_pk: ML_PK }] }, withLabel(pqReceipt, 'travellers[0].passport')), { outcome: 'pass', labels: { ...T, 'action.params.passport': 'first_party' } }, { requires_suite: 'ml-dsa-65' });
  PD('label-ml-dsa-65-unpinned', 'An ML-DSA-65 receipt whose pinned key names no PQ key.', P({}, {}, withLabel(pqReceipt, 'travellers[0].passport')), { requires_suite: 'ml-dsa-65' });
}

// ---- closed and typed policies
PD('policy-unknown-member', 'The provenance policy carries an unknown member.', P({}, { extra: 1 }));
PD('label-key-unknown-member', 'A pinned label key carries an unknown member.', P({}, { label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk, alg: 'ed25519' }] }));
PD('critical-max-number', 'critical_max is a number.', P({}, { critical_max: 1 }));
PD('material-tainted-boolean', 'material_tainted is a boolean.', P({}, { material_tainted: true }));

// ------------------------------------------------------------------ rule 18: primitives.intent_classifier
const cls = [];
function addCls(name, description, input, must, meta = {}) {
  const r = pca.decideClassifierDimensions(clone(input));
  const m = metaOf('wb18-' + name, r, meta);
  const expect = r.ok ? { ok: true, classes: r.classes } : { ok: false, ...m.exp };
  const ok = must === 'deny' ? r.ok === false : r.ok === true && JSON.stringify(r.classes) === JSON.stringify(must);
  if (!ok) throw new Error(`intent_classifier wb18-${name}: reference ${JSON.stringify(r)} does not meet ${JSON.stringify(must)}`);
  cls.push({ name: 'wb18-' + name, description, ...m.top, input: clone(input), expect });
}
const MESSAGE = 'We are sorry for the delay.';
const TONE = { id: 'tone', param: 'action.params.body', labels: ['neutral', 'apologetic', 'hostile', 'other'], keys: J.map((j) => j.pk), k: 2, measurements: ['m-tone-1'] };
const verdict = (j, label, over = {}) => pca.signClassifierVerdict({ classifier: 'tone', session: SESSION, content_digest: pca.classifierContentDigest(MESSAGE), label, measurement: 'm-tone-1', ...over }, j.sk);
const C = (verdicts, policyOver = {}, over = {}) => ({ session: SESSION, action: { params: { body: MESSAGE } }, committed: verdicts.map(pca.classifierVerdictRef), verdicts, policy: { classifiers: [{ ...TONE, ...policyOver }] }, ...over });

addCls('quorum', 'Two of three allowlisted judges agree on apologetic (k = 2); the third says neutral.', C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic'), verdict(J[2], 'neutral')]), { tone: 'apologetic' });
addCls('k1', 'k = 1 with a single verdict.', C([verdict(J[0], 'neutral')], { k: 1 }), { tone: 'neutral' });
addCls('no-measurement-pin', 'No measurements pinned: any measurement string counts.', C([verdict(J[0], 'neutral', { measurement: 'anything' }), verdict(J[1], 'neutral', { measurement: 'else' })], { measurements: undefined }), { tone: 'neutral' });
addCls('no-classifiers', 'No classifier declared and nothing committed: ok, no classes.', { session: SESSION, action: { params: {} }, committed: [], verdicts: [], policy: { classifiers: [] } }, {});
addCls('structured-content', 'The classified parameter is an object: the content digest is over its strict canonical form.', (() => {
  const body = { b: 'x', a: [1, 2] };
  const v = (j) => pca.signClassifierVerdict({ classifier: 'tone', session: SESSION, content_digest: pca.classifierContentDigest(body), label: 'neutral', measurement: 'm-tone-1' }, j.sk);
  const vs = [v(J[0]), v(J[1])];
  return { ...C(vs), action: { params: { body } } };
})(), { tone: 'neutral' });

const CD = (name, description, input, meta) => addCls(name, description + ' Refused.', input, 'deny', meta);
CD('no-quorum', 'Two judges disagree with k = 2.', C([verdict(J[0], 'apologetic'), verdict(J[1], 'neutral')]));
CD('ambiguous', 'Two labels each reach k = 1.', C([verdict(J[0], 'apologetic'), verdict(J[1], 'neutral')], { k: 1 }));
CD('off-allowlist', 'One of the two agreeing verdicts is by a key not on the allowlist.', C([verdict(J[0], 'apologetic'), verdict(ROGUE, 'apologetic')]));
CD('bad-signature', 'A verdict whose label was changed after signing (the commitment covers the tampered bytes).', C([verdict(J[0], 'neutral'), { ...verdict(J[1], 'apologetic'), label: 'neutral' }]));
CD('other-session', 'A verdict bound to another session.', C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic', { session: OTHER_SESSION })]));
CD('other-content', 'A verdict about other content.', C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic', { content_digest: pca.classifierContentDigest('other text') })]));
CD('label-outside-set', 'A verdict label outside the classifier label set.', C([verdict(J[0], 'apologetic'), verdict(J[1], 'sarcastic')]));
CD('measurement-unpinned', 'A verdict measurement that is not pinned.', C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic', { measurement: 'm-evil' })]));
CD('double-vote', 'One judge votes twice (different labels), plus one agreeing judge.', C([verdict(J[0], 'apologetic'), verdict(J[0], 'neutral'), verdict(J[1], 'apologetic')]));
CD('uncommitted-not-counted', 'Two verdicts supplied, one committed: one vote < k.', { ...C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic')]), committed: [pca.classifierVerdictRef(verdict(J[0], 'apologetic'))] });
CD('committed-not-supplied', 'Two committed, one supplied.', { ...C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic')]), verdicts: [verdict(J[0], 'apologetic')] });
CD('committed-duplicate', 'One digest committed twice.', { ...C([verdict(J[0], 'apologetic')]), committed: [pca.classifierVerdictRef(verdict(J[0], 'apologetic')), pca.classifierVerdictRef(verdict(J[0], 'apologetic'))] });
CD('committed-nine', 'Nine committed digests (max 8).', { ...C([verdict(J[0], 'apologetic')]), committed: Array.from({ length: 9 }, (_, i) => pca.b64u(seed(`wb/c${i}`))) });
CD('verdict-extra-member', 'A verdict with an unknown member (closed set).', (() => { const v = { ...verdict(J[0], 'apologetic'), note: 'x' }; return C([v, verdict(J[1], 'apologetic')]); })());
CD('undeclared-classifier', 'A verdict for a classifier the policy does not declare.', C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic'), verdict(J[2], 'x', { classifier: 'spam' })]));
CD('param-missing', 'The classified parameter is absent from the action.', { ...C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic')]), action: { params: {} } });
CD('policy-k-too-big', 'k greater than the number of keys: misconfigured.', C([verdict(J[0], 'apologetic')], { k: 4 }));
CD('policy-duplicate-labels', 'A label set with a duplicate: misconfigured.', C([verdict(J[0], 'apologetic')], { labels: ['a', 'a'] }));
CD('declared-none-committed', 'A declared classifier with no committed verdict: no quorum.', C([]));

// prototype-named classifier ids and labels (tallies must be prototype-free)
const PROTO_LABELS = ['constructor', '__proto__', 'toString', 'valueOf', 'hasOwnProperty'];
const protoVerdict = (j, label) => pca.signClassifierVerdict({ classifier: 'constructor', session: SESSION, content_digest: pca.classifierContentDigest(MESSAGE), label, measurement: 'm-tone-1' }, j.sk);
const PC = (verdicts, over = {}) => ({ session: SESSION, action: { params: { body: MESSAGE } }, committed: verdicts.map(pca.classifierVerdictRef), verdicts, policy: { classifiers: [{ ...TONE, id: 'constructor', labels: PROTO_LABELS, ...over }] } });
for (const label of PROTO_LABELS) {
  addCls(`proto-label-${label.replace(/_/g, '')}`, `Classifier id constructor, two judges agree on the label ${label} (k = 2): an ordinary label and id.`, PC([protoVerdict(J[0], label), protoVerdict(J[1], label)]), { constructor: label });
}
CD('proto-label-split', 'Classifier constructor: one vote for __proto__, one for constructor (k = 2): no quorum.', PC([protoVerdict(J[0], '__proto__'), protoVerdict(J[1], 'constructor')]));
CD('proto-label-undeclared', 'A verdict label hasOwnProperty that the label set does not declare (labels without it).', PC([protoVerdict(J[0], 'hasOwnProperty'), protoVerdict(J[1], 'hasOwnProperty')], { labels: ['constructor', 'toString'] }));

// ---- absent vs null
CD('null-committed', 'committed is null.', { ...C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic')]), committed: null });
CD('null-verdicts', 'verdicts is null.', { ...C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic')]), verdicts: null });
CD('null-params', 'action.params is null.', { ...C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic')]), action: { params: null } });
CD('null-measurements', 'measurements is null (absent would mean no pin).', C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic')], { measurements: null }));
CD('null-pq-keys', 'pq_keys is null.', C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic')], { pq_keys: null }));
CD('null-policy', 'policy is null.', { ...C([verdict(J[0], 'apologetic')]), policy: null });
CD('absent-committed', 'No committed member and a declared classifier: absent = [] (the refusal is the missing quorum, not the shape).', (() => { const i = C([]); delete i.committed; return i; })());
addCls('absent-measurements', 'measurements absent: no measurement pin (any measurement counts).', C([verdict(J[0], 'apologetic', { measurement: 'x' }), verdict(J[1], 'apologetic', { measurement: 'y' })], { measurements: undefined }), { tone: 'apologetic' });
// ---- suite capability
CD('verdict-alg-unsupported', `A committed verdict naming the suite "${UNSUPPORTED}".`, C([verdict(J[0], 'apologetic'), withAlg(verdict(J[1], 'apologetic'), UNSUPPORTED)]), { reason_contains: 'unsupported_suite' });
CD('verdict-alg-number', 'A committed verdict whose alg is a number (malformed).', C([verdict(J[0], 'apologetic'), withAlg(verdict(J[1], 'apologetic'), 1)]));
if (!SKIP_PQ) {
  const pqV = signPq(pca.INTENT_CLASSIFIER_DOMAIN, { v: 1, kind: 'pca-intent-classification', classifier: 'tone', session: SESSION, content_digest: pca.classifierContentDigest(MESSAGE), label: 'apologetic', measurement: 'm-tone-1', judge: J[1].pk }, J[1].sk, 'ml-dsa-65');
  addCls('verdict-ml-dsa-65', 'An ML-DSA-65 verdict under the PQ key pq_keys pins for its judge, plus an Ed25519 verdict: quorum.', C([verdict(J[0], 'apologetic'), pqV], { pq_keys: { [J[1].pk]: ML_PK } }), { tone: 'apologetic' }, { requires_suite: 'ml-dsa-65' });
  CD('verdict-ml-dsa-65-unpinned', 'An ML-DSA-65 verdict with no PQ key pinned for its judge.', C([verdict(J[0], 'apologetic'), pqV]), { requires_suite: 'ml-dsa-65' });
}

// ---- closed and typed policies
CD('policy-unknown-member', 'The classifier policy carries a member other than classifiers.', { ...C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic')]), policy: { classifiers: [TONE], extra: [] } });
CD('classifier-unknown-member', 'A classifier entry carries an unknown member.', C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic')], { quorum: 2 }));
CD('k-string', 'k is the numeric string "2".', C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic')], { k: '2' }));
CD('k-fraction', 'k is 1.5.', C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic')], { k: 1.5 }));

// ------------------------------------------------------------------ activity: primitives.intent_wb_active
const active = [];
function addActive(name, description, input, want) {
  const r = pca.intentWBActive(clone(input));
  if (JSON.stringify(r) !== JSON.stringify(want)) throw new Error(`intent_wb_active wbact-${name}: reference ${JSON.stringify(r)} != ${JSON.stringify(want)}`);
  active.push({ name: 'wbact-' + name, description, input: clone(input), expect: r });
}
const D32 = pca.b64u(seed('wb/active'));
const NONE = { facts: false, provenance: false, classes: false };
addActive('empty', 'No member, no policy: nothing is reported.', { intent_session: {}, policy: {} }, NONE);
addActive('facts-list', 'committed facts is a non-empty array.', { intent_session: { facts: [D32] }, policy: {} }, { ...NONE, facts: true });
addActive('facts-empty', 'committed facts is an empty array.', { intent_session: { facts: [] }, policy: {} }, NONE);
addActive('facts-object-length', 'committed facts is an object with its own length member: not an array, not active.', { intent_session: { facts: { length: 1, 0: D32 } }, policy: {} }, NONE);
addActive('offer-set-string', 'offer_set is a string.', { intent_session: { offer_set: D32 }, policy: {} }, { ...NONE, facts: true });
addActive('offer-set-object', 'offer_set is an object: not a string, not active.', { intent_session: { offer_set: { length: 43 } }, policy: {} }, NONE);
addActive('worlds-list', 'policy.world.worlds is a non-empty array.', { intent_session: {}, policy: { world: { worlds: [{ name: 'x' }] } } }, { ...NONE, facts: true });
addActive('worlds-object-length', 'policy.world.worlds is an object with a length member: not active.', { intent_session: {}, policy: { world: { worlds: { length: 2 }, relational: { length: 1 } } } }, NONE);
addActive('offers-object', 'policy.world.offers is an object.', { intent_session: {}, policy: { world: { offers: {} } } }, { ...NONE, facts: true });
addActive('offers-array', 'policy.world.offers is an array: not a plain object, not active.', { intent_session: {}, policy: { world: { offers: [] } } }, NONE);
addActive('prov-present', 'prov is present (even empty): reported, so a malformed prov is refused rather than skipped.', { intent_session: { prov: {} }, policy: {} }, { ...NONE, provenance: true });
addActive('prov-null', 'prov is null: present, reported (rule 17 then refuses it).', { intent_session: { prov: null }, policy: {} }, { ...NONE, provenance: true });
addActive('labels-list', 'labels is a non-empty array.', { intent_session: { labels: [D32] }, policy: {} }, { ...NONE, provenance: true });
addActive('labels-object-length', 'labels is an object with a length member: not active.', { intent_session: { labels: { length: 1 } }, policy: {} }, NONE);
addActive('provenance-policy', 'A provenance policy object.', { intent_session: {}, policy: { provenance: { params: {} } } }, { ...NONE, provenance: true });
addActive('provenance-policy-array', 'A provenance policy that is an array: not active.', { intent_session: {}, policy: { provenance: [] } }, NONE);
addActive('classes-list', 'classes is a non-empty array.', { intent_session: { classes: [D32] }, policy: {} }, { ...NONE, classes: true });
addActive('classes-object-length', 'classes is an object with a length member: not active.', { intent_session: { classes: { length: 1 } }, policy: {} }, NONE);
addActive('classifiers-list', 'policy.classifiers is a non-empty array.', { intent_session: {}, policy: { classifiers: [{ id: 'tone' }] } }, { ...NONE, classes: true });
addActive('classifiers-object-length', 'policy.classifiers is an object with a length member: not active.', { intent_session: {}, policy: { classifiers: { length: 3 } } }, NONE);
addActive('null-members', 'facts, offer_set, labels, classes null and the policy containers null: none is a non-empty array, a string or an object; prov null is present.', { intent_session: { facts: null, offer_set: null, labels: null, classes: null, prov: null }, policy: { world: null, provenance: null, classifiers: null } }, { ...NONE, provenance: true });
addActive('null-world-members', 'policy.world members null: not active.', { intent_session: {}, policy: { world: { worlds: null, relational: null, offers: null } } }, NONE);
addActive('absent-policy', 'No policy member at all.', { intent_session: { classes: [D32] } }, { ...NONE, classes: true });
addActive('all', 'Every member present.', { intent_session: { facts: [D32], prov: {}, classes: [D32] }, policy: {} }, { facts: true, provenance: true, classes: true });

// ------------------------------------------------------------------ V14 read purpose: primitives.intent_read_purpose
const readPurpose = [];
function addRead(name, description, input, want) {
  const i = clone(input);
  const r = pca.decideReadPurpose(i.fields, i.purpose, i.coverage, ...(i.on_uncovered !== undefined ? [i.on_uncovered] : []));
  if (JSON.stringify(r) !== JSON.stringify(want)) throw new Error(`intent_read_purpose wbread-${name}: reference ${JSON.stringify(r)} != ${JSON.stringify(want)}`);
  readPurpose.push({ name: 'wbread-' + name, description, input: clone(input), expect: r });
}
const COVER = { booking: ['pii.identity', 'itinerary'], support: ['pii.*', 'internal'], comparison: [] };
const FIELDS = [
  { path: 'passengers[].name', class: 'pii.identity' },
  { path: 'passengers[].email', class: 'pii.contact', optional: true },
  { path: 'loyalty', class: 'internal', optional: true },
  { path: 'fares', class: 'public' },
];
addRead('booking', 'Booking covers pii.identity: optional uncovered fields are minimised (sorted), public always passes.', { fields: FIELDS, purpose: 'booking', coverage: COVER }, { outcome: 'allow', minimise: ['loyalty', 'passengers[].email'], uncovered: [] });
addRead('support-prefix', 'Support covers pii.* and internal.', { fields: FIELDS, purpose: 'support', coverage: COVER }, { outcome: 'allow', minimise: [], uncovered: [] });
addRead('comparison-question', 'Comparison covers nothing: the required pii.identity field makes the read a question.', { fields: FIELDS, purpose: 'comparison', coverage: COVER }, { outcome: 'question', minimise: ['loyalty', 'passengers[].email'], uncovered: ['passengers[].name'] });
addRead('comparison-deny', 'Same with on_uncovered deny.', { fields: FIELDS, purpose: 'comparison', coverage: COVER, on_uncovered: 'deny' }, { outcome: 'deny', minimise: ['loyalty', 'passengers[].email'], uncovered: ['passengers[].name'] });
addRead('unknown-purpose', 'An unknown purpose covers nothing but public.', { fields: FIELDS, purpose: 'nope', coverage: COVER }, { outcome: 'question', minimise: ['loyalty', 'passengers[].email'], uncovered: ['passengers[].name'] });
addRead('proto-purpose', 'Purpose "constructor": not an own coverage member, covers nothing but public.', { fields: FIELDS, purpose: 'constructor', coverage: COVER }, { outcome: 'question', minimise: ['loyalty', 'passengers[].email'], uncovered: ['passengers[].name'] });
// UTF-8 byte order vs UTF-16 order: U+FFFD (EF BF BD) sorts BEFORE U+1F600 (F0 9F 98 80) in UTF-8 bytes, but AFTER it in
// UTF-16 code units (0xFFFD > 0xD83D). ASCII sorts first either way; U+00E9 (C3 A9) before both.
const MIXED = ['z\u{1F600}', 'z\uFFFD', 'z\u00E9', 'za', '\u{1F600}', '\uFFFD', 'a'];
addRead('utf8-order', 'Field paths mixing ASCII, BMP (U+00E9, U+FFFD) and non-BMP (U+1F600) characters: both lists are sorted in UTF-8 BYTE order (U+FFFD before U+1F600), never UTF-16 order.', {
  fields: MIXED.flatMap((p, i) => [{ path: p, class: 'secret', optional: i % 2 === 0 }, { path: p + '!', class: 'secret' }]),
  purpose: 'booking',
  coverage: COVER,
}, {
  outcome: 'question',
  minimise: ['a', 'z\u00E9', 'z\u{1F600}', '\u{1F600}'],
  uncovered: ['a!', 'za', 'za!', 'z\u00E9!', 'z\uFFFD', 'z\uFFFD!', 'z\u{1F600}!', '\uFFFD', '\uFFFD!', '\u{1F600}!'],
});
addRead('duplicates', 'A path listed twice appears once.', { fields: [{ path: 'x', class: 'secret' }, { path: 'x', class: 'secret' }], purpose: 'booking', coverage: COVER }, { outcome: 'question', minimise: [], uncovered: ['x'] });
const RD = (name, description, input) => addRead(name, description + ' Malformed: deny with empty lists.', input, { outcome: 'deny', minimise: [], uncovered: [] });
RD('null-fields', 'fields is null.', { fields: null, purpose: 'booking', coverage: COVER });
RD('null-coverage', 'coverage is null.', { fields: FIELDS, purpose: 'booking', coverage: null });
RD('null-purpose', 'purpose is null.', { fields: FIELDS, purpose: null, coverage: COVER });
RD('null-optional', 'A field with optional null (absent would mean required).', { fields: [{ path: 'x', class: 'secret', optional: null }], purpose: 'booking', coverage: COVER });
RD('coverage-string', 'A coverage entry that is a string, not an array.', { fields: FIELDS, purpose: 'booking', coverage: { booking: 'pii.*' } });
RD('bad-on-uncovered', 'on_uncovered is neither question nor deny.', { fields: FIELDS, purpose: 'booking', coverage: COVER, on_uncovered: 'allow' });

const file = readCore();
file.primitives = file.primitives ?? {};
file.primitives.intent_world = world;
file.primitives.intent_provenance = prov;
file.primitives.intent_classifier = cls;
file.primitives.intent_wb_active = active;
file.primitives.intent_read_purpose = readPurpose;
writeCore(file);
console.log(`intent W-B: ${world.length} intent_world, ${prov.length} intent_provenance, ${cls.length} intent_classifier, ${active.length} intent_wb_active, ${readPurpose.length} intent_read_purpose`);
