// Oracle: the intent map attestation and the intent anchor receipt of packages/pca/src/intent.ts (signIntentMapAttestation,
// verifyIntentMapAttestation, intentAnchorCommit, verifyIntentAnchor, their constants), TS reference. Writes out/ref-intent-attest.json.gz.
// Deterministic: Ed25519 and ML-DSA-65 sign deterministically, keys come from seed(label), every time is an argument.
// PORTING (fn(args) -> native entry point; compared by JSON value; a throw = the native throws; {"$num":..}; {"$bytes":{"$seed":label}} = the
// 32-byte Ed25519 secret sha256("atlas-pca-conformance/" + label); suite {alg, pqSeed} -> ML-DSA-65 from the seed; the string "$absent" = argument not given)
//   constants [] -> {INTENT_MAP_SIG_DOMAIN, INTENT_ANCHOR_DOMAIN, INTENT_ANCHOR_LOG, INTENT_ANCHOR_KINDS}
//   signIntentMapAttestation [map, secret, signedAt, suite|null] -> attestation | throws
//   verifyIntentMapAttestation [attestation, map|"$absent", opts|null] -> {ok, reason?}   opts {expectedSigner?, pqPins?} (pqPins: signer key -> pinned PQ key)
//   intentAnchorCommit [kind, digest] -> string
//   verifyIntentAnchor [receipt, guardianPublic, instanceId, pin|null] -> {ok, reason?}   pin {pqPins?}; a reason that starts with "malformed anchor receipt: " is engine text after the colon and is cut here
import { Oracle, refWrite, seed } from './lib.mjs';
import { adder, nul, flip } from './foundation.mjs';
const I: any = await import('../../../packages/pca/src/intent.ts');
const L: any = await import('../../../packages/pca/src/ledger.ts');
const PQ: any = await import('../../../packages/pca/src/pq.ts');
const { publicKeyOf } = await import('../../../packages/pca/src/keys.ts') as any;
const { b64u } = await import('../../../packages/pca/src/hash.ts') as any;
const o = new Oracle('intent-attest', 'tools/pca-audit/oracles/intent-attest.mts', 'TS-reference oracle for the intent map attestation and the intent anchor receipt.');
const suiteOf = (s: any) => (s == null ? undefined : s.alg === 'ed25519' ? { alg: s.alg } : { alg: s.alg, mlDsa: PQ.mlDsa65Keygen(s.pqSeed) });
const cut = (r: any) => (r && typeof r.reason === 'string' ? { ...r, reason: r.reason.replace(/^(malformed anchor receipt): .*$/s, '$1') } : r);
const REF: Record<string, (...a: any[]) => any> = {
  constants: () => ({ INTENT_MAP_SIG_DOMAIN: I.INTENT_MAP_SIG_DOMAIN, INTENT_ANCHOR_DOMAIN: I.INTENT_ANCHOR_DOMAIN, INTENT_ANCHOR_LOG: I.INTENT_ANCHOR_LOG, INTENT_ANCHOR_KINDS: [...I.INTENT_ANCHOR_KINDS] }),
  signIntentMapAttestation: (m, sk, at, su) => I.signIntentMapAttestation(m, sk, at, suiteOf(su)),
  verifyIntentMapAttestation: (a, m, op) => (m === '$absent' ? I.verifyIntentMapAttestation(a, undefined, nul(op) ?? {}) : I.verifyIntentMapAttestation(a, m, nul(op) ?? {})),
  intentAnchorCommit: (k, d) => I.intentAnchorCommit(k, d),
  verifyIntentAnchor: (r, g, i, pin) => cut(I.verifyIntentAnchor(r, g, i, nul(pin) ?? undefined)),
};
const add = adder(o, REF);
const SK = seed('ia/signer'), SK2 = seed('ia/signer2'), GK = seed('ia/guardian'), GK2 = seed('ia/guardian2'), PQS = seed('ia/pq'), PQS2 = seed('ia/pq2');
const PUB = b64u(publicKeyOf(SK)), PUB2 = b64u(publicKeyOf(SK2)), GPUB = b64u(publicKeyOf(GK)), GPUB2 = b64u(publicKeyOf(GK2));
const J = (x: any) => JSON.parse(JSON.stringify(x));
const D = (c: string) => Buffer.alloc(32, c).toString('base64url');
const T0 = 1_800_000_000_000;
const MAP = (over: any = {}) => ({ v: 1, kind: 'pca-intent-map', intent_ref: null, metrics: { fidelity_est_ppm: 900000, residual_risk_ppm: 1200 }, cells: { 'pay.refund': [1, 2] }, ...over });
const ML = { alg: 'ml-dsa-65', pqSeed: PQS }, HY = { alg: 'hybrid-ed25519-ml-dsa-65', pqSeed: PQS };

await add('constants', 'all', []);
// ---- sign
for (const [n, su] of [['ed', null], ['ed-explicit', { alg: 'ed25519' }], ['ml-dsa', ML], ['hybrid', HY], ['unknown-alg', { alg: 'rot13' }]] as any[]) await add('signIntentMapAttestation', n, [MAP(), SK, T0, su]);
const MAPS: [string, any][] = [['intent-ref', MAP({ intent_ref: D('r') })], ['extra-members', MAP({ note: 'é😀', nested: { b: [1, null], a: true } })], ['metrics-extra', MAP({ metrics: { fidelity_est_ppm: 0, residual_risk_ppm: 0, n: 5 } })], ['fidelity-max', MAP({ metrics: { fidelity_est_ppm: 1000000, residual_risk_ppm: 9007199254740991 } })],
  ['fidelity-over', MAP({ metrics: { fidelity_est_ppm: 1000001, residual_risk_ppm: 0 } })], ['fidelity-neg', MAP({ metrics: { fidelity_est_ppm: -1, residual_risk_ppm: 0 } })], ['fidelity-frac', MAP({ metrics: { fidelity_est_ppm: 0.5, residual_risk_ppm: 0 } })], ['risk-neg', MAP({ metrics: { fidelity_est_ppm: 1, residual_risk_ppm: -1 } })],
  ['risk-string', MAP({ metrics: { fidelity_est_ppm: 1, residual_risk_ppm: '1' } })], ['metrics-missing', (({ metrics, ...r }: any) => r)(MAP())], ['metrics-array', MAP({ metrics: [] })], ['v-2', MAP({ v: 2 })], ['kind-wrong', MAP({ kind: 'x' })], ['intent-ref-short', MAP({ intent_ref: 'AAAA' })],
  ['intent-ref-number', MAP({ intent_ref: 5 })], ['intent-ref-missing', (({ intent_ref, ...r }: any) => r)(MAP())], ['null', null], ['array', []], ['string', 'x'], ['neg-zero-member', MAP({ z: -0 })], ['nan-member', MAP({ z: { $num: 'NaN' } })]];
for (const [n, m] of MAPS) await add('signIntentMapAttestation', 'map-' + n, [m, SK, T0, null]);
for (const [n, at] of [['zero', 0], ['max', 9007199254740991], ['over', 9007199254740992], ['neg', -1], ['frac', 1.5], ['neg-zero', -0], ['nan', { $num: 'NaN' }], ['string', '5'], ['null', null]] as any[]) await add('signIntentMapAttestation', 'at-' + n, [MAP(), SK, at, null]);
await add('signIntentMapAttestation', 'other-signer', [MAP(), SK2, T0 + 1, null]);

// ---- verify
const sg = (m: any = MAP(), su: any = null, sk = SK, at = T0) => J(I.signIntentMapAttestation(m, sk, at, suiteOf(su)));
const A0 = sg(), AR = sg(MAP({ intent_ref: D('r') })), AP = sg(MAP(), ML), AH = sg(MAP(), HY);
const PQPUB = AP.pq_pk, PQPUB2 = sg(MAP(), { alg: 'ml-dsa-65', pqSeed: PQS2 }).pq_pk;
const V = (n: string, a: any, m: any = '$absent', op: any = null) => add('verifyIntentMapAttestation', n, [a, m, op]);
await V('ok', A0); await V('ok-with-map', A0, MAP()); await V('ok-intent-ref', AR, MAP({ intent_ref: D('r') })); await V('ok-expected-signer', A0, MAP(), { expectedSigner: PUB });
await V('expected-signer-mismatch', A0, '$absent', { expectedSigner: PUB2 }); await V('map-other', A0, MAP({ cells: {} })); await V('map-intent-ref-mismatch', { ...A0 }, MAP({ intent_ref: D('r') }));
await V('map-null', A0, null); await V('map-invalid', A0, MAP({ v: 2 })); await V('map-string', A0, 'x');
await V('pq-pinned', AP, MAP(), { pqPins: { [PUB]: PQPUB } }); await V('pq-unpinned', AP, MAP()); await V('pq-pinned-other-key', AP, MAP(), { pqPins: { [PUB]: PQPUB2 } }); await V('pq-pin-for-other-signer', AP, MAP(), { pqPins: { [PUB2]: PQPUB } });
await V('hybrid-pinned', AH, MAP(), { pqPins: { [PUB]: PQPUB } }); await V('hybrid-unpinned', AH, MAP()); await V('hybrid-pq-sig-flip', { ...AH, pq_sig: flip(AH.pq_sig) }, MAP(), { pqPins: { [PUB]: PQPUB } });
await V('hybrid-stripped-to-ed', (({ alg, pq_pk, pq_sig, ...r }: any) => r)(AH), MAP());
const MUT: [string, (a: any) => any][] = [['sig-flip', (a) => ({ ...a, sig: flip(a.sig) })], ['sig-missing', ({ sig, ...r }) => r], ['sig-number', (a) => ({ ...a, sig: 5 })], ['digest-other', (a) => ({ ...a, map_digest: D('x') })], ['digest-short', (a) => ({ ...a, map_digest: 'AAAA' })],
  ['digest-missing', ({ map_digest, ...r }) => r], ['intent-ref-set', (a) => ({ ...a, intent_ref: D('r') })], ['intent-ref-bad', (a) => ({ ...a, intent_ref: 'x' })], ['intent-ref-missing', ({ intent_ref, ...r }) => r], ['signer-other', (a) => ({ ...a, signer: PUB2 })],
  ['signer-short', (a) => ({ ...a, signer: 'AAAA' })], ['signed-at-other', (a) => ({ ...a, signed_at: a.signed_at + 1 })], ['signed-at-neg', (a) => ({ ...a, signed_at: -1 })], ['signed-at-frac', (a) => ({ ...a, signed_at: 1.5 })], ['signed-at-string', (a) => ({ ...a, signed_at: '5' })],
  ['v-2', (a) => ({ ...a, v: 2 })], ['v-string', (a) => ({ ...a, v: '1' })], ['extra-member', (a) => ({ ...a, extra: 1 })], ['alg-unknown', (a) => ({ ...a, alg: 'rot13' })], ['alg-ed-explicit', (a) => ({ ...a, alg: 'ed25519' })], ['alg-ml-dsa-no-key', (a) => ({ ...a, alg: 'ml-dsa-65' })],
  ['pq-pk-without-alg', (a) => ({ ...a, pq_pk: PQPUB })], ['pq-sig-without-alg', (a) => ({ ...a, pq_sig: 'AAAA' })], ['alg-number', (a) => ({ ...a, alg: 5 })]];
for (const [n, f] of MUT) await V('mut-' + n, f(J(A0)));
for (const [n, a] of [['null', null], ['array', []], ['string', 'x'], ['number', 5], ['empty', {}]] as any[]) await V('shape-' + n, a);

// ---- anchors
for (const k of [...I.INTENT_ANCHOR_KINDS, 'other', '']) await add('intentAnchorCommit', 'kind-' + k, [k, D('d')]);
await add('intentAnchorCommit', 'digest-other', ['map', D('e')]); await add('intentAnchorCommit', 'digest-not-checked', ['map', 'x']);
const INST = 'inst-1';
const mkLog = (items: [string, string][], su: any = null, gk = GK, principal = I.INTENT_ANCHOR_LOG, instance = INST) => {
  const lg = new L.TransparencyLedger(principal);
  for (const [k, d] of items) lg.appendCommitment(I.intentAnchorCommit(k, d));
  const h = lg.head();
  const sth = J(L.signTreeHead(gk, { instance_id: instance, principal, size: h.size, root: h.root, prev_root: lg.rootAt(0), timestamp: T0 }, suiteOf(su)));
  return { rc: (i: number) => J({ kind: items[i]![0], digest: items[i]![1], index: i, proof: lg.inclusionProof(i), signed_tree_head: sth }), sth };
};
const ITEMS: [string, string][] = I.INTENT_ANCHOR_KINDS.map((k: string, i: number) => [k, D(String.fromCharCode(97 + i))]);
const LOG = mkLog(ITEMS);
const VA = (n: string, r: any, g: any = GPUB, inst: any = INST, pin: any = null) => add('verifyIntentAnchor', n, [r, g, inst, pin]);
for (const [i, [k]] of ITEMS.entries()) await VA('ok-' + k, LOG.rc(i));
await VA('single-entry', mkLog([['map', D('m')]]).rc(0));
const R1 = LOG.rc(1);
await VA('kind-unknown', { ...R1, kind: 'other' }); await VA('kind-swapped', { ...R1, kind: 'statement' }); await VA('kind-missing', (({ kind, ...r }: any) => r)(R1)); await VA('digest-other', { ...R1, digest: D('z') }); await VA('digest-short', { ...R1, digest: 'AAAA' });
await VA('digest-number', { ...R1, digest: 5 }); await VA('other-instance', R1, GPUB, 'inst-2'); await VA('other-guardian', R1, GPUB2); await VA('guardian-garbage', R1, 'x'); await VA('index-mismatch', { ...R1, index: 2 });
await VA('proof-of-other-entry', { ...R1, proof: LOG.rc(2).proof }); await VA('proof-size-mismatch', { ...R1, proof: { ...R1.proof, size: R1.proof.size - 1 } }); await VA('head-other-principal', mkLog(ITEMS, null, GK, 'someone').rc(1));
await VA('head-other-instance-signed', mkLog(ITEMS, null, GK, I.INTENT_ANCHOR_LOG, 'inst-2').rc(1)); await VA('head-sig-flip', { ...R1, signed_tree_head: { ...R1.signed_tree_head, sig: flip(R1.signed_tree_head.sig) } });
await VA('head-root-other', { ...R1, signed_tree_head: { ...R1.signed_tree_head, root: D('q') } }); await VA('head-size-other', { ...R1, signed_tree_head: { ...R1.signed_tree_head, size: R1.signed_tree_head.size + 1 } });
await VA('head-missing', (({ signed_tree_head, ...r }: any) => r)(R1)); await VA('proof-missing', (({ proof, ...r }: any) => r)(R1)); await VA('receipt-null', null); await VA('receipt-string', 'x'); await VA('receipt-empty', {});
const LP = mkLog(ITEMS, ML), LH = mkLog(ITEMS, HY);
await VA('pq-head-pinned', LP.rc(0), GPUB, INST, { pqPins: { [GPUB]: LP.sth.pq_pk } }); await VA('pq-head-unpinned', LP.rc(0)); await VA('pq-head-pinned-other', LP.rc(0), GPUB, INST, { pqPins: { [GPUB]: PQPUB2 } });
await VA('hybrid-head-pinned', LH.rc(3), GPUB, INST, { pqPins: { [GPUB]: LH.sth.pq_pk } }); await VA('hybrid-head-unpinned', LH.rc(3));
refWrite(o, 'intent-attest');
