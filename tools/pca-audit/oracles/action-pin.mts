// Oracle: the SIGNING half of packages/pca/src/action-pin.ts: signRegistryDoc, signEvolutionRecord, registryKeyOf, signReapproval, plus the constants and the
// verify side exercised over documents this oracle signs (verifyRegistrySig, verifyEvolutionRecord, reapprovalValid over a real signature). actionPinError,
// evolutionRecordError, verifyRegistrySig / verifyEvolutionRecord (hand-built documents), reapprovalValid, evolutionDiffDigest and decidePin are already in
// base-actionregistry (every lane but Rust lacks the file: it is copied there).
// Writes out/ref-action-pin.json.gz. Deterministic: Ed25519 and ML-DSA-65 sign deterministically; keys from seed(label).
// PORTING (fn(args) -> native entry point; compared by JSON value; a throw = the native throws; {"$bytes":{"$seed":label}} = the 32-byte Ed25519 secret; suite {alg, pqSeed} -> ML-DSA-65 from the seed)
//   constants [] -> {ACTION_PIN_ON_NEW, EVOLUTION_CLASSES, EVOLUTION_RECORD_KIND, REAPPROVAL_KIND, EVOLUTION_DOMAIN, EVOLUTION_DIFF_DOMAIN, REAPPROVAL_DOMAIN, MAX_EVOLUTION_STEPS, MAX_ESC_TIER}
//   signRegistryDoc [domain, body, kid, secret, suite|null] -> {alg, kid, value, pq_value?}   (signs domain || strict canonical JSON(body); throws on a non-canonical body or an unknown alg)
//   signEvolutionRecord [record, kid, secret, suite|null] -> record + sig | throws (an invalid unsigned record)
//   registryKeyOf [kid, secret, suite|null] -> {kid, alg, pk, pq_pk?}
//   signReapproval [{grantId, record, principalSecret}] -> {v, kind, grant, verb, diff, sig:{alg:"ed25519", value}}   (record may be signed or unsigned; diff = evolutionDiffDigest(record))
//   verifyRegistrySig [domain, body, sig, keys] -> {ok, reason?}     verifyEvolutionRecord [record, keys] -> {ok, reason?}     reapprovalValid [r, grantId, issuerPk, verb, diff] -> bool
import { Oracle, refWrite, seed } from './lib.mjs';
import { adder } from './foundation.mjs';
const AP: any = await import('../../../packages/pca/src/action-pin.ts');
const PQ: any = await import('../../../packages/pca/src/pq.ts');
const { publicKeyOf } = await import('../../../packages/pca/src/keys.ts') as any;
const { b64u } = await import('../../../packages/pca/src/hash.ts') as any;
const o = new Oracle('action-pin', 'tools/pca-audit/oracles/action-pin.mts', 'TS-reference oracle for the signing half of packages/pca/src/action-pin.ts.');
const suiteOf = (s: any) => (s == null ? undefined : s.alg === 'ed25519' ? { alg: s.alg } : { alg: s.alg, mlDsa: PQ.mlDsa65Keygen(s.pqSeed) });
const REF: Record<string, (...a: any[]) => any> = {
  constants: () => Object.fromEntries(Object.entries(AP).filter(([k, v]) => typeof v !== 'function' && /^[A-Z][A-Z0-9_]+$/.test(k))),
  signRegistryDoc: (d, b, k, s, su) => AP.signRegistryDoc(d, b, k, s, suiteOf(su)), signEvolutionRecord: (r, k, s, su) => AP.signEvolutionRecord(r, k, s, suiteOf(su)), registryKeyOf: (k, s, su) => AP.registryKeyOf(k, s, suiteOf(su)),
  signReapproval: (a) => AP.signReapproval(a), verifyRegistrySig: (d, b, s, k) => AP.verifyRegistrySig(d, b, s, k), verifyEvolutionRecord: (r, k) => AP.verifyEvolutionRecord(r, k), reapprovalValid: (r, g, i, v, d) => AP.reapprovalValid(r, g, i, v, d),
};
const add = adder(o, REF);
const RK = seed('ap/registry'), RK2 = seed('ap/registry2'), PK = seed('ap/principal'), PK2 = seed('ap/principal2'), PQS = seed('ap/pq');
const PKPUB = b64u(publicKeyOf(PK)), PK2PUB = b64u(publicKeyOf(PK2));
const J = (x: any) => JSON.parse(JSON.stringify(x));
const D1 = 'A'.repeat(43), D2 = 'B'.repeat(43);
const REC = (over: any = {}) => ({ v: 1, kind: 'pca-evolution-record', ns: 'acme.pay', verb: 'acme.pay.refund', from: D1, to: D2, class: 'narrow', reasons: ['tightened cap'], ...over });
await add('constants', 'all', []);
const SU = [['ed', null], ['ed-explicit', { alg: 'ed25519' }], ['ml-dsa', { alg: 'ml-dsa-65', pqSeed: PQS }], ['hybrid', { alg: 'hybrid-ed25519-ml-dsa-65', pqSeed: PQS }]] as any[];
for (const [n, su] of SU) { await add('signEvolutionRecord', n, [REC(), 'k1', RK, su]); await add('registryKeyOf', n, ['k1', RK, su]); await add('signRegistryDoc', n, ['atlas-pca/action-evolution/v1\0', REC(), 'k1', RK, su]); }
await add('signEvolutionRecord', 'unknown-alg', [REC(), 'k1', RK, { alg: 'rot13' }]); await add('registryKeyOf', 'unknown-alg', ['k1', RK, { alg: 'rot13' }]); await add('signRegistryDoc', 'unknown-alg', ['d', {}, 'k', RK, { alg: 'rot13' }]);
const BADS: [string, any][] = [['added', REC({ class: 'added', from: null })], ['removed', REC({ class: 'removed', to: null })], ['equal', REC({ class: 'equal', to: D1 })], ['widen', REC({ class: 'widen', reasons: [] })], ['incomparable', REC({ class: 'incomparable' })],
  ['added-with-from', REC({ class: 'added' })], ['removed-with-to', REC({ class: 'removed' })], ['bad-class', REC({ class: 'x' })], ['bad-ns', REC({ ns: 'A.b' })], ['bad-verb-no-dot', REC({ verb: 'verb' })], ['bad-from', REC({ from: 'short' })], ['reasons-65', REC({ reasons: Array.from({ length: 65 }, () => 'r') })], ['reasons-64', REC({ reasons: Array.from({ length: 64 }, () => 'r') })], ['reason-513', REC({ reasons: ['r'.repeat(513)] })], ['reason-512', REC({ reasons: ['r'.repeat(512)] })], ['reason-num', REC({ reasons: [5] })],
  ['extra-member', { ...REC(), extra: 1 }], ['has-sig', { ...REC(), sig: { alg: 'ed25519', kid: 'k', value: 'v' } }], ['v-2', REC({ v: 2 })], ['kind-wrong', REC({ kind: 'x' })], ['null', null], ['array', []], ['string', 'x'], ['unicode-reason', REC({ reasons: ['é😀'] })], ['unpaired-surrogate-reason', REC({ reasons: ['\ud800'] })], ['reasons-missing', (({ reasons, ...r }: any) => r)(REC())]];
for (const [n, r] of BADS) await add('signEvolutionRecord', 'rec-' + n, [r, 'k1', RK, null]);
await add('signEvolutionRecord', 'kid-empty', [REC(), '', RK, null]); await add('signEvolutionRecord', 'kid-unicode', [REC(), 'ké', RK, null]);
const SD = ['atlas-pca/x/v1', 'atlas-pca/x/v1\0', ''];
for (const [i, b] of [{ a: 1 }, { b: [1, 2, { c: 'x' }], a: null }, {}, [], 'str', 5, null, { n: 1.5 }, { n: -0 }, { n: { $num: 'NaN' } }, { n: 2 ** 53 }, { u: 'é😀' }, { '': 1 }].entries()) await add('signRegistryDoc', 'body' + i, [SD[1], b, 'k1', RK, null]);
for (const [i, d] of SD.entries()) await add('signRegistryDoc', 'domain' + i, [d, { a: 1 }, 'k1', RK, null]);
// signed material for verify / reapproval
const rk = (k: string, su: any = null, sk = RK) => J(AP.registryKeyOf(k, sk, suiteOf(su)));
const sr = (r: any, k = 'k1', su: any = null, sk = RK) => J(AP.signEvolutionRecord(r, k, sk, suiteOf(su)));
const R0 = sr(REC()), RP = sr(REC(), 'k2', { alg: 'ml-dsa-65', pqSeed: PQS }), RH = sr(REC(), 'k3', { alg: 'hybrid-ed25519-ml-dsa-65', pqSeed: PQS });
const K0 = rk('k1'), KP = rk('k2', { alg: 'ml-dsa-65', pqSeed: PQS }), KH = rk('k3', { alg: 'hybrid-ed25519-ml-dsa-65', pqSeed: PQS });
const flip = (s: string) => s.slice(0, -2) + (s.slice(-2) === 'AA' ? 'BB' : 'AA');
for (const [n, r, ks] of [['ed-ok', R0, [K0]], ['pq-ok', RP, [KP]], ['hybrid-ok', RH, [KH]], ['no-keys', R0, []], ['keys-not-array', R0, null], ['wrong-kid', R0, [KP]], ['other-secret-key', R0, [rk('k1', null, RK2)]], ['sig-flip', { ...R0, sig: { ...R0.sig, value: flip(R0.sig.value) } }, [K0]], ['body-tampered', { ...R0, reasons: ['x'] }, [K0]], ['class-tampered', { ...R0, class: 'widen' }, [K0]], ['alg-key-mismatch', RP, [{ ...K0, kid: 'k2' }]], ['key-pq-no-pq-pk', RP, [(({ pq_pk, ...r }: any) => r)(KP)]], ['hybrid-pq-flip', { ...RH, sig: { ...RH.sig, pq_value: flip(RH.sig.pq_value) } }, [KH]], ['hybrid-pq-missing', { ...RH, sig: (({ pq_value, ...r }: any) => r)(RH.sig) }, [KH]], ['key-pk-bad', R0, [{ ...K0, pk: 'x' }]], ['key-pk-num', R0, [{ ...K0, pk: 5 }]], ['key-null-first', R0, [null, K0]], ['key-pq-pk-num', R0, [{ ...K0, pq_pk: 5 }]], ['sig-kid-missing', { ...R0, sig: (({ kid, ...r }: any) => r)(R0.sig) }, [K0]], ['unsigned-record', REC(), [K0]], ['record-null', null, [K0]]] as any[]) await add('verifyEvolutionRecord', n, [r, ks]);
for (const [n, d, b, s, ks] of [['ok', 'atlas-pca/action-evolution/v1\0', (({ sig, ...r }: any) => r)(R0), R0.sig, [K0]], ['wrong-domain', 'atlas-pca/other/v1\0', (({ sig, ...r }: any) => r)(R0), R0.sig, [K0]], ['body-differs', 'atlas-pca/action-evolution/v1\0', { ...REC(), ns: 'acme.x' }, R0.sig, [K0]], ['sig-alg-unknown', 'atlas-pca/action-evolution/v1\0', (({ sig, ...r }: any) => r)(R0), { ...R0.sig, alg: 'rot13' }, [K0]], ['sig-kid-null', 'd', {}, { alg: 'ed25519', kid: null, value: 'x' }, [K0]], ['sig-value-num', 'd', {}, { alg: 'ed25519', kid: 'k1', value: 5 }, [K0]]] as any[]) await add('verifyRegistrySig', n, [d, b, s, ks]);
// reapproval
const PUB = PKPUB;
const SRA = (record: any, over: any = {}) => ({ grantId: 'grant-1', record, principalSecret: PK, ...over });
await add('signReapproval', 'unsigned-record', [SRA(REC())]); await add('signReapproval', 'signed-record', [SRA(R0)]); await add('signReapproval', 'other-grant', [SRA(REC(), { grantId: 'grant-2' })]); await add('signReapproval', 'other-principal', [SRA(REC(), { principalSecret: PK2 })]); await add('signReapproval', 'added-record', [SRA(REC({ class: 'added', from: null }))]);
await add('signReapproval', 'record-invalid-still-signs', [SRA({ verb: 'x.y', ns: 'a', from: null, to: null, class: 'added', reasons: [] })]); await add('signReapproval', 'grant-empty', [SRA(REC(), { grantId: '' })]); await add('signReapproval', 'record-missing-verb', [SRA({})]);
const RA = J(AP.signReapproval(SRA(REC()))); const DIFF = AP.evolutionDiffDigest(REC());
await add('signReapproval', 'diff-matches-evolutionDiffDigest', [SRA(REC())]);
for (const [n, r, g, i, v, d] of [['ok', RA, 'grant-1', PUB, 'acme.pay.refund', DIFF], ['wrong-grant', RA, 'grant-2', PUB, 'acme.pay.refund', DIFF], ['wrong-issuer', RA, 'grant-1', PK2PUB, 'acme.pay.refund', DIFF], ['wrong-verb', RA, 'grant-1', PUB, 'acme.pay.other', DIFF], ['wrong-diff', RA, 'grant-1', PUB, 'acme.pay.refund', D1],
  ['sig-flip', { ...RA, sig: { ...RA.sig, value: flip(RA.sig.value) } }, 'grant-1', PUB, 'acme.pay.refund', DIFF], ['alg-ml-dsa', { ...RA, sig: { ...RA.sig, alg: 'ml-dsa-65' } }, 'grant-1', PUB, 'acme.pay.refund', DIFF], ['sig-extra-member', { ...RA, sig: { ...RA.sig, kid: 'k' } }, 'grant-1', PUB, 'acme.pay.refund', DIFF], ['extra-member', { ...RA, extra: 1 }, 'grant-1', PUB, 'acme.pay.refund', DIFF],
  ['v-2', { ...RA, v: 2 }, 'grant-1', PUB, 'acme.pay.refund', DIFF], ['kind-wrong', { ...RA, kind: 'x' }, 'grant-1', PUB, 'acme.pay.refund', DIFF], ['null', null, 'grant-1', PUB, 'v', DIFF], ['array', [], 'grant-1', PUB, 'v', DIFF], ['sig-missing', (({ sig, ...r }: any) => r)(RA), 'grant-1', PUB, 'acme.pay.refund', DIFF], ['sig-value-num', { ...RA, sig: { alg: 'ed25519', value: 5 } }, 'grant-1', PUB, 'acme.pay.refund', DIFF],
  ['issuer-short', RA, 'grant-1', 'abc', 'acme.pay.refund', DIFF], ['issuer-num', RA, 'grant-1', 5, 'acme.pay.refund', DIFF]] as any[]) await add('reapprovalValid', n, [r, g, i, v, d]);
refWrite(o, 'action-pin');
