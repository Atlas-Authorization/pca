// Oracle: packages/pca/src/zk.ts + zk-ceremony.ts (Groth16 / Policy-VM zk compliance verifier, public-input derivation, attested-VM statements,
// circuit provenance and ceremony transcript checks), TS reference. Writes out/ref-zk.json.gz. VERIFY-SIDE ONLY: the reference proves with
// snarkjs and multi-GB proving keys that are not in the repository, and a Groth16 proof carries fresh randomness, so no prover output is
// recorded. Deterministic: Ed25519 keys come from seed labels, every clock is an argument, proofs and keys are the committed fixtures.
//
// CURVES: the committed Policy-VM key + proof exist for BOTH BN254 (snarkjs "bn128", system "groth16-bn254") and BLS12-381 ("bls12381",
// system "groth16-bls12-381"); proof system Groth16, encoding = snarkjs JSON (decimal-string field elements, G1 = [x, y, "1"],
// G2 = [[x0, x1], [y0, y1], ["1", "0"]]). The risk-bound circuit 'pca-policyvm-v2' (BN254) and the first circuit 'pca-compliance-v1' (BN254)
// have NO committed key or proof (their keys are dev-only builds), so those two are covered on their refusal branches only.
// QUIRK (cases named quirk-*): snarkjs ignores vkey.nPublic, vkey.protocol and IC entries beyond the public-signal count, so those keys still verify (verdict true). A native may mirror this or refuse (then list the cases as deviations).
// snarkjs checks only that a proof point is ON THE CURVE (no subgroup test) and relies on the pairing equation for the rest; every case below
// records the verdict (false), so a native verifier that also tests subgroup membership agrees on the verdict.
//
// PORTING (fn(args) -> native entry point; the result is compared by JSON value; a reference throw is {"$throws"} = the native refuses, message not compared):
//   args conventions: {"$bigint": "<decimal>"} anywhere = that integer (uint64 quantizer inputs above 2^53); {"$num": "NaN"|"Infinity"|"-Infinity"} = that double;
//   {"$bytes": {"$seed": label}} = the 32-byte secret key sha256("atlas-pca-conformance/" + label) (the committed corpus carries the label, never the key).
//   {"$expectThunk": X} as a PolicyVmExpectSource = a function returning X; X = "throw" = a function that throws; the string "$absent" = argument not given.
//   Fixtures the corpus embeds by value: VK_BN = circuits/policyvm_vkey.json, VK_BLS = circuits/policyvm_bls12381_vkey.json, the sample proofs
//   circuits/policyvm_sample_proof.json / policyvm_bls12381_sample_proof.json (public signals [54904898..., ..., "1", "1", "1", "1000000000", "0", "0", "0", "500000"]),
//   circuits/circuit-versions.json (out of circuitVersion). A case whose opts omit `verificationKey` selects the bundled key of the proof's curve.
//   policyCommitment(grant) / actionCommitment(pcactn) / pinnedPolicyCommitment(grant)     -> string
//   commitmentField(b64u) / proverKeyBinding(pub, epoch, nonce)                              -> decimal string / object
//   isCanonicalGroth16Envelope(env, curve)                                                   -> bool  (curve "bn254" | "bls12-381")
//   policyVmStructHash(fields) / policyVmRiskHash(fields)                                    -> {hi, lo}
//   quantizeActionStruct / quantizePlanStruct / quantizePolicyStruct / quantizePolicyVmInputs / policyVmCommitmentFromAction     (args as the reference; bigint out as {"$bigint"})
//   decodePolicyVmPublic / decodePolicyVmBoundPublic(publicSignals)                          -> decoded statement
//   policyVmContextMatches(ps, expect|{$expectThunk}, layout?)                               -> bool  (layout "bound" = POLICYVM_BOUND_PUBLIC_SIGNAL, else the v1 table)
//   verifyPolicyVmProof(env, opts)                                                           -> bool  (opts: verificationKey, expect, expectRiskHash)
//   createGroth16SnarkBackend(opts, input) / createPolicyVmSnarkBackend(opts, input) / createPolicyVmSnarkBackendBls12381(opts, input) /
//   createPolicyVmBoundSnarkBackend(opts, input)                                             -> {verified: bool, label}  (label = the assurance label of the backend; input = {proof, publicInputs, ctx})
//   createZkVerifier(spec, ctx)                                                              -> {result, label}  spec = {trustedProverKeys, policyCommitments?, revokedProverKeys?, clockSkewMs?, nowMs, snark?: {kind: groth16|policyvm|policyvm-bls|policyvm-bound, opts}}
//                                                                                              result.reason after "zk verification error (fail closed): " is engine text and is cut here
//   createAttestedComplianceProver(secret, proveOpts)                                        -> {publicKey, statement}   (needs the Policy VM decide; the signature is Ed25519, deterministic)
//   circuitVersion(id)                                                                       -> CircuitVersion (or a throw for an unknown id)
//   vkId / circuitProvenance / checkCircuitProvenance / transcriptSha256 / checkTranscript / ceremonyOf   (zk-ceremony.ts, args as the reference)
//   constants()                                                                              -> every exported constant; `paths` holds the path functions' results relative to the package root
//   provePolicyVmCompliance / provePolicyVmBoundCompliance / proveGroth16Compliance: NOT replayable (random proofs, no zkey). The one case `provePolicyVmCompliance/roundtrip`
//   records the contract: proving the committed sample witness (policyvm_sample_input.json) must give exactly these publicSignals, and the proof must verify under VK_BN.
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import { Oracle, refWrite, seed, variants } from './lib.mjs';
import * as PCA0 from '@atlasauth/pca';

const root = fileURLToPath(new URL('../../../packages/pca/', import.meta.url));
const Z: any = await import('../../../packages/pca/src/zk.ts');
const C: any = await import('../../../packages/pca/src/zk-ceremony.ts');
const AS: any = await import('../../../packages/pca/src/assurance.ts');
const H: any = await import('../../../packages/pca/src/hash.ts');
const P: any = (PCA0 as any).default ?? PCA0;
const { buildPCActn, encodeKey, mintGrant, DEFAULT_RISK_POLICY, publicKeyOf } = P;

const o = new Oracle('zk', 'tools/pca-audit/oracles/zk.mts', 'TS-reference oracle for the Groth16 / Policy-VM zk compliance verifier, public-input derivation, attested-VM statements, circuit provenance and ceremony transcript checks (verify side).');
const jr = (f: string) => JSON.parse(fs.readFileSync(root + 'circuits/' + f, 'utf8'));
const VK_BN = jr('policyvm_vkey.json'), VK_BLS = jr('policyvm_bls12381_vkey.json');
const PR_BN = jr('policyvm_sample_proof.json'), PR_BLS = jr('policyvm_bls12381_sample_proof.json');
const SAMPLE_INPUT = jr('policyvm_sample_input.json');
const cl = (x: any) => JSON.parse(JSON.stringify(x));

// ---- argument revival (the inverse of the corpus conventions above) ---------------------------------------------------------------
const rv = (v: any): any => {
  if (Array.isArray(v)) return v.map(rv);
  if (v && typeof v === 'object') {
    const k = Object.keys(v);
    if (k.length === 1 && k[0] === '$bigint') return BigInt(v.$bigint);
    if (k.length === 1 && k[0] === '$num') return Number(v.$num);
    if (k.length === 1 && k[0] === '$bytes' && v.$bytes && typeof v.$bytes === 'object') return seed(v.$bytes.$seed);
    return Object.fromEntries(k.map((x) => [x, rv(v[x])]));
  }
  return v;
};
const expectOf = (e: any) => (e === '$absent' ? undefined : e && typeof e === 'object' && '$expectThunk' in e ? (e.$expectThunk === 'throw' ? () => { throw new Error('thunk'); } : () => e.$expectThunk) : e);
/** run `f` on the revived args; the corpus args are the reparsed originals (the oracle re-parses, so -0/undefined behave as on the wire) */
const run = (fn: string, name: string, f: (...a: any[]) => any, args: any[]) => o.run(fn, name, (...a: any[]) => f(...rv(a)), args);
const big = (x: any): any => (typeof x === 'bigint' ? { $bigint: x.toString() } : Array.isArray(x) ? x.map(big) : x && typeof x === 'object' ? Object.fromEntries(Object.entries(x).map(([k, v]) => [k, big(v)])) : x);
const pick = <T,>(xs: T[], max: number) => (xs.length <= max ? xs : xs.filter((_, i) => i % Math.ceil(xs.length / max) === 0));

// ============================ constants =======================================================================================
await o.run('constants', 'all', () => ({
  ZK_PROVER_BINDING_REF: Z.ZK_PROVER_BINDING_REF,
  POLICYVM_PUBLIC_SIGNAL: Z.POLICYVM_PUBLIC_SIGNAL, POLICYVM_PUBLIC_SIGNAL_COUNT: Z.POLICYVM_PUBLIC_SIGNAL_COUNT,
  POLICYVM_BOUND_PUBLIC_SIGNAL: Z.POLICYVM_BOUND_PUBLIC_SIGNAL, POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT: Z.POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT,
  POLICYVM_BOUND_RISK_FIELDS: [...Z.POLICYVM_BOUND_RISK_FIELDS], POLICYVM_REVERSIBILITY_ORDER: [...Z.POLICYVM_REVERSIBILITY_ORDER],
  paths: Object.fromEntries(['DEFAULT_VKEY_PATH', 'DEFAULT_WASM_PATH', 'DEFAULT_ZKEY_PATH', 'POLICYVM_VKEY_PATH', 'POLICYVM_SAMPLE_PROOF_PATH', 'POLICYVM_WASM_PATH', 'POLICYVM_ZKEY_PATH',
    'POLICYVM_BLS12381_VKEY_PATH', 'POLICYVM_BLS12381_SAMPLE_PROOF_PATH', 'POLICYVM_BOUND_VKEY_PATH', 'POLICYVM_BOUND_SAMPLE_PROOF_PATH', 'POLICYVM_BOUND_WASM_PATH', 'POLICYVM_BOUND_ZKEY_PATH']
    .map((k) => [k, (Z[k]() as string).split('/packages/pca/')[1]!.replace(/^src\/\.\.\//, '')])),
}), []);

// ============================ commitments, binding tag =========================================================================
const R_BN = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const b32 = (i: number) => Buffer.alloc(32, i).toString('base64url');
const be32 = (v: bigint) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex').toString('base64url');
const CF = ['', b32(0), b32(1), b32(255), Buffer.alloc(31, 7).toString('base64url'), Buffer.alloc(33, 7).toString('base64url'), Buffer.alloc(1, 9).toString('base64url'),
  'a', '!!', 'AA==', ' ' + b32(3), b32(3) + '=', 'x'.repeat(100),
  be32(R_BN - 1n), be32(R_BN), be32(R_BN + 1n), be32(2n * R_BN), be32(5n * R_BN), be32(5n * R_BN + 1n), be32(6n * R_BN - 1n),
  H.b64u(H.sha256(new TextEncoder().encode('commit-a'))), H.b64u(H.sha256(new TextEncoder().encode('commit-b')))];
for (const [i, c] of CF.entries()) await o.run('commitmentField', `c${i}`, Z.commitmentField, [c]);
for (const v of [null, 5, {}, [1]]) await o.run('commitmentField', `type-${JSON.stringify(v)}`, Z.commitmentField, [v]);

const T0 = 1_800_000_000_000;
const key = (l: string) => { const sk = seed('zk/' + l); return { sk, pk: encodeKey(publicKeyOf(sk)) }; };
const PRIN = key('principal'), AG = key('agent');
const GRANT = cl(mintGrant({ principalSecret: PRIN.sk, principalPublic: PRIN.pk, holder: AG.pk, goal: 'secure my account', salt: 'c2FsdC16ay1vcmFjbGU', envelope: { predicates: [{ verb: 'revoke_session', resource: '/acct/*' }], caveats: [{ type: 'expires', at: 9e12 }], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } }).grant);
const PLAN = [{ id: 'n1', verb: 'revoke_session', resource: '/acct/1/s', reversibility_class: 'reversible' }];
const mkAct = (extra: any = {}) => cl(buildPCActn({ grant: GRANT, chain: [GRANT], plan: PLAN, nodeId: 'n1', params: {}, counter: 1, signerSecret: AG.sk, aud: 'rs', now: T0, nonce: 'n-1', ...extra }));
const ACT = mkAct();
for (const [n, g] of Object.entries({ grant: GRANT, noId: { ...GRANT, id: undefined }, idNumber: { ...GRANT, id: 5 }, empty: {}, nul: null, arr: [1], str: 'x' } as any)) {
  await o.run('policyCommitment', n, Z.policyCommitment, [g]);
  await o.run('pinnedPolicyCommitment', n, Z.pinnedPolicyCommitment, [g]);
}
for (const [n, a] of Object.entries({ act: ACT, noAction: {}, nul: null, other: mkAct({ params: { x: 1 } }), actionNull: { action: null }, undef: { action: undefined } } as any)) await o.run('actionCommitment', n, Z.actionCommitment, [a]);
for (const [i, a] of [['pk', 0, 'n'], ['pk', 1, 'n'], ['', 0, ''], ['pk', -1, 'n'], ['pk', 1.5, 'n'], ['pk', 2 ** 53, 'n'], ['', 1, 'é']].entries()) await o.run('proverKeyBinding', `b${i}`, Z.proverKeyBinding, a as any);

// ============================ struct hashes, quantization ====================================================================
const S = SAMPLE_INPUT as any;
const hashCases: Array<[string, any[]]> = [
  ['empty', []], ['one-zero', [0]], ['zeros4', [0, 0, 0, 0]], ['sample-action', [7, 42, 0, 100]], ['u64max', [{ $bigint: '18446744073709551615' }]],
  ['u64max+1', [{ $bigint: '18446744073709551616' }]], ['neg', [-1]], ['neg-big', [{ $bigint: '-1' }]], ['dec-string', ['12345']], ['hex-string', ['0x10']], ['bad-string', ['abc']],
  ['empty-string', ['']], ['float', [1.5]], ['nan', [{ $num: 'NaN' }]], ['inf', [{ $num: 'Infinity' }]], ['2^53', [2 ** 53]], ['null', [null]], ['bool', [true]], ['mixed', [1, '2', { $bigint: '3' }]],
  ['long', Array.from({ length: 64 }, (_, i) => i * 1000003)],
  ['sample-witness-action', [S.verb, S.resource, S.reversibility, S.paramScalar]],
  ['sample-witness-plan', [S.planVerb, S.planResource, S.semanticDist, S.planSalt]],
  ['sample-witness-policy', ['wAlpha', 'wBeta', 'wGamma', 'wDelta', 'wEpsilon', 'wZeta', 'theta1', 'theta2', 'kappa', 'budgetB', 'policyVerb', 'policyResource', 'policyParamBound', 'expiresAt', 'notBefore', 'maxBlast', 'maxDepth', 'revMax', 'rateMax', 'allocParent'].map((k) => S[k])],
];
for (const [n, a] of hashCases) await run('policyVmStructHash', n, Z.policyVmStructHash, [a]);
for (const [n, a] of [['ok', [1, 2, 3, 4, 5]], ['four', [1, 2, 3, 4]], ['six', [1, 2, 3, 4, 5, 6]], ['zero', [0, 0, 0, 0, 0]], ['scale', [1000000, 500000, 0, 12, 999999]], ['neg', [-1, 0, 0, 0, 0]], ['str', ['1', '2', '3', '4', '5']], ['notarray', 'x'], ['null', null]] as any) await run('policyVmRiskHash', n, Z.policyVmRiskHash, [a]);

const ACTION = { verb: 'read', resource: 'doc:1', reversibility_class: 'reversible', params: { amount: 100 } };
const CAT = { verbCodes: { read: 7, write: 8 }, resourceCodes: { 'doc:1': 42 } };
const PSF = { paramScalarField: 'amount' };
const pa = (v: any) => [{ ...ACTION, params: { amount: v } }, PSF];
const qa: Array<[string, any[]]> = [
  ['basic', [ACTION]], ['catalog', [ACTION, CAT]], ['paramScalar', [ACTION, PSF]], ['catalog+param', [ACTION, { ...CAT, ...PSF }]],
  ['strict-hit', [ACTION, { ...CAT, strictCatalog: true }]], ['strict-miss-verb', [{ ...ACTION, verb: 'zap' }, { ...CAT, strictCatalog: true }]], ['strict-miss-resource', [{ ...ACTION, resource: 'x' }, { ...CAT, strictCatalog: true }]],
  ['strict-no-maps', [ACTION, { strictCatalog: true }]], ['strict-false', [{ ...ACTION, verb: 'zap' }, { ...CAT, strictCatalog: false }]],
  ['default-rev', [{ verb: 'a', resource: 'b' }]], ['rev-rate', [{ ...ACTION, reversibility_class: 'rate_limited' }]], ['rev-irr', [{ ...ACTION, reversibility_class: 'irreversible' }]],
  ['rev-unknown', [{ ...ACTION, reversibility_class: 'weird' }]], ['rev-null', [{ ...ACTION, reversibility_class: null }]], ['rev-case', [{ ...ACTION, reversibility_class: 'Reversible' }]],
  ['verb-number', [{ ...ACTION, verb: 5 }]], ['verb-null', [{ ...ACTION, verb: null }]], ['resource-missing', [{ verb: 'a' }]], ['verb-empty', [{ ...ACTION, verb: '' }]],
  ['verb-unicode', [{ ...ACTION, verb: 'é\u0000😀' }]],
  ['action-null', [null]], ['action-undefined', []], ['action-string', ['x']],
  ['param-missing', [{ ...ACTION, params: {} }, PSF]], ['param-null', pa(null)], ['param-no-params', [{ verb: 'a', resource: 'b' }, PSF]], ['param-neg', pa(-1)],
  ['param-negzero', pa(-0)], ['param-frac', pa(1.5)], ['param-string-dec', pa('123')], ['param-string-hex', pa('0x1')], ['param-string-neg', pa('-1')], ['param-string-space', pa(' 1')],
  ['param-string-big', pa('18446744073709551615')], ['param-string-over', pa('18446744073709551616')],
  ['param-bigint-max', pa({ $bigint: '18446744073709551615' })], ['param-bigint-over', pa({ $bigint: '18446744073709551616' })],
  ['param-2^53', pa(2 ** 53)], ['param-1e21', pa(1e21)], ['param-bool', pa(true)], ['param-array', pa([1])], ['param-nan', pa({ $num: 'NaN' })], ['param-inf', pa({ $num: 'Infinity' })],
  ['param-field-empty', [ACTION, { paramScalarField: '' }]], ['param-field-proto', [ACTION, { paramScalarField: 'constructor' }]],
  ['code-bigint-max', [ACTION, { verbCodes: { read: { $bigint: '18446744073709551615' } } }]], ['code-over', [ACTION, { verbCodes: { read: { $bigint: '18446744073709551616' } } }]],
  ['code-neg', [ACTION, { verbCodes: { read: -1 } }]], ['code-frac', [ACTION, { verbCodes: { read: 1.5 } }]], ['code-string', [ACTION, { verbCodes: { read: '7' } }]], ['code-zero', [ACTION, { verbCodes: { read: 0 } }]],
  ['code-proto-verb', [{ ...ACTION, verb: 'constructor' }, { verbCodes: {} }]], ['code-proto-strict', [{ ...ACTION, verb: 'toString' }, { verbCodes: {}, strictCatalog: true }]],
  ['opts-null', [ACTION, null]],
];
for (const [n, a] of qa) {
  await run('quantizeActionStruct', n, (...x: any[]) => big((Z.quantizeActionStruct as any)(...x)), a);
  await run('policyVmCommitmentFromAction', n, (...x: any[]) => (Z.policyVmCommitmentFromAction as any)(...x), a);
}
const PLANQ = { verb: 'read', resource: 'doc:1', semanticDist: 0, planSalt: 12345 };
const qp: Array<[string, any[]]> = [
  ['basic', [PLANQ]], ['catalog', [PLANQ, CAT]], ['strict-miss', [PLANQ, { ...CAT, strictCatalog: true }]], ['dist-neg', [{ ...PLANQ, semanticDist: -1 }]], ['dist-frac', [{ ...PLANQ, semanticDist: 0.5 }]],
  ['salt-big', [{ ...PLANQ, planSalt: { $bigint: '18446744073709551615' } }]], ['salt-over', [{ ...PLANQ, planSalt: { $bigint: '18446744073709551616' } }]], ['salt-string', [{ ...PLANQ, planSalt: '5' }]],
  ['verb-number', [{ ...PLANQ, verb: 1 }]], ['missing-dist', [{ verb: 'a', resource: 'b', planSalt: 1 }]], ['null', [null]],
];
for (const [n, a] of qp) await run('quantizePlanStruct', n, (...x: any[]) => big((Z.quantizePlanStruct as any)(...x)), a);
const POL = { weights: { alpha: 250000, beta: 200000, gamma: 200000, delta: 200000, epsilon: 100000, zeta: 50000 }, theta1: 250000, theta2: 600000, kappa: 1000000, budgetB: 1000000, policyVerb: 'read', policyResource: 'doc:1',
  policyParamBound: 1000, expiresAt: 9000000000000, notBefore: 0, maxBlast: 1000000, maxDepth: 16, revMax: 'rate_limited', rateMax: 5, allocParent: 500000 };
const qpo: Array<[string, any[]]> = [
  ['basic', [POL]], ['catalog', [POL, CAT]], ['strict-miss', [POL, { ...CAT, strictCatalog: true }]], ['revmax-irr', [{ ...POL, revMax: 'irreversible' }]], ['revmax-bad', [{ ...POL, revMax: 'x' }]], ['revmax-missing', [{ ...POL, revMax: undefined }]],
  ['weight-neg', [{ ...POL, weights: { ...POL.weights, alpha: -1 } }]], ['weight-frac', [{ ...POL, weights: { ...POL.weights, zeta: 0.5 } }]], ['weights-missing', [{ ...POL, weights: undefined }]], ['weights-partial', [{ ...POL, weights: { alpha: 1 } }]],
  ['theta-string', [{ ...POL, theta1: '1' }]], ['expires-max', [{ ...POL, expiresAt: { $bigint: '18446744073709551615' } }]], ['expires-over', [{ ...POL, expiresAt: { $bigint: '18446744073709551616' } }]],
  ['expires-2^53', [{ ...POL, expiresAt: 2 ** 53 }]], ['alloc-nan', [{ ...POL, allocParent: { $num: 'NaN' } }]], ['verb-null', [{ ...POL, policyVerb: null }]], ['null', [null]],
];
for (const [n, a] of qpo) await run('quantizePolicyStruct', n, (...x: any[]) => big((Z.quantizePolicyStruct as any)(...x)), a);
const qi: Array<[string, any[]]> = [
  ['action-only', [{ action: ACTION }]], ['all', [{ action: ACTION, plan: PLANQ, policy: POL }, CAT]], ['plan-only', [{ action: ACTION, plan: PLANQ }]], ['policy-only', [{ action: ACTION, policy: POL }]],
  ['action-bad', [{ action: { ...ACTION, reversibility_class: 'x' }, plan: PLANQ }]], ['plan-bad', [{ action: ACTION, plan: { ...PLANQ, semanticDist: -1 } }]], ['policy-bad', [{ action: ACTION, policy: { ...POL, revMax: 'x' } }]],
  ['no-action', [{}]], ['strict', [{ action: ACTION, plan: PLANQ, policy: POL }, { strictCatalog: true }]], ['plan-null', [{ action: ACTION, plan: null }]], ['policy-null', [{ action: ACTION, policy: null }]],
];
for (const [n, a] of qi) await run('quantizePolicyVmInputs', n, (...x: any[]) => big((Z.quantizePolicyVmInputs as any)(...x)), a);

// ============================ public-signal decoding / context pins ============================================================
const PS_BN = PR_BN.publicSignals as string[];
const PSB = [...PS_BN.slice(0, 9), '11', '22', ...PS_BN.slice(9)]; // the 17-signal v2 layout
for (const [n, ps] of Object.entries({ sample: PS_BN, short: PS_BN.slice(0, 5), empty: [], long: [...PS_BN, '9'], nonnumeric: PS_BN.map((_, i) => 'x' + i) } as any)) await o.run('decodePolicyVmPublic', n, Z.decodePolicyVmPublic, [ps]);
for (const [n, ps] of Object.entries({ sample: PSB, short: PSB.slice(0, 5), empty: [] } as any)) await o.run('decodePolicyVmBoundPublic', n, Z.decodePolicyVmBoundPublic, [ps]);
await o.run('decodePolicyVmPublic', 'notarray', Z.decodePolicyVmPublic, [null]);
const setPs = (i: number, v: string) => PS_BN.map((x, j) => (j === i ? v : x));
const NOW_I = 10, BLAST = 11, DEPTH = 12, RECENT = 13, ALLOC = 14;
const ctxCases: Array<[string, any[]]> = [
  ['no-expect', [PS_BN, '$absent']], ['expect-empty', [PS_BN, {}]], ['now-exact', [PS_BN, { now: '1000000000' }]], ['now-exact-number', [PS_BN, { now: 1000000000 }]], ['now-exact-bigint', [PS_BN, { now: { $bigint: '1000000000' } }]],
  ['now-wrong', [PS_BN, { now: 999999999 }]], ['now-window-in', [PS_BN, { now: { min: 999999000, max: 1000001000 } }]], ['now-window-edge-lo', [PS_BN, { now: { min: 1000000000, max: 1000000001 } }]], ['now-window-edge-hi', [PS_BN, { now: { min: 1, max: 1000000000 } }]],
  ['now-window-out', [PS_BN, { now: { min: 1, max: 999999999 } }]], ['now-window-inverted', [PS_BN, { now: { min: 1000000001, max: 1 } }]], ['now-window-string', [PS_BN, { now: { min: '1', max: '2000000000' } }]],
  ['now-pin-frac', [PS_BN, { now: 1.5 }]], ['now-pin-unsafe', [PS_BN, { now: 2 ** 60 }]], ['now-pin-bad-string', [PS_BN, { now: 'x' }]], ['now-pin-neg', [PS_BN, { now: -1 }]], ['now-pin-null', [PS_BN, { now: null }]], ['now-pin-bool', [PS_BN, { now: true }]],
  ['blast', [PS_BN, { blast: 0 }]], ['blast-wrong', [PS_BN, { blast: 1 }]], ['depth', [PS_BN, { delegationDepth: 0 }]], ['depth-wrong', [PS_BN, { delegationDepth: 1 }]], ['recent', [PS_BN, { recentCount: 0 }]], ['recent-wrong', [PS_BN, { recentCount: 3 }]],
  ['alloc', [PS_BN, { allocChild: 500000 }]], ['alloc-wrong', [PS_BN, { allocChild: 1 }]], ['r', [PS_BN, { r: 0 }]], ['r-wrong', [PS_BN, { r: 1 }]], ['t', [PS_BN, { t: 1 }]], ['t-wrong', [PS_BN, { t: 2 }]],
  ['admit', [PS_BN, { requireAdmit: true }]], ['admit-false', [PS_BN, { requireAdmit: false }]], ['tier1', [PS_BN, { requireTier1: true }]],
  ['all-pins', [PS_BN, { now: 1000000000, blast: 0, delegationDepth: 0, recentCount: 0, allocChild: 500000, r: 0, t: 1, requireAdmit: true, requireTier1: true }]],
  ['admit-0', [setPs(8, '0'), { requireAdmit: true }]], ['admit-0-nopin', [setPs(8, '0'), '$absent']], ['t-2-tier1', [setPs(7, '2'), { requireTier1: true }]], ['t-2-nopin', [setPs(7, '2'), '$absent']],
  ['now-2^64-1', [setPs(NOW_I, '18446744073709551615'), '$absent']], ['now-2^64', [setPs(NOW_I, '18446744073709551616'), '$absent']],
  ['now-field-neg', [setPs(NOW_I, '21888242871839275222246405745257275088548364400416034343698204186575808495616'), '$absent']],
  ['now-leading-zero', [setPs(NOW_I, '01'), '$absent']], ['now-empty', [setPs(NOW_I, ''), '$absent']], ['now-hex', [setPs(NOW_I, '0x1'), '$absent']], ['now-neg', [setPs(NOW_I, '-1'), '$absent']], ['now-plus', [setPs(NOW_I, '+1'), '$absent']], ['now-space', [setPs(NOW_I, '1 '), '$absent']],
  ['blast-big', [setPs(BLAST, '18446744073709551616'), '$absent']], ['depth-big', [setPs(DEPTH, '18446744073709551616'), '$absent']], ['recent-big', [setPs(RECENT, '18446744073709551616'), '$absent']], ['alloc-big', [setPs(ALLOC, '18446744073709551616'), '$absent']],
  ['r-big-ok', [setPs(6, '18446744073709551616'), '$absent']], ['short', [PS_BN.slice(0, 11), '$absent']], ['short-pin', [PS_BN.slice(0, 11), { now: 1 }]],
  ['thunk-ok', [PS_BN, { $expectThunk: { now: 1000000000 } }]], ['thunk-wrong', [PS_BN, { $expectThunk: { now: 1 } }]], ['thunk-throws', [PS_BN, { $expectThunk: 'throw' }]], ['thunk-null', [PS_BN, { $expectThunk: null }]],
  ['expect-null', [PS_BN, null]], ['expect-string', [PS_BN, 'x']], ['expect-array', [PS_BN, []]],
  ['bound-no-expect', [PSB, '$absent', 'bound']], ['bound-now', [PSB, { now: 1000000000 }, 'bound']], ['bound-now-wrong-layout', [PSB, { now: 1000000000 }]], ['bound-allocChild', [PSB, { allocChild: 500000 }, 'bound']], ['bound-short', [PS_BN, '$absent', 'bound']],
];
for (const [n, a] of ctxCases) await o.run('policyVmContextMatches', n, (ps: any, e: any, l: any) => Z.policyVmContextMatches(ps, expectOf(e), l === 'bound' ? Z.POLICYVM_BOUND_PUBLIC_SIGNAL : undefined), a);

// ============================ canonical envelope gate (no snarkjs) =============================================================
for (const [curve, pr] of [['bn254', PR_BN], ['bls12-381', PR_BLS]] as const) {
  await o.run('isCanonicalGroth16Envelope', `${curve}/valid`, Z.isCanonicalGroth16Envelope, [pr, curve]);
  await o.run('isCanonicalGroth16Envelope', `${curve}/valid-other-curve`, Z.isCanonicalGroth16Envelope, [pr, curve === 'bn254' ? 'bls12-381' : 'bn254']);
  const vs = pick([...variants(pr, { depth: 5 })], 220);
  for (const [i, [label, v]] of vs.entries()) await o.run('isCanonicalGroth16Envelope', `${curve}/v${i} ${label}`, Z.isCanonicalGroth16Envelope, [v, curve]);
}
for (const [n, e] of Object.entries({ null: null, arr: [], str: 'x', num: 5, empty: {} } as any)) await o.run('isCanonicalGroth16Envelope', `shape-${n}`, Z.isCanonicalGroth16Envelope, [e, 'bn254']);
for (const c of ['bn128', 'x', null, 'BN254']) await o.run('isCanonicalGroth16Envelope', `curve-${c}`, Z.isCanonicalGroth16Envelope, [PR_BN, c]);
const BN_P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BLS_P = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
{ // field bounds, exactly at the modulus
  const p = BN_P, r = R_BN;
  const w = (f: (e: any) => void) => { const e = cl(PR_BN); f(e); return e; };
  const cases: Array<[string, any]> = [
    ['pi_a.x=p-1', w((e) => { e.proof.pi_a[0] = String(p - 1n); })], ['pi_a.x=p', w((e) => { e.proof.pi_a[0] = String(p); })], ['pi_a.x=p+1', w((e) => { e.proof.pi_a[0] = String(p + 1n); })],
    ['pi_b.x1=p', w((e) => { e.proof.pi_b[0][1] = String(p); })], ['pi_b.y0=p-1', w((e) => { e.proof.pi_b[1][0] = String(p - 1n); })],
    ['sig=r-1', w((e) => { e.publicSignals[0] = String(r - 1n); })], ['sig=r', w((e) => { e.publicSignals[0] = String(r); })], ['sig=r+1', w((e) => { e.publicSignals[0] = String(r + 1n); })],
    ['sig-len120', w((e) => { e.publicSignals[0] = '1'.repeat(120); })], ['sig-len121', w((e) => { e.publicSignals[0] = '1'.repeat(121); })], ['sig-number', w((e) => { e.publicSignals[0] = 5; })],
    ['sig-hex', w((e) => { e.publicSignals[0] = '0x5'; })], ['sig-zero', w((e) => { e.publicSignals[0] = '0'; })], ['sig-leading-zero', w((e) => { e.publicSignals[0] = '05'; })], ['sig-neg', w((e) => { e.publicSignals[0] = '-5'; })],
    ['sig-unicode-digit', w((e) => { e.publicSignals[0] = '٣'; })], ['sig-newline', w((e) => { e.publicSignals[0] = '5\n'; })],
    ['no-signals', w((e) => { e.publicSignals = []; })], ['signals-object', w((e) => { e.publicSignals = {}; })], ['z-not-1', w((e) => { e.proof.pi_a[2] = '2'; })], ['pib-z', w((e) => { e.proof.pi_b[2] = ['1', '1']; })],
    ['key-order', { circuit: PR_BN.circuit, system: PR_BN.system, publicSignals: PR_BN.publicSignals, proof: { curve: 'bn128', protocol: 'groth16', pi_c: PR_BN.proof.pi_c, pi_b: PR_BN.proof.pi_b, pi_a: PR_BN.proof.pi_a } }],
    ['extra-top', w((e) => { e.extra = 1; })], ['extra-proof', w((e) => { e.proof.extra = 1; })], ['curve-bls-label', w((e) => { e.proof.curve = 'bls12381'; })], ['protocol-plonk', w((e) => { e.proof.protocol = 'plonk'; })],
  ];
  for (const [n, e] of cases) await o.run('isCanonicalGroth16Envelope', `bounds/${n}`, Z.isCanonicalGroth16Envelope, [e, 'bn254']);
}

// ============================ geometry for off-subgroup points =================================================================
// Fq2 = Fq[u]/(u^2+1) (both BN254 and BLS12-381 have p = 3 mod 4). Builds points ON the curve / twist but (almost surely) outside the prime-order subgroup.
const mod = (a: bigint, m: bigint) => ((a % m) + m) % m;
const pw = (b: bigint, e: bigint, m: bigint) => { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
type F2 = [bigint, bigint];
const fq2 = (p: bigint) => {
  const add = (a: F2, b: F2): F2 => [mod(a[0] + b[0], p), mod(a[1] + b[1], p)];
  const mul = (a: F2, b: F2): F2 => [mod(a[0] * b[0] - a[1] * b[1], p), mod(a[0] * b[1] + a[1] * b[0], p)];
  const sq = (a: F2) => mul(a, a);
  const conj = (a: F2): F2 => [a[0], mod(-a[1], p)];
  const eq = (a: F2, b: F2) => a[0] === b[0] && a[1] === b[1];
  const powf = (a: F2, e: bigint): F2 => { let r: F2 = [1n, 0n]; let b = a; while (e > 0n) { if (e & 1n) r = mul(r, b); b = sq(b); e >>= 1n; } return r; };
  const invf = (a: F2): F2 => { const n = pw(mod(a[0] * a[0] + a[1] * a[1], p), p - 2n, p); return [mod(a[0] * n, p), mod(-a[1] * n, p)]; };
  const sqrt = (a: F2): F2 | null => {
    if (a[0] === 0n && a[1] === 0n) return [0n, 0n];
    const a1 = powf(a, (p - 3n) / 4n); const alpha = mul(sq(a1), a); const a0 = mul(conj(alpha), alpha);
    if (eq(a0, [mod(-1n, p), 0n])) return null;
    const x0 = mul(a1, a);
    const x = eq(alpha, [mod(-1n, p), 0n]) ? mul([0n, 1n], x0) : mul(powf(add([1n, 0n], alpha), (p - 1n) / 2n), x0);
    return eq(sq(x), a) ? x : null;
  };
  return { add, mul, sq, eq, sqrt, invf };
};
function g1On(p: bigint, b: bigint, start: bigint): [string, string] {
  for (let x = start; ; x++) { const rhs = mod(x * x * x + b, p); const y = pw(rhs, (p + 1n) / 4n, p); if (mod(y * y, p) === rhs) return [String(x), String(y)]; }
}
function g2On(p: bigint, b2: F2, start: bigint): [[string, string], [string, string]] {
  const F = fq2(p);
  for (let x0 = start; ; x0++) { const x: F2 = [x0, 1n]; const rhs = F.add(F.mul(F.sq(x), x), b2); const y = F.sqrt(rhs); if (y) return [[String(x[0]), String(x[1])], [String(y[0]), String(y[1])]]; }
}
const F_BN = fq2(BN_P);
const B2_BN: F2 = F_BN.mul([3n, 0n], F_BN.invf([9n, 1n])); // BN254 twist coefficient 3/(9+u)
const B2_BLS: F2 = [4n, 4n]; // BLS12-381 twist coefficient 4(1+u)

// ============================ verifyPolicyVmProof =============================================================================
const vk = (c: string) => (c === 'bn' ? VK_BN : VK_BLS);
const prf = (c: string) => (c === 'bn' ? PR_BN : PR_BLS);
const V = (name: string, env: any, opts: any) => o.run('verifyPolicyVmProof', name, (e: any, op: any) => Z.verifyPolicyVmProof(e, rv({ ...op, ...(op && op.expect !== undefined ? { expect: expectOf(op.expect) } : {}) })), [env, opts]);
for (const c of ['bn', 'bls']) {
  const pr = prf(c), K = vk(c);
  const mut = (f: (e: any) => void) => { const e = cl(pr); f(e); return e; };
  const vopts = { verificationKey: K };
  const Pq = c === 'bn' ? BN_P : BLS_P;
  const Rq = c === 'bn' ? R_BN : 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
  await V(`${c}/valid`, pr, vopts);
  await V(`${c}/valid-default-key`, pr, {});
  await V(`${c}/valid-expect-now`, pr, { ...vopts, expect: { now: 1000000000, requireAdmit: true, requireTier1: true } });
  await V(`${c}/expect-now-wrong`, pr, { ...vopts, expect: { now: 1 } });
  await V(`${c}/expect-window`, pr, { ...vopts, expect: { now: { min: 999999999, max: 1000000001 } } });
  await V(`${c}/expect-thunk-throws`, pr, { ...vopts, expect: { $expectThunk: 'throw' } });
  await V(`${c}/expect-thunk-ok`, pr, { ...vopts, expect: { $expectThunk: { recentCount: 0 } } });
  await V(`${c}/expectRiskHash-on-v1`, pr, { ...vopts, expectRiskHash: { hi: '1', lo: '2' } });
  for (let i = 0; i < 15; i++) await V(`${c}/signal${i}+1`, mut((e) => { e.publicSignals[i] = String(BigInt(e.publicSignals[i]) + 1n); }), vopts);
  await V(`${c}/signal-count-14`, mut((e) => { e.publicSignals.pop(); }), vopts);
  await V(`${c}/signal-count-16`, mut((e) => { e.publicSignals.push('0'); }), vopts);
  await V(`${c}/allow-0`, mut((e) => { e.publicSignals[9] = '0'; }), vopts);
  await V(`${c}/signal-noncanonical-leading-zero`, mut((e) => { e.publicSignals[6] = '00'; }), vopts);
  await V(`${c}/signal-plus-order`, mut((e) => { e.publicSignals[6] = String(Rq); }), vopts);
  await V(`${c}/pi_a.y+1`, mut((e) => { e.proof.pi_a[1] = String(BigInt(e.proof.pi_a[1]) + 1n); }), vopts);
  await V(`${c}/pi_a.x+1`, mut((e) => { e.proof.pi_a[0] = String(BigInt(e.proof.pi_a[0]) + 1n); }), vopts);
  await V(`${c}/pi_a.y-neg`, mut((e) => { e.proof.pi_a[1] = String(Pq - BigInt(e.proof.pi_a[1])); }), vopts); // -A: on the curve, in the subgroup, wrong proof
  await V(`${c}/pi_c.y-neg`, mut((e) => { e.proof.pi_c[1] = String(Pq - BigInt(e.proof.pi_c[1])); }), vopts);
  await V(`${c}/pi_c.x+1`, mut((e) => { e.proof.pi_c[0] = String(BigInt(e.proof.pi_c[0]) + 1n); }), vopts);
  await V(`${c}/pi_b.x0+1`, mut((e) => { e.proof.pi_b[0][0] = String(BigInt(e.proof.pi_b[0][0]) + 1n); }), vopts);
  await V(`${c}/pi_b.y1+1`, mut((e) => { e.proof.pi_b[1][1] = String(BigInt(e.proof.pi_b[1][1]) + 1n); }), vopts);
  await V(`${c}/pi_b.conj`, mut((e) => { e.proof.pi_b[0][1] = String(Pq - BigInt(e.proof.pi_b[0][1])); }), vopts);
  await V(`${c}/pi_a-is-pi_c`, mut((e) => { e.proof.pi_a = [...e.proof.pi_c]; }), vopts);
  await V(`${c}/pi_a-zero-xy`, mut((e) => { e.proof.pi_a = ['0', '0', '1']; }), vopts);
  await V(`${c}/pi_a-infinity`, mut((e) => { e.proof.pi_a = ['0', '1', '0']; }), vopts);
  await V(`${c}/pi_b-zero`, mut((e) => { e.proof.pi_b = [['0', '0'], ['0', '0'], ['1', '0']]; }), vopts);
  await V(`${c}/pi_a-affine-2`, mut((e) => { e.proof.pi_a = e.proof.pi_a.slice(0, 2); }), vopts);
  await V(`${c}/pi_b-short`, mut((e) => { e.proof.pi_b = e.proof.pi_b.slice(0, 2); }), vopts);
  await V(`${c}/proof-null`, mut((e) => { e.proof = null; }), vopts);
  await V(`${c}/proof-missing`, mut((e) => { delete e.proof; }), vopts);
  await V(`${c}/proof-string`, mut((e) => { e.proof = 'x'; }), vopts);
  await V(`${c}/pi_a.x-hex`, mut((e) => { e.proof.pi_a[0] = '0x' + BigInt(e.proof.pi_a[0]).toString(16); }), vopts);
  await V(`${c}/pi_a.x+p`, mut((e) => { e.proof.pi_a[0] = String(BigInt(e.proof.pi_a[0]) + Pq); }), vopts);
  await V(`${c}/pi_a.x-leading-zero`, mut((e) => { e.proof.pi_a[0] = '0' + e.proof.pi_a[0]; }), vopts);
  await V(`${c}/pi_a.z-0`, mut((e) => { e.proof.pi_a[2] = '0'; }), vopts);
  await V(`${c}/extra-key`, mut((e) => { e.extra = 1; }), vopts);
  await V(`${c}/proof-extra-key`, mut((e) => { e.proof.extra = 1; }), vopts);
  await V(`${c}/protocol-plonk`, mut((e) => { e.proof.protocol = 'plonk'; }), vopts);
  await V(`${c}/proof-curve-wrong`, mut((e) => { e.proof.curve = c === 'bn' ? 'bls12381' : 'bn128'; }), vopts);
  await V(`${c}/system-other-curve`, mut((e) => { e.system = c === 'bn' ? 'groth16-bls12-381' : 'groth16-bn254'; }), vopts);
  await V(`${c}/system-unknown`, mut((e) => { e.system = 'groth16'; }), vopts);
  await V(`${c}/system-missing`, mut((e) => { delete e.system; }), vopts);
  await V(`${c}/circuit-other`, mut((e) => { e.circuit = 'pca-compliance-v1'; }), vopts);
  await V(`${c}/circuit-v2-count-mismatch`, mut((e) => { e.circuit = 'pca-policyvm-v2'; }), vopts);
  await V(`${c}/circuit-missing`, mut((e) => { delete e.circuit; }), vopts);
  await V(`${c}/vkey-other-curve`, pr, { verificationKey: c === 'bn' ? VK_BLS : VK_BN });
  const vm = (f: (k: any) => void) => { const k = cl(K); f(k); return k; };
  await V(`${c}/vkey-alpha-flipped`, pr, { verificationKey: vm((k) => { k.vk_alpha_1[1] = String(Pq - BigInt(k.vk_alpha_1[1])); }) });
  await V(`${c}/vkey-alpha-offcurve`, pr, { verificationKey: vm((k) => { k.vk_alpha_1[1] = String(BigInt(k.vk_alpha_1[1]) + 1n); }) });
  await V(`${c}/vkey-ic0-flipped`, pr, { verificationKey: vm((k) => { k.IC[0][1] = String(Pq - BigInt(k.IC[0][1])); }) });
  await V(`${c}/vkey-ic1-swapped-ic2`, pr, { verificationKey: vm((k) => { [k.IC[1], k.IC[2]] = [k.IC[2], k.IC[1]]; }) });
  await V(`${c}/vkey-ic-short`, pr, { verificationKey: vm((k) => { k.IC.pop(); }) });
  await V(`${c}/quirk-vkey-ic-long`, pr, { verificationKey: vm((k) => { k.IC.push(k.IC[0]); }) });
  await V(`${c}/quirk-vkey-nPublic-14`, pr, { verificationKey: vm((k) => { k.nPublic = 14; }) });
  await V(`${c}/quirk-vkey-protocol-plonk`, pr, { verificationKey: vm((k) => { k.protocol = 'plonk'; }) });
  await V(`${c}/vkey-curve-unknown`, pr, { verificationKey: vm((k) => { k.curve = 'bn255'; }) });
  await V(`${c}/vkey-no-curve`, pr, { verificationKey: vm((k) => { delete k.curve; }) });
  await V(`${c}/vkey-no-beta`, pr, { verificationKey: vm((k) => { delete k.vk_beta_2; }) });
  await V(`${c}/vkey-empty`, pr, { verificationKey: {} });
  await V(`${c}/vkey-gamma-eq-delta`, pr, { verificationKey: vm((k) => { k.vk_delta_2 = cl(k.vk_gamma_2); }) });
  await V(`${c}/vkey-delta-offcurve`, pr, { verificationKey: vm((k) => { k.vk_delta_2[0][0] = String(BigInt(k.vk_delta_2[0][0]) + 1n); }) });
}
{ // on the curve but NOT in the prime-order subgroup (BN254 G1 has cofactor 1: that case does not exist there)
  const g1bls = g1On(BLS_P, 4n, 1n), g2bls = g2On(BLS_P, B2_BLS, 1n), g2bn = g2On(BN_P, B2_BN, 1n);
  const mutb = (f: (e: any) => void) => { const e = cl(PR_BLS); f(e); return e; };
  const mutn = (f: (e: any) => void) => { const e = cl(PR_BN); f(e); return e; };
  await V('bls/pi_a-on-curve-not-in-g1', mutb((e) => { e.proof.pi_a = [g1bls[0], g1bls[1], '1']; }), { verificationKey: VK_BLS });
  await V('bls/pi_c-on-curve-not-in-g1', mutb((e) => { e.proof.pi_c = [g1bls[0], g1bls[1], '1']; }), { verificationKey: VK_BLS });
  await V('bls/pi_b-on-twist-not-in-g2', mutb((e) => { e.proof.pi_b = [g2bls[0], g2bls[1], ['1', '0']]; }), { verificationKey: VK_BLS });
  await V('bn/pi_b-on-twist-not-in-g2', mutn((e) => { e.proof.pi_b = [g2bn[0], g2bn[1], ['1', '0']]; }), { verificationKey: VK_BN });
  const vb = cl(VK_BLS); vb.vk_alpha_1 = [g1bls[0], g1bls[1], '1'];
  await V('bls/vkey-alpha-not-in-g1', PR_BLS, { verificationKey: vb });
  const vb2 = cl(VK_BLS); vb2.vk_beta_2 = [g2bls[0], g2bls[1], ['1', '0']];
  await V('bls/vkey-beta-not-in-g2', PR_BLS, { verificationKey: vb2 });
  const vn2 = cl(VK_BN); vn2.vk_beta_2 = [g2bn[0], g2bn[1], ['1', '0']];
  await V('bn/vkey-beta-not-in-g2', PR_BN, { verificationKey: vn2 });
}
{ // risk-bound circuit v2: no committed key; gate branches only (17 signals, BN254 only, expectRiskHash)
  const v2 = (f: (e: any) => void = () => {}) => { const e: any = { system: 'groth16-bn254', circuit: 'pca-policyvm-v2', proof: cl(PR_BN.proof), publicSignals: [...PSB] }; f(e); return e; };
  await V('v2/valid-shape-wrong-key', v2(), { verificationKey: VK_BN });
  await V('v2/risk-hash-mismatch', v2(), { verificationKey: VK_BN, expectRiskHash: { hi: '9', lo: '9' } });
  await V('v2/risk-hash-match-wrong-key', v2(), { verificationKey: VK_BN, expectRiskHash: { hi: '11', lo: '22' } });
  await V('v2/risk-hash-half', v2(), { verificationKey: VK_BN, expectRiskHash: { hi: '11', lo: '23' } });
  await V('v2/bls-not-allowed', v2((e) => { e.system = 'groth16-bls12-381'; e.proof = cl(PR_BLS.proof); }), { verificationKey: VK_BLS });
  await V('v2/allow-0', v2((e) => { e.publicSignals[11] = '0'; }), { verificationKey: VK_BN });
  await V('v2/15-signals', v2((e) => { e.publicSignals = [...PS_BN]; }), { verificationKey: VK_BN });
  await V('v2/now-out-of-range', v2((e) => { e.publicSignals[12] = '18446744073709551616'; }), { verificationKey: VK_BN });
  await V('v2/context-pin', v2(), { verificationKey: VK_BN, expect: { now: 1 } });
}
for (const [n, e] of Object.entries({ null: null, undefined: undefined, string: 'x', number: 1, array: [], empty: {} } as any)) await V(`shape-${n}`, e, { verificationKey: VK_BN });
await V('opts-undefined', PR_BN, undefined);

// ============================ ceremony fixtures (also used by the backend labels) ============================================
const sh = (s: string) => Buffer.from(H.sha256(new TextEncoder().encode(s))).toString('hex');
const H64 = (c: string) => c.repeat(64);
const mkTranscript = (vkey: any, circuit: string, curve = 'bn128') => {
  const init = sh('init'), c1 = sh('c1'), c2 = sh('c2'), fin = sh('final');
  return {
    version: 1, circuit, curve, r1csSha256: sh('r1cs'), ptauSha256: sh('ptau'), initZkeySha256: init, minContributions: 2,
    contributions: [{ index: 0, name: 'alice', prevZkeySha256: init, zkeySha256: c1 }, { index: 1, name: 'bob', prevZkeySha256: c1, zkeySha256: c2 }],
    beacon: { hashHex: sh('beacon'), iterationsExp: 10, prevZkeySha256: c2, zkeySha256: fin }, finalZkeySha256: fin, vkId: C.vkId(vkey),
  };
};
const TR_BN = mkTranscript(VK_BN, 'pca-policyvm-v1');
const evid = (t: any, over: any = {}) => ({ transcript: t, sha256: C.transcriptSha256(t), ...over });

// ============================ backends ========================================================================================
const BK = (fn: string, name: string, make: (opts: any) => any, opts: any, input: any) =>
  o.run(fn, name, async (op: any, inp: any) => {
    const b = make(rv({ ...op, ...(op.expect !== undefined ? { expect: expectOf(op.expect) } : {}) }));
    return { verified: await b.verify(inp), label: AS.assuranceLabelOf(b) ?? null };
  }, [opts, input]);
const PIN = { proof: null, publicInputs: { action_commit: b32(1), policy_commit: b32(2), plan_commit: b32(3) }, ctx: {} };
const halves = (xs: string[], i: number) => ({ hi: xs[i]!, lo: xs[i + 1]! });
const bind = { expectActionHash: halves(PS_BN, 0), expectPolicyHash: halves(PS_BN, 2), expectPlanHash: halves(PS_BN, 4) };
for (const [fn, make, K, PR] of [
  ['createPolicyVmSnarkBackend', Z.createPolicyVmSnarkBackend, VK_BN, PR_BN],
  ['createPolicyVmSnarkBackendBls12381', Z.createPolicyVmSnarkBackendBls12381, VK_BLS, PR_BLS],
] as const) {
  const t = fn.endsWith('Bls12381') ? 'bls' : 'bn';
  const ps = PR.publicSignals as string[];
  const bd = { expectActionHash: halves(ps, 0), expectPolicyHash: halves(ps, 2), expectPlanHash: halves(ps, 4) };
  const inp = (p: any) => ({ ...PIN, proof: p });
  await BK(fn, `${t}/valid-unbound`, make, { verificationKey: K }, inp(PR));
  await BK(fn, `${t}/valid-bound`, make, { verificationKey: K, ...bd }, inp(PR));
  await BK(fn, `${t}/valid-default-key`, make, {}, inp(PR));
  await BK(fn, `${t}/action-hash-wrong`, make, { verificationKey: K, ...bd, expectActionHash: { hi: '1', lo: '2' } }, inp(PR));
  await BK(fn, `${t}/policy-hash-wrong`, make, { verificationKey: K, ...bd, expectPolicyHash: { hi: ps[2], lo: '2' } }, inp(PR));
  await BK(fn, `${t}/plan-hash-wrong`, make, { verificationKey: K, ...bd, expectPlanHash: { hi: '1', lo: ps[5] } }, inp(PR));
  await BK(fn, `${t}/only-action-pinned`, make, { verificationKey: K, expectActionHash: bd.expectActionHash }, inp(PR));
  await BK(fn, `${t}/expect-now`, make, { verificationKey: K, ...bd, expect: { now: 1000000000, requireAdmit: true } }, inp(PR));
  await BK(fn, `${t}/expect-now-wrong`, make, { verificationKey: K, ...bd, expect: { now: 5 } }, inp(PR));
  await BK(fn, `${t}/other-circuit`, make, { verificationKey: K }, inp({ ...PR, circuit: 'pca-compliance-v1' }));
  await BK(fn, `${t}/proof-null`, make, { verificationKey: K }, inp(null));
  await BK(fn, `${t}/proof-string`, make, { verificationKey: K }, inp('x'));
  await BK(fn, `${t}/signals-not-array`, make, { verificationKey: K }, inp({ ...PR, publicSignals: 'x' }));
  await BK(fn, `${t}/other-curve-proof`, make, { verificationKey: K }, inp(fn.endsWith('Bls12381') ? PR_BN : PR_BLS));
  await BK(fn, `${t}/vkey-wrong`, make, { verificationKey: K === VK_BN ? VK_BLS : VK_BN }, inp(PR));
}
await BK('createPolicyVmSnarkBackend', 'bn/ceremony-multi-party', Z.createPolicyVmSnarkBackend, { verificationKey: VK_BN, ...bind, ceremony: evid(TR_BN) }, { ...PIN, proof: PR_BN });
await BK('createPolicyVmSnarkBackend', 'bn/ceremony-wrong-sha', Z.createPolicyVmSnarkBackend, { verificationKey: VK_BN, ...bind, ceremony: evid(TR_BN, { sha256: sh('other') }) }, { ...PIN, proof: PR_BN });
await BK('createPolicyVmSnarkBackend', 'bn/ceremony-other-circuit', Z.createPolicyVmSnarkBackend, { verificationKey: VK_BN, ...bind, ceremony: evid(mkTranscript(VK_BN, 'pca-compliance-v1')) }, { ...PIN, proof: PR_BN });
await BK('createPolicyVmSnarkBackend', 'bn/ceremony-other-key', Z.createPolicyVmSnarkBackend, { verificationKey: VK_BN, ...bind, ceremony: evid(mkTranscript(VK_BLS, 'pca-policyvm-v1')) }, { ...PIN, proof: PR_BN });
await BK('createPolicyVmSnarkBackend', 'bn/ceremony-without-explicit-key', Z.createPolicyVmSnarkBackend, { ...bind, ceremony: evid(TR_BN) }, { ...PIN, proof: PR_BN });

{ // first circuit (compliance-v1): no committed key; the pre-pairing gates, then the pairing against a key of another circuit
  const sig = (p: any) => [Z.commitmentField(p.policy_commit), Z.commitmentField(p.plan_commit), Z.commitmentField(p.action_commit)];
  const pi1 = (fn?: (p: any) => void) => { const p = { action_commit: b32(1), policy_commit: b32(2), plan_commit: b32(3) }; fn?.(p); return p; };
  const env1 = (p: any, f: (e: any) => void = () => {}) => { const s = sig(p); const e: any = { system: 'groth16-bn254', circuit: 'pca-compliance-v1', proof: cl(PR_BN.proof), publicSignals: ['1', '2', '3', s[0], s[1], s[2], '1'] }; f(e); return e; };
  const G = (n: string, env: any, p: any) => BK('createGroth16SnarkBackend', n, Z.createGroth16SnarkBackend, { verificationKey: VK_BN }, { proof: env, publicInputs: p, ctx: {} });
  await G('bound-wrong-key', env1(pi1()), pi1()); // passes the gates, then snarkjs rejects (7 signals against a 15-input key)
  await G('allow-0', env1(pi1(), (e) => { e.publicSignals[6] = '0'; }), pi1());
  await G('policy-tag-mismatch', env1(pi1()), pi1((p) => { p.policy_commit = b32(9); }));
  await G('plan-tag-mismatch', env1(pi1()), pi1((p) => { p.plan_commit = b32(9); }));
  await G('action-tag-mismatch', env1(pi1()), pi1((p) => { p.action_commit = b32(9); }));
  await G('bad-commit-b64', env1(pi1()), pi1((p) => { p.action_commit = '!!'; }));
  await G('wrong-system', env1(pi1(), (e) => { e.system = 'groth16-bls12-381'; }), pi1());
  await G('wrong-circuit', env1(pi1(), (e) => { e.circuit = 'pca-policyvm-v1'; }), pi1());
  await G('signals-6', env1(pi1(), (e) => { e.publicSignals.pop(); }), pi1());
  await G('signals-8', env1(pi1(), (e) => { e.publicSignals.push('1'); }), pi1());
  await G('proof-null', env1(pi1(), (e) => { e.proof = null; }), pi1());
  await G('null', null, pi1());
  await G('noncanonical-signal', env1(pi1(), (e) => { e.publicSignals[0] = '01'; }), pi1());
  await BK('createGroth16SnarkBackend', 'ceremony-multi-party', Z.createGroth16SnarkBackend, { verificationKey: VK_BN, ceremony: evid(mkTranscript(VK_BN, 'pca-compliance-v1')) }, { proof: null, publicInputs: pi1(), ctx: {} });
}
{ // risk-bound backend
  const v2 = () => ({ system: 'groth16-bn254', circuit: 'pca-policyvm-v2', proof: cl(PR_BN.proof), publicSignals: [...PSB] });
  const Bd = (n: string, opts: any, env: any) => BK('createPolicyVmBoundSnarkBackend', n, Z.createPolicyVmBoundSnarkBackend, { verificationKey: VK_BN, ...opts }, { ...PIN, proof: env });
  const all4 = { ...bind, expectRiskHash: { hi: '11', lo: '22' } };
  await Bd('pinned-wrong-key', all4, v2());
  await Bd('unpinned-wrong-key', {}, v2());
  await Bd('risk-wrong', { ...all4, expectRiskHash: { hi: '11', lo: '23' } }, v2());
  await Bd('action-wrong', { ...all4, expectActionHash: { hi: '1', lo: '2' } }, v2());
  await Bd('v1-circuit', all4, { ...v2(), circuit: 'pca-policyvm-v1' });
  await Bd('signals-missing', all4, { ...v2(), publicSignals: undefined });
  await Bd('null', all4, null);
}

// ============================ createZkVerifier (attested-VM statements, snark seam) ============================================
const PROVER = key('prover'), OTHER = key('other-prover');
const DEC = (act: any) => ({
  grant: GRANT, chain: [GRANT], action: { action: { verb: act.action.verb, resource: act.action.resource, params: {}, reversibility_class: act.action.reversibility_class } }, plan: PLAN,
  risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 }, budget: { B: 1, tau: T0, asOf: T0 }, now: T0, nodeId: act.plan.node_id,
});
const mkProver = (sk: Uint8Array) => Z.createAttestedComplianceProver(sk);
const proveOpts = (act: any, over: any = {}) => ({ pcactn: act, decideInput: DEC(act), issued_at: T0 - 1000, expires_at: T0 + 60_000, ...over });
const proverCase = (name: string, label: string, act: any, over: any = {}) =>
  o.run('createAttestedComplianceProver', name, async (sec: any, po: any) => { const p = mkProver(rv(sec)); return { publicKey: p.publicKey, statement: p.prove(po) }; }, [{ $bytes: { $seed: 'zk/' + label } }, proveOpts(act, over)]);
await proverCase('compliant', 'prover', ACT);
await proverCase('window-zero', 'prover', ACT, { issued_at: T0, expires_at: T0 });
await proverCase('window-inverted-still-signs', 'prover', ACT, { issued_at: T0, expires_at: T0 - 1 });
await proverCase('other-key', 'other-prover', ACT);
{
  await o.run('createAttestedComplianceProver', 'non-compliant-refused', async (sec: any, po: any) => mkProver(rv(sec)).prove(po),
    [{ $bytes: { $seed: 'zk/prover' } }, { ...proveOpts(ACT), decideInput: { ...DEC(ACT), action: { action: { verb: 'exfiltrate', resource: ACT.action.resource, params: {}, reversibility_class: 'reversible' } } } }]);
  const noroot = cl(ACT); noroot.plan = { ...noroot.plan, root: 5 };
  await proverCase('plan-root-not-string', 'prover', noroot);
}
const STM = cl(mkProver(PROVER.sk).prove(proveOpts(ACT)));
const PUBK = mkProver(PROVER.sk).publicKey, PUBO = mkProver(OTHER.sk).publicKey;
const withZk = (a: any, z: any) => ({ ...a, zk_compliance: z });
const SNARK: any = { groth16: Z.createGroth16SnarkBackend, policyvm: Z.createPolicyVmSnarkBackend, 'policyvm-bls': Z.createPolicyVmSnarkBackendBls12381, 'policyvm-bound': Z.createPolicyVmBoundSnarkBackend };
const ZV = (name: string, spec: any, pcactn: any, grant: any = GRANT) => o.run('createZkVerifier', name, async (sp: any, ctx: any) => {
  const s = rv(sp);
  const snark = s.snark ? SNARK[s.snark.kind](rv(s.snark.opts ?? {})) : undefined;
  const hook = Z.createZkVerifier({ trustedProverKeys: s.trustedProverKeys, policyCommitments: s.policyCommitments, revokedProverKeys: s.revokedProverKeys, clockSkewMs: s.clockSkewMs, now: () => s.nowMs, snarkBackend: snark });
  const result = await hook(ctx);
  if (result && typeof result.reason === 'string') result.reason = result.reason.replace(/(zk verification error \(fail closed\)): .*$/s, '$1');
  return { result, label: AS.assuranceLabelOf(hook) ?? null };
}, [spec, { pcactn, grant }]);
const base = { trustedProverKeys: [PUBK], policyCommitments: [Z.policyCommitment(GRANT)], nowMs: T0 };
await ZV('ok', base, withZk(ACT, STM));
await ZV('ok-no-policy-pin-derives-from-grant', { trustedProverKeys: [PUBK], nowMs: T0 }, withZk(ACT, STM));
await ZV('no-proof', base, ACT);
await ZV('proof-null', base, withZk(ACT, null));
await ZV('no-pcactn', base, undefined);
await ZV('untrusted', { ...base, trustedProverKeys: [PUBO] }, withZk(ACT, STM));
await ZV('trusted-empty', { ...base, trustedProverKeys: [] }, withZk(ACT, STM));
await ZV('trusted-not-array', { ...base, trustedProverKeys: 'x' }, withZk(ACT, STM));
await ZV('revoked', { ...base, revokedProverKeys: [PUBK] }, withZk(ACT, STM));
await ZV('revoked-other', { ...base, revokedProverKeys: [PUBO] }, withZk(ACT, STM));
await ZV('policy-pin-wrong', { ...base, policyCommitments: ['nope'] }, withZk(ACT, STM));
await ZV('policy-pin-empty', { ...base, policyCommitments: [] }, withZk(ACT, STM));
await ZV('policy-pin-two', { ...base, policyCommitments: ['x', Z.policyCommitment(GRANT)] }, withZk(ACT, STM));
await ZV('not-yet-valid', { ...base, nowMs: T0 - 1001 }, withZk(ACT, STM));
await ZV('not-yet-valid-skew', { ...base, nowMs: T0 - 1001, clockSkewMs: 1 }, withZk(ACT, STM));
await ZV('issued-edge', { ...base, nowMs: T0 - 1000 }, withZk(ACT, STM));
await ZV('expired', { ...base, nowMs: T0 + 60_001 }, withZk(ACT, STM));
await ZV('expires-edge', { ...base, nowMs: T0 + 60_000 }, withZk(ACT, STM));
await ZV('expired-skew', { ...base, nowMs: T0 + 60_001, clockSkewMs: 1 }, withZk(ACT, STM));
await ZV('skew-negative', { ...base, nowMs: T0 + 60_001, clockSkewMs: -5 }, withZk(ACT, STM));
await ZV('skew-nan', { ...base, nowMs: T0 + 60_001, clockSkewMs: { $num: 'NaN' } }, withZk(ACT, STM));
await ZV('skew-huge', { ...base, nowMs: T0 + 60_001, clockSkewMs: 1e12 }, withZk(ACT, STM));
{
  const sm = (f: (s: any) => void) => { const s = cl(STM); f(s); return s; };
  const stmts: Array<[string, any]> = [
    ['r-tampered', sm((s) => { s.r = 0.99; })], ['sig-empty', sm((s) => { s.sig = ''; })], ['sig-missing', sm((s) => { delete s.sig; })], ['sig-number', sm((s) => { s.sig = 5; })], ['sig-bit-flip', sm((s) => { s.sig = (s.sig[0] === 'A' ? 'B' : 'A') + s.sig.slice(1); })],
    ['v2', sm((s) => { s.v = 2; })], ['mode-other', sm((s) => { s.mode = 'zk'; })], ['released-false', sm((s) => { s.released = false; })], ['released-string', sm((s) => { s.released = 'true'; })],
    ['prover-other', sm((s) => { s.prover = PUBO; })], ['prover-number', sm((s) => { s.prover = 5; })], ['prover-missing', sm((s) => { delete s.prover; })],
    ['issued-nan-string', sm((s) => { s.issued_at = 'x'; })], ['expires-before-issued', sm((s) => { s.expires_at = s.issued_at - 1; })], ['issued-null', sm((s) => { s.issued_at = null; })],
    ['action-commit', sm((s) => { s.action_commit = b32(1); })], ['plan-commit', sm((s) => { s.plan_commit = b32(1); })], ['policy-commit', sm((s) => { s.policy_commit = b32(1); })], ['policy-commit-number', sm((s) => { s.policy_commit = 5; })],
    ['extra-member', sm((s) => { s.extra = 1; })], ['empty', {}], ['array', []], ['string', 'x'], ['number', 5], ['true', true],
  ];
  for (const [n, s] of stmts) await ZV(`stmt/${n}`, base, withZk(ACT, s));
  const act2 = (f: (a: any) => void) => { const a = cl(ACT); f(a); return withZk(a, STM); };
  await ZV('action-tampered', base, act2((a) => { a.action = { ...a.action, resource: '/acct/EVIL' }; }));
  await ZV('plan-root-tampered', base, act2((a) => { a.plan = { ...a.plan, root: 'zzz' }; }));
  await ZV('plan-root-missing', base, act2((a) => { delete a.plan.root; }));
  await ZV('plan-missing', base, act2((a) => { delete a.plan; }));
  await ZV('grant-null', base, withZk(ACT, STM), null);
  await ZV('grant-null-no-pin', { trustedProverKeys: [PUBK], nowMs: T0 }, withZk(ACT, STM), null);
  await ZV('grant-other', { trustedProverKeys: [PUBK], nowMs: T0 }, withZk(ACT, STM), { ...GRANT, id: 'other' });
  for (const [i, [label, v]] of pick([...variants(STM, { depth: 2 })], 90).entries()) await ZV(`sweep${i} ${label}`, base, withZk(ACT, v));
}
// snark seam through createZkVerifier: the backend decides; the hook adds nothing and reports the backend's label
await ZV('snark/policyvm-bn-valid', { trustedProverKeys: [], nowMs: T0, snark: { kind: 'policyvm', opts: { verificationKey: VK_BN, ...bind } } }, withZk(ACT, PR_BN));
await ZV('snark/policyvm-bn-unbound-label', { trustedProverKeys: [], nowMs: T0, snark: { kind: 'policyvm', opts: { verificationKey: VK_BN } } }, withZk(ACT, PR_BN));
await ZV('snark/policyvm-bn-tampered', { trustedProverKeys: [], nowMs: T0, snark: { kind: 'policyvm', opts: { verificationKey: VK_BN } } }, withZk(ACT, { ...PR_BN, publicSignals: PS_BN.map((x, i) => (i === 6 ? '5' : x)) }));
await ZV('snark/policyvm-bls-valid', { trustedProverKeys: [], nowMs: T0, snark: { kind: 'policyvm-bls', opts: { verificationKey: VK_BLS } } }, withZk(ACT, PR_BLS));
await ZV('snark/policyvm-bls-bn-proof', { trustedProverKeys: [], nowMs: T0, snark: { kind: 'policyvm-bls', opts: { verificationKey: VK_BLS } } }, withZk(ACT, PR_BN));
await ZV('snark/no-proof', { trustedProverKeys: [], nowMs: T0, snark: { kind: 'policyvm', opts: { verificationKey: VK_BN } } }, ACT);
await ZV('snark/backend-bound-ceremony', { trustedProverKeys: [], nowMs: T0, snark: { kind: 'policyvm', opts: { verificationKey: VK_BN, ...bind, ceremony: evid(TR_BN) } } }, withZk(ACT, PR_BN));
await ZV('snark/groth16-compliance-garbage', { trustedProverKeys: [], nowMs: T0, snark: { kind: 'groth16', opts: { verificationKey: VK_BN } } }, withZk(ACT, { system: 'groth16-bn254' }));

// ============================ circuit version ================================================================================
for (const id of ['pca-compliance-v1', 'pca-policyvm-v1', 'pca-policyvm-v2', 'nope', '', 'PCA-POLICYVM-V1', '__proto__', 'constructor', 'hasOwnProperty', 'toString', 'pca-policyvm-v1 ']) await o.run('circuitVersion', `id-${JSON.stringify(id)}`, Z.circuitVersion, [id]);
for (const v of [null, 5, undefined]) await o.run('circuitVersion', `type-${JSON.stringify(v)}`, Z.circuitVersion, [v]);

// ============================ ceremony ========================================================================================
const SRC = jr('circuit-versions.json').circuits['pca-policyvm-v1'].source_sha256;
await o.run('vkId', 'bn', C.vkId, [VK_BN]);
await o.run('vkId', 'bls', C.vkId, [VK_BLS]);
await o.run('vkId', 'key-order-irrelevant', C.vkId, [Object.fromEntries(Object.entries(VK_BN).reverse())]);
await o.run('vkId', 'empty', C.vkId, [{}]);
await o.run('vkId', 'nested', C.vkId, [{ b: [1, { z: 1, a: null }], a: 'é' }]);
for (const v of [null, 5, 'x', [], [1, 2]]) await o.run('vkId', `type-${JSON.stringify(v)}`, C.vkId, [v]);
const provArgs = (over: any = {}) => ({ circuit: 'pca-policyvm-v1', sourceSha256: SRC, r1csSha256: sh('r1cs'), vkey: VK_BN, ...over });
await o.run('circuitProvenance', 'ok', C.circuitProvenance, [provArgs()]);
await o.run('circuitProvenance', 'ok-bls', C.circuitProvenance, [provArgs({ vkey: VK_BLS })]);
for (const [n, over] of Object.entries({ 'empty-circuit': { circuit: '' }, 'src-short': { sourceSha256: 'ab' }, 'src-upper': { sourceSha256: H64('A') }, 'src-63': { sourceSha256: H64('a').slice(1) }, 'src-65': { sourceSha256: H64('a') + 'a' },
  'r1cs-bad': { r1csSha256: 'zz' }, 'r1cs-number': { r1csSha256: 5 }, 'circuit-number': { circuit: 5 }, 'no-vkey': { vkey: undefined }, 'vkey-null': { vkey: null }, 'src-undefined': { sourceSha256: undefined } } as any)) await o.run('circuitProvenance', n, C.circuitProvenance, [provArgs(over)]);
const PROV = C.circuitProvenance(provArgs());
const expectP = (over: any = {}) => ({ circuit: 'pca-policyvm-v1', sourceSha256: SRC, r1csSha256: sh('r1cs'), vkey: VK_BN, ...over });
await o.run('checkCircuitProvenance', 'ok', C.checkCircuitProvenance, [PROV, expectP()]);
await o.run('checkCircuitProvenance', 'ok-r1cs-unpinned', C.checkCircuitProvenance, [PROV, expectP({ r1csSha256: undefined })]);
await o.run('checkCircuitProvenance', 'other-circuit', C.checkCircuitProvenance, [PROV, expectP({ circuit: 'pca-policyvm-v2' })]);
await o.run('checkCircuitProvenance', 'other-source', C.checkCircuitProvenance, [PROV, expectP({ sourceSha256: H64('0') })]);
await o.run('checkCircuitProvenance', 'other-r1cs', C.checkCircuitProvenance, [PROV, expectP({ r1csSha256: H64('0') })]);
await o.run('checkCircuitProvenance', 'other-vkey', C.checkCircuitProvenance, [PROV, expectP({ vkey: VK_BLS })]);
for (const [n, v] of Object.entries({ null: null, undefined: undefined, string: 'x', number: 5, array: [], empty: {} } as any)) await o.run('checkCircuitProvenance', `prov-${n}`, C.checkCircuitProvenance, [v, expectP()]);
for (const [n, f] of Object.entries({ 'r1cs-missing': (p: any) => delete p.r1csSha256, 'r1cs-uppercase': (p: any) => { p.r1csSha256 = H64('A'); }, 'r1cs-short': (p: any) => { p.r1csSha256 = 'ab'; }, 'r1cs-number': (p: any) => { p.r1csSha256 = 5; }, 'vkid-missing': (p: any) => delete p.vkId, 'vkid-bad': (p: any) => { p.vkId = 'vk_x'; }, extra: (p: any) => { p.extra = 1; } } as any)) {
  const p = cl(PROV); (f as any)(p); await o.run('checkCircuitProvenance', n, C.checkCircuitProvenance, [p, expectP({ r1csSha256: undefined })]);
}
await o.run('checkCircuitProvenance', 'expect-vkey-null', C.checkCircuitProvenance, [PROV, expectP({ vkey: null })]);

await o.run('transcriptSha256', 'valid', C.transcriptSha256, [TR_BN]);
await o.run('transcriptSha256', 'key-order', C.transcriptSha256, [Object.fromEntries(Object.entries(TR_BN).reverse())]);
await o.run('transcriptSha256', 'empty', C.transcriptSha256, [{}]);
{
  const t0 = cl(TR_BN);
  await o.run('checkTranscript', 'valid', C.checkTranscript, [t0]);
  await o.run('checkTranscript', 'valid-bls-curve', C.checkTranscript, [{ ...t0, curve: 'bls12-381' }]);
  await o.run('checkTranscript', 'opts-circuit-ok', C.checkTranscript, [t0, { circuit: 'pca-policyvm-v1' }]);
  await o.run('checkTranscript', 'opts-circuit-wrong', C.checkTranscript, [t0, { circuit: 'x' }]);
  await o.run('checkTranscript', 'opts-r1cs-ok', C.checkTranscript, [t0, { r1csSha256: t0.r1csSha256 }]);
  await o.run('checkTranscript', 'opts-r1cs-wrong', C.checkTranscript, [t0, { r1csSha256: H64('0') }]);
  for (const m of [0, 1, 2, 3, -1, 1.5, 2 ** 53]) await o.run('checkTranscript', `opts-min-${m}`, C.checkTranscript, [t0, { minContributions: m }]);
  for (const m of [0, 1, 3, 5, '2', null, 1.5, -1, 2 ** 53, 1e21]) await o.run('checkTranscript', `t-min-${JSON.stringify(m)}`, C.checkTranscript, [{ ...t0, minContributions: m }]);
  const three = cl(t0); const c3 = sh('c3'); three.contributions.push({ index: 2, name: 'carol', prevZkeySha256: t0.contributions[1].zkeySha256, zkeySha256: c3 }); three.beacon.prevZkeySha256 = c3;
  await o.run('checkTranscript', 'three-contributions', C.checkTranscript, [three]);
  await o.run('checkTranscript', 'three-min-3', C.checkTranscript, [three, { minContributions: 3 }]);
  await o.run('checkTranscript', 'three-min-4', C.checkTranscript, [three, { minContributions: 4 }]);
  for (const [n, f] of Object.entries({
    'one-contribution': (t: any) => { t.contributions.pop(); t.beacon.prevZkeySha256 = t.contributions[0].zkeySha256; },
    'no-contributions': (t: any) => { t.contributions = []; }, 'contributions-object': (t: any) => { t.contributions = {}; },
    'dup-name': (t: any) => { t.contributions[1].name = 'alice'; }, 'dup-key': (t: any) => { t.contributions[1].zkeySha256 = t.contributions[0].zkeySha256; t.beacon.prevZkeySha256 = t.contributions[0].zkeySha256; },
    'index-gap': (t: any) => { t.contributions[1].index = 5; }, 'index-negzero': (t: any) => { t.contributions[0].index = -0; }, 'index-string': (t: any) => { t.contributions[0].index = '0'; },
    'chain-broken': (t: any) => { t.contributions[1].prevZkeySha256 = sh('x'); }, 'first-not-init': (t: any) => { t.contributions[0].prevZkeySha256 = sh('x'); },
    'name-empty': (t: any) => { t.contributions[0].name = ''; }, 'name-number': (t: any) => { t.contributions[0].name = 5; }, 'name-same-case': (t: any) => { t.contributions[1].name = 'ALICE'; },
    'contribution-null': (t: any) => { t.contributions[1] = null; }, 'zkey-uppercase': (t: any) => { t.contributions[0].zkeySha256 = H64('A'); },
    'beacon-missing': (t: any) => { delete t.beacon; }, 'beacon-hash-bad': (t: any) => { t.beacon.hashHex = 'zz'; }, 'beacon-exp-9': (t: any) => { t.beacon.iterationsExp = 9; }, 'beacon-exp-10': (t: any) => { t.beacon.iterationsExp = 10; },
    'beacon-exp-63': (t: any) => { t.beacon.iterationsExp = 63; }, 'beacon-exp-64': (t: any) => { t.beacon.iterationsExp = 64; }, 'beacon-exp-frac': (t: any) => { t.beacon.iterationsExp = 10.5; }, 'beacon-exp-string': (t: any) => { t.beacon.iterationsExp = '10'; },
    'beacon-not-after-last': (t: any) => { t.beacon.prevZkeySha256 = sh('x'); }, 'beacon-zkey-bad': (t: any) => { t.beacon.zkeySha256 = 'x'; },
    'final-missing': (t: any) => { delete t.finalZkeySha256; }, 'final-not-beacon': (t: any) => { t.finalZkeySha256 = sh('x'); },
    'vkid-missing': (t: any) => { delete t.vkId; }, 'vkid-bad': (t: any) => { t.vkId = 'vk_' + 'A'.repeat(64); }, 'vkid-short': (t: any) => { t.vkId = 'vk_ab'; }, 'vkid-no-prefix': (t: any) => { t.vkId = 'a'.repeat(64); },
    'version-2': (t: any) => { t.version = 2; }, 'version-string': (t: any) => { t.version = '1'; }, 'version-missing': (t: any) => { delete t.version; },
    'circuit-empty': (t: any) => { t.circuit = ''; }, 'circuit-number': (t: any) => { t.circuit = 1; }, 'curve-bn254': (t: any) => { t.curve = 'bn254'; }, 'curve-missing': (t: any) => { delete t.curve; },
    'r1cs-bad': (t: any) => { t.r1csSha256 = 'x'; }, 'ptau-bad': (t: any) => { t.ptauSha256 = H64('G'); }, 'init-bad': (t: any) => { t.initZkeySha256 = H64('a').slice(2); }, 'ptau-number': (t: any) => { t.ptauSha256 = 5; },
    'extra-member': (t: any) => { t.extra = 1; },
  } as any)) { const t = cl(t0); (f as any)(t); await o.run('checkTranscript', n, C.checkTranscript, [t]); }
  for (const [n, v] of Object.entries({ null: null, undefined: undefined, string: 'x', number: 5, array: [], empty: {} } as any)) await o.run('checkTranscript', `shape-${n}`, C.checkTranscript, [v]);
  for (const [i, [label, v]] of pick([...variants(t0, { depth: 4 })], 220).entries()) await o.run('checkTranscript', `sweep${i} ${label}`, C.checkTranscript, [v]);
  const ev = (t: any, over: any = {}) => ({ transcript: t, sha256: C.transcriptSha256(t), ...over });
  await o.run('ceremonyOf', 'multi-party', C.ceremonyOf, [VK_BN, ev(t0)]);
  await o.run('ceremonyOf', 'multi-party-circuit-pinned', C.ceremonyOf, [VK_BN, ev(t0, { circuit: 'pca-policyvm-v1' })]);
  await o.run('ceremonyOf', 'circuit-wrong', C.ceremonyOf, [VK_BN, ev(t0, { circuit: 'pca-compliance-v1' })]);
  await o.run('ceremonyOf', 'r1cs-pinned-ok', C.ceremonyOf, [VK_BN, ev(t0, { r1csSha256: t0.r1csSha256 })]);
  await o.run('ceremonyOf', 'r1cs-pinned-wrong', C.ceremonyOf, [VK_BN, ev(t0, { r1csSha256: H64('0') })]);
  await o.run('ceremonyOf', 'sha-wrong', C.ceremonyOf, [VK_BN, ev(t0, { sha256: H64('0') })]);
  await o.run('ceremonyOf', 'sha-uppercase', C.ceremonyOf, [VK_BN, ev(t0, { sha256: C.transcriptSha256(t0).toUpperCase() })]);
  await o.run('ceremonyOf', 'sha-missing', C.ceremonyOf, [VK_BN, ev(t0, { sha256: undefined })]);
  await o.run('ceremonyOf', 'other-vkey', C.ceremonyOf, [VK_BLS, ev(t0)]);
  await o.run('ceremonyOf', 'vkey-undefined', C.ceremonyOf, [undefined, ev(t0)]);
  await o.run('ceremonyOf', 'vkey-null', C.ceremonyOf, [null, ev(t0)]);
  await o.run('ceremonyOf', 'evidence-undefined', C.ceremonyOf, [VK_BN]);
  await o.run('ceremonyOf', 'evidence-null', C.ceremonyOf, [VK_BN, null]);
  await o.run('ceremonyOf', 'evidence-empty', C.ceremonyOf, [VK_BN, {}]);
  await o.run('ceremonyOf', 'transcript-null', C.ceremonyOf, [VK_BN, { transcript: null, sha256: H64('0') }]);
  await o.run('ceremonyOf', 'transcript-string', C.ceremonyOf, [VK_BN, { transcript: 'x', sha256: H64('0') }]);
  await o.run('ceremonyOf', 'vkey-string', C.ceremonyOf, ['x', ev(t0)]);
  await o.run('ceremonyOf', 'vkey-empty-object', C.ceremonyOf, [{}, ev(t0)]);
  const one = cl(t0); one.contributions.pop(); one.beacon.prevZkeySha256 = one.contributions[0].zkeySha256;
  await o.run('ceremonyOf', 'single-contribution', C.ceremonyOf, [VK_BN, ev(one)]);
  const nb = cl(t0); delete nb.beacon;
  await o.run('ceremonyOf', 'no-beacon', C.ceremonyOf, [VK_BN, ev(nb)]);
}

// ============================ prover contract (not replayable) ================================================================
o.add('provePolicyVmCompliance', 'roundtrip', [SAMPLE_INPUT], { publicSignals: PS_BN, verifiesUnder: 'VK_BN', sampleProofCircuit: 'pca-policyvm-v1' });

refWrite(o, 'zk');
process.exit(0);
