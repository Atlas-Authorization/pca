// Oracle: packages/pca/src/attestation.ts and the config helpers ext/attestation re-exports (software attestation: binding, the dev attestor, documents, the
// resolver, the nonce store and entropy gate, the agent-binding match, the verifier and its hook, the multi-root verifier, evidence anchoring; x509 validity
// helpers; allowlist manifests). Hardware verifiers (SEV-SNP, TDX, MAA, GCP, NVIDIA) and their wire parsers are NOT here.
// Writes out/ref-attestation-soft.json.gz. Deterministic: Ed25519 / ML-DSA-65 keys from seed(label), fixed clocks, explicit nonces.
// PORTING (fn(args) -> native entry point; compared by JSON value; a reference throw = the native throws; {"$num":..} non-finite doubles; {"$bytes":{"$seed":label}} = the 32-byte secret sha256("atlas-pca-conformance/"+label))
//   attestationBinding [exp] -> {"$bytes": 64 bytes: SHA-512(ATTEST_BIND_DOMAIN || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce)), lp = u32be length || utf-8} | throws
//   attestationBindingB64u [exp] -> string | throws
//   attest [secret, suite|null, claims] -> AttestationDocument (createDevAttestor(secret, suite).attest(claims)); suite {alg, pqSeed} -> ML-DSA-65 key pair mlDsa65Keygen(pqSeed) (deterministic); throws on an unknown alg
//   attestorPublicKey [secret, suite|null] -> string | throws
//   attestationDigest [doc] -> string (hashCanonical)
//   registry [docs, quoteDigests] -> per quote digest: the doc registered under that NONCE (last wins) or null; ctx = {pcactn:{attestation:{quote_digest}}}; a non-string digest probes ctx.pcactn.attestation.quote_digest = that value
//   nonceStore [max|null, opts|null, ops] -> per op; ["clock", t] sets the store clock (opts.now), ["consume", nonce] -> bool. A constructor throw = {"$throws"} (the whole case). opts {retentionMs?}; max null = default 100000
//   nonceEntropyOk [nonce, minBytes|null] -> bool
//   requiresAttestation [binding|null] -> bool ; nonceBinds [doc, ctx] -> bool ; matchAgentBinding [identity, binding|null] -> string | null (reasons compared exactly)
//   verifyAttestation [input] -> {ok, present, bound, reason?, identity?}
//        input = {document|null, ctx, expected, nowMs, trustedAttestorKeys[], pqPins?, allowUnboundPq?, hardware?: HW, maxNonceAgeMs?, clockSkewMs?}; HW = a constant hardware verifier: {result: HardwareAttestationResult} | {throws: "msg"}
//        ctx = {pcactn:{grant_ref, attestation:{epoch, quote_digest}, cap_chain?}, grant: <a grant carrying the envelope>}
//   NOTE reasons: a missing member is spelled `undefined` inside the reference's reason text (`operator undefined is not the bound operator`, `document mode undefined needs ...`); a reason that starts with
//   `attestation verification error (fail closed):` carries the reference's own exception text after the colon (e.g. `canonicalize: non-finite number`): compare only the prefix there.
//   attestationHook [opts, ctxs] -> per ctx {enforced, ok, reason?, present, bound}; ONE hook (createAttestationVerifier) serves the ctxs in order (nonce store state persists).
//        opts = {trustedAttestorKeys, minNonceBytes?, insecure_selfDeclaredNonce?, maxNonceAgeMs?, clockSkewMs?, pqPins?, allowUnboundPq?, now: <ms>, store?: {max?, retentionMs?} (a fresh memoryNonceStore on the same clock),
//                storeConsume?: bool (a constant store: always that answer), hardware?: HW, docs: [doc] (resolveDocument = registry), binding?: {byNonce: {<nonce>: ExpectedAttestationBinding}} (expectedBinding looks the ctx quote_digest up; absent member = undefined) | "throws"}
//   multiRoot [policy, input|null] -> HardwareAttestationResult (verify) ; policy = {threshold, roots:[{id, required?, suite?, hw: HW}]}; null input = construction only -> {"built": true}; construction errors are throws
//   attestationEvidenceDigest [ev] -> string ; anchorEvidence [ev, opts] -> {index, commit, sth?} | throws (opts {guardianSeed?: secret, instanceId?, now?, required?, ledger: "ok"|"none", principal?, preload?: n (append n commitments first)})
//   constants [] -> {ATTEST_BIND_DOMAIN, MAX_ATTESTATION_AGE_MS, DEFAULT_NONCE_RETENTION_MS, MIN_ATTESTATION_NONCE_BYTES, ATTEST_ANCHOR_DOMAIN}
import { Oracle, refWrite, seed } from './lib.mjs';
import { adder, nul } from './foundation.mjs';
const P: any = await import('../../../packages/pca/src/index.ts').then((m: any) => m.default ?? m);
const A: any = await import('../../../packages/pca/src/attestation.ts');
const PQ: any = await import('../../../packages/pca/src/pq.ts');
const LG: any = await import('../../../packages/pca/src/ledger.ts');
const { mintGrant, publicKeyOf, encodeKey, DEFAULT_RISK_POLICY } = P;
const o = new Oracle('attestation-soft', 'tools/pca-audit/oracles/attestation-soft.mts', 'TS-reference oracle for packages/pca/src/attestation.ts and the ext/attestation config helpers.');
const T0 = 1_800_000_000_000;
const AT = seed('att/attestor'), AT2 = seed('att/attestor2'), PR = seed('att/principal'), HOLD = seed('att/holder'), PQS = seed('att/pq'), GS = seed('att/guardian');
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const ATPK = b64(publicKeyOf(AT)), AT2PK = b64(publicKeyOf(AT2)), HPK = encodeKey(publicKeyOf(HOLD)), PRPK = encodeKey(publicKeyOf(PR));
const J = (x: any) => JSON.parse(JSON.stringify(x));
const suiteOf = (s: any) => (s == null ? undefined : s.alg === 'ed25519' ? { alg: s.alg } : { alg: s.alg, mlDsa: PQ.mlDsa65Keygen(s.pqSeed) });
const hw = (h: any) => h == null ? undefined : { verify: async () => { if (h.throws !== undefined) throw new Error(h.throws); return h.result; } };
const ctxOf = (c: any) => c;
const { createMemoryDurableKv } = await import('../../../packages/pca/src/durable-state.ts') as any;
const REF: Record<string, (...a: any[]) => any> = {
  attestationBinding: (e) => A.attestationBinding(e), attestationBindingB64u: (e) => A.attestationBindingB64u(e),
  attest: (s, su, cl) => A.createDevAttestor(s, suiteOf(su)).attest(cl), attestorPublicKey: (s, su) => A.createDevAttestor(s, suiteOf(su)).publicKey,
  attestationDigest: (d) => A.attestationDigest(d),
  registry: (docs, qs) => { const r = A.attestationRegistry(docs); return qs.map((q: any) => r({ pcactn: { attestation: { quote_digest: q } } }) ?? null); },
  nonceStore: (max, op, ops) => { let t = 0; const st = A.memoryNonceStore(max === null ? undefined : max, { ...(nul(op) ?? {}), now: () => t }); return ops.map((x: any) => { if (x[0] === 'clock') { t = x[1]; return null; } return st.consume(x[1]); }); },
  nonceEntropyOk: (n, m) => A.nonceEntropyOk(n, nul(m)), requiresAttestation: (b) => A.requiresAttestation(nul(b)), nonceBinds: (d, c) => A.nonceBinds(d, c), matchAgentBinding: (i, b) => A.matchAgentBinding(i, nul(b)),
  verifyAttestation: async (i) => { const { hardware, document, ...r } = i; const v = await A.verifyAttestation({ ...r, document: nul(document), hardwareVerifier: hw(hardware) }); return v; },
  attestationHook: async (op, ctxs) => {
    const { store, storeConsume, hardware, docs, binding, now, ...rest } = op;
    const o2: any = { ...rest, now: () => now, hardwareVerifier: hw(hardware), resolveDocument: A.attestationRegistry(docs ?? []) };
    if (store) { let t = now; o2.nonceStore = A.memoryNonceStore(store.max, { retentionMs: store.retentionMs, now: () => t }); }
    if (storeConsume !== undefined) o2.nonceStore = { consume: () => storeConsume };
    if (binding === 'throws') o2.expectedBinding = () => { throw new Error('boom'); };
    else if (binding) o2.expectedBinding = (c: any) => binding.byNonce[c?.pcactn?.attestation?.quote_digest];
    const v = A.createAttestationVerifier(o2);
    const out: any[] = []; for (const c of ctxs) out.push(await v(c)); return out;
  },
  multiRoot: async (pol, inp) => { const v = A.createMultiRootVerifier({ threshold: pol.threshold, roots: pol.roots.map((r: any) => ({ id: r.id, ...(r.required !== undefined ? { required: r.required } : {}), ...(r.suite !== undefined ? { suite: r.suite } : {}), verifier: hw(r.hw) })) }); if (inp === null) return { built: true }; return v.verify({ ...inp, document: inp.document }); },
  attestationEvidenceDigest: (e) => A.attestationEvidenceDigest(e),
  anchorEvidence: (ev, op) => { const ledger = op.ledger === 'ok' ? new LG.TransparencyLedger(op.principal ?? '') : undefined; for (let i = 0; i < (op.preload ?? 0); i++) ledger.appendCommitment('c' + i); return A.anchorAttestationEvidence(ev, { ledger, ...(op.guardianSeed ? { guardianSecret: op.guardianSeed } : {}), ...(op.instanceId !== undefined ? { instanceId: op.instanceId } : {}), ...(op.now !== undefined ? { now: () => op.now } : {}), ...(op.required !== undefined ? { required: op.required } : {}) }); },
  constants: () => Object.fromEntries(Object.entries(A).filter(([k, v]) => typeof v !== 'function' && /^[A-Z][A-Z0-9_]+$/.test(k))),
};
const add = adder(o, REF);

// ---- binding
const EB = (over: any = {}) => ({ holderPub: HPK, grantRef: 'grant-1', epoch: 3, nonce: 'abcdefghijklmnopqrstuvwxyz012345', ...over });
for (const [n, e] of [['ok', EB()], ['epoch0', EB({ epoch: 0 })], ['epoch-big', EB({ epoch: 2 ** 53 - 1 })], ['epoch-neg', EB({ epoch: -1 })], ['epoch-frac', EB({ epoch: 1.5 })], ['epoch-str', EB({ epoch: '3' })], ['epoch-nan', EB({ epoch: { $num: 'NaN' } })], ['epoch-2^53', EB({ epoch: 2 ** 53 })], ['epoch-negzero', EB({ epoch: -0 })], ['epoch-missing', EB({ epoch: undefined })],
  ['holder-empty', EB({ holderPub: '' })], ['holder-num', EB({ holderPub: 5 })], ['holder-missing', EB({ holderPub: undefined })], ['grant-empty', EB({ grantRef: '' })], ['grant-num', EB({ grantRef: 5 })], ['nonce-empty', EB({ nonce: '' })], ['nonce-num', EB({ nonce: 5 })],
  ['unicode', EB({ holderPub: 'hé😀', grantRef: 'g\u0000r', nonce: 'n\n' })], ['nonceIssuedAt-ignored', EB({ nonceIssuedAt: 5 })], ['extra-ignored', EB({ extra: 1 })], ['null', null], ['string', 'x'], ['array', []], ['empty-obj', {}], ['long', EB({ nonce: 'n'.repeat(70000) })],
  ['lp-boundary-ab', EB({ holderPub: 'ab', grantRef: 'c' })], ['lp-boundary-a-bc', EB({ holderPub: 'a', grantRef: 'bc' })]] as [string, any][]) { await add('attestationBinding', n, [e]); await add('attestationBindingB64u', n, [e]); }

// ---- dev attestor + documents
const CL = (over: any = {}) => ({ model_id: 'm1', weights_digest: 'w1', runtime_measurement: 'r1', operator: 'op', nonce: EB().nonce, issued_at: T0 - 1000, expires_at: T0 + 100000, ...over });
const BINDC = { holder_pub: HPK, grant_ref: 'grant-1', epoch: 3 };
const ATS: [string, any][] = [['plain', CL()], ['bound', CL({ ...BINDC })], ['prompt-tools', CL({ system_prompt_digest: 'sp', tool_manifest_digest: 'tm', ...BINDC })], ['partial-binding-ignored', CL({ holder_pub: HPK, grant_ref: 'grant-1' })], ['binding-epoch0', CL({ ...BINDC, epoch: 0 })], ['binding-bad-epoch', CL({ ...BINDC, epoch: -1 })], ['binding-empty-grant', CL({ ...BINDC, grant_ref: '' })],
  ['extra-claims-dropped', CL({ extra: 1, ...BINDC })], ['issued-nan', CL({ issued_at: { $num: 'NaN' } })], ['missing-model', CL({ model_id: undefined })], ['null-model', CL({ model_id: null })], ['empty-claims', {}], ['expires-before-issue', CL({ issued_at: 5, expires_at: 1 })]];
for (const [n, c] of ATS) { await add('attest', n, [AT, null, c]); }
for (const alg of ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65', 'hybrid-nested-ed25519-ml-dsa-65']) await add('attest', 'suite-' + alg, [AT, { alg, pqSeed: PQS }, CL({ ...BINDC, system_prompt_digest: 'sp' })]);
await add('attest', 'suite-unknown', [AT, { alg: 'rot13' }, CL()]); await add('attestorPublicKey', 'plain', [AT, null]); await add('attestorPublicKey', 'ml-dsa', [AT, { alg: 'ml-dsa-65', pqSeed: PQS }]); await add('attestorPublicKey', 'unknown-alg', [AT, { alg: 'rot13' }]);
const mkdoc = (c: any, su: any = null, sk = AT) => J(A.createDevAttestor(sk, suiteOf(su)).attest(c));
const D0 = mkdoc(CL(), null), DB = mkdoc(CL({ ...BINDC })), DPQ = mkdoc(CL({ ...BINDC }), { alg: 'ml-dsa-65', pqSeed: PQS }), DH = mkdoc(CL({ ...BINDC }), { alg: 'hybrid-ed25519-ml-dsa-65', pqSeed: PQS });
await add('attestationDigest', 'plain', [D0]); await add('attestationDigest', 'bound', [DB]); await add('attestationDigest', 'pq', [DPQ]); await add('attestationDigest', 'member-order', [{ sig: D0.sig, ...D0 }]); await add('attestationDigest', 'empty', [{}]); await add('attestationDigest', 'nan', [{ ...D0, issued_at: { $num: 'NaN' } }]);

// ---- registry
await add('registry', 'basic', [[DB, D0], [DB.nonce, 'zzz']]); await add('registry', 'last-wins', [[D0, { ...D0, operator: 'second' }], [D0.nonce]]); await add('registry', 'junk-docs', [[null, 5, {}, { nonce: 5 }, D0, 'x'], [D0.nonce, 'x', '']]);
await add('registry', 'not-array', ['x', ['a']]); await add('registry', 'empty', [[], ['a']]); await add('registry', 'non-string-probe', [[D0], [5, null, {}, D0.nonce]]);

// ---- nonce store
const NS: [string, any, any, any[]][] = [
  ['basic', null, null, [['clock', 100], ['consume', 'a'], ['consume', 'a'], ['consume', 'b']]], ['default-retention-edge', null, null, [['clock', 0], ['consume', 'a'], ['clock', 3_599_999], ['consume', 'a'], ['clock', 3_600_000], ['consume', 'a'], ['consume', 'a']]],
  ['retention-small', null, { retentionMs: 10 }, [['clock', 0], ['consume', 'a'], ['clock', 9], ['consume', 'a'], ['clock', 10], ['consume', 'a']]], ['full', 2, null, [['clock', 1], ['consume', 'a'], ['consume', 'b'], ['consume', 'c'], ['consume', 'a']]],
  ['full-evict-aged', 2, { retentionMs: 10 }, [['clock', 0], ['consume', 'a'], ['clock', 5], ['consume', 'b'], ['clock', 12], ['consume', 'c'], ['consume', 'd'], ['consume', 'b']]], ['full-evict-partial', 3, { retentionMs: 10 }, [['clock', 0], ['consume', 'a'], ['clock', 1], ['consume', 'b'], ['clock', 6], ['consume', 'c'], ['clock', 10], ['consume', 'd'], ['consume', 'e'], ['clock', 11], ['consume', 'e']]],
  ['non-string', null, null, [['clock', 1], ['consume', 5], ['consume', null], ['consume', {}], ['consume', '']]], ['bad-clock', null, null, [['clock', { $num: 'NaN' }], ['consume', 'a'], ['clock', 1.5], ['consume', 'a'], ['clock', { $num: 'Infinity' }], ['consume', 'a'], ['clock', -1], ['consume', 'a'], ['clock', 2 ** 53], ['consume', 'a'], ['clock', 5], ['consume', 'a']]],
  ['max-1', 1, null, [['clock', 0], ['consume', 'a'], ['consume', 'b']]], ['negative-time', null, null, [['clock', -5], ['consume', 'a'], ['consume', 'a'], ['clock', 3_599_995], ['consume', 'a']]],
  ['ctor-max-0', 0, null, []], ['ctor-max-neg', -1, null, []], ['ctor-max-frac', 1.5, null, []], ['ctor-max-nan', { $num: 'NaN' }, null, []], ['ctor-max-str', '5', null, []], ['ctor-max-inf', { $num: 'Infinity' }, null, []], ['ctor-max-big', 2 ** 53, null, []],
  ['ctor-ret-0', null, { retentionMs: 0 }, []], ['ctor-ret-neg', null, { retentionMs: -1 }, []], ['ctor-ret-frac', null, { retentionMs: 1.5 }, []], ['ctor-ret-str', null, { retentionMs: '5' }, []], ['ctor-ret-nan', null, { retentionMs: { $num: 'NaN' } }, []], ['ctor-ret-null', null, { retentionMs: null }, []]];
for (const [n, m, op, ops] of NS) await add('nonceStore', n, [m, op, ops]);

// ---- entropy
for (const [i, [n, m]] of ([['0123456789abcdef0123456789abcdef', null], ['0123456789abcdef', null], ['0123456789abcde', null], ['abcdefghijklmnopqrstuvwxyz', null], ['abcdefghijklmnopqrstuv', null], ['abcdefghijklmnop', null], ['abcdefghijklmnopq', null], ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', null], ['abcdefgabcdefgabcdefgabcdefgabcd', null], ['abcdefghabcdefghabcdefghabcdefgh', null],
  ['abcdefghijklmnopqrstuvwxyz0123456789', 32], ['abcdefghijklmnopqrstuvwxyz0123456789', 64], ['abcdefghijklmnopqrstuvwxyz012345', 8], ['abcdefghijklmnopqrstuvwxyz012345', 0], ['abcdefghijklmnopqrstuvwxyz012345', -5], ['abcdefghijklmnopqrstuvwxyz012345', { $num: 'NaN' }], ['abcdefghijklmnopqrstuvwxyz012345', '40'],
  ['ABCDEFabcdef012345ABCDEFabcdef012345', null], ['0123456789abcdefg0123456789abcdef', null], ['abcdefghijklmnop+rstuvwxyz012345', null], ['abcdefghijklmnop=rstuvwxyz012345', null], ['abcdefghijklmnop rstuvwxyz012345', null], ['abcdefghijklmnop\nrstuvwxyz012345', null], ['', null], [5, null], [null, null], [['a'], null], ['0123456789ab', null], ['0123456789abcdef0123456789abcdef0', null], ['é'.repeat(30), null], ['abcdefgh'.repeat(3), null], ['abcdefg'.repeat(4), null]] as any[]).entries()) await add('nonceEntropyOk', 'n' + i, [n, m]);

// ---- binding match
const ID = { model_id: 'm1', weights_digest: 'w1', runtime_measurement: '5', operator: 'op', system_prompt_digest: 'sp', tool_manifest_digest: 'tm' };
const BINDS: [string, any][] = [['none', null], ['empty', {}], ['model-ok', { model_allowlist: ['m1', 'm2'] }], ['model-bad', { model_allowlist: ['x'] }], ['model-empty-list', { model_allowlist: [] }], ['min-eq-ok', { min_measurement: '5' }], ['min-eq-bad', { min_measurement: '6' }], ['svn-ok', { min_measurement: { svn: 5 } }], ['svn-ok-lower', { min_measurement: { svn: 4 } }], ['svn-bad', { min_measurement: { svn: 6 } }], ['svn-frac', { min_measurement: { svn: 4.5 } }], ['svn-neg', { min_measurement: { svn: -1 } }], ['svn-nan', { min_measurement: { svn: { $num: 'NaN' } } }], ['svn-str', { min_measurement: { svn: '4' } }], ['svn-empty', { min_measurement: {} }],
  ['operator-ok', { operator: 'op' }], ['operator-bad', { operator: 'other' }], ['weights-ok', { weights_allowlist: ['w1'] }], ['weights-bad', { weights_allowlist: ['w2'] }], ['prompt-ok', { system_prompt_allowlist: ['sp'] }], ['prompt-bad', { system_prompt_allowlist: ['zz'] }], ['tools-ok', { tool_manifest_allowlist: ['tm'] }], ['tools-bad', { tool_manifest_allowlist: ['zz'] }], ['require-hw', { require_hardware: true }], ['all-ok', { model_allowlist: ['m1'], min_measurement: { svn: 1 }, operator: 'op', weights_allowlist: ['w1'], system_prompt_allowlist: ['sp'], tool_manifest_allowlist: ['tm'] }], ['allowlist-not-array', { model_allowlist: 'm1' }], ['allowlist-num', { weights_allowlist: [5] }]];
const IDS: [string, any][] = [['full', ID], ['no-prompt', (({ system_prompt_digest, ...r }) => r)(ID)], ['no-tools', (({ tool_manifest_digest, ...r }) => r)(ID)], ['svn-text', { ...ID, runtime_measurement: 'abc' }], ['svn-hex-looking', { ...ID, runtime_measurement: '0x10' }], ['svn-neg', { ...ID, runtime_measurement: '-3' }], ['svn-big', { ...ID, runtime_measurement: '99999999999999999999' }], ['svn-spaces', { ...ID, runtime_measurement: ' 5 ' }], ['svn-frac', { ...ID, runtime_measurement: '5.5' }], ['svn-empty', { ...ID, runtime_measurement: '' }], ['measured-weights', { ...ID, weights_measured: true }]];
for (const [bn, b] of BINDS) { await add('requiresAttestation', bn, [b]); for (const [iname, i] of IDS) { if (iname !== 'full' && !bn.startsWith('svn') && !bn.startsWith('min') && !bn.startsWith('prompt') && !bn.startsWith('tools')) continue; await add('matchAgentBinding', `${bn}/${iname}`, [i, b]); } }
await add('requiresAttestation', 'array', [[]]); await add('requiresAttestation', 'string', ['x']);
await add('matchAgentBinding', 'identity-null', [null, { operator: 'op' }]); await add('matchAgentBinding', 'identity-empty', [{}, { operator: 'op' }]); await add('matchAgentBinding', 'identity-empty-nobinding', [{}, null]);
for (const [n, d, c] of [['eq', { nonce: 'q' }, { pcactn: { attestation: { quote_digest: 'q' } } }], ['ne', { nonce: 'q' }, { pcactn: { attestation: { quote_digest: 'r' } } }], ['doc-nonce-num', { nonce: 5 }, { pcactn: { attestation: { quote_digest: 5 } } }], ['ctx-missing', { nonce: 'q' }, {}], ['ctx-null', { nonce: 'q' }, null], ['doc-null', null, { pcactn: { attestation: { quote_digest: 'q' } } }], ['both-undefined', {}, {}], ['empty-nonce', { nonce: '' }, { pcactn: { attestation: { quote_digest: '' } } }]] as any[]) await add('nonceBinds', n, [d, c]);

// ---- verifyAttestation
const NONCE = EB().nonce;
const envG = (binding: any = {}) => J(mintGrant({ principalSecret: PR, principalPublic: PRPK, holder: HPK, goal: 'g', salt: 'c2FsdC1zYWx0LXNhbHQ', envelope: { predicates: [{ verb: 'read', resource: '*' }], caveats: [], agent_binding: binding, risk_policy: DEFAULT_RISK_POLICY } }).grant);
const G0 = envG(), GBIND = envG({ model_allowlist: ['m1'], operator: 'op', min_measurement: { svn: 1 } }), GBAD = envG({ model_allowlist: ['zzz'] }), GHW = envG({ require_hardware: true });
const GNOENV = J(P.mintRoot({ principalSecret: PR, principalPublic: PRPK, holder: HPK, caveats: [] }));
const ctxFor = (g: any, over: any = {}) => ({ pcactn: { grant_ref: 'grant-1', attestation: { epoch: 3, quote_digest: NONCE }, ...over }, grant: g });
const VI = (over: any = {}) => ({ document: DB, ctx: ctxFor(G0), expected: EB(), nowMs: T0, trustedAttestorKeys: [ATPK], ...over });
const V = (n: string, over: any = {}) => add('verifyAttestation', n, [VI(over)]);
const DOK = mkdoc(CL({ ...BINDC, runtime_measurement: '5' }));
await V('ok'); await V('ok-doc', { document: DOK }); await V('ok-bound-grant', { document: DOK, ctx: ctxFor(GBIND) }); await V('binding-model-reject', { document: DOK, ctx: ctxFor(GBAD) }); await V('no-envelope-grant', { ctx: ctxFor(GNOENV) }); await V('ctx-no-grant', { ctx: { pcactn: ctxFor(G0).pcactn } });
await V('doc-null', { document: null }); await V('doc-string', { document: 'x' }); await V('doc-empty', { document: {} }); await V('doc-array', { document: [] });
await V('nowMs-nan', { nowMs: { $num: 'NaN' } }); await V('nowMs-inf', { nowMs: { $num: 'Infinity' } }); await V('nowMs-str', { nowMs: '5' }); await V('nowMs-missing', { nowMs: undefined });
await V('binding-not-constructible', { expected: EB({ epoch: -1 }) }); await V('binding-empty-holder', { expected: EB({ holderPub: '' }) }); await V('expected-null', { expected: null });
await V('grant-ref-mismatch', { ctx: ctxFor(G0, { grant_ref: 'other' }) }); await V('epoch-mismatch', { ctx: ctxFor(G0, { attestation: { epoch: 4, quote_digest: NONCE } }) }); await V('quote-mismatch', { ctx: ctxFor(G0, { attestation: { epoch: 3, quote_digest: 'zz' } }) }); await V('no-attestation-claim', { ctx: ctxFor(G0, { attestation: undefined }) });
await V('doc-nonce-mismatch', { document: mkdoc(CL({ ...BINDC, nonce: 'different-nonce-different-nonce-1234' })) });
await V('untrusted-attestor', { trustedAttestorKeys: [AT2PK] }); await V('no-trusted-keys', { trustedAttestorKeys: [] }); await V('two-trusted', { trustedAttestorKeys: [AT2PK, ATPK] }); await V('trusted-not-iterable-object', { trustedAttestorKeys: [5, null] });
await V('sig-flip', { document: { ...DB, sig: DB.sig.slice(0, -2) + (DB.sig.endsWith('AA') ? 'BB' : 'AA') } }); await V('sig-missing', { document: (({ sig, ...r }: any) => r)(DB) }); await V('field-tampered', { document: { ...DB, operator: 'evil' } }); await V('attestor-swapped', { document: mkdoc(CL({ ...BINDC }), null, AT2), trustedAttestorKeys: [AT2PK, ATPK] });
await V('attestor-claims-other-key', { document: { ...DB, attestor: AT2PK }, trustedAttestorKeys: [AT2PK] });
await V('alg-unknown', { document: { ...DB, alg: 'rot13' } }); await V('alg-ed25519-explicit-breaks-sig', { document: { ...DB, alg: 'ed25519' } });
await V('pq-no-pin', { document: DPQ }); await V('pq-pinned', { document: DPQ, pqPins: { [ATPK]: DPQ.pq_pk } }); await V('pq-unbound', { document: DPQ, allowUnboundPq: true }); await V('hybrid-pinned', { document: DH, pqPins: { [ATPK]: DH.pq_pk } }); await V('hybrid-unbound', { document: DH, allowUnboundPq: true }); await V('hybrid-no-pin', { document: DH });
await V('binding-absent', { document: D0 }); await V('binding-empty', { document: mkdoc(CL({ ...BINDC }), null) && { ...DB, binding: '' } }); await V('binding-wrong', { document: mkdoc(CL({ holder_pub: HPK, grant_ref: 'other', epoch: 3 })) });
for (const [n, over] of [['issued-future', { issued_at: T0 + 10_000 }], ['issued-edge-now', { issued_at: T0 }], ['expired', { expires_at: T0 - 1 }], ['expires-edge-now', { expires_at: T0 }], ['malformed-window', { issued_at: T0, expires_at: T0 - 5000 }], ['window-nan', { issued_at: { $num: 'NaN' } }], ['window-frac', { issued_at: T0 - 0.5 }], ['window-str', { issued_at: String(T0) }]] as any[]) await V('win-' + n, { document: mkdoc(CL({ ...BINDC, ...over })) });
for (const [n, over] of [['skew-allows-future', { clockSkewMs: 20_000 }], ['skew-allows-expired', { clockSkewMs: 100_000 }]] as any[]) { await V(n + '-a', { document: mkdoc(CL({ ...BINDC, issued_at: T0 + 10_000 })), ...over }); await V(n + '-b', { document: mkdoc(CL({ ...BINDC, expires_at: T0 - 50_000 })), ...over }); }
await V('skew-neg', { clockSkewMs: -5 }); await V('skew-nan', { clockSkewMs: { $num: 'NaN' } }); await V('skew-str', { clockSkewMs: '5' });
for (const [n, e] of [['nonce-age-ok', { nonceIssuedAt: T0 - 1000 }], ['nonce-age-edge', { nonceIssuedAt: T0 - 300_000 }], ['nonce-age-stale', { nonceIssuedAt: T0 - 300_001 }], ['nonce-age-future', { nonceIssuedAt: T0 + 1 }], ['nonce-age-nan', { nonceIssuedAt: { $num: 'NaN' } }], ['nonce-age-str', { nonceIssuedAt: '5' }], ['nonce-age-frac', { nonceIssuedAt: T0 - 0.5 }]] as any[]) await V(n, { expected: EB(e) });
await V('maxage-smaller', { expected: EB({ nonceIssuedAt: T0 - 2000 }), maxNonceAgeMs: 1000 }); await V('maxage-larger-capped', { expected: EB({ nonceIssuedAt: T0 - 400_000 }), maxNonceAgeMs: 900_000 }); await V('maxage-zero-default', { expected: EB({ nonceIssuedAt: T0 - 400_000 }), maxNonceAgeMs: 0 }); await V('maxage-nan', { expected: EB({ nonceIssuedAt: T0 - 400_000 }), maxNonceAgeMs: { $num: 'NaN' } });
await V('skew-extends-age', { expected: EB({ nonceIssuedAt: T0 - 301_000 }), clockSkewMs: 2000 });
// hardware paths
const MI = { model_id: 'm1', weights_digest: 'w1', runtime_measurement: '5', operator: 'op' };
const HDOC = mkdoc(CL({ ...BINDC })); const HDOCH = { ...HDOC, mode: 'hardware' };
const HOK = { result: { ok: true, bound: true, measured: MI } };
await V('hw-ok-software-doc', { hardware: HOK }); await V('hw-ok-hardware-doc', { document: HDOCH, hardware: HOK, expected: EB({ nonceIssuedAt: T0 - 10 }) }); await V('hw-no-nonce-issued-at', { document: HDOCH, hardware: HOK });
const HX = (r: any) => ({ document: HDOCH, expected: EB({ nonceIssuedAt: T0 - 10 }), hardware: { result: r } });
await V('hw-rejected', HX({ ok: false, reason: 'bad quote' })); await V('hw-rejected-noreason', HX({ ok: false })); await V('hw-not-bound', HX({ ok: true, bound: false, measured: MI })); await V('hw-bound-missing', HX({ ok: true, measured: MI })); await V('hw-no-measured', HX({ ok: true, bound: true }));
await V('hw-measured-checked-vs-binding', { ...HX({ ok: true, bound: true, measured: { ...MI, model_id: 'evil' } }), ctx: ctxFor(GBIND) }); await V('hw-measured-ok-binding', { ...HX({ ok: true, bound: true, measured: MI }), ctx: ctxFor(GBIND) });
await V('hw-verifier-throws', { document: HDOCH, expected: EB({ nonceIssuedAt: T0 - 10 }), hardware: { throws: 'kaboom' } }); await V('hw-result-string', HX('ok'));
await V('require-hw-no-verifier', { ctx: ctxFor(GHW) }); await V('require-hw-software-doc', { ctx: ctxFor(GHW), hardware: HOK }); await V('require-hw-hw-doc-ok', { ...HX({ ok: true, bound: true, measured: MI }), ctx: ctxFor(GHW) });
await V('software-doc-mode-hardware-no-verifier', { document: HDOCH }); await V('doc-mode-missing', { document: (({ mode, ...r }: any) => r)(DB) });
await V('hw-ignores-untrusted-attestor', { ...HX({ ok: true, bound: true, measured: MI }), trustedAttestorKeys: [] }); await V('hw-doc-sig-unchecked', { ...HX({ ok: true, bound: true, measured: MI }), document: { ...HDOCH, sig: 'AAAA' } });
await V('hw-doc-binding-unchecked', { ...HX({ ok: true, bound: true, measured: MI }), document: { ...HDOCH, binding: 'zzz' } });
await V('ctx-null', { ctx: null }); await V('ctx-empty', { ctx: {} });

// ---- hook
const HK = (n: string, op: any, ctxs: any[]) => add('attestationHook', n, [{ trustedAttestorKeys: [ATPK], now: T0, docs: [DB], binding: { byNonce: { [NONCE]: EB() } }, ...op }, ctxs]);
const C0 = ctxFor(G0);
await HK('ok', {}, [C0]); await HK('ok-twice-no-store', {}, [C0, C0]); await HK('store-replay', { store: {} }, [C0, C0]); await HK('store-const-false', { storeConsume: false }, [C0]); await HK('store-const-true', { storeConsume: true }, [C0]);
await HK('store-not-consumed-on-failure', { store: {}, trustedAttestorKeys: [] }, [C0, C0]); await HK('store-full', { store: { max: 1 } }, [C0, ctxFor(G0, { attestation: { epoch: 3, quote_digest: 'other' } })]);
await HK('no-binding-source', { binding: undefined }, [C0]); await HK('binding-throws', { binding: 'throws' }, [C0]); await HK('binding-unknown-nonce', { binding: { byNonce: {} } }, [C0]);
await HK('no-doc', { docs: [] }, [C0]); await HK('weak-nonce', { binding: { byNonce: { [NONCE]: EB({ nonce: 'aaaa' }) } }, docs: [mkdoc(CL({ ...BINDC, nonce: 'aaaa' }))] }, [ctxFor(G0, { attestation: { epoch: 3, quote_digest: 'aaaa' } })]);
await HK('min-nonce-bytes', { minNonceBytes: 64 }, [C0]); await HK('min-nonce-bytes-low-floored', { minNonceBytes: 1 }, [C0]);
await HK('self-declared', { binding: undefined, insecure_selfDeclaredNonce: true }, [C0]); await HK('self-declared-weak-nonce-ok', { binding: undefined, insecure_selfDeclaredNonce: true, docs: [mkdoc(CL({ ...BINDC, nonce: 'aaaa' }))] }, [ctxFor(G0, { attestation: { epoch: 3, quote_digest: 'aaaa' } })]);
await HK('self-declared-leaf-from-chain', { binding: undefined, insecure_selfDeclaredNonce: true }, [ctxFor(G0, { cap_chain: [{ holder: 'other' }, { holder: HPK }] })]); await HK('self-declared-wrong-leaf', { binding: undefined, insecure_selfDeclaredNonce: true }, [ctxFor(G0, { cap_chain: [{ holder: 'other' }] })]);
await HK('hardware', { hardware: HOK, docs: [HDOCH], binding: { byNonce: { [NONCE]: EB({ nonceIssuedAt: T0 - 5 }) } } }, [C0]); await HK('now-skew', { now: T0 + 100_000, clockSkewMs: 100_000 }, [C0]);
await HK('ctx-null', {}, [null]); await HK('trusted-not-array', { trustedAttestorKeys: 'x' }, [C0]); await HK('pq-pinned', { docs: [DPQ], pqPins: { [ATPK]: DPQ.pq_pk } }, [C0]);

// ---- multi-root
const RT = (id: string, hwr: any, extra: any = {}) => ({ id, hw: hwr, ...extra });
const OKH = { result: { ok: true, bound: true, measured: MI } }, NOH = { result: { ok: false, reason: 'nope' } }, BADB = { result: { ok: true, bound: false, measured: MI } }, THR = { throws: 'boom' };
const MIN = { document: HDOCH, ctx: C0, nowMs: T0, expected: EB() };
const MR = (n: string, pol: any, inp: any = MIN) => add('multiRoot', n, [pol, inp]);
await MR('1of1', { threshold: 1, roots: [RT('a', OKH)] }); await MR('1of2-one-fails', { threshold: 1, roots: [RT('a', NOH), RT('b', OKH)] }); await MR('2of2-one-fails', { threshold: 2, roots: [RT('a', NOH), RT('b', OKH)] }); await MR('2of3', { threshold: 2, roots: [RT('a', OKH), RT('b', NOH), RT('c', OKH)] });
await MR('required-fails', { threshold: 1, roots: [RT('a', NOH, { required: true }), RT('b', OKH)] }); await MR('required-ok', { threshold: 1, roots: [RT('a', OKH, { required: true }), RT('b', NOH)] }); await MR('all-fail', { threshold: 1, roots: [RT('a', NOH), RT('b', NOH)] });
await MR('throws-counts-as-fail', { threshold: 1, roots: [RT('a', THR), RT('b', OKH)] }); await MR('not-bound', { threshold: 1, roots: [RT('a', BADB)] }); await MR('no-measured', { threshold: 1, roots: [RT('a', { result: { ok: true, bound: true } })] });
await MR('measured-disagree', { threshold: 2, roots: [RT('a', OKH), RT('b', { result: { ok: true, bound: true, measured: { ...MI, weights_digest: 'other' } } })] }); await MR('measured-agree-extra-hostasserted', { threshold: 2, roots: [RT('a', { result: { ok: true, bound: true, measured: MI, hostAsserted: { k: 'v' } } }), RT('b', OKH)] });
await MR('suites', { threshold: 2, roots: [RT('a', OKH, { suite: 'ed25519' }), RT('b', OKH, { suite: 'ml-dsa-65' })] }); await MR('construct-only', { threshold: 1, roots: [RT('a', OKH)] }, null);
for (const [n, pol] of [['threshold-0', { threshold: 0, roots: [RT('a', OKH)] }], ['threshold-neg', { threshold: -1, roots: [RT('a', OKH)] }], ['threshold-frac', { threshold: 1.5, roots: [RT('a', OKH)] }], ['threshold-over', { threshold: 2, roots: [RT('a', OKH)] }], ['threshold-nan', { threshold: { $num: 'NaN' }, roots: [RT('a', OKH)] }], ['threshold-str', { threshold: '1', roots: [RT('a', OKH)] }],
  ['no-roots', { threshold: 1, roots: [] }], ['dup-ids', { threshold: 1, roots: [RT('a', OKH), RT('a', OKH)] }], ['empty-id', { threshold: 1, roots: [RT('', OKH)] }], ['id-num', { threshold: 1, roots: [RT(5 as any, OKH)] }], ['required-more-than-threshold', { threshold: 1, roots: [RT('a', OKH, { required: true }), RT('b', OKH, { required: true })] }], ['required-str', { threshold: 1, roots: [RT('a', OKH, { required: 'yes' })] }]] as any[]) await MR(n, pol, null);
await MR('inputs-null-doc', { threshold: 1, roots: [RT('a', OKH)] }, { ...MIN, document: null });

// ---- evidence digest + anchoring
const EV = (over: any = {}) => ({ identity: { ...MI, weights_measured: true, system_prompt_digest: 'sp', tool_manifest_digest: 'tm' }, binding: EB(), rootIds: ['b', 'a'], suite: 'ed25519', verifiedAt: T0, ...over });
for (const [n, e] of [['full', EV()], ['minimal', { identity: MI, binding: EB(), verifiedAt: T0 }], ['roots-sorted', EV({ rootIds: ['z', 'a', 'M'] })], ['no-roots', EV({ rootIds: undefined })], ['empty-roots', EV({ rootIds: [] })], ['measured-false', EV({ identity: { ...MI, weights_measured: false } })], ['measured-truthy-num', EV({ identity: { ...MI, weights_measured: 1 } })], ['no-suite', EV({ suite: undefined })], ['time-nan', EV({ verifiedAt: { $num: 'NaN' } })], ['binding-extra-ignored', EV({ binding: { ...EB(), nonceIssuedAt: 5 } })], ['roots-dup', EV({ rootIds: ['a', 'a'] })]] as any[]) { await add('attestationEvidenceDigest', n, [e]); }
const AO = (n: string, ev: any, op: any) => add('anchorEvidence', n, [ev, op]);
await AO('ledger-only', EV(), { ledger: 'ok' }); await AO('ledger-preload', EV(), { ledger: 'ok', preload: 3, principal: 'p1' }); await AO('signed', EV(), { ledger: 'ok', guardianSeed: GS, instanceId: 'ins_1', now: T0, principal: 'p1' }); await AO('signed-preload', EV(), { ledger: 'ok', guardianSeed: GS, now: T0, preload: 2 });
await AO('required-signed', EV(), { ledger: 'ok', guardianSeed: GS, now: T0, required: true }); await AO('required-no-secret', EV(), { ledger: 'ok', required: true }); await AO('no-ledger', EV(), { ledger: 'none' }); await AO('no-ledger-required', EV(), { ledger: 'none', required: true, guardianSeed: GS });
await AO('required-false', EV(), { ledger: 'ok', required: false }); await AO('signed-now-nan', EV(), { ledger: 'ok', guardianSeed: GS, now: { $num: 'NaN' } });
await add('constants', 'all', []);
refWrite(o, 'attestation-soft');
