// Oracle: every export of packages/pca/src/attest-pq-software.ts (the post-quantum software / HSM attestation root: statement minting under PQ and
// hybrid suites, the PQ-software verifier), TS reference. Writes out/ref-attest-pq-software.json.gz. Deterministic: every signing suite signs
// deterministically; keys derive from seed labels (the strip tool rewrites `seed` / `edSecret` members to {"$seed": label}); SLH-DSA statements are
// VERIFY-ONLY inputs (their keys never reach the corpus).
//
// PORTING (fn(args) -> native entry point; JSON values; a reference throw ({"$throws"}) only requires the native to refuse)
//   keySpec = {alg, edSecret?, seed?}   edSecret = Ed25519 secret (hybrid suites), seed = the ML-DSA keygen seed (ml-dsa-65 / ml-dsa-87 families)
//   constants []                                       -> {PQ_ATTEST_DOMAIN}
//   attest [keySpec, claims]                           -> {pqPublicKey, ed25519PublicKey?, statement}   (createPqSoftwareAttestor(keys) then .attest(claims);
//                                                          statements are byte-exact: the body is signed as canonical JSON under the domain)
//   buildAttestor [keySpec]                            -> {pqPublicKey, ed25519PublicKey?} | {$throws}     (construction only)
//   verifyPq [scenario]                                -> HardwareAttestationResult
//        scenario = {config, evidence, input}; config = {trustedPqPublicKeys, trustedEd25519PublicKeys?, requirePq?, requireHybrid?, allowedSuites?,
//        policy:{measurements, weightsMeasurements?}, noEvidenceSeam?}; evidence = the statement the seam returns (null = returns undefined);
//        input = {nowMs, expected|undefined}
//   buildVerifier [config]                             -> {built:true} | {$throws}   (construction refusals; the evidence seam, when present, returns undefined)
import { Oracle, refWrite, seed } from './lib.mjs';
import { b64u, B, unb, suiteKey, secretsOfSpec, chr, flip, EXPECTED, T0 } from './attest-roots-kit.mts';

const M: any = await import('../../../packages/pca/src/attest-pq-software.ts');
const PQ: any = await import('../../../packages/pca/src/pq.ts');
const H: any = await import('../../../packages/pca/src/hash.ts');
const o = new Oracle('attest-pq-software', 'tools/pca-audit/oracles/attest-pq-software.mts', 'TS-reference oracle for the post-quantum software attestation root.');
const J = (x: any) => JSON.parse(JSON.stringify(x, (_k, v) => (v instanceof Uint8Array ? { $bytes: b64u(v) } : v)));
const run = (fn: () => any) => { try { return J(fn()); } catch (e: any) { return { $throws: e instanceof Error ? e.message : String(e) }; } };
const add = (fn: string, name: string, args: any[], out: any) => o.add(fn, name, args, out);

const ALGS = ['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65', 'hybrid-nested-ed25519-ml-dsa-65', 'ml-dsa-87', 'hybrid-ed25519-ml-dsa-87', 'slh-dsa-sha2-128f', 'hybrid-ed25519-slh-dsa-sha2-128f', 'slh-dsa-sha2-256s', 'hybrid-ed25519-slh-dsa-sha2-256s'];
const K: Record<string, ReturnType<typeof suiteKey>> = {};
for (const a of [...ALGS, 'ed25519']) K[a] = suiteKey('pq-software/' + a, a);
const attestorOf = (alg: string) => M.createPqSoftwareAttestor({ alg, ...K[alg]!.secrets });
const claims = (over: any = {}) => ({ measurement: 'meas-0001', holder_pub: EXPECTED.holderPub, grant_ref: EXPECTED.grantRef, epoch: EXPECTED.epoch, nonce: EXPECTED.nonce, ...over });
const FULL = { weights_digest: 'wd-1', system_prompt_digest: 'sp-1', tool_manifest_digest: 'tm-1', model_id: 'model-x', operator: 'op-1' };

add('constants', 'all', [], { PQ_ATTEST_DOMAIN: M.PQ_ATTEST_DOMAIN });

// ---- attestor ----
for (const a of ALGS) {
  const spec = K[a]!.spec;
  if (!spec) continue; // SLH-DSA seeds are wider than a label digest: their statements are verify-only below
  for (const [nm, c] of [['basic', claims()], ['full', claims(FULL)], ['weights', claims({ weights_digest: 'wd-1' })], ['unicode', claims({ operator: 'é "', model_id: '\u{1F600}' })]] as any[]) add('attest', `${a}-${nm}`, [spec, c], run(() => { const t = attestorOf(a); return { pqPublicKey: t.pqPublicKey, ...(t.ed25519PublicKey ? { ed25519PublicKey: t.ed25519PublicKey } : {}), statement: t.attest(c) }; }));
}
{
  const spec = K['hybrid-ed25519-ml-dsa-65']!.spec!;
  const at = (nm: string, c: any) => add('attest', nm, [spec, c], run(() => { const t = M.createPqSoftwareAttestor({ alg: 'hybrid-ed25519-ml-dsa-65', ...secretsOfSpec(spec) }); return { pqPublicKey: t.pqPublicKey, ed25519PublicKey: t.ed25519PublicKey, statement: t.attest(c) }; }));
  at('bad-claims-holder-empty', claims({ holder_pub: '' }));
  at('bad-claims-grant-empty', claims({ grant_ref: '' }));
  at('bad-claims-nonce-empty', claims({ nonce: '' }));
  at('bad-claims-epoch-negative', claims({ epoch: -1 }));
  at('bad-claims-epoch-fraction', claims({ epoch: 0.5 }));
  at('bad-claims-epoch-unsafe', claims({ epoch: 2 ** 53 }));
  at('epoch-zero', claims({ epoch: 0 }));
  at('epoch-max-safe', claims({ epoch: 2 ** 53 - 1 }));
  at('optional-empty-strings', claims({ weights_digest: '', model_id: '', operator: '' }));
}
const bld = (nm: string, spec: any, secrets: any) => add('buildAttestor', nm, [spec], run(() => { const t = M.createPqSoftwareAttestor(secrets); return { pqPublicKey: t.pqPublicKey, ...(t.ed25519PublicKey ? { ed25519PublicKey: t.ed25519PublicKey } : {}) }; }));
bld('classical-ed25519-refused', K['ed25519']!.spec, { alg: 'ed25519', edSecret: K['ed25519']!.secrets.edSecret });
bld('unknown-alg', { alg: 'rsa' }, { alg: 'rsa' });
bld('alg-missing', {}, {});
bld('ml65-no-key-material', { alg: 'ml-dsa-65' }, { alg: 'ml-dsa-65' });
bld('hybrid-no-ed-secret', { alg: 'hybrid-ed25519-ml-dsa-65', seed: K['ml-dsa-65']!.spec!.seed }, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: K['ml-dsa-65']!.secrets.mlDsa });
bld('wrong-key-family', { alg: 'ml-dsa-87', seed: K['ml-dsa-65']!.spec!.seed }, { alg: 'ml-dsa-87', mlDsa: K['ml-dsa-65']!.secrets.mlDsa });
bld('fn-dsa-suite-no-material', { alg: 'fn-dsa-512' }, { alg: 'fn-dsa-512' });
bld('ok-ml65', K['ml-dsa-65']!.spec, { alg: 'ml-dsa-65', ...K['ml-dsa-65']!.secrets });
bld('ok-hybrid-87', K['hybrid-ed25519-ml-dsa-87']!.spec, { alg: 'hybrid-ed25519-ml-dsa-87', ...K['hybrid-ed25519-ml-dsa-87']!.secrets });

// ---- verifier ----
const stmtMessage = (body: any) => { const d = H.canonicalBytes(body); const p = H.utf8(M.PQ_ATTEST_DOMAIN); const m = new Uint8Array(p.length + d.length); m.set(p); m.set(d, p.length); return m; };
const mint = (alg: string, c: any = claims(), over: any = {}) => { const st = attestorOf(alg).attest(c); return { ...st, ...over }; };
/** a statement whose body is re-signed after `bodyOver` (so only the verifier's policy checks can refuse it) */
const resign = (alg: string, c: any, bodyOver: any) => {
  const base = attestorOf(alg).attest(c);
  const { sig: _s, pq_sig: _p, ...body } = base as any;
  const nb = { ...body, ...bodyOver };
  for (const k of Object.keys(nb)) if (nb[k] === undefined) delete nb[k];
  const keys = K[alg]!.secrets;
  const parts = PQ.signWithSuite(nb.alg, keys, stmtMessage(nb));
  return { ...nb, sig: parts.sig, ...(parts.pq_sig !== undefined ? { pq_sig: parts.pq_sig } : {}) };
};
const trustedOf = (...algs: string[]) => ({ trustedPqPublicKeys: algs.flatMap((a) => (K[a]!.secrets.mlDsa ? [PQ.encodeMlDsaPublicKey(K[a]!.secrets.mlDsa.publicKey)] : K[a]!.secrets.mlDsa87 ? [PQ.encodeMlDsa87PublicKey(K[a]!.secrets.mlDsa87.publicKey)] : K[a]!.secrets.slhDsa ? [PQ.encodeSlhDsaPublicKey(K[a]!.secrets.slhDsa.publicKey)] : K[a]!.secrets.slhDsa256s ? [PQ.encodeSlhDsa256sPublicKey(K[a]!.secrets.slhDsa256s.publicKey)] : [])), trustedEd25519PublicKeys: algs.flatMap((a) => (K[a]!.pub.edPub ? [K[a]!.pub.edPub] : [])) });
const POL = { measurements: ['meas-0001'] };
const CFG = (algs: string[], over: any = {}) => ({ ...trustedOf(...algs), policy: POL, ...over });
const INPUT = { nowMs: T0, expected: EXPECTED };
const build = (c: any, ev: any) => {
  const cfg: any = { trustedPqPublicKeys: c.trustedPqPublicKeys, ...(c.trustedEd25519PublicKeys ? { trustedEd25519PublicKeys: c.trustedEd25519PublicKeys } : {}), policy: c.policy };
  for (const k of ['requirePq', 'requireHybrid', 'allowedSuites']) if (c[k] !== undefined) cfg[k] = c[k];
  if (!c.noEvidenceSeam) cfg.resolveEvidence = () => (ev === null ? undefined : ev);
  return cfg;
};
const vp = async (nm: string, sc: any) => {
  sc = JSON.parse(JSON.stringify(sc));
  let out: any;
  try { out = J(await M.createPqSoftwareVerifier(build(sc.config, sc.evidence)).verify({ document: {}, ctx: {}, nowMs: sc.input.nowMs, expected: sc.input.expected })); } catch (e: any) { out = { $throws: e instanceof Error ? e.message : String(e) }; }
  add('verifyPq', nm, [sc], out);
};
const sc = (algs: string[], evidence: any, over: any = {}, input: any = INPUT) => ({ config: CFG(algs, over), evidence, input });
for (const a of ALGS) await vp('ok-' + a, sc([a], mint(a)));
await vp('ok-full-claims-identity', sc(['hybrid-ed25519-ml-dsa-65'], mint('hybrid-ed25519-ml-dsa-65', claims(FULL))));
await vp('ok-weights-gated', sc(['ml-dsa-65'], mint('ml-dsa-65', claims({ weights_digest: 'wd-1' })), { policy: { ...POL, weightsMeasurements: ['wd-1', 'wd-2'] } }));
await vp('ok-weights-list-empty', sc(['ml-dsa-65'], mint('ml-dsa-65'), { policy: { ...POL, weightsMeasurements: [] } }));
await vp('ok-require-hybrid', sc(['hybrid-ed25519-ml-dsa-65'], mint('hybrid-ed25519-ml-dsa-65'), { requireHybrid: true }));
await vp('ok-allowed-suites', sc(['ml-dsa-87'], mint('ml-dsa-87'), { allowedSuites: ['ml-dsa-87', 'ml-dsa-65'] }));
await vp('ok-two-trusted-keys', { config: { ...CFG(['ml-dsa-65']), trustedPqPublicKeys: [...trustedOf('ml-dsa-87').trustedPqPublicKeys, ...trustedOf('ml-dsa-65').trustedPqPublicKeys] }, evidence: mint('ml-dsa-65'), input: INPUT });
await vp('ok-require-pq-false-pq-statement', sc(['ml-dsa-65'], mint('ml-dsa-65'), { requirePq: false }));
await vp('deny-require-hybrid-pure', sc(['ml-dsa-65'], mint('ml-dsa-65'), { requireHybrid: true }));
await vp('deny-allowed-suites-other', sc(['ml-dsa-65'], mint('ml-dsa-65'), { allowedSuites: ['ml-dsa-87'] }));
await vp('deny-allowed-suites-empty', sc(['ml-dsa-65'], mint('ml-dsa-65'), { allowedSuites: [] }));
await vp('deny-allowed-suites-not-array', sc(['ml-dsa-65'], mint('ml-dsa-65'), { allowedSuites: 'ml-dsa-65' }));
// classical statement (suite ed25519): refused by default, reaches the signature check with requirePq false
{
  const ed = K['ed25519']!;
  const body: any = { measurement: 'meas-0001', binding: '', alg: 'ed25519', attestor_ed25519: ed.pub.edPub };
  const fromAtt = attestorOf('hybrid-ed25519-ml-dsa-65').attest(claims());
  body.binding = fromAtt.binding;
  const parts = PQ.signWithSuite('ed25519', ed.secrets, stmtMessage(body));
  const classical = { ...body, sig: parts.sig };
  await vp('deny-classical-by-default', { config: { trustedPqPublicKeys: ['AAAA'], trustedEd25519PublicKeys: [ed.pub.edPub], policy: POL }, evidence: classical, input: INPUT });
  await vp('ok-classical-when-pq-not-required', { config: { trustedPqPublicKeys: ['AAAA'], trustedEd25519PublicKeys: [ed.pub.edPub], policy: POL, requirePq: false }, evidence: classical, input: INPUT });
  await vp('deny-classical-untrusted-ed-key', { config: { trustedPqPublicKeys: ['AAAA'], policy: POL, requirePq: false }, evidence: classical, input: INPUT });
  await vp('deny-classical-require-hybrid', { config: { trustedPqPublicKeys: ['AAAA'], trustedEd25519PublicKeys: [ed.pub.edPub], policy: POL, requirePq: false, requireHybrid: true }, evidence: classical, input: INPUT });
}
await vp('deny-no-seam', sc(['ml-dsa-65'], mint('ml-dsa-65'), { noEvidenceSeam: true }));
await vp('deny-evidence-undefined', sc(['ml-dsa-65'], null));
await vp('deny-evidence-string', sc(['ml-dsa-65'], 'x'));
await vp('deny-evidence-no-alg', sc(['ml-dsa-65'], { ...mint('ml-dsa-65'), alg: undefined }));
await vp('deny-alg-unknown', sc(['ml-dsa-65'], { ...mint('ml-dsa-65'), alg: 'rsa' }));
await vp('deny-alg-number', sc(['ml-dsa-65'], { ...mint('ml-dsa-65'), alg: 5 }));
await vp('deny-pq-key-untrusted', sc(['ml-dsa-87'], mint('ml-dsa-65'), {}));
await vp('deny-pq-key-missing', sc(['ml-dsa-65'], { ...mint('ml-dsa-65'), pq_pk: undefined }));
await vp('deny-pq-key-number', sc(['ml-dsa-65'], { ...mint('ml-dsa-65'), pq_pk: 5 }));
await vp('deny-ed-key-untrusted', { config: { ...CFG(['hybrid-ed25519-ml-dsa-65']), trustedEd25519PublicKeys: [K['ed25519']!.pub.edPub] }, evidence: mint('hybrid-ed25519-ml-dsa-65'), input: INPUT });
await vp('deny-ed-key-missing', sc(['hybrid-ed25519-ml-dsa-65'], { ...mint('hybrid-ed25519-ml-dsa-65'), attestor_ed25519: undefined }));
await vp('deny-ed-trust-list-absent', { config: { trustedPqPublicKeys: trustedOf('hybrid-ed25519-ml-dsa-65').trustedPqPublicKeys, policy: POL }, evidence: mint('hybrid-ed25519-ml-dsa-65'), input: INPUT });
for (const a of ['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65', 'hybrid-nested-ed25519-ml-dsa-65', 'ml-dsa-87', 'slh-dsa-sha2-128f', 'hybrid-ed25519-slh-dsa-sha2-128f']) {
  const st = mint(a);
  await vp(`deny-sig-flipped-${a}`, sc([a], { ...st, sig: b64u(flip(unb(st.sig), 5)) }));
  await vp(`deny-sig-truncated-${a}`, sc([a], { ...st, sig: st.sig.slice(0, st.sig.length - 4) }));
  await vp(`deny-measurement-edited-${a}`, sc([a], { ...st, measurement: 'meas-0002' }, { policy: { measurements: ['meas-0002'] } }));
  await vp(`deny-binding-edited-${a}`, sc([a], { ...st, binding: chr(st.binding, 3) }));
  if (st.pq_sig) {
    await vp(`deny-pq-sig-flipped-${a}`, sc([a], { ...st, pq_sig: b64u(flip(unb(st.pq_sig), 9)) }));
    await vp(`deny-pq-sig-missing-${a}`, sc([a], { ...st, pq_sig: undefined }));
  } else await vp(`ok-spurious-pq-sig-ignored-${a}`, sc([a], { ...st, pq_sig: 'AAAA' }));
}
await vp('deny-nested-signature-over-plain-message', sc(['hybrid-ed25519-ml-dsa-65'], { ...mint('hybrid-ed25519-ml-dsa-65'), alg: 'hybrid-nested-ed25519-ml-dsa-65' }));
await vp('deny-hybrid-cross-key-pq', { config: { ...CFG(['hybrid-ed25519-ml-dsa-65']), trustedPqPublicKeys: trustedOf('ml-dsa-65').trustedPqPublicKeys }, evidence: mint('hybrid-ed25519-ml-dsa-65'), input: INPUT });
await vp('deny-extra-member', sc(['ml-dsa-65'], { ...mint('ml-dsa-65'), extra: 1 }));
await vp('deny-alg-downgrade-signed-body', sc(['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'], { ...mint('hybrid-ed25519-ml-dsa-65'), alg: 'ml-dsa-65' }));
await vp('deny-sig-empty', sc(['ml-dsa-65'], { ...mint('ml-dsa-65'), sig: '' }));
await vp('deny-sig-missing', sc(['ml-dsa-65'], { ...mint('ml-dsa-65'), sig: undefined }));
await vp('deny-sig-not-base64url', sc(['ml-dsa-65'], { ...mint('ml-dsa-65'), sig: '!!!' }));
// binding (the statement is correctly re-signed: only the binding check can refuse)
const SB = (b: string | undefined) => resign('ml-dsa-65', claims(), { binding: b });
await vp('deny-binding-empty', sc(['ml-dsa-65'], SB('')));
await vp('deny-binding-absent', sc(['ml-dsa-65'], SB(undefined)));
await vp('deny-binding-wrong', sc(['ml-dsa-65'], SB('AAAA')));
await vp('deny-binding-holder', sc(['ml-dsa-65'], mint('ml-dsa-65'), {}, { nowMs: T0, expected: { ...EXPECTED, holderPub: 'other' } }));
await vp('deny-binding-grant', sc(['ml-dsa-65'], mint('ml-dsa-65'), {}, { nowMs: T0, expected: { ...EXPECTED, grantRef: 'g2' } }));
await vp('deny-binding-epoch', sc(['ml-dsa-65'], mint('ml-dsa-65'), {}, { nowMs: T0, expected: { ...EXPECTED, epoch: 8 } }));
await vp('deny-binding-nonce', sc(['ml-dsa-65'], mint('ml-dsa-65'), {}, { nowMs: T0, expected: { ...EXPECTED, nonce: 'n2' } }));
await vp('deny-expected-missing', sc(['ml-dsa-65'], mint('ml-dsa-65'), {}, { nowMs: T0 }));
await vp('deny-expected-not-constructible', sc(['ml-dsa-65'], mint('ml-dsa-65'), {}, { nowMs: T0, expected: { ...EXPECTED, epoch: -1 } }));
// policy
await vp('deny-measurement-not-allowlisted', sc(['ml-dsa-65'], mint('ml-dsa-65'), { policy: { measurements: ['other'] } }));
await vp('deny-weights-absent', sc(['ml-dsa-65'], mint('ml-dsa-65'), { policy: { ...POL, weightsMeasurements: ['wd-1'] } }));
await vp('deny-weights-wrong', sc(['ml-dsa-65'], mint('ml-dsa-65', claims({ weights_digest: 'zz' })), { policy: { ...POL, weightsMeasurements: ['wd-1'] } }));
await vp('deny-measurement-case-sensitive', sc(['ml-dsa-65'], mint('ml-dsa-65', claims({ measurement: 'MEAS-0001' })), {}));
await vp('ok-measurement-in-second-slot', sc(['ml-dsa-65'], mint('ml-dsa-65'), { policy: { measurements: ['other', 'meas-0001'] } }));
// construction
const cons = (nm: string, c: any) => add('buildVerifier', nm, [c], run(() => { M.createPqSoftwareVerifier({ ...c, ...(c.noEvidenceSeam ? {} : { resolveEvidence: () => undefined }) }); return { built: true }; }));
cons('ok', { trustedPqPublicKeys: ['AAAA'], policy: POL });
cons('no-trusted-keys', { trustedPqPublicKeys: [], policy: POL });
cons('trusted-keys-missing', { policy: POL });
cons('trusted-keys-not-array', { trustedPqPublicKeys: 'AAAA', policy: POL });
cons('policy-empty', { trustedPqPublicKeys: ['AAAA'], policy: { measurements: [] } });
cons('policy-missing', { trustedPqPublicKeys: ['AAAA'] });
cons('policy-not-array', { trustedPqPublicKeys: ['AAAA'], policy: { measurements: 'x' } });
cons('no-seam-builds', { trustedPqPublicKeys: ['AAAA'], policy: POL, noEvidenceSeam: true });

refWrite(o, 'attest-pq-software');
