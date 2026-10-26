// Deterministic wire-level vectors for the signed agent passport (ed25519; every vector is verifiable offline).
import { b64u, canonicalBytesStrict, utf8 } from '../hash';
import { publicKeyOf, sign } from '../keys';
import type { HardwareAttestationVerifier, MeasuredIdentity } from '../attestation';
import { PASSPORT_SIG_DOMAIN, issuePassport, passportEvidenceBinding, signPassport, verifyPassport, type SignedPassport } from '../passport';
import { verifierFromConfig, type JsonObject, type Vendor } from './attestation-wire';
import { passportHardwareEvidence } from './attestation-passport-evidence';
import { encodeMlDsaPublicKey, fnDsa1024Keygen, fnDsa512Keygen, mlDsa65Keygen, mlDsa87Keygen, slhDsa128fKeygen, slhDsa256sKeygen, suitePqPublicKey, type SigAlg, type SignerSuiteOpts } from '../pq';

export const PASSPORT_VECTOR_NOW = 1_800_000_000_000;
const ISS_SECRET = new Uint8Array(32).fill(7);
const OTHER_SECRET = new Uint8Array(32).fill(9);
const SUBJECT = b64u(publicKeyOf(new Uint8Array(32).fill(3)));
const OTHER_SUBJECT = b64u(publicKeyOf(new Uint8Array(32).fill(4)));
const ISS = b64u(publicKeyOf(ISS_SECRET));

/** What the stub hardware verifier answers in a vector (natives plug the same answer into their `attest` seam). */
export interface HardwareStub {
  ok: boolean;
  bound: boolean;
  throws?: boolean;
  measured?: Record<string, unknown> | null;
}

export interface PassportVector {
  name: string;
  signed?: unknown;
  /** Use the `signed` document of the vector with this name. */
  signed_ref?: string;
  pqPins?: Record<string, string>;
  hardware?: HardwareStub;
  /** A REAL vendor verifier built from the attestation-evidence `config` schema; `evidence` is what its resolver answers. Mutually exclusive with `hardware`. */
  hardware_verifier?: { vendor: Vendor; config: JsonObject; evidence: JsonObject };
  /** The binding the hardware verifier must be handed (recorded from the reference). */
  expectBinding?: { holderPub: string; grantRef: string; epoch: number; nonce: string };
  trustedIssuers: string[];
  now: number;
  clockSkewMs?: number;
  maxEvidenceAgeMs?: number;
  subject?: string;
  revoked: string[];
  expect: { ok: true } | { ok: false; reason: string };
}

const ident = { model_id: 'm1', weights_digest: 'w1', operator: 'acme', hardware_rooted: false, weights_measured: false, issued_at: PASSPORT_VECTOR_NOW - 1000 };

export async function buildPassportVectors() {
  const p = issuePassport(ident);
  const good = signPassport(p, { issuerSecret: ISS_SECRET, subject: SUBJECT, exp: PASSPORT_VECTOR_NOW + 60_000 });
  const clone = (): SignedPassport => JSON.parse(JSON.stringify(good));
  const base = { trustedIssuers: [ISS], now: PASSPORT_VECTOR_NOW, revoked: [] as string[] };
  const hwId = issuePassport({ ...ident, hardware_rooted: true });
  const hwUnsigned = { ...signPassport(hwId, { issuerSecret: ISS_SECRET, subject: SUBJECT, exp: PASSPORT_VECTOR_NOW + 60_000, evidence: { document: { nonce: 'n' } as never, at: PASSPORT_VECTOR_NOW - 1000 } }) };
  // an issuer that signed a bad body (signPassport itself refuses these)
  const rawSign = (over: Record<string, unknown>) => {
    const body = { typ: 'atlas-pca/passport', ver: 1, passport: p, iss: ISS, sub: SUBJECT, iat: ident.issued_at, nbf: ident.issued_at, exp: PASSPORT_VECTOR_NOW + 60_000, ...over };
    return { ...body, sig: b64u(sign(ISS_SECRET, new Uint8Array([...utf8(PASSPORT_SIG_DOMAIN), ...canonicalBytesStrict(body)]))) };
  };
  const v: Omit<PassportVector, 'expect'>[] = [
    { name: 'ok', signed: good, ...base },
    { name: 'ok-skew-nbf', signed: signPassport(p, { issuerSecret: ISS_SECRET, subject: SUBJECT, nbf: PASSPORT_VECTOR_NOW + 5_000, exp: PASSPORT_VECTOR_NOW + 60_000 }), ...base, clockSkewMs: 5_000 },
    { name: 'not-an-object', signed: 'x', ...base },
    { name: 'wrong-version', signed: { ...clone(), ver: 2 }, ...base },
    { name: 'unknown-alg', signed: { ...clone(), alg: 'rot13' }, ...base },
    { name: 'unknown-issuer', signed: good, ...base, trustedIssuers: [b64u(publicKeyOf(OTHER_SECRET))] },
    { name: 'no-trusted-issuers', signed: good, ...base, trustedIssuers: [] },
    { name: 'tampered-model', signed: { ...clone(), passport: { ...p, model_id: 'm2' } }, ...base },
    { name: 'tampered-operator', signed: { ...clone(), passport: { ...p, operator: 'evil' } }, ...base },
    { name: 'tampered-subject', signed: { ...clone(), sub: OTHER_SUBJECT }, ...base },
    { name: 'tampered-exp', signed: { ...clone(), exp: PASSPORT_VECTOR_NOW + 600_000 }, ...base },
    { name: 'forged-hardware-flag', signed: { ...clone(), passport: { ...p, hardware_rooted: true } }, ...base },
    { name: 'not-yet-valid', signed: signPassport(p, { issuerSecret: ISS_SECRET, subject: SUBJECT, nbf: PASSPORT_VECTOR_NOW + 5_000, exp: PASSPORT_VECTOR_NOW + 60_000 }), ...base },
    { name: 'expired', signed: signPassport(p, { issuerSecret: ISS_SECRET, subject: SUBJECT, exp: PASSPORT_VECTOR_NOW - 1 }), ...base },
    { name: 'expired-at-boundary', signed: signPassport(p, { issuerSecret: ISS_SECRET, subject: SUBJECT, exp: PASSPORT_VECTOR_NOW }), ...base },
    { name: 'subject-ok', signed: good, ...base, subject: SUBJECT },
    { name: 'subject-mismatch', signed: good, ...base, subject: OTHER_SUBJECT },
    { name: 'revoked', signed: good, ...base, revoked: [p.id] },
    { name: 'hardware-rooted-without-evidence', signed: rawSign({ passport: hwId }), ...base },
    { name: 'hardware-evidence-stale', signed: signPassport(hwId, { issuerSecret: ISS_SECRET, subject: SUBJECT, exp: PASSPORT_VECTOR_NOW + 60_000, evidence: { document: { nonce: 'n' } as never, at: PASSPORT_VECTOR_NOW - 25 * 3600_000 } }), ...base },
    { name: 'hardware-evidence-stale-custom-max', signed: hwUnsigned, ...base, maxEvidenceAgeMs: 100 },
    { name: 'hardware-evidence-future', signed: signPassport(hwId, { issuerSecret: ISS_SECRET, subject: SUBJECT, exp: PASSPORT_VECTOR_NOW + 60_000, evidence: { document: { nonce: 'n' } as never, at: PASSPORT_VECTOR_NOW + 1 } }), ...base },
    { name: 'id-mismatch', signed: rawSign({ passport: { ...p, id: 'not-the-fingerprint' } }), ...base },
    { name: 'hardware-rooted-evidence-no-verifier', signed: hwUnsigned, ...base },
  ];
  // ---- every signature suite the TypeScript reference registers and the natives implement (LESS needs an optional backend: not here)
  const pqKeys = {
    mlDsa: mlDsa65Keygen(new Uint8Array(32).fill(11)),
    mlDsa87: mlDsa87Keygen(new Uint8Array(32).fill(12)),
    slhDsa: slhDsa128fKeygen(new Uint8Array(48).fill(13)),
    slhDsa256s: slhDsa256sKeygen(new Uint8Array(96).fill(14)),
  };
  const fn512 = fnDsa512Keygen(new Uint8Array(32).fill(15));
  const fn1024 = fnDsa1024Keygen(new Uint8Array(32).fill(16));
  const signSeed = new Uint8Array(32).fill(17);
  const suiteKeys: Record<string, SignerSuiteOpts> = {
    'ml-dsa-65': { mlDsa: pqKeys.mlDsa },
    'hybrid-ed25519-ml-dsa-65': { mlDsa: pqKeys.mlDsa },
    'hybrid-nested-ed25519-ml-dsa-65': { mlDsa: pqKeys.mlDsa },
    'ml-dsa-87': { mlDsa87: pqKeys.mlDsa87 },
    'hybrid-ed25519-ml-dsa-87': { mlDsa87: pqKeys.mlDsa87 },
    'slh-dsa-sha2-128f': { slhDsa: pqKeys.slhDsa },
    'hybrid-ed25519-slh-dsa-sha2-128f': { slhDsa: pqKeys.slhDsa },
    'slh-dsa-sha2-256s': { slhDsa256s: pqKeys.slhDsa256s },
    'hybrid-ed25519-slh-dsa-sha2-256s': { slhDsa256s: pqKeys.slhDsa256s },
    'fn-dsa-512': { fnDsa512: { ...fn512, signSeed } },
    'fn-dsa-1024': { fnDsa1024: { ...fn1024, signSeed } },
  };
  const wrongPk = encodeMlDsaPublicKey(mlDsa65Keygen(new Uint8Array(32).fill(99)).publicKey);
  const suiteVectors: Omit<PassportVector, 'expect'>[] = [];
  for (const [alg, keys] of Object.entries(suiteKeys)) {
    const signed = signPassport(p, { issuerSecret: ISS_SECRET, subject: SUBJECT, exp: PASSPORT_VECTOR_NOW + 60_000, suite: { alg: alg as SigAlg, ...keys } });
    const pk = suitePqPublicKey(alg, keys) as string;
    suiteVectors.push(
      { name: `suite-${alg}`, signed, pqPins: { [ISS]: pk }, ...base },
      { name: `suite-${alg}-unpinned`, signed_ref: `suite-${alg}`, ...base },
      { name: `suite-${alg}-wrong-pin`, signed_ref: `suite-${alg}`, pqPins: { [ISS]: wrongPk }, ...base },
    );
    if (alg === 'ml-dsa-65' || alg === 'hybrid-nested-ed25519-ml-dsa-65') {
      suiteVectors.push({ name: `suite-${alg}-tampered`, signed: { ...signed, passport: { ...p, model_id: 'm2' } }, pqPins: { [ISS]: pk }, ...base });
    }
    if (alg === 'hybrid-ed25519-ml-dsa-65') {
      const { alg: _a, pq_pk: _k, pq_sig: _s, ...stripped } = signed;
      suiteVectors.push({ name: 'suite-downgrade-stripped', signed: stripped, pqPins: { [ISS]: pk }, ...base });
    }
  }

  // ---- hardware-rooted passports: a stub vendor verifier answers; the passport-side logic is what is under test
  const HWID = { ...ident, hardware_rooted: true, weights_measured: true };
  const hwSign = (id: Parameters<typeof issuePassport>[0], at = PASSPORT_VECTOR_NOW - 1000) =>
    signPassport(issuePassport(id), { issuerSecret: ISS_SECRET, subject: SUBJECT, exp: PASSPORT_VECTOR_NOW + 60_000, evidence: { document: { nonce: 'n-hw' } as never, at } });
  const hw1 = hwSign(HWID);
  const M = { model_id: 'm1', operator: 'acme', weights_digest: 'w1', weights_measured: true, runtime_measurement: 'r1', system_prompt_digest: 'sp', tool_manifest_digest: 'tm' };
  const claims = { ...HWID, runtime_measurement: '42', system_prompt_digest: 'sp', tool_manifest_digest: 'tm' };
  const hw2 = hwSign(claims);
  const M2 = { ...M, runtime_measurement: '42' };
  const stub = (hardware: HardwareStub, signed: unknown, name: string): Omit<PassportVector, 'expect'> => ({ name, signed, hardware, ...base });
  const hardwareVectors = [
    stub({ ok: true, bound: true, measured: M }, hw1, 'hardware-ok'),
    stub({ ok: true, bound: true, measured: M2 }, hw2, 'hardware-ok-optional-claims'),
    stub({ ok: true, bound: true, measured: { ...M2, runtime_measurement: '43' } }, hw2, 'hardware-runtime-mismatch'),
    stub({ ok: true, bound: true, measured: { ...M2, system_prompt_digest: 'x' } }, hw2, 'hardware-prompt-mismatch'),
    stub({ ok: true, bound: true, measured: { ...M2, tool_manifest_digest: 'x' } }, hw2, 'hardware-tools-mismatch'),
    stub({ ok: true, bound: false, measured: M }, hw1, 'hardware-unbound'),
    stub({ ok: false, bound: true, measured: M }, hw1, 'hardware-refused'),
    stub({ ok: true, bound: true, throws: true }, hw1, 'hardware-verifier-throws'),
    stub({ ok: true, bound: true, measured: null }, hw1, 'hardware-no-measured'),
    stub({ ok: true, bound: true, measured: { ...M, model_id: 'other' } }, hw1, 'hardware-model-mismatch'),
    stub({ ok: true, bound: true, measured: { ...M, operator: 'other' } }, hw1, 'hardware-operator-mismatch'),
    stub({ ok: true, bound: true, measured: { ...M, weights_digest: 'other' } }, hw1, 'hardware-weights-mismatch'),
    stub({ ok: true, bound: true, measured: { ...M, weights_measured: false } }, hw1, 'hardware-weights-not-measured'),
    stub({ ok: true, bound: true, measured: M }, hwSign(HWID, PASSPORT_VECTOR_NOW - 25 * 3600_000), 'hardware-ok-but-stale'),
  ];

  // ---- hardware-rooted passports verified by a REAL vendor verifier (synthetic evidence minted under test roots, bound to the passport)
  const vendorVectors: Omit<PassportVector, 'expect'>[] = [];
  const IDENTITY = { model_id: HWID.model_id, operator: HWID.operator, weights_digest: HWID.weights_digest, weights_measured: true };
  const hwPassport = issuePassport(HWID);
  const bindFor = (vendor: string, subject = SUBJECT, id = hwPassport.id) => passportEvidenceBinding(id, subject, `n-${vendor}`);
  const sign = (vendor: string, at = PASSPORT_VECTOR_NOW - 1000, nonce = `n-${vendor}`) =>
    signPassport(hwPassport, { issuerSecret: ISS_SECRET, subject: SUBJECT, exp: PASSPORT_VECTOR_NOW + 60_000, evidence: { document: { nonce } as never, at } });
  for (const vendor of ['amd-sev-snp', 'intel-tdx-dcap', 'azure-maa', 'gcp-confidential-space', 'nvidia-gpu-spdm'] as const) {
    const good = passportHardwareEvidence(vendor, bindFor(vendor), PASSPORT_VECTOR_NOW);
    const hv = (config: JsonObject, evidence: JsonObject) => ({ vendor, config: { ...config, identity_overrides: IDENTITY }, evidence });
    const name = `hardware-${vendor}`;
    vendorVectors.push(
      { name: `${name}-ok`, signed: sign(vendor), hardware_verifier: hv(good.config, good.evidence), ...base },
      { name: `${name}-identity-mismatch`, signed: sign(vendor), hardware_verifier: { vendor, config: { ...good.config, identity_overrides: { ...IDENTITY, operator: 'other' } }, evidence: good.evidence }, ...base },
      { name: `${name}-bound-to-another-passport`, signed: sign(vendor), hardware_verifier: hv(good.config, passportHardwareEvidence(vendor, bindFor(vendor, SUBJECT, 'passport-other'), PASSPORT_VECTOR_NOW).evidence), ...base },
      { name: `${name}-bound-to-another-subject`, signed: sign(vendor), hardware_verifier: hv(good.config, passportHardwareEvidence(vendor, bindFor(vendor, OTHER_SUBJECT), PASSPORT_VECTOR_NOW).evidence), ...base },
      { name: `${name}-nonce-differs`, signed: sign(vendor, PASSPORT_VECTOR_NOW - 1000, `n-${vendor}-x`), hardware_verifier: hv(good.config, good.evidence), ...base },
      { name: `${name}-no-evidence`, signed: sign(vendor), hardware_verifier: { vendor, config: { ...good.config, identity_overrides: IDENTITY }, evidence: null as never }, ...base },
      { name: `${name}-stale`, signed: sign(vendor, PASSPORT_VECTOR_NOW - 25 * 3600_000), hardware_verifier: hv(good.config, good.evidence), ...base },
      { name: `${name}-wrong-trust-pin`, signed: sign(vendor), hardware_verifier: hv(good.wrongPinConfig, good.evidence), ...base },
    );
  }

  const docs = new Map<string, unknown>();
  const runAll = async (list: Omit<PassportVector, 'expect'>[]): Promise<PassportVector[]> => {
  const vectors: PassportVector[] = [];
  for (const x of list) {
    const signed = x.signed_ref !== undefined ? docs.get(x.signed_ref) : x.signed;
    if (x.name) docs.set(x.name, signed);
    let seen: PassportVector['expectBinding'];
    const verifier: HardwareAttestationVerifier | undefined = x.hardware_verifier ? verifierFromConfig(x.hardware_verifier.vendor, x.hardware_verifier.config, x.hardware_verifier.evidence) : x.hardware && {
      verify: (i) => {
        seen = { holderPub: i.expected.holderPub, grantRef: i.expected.grantRef, epoch: i.expected.epoch, nonce: i.expected.nonce };
        if (x.hardware!.throws) throw new Error('verifier down');
        return { ok: x.hardware!.ok, bound: x.hardware!.bound, ...(x.hardware!.measured ? { measured: x.hardware!.measured as unknown as MeasuredIdentity } : {}) };
      },
    };
    const r = await verifyPassport(signed, { trustedIssuers: x.trustedIssuers, now: x.now, clockSkewMs: x.clockSkewMs, maxEvidenceAgeMs: x.maxEvidenceAgeMs, subject: x.subject, pqPins: x.pqPins, attestationVerifier: verifier, revocation: ({ id }) => x.revoked.includes(id) });
    const out: PassportVector = { ...x, ...(x.signed_ref !== undefined ? {} : { signed }), expect: r.ok ? { ok: true } : { ok: false, reason: r.reason } };
    if (seen) out.expectBinding = seen;
    vectors.push(out);
  }
  return vectors;
  };
  const vectors = await runAll([...v, ...suiteVectors, ...hardwareVectors]);
  const hardwareRealVectors = await runAll(vendorVectors);
  return {
    format: 1,
    suite: 'agent-passport',
    layer: 'identity',
    description: 'Signed agent passport: a signature over domain "atlas-pca/passport-sig/v1\\0" || canonical JSON of every field except sig/pq_sig. Native verifiers reproduce `expect.ok` and `expect.reason` (reason text beyond the code is not part of the contract). Check order: shape, version, suite, issuer, signature, id, validity window, subject, revocation, hardware evidence (presence, age, verifier, binding, identity). A vector with `signed_ref` reuses the document of the named vector. `pqPins` pins the PQ key of the issuer; a non-Ed25519 suite verifies only under it. A verifier that does not implement the suite of a vector must answer `unsupported_suite` instead of `expect`. A vector with `hardware` stands in for a vendor verifier: the stub answers {ok, bound, measured} (or throws) and must be handed `expectBinding`; verifiers without a stub seam answer `hardware_verifier_missing`. `passport_hardware_vectors` (same row shape) carry a `hardware_verifier` {vendor, config, evidence} instead of a stub: build the real vendor verifier with verifier_from_config(vendor, config) (schema in attestation-evidence-vectors.json), let its evidence resolver answer `evidence` (null: none), and verify; the evidence is bound to (subject key, grant `passport:<id>`, epoch 0, the evidence nonce). Natives without a vendor verifier skip this table.',
    passport_vectors: vectors,
    passport_hardware_vectors: hardwareRealVectors,
  };
}
