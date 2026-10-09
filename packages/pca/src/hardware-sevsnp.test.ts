/**
 * Tests for the AMD SEV-SNP report primitives (`hardware-sevsnp.ts`).
 *
 * Two kinds of evidence:
 *   1. A GENUINE AMD SEV-SNP report + VCEK + ASK/ARK chain captured from an Azure confidential VM
 *      (AMD EPYC Milan; testdata/sevsnp-real/): the end-to-end `verifyGenuineSevSnpReport` path, the real
 *      RSA-PSS chain to the pinned AMD ARK, and the report-signature check.
 *   2. Reports in the genuine layout that the tests build and sign with a LOCAL test key (see
 *      `test-support/sevsnp-report.ts`), used only to exercise parsing, policy gates, the VCEK<->report
 *      binding scan and the policy gates, where real silicon cannot supply the variations.
 *      The test key stands in for the VCEK; no production code path accepts such a report.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { p384 } from '@noble/curves/p384';
import { sha384 } from '@noble/hashes/sha512';
import {
  type EcdsaP384PublicKey,
  AMD_MILAN_ARK_SPKI_SHA384,
  SEV_SNP_POLICY_DEBUG_BIT,
  checkSevSnpPolicy,
  checkVcekReportBinding,
  ecdsaP384PublicKey,
  extractTbsCertificate,
  extractVcekPublicKey,
  makeDefaultDeriveIdentity,
  parseSevSnpReport,
  sevSnpSignatureToCompact,
  splitPemCertificates,
  toHex,
  verifyAmdCertChain,
  verifyGenuineSevSnpReport,
  verifySevSnpReportSignature,
} from './hardware-sevsnp';
import {
  attestationBinding,
  createAttestationVerifier,
  type AttestationDocument,
  type ExpectedAttestationBinding,
  type HardwareAttestationVerifier,
} from './attestation';
import { mintGrant, type AgentBinding } from './envelope';
import { buildPCActn, type PCActn } from './pcactn';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY } from './risk';
import type { Capability } from './capability';
import { serializeSevSnpReport } from './test-support/sevsnp-report';
import { forgeCert, forgeKey, ext } from './test-support/forge-x509';
import { amdVcekExtensions } from './test-support/forge-amd';

// ── local P-384 test key (stands in for the VCEK) ─────────────────────────────────────────────────
interface TestKey {
  priv: Uint8Array;
  pub: EcdsaP384PublicKey;
}
function genP384(): TestKey {
  const priv = p384.utils.randomPrivateKey();
  return { priv, pub: ecdsaP384PublicKey(p384.getPublicKey(priv, false)) };
}
/** ECDSA-P384/SHA-384 sign, returning the big-endian compact r||s. */
function signP384(priv: Uint8Array, msg: Uint8Array): Uint8Array {
  return p384.sign(sha384(msg), priv, { lowS: false }).toCompactRawBytes();
}
/** Encode a big-endian 48-byte scalar back into AMD's 72-byte little-endian signature field. */
function toLe72(beCompactHalf: Uint8Array): Uint8Array {
  const le = new Uint8Array(72);
  for (let i = 0; i < beCompactHalf.length; i++) le[i] = beCompactHalf[beCompactHalf.length - 1 - i]!;
  return le;
}

const ASK = genP384();
const VCEK = genP384();

const MEASUREMENT = new Uint8Array(48).fill(0xab);
const CHIP_ID = new Uint8Array(64).fill(0x5c);
const HOST_DATA = new Uint8Array(32).fill(0x7d);
const WEIGHTS = new Uint8Array(48).fill(0x9e); // a known weights digest (test-double identity only)
const WEIGHTS_HEX = toHex(WEIGHTS);
const NONCE = 'nonce-epoch-1';
const T = 1_000_000;
/** A verifier clock inside the validity window of the committed real chains (VCEK issued 2026-10-06). */
const REAL_NOW_MS = Date.parse('2026-10-08T12:00:00Z');
const P = generateKeyPair();
const A = generateKeyPair();
const EXPECTED: ExpectedAttestationBinding = {
  holderPub: encodeKey(A.publicKey),
  grantRef: 'grant-ref-1',
  epoch: 1,
  nonce: NONCE,
  nonceIssuedAt: T - 1000,
};
const BOUND = attestationBinding(EXPECTED);

// ── X.509 fabrication: real certificates (forge-x509) carrying the AMD VCEK extension profile ───────
interface VcekExt {
  chip?: Uint8Array;
  bl?: number;
  tee?: number;
  snp?: number;
  ucode?: number;
}
const forgedTbs = (extensions: Uint8Array[]): Uint8Array =>
  extractTbsCertificate(
    forgeCert({
      subject: [['CN', 'SEV-VCEK']],
      issuer: [['CN', 'SEV-Genoa']],
      subjectKey: forgeKey('binding-subject', 'P-384'),
      signer: forgeKey('binding-signer', 'P-384'),
      serial: 1n,
      notBefore: new Date('2022-01-01Z'),
      notAfter: new Date('2040-01-01Z'),
      extensions,
    }).der,
  );
function askTbs(): Uint8Array {
  return forgedTbs([ext.basicConstraints(true, 0)]);
}
function vcekTbs(e: VcekExt = {}): Uint8Array {
  // defaults match the default report: reported_tcb 0x0003_0000_0000_0007 => bl 7, tee 0, snp 3, ucode 0
  return forgedTbs(amdVcekExtensions({ chip: e.chip ?? CHIP_ID, bl: e.bl ?? 7, tee: e.tee ?? 0, snp: e.snp ?? 3, ucode: e.ucode ?? 0 }));
}

/** Craft a report in the genuine layout with known fields and sign [0x000,0x2A0) with the test VCEK. */
function buildSignedReport(over: Parameters<typeof serializeSevSnpReport>[0] = {}, signer: Uint8Array = VCEK.priv): Uint8Array {
  const fields = {
    version: 2,
    guest_svn: 3,
    vmpl: 0,
    reported_tcb: 0x0003_0000_0000_0007n,
    report_data: BOUND,
    measurement: MEASUREMENT,
    chip_id: CHIP_ID,
    host_data: HOST_DATA,
    ...over,
  };
  const parsed = parseSevSnpReport(serializeSevSnpReport(fields));
  const compact = signP384(signer, parsed.signed);
  return serializeSevSnpReport({ ...fields, signature: { r: toLe72(compact.subarray(0, 48)), s: toLe72(compact.subarray(48, 96)) } });
}

// ── grant / pcactn / document plumbing (mirrors attestation.test.ts) ─────────────────────────────
const MEASURED_BINDING: AgentBinding = {
  min_measurement: toHex(MEASUREMENT),
  operator: toHex(CHIP_ID),
};

function grantWith(binding: AgentBinding): Capability {
  return mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'secure my account',
    envelope: { predicates: [{ verb: 'read', resource: '/acct/*' }], caveats: [], agent_binding: binding, risk_policy: DEFAULT_RISK_POLICY },
  }).grant;
}

function pcactn(grant: Capability, quoteDigest = NONCE): PCActn {
  return buildPCActn({ aud: 'test-aud',
    grant,
    chain: [grant],
    plan: [{ id: 'n1', verb: 'read', resource: '/acct/1', reversibility_class: 'reversible' }],
    nodeId: 'n1',
    counter: 1,
    signerSecret: A.secretKey,
    attestation: { quote_digest: quoteDigest, epoch: 1, model_id: 'gpt-x', measurement: toHex(MEASUREMENT), operator: toHex(CHIP_ID) },
  });
}

/** A hardware-mode document carrying only the nonce + validity window (fields are self-asserted). */
function hwDoc(nonce = NONCE): AttestationDocument {
  return {
    model_id: 'self-asserted-ignored',
    weights_digest: 'self-asserted-ignored',
    runtime_measurement: 'self-asserted-ignored',
    operator: 'self-asserted-ignored',
    nonce,
    issued_at: T - 1000,
    expires_at: T + 60_000,
    attestor: 'n/a',
    mode: 'hardware',
    sig: 'n/a',
  };
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
describe('parseSevSnpReport', () => {
  it('parses the documented field layout', () => {
    const bytes = buildSignedReport();
    const r = parseSevSnpReport(bytes);
    expect(r.version).toBe(2);
    expect(r.guest_svn).toBe(3);
    expect(r.vmpl).toBe(0);
    expect(r.signature_algo).toBe(1);
    expect(r.reported_tcb).toBe(0x0003_0000_0000_0007n);
    expect(toHex(r.measurement)).toBe(toHex(MEASUREMENT));
    expect(r.measurement.length).toBe(48);
    expect(r.report_data.length).toBe(64);
    expect(r.chip_id.length).toBe(64);
    expect(toHex(r.report_data)).toBe(toHex(BOUND));
    expect(r.signed.length).toBe(0x2a0);
    expect(r.signature.r.length).toBe(72);
    expect(r.signature.s.length).toBe(72);
  });

  it('rejects a buffer too short to hold the signature fields', () => {
    expect(() => parseSevSnpReport(new Uint8Array(100))).toThrow(/too short/);
  });
});

describe('SEV-SNP primitives', () => {
  it('verifies a P-384 report signature and rejects a tampered signed region', () => {
    const bytes = buildSignedReport();
    const report = parseSevSnpReport(bytes);
    expect(verifySevSnpReportSignature(report, VCEK.pub)).toBe(true);
    expect(verifySevSnpReportSignature(report, ASK.pub)).toBe(false);
    const tampered = bytes.slice();
    tampered[0x090] = (tampered[0x090]! ^ 0x01) & 0xff; // first measurement byte
    expect(verifySevSnpReportSignature(parseSevSnpReport(tampered), VCEK.pub)).toBe(false);
  });

  it('sevSnpSignatureToCompact rejects out-of-range scalars', () => {
    expect(() => sevSnpSignatureToCompact({ r: new Uint8Array(72), s: new Uint8Array(72) })).toThrow(/out of range/);
  });

  it('checkVcekReportBinding fails closed when the extensions are missing', () => {
    const report = parseSevSnpReport(buildSignedReport());
    expect(checkVcekReportBinding(vcekTbs(), report)).toBeNull();
    expect(checkVcekReportBinding(askTbs(), report)).toMatch(/no CHIP_ID/);
  });

  it('TCB downgrade: an old VCEK (lower SPLs) cannot vouch for a report claiming a newer TCB', () => {
    const report = parseSevSnpReport(buildSignedReport());
    expect(checkVcekReportBinding(vcekTbs({ bl: 2 }), report)).toMatch(/bootloader SPL 2.*downgrade/);
    expect(checkVcekReportBinding(vcekTbs({ snp: 1 }), report)).toMatch(/snp SPL/);
    expect(checkVcekReportBinding(vcekTbs({ tee: 9 }), report)).toMatch(/tee SPL/);
    expect(checkVcekReportBinding(vcekTbs({ ucode: 4 }), report)).toMatch(/microcode SPL/);
  });

  it('CHIP_ID: a VCEK for a different chip cannot vouch for this report', () => {
    const report = parseSevSnpReport(buildSignedReport());
    expect(checkVcekReportBinding(vcekTbs({ chip: new Uint8Array(64).fill(0x11) }), report)).toMatch(/CHIP_ID does not match/);
  });

  it('checkSevSnpPolicy gates measurement / chip / tcb / vmpl / svn', () => {
    const r = parseSevSnpReport(buildSignedReport());
    expect(checkSevSnpPolicy(r, { measurements: [toHex(MEASUREMENT)] })).toBeNull();
    expect(checkSevSnpPolicy(r, { measurements: ['00'] })).toMatch(/measurement not in policy/);
    expect(checkSevSnpPolicy(r, { chipIds: ['00'] })).toMatch(/chip_id/);
    expect(checkSevSnpPolicy(r, { minGuestSvn: 99 })).toMatch(/guest_svn/);
    expect(checkSevSnpPolicy(r, { minReportedTcb: 0xffff_ffff_ffff_ffffn })).toMatch(/reported_tcb/);
    expect(checkSevSnpPolicy(r, { requireVmpl: 1 })).toMatch(/vmpl/);
  });

  it('DEBUG policy bit is rejected unless explicitly opted in', () => {
    const r = parseSevSnpReport(buildSignedReport({ policy: SEV_SNP_POLICY_DEBUG_BIT }));
    expect(checkSevSnpPolicy(r, { measurements: [toHex(MEASUREMENT)] })).toMatch(/DEBUG/);
    expect(checkSevSnpPolicy(r, { measurements: [toHex(MEASUREMENT)], allowDebug: true })).toBeNull();
  });

  it('HOST_DATA can be gated as launch config', () => {
    const r = parseSevSnpReport(buildSignedReport());
    expect(checkSevSnpPolicy(r, { hostData: [toHex(HOST_DATA)] })).toBeNull();
    expect(checkSevSnpPolicy(r, { hostData: ['00'.repeat(32)] })).toMatch(/host_data/);
  });

  it('HOST_DATA is host-asserted: not mapped to weights by default', () => {
    const r = parseSevSnpReport(buildSignedReport());
    expect(makeDefaultDeriveIdentity(false)(r).weights_digest).toBe('');
    const insecure = makeDefaultDeriveIdentity(true)(r);
    expect(insecure.weights_digest).toBe(toHex(HOST_DATA));
    expect(insecure.weights_measured).toBe(false);
  });

  it('SEV-SNP has no native weights field: the default identity is never weights_measured', () => {
    const id = makeDefaultDeriveIdentity(false)(parseSevSnpReport(buildSignedReport()));
    expect(id.weights_digest).toBe('');
    expect(id.weights_measured).toBe(false);
    expect(id.runtime_measurement).toBe(toHex(MEASUREMENT));
    expect(id.operator).toBe(toHex(CHIP_ID));
  });

  it('minCommittedTcb / minLaunchTcb gate the AMD committed and launch TCB fields', () => {
    const r = parseSevSnpReport(buildSignedReport({ committed_tcb: 0x581b_0000_0000_000an, launch_tcb: 5n }));
    expect(checkSevSnpPolicy(r, { minCommittedTcb: 0x581b_0000_0000_000an })).toBeNull();
    expect(checkSevSnpPolicy(r, { minCommittedTcb: 0x59_00_00_00_00_00_00_00n })).toMatch(/committed_tcb/);
    expect(checkSevSnpPolicy(r, { minLaunchTcb: 5n })).toBeNull();
    expect(checkSevSnpPolicy(r, { minLaunchTcb: 6n })).toMatch(/launch_tcb/);
  });
});

// A HardwareAttestationVerifier TEST DOUBLE composed from the real primitives: it checks a locally-signed
// report (signature under the test VCEK, report_data binding, policy) and derives the measured identity
// with the production default mapping. It exists only to drive `createAttestationVerifier`'s
// require_measured_weights enforcement with the SEV-SNP identity mapping.
describe('measured weights through createAttestationVerifier (require_measured_weights)', () => {
  const policy = { measurements: [toHex(MEASUREMENT)] };
  // SEV-SNP cannot measure weights, so the "measured weights" identity here is a TEST-DOUBLE override of the
  // derived identity (standing in for a root that genuinely measures weights, e.g. a GPU RIM-backed root).
  function e2e(grant: Capability, o: { measuredWeights?: string; weightsFromHostData?: boolean } = {}) {
    const p = pcactn(grant);
    const base: ExpectedAttestationBinding = { ...EXPECTED, grantRef: p.grant_ref };
    const report = parseSevSnpReport(buildSignedReport({ report_data: attestationBinding(base) }));
    const hw: HardwareAttestationVerifier = {
      verify({ expected }) {
        if (!verifySevSnpReportSignature(report, VCEK.pub)) return { ok: false, reason: 'report signature does not verify' };
        if (toHex(report.report_data) !== toHex(attestationBinding(expected))) return { ok: false, reason: 'report_data does not bind' };
        const err = checkSevSnpPolicy(report, policy);
        if (err) return { ok: false, reason: err };
        const derived = makeDefaultDeriveIdentity(o.weightsFromHostData === true)(report);
        const measured = o.measuredWeights === undefined ? derived : { ...derived, weights_digest: o.measuredWeights, weights_measured: true };
        return { ok: true, bound: true, measured };
      },
    };
    const verify = createAttestationVerifier({
      trustedAttestorKeys: [],
      hardwareVerifier: hw,
      resolveDocument: () => hwDoc(),
      expectedBinding: () => base,
      now: () => T,
    });
    return verify({ pcactn: p, grant });
  }
  const weightsBinding = (over: Partial<AgentBinding> = {}): AgentBinding => ({ ...MEASURED_BINDING, ...over });

  it('a measured weights digest IN the allowlist passes under require_measured_weights (present+bound)', async () => {
    const grant = grantWith(weightsBinding({ weights_allowlist: [WEIGHTS_HEX], require_measured_weights: true }));
    expect(await e2e(grant, { measuredWeights: WEIGHTS_HEX })).toEqual({ enforced: true, ok: true, present: true, bound: true });
  });

  it('a measured weights digest NOT in the allowlist fails (model swap / fine-tune)', async () => {
    const grant = grantWith(weightsBinding({ weights_allowlist: ['00'.repeat(48)], require_measured_weights: true }));
    const res = await e2e(grant, { measuredWeights: WEIGHTS_HEX });
    expect(res).toMatchObject({ enforced: true, ok: false, bound: false });
    expect((res as { reason: string }).reason).toMatch(/weights_digest not in weights_allowlist/);
  });

  it('absent-when-required: identity not weights-measured + require_measured_weights => fail closed', async () => {
    const grant = grantWith(weightsBinding({ weights_allowlist: [WEIGHTS_HEX], require_measured_weights: true }));
    const res = await e2e(grant);
    expect(res).toMatchObject({ enforced: true, ok: false, bound: false });
    expect((res as { reason: string }).reason).toMatch(/not hardware-measured \(require_measured_weights/);
  });

  it('host-asserted weights cannot satisfy require_measured_weights even if the VALUE is allowlisted', async () => {
    const grant = grantWith(weightsBinding({ weights_allowlist: [toHex(HOST_DATA)], require_measured_weights: true }));
    const res = await e2e(grant, { weightsFromHostData: true });
    expect(res).toMatchObject({ enforced: true, ok: false, bound: false });
    expect((res as { reason: string }).reason).toMatch(/not hardware-measured \(require_measured_weights/);
  });

  it('weights_allowlist WITHOUT require_measured_weights matches the measured identity by value', async () => {
    const grant = grantWith(weightsBinding({ weights_allowlist: [WEIGHTS_HEX] }));
    expect(await e2e(grant, { measuredWeights: WEIGHTS_HEX })).toEqual({ enforced: true, ok: true, present: true, bound: true });
  });

  it('a binding with NO weights requirement is unchanged by measured weights being present', async () => {
    const grant = grantWith(MEASURED_BINDING);
    expect(await e2e(grant, { measuredWeights: WEIGHTS_HEX })).toEqual({ enforced: true, ok: true, present: true, bound: true });
    expect(await e2e(grant)).toEqual({ enforced: true, ok: true, present: true, bound: true });
  });

  it('the MEASURED identity (not the document) is matched against agent_binding', async () => {
    const res = await e2e(grantWith({ ...MEASURED_BINDING, operator: 'some-other-operator' }));
    expect(res).toMatchObject({ enforced: true, ok: false, bound: false });
    expect((res as { reason: string }).reason).toMatch(/operator/);
  });
});

// ══════════════════════════════════════════════════════════════════════════════════════════════
// VALIDATED-AGAINST-REAL-SILICON: a GENUINE AMD SEV-SNP report captured from an Azure confidential VM
// (AMD EPYC Milan). These are OFFLINE tests over committed fixtures (testdata/sevsnp-real/): no network,
// no hardware needed in CI. They prove our
// verifier accepts REAL silicon, extracts the VCEK key from the REAL vcek.der, and verifies the REAL
// VCEK→ASK→ARK RSA-PSS chain (trailerField tolerated via OpenSSL). See the module header's AZURE nuance:
// the Azure capture's report_data is the vTPM-AK digest, NOT a PCA binding, so the PCA report_data bind
// is NOT asserted here — the cryptographic root-of-trust + report-signature + VCEK↔report binding are.
// ══════════════════════════════════════════════════════════════════════════════════════════════
describe('GENUINE AMD SEV-SNP report (real silicon, offline fixtures)', () => {
  const REAL = resolve(__dirname, '..', 'testdata', 'sevsnp-real');
  const reportBin = () => new Uint8Array(readFileSync(resolve(REAL, 'snp_report.bin')));
  const vcekDer = () => new Uint8Array(readFileSync(resolve(REAL, 'vcek.der')));
  const chainPem = () => readFileSync(resolve(REAL, 'chain.pem'), 'utf8');

  it('the fixtures are the documented shape (1184-byte v3 report, 2-cert chain, EC-P384 VCEK)', async () => {
    const report = parseSevSnpReport(reportBin());
    expect(reportBin().length).toBe(1184);
    expect(report.version).toBe(3);
    expect(report.signature_algo).toBe(1); // ECDSA_P384_SHA384
    expect(splitPemCertificates(chainPem()).length).toBe(2); // ASK + ARK
    const { key } = await extractVcekPublicKey(vcekDer());
    expect(key.point.length).toBe(97); // uncompressed SEC1 P-384 point
    expect(key.point[0]).toBe(0x04);
  });

  it('extracts the VCEK EC-P384 point and verifies the GENUINE report signature under it', async () => {
    const { key } = await extractVcekPublicKey(vcekDer());
    const report = parseSevSnpReport(reportBin());
    // The core F-4 fix: the genuine report's ECDSA-P384 sig (AMD little-endian r‖s) verifies in OUR code.
    expect(verifySevSnpReportSignature(report, key)).toBe(true);
  });

  it('verifies the GENUINE VCEK→ASK→ARK chain (RSA-PSS trailerField via OpenSSL), ARK pinned', async () => {
    const res = await verifyAmdCertChain({ vcekDer: vcekDer(), askArkPem: chainPem(), nowMs: REAL_NOW_MS });
    expect(res.ok).toBe(true);
    expect(res.vcek?.point.length).toBe(97);
    expect(res.vcekTbs).toBeInstanceOf(Uint8Array);
    // the VCEK cert body binds to the report (CHIP_ID + reported-TCB SPLs)
    expect(checkVcekReportBinding(res.vcekTbs!, parseSevSnpReport(reportBin()))).toBeNull();
  });

  it('rejects the chain when the ARK pin is wrong (root of trust is NOT self-asserted)', async () => {
    const wrong = 'ab'.repeat(48);
    const res = await verifyAmdCertChain({ vcekDer: vcekDer(), askArkPem: chainPem(), nowMs: REAL_NOW_MS, trustAnchorArkSpkiSha384: wrong });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/ARK does not match the pinned AMD trust anchor/);
  });

  it('END-TO-END: ACCEPTS the genuine report (chain + report signature + VCEK↔report binding)', async () => {
    const res = await verifyGenuineSevSnpReport({ report: reportBin(), vcekDer: vcekDer(), askArkPem: chainPem(), nowMs: REAL_NOW_MS });
    expect(res.ok).toBe(true);
    expect(res.report?.version).toBe(3);
    // the measured identity is the hardware-authoritative launch measurement + chip operator
    expect(res.measured?.runtime_measurement).toBe(toHex(parseSevSnpReport(reportBin()).measurement));
    expect(res.measured?.operator).toBe(toHex(parseSevSnpReport(reportBin()).chip_id));
  });

  it('REJECTS a 1-bit-tampered genuine report (flip one byte in the signed region)', async () => {
    const bad = reportBin();
    bad[0x090] = (bad[0x090]! ^ 0x01) & 0xff; // flip one measurement bit — inside [0x000,0x2A0)
    const res = await verifyGenuineSevSnpReport({ report: bad, vcekDer: vcekDer(), askArkPem: chainPem(), nowMs: REAL_NOW_MS });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/report signature does not verify under VCEK/);
  });

  it('REJECTS the genuine report checked against a WRONG/other VCEK key', async () => {
    const report = parseSevSnpReport(reportBin());
    // an unrelated, valid P-384 key is not the VCEK that signed this report
    const other = ecdsaP384PublicKey(p384.getPublicKey(p384.utils.randomPrivateKey(), false));
    expect(verifySevSnpReportSignature(report, other)).toBe(false);
  });

  it('the pinned AMD Milan ARK matches the fixture chain root', async () => {
    // sanity: the default pin is exactly the root of the committed genuine chain
    const res = await verifyAmdCertChain({ vcekDer: vcekDer(), askArkPem: chainPem(), nowMs: REAL_NOW_MS, trustAnchorArkSpkiSha384: AMD_MILAN_ARK_SPKI_SHA384 });
    expect(res.ok).toBe(true);
  });

  it('extractTbsCertificate yields scannable AMD VCEK extensions (CHIP_ID bound to the report)', () => {
    const tbs = extractTbsCertificate(vcekDer());
    expect(tbs.length).toBeGreaterThan(0);
    // reuse the production binding check: genuine VCEK body ↔ genuine report must bind
    expect(checkVcekReportBinding(tbs, parseSevSnpReport(reportBin()))).toBeNull();
  });
});

describe('parseSevSnpReport: GENUINE Azure Genoa SEV-SNP report (v5) field values', () => {
  const FIX = resolve(__dirname, '..', 'fixtures', 'real-azure-maa');
  const real = () => new Uint8Array(readFileSync(resolve(FIX, 'sevsnp-hcl-report.bin'))).slice(32, 32 + 1184);
  const claims = () => {
    const payload = readFileSync(resolve(FIX, 'sevsnp-token.jwt'), 'utf8').trim().split('.')[1]!;
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<string, string | number | boolean>;
  };
  // AMD packs a TCB as bootloader(byte0) tee(1) reserved(2-5) snp(6) microcode(7).
  const tcbBytes = (t: bigint) => ({ bl: Number(t & 0xffn), tee: Number((t >> 8n) & 0xffn), snp: Number((t >> 48n) & 0xffn), ucode: Number((t >> 56n) & 0xffn) });

  it('parses version 5, Genoa CPUID, chip id and guest fields identical to the Azure MAA token claims', () => {
    const r = parseSevSnpReport(real());
    const c = claims();
    expect(r.version).toBe(5);
    expect([r.cpuid_fam_id, r.cpuid_mod_id, r.cpuid_step]).toEqual([0x19, 0x11, 1]); // family 19h model 11h = Genoa
    expect(c['x-ms-sevsnpvm-chip-family']).toBe('Genoa');
    expect(toHex(r.chip_id)).toBe(c['x-ms-sevsnpvm-chipid']);
    expect(r.guest_svn).toBe(c['x-ms-sevsnpvm-guestsvn']);
    expect(toHex(r.measurement)).toBe(c['x-ms-sevsnpvm-launchmeasurement']);
    expect(toHex(r.report_id)).toBe(c['x-ms-sevsnpvm-reportid']);
    expect(toHex(r.family_id)).toBe(c['x-ms-sevsnpvm-familyId']);
    expect(toHex(r.image_id)).toBe(c['x-ms-sevsnpvm-imageId']);
    expect(toHex(r.id_key_digest)).toBe(c['x-ms-sevsnpvm-idkeydigest']);
    expect(r.vmpl).toBe(0);
  });

  it('reported, committed and launch TCB equal the token SVN claims (bl=10 snp=27 ucode=88 tee=0)', () => {
    const r = parseSevSnpReport(real());
    const want = { bl: 10, tee: 0, snp: 27, ucode: 88 };
    expect(want).toEqual({ bl: claims()['x-ms-sevsnpvm-bootloader-svn'], tee: claims()['x-ms-sevsnpvm-tee-svn'], snp: claims()['x-ms-sevsnpvm-snpfw-svn'], ucode: claims()['x-ms-sevsnpvm-microcode-svn'] });
    expect(tcbBytes(r.reported_tcb)).toEqual(want);
    expect(tcbBytes(r.current_tcb)).toEqual(want);
    expect(tcbBytes(r.committed_tcb)).toEqual(want);
    expect(tcbBytes(r.launch_tcb)).toEqual(want);
    expect(r.current_version).toEqual({ major: 1, minor: 55, build: 49 });
    expect(r.committed_version).toEqual({ major: 1, minor: 55, build: 49 });
    expect(r.launch_mit_vector).toBe(7n);
    expect(r.current_mit_vector).toBe(7n);
  });

  it('the real report carries NO weights claim: derived identity is weights_measured:false with an empty digest', () => {
    const id = makeDefaultDeriveIdentity(false)(parseSevSnpReport(real()));
    expect(id.weights_measured).toBe(false);
    expect(id.weights_digest).toBe('');
    expect(id.runtime_measurement).toBe(claims()['x-ms-sevsnpvm-launchmeasurement']);
  });
});
