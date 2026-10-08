/**
 * HONEST VALIDATION of the AMD SEV-SNP hardware attestation VERIFIER (`hardware-sevsnp.ts`).
 *
 * There is NO AMD SEV-SNP hardware in CI to GENERATE a genuine ATTESTATION_REPORT, nor genuine
 * VCEK/ASK/ARK certificates. So these tests build a SYNTHETIC-but-cryptographically-real P-384 trust
 * chain: fresh ARK → ASK → VCEK P-384 keypairs, real ECDSA-P384/SHA-384 signatures binding each link,
 * and a report crafted with a known measurement + report_data and signed with the test VCEK. The
 * decisive test asserts the FULL path verifies end-to-end — report signature, VCEK→ASK→ARK chain to
 * the ARK trust anchor, report_data↔nonce binding, policy, and the hardware-measured identity flowing
 * through `createAttestationVerifier` into the agent_binding check. The negative tests exercise every
 * fail-closed branch.
 *
 * WHAT THIS DOES NOT PROVE: that AMD's real report byte-layout matches ours on a live CPU, or that a
 * genuine VCEK cert decodes to the point we check. Those are the remaining production integration — a
 * real report plus X.509 decode of the AMD certs (and/or AMD KDS fetch). What IS proven here is the
 * cryptographic machinery: parse → P-384 signature verify → chain verify → nonce bind → policy →
 * measured identity, all against real @noble/curves P-384 operations.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { p384 } from '@noble/curves/p384';
import { sha384, sha512 } from '@noble/hashes/sha512';
import {
  type EcdsaP384PublicKey,
  type SevSnpCertChain,
  type SevSnpEvidence,
  AMD_MILAN_ARK_SPKI_SHA384,
  checkSevSnpPolicy,
  checkVcekReportBinding,
  createSevSnpVerifier,
  ecdsaP384PublicKey,
  extractTbsCertificate,
  extractVcekPublicKey,
  parseSevSnpReport,
  serializeSevSnpReport,
  sevSnpSignatureToCompact,
  splitPemCertificates,
  toHex,
  verifyAmdCertChain,
  verifyGenuineSevSnpReport,
  verifySevSnpReportSignature,
  verifyVcekChain,
} from './hardware-sevsnp';
import {
  attestationBinding,
  createAttestationVerifier,
  type AttestationDocument,
  type ExpectedAttestationBinding,
} from './attestation';
import { mintGrant, type AgentBinding } from './envelope';
import { buildPCActn, type PCActn } from './pcactn';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY } from './risk';
import type { Capability } from './capability';

// ── synthetic P-384 key material ───────────────────────────────────────────────────────────────
interface TestKey {
  priv: Uint8Array;
  pub: EcdsaP384PublicKey;
}
function genP384(): TestKey {
  const priv = p384.utils.randomPrivateKey();
  return { priv, pub: ecdsaP384PublicKey(p384.getPublicKey(priv, false)) };
}
/** ECDSA-P384/SHA-384 sign, returning the big-endian compact r‖s the chain/report verify expects. */
function signP384(priv: Uint8Array, msg: Uint8Array): Uint8Array {
  return p384.sign(sha384(msg), priv, { lowS: false }).toCompactRawBytes();
}
/** Encode a big-endian 48-byte scalar back into AMD's 72-byte little-endian signature field. */
function toLe72(beCompactHalf: Uint8Array): Uint8Array {
  const le = new Uint8Array(72);
  for (let i = 0; i < beCompactHalf.length; i++) le[i] = beCompactHalf[beCompactHalf.length - 1 - i]!;
  return le;
}

const ARK = genP384();
const ASK = genP384();
const VCEK = genP384();

const MEASUREMENT = new Uint8Array(48).fill(0xab); // a known launch measurement
const CHIP_ID = new Uint8Array(64).fill(0x5c);
const HOST_DATA = new Uint8Array(32).fill(0x7d);
const WEIGHTS = new Uint8Array(48).fill(0x9e); // a known HARDWARE-MEASURED weights digest
const WEIGHTS_HEX = toHex(WEIGHTS);
const NONCE = 'nonce-epoch-1';
const T = 1_000_000;
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

// ── minimal DER fabrication (mirrors the AMD VCEK layout the verifier scans) ────────────────────
const cat = (...a: Uint8Array[]) => {
  const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let off = 0;
  for (const x of a) {
    o.set(x, off);
    off += x.length;
  }
  return o;
};
const OID_ARC = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x9c, 0x78, 0x01]; // 1.3.6.1.4.1.3704.1
const oidTlv = (tail: number[]) => Uint8Array.from([0x06, OID_ARC.length + tail.length, ...OID_ARC, ...tail]);
const spki = (k: EcdsaP384PublicKey) => cat(Uint8Array.from([0x03, 0x62, 0x00]), k.point);
const extInt = (tail: number[], v: number) => cat(oidTlv(tail), Uint8Array.from([0x04, 0x03, 0x02, 0x01, v]));
const extHwId = (chip: Uint8Array) => cat(oidTlv([0x04]), Uint8Array.from([0x04, 0x42, 0x04, 0x40]), chip);
const pre = (s: string) => new TextEncoder().encode(s);

interface VcekExt {
  chip?: Uint8Array;
  bl?: number;
  tee?: number;
  snp?: number;
  ucode?: number;
}
function askTbs(k: EcdsaP384PublicKey): Uint8Array {
  return cat(pre('ASK-tbs|'), spki(k), pre('|end'));
}
function vcekTbs(k: EcdsaP384PublicKey, e: VcekExt = {}): Uint8Array {
  // defaults match the default report: reported_tcb 0x0003_0000_0000_0007 => bl 7, tee 0, snp 3, ucode 0
  return cat(
    pre('VCEK-tbs|'),
    spki(k),
    extHwId(e.chip ?? CHIP_ID),
    extInt([0x03, 0x01], e.bl ?? 7),
    extInt([0x03, 0x02], e.tee ?? 0),
    extInt([0x03, 0x03], e.snp ?? 3),
    extInt([0x03, 0x08], e.ucode ?? 0),
  );
}

/** Build a VALID chain: ASK signed by ARK, VCEK signed by ASK; each TBS embeds its subject key. */
function buildChain(over: Partial<SevSnpCertChain> = {}, ext: VcekExt = {}): SevSnpCertChain {
  const ask_tbs = askTbs(ASK.pub);
  const vcek_tbs = vcekTbs(VCEK.pub, ext);
  return {
    ark: ARK.pub,
    ask: ASK.pub,
    vcek: VCEK.pub,
    ask_tbs,
    ask_sig: signP384(ARK.priv, ask_tbs),
    vcek_tbs,
    vcek_sig: signP384(ASK.priv, vcek_tbs),
    ...over,
  };
}

/** Craft a report with known fields and sign the signed region [0x000,0x2A0) with the test VCEK. */
function buildSignedReport(
  over: Partial<Parameters<typeof serializeSevSnpReport>[0]> = {},
  signer: Uint8Array = VCEK.priv,
): Uint8Array {
  const base = serializeSevSnpReport({
    version: 2,
    guest_svn: 3,
    vmpl: 0,
    reported_tcb: 0x0003_0000_0000_0007n,
    report_data: BOUND,
    measurement: MEASUREMENT,
    chip_id: CHIP_ID,
    host_data: HOST_DATA,
    ...over,
  });
  const parsed = parseSevSnpReport(base);
  const compact = signP384(signer, parsed.signed); // real ECDSA-P384 over SHA-384(signed)
  const r = compact.subarray(0, 48);
  const s = compact.subarray(48, 96);
  return serializeSevSnpReport({
    version: 2,
    guest_svn: 3,
    vmpl: 0,
    reported_tcb: 0x0003_0000_0000_0007n,
    report_data: BOUND,
    measurement: MEASUREMENT,
    chip_id: CHIP_ID,
    host_data: HOST_DATA,
    ...over,
    signature: { r: toLe72(r), s: toLe72(s) },
  });
}

function evidence(over: { report?: Uint8Array; chain?: SevSnpCertChain } = {}): SevSnpEvidence {
  return { report: over.report ?? buildSignedReport(), chain: over.chain ?? buildChain() };
}

// ── grant / pcactn / document plumbing (mirrors attestation.test.ts) ─────────────────────────────
const MEASURED_BINDING: AgentBinding = {
  // The measured identity the default deriveIdentity yields: runtime_measurement = hex(MEASUREMENT),
  // operator = hex(CHIP_ID). weights_digest is '' (HOST_DATA is host-asserted, not identity).
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
describe('parseSevSnpReport / serializeSevSnpReport', () => {
  it('round-trips the documented field layout', () => {
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
  it('verifies a real P-384 report signature and rejects a tampered signed region', () => {
    const bytes = buildSignedReport();
    const report = parseSevSnpReport(bytes);
    expect(verifySevSnpReportSignature(report, VCEK.pub)).toBe(true);
    // wrong key fails
    expect(verifySevSnpReportSignature(report, ASK.pub)).toBe(false);
    // flip a byte inside the signed region → signature no longer covers it
    const tampered = bytes.slice();
    tampered[0x090] = (tampered[0x090]! ^ 0x01) & 0xff; // first measurement byte
    expect(verifySevSnpReportSignature(parseSevSnpReport(tampered), VCEK.pub)).toBe(false);
  });

  it('sevSnpSignatureToCompact rejects out-of-range scalars', () => {
    expect(() => sevSnpSignatureToCompact({ r: new Uint8Array(72), s: new Uint8Array(72) })).toThrow(/out of range/);
  });

  it('verifyVcekChain accepts a valid chain and rejects every broken link', () => {
    expect(verifyVcekChain({ chain: buildChain(), trustAnchorArk: ARK.pub })).toEqual({ ok: true });
    // wrong trust anchor
    expect(verifyVcekChain({ chain: buildChain(), trustAnchorArk: genP384().pub })).toMatchObject({ ok: false });
    // VCEK not signed by ASK (sign it with ARK instead)
    const badVcek = buildChain({ vcek_sig: signP384(ARK.priv, buildChain().vcek_tbs) });
    expect(verifyVcekChain({ chain: badVcek, trustAnchorArk: ARK.pub }).reason).toMatch(/VCEK is not signed by ASK/);
    // ASK not signed by ARK
    const badAsk = buildChain({ ask_sig: signP384(ASK.priv, buildChain().ask_tbs) });
    expect(verifyVcekChain({ chain: badAsk, trustAnchorArk: ARK.pub }).reason).toMatch(/ASK is not signed by ARK/);
  });

  it('forged key/TBS pairing is rejected: genuine ARK-signed ASK TBS with an ATTACKER ASK key', () => {
    // The attacker holds a genuine (ARK-signed) ASK TBS embedding the real ASK key, but supplies their
    // own ASK key, uses it to sign a VCEK TBS they control, and claims that chain.
    const evil = genP384();
    const evilVcek = genP384();
    const vcek_tbs = vcekTbs(evilVcek.pub);
    const genuine = buildChain();
    const forged = buildChain({ ask: evil.pub, vcek: evilVcek.pub, vcek_tbs, vcek_sig: signP384(evil.priv, vcek_tbs), ask_tbs: genuine.ask_tbs, ask_sig: genuine.ask_sig });
    // every signature verifies — only the TBS<->key binding catches it
    const r = verifyVcekChain({ chain: forged, trustAnchorArk: ARK.pub });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/ASK key is not the subject key/);
    // same trick one level down: genuine VCEK TBS + attacker VCEK key
    const g2 = buildChain();
    const forged2 = buildChain({ vcek: evilVcek.pub, vcek_tbs: g2.vcek_tbs, vcek_sig: g2.vcek_sig });
    expect(verifyVcekChain({ chain: forged2, trustAnchorArk: ARK.pub }).reason).toMatch(/VCEK key is not the subject key/);
  });

  it('checkVcekReportBinding fails closed when the extensions are missing', () => {
    const report = parseSevSnpReport(buildSignedReport());
    expect(checkVcekReportBinding(vcekTbs(VCEK.pub), report)).toBeNull();
    expect(checkVcekReportBinding(askTbs(VCEK.pub), report)).toMatch(/no CHIP_ID/);
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
});

describe('createSevSnpVerifier — decisive end-to-end path', () => {
  const policy = { measurements: [toHex(MEASUREMENT)], chipIds: [toHex(CHIP_ID)], requireVmpl: 0, minGuestSvn: 1 };

  /** Wire a full hook for `grant`; the report is bound to the PCActn-derived expected binding. */
  function e2e(
    grant: Capability,
    o: { exp?: Partial<ExpectedAttestationBinding>; reportOver?: Parameters<typeof serializeSevSnpReport>[0]; reportBind?: Partial<ExpectedAttestationBinding>; chainExt?: VcekExt; policy?: typeof policy & Record<string, unknown>; now?: number; doc?: AttestationDocument } = {},
  ) {
    const p = pcactn(grant);
    const base: ExpectedAttestationBinding = { ...EXPECTED, grantRef: p.grant_ref };
    const report = buildSignedReport({ report_data: attestationBinding({ ...base, ...(o.reportBind ?? {}) }), ...(o.reportOver ?? {}) });
    const hw = createSevSnpVerifier({
      trustAnchorArk: ARK.pub,
      policy: o.policy ?? policy,
      resolveEvidence: () => evidence({ report, chain: buildChain({}, o.chainExt) }),
    });
    const verify = createAttestationVerifier({
      trustedAttestorKeys: [],
      hardwareVerifier: hw,
      resolveDocument: () => o.doc ?? hwDoc(),
      expectedBinding: () => ({ ...base, ...(o.exp ?? {}) }),
      now: () => o.now ?? T,
    });
    return verify({ pcactn: p, grant });
  }

  it('FULL PATH: a correctly-bound synthetic ARK→ASK→VCEK report verifies end-to-end (present+bound)', async () => {
    const res = await e2e(grantWith(MEASURED_BINDING));
    expect(res).toEqual({ enforced: true, ok: true, present: true, bound: true });
  });

  it('relay: a quote bound to another holder / grant / epoch / nonce is rejected', async () => {
    const grant = grantWith(MEASURED_BINDING);
    for (const wrong of [{ holderPub: encodeKey(generateKeyPair().publicKey) }, { grantRef: 'other-grant' }, { epoch: 2 }, { nonce: 'other-nonce' }]) {
      // the quote was produced for `wrong`, but the server expects the real binding
      const res = await e2e(grant, { reportBind: wrong });
      expect(res).toMatchObject({ enforced: true, ok: false, bound: false });
      expect((res as { reason: string }).reason).toMatch(/report_data does not bind/);
    }
  });

  it('document-date spoof: self-asserted dates are ignored; freshness comes from the server nonce age', async () => {
    const grant = grantWith(MEASURED_BINDING);
    // document claims to be valid for 100 years, but the server nonce was issued 10 minutes ago
    const spoof = { ...hwDoc(), issued_at: 0, expires_at: Number.MAX_SAFE_INTEGER };
    const stale = await e2e(grant, { doc: spoof, exp: { nonceIssuedAt: T - 10 * 60_000 } });
    expect(stale).toMatchObject({ ok: false });
    expect((stale as { reason: string }).reason).toMatch(/nonce expired/);
    // conversely an "expired" document with a fresh server nonce is accepted (dates not consulted)
    const expiredDoc = { ...hwDoc(), issued_at: 0, expires_at: 1 };
    expect(await e2e(grant, { doc: expiredDoc })).toMatchObject({ ok: true, bound: true });
    // unknown nonce issue time => cannot establish freshness => fail closed
    const unknown = await e2e(grant, { exp: { nonceIssuedAt: undefined } });
    expect(unknown).toMatchObject({ ok: false });
    expect((unknown as { reason: string }).reason).toMatch(/issue time unknown/);
  });

  it('DEBUG policy bit is rejected (unless explicitly opted in)', async () => {
    const grant = grantWith(MEASURED_BINDING);
    const res = await e2e(grant, { reportOver: { policy: 1n << 19n } });
    expect(res).toMatchObject({ ok: false });
    expect((res as { reason: string }).reason).toMatch(/DEBUG/);
    expect(await e2e(grant, { reportOver: { policy: 1n << 19n }, policy: { ...policy, allowDebug: true } })).toMatchObject({ ok: true });
  });

  it('TCB downgrade: an old VCEK (lower SPLs) cannot vouch for a report claiming a newer TCB', async () => {
    const res = await e2e(grantWith(MEASURED_BINDING), { chainExt: { bl: 2 } }); // VCEK says bl SPL 2; report says 7
    expect(res).toMatchObject({ ok: false });
    expect((res as { reason: string }).reason).toMatch(/bootloader SPL 2.*downgrade/);
    const snp = await e2e(grantWith(MEASURED_BINDING), { chainExt: { snp: 1 } });
    expect((snp as { reason: string }).reason).toMatch(/snp SPL/);
  });

  it('CHIP_ID: a VCEK for a different chip cannot vouch for this report', async () => {
    const res = await e2e(grantWith(MEASURED_BINDING), { chainExt: { chip: new Uint8Array(64).fill(0x11) } });
    expect(res).toMatchObject({ ok: false });
    expect((res as { reason: string }).reason).toMatch(/CHIP_ID does not match/);
  });

  it('HOST_DATA is host-asserted: not mapped to weights by default (weights_allowlist unsatisfiable)', async () => {
    const grant = grantWith({ ...MEASURED_BINDING, weights_allowlist: [toHex(HOST_DATA)] });
    const res = await e2e(grant);
    expect(res).toMatchObject({ ok: false });
    expect((res as { reason: string }).reason).toMatch(/weights_digest/);
    // explicit INSECURE opt-in maps it
    expect(await e2e(grant, { policy: { ...policy, weightsFromHostData: true } })).toMatchObject({ ok: true, bound: true });
    // and HOST_DATA can be gated as launch config
    const gated = await e2e(grantWith(MEASURED_BINDING), { policy: { ...policy, hostData: ['00'.repeat(32)] } });
    expect((gated as { reason: string }).reason).toMatch(/host_data/);
  });

  it('empty / missing measurement allowlist is rejected at construction', () => {
    expect(() => createSevSnpVerifier({ trustAnchorArk: ARK.pub, policy: {} })).toThrow(/NON-EMPTY/);
    expect(() => createSevSnpVerifier({ trustAnchorArk: ARK.pub, policy: { measurements: [] } })).toThrow(/NON-EMPTY/);
    expect(() => createSevSnpVerifier({ trustAnchorArk: ARK.pub, policy: { chipIds: [toHex(CHIP_ID)] } })).toThrow(/NON-EMPTY/);
  });

  it('the MEASURED identity (not the document) is matched against agent_binding', async () => {
    const res = await e2e(grantWith({ ...MEASURED_BINDING, operator: 'some-other-operator' }));
    expect(res).toMatchObject({ enforced: true, ok: false, bound: false });
    expect((res as { reason: string }).reason).toMatch(/operator/);
  });

  it('negative: a tampered report byte breaks the report signature', async () => {
    const bad = buildSignedReport();
    bad[0x090] = (bad[0x090]! ^ 0xff) & 0xff; // flip a measurement byte after signing
    const hw = createSevSnpVerifier({ trustAnchorArk: ARK.pub, policy, resolveEvidence: () => evidence({ report: bad }) });
    const r = await hw.verify({ document: hwDoc(), ctx: {} as never, nowMs: T, expected: EXPECTED });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/report signature does not verify/);
  });

  it('negative: a VCEK not endorsed by the chain fails chain verification', async () => {
    const rogue = genP384();
    const report = buildSignedReport({}, rogue.priv); // signed by a rogue key
    const chain = buildChain({ vcek: rogue.pub, vcek_tbs: vcekTbs(rogue.pub), vcek_sig: new Uint8Array(96) }); // chain cannot endorse it
    const hw = createSevSnpVerifier({ trustAnchorArk: ARK.pub, policy, resolveEvidence: () => evidence({ report, chain }) });
    const r = await hw.verify({ document: hwDoc(), ctx: {} as never, nowMs: T, expected: EXPECTED });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/cert chain invalid.*VCEK is not signed by ASK/);
  });

  it('negative: wrong ARK trust anchor fails', async () => {
    const hw = createSevSnpVerifier({ trustAnchorArk: genP384().pub, policy, resolveEvidence: () => evidence() });
    const r = await hw.verify({ document: hwDoc(), ctx: {} as never, nowMs: T, expected: EXPECTED });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/ARK does not match the configured trust anchor/);
  });

  it('negative: report_data nonce mismatch fails', async () => {
    // report_data binds NONCE, but the server expects a different nonce.
    const hw = createSevSnpVerifier({ trustAnchorArk: ARK.pub, policy, resolveEvidence: () => evidence() });
    const r = await hw.verify({ document: hwDoc(), ctx: {} as never, nowMs: T, expected: { ...EXPECTED, nonce: 'a-different-nonce' } });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/report_data does not bind/);
  });

  it('negative: measurement not in policy fails', async () => {
    const hw = createSevSnpVerifier({ trustAnchorArk: ARK.pub, policy: { measurements: ['00'.repeat(48)] }, resolveEvidence: () => evidence() });
    const r = await hw.verify({ document: hwDoc(), ctx: {} as never, nowMs: T, expected: EXPECTED });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/measurement not in policy/);
  });

  it('negative: no evidence resolver fails closed', async () => {
    const hw = createSevSnpVerifier({ trustAnchorArk: ARK.pub, policy });
    const r = await hw.verify({ document: hwDoc(), ctx: {} as never, nowMs: T, expected: EXPECTED });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no SEV-SNP evidence resolver/);
  });

  it('direct verify of a bound genuine report returns bound + measured identity + host-asserted data', async () => {
    const hw = createSevSnpVerifier({ trustAnchorArk: ARK.pub, policy, resolveEvidence: () => evidence() });
    const r = await hw.verify({ document: hwDoc(), ctx: {} as never, nowMs: T, expected: EXPECTED });
    expect(r.ok).toBe(true);
    expect(r.bound).toBe(true);
    expect(r.measured?.runtime_measurement).toBe(toHex(MEASUREMENT));
    expect(r.measured?.weights_digest).toBe('');
    expect(r.measured?.weights_measured).toBe(false); // nothing measured the weights
    expect(r.hostAsserted?.host_data).toBe(toHex(HOST_DATA));
  });

  // ── WEIGHTS-LEVEL ATTESTATION: the measured-weights slot is hardware-rooted (signed region) ──────
  describe('hardware-measured weights (require_measured_weights, fail-closed on self/host-asserted)', () => {
    const weightsBinding = (over: Partial<AgentBinding> = {}): AgentBinding => ({ ...MEASURED_BINDING, ...over });

    it('a measured weights digest IN the allowlist passes under require_measured_weights (present+bound)', async () => {
      const grant = grantWith(weightsBinding({ weights_allowlist: [WEIGHTS_HEX], require_measured_weights: true }));
      const res = await e2e(grant, { reportOver: { weights_measurement: WEIGHTS } });
      expect(res).toEqual({ enforced: true, ok: true, present: true, bound: true });
    });

    it('a measured weights digest NOT in the allowlist fails (model swap / fine-tune)', async () => {
      const grant = grantWith(weightsBinding({ weights_allowlist: ['00'.repeat(48)], require_measured_weights: true }));
      const res = await e2e(grant, { reportOver: { weights_measurement: WEIGHTS } });
      expect(res).toMatchObject({ enforced: true, ok: false, bound: false });
      expect((res as { reason: string }).reason).toMatch(/weights_digest not in weights_allowlist/);
    });

    it('absent-when-required: no measured-weights slot + require_measured_weights => fail closed', async () => {
      // the report carries the default all-zero slot (nothing measured the weights)
      const grant = grantWith(weightsBinding({ weights_allowlist: [WEIGHTS_HEX], require_measured_weights: true }));
      const res = await e2e(grant); // default report: weights_measurement is all zero
      expect(res).toMatchObject({ enforced: true, ok: false, bound: false });
      expect((res as { reason: string }).reason).toMatch(/not hardware-measured \(require_measured_weights/);
    });

    it('host-asserted weights (weightsFromHostData) cannot satisfy require_measured_weights even if the VALUE is allowlisted', async () => {
      // HOST_DATA is host-asserted; map it to weights_digest and ALLOWLIST that exact value...
      const grant = grantWith(weightsBinding({ weights_allowlist: [toHex(HOST_DATA)], require_measured_weights: true }));
      const res = await e2e(grant, { policy: { ...policy, weightsFromHostData: true } });
      // ...it still FAILS CLOSED: a host-asserted digest is not silicon-measured (weights_measured=false)
      expect(res).toMatchObject({ enforced: true, ok: false, bound: false });
      expect((res as { reason: string }).reason).toMatch(/not hardware-measured \(require_measured_weights/);
    });

    it('BACKWARD-COMPAT: weights_allowlist WITHOUT require_measured_weights matches the measured slot by value', async () => {
      const grant = grantWith(weightsBinding({ weights_allowlist: [WEIGHTS_HEX] }));
      const res = await e2e(grant, { reportOver: { weights_measurement: WEIGHTS } });
      expect(res).toEqual({ enforced: true, ok: true, present: true, bound: true });
    });

    it('BACKWARD-COMPAT: a binding with NO weights requirement is unchanged by a measured slot being present', async () => {
      // MEASURED_BINDING pins only measurement + operator; a populated weights slot must not change the verdict
      const grant = grantWith(MEASURED_BINDING);
      expect(await e2e(grant, { reportOver: { weights_measurement: WEIGHTS } })).toEqual({ enforced: true, ok: true, present: true, bound: true });
      expect(await e2e(grant)).toEqual({ enforced: true, ok: true, present: true, bound: true });
    });

    it('verifier-side weightsMeasurements allowlist gates the measured slot (and rejects an absent slot)', async () => {
      const grant = grantWith(MEASURED_BINDING);
      // report carries WEIGHTS; verifier policy allows it
      expect(await e2e(grant, { reportOver: { weights_measurement: WEIGHTS }, policy: { ...policy, weightsMeasurements: [WEIGHTS_HEX] } })).toMatchObject({ ok: true, bound: true });
      // report carries a DIFFERENT measured digest => rejected at the verifier
      const other = new Uint8Array(48).fill(0x22);
      const wrong = await e2e(grant, { reportOver: { weights_measurement: other }, policy: { ...policy, weightsMeasurements: [WEIGHTS_HEX] } });
      expect((wrong as { reason: string }).reason).toMatch(/measured weights digest not in policy allowlist/);
      // no measured slot at all => rejected when the verifier requires one
      const absent = await e2e(grant, { policy: { ...policy, weightsMeasurements: [WEIGHTS_HEX] } });
      expect((absent as { reason: string }).reason).toMatch(/no measured weights digest in report/);
    });

    it('the measured-weights slot is HARDWARE-ROOTED: flipping it after signing breaks the report signature', async () => {
      const bytes = buildSignedReport({ weights_measurement: WEIGHTS });
      // sanity: it verifies before tampering
      expect(verifySevSnpReportSignature(parseSevSnpReport(bytes), VCEK.pub)).toBe(true);
      const tampered = bytes.slice();
      tampered[0x1e0] = (tampered[0x1e0]! ^ 0xff) & 0xff; // flip the first measured-weights byte
      expect(verifySevSnpReportSignature(parseSevSnpReport(tampered), VCEK.pub)).toBe(false);
    });

    it('direct verify EXPOSES the hardware-measured weights digest with weights_measured:true', async () => {
      const hw = createSevSnpVerifier({ trustAnchorArk: ARK.pub, policy, resolveEvidence: () => evidence({ report: buildSignedReport({ weights_measurement: WEIGHTS }) }) });
      const r = await hw.verify({ document: hwDoc(), ctx: {} as never, nowMs: T, expected: EXPECTED });
      expect(r.ok).toBe(true);
      expect(r.measured?.weights_digest).toBe(WEIGHTS_HEX);
      expect(r.measured?.weights_measured).toBe(true);
    });
  });
});

// ══════════════════════════════════════════════════════════════════════════════════════════════
// VALIDATED-AGAINST-REAL-SILICON: a GENUINE AMD SEV-SNP report captured from an Azure confidential VM
// (AMD EPYC Milan). These are OFFLINE tests over committed fixtures (testdata/sevsnp-real/): no network,
// no hardware needed in CI. They upgrade the suite above (synthetic-but-real-crypto) to prove our
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
    const res = await verifyAmdCertChain({ vcekDer: vcekDer(), askArkPem: chainPem() });
    expect(res.ok).toBe(true);
    expect(res.vcek?.point.length).toBe(97);
    expect(res.vcekTbs).toBeInstanceOf(Uint8Array);
    // the VCEK cert body binds to the report (CHIP_ID + reported-TCB SPLs)
    expect(checkVcekReportBinding(res.vcekTbs!, parseSevSnpReport(reportBin()))).toBeNull();
  });

  it('rejects the chain when the ARK pin is wrong (root of trust is NOT self-asserted)', async () => {
    const wrong = 'ab'.repeat(48);
    const res = await verifyAmdCertChain({ vcekDer: vcekDer(), askArkPem: chainPem(), trustAnchorArkSpkiSha384: wrong });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/ARK does not match the pinned AMD trust anchor/);
  });

  it('END-TO-END: ACCEPTS the genuine report (chain + report signature + VCEK↔report binding)', async () => {
    const res = await verifyGenuineSevSnpReport({ report: reportBin(), vcekDer: vcekDer(), askArkPem: chainPem() });
    expect(res.ok).toBe(true);
    expect(res.report?.version).toBe(3);
    // the measured identity is the hardware-authoritative launch measurement + chip operator
    expect(res.measured?.runtime_measurement).toBe(toHex(parseSevSnpReport(reportBin()).measurement));
    expect(res.measured?.operator).toBe(toHex(parseSevSnpReport(reportBin()).chip_id));
  });

  it('REJECTS a 1-bit-tampered genuine report (flip one byte in the signed region)', async () => {
    const bad = reportBin();
    bad[0x090] = (bad[0x090]! ^ 0x01) & 0xff; // flip one measurement bit — inside [0x000,0x2A0)
    const res = await verifyGenuineSevSnpReport({ report: bad, vcekDer: vcekDer(), askArkPem: chainPem() });
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
    const res = await verifyAmdCertChain({ vcekDer: vcekDer(), askArkPem: chainPem(), trustAnchorArkSpkiSha384: AMD_MILAN_ARK_SPKI_SHA384 });
    expect(res.ok).toBe(true);
  });

  it('extractTbsCertificate yields scannable AMD VCEK extensions (CHIP_ID bound to the report)', () => {
    const tbs = extractTbsCertificate(vcekDer());
    expect(tbs.length).toBeGreaterThan(0);
    // reuse the production binding check: genuine VCEK body ↔ genuine report must bind
    expect(checkVcekReportBinding(tbs, parseSevSnpReport(reportBin()))).toBeNull();
  });
});

describe('parseSevSnpReport: measured-weights slot', () => {
  it('round-trips the 48-byte weights_measurement slot inside the signed region', () => {
    const r = parseSevSnpReport(buildSignedReport({ weights_measurement: WEIGHTS }));
    expect(r.weights_measurement.length).toBe(48);
    expect(toHex(r.weights_measurement)).toBe(WEIGHTS_HEX);
    // the slot sits within [0x000, 0x2A0): it is covered by the report signature
    expect(r.signed.length).toBe(0x2a0);
    // default (unset) slot is all-zero => ABSENT
    expect(toHex(parseSevSnpReport(buildSignedReport()).weights_measurement)).toBe('00'.repeat(48));
  });
});
