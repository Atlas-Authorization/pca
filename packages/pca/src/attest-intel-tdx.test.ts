/**
 * HONEST VALIDATION of the Intel TDX/DCAP attestation VERIFIER (`attest-intel-tdx.ts`).
 *
 * No Intel TDX hardware in CI, so these build a SYNTHETIC-but-cryptographically-real P-256 trust chain
 * (fresh Root CA → PCK leaf → AK keypairs, real ECDSA-P256/SHA-256 signatures, a TD report crafted with a
 * known MRTD + report_data and signed by a test AK, plus a QE report binding the AK). The decisive test
 * asserts the full DCAP path verifies end-to-end; the negatives exercise every fail-closed branch. This is
 * a CLASSICAL ECDSA-P256 root (see the module header's honest-scope note) — not post-quantum.
 */
import { describe, expect, it } from 'vitest';
import { p256 } from '@noble/curves/p256';
import { sha256 } from './hash';
import {
  type IntelPckChain,
  type IntelTdxQuote,
  type EcdsaP256PublicKey,
  INTEL_TDX_SUITE,
  checkIntelTdxPolicy,
  createIntelTdxVerifier,
  ecdsaP256PublicKey,
  encodeTdxTbs,
  parseTdReport,
  serializeTdReport,
  toHex,
} from './attest-intel-tdx';
import { attestationBinding, type ExpectedAttestationBinding } from './attestation';
import { encodeKey, generateKeyPair } from './keys';

interface P256Key {
  priv: Uint8Array;
  pub: EcdsaP256PublicKey;
}
function genP256(): P256Key {
  const priv = p256.utils.randomPrivateKey();
  return { priv, pub: ecdsaP256PublicKey(p256.getPublicKey(priv, false)) };
}
function signP256(priv: Uint8Array, msg: Uint8Array): Uint8Array {
  return p256.sign(sha256(msg), priv, { lowS: false }).toCompactRawBytes();
}
function cat(...a: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of a) {
    out.set(x, o);
    o += x.length;
  }
  return out;
}
function u16be(n: number): Uint8Array {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, false);
  return b;
}

const ROOT = genP256();
const PCK = genP256();
const AK = genP256();
const MRTD = new Uint8Array(48).fill(0xab);
const FMSPC = new Uint8Array(6).fill(0x5c);
const WEIGHTS = new Uint8Array(48).fill(0x9e);
const QE_AUTH = new Uint8Array([0x11, 0x22, 0x33]);
const HEADER = new Uint8Array([0x04, 0x00, 0x81, 0x00]); // a quote header
const T = 1_000_000;
const A = generateKeyPair();
const EXPECTED: ExpectedAttestationBinding = {
  holderPub: encodeKey(A.publicKey),
  grantRef: 'grant-tdx-1',
  epoch: 1,
  nonce: 'nonce-tdx-1',
  nonceIssuedAt: T - 1000,
};
const BOUND = attestationBinding(EXPECTED);

interface LeafOpts {
  subject?: EcdsaP256PublicKey;
  fmspc?: Uint8Array;
  tcbSvn?: number;
  issuerPriv?: Uint8Array;
}
function buildLeaf(o: LeafOpts = {}): IntelPckChain['leaf'] {
  const subject = o.subject ?? PCK.pub;
  const tbs = encodeTdxTbs([
    { tag: 0x01, value: subject.point },
    { tag: 0x02, value: o.fmspc ?? FMSPC },
    { tag: 0x03, value: u16be(o.tcbSvn ?? 5) },
  ]);
  return { subject, tbs, sig: signP256(o.issuerPriv ?? ROOT.priv, tbs) };
}
function buildChain(over: Partial<IntelPckChain> = {}, leafOpts: LeafOpts = {}): IntelPckChain {
  return { rootCa: ROOT.pub, intermediates: [], leaf: buildLeaf(leafOpts), ...over };
}
function buildQeReport(ak: EcdsaP256PublicKey = AK.pub, auth: Uint8Array = QE_AUTH): Uint8Array {
  const body = new Uint8Array(384);
  const rd = cat(sha256(cat(ak.point, auth)), new Uint8Array(32));
  body.set(rd, 0x140);
  return body;
}
interface QuoteOpts {
  reportOver?: Parameters<typeof serializeTdReport>[0];
  reportBind?: Partial<ExpectedAttestationBinding>;
  chain?: IntelPckChain;
  leafOpts?: LeafOpts;
  ak?: P256Key;
  qeSigner?: Uint8Array;
  tamperQuoteSig?: boolean;
}
function buildQuote(o: QuoteOpts = {}): IntelTdxQuote {
  const ak = o.ak ?? AK;
  const reportBody = serializeTdReport({
    report_data: o.reportBind ? attestationBinding({ ...EXPECTED, ...o.reportBind }) : BOUND,
    mrtd: MRTD,
    tee_tcb_svn: 3,
    ...(o.reportOver ?? {}),
  });
  const qeReportBody = buildQeReport(ak.pub, QE_AUTH);
  const chain = o.chain ?? buildChain({}, o.leafOpts ?? {});
  let quoteSignature = signP256(ak.priv, cat(HEADER, reportBody));
  if (o.tamperQuoteSig) {
    const s = quoteSignature.slice();
    s[0] = (s[0]! ^ 0xff) & 0xff;
    quoteSignature = s;
  }
  return {
    header: HEADER,
    reportBody,
    quoteSignature,
    akPub: ak.pub,
    qeAuthData: QE_AUTH,
    qeReportBody,
    qeReportSignature: signP256((o.qeSigner ?? PCK.priv), qeReportBody),
    pckChain: chain,
  };
}

const POLICY = { mrtds: [toHex(MRTD)], fmspcs: [toHex(FMSPC)], minTeeTcbSvn: 1 };
function verifier(over: Partial<Parameters<typeof createIntelTdxVerifier>[0]> = {}, quote: IntelTdxQuote = buildQuote()) {
  return createIntelTdxVerifier({ trustAnchorRootCa: ROOT.pub, policy: POLICY, resolveEvidence: () => quote, ...over });
}
function run(v: ReturnType<typeof createIntelTdxVerifier>) {
  return v.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected: EXPECTED });
}

describe('attest-intel-tdx: suite label', () => {
  it('declares the classical ECDSA-P256 suite', () => {
    expect(INTEL_TDX_SUITE).toBe('ecdsa-p256-sha256');
  });
});

describe('attest-intel-tdx: report parse/serialize', () => {
  it('round-trips the TD report body layout', () => {
    const r = parseTdReport(serializeTdReport({ report_data: BOUND, mrtd: MRTD, weights_measurement: WEIGHTS, tee_tcb_svn: 7 }));
    expect(toHex(r.report_data)).toBe(toHex(BOUND));
    expect(toHex(r.mrtd)).toBe(toHex(MRTD));
    expect(toHex(r.weights_measurement)).toBe(toHex(WEIGHTS));
    expect(r.tee_tcb_svn).toBe(7);
  });
  it('rejects a short body', () => {
    expect(() => parseTdReport(new Uint8Array(10))).toThrow(/too short/);
  });
});

describe('attest-intel-tdx: decisive end-to-end path', () => {
  it('ACCEPTS a correctly-bound synthetic Root→PCK→AK quote (bound + measured)', async () => {
    const r = await run(verifier());
    expect(r.ok).toBe(true);
    expect(r.bound).toBe(true);
    expect(r.measured?.runtime_measurement).toBe(toHex(MRTD));
    expect(r.hostAsserted?.fmspc).toBe(toHex(FMSPC));
  });

  it('exposes a hardware-measured weights digest with weights_measured:true', async () => {
    const r = await run(verifier({}, buildQuote({ reportOver: { report_data: BOUND, mrtd: MRTD, tee_tcb_svn: 3, weights_measurement: WEIGHTS } })));
    expect(r.ok).toBe(true);
    expect(r.measured?.weights_digest).toBe(toHex(WEIGHTS));
    expect(r.measured?.weights_measured).toBe(true);
  });
});

describe('attest-intel-tdx: fail-closed branches', () => {
  it('construction rejects an empty MRTD allowlist', () => {
    expect(() => createIntelTdxVerifier({ trustAnchorRootCa: ROOT.pub, policy: { mrtds: [] } })).toThrow(/NON-EMPTY/);
  });

  it('tampered quote signature denied', async () => {
    const r = await run(verifier({}, buildQuote({ tamperQuoteSig: true })));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/TD quote signature does not verify/);
  });

  it('wrong Root CA anchor denied', async () => {
    const r = await run(verifier({ trustAnchorRootCa: genP256().pub }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/Root CA does not match/);
  });

  it('PCK not signed by root denied (broken chain)', async () => {
    const badLeaf = buildLeaf({ issuerPriv: AK.priv }); // signed by the wrong issuer
    const r = await run(verifier({}, buildQuote({ chain: buildChain({ leaf: badLeaf }) })));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/not signed by its issuer/);
  });

  it('forged key/TBS pairing denied: a genuine root-signed TBS re-used with an attacker key', async () => {
    const evil = genP256();
    // attacker keeps a genuine leaf TBS+sig but swaps in their own subject key
    const genuine = buildLeaf();
    const forged = { subject: evil.pub, tbs: genuine.tbs, sig: genuine.sig };
    const r = await run(verifier({}, buildQuote({ chain: buildChain({ leaf: forged }) })));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/subject key is not bound in its TBS/);
  });

  it('absent evidence (no resolver) denied', async () => {
    const v = createIntelTdxVerifier({ trustAnchorRootCa: ROOT.pub, policy: POLICY });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no Intel TDX evidence resolver/);
  });

  it('mismatched MRTD denied', async () => {
    const v = verifier({ policy: { mrtds: ['00'.repeat(48)], fmspcs: [toHex(FMSPC)] } });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/MRTD not in policy allowlist/);
  });

  it('STALE TCB: an old PCK (lower TCB SVN) cannot vouch for a newer TD', async () => {
    // PCK issued at TCB SVN 2, but the TD report claims TEE_TCB_SVN 9
    const r = await run(verifier({}, buildQuote({ leafOpts: { tcbSvn: 2 }, reportOver: { report_data: BOUND, mrtd: MRTD, tee_tcb_svn: 9 } })));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/exceeds the PCK leaf TCB SVN.*old PCK cannot vouch a newer TD/);
  });

  it('FMSPC not in policy denied', async () => {
    const r = await run(verifier({ policy: { mrtds: [toHex(MRTD)], fmspcs: ['aabbccddeeff'] } }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/FMSPC not in policy allowlist/);
  });

  it('QE does not endorse the AK: a correctly-PCK-signed QE report binding a DIFFERENT key denied', async () => {
    // Quote is signed by the genuine AK (akPub = AK.pub), but the (correctly PCK-signed) QE report binds a
    // rogue key — so the QE did not vouch for this AK. QE-sig verification passes; the AK binding fails.
    const rogue = genP256();
    const base = buildQuote();
    const qeBody = buildQeReport(rogue.pub, QE_AUTH);
    const mixed: IntelTdxQuote = { ...base, qeReportBody: qeBody, qeReportSignature: signP256(PCK.priv, qeBody) };
    const r = await run(verifier({}, mixed));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/QE report_data does not bind the attestation key/);
  });

  it('QE report not signed by the PCK leaf denied', async () => {
    const r = await run(verifier({}, buildQuote({ qeSigner: genP256().priv })));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/QE report signature does not verify/);
  });

  it('RELAY: report_data bound to another holder/grant/epoch/nonce denied', async () => {
    for (const wrong of [{ holderPub: encodeKey(generateKeyPair().publicKey) }, { grantRef: 'other' }, { epoch: 2 }, { nonce: 'other' }]) {
      const r = await run(verifier({}, buildQuote({ reportBind: wrong })));
      expect(r.ok).toBe(false);
      expect(r.reason).toMatch(/report_data does not bind/);
    }
  });

  it('checkIntelTdxPolicy gates measurement / rtmr / weights / tcb floor', () => {
    const report = parseTdReport(serializeTdReport({ mrtd: MRTD, tee_tcb_svn: 3, weights_measurement: WEIGHTS }));
    expect(checkIntelTdxPolicy(report, { mrtds: [toHex(MRTD)] })).toBeNull();
    expect(checkIntelTdxPolicy(report, { mrtds: ['00'] })).toMatch(/MRTD/);
    expect(checkIntelTdxPolicy(report, { mrtds: [toHex(MRTD)], minTeeTcbSvn: 99 })).toMatch(/TEE_TCB_SVN/);
    expect(checkIntelTdxPolicy(report, { mrtds: [toHex(MRTD)], weightsMeasurements: ['00'.repeat(48)] })).toMatch(/weights/);
  });
});
