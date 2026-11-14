/**
 * NVIDIA collateral: SPDM version agreement, the RIM XML depth pre-scan (each construct's end), revocation coverage
 * indices, collateral-hook configuration, and the OCSP signature key rule (RSA exponent / key type) on a direct-issuer
 * response built here from scratch (SYNTHETIC keys, not NVIDIA's).
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash, generateKeyPairSync, sign as nodeSign, X509Certificate } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createNvidiaSpdmVerifier, parseNvidiaSpdmEvidence, parsePemChain, spkiSha256Hex } from './attest-nvidia-spdm';
import { checkNvidiaChainRevocation, nvidiaCollateralHook, verifyNvidiaRim } from './attest-nvidia-rim';
import { buildNvidiaOcspRequest, verifyNvidiaOcspResponse } from './attest-nvidia-ocsp';
import type { AttestationDocument, ExpectedAttestationBinding } from './attestation';
import { bitString, ctx, ctxPrim, forgeCert, forgeKey, generalizedTime, integer, nul, octets, oid, readDer, seq, tlv, type ForgeKey } from './test-support/forge-x509';

const FX = (...p: string[]) => resolve(__dirname, '..', 'fixtures', 'real-nvidia-cc', ...p);

// ---- SPDM: request and response versions must agree ------------------------------------------------------------------
describe('SPDM GET_MEASUREMENTS version agreement', () => {
  const REPORT = new Uint8Array(readFileSync(FX('h100-gpu-attestation-report.bin')));
  const CHAIN_PEM = readFileSync(FX('h100-device-cert-chain.pem'), 'utf8');
  const EXPECTED: ExpectedAttestationBinding = { holderPub: 'pca-realsilicon-nvidia-h100-holder', grantRef: 'grant_pca_nvidia_gpucc_realsilicon', epoch: 1, nonce: 'srv-nonce-nv-7c1e9f2a4b8d0536' };
  it('a response version that differs from the request version is refused before the signature check', async () => {
    const parsed = parseNvidiaSpdmEvidence(REPORT);
    const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
    const ev = new Uint8Array(REPORT);
    expect(ev[0]).toBe(0x11);
    ev[37] = 0x12; // first byte of the MEASUREMENTS response: its SPDM version
    const v = createNvidiaSpdmVerifier({
      rootSpkiSha256: [spkiSha256Hex(parsePemChain(CHAIN_PEM)[4]!)],
      policy: { measurements: { 2: hex(parsed.response.measurements[1]!.digest) }, leafSubjectIncludes: 'GH100' },
      resolveEvidence: () => ({ evidence: ev, certChainPem: CHAIN_PEM }),
    });
    const r = await v.verify({ document: {} as unknown as AttestationDocument, ctx: {} as never, nowMs: 1_791_498_000_000, expected: EXPECTED });
    expect(r).toEqual({ ok: false, reason: 'SPDM version 0x11/0x12 is not an accepted GET_MEASUREMENTS version' });
  });
});

// ---- RIM: XML depth pre-scan ------------------------------------------------------------------------------------------
describe('RIM XML depth pre-scan', () => {
  const DEEP = 'RIM: verification error (fail closed): XML nesting is too deep';
  const reason = async (xml: string) => {
    const r = await verifyNvidiaRim(xml, { rimRootSpkiSha256: ['00'.repeat(32)], nowMs: 0 });
    return r.ok ? 'ok' : r.reason;
  };
  const open = (n: number) => '<a>'.repeat(n);
  const nest = (n: number) => open(n) + '</a>'.repeat(n);

  it('boundary: 64 levels pass the pre-scan, 65 do not', async () => {
    expect(await reason(nest(64))).not.toBe(DEEP);
    expect(await reason(nest(65))).toBe(DEEP);
  });
  it('a comment before the first tag is skipped, also after leading whitespace', async () => {
    expect(await reason(` <!-- c -->${nest(64)}`)).not.toBe(DEEP);
    expect(await reason(`<!--c-->${open(65)}`)).toBe(DEEP); // the tag right after the comment end is counted
  });
  it('a comment, CDATA section or PI ends at its own terminator, searched after its opener', async () => {
    expect(await reason(`<!-->${'<b>'.repeat(70)}-->`)).not.toBe(DEEP);
    expect(await reason(`<?>${'<b>'.repeat(70)}?>`)).not.toBe(DEEP);
    expect(await reason('<r>]]><a><![CDATA[x]]></a></r>')).not.toBe(DEEP);
    expect(await reason('<r><!x></r>')).not.toBe(DEEP);
  });
  it('an unterminated start tag ends the scan without counting', async () => {
    expect(await reason(`<a x="${open(66)}`)).not.toBe(DEEP);
    expect(await reason(`${open(64)}<b`)).not.toBe(DEEP);
  });
  it("a '>' inside single quotes does not end a tag", async () => {
    expect(await reason("<a x='>'/>".repeat(65))).not.toBe(DEEP);
  });
  it('the scan resumes after the end of the construct', async () => {
    expect(await reason('<a<>')).not.toBe(DEEP);
  });
});

// ---- revocation coverage and hook configuration -----------------------------------------------------------------------
describe('checkNvidiaChainRevocation: explicit coverage indices', () => {
  it('index 0 (the leaf) is a valid index', () => {
    const synth = parsePemChain(readFileSync(FX('collateral', 'synthetic', 'chain.pem'), 'utf8'));
    const crl = new Uint8Array(readFileSync(FX('collateral', 'synthetic', 'ica-clean.der')));
    expect(checkNvidiaChainRevocation(synth, [crl], Date.parse('2027-01-01T00:00:00Z'), [], [0])).toEqual({ ok: true, verifiedCrls: 1 });
  });
});

describe('nvidiaCollateralHook configuration', () => {
  const base = { rimRootSpkiSha256: ['00'.repeat(32)], resolve: () => undefined };
  it('a non-string minimum version is named as given', () => {
    expect(() => nvidiaCollateralHook({ ...base, firmware: { minDriverVersion: Symbol('v') as unknown as string } })).toThrow(new TypeError("nvidiaCollateralHook: malformed minDriverVersion 'Symbol(v)'"));
  });
  it('every explicit requireCrlFor index must be a non-negative integer', () => {
    expect(() => nvidiaCollateralHook({ ...base, requireCrlFor: [0, -1] })).toThrow(new TypeError("nvidiaCollateralHook: malformed requireCrlFor '0,-1'"));
  });
});

// ---- OCSP: the RSA key rule on a direct-issuer response ----------------------------------------------------------------
describe('OCSP response signature: RSA key rule (SYNTHETIC issuer)', () => {
  const NOW = Date.UTC(2026, 0, 1);
  const FROM = new Date(Date.UTC(2020, 0, 1));
  const TO = new Date(Date.UTC(2040, 0, 1));
  const ec = forgeKey('ocsp-rsa-rule-signer', 'P-256');
  const leafKey = forgeKey('ocsp-rsa-rule-leaf', 'P-256');
  const ISSUER_DN = [['CN', 'Synthetic RSA OCSP Issuer']] as const;

  /** Bit-string payload of an SPKI (what the OCSP byKey responderID hashes). */
  const keyBits = (spki: Uint8Array): Uint8Array => {
    const bs = readDer(spki).children![1]!;
    return spki.subarray(bs.start + 1, bs.end);
  };
  async function response(issuerSpki: Uint8Array, signTbs: (tbs: Uint8Array) => Uint8Array) {
    const issuer = new X509Certificate(forgeCert({ subject: ISSUER_DN, issuer: ISSUER_DN, subjectKey: { ...ec, spki: issuerSpki } as ForgeKey, signer: ec, serial: 1n, notBefore: FROM, notAfter: TO }).der);
    const leaf = new X509Certificate(forgeCert({ subject: [['CN', 'Synthetic OCSP Leaf']], issuer: ISSUER_DN, subjectKey: leafKey, signer: ec, serial: 77n, notBefore: FROM, notAfter: TO }).der);
    const req = await buildNvidiaOcspRequest(leaf, issuer, { hash: 'sha256' });
    const tbsReq = readDer(req).children![0]!;
    const list = tbsReq.children!.find((c) => c.tag === 0x30)!;
    const certIdNode = list.children![0]!.children![0]!;
    const certId = tlv(0x30, req.subarray(certIdNode.start, certIdNode.end));
    const single = seq(certId, ctxPrim(0, new Uint8Array(0)), generalizedTime(new Date(NOW - 60_000)), ctx(0, generalizedTime(new Date(NOW + 86_400_000))));
    const responderId = ctx(2, octets(new Uint8Array(createHash('sha1').update(keyBits(issuerSpki)).digest())));
    const tbs = seq(responderId, generalizedTime(new Date(NOW - 60_000)), seq(single));
    const basic = seq(tbs, seq(oid('1.2.840.113549.1.1.11'), nul()), bitString(signTbs(tbs)));
    const der = seq(tlv(0x0a, Uint8Array.of(0)), ctx(0, seq(oid('1.3.6.1.5.5.7.48.1.1'), octets(basic))));
    return verifyNvidiaOcspResponse(der, { cert: leaf, issuer, chain: [leaf, issuer], nowMs: NOW });
  }
  const REFUSED = { ok: false, reason: 'OCSP response signature does not verify under the issuer key' };

  it('control: a sound RSA issuer key and a PKCS#1 signature verify', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const spki = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }));
    expect(await response(spki, (tbs) => new Uint8Array(nodeSign('sha256', tbs, privateKey)))).toMatchObject({ ok: true, status: 'good', responder: 'issuer' });
  });

  it('an RSA issuer key with e = 1 is refused even though the "signature" checks out arithmetically', async () => {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const n = Buffer.from(publicKey.export({ format: 'jwk' }).n!, 'base64url');
    const spki = seq(seq(oid('1.2.840.113549.1.1.1'), nul()), bitString(seq(integer(new Uint8Array(n)), integer(1))));
    // with e = 1 the RSA public operation is the identity, so the encoded message itself "verifies"
    const em = (tbs: Uint8Array) => {
      const t = Buffer.concat([Buffer.from('3031300d060960864801650304020105000420', 'hex'), createHash('sha256').update(tbs).digest()]);
      return new Uint8Array(Buffer.concat([Buffer.from([0, 1]), Buffer.alloc(n.length - 3 - t.length, 0xff), Buffer.from([0]), t]));
    };
    expect(await response(spki, em)).toEqual(REFUSED);
  });

  it('an RSA-PSS issuer key does not verify a PKCS#1 (rsa) signature algorithm', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('rsa-pss', { modulusLength: 2048 });
    const spki = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }));
    expect(await response(spki, (tbs) => new Uint8Array(nodeSign('sha256', tbs, privateKey)))).toEqual(REFUSED);
  });
});
