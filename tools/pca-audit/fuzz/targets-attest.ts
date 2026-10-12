/**
 * Fuzz targets for the attestation evidence parsers / verifiers (SPDM, DCAP/TDX, SEV-SNP, MAA, GCP, NVIDIA RIM / OCSP /
 * CRL, allowlist manifests). Seeds are the REAL captured fixtures shipped with the package, so mutation starts from
 * bytes that actually parse and verify.
 */
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { verifyAllowlistManifest, signAllowlistManifest, type AllowlistIssuerKey } from '../../../packages/pca/src/attest-allowlist';
import { createAmdSnpVerifier, pemToDer, type AmdSnpEvidence } from '../../../packages/pca/src/attest-amd-snp';
import { parseSevSnpReport } from '../../../packages/pca/src/hardware-sevsnp';
import { parseGcpCsJwt } from '../../../packages/pca/src/attest-gcp-confidential-space';
import { decodeIssuerChainHeader, verifyCrl } from '../../../packages/pca/src/attest-intel-collateral';
import { parseDcapQuote, parseDcapTdReport } from '../../../packages/pca/src/attest-intel-tdx';
import { parseMaaJwt } from '../../../packages/pca/src/attest-azure-maa';
import { createNvidiaSpdmVerifier, parseNvidiaSpdmEvidence, parsePemChain, verifyNvidiaDeviceChain } from '../../../packages/pca/src/attest-nvidia-spdm';
import { nvidiaCollateralHook, verifyNvidiaRim, nvidiaRimIdsForReport, checkNvidiaChainRevocation } from '../../../packages/pca/src/attest-nvidia-rim';
import { verifyNvidiaOcspResponse } from '../../../packages/pca/src/attest-nvidia-ocsp';
import { generateKeyPair } from '../../../packages/pca/src/keys';
import { b64u } from '../../../packages/pca/src/hash';
import { mutateBytes, mutateJson, mutateText, projectOnto, firstDiff, typedBy, neverThrows } from './lib';
import type { Target } from './targets-core';

const PKG = resolve(import.meta.dirname, '../../../packages/pca');
const fx = (...p: string[]): Buffer => readFileSync(resolve(PKG, 'fixtures', ...p));
const fxb = (...p: string[]): Uint8Array => new Uint8Array(fx(...p));
const fxt = (...p: string[]): string => fx(...p).toString('utf8');
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
const unb64 = (s: unknown) => new Uint8Array(Buffer.from(String(s), 'base64'));
const NV = 'real-nvidia-cc';

const bytesT = (name: string, run: (b: Uint8Array) => unknown, prefix: string, seeds: () => Uint8Array[]): Target<{ b64: string }> => ({
  name,
  allow: typedBy({ prefixes: [prefix] }),
  seeds: () => seeds().map((b) => ({ b64: b64(b) })),
  mutate: (r, c) => ({ b64: b64(mutateBytes(r, unb64(c.b64))) }),
  run: (c) => run(unb64(c.b64)),
});
const textT = (name: string, run: (s: string) => unknown, prefix: string, seeds: () => string[]): Target<{ text: string }> => ({
  name,
  allow: typedBy({ prefixes: [prefix] }),
  seeds: () => seeds().map((text) => ({ text })),
  mutate: (r, c) => ({ text: mutateText(r, c.text) }),
  run: (c) => run(c.text),
});

export function attestTargets(): Target<any>[] {
  const t: Target<any>[] = [];

  t.push(bytesT('parseDcapQuote (real Azure TDX quote)', parseDcapQuote, 'parseDcapQuote:', () => [fxb('real-tdx', 'azure-intel-tdx-dcap-quote.bin'), fxb('real-azure-maa', 'pcabound-tdx-dcap-quote.bin')]));
  t.push(bytesT('parseDcapTdReport', parseDcapTdReport, 'parseDcapTdReport:', () => [fxb('real-tdx', 'azure-intel-tdx-dcap-quote.bin').slice(48, 48 + 584)]));
  t.push(bytesT('parseNvidiaSpdmEvidence (real H100 / GB100 transcripts)', parseNvidiaSpdmEvidence, 'parseNvidiaSpdmEvidence:', () => [fxb(NV, 'h100-gpu-attestation-report.bin'), fxb(NV, 'own-h100', 'h100-gpu-attestation-report.bin'), fxb(NV, 'blackwell', 'gb100-gpu-attestation-report.bin')]));
  t.push(bytesT('parseSevSnpReport (real Azure SEV-SNP report)', parseSevSnpReport, 'parseSevSnpReport:', () => [fxb('..', 'testdata', 'sevsnp-real', 'snp_report.bin')]));
  t.push(textT('parseMaaJwt (real MAA tokens)', parseMaaJwt, 'parseMaaJwt:', () => [fxt('real-azure-maa', 'sevsnp-token.jwt').trim(), fxt('real-azure-maa', 'tdxvm-token.jwt').trim()]));
  t.push(textT('parseGcpCsJwt (real Confidential Space tokens)', parseGcpCsJwt, 'parseGcpCsJwt:', () => {
    // the real GCP captures identify a cloud project and are withheld from the public mirror: fall back to a minimal JWT-shaped seed there
    try { return [fxt('real-gcp-cs', 'prod-token.jwt').trim(), fxt('real-gcp-cs', 'prod-tdx-token.jwt').trim()]; } catch { return ['eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.c2ln']; }
  }));
  t.push(textT('parsePemChain / pemToDer', (s) => [parsePemChain(s).length, pemToDer(s).length], 'p', () => [fxt(NV, 'h100-device-cert-chain.pem')]));
  // the two PEM helpers throw their own prefixed errors (parsePemChain: / pemToDer:); parsePemChain may surface X509 parse errors
  t[t.length - 1]!.allow = (e) => e instanceof Error;
  t.push(textT('decodeIssuerChainHeader', decodeIssuerChainHeader, 'decodeIssuerChainHeader', () => [encodeURIComponent(fxt('real-tdx-collateral', 'tdx-tcbinfo-issuer-chain.pem'))]));
  t[t.length - 1]!.allow = (e) => e instanceof Error;

  // CRL verification against the real Intel root key.
  const rootKey = () => {
    const chainPem = fxt('real-tdx-collateral', 'pckcrl-platform-issuer-chain.pem');
    const certs = chainPem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)!.map((p) => new X509Certificate(p));
    return certs[certs.length - 1]!;
  };
  t.push({
    ...bytesT('verifyCrl (real Intel CRLs)', () => undefined, 'verifyCrl', () => [fxb('real-tdx-collateral', 'pckcrl-platform.der'), fxb('real-tdx-collateral', 'IntelSGXRootCA.crl.der')]),
    allow: neverThrows,
    run: (c: { b64: string }) => verifyCrl(unb64(c.b64), rootKey().publicKey, new Date('2026-10-09T00:00:00Z')),
  });

  // OCSP verification (real NVIDIA responses).
  const chain = () => parsePemChain(fxt(NV, 'h100-device-cert-chain.pem')) as X509Certificate[];
  t.push({
    ...bytesT('verifyNvidiaOcspResponse (real NVIDIA OCSP)', () => undefined, 'x', () => [1, 2, 3].map((i) => fxb(NV, 'ocsp', `${['0-leaf-fmc', '1-brom', '2-provisioner-ica', '3-identity'][i]}.nononce.resp.der`))),
    allow: neverThrows,
    run: async (c: { b64: string }) => {
      const ch = chain();
      return verifyNvidiaOcspResponse(unb64(c.b64), { cert: ch[3]!, issuer: ch[4]!, chain: ch, nowMs: Date.parse('2026-10-08T23:08:00Z') });
    },
  });

  // RIM XML (XMLDSig + CoRIM).
  t.push({
    ...textT('verifyNvidiaRim (real signed RIM XML)', () => undefined, 'x', () => [fxt(NV, 'own-h100', 'driver-rim.xml'), fxt(NV, 'own-h100', 'vbios-rim.xml')]),
    allow: neverThrows,
    run: async (c: { text: string }) => verifyNvidiaRim(c.text, { rimRootSpkiSha256: ['dec1dc316477aa851eebdf51327ae9f864bc8d89254657ed1e7eb9168af1e1a3'], nowMs: Date.parse('2026-10-09T00:00:00Z') }),
  });

  // Full verifiers over mutated evidence: must NEVER throw and must NEVER accept bytes that differ in the signed area.
  const ownReport = () => fxb(NV, 'own-h100', 'h100-gpu-attestation-report.bin');
  t.push({
    name: 'NVIDIA SPDM verifier (mutated transcript + chain PEM)',
    allow: neverThrows,
    seeds: () => [{ rep: b64(ownReport()), pem: fxt(NV, 'own-h100', 'h100-device-cert-chain.pem') }],
    mutate: (r, c) => (r() < 0.7 ? { ...c, rep: b64(mutateBytes(r, unb64(c.rep))) } : { ...c, pem: mutateText(r, c.pem) }),
    run: async (c: { rep: string; pem: string }) => {
      const v = createNvidiaSpdmVerifier({
        rootSpkiSha256: ['a90c4eb5acfd3e3d03a25db6a26b84f720ad0503196c627c21ddd48dd85b06a4'],
        policy: { measurements: {}, leafSubjectIncludes: 'GH100' },
        resolveEvidence: () => ({ evidence: unb64(c.rep), certChainPem: c.pem }),
        postVerify: nvidiaCollateralHook({
          rimRootSpkiSha256: ['dec1dc316477aa851eebdf51327ae9f864bc8d89254657ed1e7eb9168af1e1a3'],
          resolve: () => ({ driverRimXml: fxt(NV, 'own-h100', 'driver-rim.xml'), vbiosRimXml: fxt(NV, 'own-h100', 'vbios-rim.xml'), crls: [fxb(NV, 'collateral', 'l2-gh100.crl'), fxb(NV, 'collateral', 'l1-root.crl')] }),
          requireCrlIssuers: ['NVIDIA GH100 Identity', 'NVIDIA Device Identity CA'],
        }),
      });
      return v.verify({ document: {} as never, ctx: {} as never, nowMs: Date.parse('2026-10-09T00:00:00Z'), expected: { holderPub: 'pca-realsilicon-nvidia-h100-holder', grantRef: 'grant_pca_nvidia_gpucc_realsilicon', epoch: 1, nonce: 'srv-nonce-nv-7c1e9f2a4b8d0536' } });
    },
    check: (c: { rep: string; pem: string }, res) => {
      const r = res as { ok: boolean };
      // PEM armour / whitespace / junk outside the certificates is not signed content: compare the parsed DER chain instead.
      const ders = (pem: string): string => {
        try {
          return parsePemChain(pem).map((x) => x.raw.toString('hex')).join('|');
        } catch {
          return 'UNPARSEABLE:' + pem;
        }
      };
      const same = c.rep === b64(ownReport()) && ders(c.pem) === ders(fxt(NV, 'own-h100', 'h100-device-cert-chain.pem'));
      return r.ok && !same ? 'NVIDIA SPDM verifier ACCEPTED mutated evidence' : undefined;
    },
  });

  const amd = () => {
    const A = JSON.parse(fxt('real-azure-maa', 'sevsnp-amd-certs.json')) as { vcekCert: string; certificateChain: string };
    const report = fxb('..', 'testdata', 'sevsnp-real', 'snp_report.bin');
    return { report, A };
  };
  t.push({
    name: 'AMD SEV-SNP verifier (mutated report / VCEK / chain)',
    allow: neverThrows,
    seeds: () => {
      const { report, A } = amd();
      const hcl = fxb('real-azure-maa', 'sevsnp-hcl-report.bin');
      return [{ rep: b64(hcl.slice(32, 32 + 1184)), vcek: A.vcekCert, chain: A.certificateChain, rt: b64(fxb('real-azure-maa', 'sevsnp-runtime-data.json')) }, { rep: b64(report), vcek: A.vcekCert, chain: A.certificateChain, rt: '' }];
    },
    mutate: (r, c) => {
      const k = Math.floor(r() * 4);
      return k === 0 ? { ...c, rep: b64(mutateBytes(r, unb64(c.rep))) } : k === 1 ? { ...c, vcek: mutateText(r, c.vcek) } : k === 2 ? { ...c, chain: mutateText(r, c.chain) } : { ...c, rt: b64(mutateBytes(r, unb64(c.rt))) };
    },
    run: async (c: { rep: string; vcek: string; chain: string; rt: string }) => {
      const meas = Buffer.from(parseSevSnpReport(unb64(c.rep).length === 1184 ? unb64(c.rep) : fxb('..', 'testdata', 'sevsnp-real', 'snp_report.bin')).measurement).toString('hex');
      const v = createAmdSnpVerifier({
        family: 'genoa',
        binding: 'azure-runtime-data',
        policy: { measurements: [meas] },
        resolveEvidence: () => ({ report: unb64(c.rep), vcekDer: pemToDer(c.vcek), askArkPem: c.chain, runtimeData: unb64(c.rt) }) as AmdSnpEvidence,
      });
      return v.verify({ document: {} as never, ctx: {} as never, nowMs: Date.parse('2026-10-09T00:30:00Z'), expected: { holderPub: 'pca-realsilicon-azure-tdx-holder', grantRef: 'grant_pca_azure_maa_realsilicon', epoch: 1, nonce: 'srv-nonce-maa-5d3b8e1f9a27c604' } });
    },
  });

  // Allowlist manifests: a mutated signed manifest must never verify unless only unknown fields were added.
  const ops = generateKeyPair();
  const issuerKeys: Record<string, AllowlistIssuerKey> = { ops: { alg: 'ed25519', keys: { edPub: b64u(ops.publicKey) } } };
  const NOW = Date.parse('2026-10-09T00:00:00Z');
  const manifest = () =>
    JSON.parse(
      JSON.stringify(
        signAllowlistManifest(
          { version: 3, issuedAt: NOW, notBefore: NOW - 86_400_000, expiresAt: NOW + 86_400_000 * 30, entries: [{ kind: 'tdx-mrtd', value: 'ab'.repeat(48), label: 'boot' }, { kind: 'sev-snp-measurement', value: 'cd'.repeat(48), label: 'snp' }] },
          { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: ops.secretKey } },
        ),
      ),
    ) as Record<string, unknown>;
  let base: Record<string, unknown> | undefined;
  t.push({
    name: 'verifyAllowlistManifest (mutated signed manifest)',
    allow: neverThrows,
    seeds: () => [(base ??= manifest())],
    mutate: (r, c) => mutateJson(r, mutateJson(r, c)) as Record<string, unknown>,
    run: (c: unknown) => verifyAllowlistManifest(c, { issuerKeys, nowMs: NOW }),
    check: (c: unknown, res) => {
      const r = res as { ok: boolean };
      const b = (base ??= manifest());
      const proj = projectOnto(b, c);
      return r.ok && JSON.stringify(proj) !== JSON.stringify(b) ? `allowlist manifest ACCEPTED a mutated manifest at ${firstDiff(b, proj)}` : undefined;
    },
  });

  void nvidiaCollateralHook; void nvidiaRimIdsForReport; void checkNvidiaChainRevocation; void verifyNvidiaDeviceChain; void createNvidiaSpdmVerifier;
  return t;
}
