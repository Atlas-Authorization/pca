/**
 * REAL-SILICON test for the NVIDIA GPU-CC root (real SPDM/X.509 wire format).
 *
 * Evidence: a GENUINE NVIDIA H100 (GH100, Hopper) confidential-computing attestation — the SPDM
 * GET_MEASUREMENTS request‖response transcript and the 5-certificate device chain — captured 2026-10-08
 * from a Phala GPU-TEE node, with the SPDM request nonce set to the PCA challenge
 * `sha256(attestationBinding(EXPECTED))`. Verified offline against NVIDIA's pinned Device Identity CA.
 * See fixtures/real-nvidia-cc/README.md.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect } from 'vitest';
import {
  createNvidiaSpdmVerifier,
  parseNvidiaSpdmEvidence,
  parsePemChain,
  spkiSha256Hex,
  NVIDIA_OPAQUE,
  type NvidiaSpdmEvidence,
} from './attest-nvidia-spdm';
import type { AttestationDocument, ExpectedAttestationBinding } from './attestation';

const FIX = (f: string) => resolve(__dirname, '..', 'fixtures', 'real-nvidia-cc', f);
const REPORT = new Uint8Array(readFileSync(FIX('h100-gpu-attestation-report.bin')));
const CHAIN_PEM = readFileSync(FIX('h100-device-cert-chain.pem'), 'utf8');

const EXPECTED: ExpectedAttestationBinding = {
  holderPub: 'pca-realsilicon-nvidia-h100-holder',
  grantRef: 'grant_pca_nvidia_gpucc_realsilicon',
  epoch: 1,
  nonce: 'srv-nonce-nv-7c1e9f2a4b8d0536',
};
/** NVIDIA Device Identity CA — equals the root NVIDIA ships pinned in its own local GPU verifier. */
const NVIDIA_ROOT_SPKI = 'a90c4eb5acfd3e3d03a25db6a26b84f720ad0503196c627c21ddd48dd85b06a4';
const NOW_MS = 1_791_498_000_000;

const parsed = parseNvidiaSpdmEvidence(REPORT);
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const M2 = hex(parsed.response.measurements[1]!.digest);
const M3 = hex(parsed.response.measurements[2]!.digest);

const DOC = {} as unknown as AttestationDocument;
const CTX = {} as never;

function verifier(over: { ev?: NvidiaSpdmEvidence; pins?: string[]; meas?: Record<number, string>; subject?: string } = {}) {
  const ev: NvidiaSpdmEvidence = over.ev ?? { evidence: REPORT, certChainPem: CHAIN_PEM };
  return createNvidiaSpdmVerifier({
    rootSpkiSha256: over.pins ?? [NVIDIA_ROOT_SPKI],
    policy: {
      measurements: over.meas ?? { 2: M2, 3: M3 },
      ...(over.subject ? { leafSubjectIncludes: over.subject } : { leafSubjectIncludes: 'GH100' }),
    },
    resolveEvidence: () => ev,
  });
}
const run = (v: ReturnType<typeof verifier>, expected: ExpectedAttestationBinding = EXPECTED, nowMs = NOW_MS) =>
  v.verify({ document: DOC, ctx: CTX, nowMs, expected });
const flip = (b: Uint8Array, i: number) => {
  const c = new Uint8Array(b);
  c[i] = (c[i] ?? 0) ^ 0x01;
  return c;
};

describe('NVIDIA GPU-CC SPDM — REAL H100 silicon', () => {
  it('parses the genuine transcript (64 blocks, 96-byte sig, opaque TLVs)', () => {
    expect(parsed.request.nonce.length).toBe(32);
    expect(parsed.response.measurements.length).toBe(64);
    expect(parsed.response.measurements.every((m) => m.digest.length === 48)).toBe(true);
    expect(parsed.response.signature.length).toBe(96);
    expect(Buffer.from(parsed.response.opaque.get(NVIDIA_OPAQUE.DRIVER_VERSION) ?? []).toString().replace(/\0/g, '')).toBe('580.95.05');
  });

  it('the captured device chain is the 5-cert GH100 chain to the NVIDIA Device Identity CA', () => {
    const chain = parsePemChain(CHAIN_PEM);
    expect(chain.length).toBe(5);
    expect(chain[0]!.subject).toContain('GH100');
    expect(spkiSha256Hex(chain[4]!)).toBe(NVIDIA_ROOT_SPKI);
  });

  it('verifies end-to-end: chain + report signature + PCA binding + pinned measurements', async () => {
    const r = await run(verifier());
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.bound).toBe(true);
      expect(r.hostAsserted?.driver_version).toBe('580.95.05');
      expect(r.hostAsserted?.leaf_subject).toContain('GH100');
      expect(r.measured?.runtime_measurement).toBe(''); // a GPU is a gate, not a workload identity (composes with CPU roots)
      expect(r.hostAsserted?.gpu_measurements_sha384).toMatch(/^[0-9a-f]{96}$/);
    }
  });

  it('fails closed: any bit flipped in a measurement digest (signature breaks)', async () => {
    const off = 37 + 8 + 4 + 3 + 5; // inside the first measurement digest
    const r = await run(verifier({ ev: { evidence: flip(REPORT, off), certChainPem: CHAIN_PEM } }));
    expect(r.ok).toBe(false);
  });

  it('fails closed: tampered signature, tampered request nonce', async () => {
    expect((await run(verifier({ ev: { evidence: flip(REPORT, REPORT.length - 1), certChainPem: CHAIN_PEM } }))).ok).toBe(false);
    expect((await run(verifier({ ev: { evidence: flip(REPORT, 10), certChainPem: CHAIN_PEM } }))).ok).toBe(false);
  });

  it('fails closed: a different holder / grant / epoch / nonce (relayed report)', async () => {
    for (const bad of [
      { ...EXPECTED, holderPub: 'someone-else' },
      { ...EXPECTED, grantRef: 'grant_other' },
      { ...EXPECTED, epoch: 2 },
      { ...EXPECTED, nonce: 'srv-nonce-other' },
    ]) {
      const r = await run(verifier(), bad);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toContain('does not bind');
    }
  });

  it('fails closed: pinned measurement mismatch / missing block / wrong pin / wrong GPU family', async () => {
    expect((await run(verifier({ meas: { 2: '00'.repeat(48) } }))).ok).toBe(false);
    expect((await run(verifier({ meas: { 200: M2 } }))).ok).toBe(false);
    expect((await run(verifier({ pins: ['00'.repeat(32)] }))).ok).toBe(false);
    expect((await run(verifier({ subject: 'GB100' }))).ok).toBe(false);
  });

  it('fails closed: broken / reordered / truncated / foreign chain', async () => {
    const blocks = CHAIN_PEM.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)!;
    const variants = [
      blocks.slice(0, 4).join('\n'), // root dropped → top is not self-signed
      [blocks[1]!, blocks[0]!, ...blocks.slice(2)].join('\n'), // leaf/intermediate swapped
      [blocks[0]!, blocks[4]!].join('\n'), // intermediates skipped
      '',
    ];
    for (const pem of variants) expect((await run(verifier({ ev: { evidence: REPORT, certChainPem: pem } }))).ok).toBe(false);
  });

  it('fails closed outside the certificates validity window', async () => {
    expect((await run(verifier(), EXPECTED, 0)).ok).toBe(false);
  });

  it('fails closed with no evidence resolver / no evidence', async () => {
    const noResolver = createNvidiaSpdmVerifier({ rootSpkiSha256: [NVIDIA_ROOT_SPKI], policy: { measurements: { 2: M2 } } });
    expect((await run(noResolver)).ok).toBe(false);
    const none = createNvidiaSpdmVerifier({ rootSpkiSha256: [NVIDIA_ROOT_SPKI], policy: { measurements: { 2: M2 } }, resolveEvidence: () => undefined });
    expect((await run(none)).ok).toBe(false);
  });

  it('refuses accept-all construction', () => {
    expect(() => createNvidiaSpdmVerifier({ rootSpkiSha256: [], policy: { measurements: { 2: M2 } } })).toThrow();
    expect(() => createNvidiaSpdmVerifier({ rootSpkiSha256: [NVIDIA_ROOT_SPKI], policy: { measurements: {} } })).toThrow();
    expect(() => createNvidiaSpdmVerifier({ rootSpkiSha256: [NVIDIA_ROOT_SPKI], policy: { measurements: { 999: M2 } } })).toThrow();
  });

  it('parser is total: every truncation and random corruption throws a typed error, never reads out of bounds', () => {
    for (let n = 0; n < REPORT.length; n += 97) expect(() => parseNvidiaSpdmEvidence(REPORT.slice(0, n))).toThrow();
    let seed = 0x9e3779b9;
    const rnd = () => ((seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0) / 2 ** 32);
    for (let i = 0; i < 400; i++) {
      const c = new Uint8Array(REPORT);
      const k = 1 + Math.floor(rnd() * 4);
      for (let j = 0; j < k; j++) c[37 + Math.floor(rnd() * 40)] = Math.floor(rnd() * 256); // header/length fields
      try {
        const p = parseNvidiaSpdmEvidence(c);
        expect(p.response.signature.length).toBe(96); // if it parses, it is structurally exact
      } catch (e) {
        expect(e instanceof RangeError || e instanceof TypeError).toBe(true);
      }
    }
  });
});
