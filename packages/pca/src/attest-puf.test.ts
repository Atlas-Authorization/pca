/**
 * VALIDATION of the PUF unclonable attestation root (`attest-puf.ts`).
 *
 * HONEST SCOPE: PUF unclonability is a CLASSICAL property (manufacturing entropy — the root device can't be
 * copied); it is a different axis from quantum-resistance and COMPLEMENTS the PQ root. The simulated PUF
 * used here is DETERMINISTIC and therefore clonable — a test stand-in, not a real root. What is proven: the
 * fuzzy extractor reproduces the exact key through bounded noise and diverges beyond the bound, the derived
 * key can be POST-QUANTUM (ML-DSA), a cloned/other device fails, and the verifier is fail-closed throughout.
 */
import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import {
  type PufEnrollment,
  type TpmCommandResult,
  type TpmCommandRunner,
  TpmEkPufProvider,
  createPufAttestor,
  createPufEnrollmentRegistry,
  createPufVerifier,
  createSimulatedPuf,
  enrollPuf,
  fuzzyEnroll,
  fuzzyReproduce,
  repetitionCorrectionBound,
} from './attest-puf';
import { type ExpectedAttestationBinding } from './attestation';
import { encodeKey, generateKeyPair } from './keys';

const REP = 7;
const MSG_BITS = 4;
const N = REP * MSG_BITS; // 28
const CHALLENGE = new Uint8Array([0xca, 0xfe, 0x01]);
const T = 1_000_000;
const A = generateKeyPair();
const EXPECTED: ExpectedAttestationBinding = {
  holderPub: encodeKey(A.publicKey),
  grantRef: 'grant-puf-1',
  epoch: 1,
  nonce: 'nonce-puf-1',
  nonceIssuedAt: T - 1000,
};
const MEASUREMENT = 'puf-workload-measurement';
const CLAIMS = { measurement: MEASUREMENT, holder_pub: EXPECTED.holderPub, grant_ref: EXPECTED.grantRef, epoch: EXPECTED.epoch, nonce: EXPECTED.nonce };

// deterministic RNG for enrollment (codeword message + salt) so tests are stable
function detRng(n: number): Uint8Array {
  const o = new Uint8Array(n);
  for (let i = 0; i < n; i++) o[i] = (i * 7 + 1) & 0xff;
  return o;
}

const SEED_A = new Uint8Array(32).fill(0x11);
const SEED_B = new Uint8Array(32).fill(0x22);

function run(v: ReturnType<typeof createPufVerifier>) {
  return v.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected: EXPECTED });
}

describe('attest-puf: fuzzy extractor (secure sketch + strong extractor)', () => {
  it('reports the per-block correction bound', () => {
    expect(repetitionCorrectionBound(7)).toBe(3);
  });

  it('reproduces the EXACT key through noise WITHIN the correction bound, and diverges beyond it', () => {
    const response = detRng(N).map((x) => x & 1); // a deterministic 0/1 response of length N
    const { key, helper } = fuzzyEnroll(response, { rep: REP, messageBits: MSG_BITS }, detRng);

    // 0 flips => identical key
    expect(b64u(fuzzyReproduce(response, helper))).toBe(b64u(key));

    const flip = (bits: Uint8Array, positions: number[]): Uint8Array => {
      const out = bits.slice();
      for (const p of positions) out[p] = (out[p]! ^ 1) & 1;
      return out;
    };

    // 3 flips inside code block 0 (positions 0,1,2) <= bound(3) => still the same key
    expect(b64u(fuzzyReproduce(flip(response, [0, 1, 2]), helper))).toBe(b64u(key));

    // 4 flips inside code block 0 (positions 0,1,2,3) > bound => a DIFFERENT key (fail-closed)
    expect(b64u(fuzzyReproduce(flip(response, [0, 1, 2, 3]), helper))).not.toBe(b64u(key));
  });

  it('rejects even rep / mismatched length (malformed)', () => {
    expect(() => fuzzyEnroll(new Uint8Array(N), { rep: 6, messageBits: MSG_BITS }, detRng)).toThrow(/odd/);
    expect(() => fuzzyEnroll(new Uint8Array(N + 1), { rep: REP, messageBits: MSG_BITS }, detRng)).toThrow(/length/);
  });
});

describe('attest-puf: end-to-end unclonable attestation (PQ-derived key)', () => {
  const base = createSimulatedPuf({ id: 'gpu-box-7', seed: SEED_A, length: N });
  const enrollment = enrollPuf(base, CHALLENGE, { rep: REP, messageBits: MSG_BITS, alg: 'ml-dsa-65', randomBytes: detRng });
  const registry = createPufEnrollmentRegistry([enrollment]);
  const verifier = createPufVerifier({ resolveEnrollment: (id) => registry.lookup(id), policy: { measurements: [MEASUREMENT] }, resolveEvidence: () => currentStatement });

  // `currentStatement` is the evidence the verifier resolves; each test points it at a fresh statement.
  let currentStatement = createPufAttestor(base, enrollment).attest(CLAIMS);

  it('enrollment yields a POST-QUANTUM (ML-DSA-65) PUF-derived identity', () => {
    expect(enrollment.alg).toBe('ml-dsa-65');
    expect(enrollment.publicKey.length).toBeGreaterThan(100); // ML-DSA-65 public key is large
  });

  it('ACCEPTS a statement from the SAME device with noise within the correction bound', async () => {
    const noisy = createSimulatedPuf({ id: 'gpu-box-7', seed: SEED_A, length: N, flip: [0, 1, 2] });
    currentStatement = createPufAttestor(noisy, enrollment).attest(CLAIMS);
    const r = await run(verifier);
    expect(r.ok).toBe(true);
    expect(r.bound).toBe(true);
    expect(r.measured?.runtime_measurement).toBe(MEASUREMENT);
    expect(r.measured?.weights_measured).toBe(false); // HONEST: PUF roots the identity, not a silicon weights measurement
    expect(r.hostAsserted?.provider_id).toBe('gpu-box-7');
  });

  it('DENIES a statement from a CLONED/other device (different PUF entropy)', async () => {
    const clone = createSimulatedPuf({ id: 'gpu-box-7', seed: SEED_B, length: N });
    currentStatement = createPufAttestor(clone, enrollment).attest(CLAIMS);
    const r = await run(verifier);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/does not verify under the enrolled public key/);
  });

  it('DENIES a statement when PUF noise EXCEEDS the correction bound', async () => {
    const tooNoisy = createSimulatedPuf({ id: 'gpu-box-7', seed: SEED_A, length: N, flip: [0, 1, 2, 3] });
    currentStatement = createPufAttestor(tooNoisy, enrollment).attest(CLAIMS);
    const r = await run(verifier);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/does not verify under the enrolled public key/);
  });

  it('RELAY: a statement bound to another action is denied', async () => {
    currentStatement = createPufAttestor(base, enrollment).attest({ ...CLAIMS, nonce: 'other-nonce' });
    const r = await run(verifier);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/binding mismatch/);
  });

  it('a tampered helper (commitment mismatch) is denied', async () => {
    currentStatement = createPufAttestor(base, enrollment).attest(CLAIMS);
    const tampered: PufEnrollment = { ...enrollment, helper: { ...enrollment.helper, sketch: b64u(new Uint8Array(4)) } };
    const v = createPufVerifier({ resolveEnrollment: () => tampered, policy: { measurements: [MEASUREMENT] }, resolveEvidence: () => currentStatement });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/helper commitment mismatch/);
  });

  it('an unregistered provider id is denied', async () => {
    currentStatement = { ...createPufAttestor(base, enrollment).attest(CLAIMS), provider_id: 'unknown-box' };
    const r = await run(verifier);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no PUF enrollment registered/);
  });

  it('measurement not in policy allowlist is denied', async () => {
    currentStatement = createPufAttestor(base, enrollment).attest(CLAIMS);
    const v = createPufVerifier({ resolveEnrollment: (id) => registry.lookup(id), policy: { measurements: ['other'] }, resolveEvidence: () => currentStatement });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/measurement not in policy allowlist/);
  });
});

describe('attest-puf: classical vs PQ PUF-derived key', () => {
  const base = createSimulatedPuf({ id: 'dev-ed', seed: SEED_A, length: N });

  it('accepts a CLASSICAL (ed25519) PUF-derived identity (unclonable but classical)', async () => {
    const enr = enrollPuf(base, CHALLENGE, { rep: REP, messageBits: MSG_BITS, alg: 'ed25519', randomBytes: detRng });
    const st = createPufAttestor(base, enr).attest(CLAIMS);
    const v = createPufVerifier({ resolveEnrollment: () => enr, policy: { measurements: [MEASUREMENT] }, resolveEvidence: () => st });
    const r = await run(v);
    expect(r.ok).toBe(true);
  });

  it('DENIES a classical PUF key when requirePq is set', async () => {
    const enr = enrollPuf(base, CHALLENGE, { rep: REP, messageBits: MSG_BITS, alg: 'ed25519', randomBytes: detRng });
    const st = createPufAttestor(base, enr).attest(CLAIMS);
    const v = createPufVerifier({ requirePq: true, resolveEnrollment: () => enr, policy: { measurements: [MEASUREMENT] }, resolveEvidence: () => st });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/PQ required: PUF-derived suite 'ed25519' is classical/);
  });
});

describe('attest-puf: construction fail-closed', () => {
  it('rejects an empty measurement allowlist', () => {
    expect(() => createPufVerifier({ resolveEnrollment: () => undefined, policy: { measurements: [] } })).toThrow(/NON-EMPTY/);
  });
});

describe('attest-puf: TPM 2.0 Endorsement-Key-backed PufProvider (real hardware backend)', () => {
  // A deterministic, device-unique "EK public area" stand-in for the MOCKED tpm2-tools runner. This is NOT a
  // simulated PUF — it models the bytes the real `tpm2_readpublic` would print for a given TPM, so the
  // provider's derivation path (HKDF over EK → stable bits → fuzzy extractor) is exercised end to end.
  function fakeEkPublic(label: string, bytes = 272): Uint8Array {
    const out = new Uint8Array(bytes);
    for (let blk = 0; blk * 32 < bytes; blk++) {
      const h = detRng(32).map((x, i) => (x ^ label.charCodeAt(i % label.length) ^ (blk + 1)) & 0xff);
      out.set(h.subarray(0, Math.min(32, bytes - blk * 32)), blk * 32);
    }
    return out;
  }

  const EK_DEVICE = fakeEkPublic('tpm-device-A');
  const EK_CLONE = fakeEkPublic('tpm-device-B'); // a DIFFERENT TPM — different EK bytes

  // A MOCK tpm2-tools runner that returns a fixed EK public on stdout (status 0). The real backend shells to
  // tpm2-tools; this double lets CI prove the derivation + fuzzy-extractor + verifier path without hardware.
  function mockRunner(ek: Uint8Array): TpmCommandRunner {
    return (command, args): TpmCommandResult => {
      expect(command).toBe('tpm2_readpublic');
      expect(args).toContain('-c');
      return { status: 0, stdout: ek };
    };
  }

  it('enrolls from a (mocked) real EK and the verifier ACCEPTS a reproduced PQ statement', async () => {
    const provider = new TpmEkPufProvider({ id: 'azure-vtpm-1', length: N, run: mockRunner(EK_DEVICE) });
    const enrollment = enrollPuf(provider, CHALLENGE, { rep: REP, messageBits: MSG_BITS, alg: 'ml-dsa-65', randomBytes: detRng });
    expect(enrollment.alg).toBe('ml-dsa-65');
    expect(enrollment.publicKey.length).toBeGreaterThan(100); // ML-DSA-65 => unclonable AND post-quantum

    const registry = createPufEnrollmentRegistry([enrollment]);
    // A fresh provider over the SAME device EK reproduces the exact key (EK reads are deterministic => 0 noise).
    const st = createPufAttestor(new TpmEkPufProvider({ id: 'azure-vtpm-1', length: N, run: mockRunner(EK_DEVICE) }), enrollment).attest(CLAIMS);
    const v = createPufVerifier({ resolveEnrollment: (id) => registry.lookup(id), policy: { measurements: [MEASUREMENT] }, resolveEvidence: () => st });
    const r = await run(v);
    expect(r.ok).toBe(true);
    expect(r.bound).toBe(true);
    expect(r.measured?.weights_measured).toBe(false);
    expect(r.hostAsserted?.provider_id).toBe('azure-vtpm-1');
  });

  it('a CLONED/other TPM (different EK) yields a DIFFERENT enrolled key and FAILS verification', async () => {
    const deviceEnr = enrollPuf(new TpmEkPufProvider({ id: 'azure-vtpm-1', length: N, run: mockRunner(EK_DEVICE) }), CHALLENGE, {
      rep: REP,
      messageBits: MSG_BITS,
      alg: 'ml-dsa-65',
      randomBytes: detRng,
    });
    const cloneEnr = enrollPuf(new TpmEkPufProvider({ id: 'azure-vtpm-1', length: N, run: mockRunner(EK_CLONE) }), CHALLENGE, {
      rep: REP,
      messageBits: MSG_BITS,
      alg: 'ml-dsa-65',
      randomBytes: detRng,
    });
    // Different EK => different device-unique response => different fuzzy-extractor key => different identity.
    expect(cloneEnr.publicKey).not.toBe(deviceEnr.publicKey);

    // A cloned TPM signs under its own derived key; the verifier checks under the DEVICE's enrolled public key.
    const stFromClone = createPufAttestor(new TpmEkPufProvider({ id: 'azure-vtpm-1', length: N, run: mockRunner(EK_CLONE) }), deviceEnr).attest(CLAIMS);
    const v = createPufVerifier({ resolveEnrollment: () => deviceEnr, policy: { measurements: [MEASUREMENT] }, resolveEvidence: () => stFromClone });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/does not verify under the enrolled public key/);
  });

  it('fails CLOSED when tpm2-tools is absent (runner reports a spawn error)', () => {
    const absent: TpmCommandRunner = () => ({ status: null, stdout: new Uint8Array(0), error: 'tpm2_readpublic: ENOENT' });
    const provider = new TpmEkPufProvider({ id: 'no-tpm', length: N, run: absent });
    expect(() => provider.response(CHALLENGE)).toThrow(/tpm2-tools unavailable.*ENOENT/);
  });

  it('fails CLOSED when the tpm2 command errors (non-zero exit)', () => {
    const errored: TpmCommandRunner = () => ({ status: 1, stdout: new Uint8Array(0), stderr: 'ERROR: FAPI: no TPM' });
    const provider = new TpmEkPufProvider({ id: 'bad-tpm', length: N, run: errored });
    expect(() => provider.response(CHALLENGE)).toThrow(/exited with status 1/);
  });

  it('fails CLOSED when the EK public is implausibly short (truncated/empty read)', () => {
    const tiny: TpmCommandRunner = () => ({ status: 0, stdout: new Uint8Array(8) });
    const provider = new TpmEkPufProvider({ id: 'short-ek', length: N, run: tiny });
    expect(() => provider.response(CHALLENGE)).toThrow(/EK public too short/);
  });

  it('the DEFAULT runner fails CLOSED on a host without tpm2-tools (real execFileSync path)', () => {
    // No injected runner => the real default runner spawns `tpm2_readpublic`, which is absent on this host.
    const provider = new TpmEkPufProvider({ id: 'this-host', length: N });
    expect(() => provider.response(CHALLENGE)).toThrow(/tpm2-tools (unavailable|invocation)/);
  });

  it('rejects malformed construction (bad id / length)', () => {
    expect(() => new TpmEkPufProvider({ id: '', length: N })).toThrow(/id/);
    expect(() => new TpmEkPufProvider({ id: 'x', length: 0 })).toThrow(/length/);
  });
});
