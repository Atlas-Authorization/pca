import { beforeAll, describe, expect, it } from 'vitest';
import SEAL from 'node-seal';
import { DEFAULT_RISK_POLICY, type RiskPolicy } from '@atlasauth/pca';
import {
  PLAIN_MODULUS,
  POLY_MODULUS_DEGREE,
  RISK_DIM,
  type EvalKeys,
  type FheKeyset,
  createFheContext,
  decryptVerdict,
  encryptRiskInputs,
  evalRiskGate,
  fheRiskPolicy,
  keygen,
} from './index';

const TIMEOUT = 600_000;
const policy = fheRiskPolicy(DEFAULT_RISK_POLICY, 0.6);
const inputs = [100, 900, 100, 100, 100, 100];
const rawExpected = inputs.reduce((a, x, i) => a + x * (policy.weightsScaled[i] ?? 0), 0); // 260000

describe('parameter security (128-bit, Homomorphic Encryption Standard tables)', () => {
  /*
   * Homomorphic Encryption Security Standard (Albrecht et al., 2018), Table 1 ("max log2 q"
   * for classical 128-bit security, ternary secret): n = 1024 -> 27, 2048 -> 54, 4096 -> 109,
   * 8192 -> 218, 16384 -> 438, 32768 -> 881.
   * Source: https://homomorphicencryption.org/standard/ (HomomorphicEncryptionStandard_2018118.pdf).
   * Microsoft SEAL's `CoeffModulus::MaxBitCount(n, tc128)` is built from the same table.
   */
  const HE_STANDARD_128_MAX_LOG_Q = { 1024: 27, 2048: 54, 4096: 109, 8192: 218, 16384: 438, 32768: 881 } as const;

  it('uses n = 8192 and a total coefficient-modulus size within the standard 128-bit bound (218 bits)', async () => {
    const seal = await SEAL();
    const primes = Array.from(
      seal.CoeffModulus.BFVDefault(POLY_MODULUS_DEGREE, seal.SecurityLevel.tc128).toArray() as BigUint64Array,
    );
    const totalBits = primes.reduce((a, p) => a + p.toString(2).length, 0);
    expect(POLY_MODULUS_DEGREE).toBe(8192);
    expect(totalBits).toBeLessThanOrEqual(HE_STANDARD_128_MAX_LOG_Q[8192]);
    expect(totalBits).toBe(218);
    expect(primes.map((p) => p.toString(2).length)).toEqual([43, 43, 44, 44, 44]);
    // the library's own table agrees with the published one
    expect(seal.CoeffModulus.MaxBitCount(8192, seal.SecurityLevel.tc128)).toBe(HE_STANDARD_128_MAX_LOG_Q[8192]);
    // every prime is NTT-friendly for n = 8192 (p = 1 mod 2n)
    for (const p of primes) expect(p % BigInt(2 * POLY_MODULUS_DEGREE)).toBe(1n);
  });

  it('the live context is built at the tc128 security level and has the documented plain modulus', async () => {
    const ctx = await createFheContext();
    try {
      expect(ctx.context.parametersSet()).toBe(true);
      expect(ctx.slotCount).toBe(POLY_MODULUS_DEGREE);
      expect(PLAIN_MODULUS).toBe(1_073_692_673);
      expect((PLAIN_MODULUS - 1) % (2 * POLY_MODULUS_DEGREE)).toBe(0); // batching-compatible
    } finally {
      ctx.dispose();
    }
  });

  it('the same degree with an over-large modulus (240 bits) is REJECTED at tc128 and only accepted with security disabled', async () => {
    const seal = await SEAL();
    const parms = seal.EncryptionParameters(seal.SchemeType.bfv);
    parms.setPolyModulusDegree(8192);
    parms.setCoeffModulus(seal.CoeffModulus.Create(8192, Int32Array.from([60, 60, 60, 60])));
    parms.setPlainModulus(seal.PlainModulus.Batching(8192, 30));
    const secure = seal.Context(parms, true, seal.SecurityLevel.tc128);
    expect(secure.parametersSet()).toBe(false); // 240 > 218: insecure for 128-bit
    const unchecked = seal.Context(parms, true, seal.SecurityLevel.none);
    expect(unchecked.parametersSet()).toBe(true); // proves the rejection above was the security check, nothing else
    secure.delete();
    unchecked.delete();
    parms.delete();
  });
});

describe('serialization and tamper behaviour', () => {
  let keys: FheKeyset;
  let evalKeys: EvalKeys;

  beforeAll(async () => {
    keys = await keygen();
    evalKeys = { publicKey: keys.publicKey, relinKeys: keys.relinKeys, galoisKeys: keys.galoisKeys };
  }, TIMEOUT);

  it(
    'ciphertext round-trip: load -> save -> load decrypts to the same slots, and re-saving is byte-stable',
    async () => {
      const enc = await encryptRiskInputs(keys.publicKey, inputs);
      const ctx = await createFheContext();
      try {
        const c1 = ctx.seal.CipherText();
        c1.load(ctx.context, enc);
        const resaved = c1.save();
        const c2 = ctx.seal.CipherText();
        c2.load(ctx.context, resaved);
        expect(c2.save()).toBe(resaved);
        const sk = ctx.seal.SecretKey();
        sk.load(ctx.context, keys.secretKey);
        const dec = ctx.seal.Decryptor(ctx.context, sk);
        const decode = (c: typeof c1): number[] => {
          const pt = dec.decrypt(c);
          if (pt === undefined) throw new Error('decrypt returned void');
          return Array.from(ctx.encoder.decode(pt, true).slice(0, RISK_DIM));
        };
        expect(decode(c1)).toEqual(inputs);
        expect(decode(c2)).toEqual(inputs);
      } finally {
        ctx.dispose();
      }
      // A restored copy flows through the public API identically.
      const gate = await evalRiskGate(evalKeys, enc, policy);
      const v = await decryptVerdict(keys.secretKey, gate.encRiskRaw, gate.encSlack, policy);
      expect(v.rScaled).toBe(rawExpected);
    },
    TIMEOUT,
  );

  it(
    'gate outputs survive an extra serialize/deserialize hop (as they would over the wire) and key blobs round-trip',
    async () => {
      const enc = await encryptRiskInputs(keys.publicKey, inputs);
      const gate = await evalRiskGate(evalKeys, enc, policy);
      const ctx = await createFheContext();
      let hopped: { r: string; s: string };
      try {
        const rehop = (blob: string): string => {
          const c = ctx.seal.CipherText();
          c.load(ctx.context, blob);
          const out = c.save();
          c.delete();
          return out;
        };
        hopped = { r: rehop(gate.encRiskRaw), s: rehop(gate.encSlack) };
        // key blobs: load + save is accepted and stable
        const pk = ctx.seal.PublicKey();
        pk.load(ctx.context, keys.publicKey);
        const pkBlob = pk.save();
        const sk = ctx.seal.SecretKey();
        sk.load(ctx.context, keys.secretKey);
        const skBlob = sk.save();
        // the re-saved key still works end to end
        const enc2 = await encryptRiskInputs(pkBlob, inputs);
        const gate2 = await evalRiskGate({ ...evalKeys, publicKey: pkBlob }, enc2, policy);
        const v2 = await decryptVerdict(skBlob, gate2.encRiskRaw, gate2.encSlack, policy);
        expect(v2.rScaled).toBe(rawExpected);
      } finally {
        ctx.dispose();
      }
      const v = await decryptVerdict(keys.secretKey, hopped.r, hopped.s, policy);
      expect(v).toEqual({ rScaled: rawExpected, slack: policy.budgetScaled - rawExpected, admit: true });
    },
    TIMEOUT,
  );

  it(
    'semantic security smoke: encrypting the same plaintext twice gives different ciphertexts that decrypt identically',
    async () => {
      const a = await encryptRiskInputs(keys.publicKey, inputs);
      const b = await encryptRiskInputs(keys.publicKey, inputs);
      expect(a).not.toBe(b);
      const va = await decryptVerdict(keys.secretKey, a, b, policy);
      expect(va.rScaled).toBe(inputs[0]);
      expect(va.slack).toBe(inputs[0]);
    },
    TIMEOUT,
  );

  it(
    'wrong secret key: decrypts to a different value, deterministically NOT the true verdict (checked over several fresh keys)',
    async () => {
      const enc = await encryptRiskInputs(keys.publicKey, inputs);
      const gate = await evalRiskGate(evalKeys, enc, policy);
      for (let i = 0; i < 3; i++) {
        const wrong = await keygen();
        const v = await decryptVerdict(wrong.secretKey, gate.encRiskRaw, gate.encSlack, policy);
        expect(v.slack).not.toBe(policy.budgetScaled - rawExpected);
        expect(v.rScaled === rawExpected).toBe(false);
      }
    },
    TIMEOUT,
  );

  it(
    'a ciphertext encrypted under a DIFFERENT public key is not decryptable by the real key holder',
    async () => {
      const other = await keygen();
      const enc = await encryptRiskInputs(other.publicKey, inputs);
      const v = await decryptVerdict(keys.secretKey, enc, enc, policy);
      expect(v.rScaled === inputs[0]).toBe(false);
    },
    TIMEOUT,
  );

  it(
    'malformed or truncated blobs are rejected up front, each with its specific reason',
    async () => {
      const enc = await encryptRiskInputs(keys.publicKey, inputs);
      const gate = await evalRiskGate(evalKeys, enc, policy);
      const cases: Array<[string, string, RegExp]> = [
        ['empty string', '', /bad encoding/],
        ['not base64', '!!!not-a-ciphertext!!!', /bad encoding/],
        ['valid base64, wrong magic', Buffer.from('this is definitely not seal data at all').toString('base64'), /bad header/],
        ['truncated to half', gate.encRiskRaw.slice(0, Math.floor(gate.encRiskRaw.length / 8) * 4), /truncated or padded/],
        ['header only', gate.encRiskRaw.slice(0, 24), /truncated or padded/],
        ['padded', Buffer.concat([Buffer.from(gate.encRiskRaw, 'base64'), Buffer.from([0, 0, 0])]).toString('base64'), /truncated or padded/],
      ];
      for (const [label, blob, reason] of cases) {
        await expect(decryptVerdict(keys.secretKey, blob, gate.encSlack, policy), label).rejects.toThrow(reason);
        await expect(decryptVerdict(keys.secretKey, gate.encRiskRaw, blob, policy), label).rejects.toThrow(reason);
        await expect(evalRiskGate(evalKeys, blob, policy), label).rejects.toThrow(reason);
        await expect(evalRiskGate({ ...evalKeys, galoisKeys: blob }, enc, policy), label).rejects.toThrow(reason);
      }
      await expect(decryptVerdict('', gate.encRiskRaw, gate.encSlack, policy)).rejects.toThrow(/secretKey: .*bad encoding/);
      await expect(encryptRiskInputs('', inputs)).rejects.toThrow(/publicKey: .*bad encoding/);
    },
    TIMEOUT,
  );

  it(
    'REGRESSION: repeatedly feeding the evaluator malformed blobs does not leak WASM memory',
    async () => {
      const enc = await encryptRiskInputs(keys.publicKey, inputs);
      const truncated = enc.slice(0, 1000);
      const rssMb = (): number => process.memoryUsage().rss / 1e6;
      await evalRiskGate(evalKeys, enc, policy); // warm up allocator and Galois-key load
      const before = rssMb();
      for (let i = 0; i < 12; i++) await expect(evalRiskGate(evalKeys, truncated, policy)).rejects.toThrow();
      // Before the fix each failed call stranded a loaded Galois-key set (~80 MB), i.e. ~950 MB over 12 calls.
      expect(rssMb() - before).toBeLessThan(200);
    },
    TIMEOUT,
  );

  it(
    'a key blob passed in the wrong role is rejected by SEAL: public key as secret key, secret key / ciphertext as public key',
    async () => {
      const enc = await encryptRiskInputs(keys.publicKey, inputs);
      const gate = await evalRiskGate(evalKeys, enc, policy);
      await expect(decryptVerdict(keys.publicKey, gate.encRiskRaw, gate.encSlack, policy)).rejects.toThrow(/plaintext data is invalid/);
      await expect(encryptRiskInputs(keys.secretKey, inputs)).rejects.toThrow(/cast failed/);
      await expect(encryptRiskInputs(enc, inputs)).rejects.toThrow(/PublicKey data is invalid/);
    },
    TIMEOUT,
  );

  it(
    'a bit-flipped ciphertext either fails to load or never yields the true verdict (flip swept across the blob)',
    async () => {
      const enc = await encryptRiskInputs(keys.publicKey, inputs);
      const raw = Buffer.from(enc, 'base64');
      // positions across header, early payload and the body
      for (const frac of [0.0, 0.5, 0.9]) {
        const pos = Math.min(raw.length - 1, Math.floor(raw.length * frac) + 20);
        const mutated = Buffer.from(raw);
        mutated[pos] = (mutated[pos] ?? 0) ^ 0x40;
        let verdictMatches = false;
        let threw = false;
        try {
          const gate = await evalRiskGate(evalKeys, mutated.toString('base64'), policy);
          const v = await decryptVerdict(keys.secretKey, gate.encRiskRaw, gate.encSlack, policy);
          verdictMatches = v.rScaled === rawExpected && v.slack === policy.budgetScaled - rawExpected;
        } catch {
          threw = true;
        }
        expect(threw || !verdictMatches, `flip at ${pos}`).toBe(true);
      }
    },
    TIMEOUT,
  );

  it(
    'REGRESSION: a policy whose scaled weights are all zero evaluates (SEAL rejects multiplyPlain by a zero plaintext)',
    async () => {
      const enc = await encryptRiskInputs(keys.publicKey, inputs);

      // (a) every weight rounds to zero at scale 1000
      const tinyW: RiskPolicy = {
        ...DEFAULT_RISK_POLICY,
        weights: { alpha: 0.0004, beta: 0.0004, gamma: 0.0004, delta: 0.0004, epsilon: 0.0004, zeta: 0.0004 },
      };
      const pa = fheRiskPolicy(tinyW, 0.5);
      expect(pa.weightsScaled).toEqual([0, 0, 0, 0, 0, 0]);
      const ga = await evalRiskGate(evalKeys, enc, pa);
      expect(await decryptVerdict(keys.secretKey, ga.encRiskRaw, ga.encSlack, pa)).toEqual({
        rScaled: 0,
        slack: pa.budgetScaled,
        admit: true,
      });

      // (b) weights are fine but kappa is so small that every kappa-weight rounds to zero
      const tinyK: RiskPolicy = { ...DEFAULT_RISK_POLICY, kappa: 0.0001 };
      const pb = fheRiskPolicy(tinyK, 0.5);
      expect(pb.kappaWeightsScaled).toEqual([0, 0, 0, 0, 0, 0]);
      expect(pb.weightsScaled.some((w) => w !== 0)).toBe(true);
      const gb = await evalRiskGate(evalKeys, enc, pb);
      const vb = await decryptVerdict(keys.secretKey, gb.encRiskRaw, gb.encSlack, pb);
      expect(vb).toEqual({ rScaled: rawExpected, slack: pb.budgetScaled, admit: true });
    },
    TIMEOUT,
  );
});
