/**
 * Community-standard BLS12-381 test vectors (ethereum/bls12-381-tests v0.1.2) for the
 * proof-of-possession ciphersuite `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` that this package
 * implements (draft-irtf-cfrg-bls-signature). The IETF draft itself publishes no vectors (its
 * Appendix B is "TBA"), so these are the reference vectors for the scheme. Provenance and per-file
 * SHA-256 are in `test-vectors/ethereum-bls12-381-tests-v0.1.2/PROVENANCE.json`.
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import {
  aggregate,
  aggregatePublicKeys,
  aggregateVerify,
  fastAggregateVerify,
  keyValidate,
  popProve,
  popVerify,
  publicKeyOf,
  sign,
  verify,
} from './bls';

const ROOT = join(__dirname, '../test-vectors/ethereum-bls12-381-tests-v0.1.2');
const strip = (s: string): string => (s.startsWith('0x') ? s.slice(2) : s);
const h = (s: string): Uint8Array => hexToBytes(strip(s));

function cases<I, O>(dir: string): { name: string; input: I; output: O }[] {
  return readdirSync(join(ROOT, dir))
    .sort()
    .map((f) => {
      const j = JSON.parse(readFileSync(join(ROOT, dir, f), 'utf8')) as { input: I; output: O };
      return { name: f.replace(/\.json$/, ''), ...j };
    });
}

describe('fixture integrity', () => {
  it('every vendored file matches its recorded SHA-256 (90 files)', () => {
    const prov = JSON.parse(readFileSync(join(ROOT, 'PROVENANCE.json'), 'utf8')) as {
      archiveSha256: string;
      files_sha256: Record<string, string>;
    };
    const entries = Object.entries(prov.files_sha256);
    expect(entries.length).toBe(90);
    expect(prov.archiveSha256).toMatch(/^[0-9a-f]{64}$/);
    for (const [rel, sha] of entries) {
      expect(createHash('sha256').update(readFileSync(join(ROOT, rel))).digest('hex'), rel).toBe(sha);
    }
  });
});

describe('sign (10 vectors)', () => {
  for (const c of cases<{ privkey: string; message: string }, string | null>('sign')) {
    it(c.name, () => {
      if (c.output === null) {
        // zero private key: the signer must refuse rather than emit a signature
        expect(() => sign(h(c.input.privkey), h(c.input.message))).toThrow();
      } else {
        expect(bytesToHex(sign(h(c.input.privkey), h(c.input.message)))).toBe(strip(c.output));
      }
    });
  }
});

describe('verify (29 vectors)', () => {
  for (const c of cases<{ pubkey: string; message: string; signature: string }, boolean>('verify')) {
    it(`${c.name} -> ${String(c.output)}`, () => {
      expect(verify(h(c.input.pubkey), h(c.input.message), h(c.input.signature))).toBe(c.output);
    });
  }
});

describe('aggregate (6 vectors)', () => {
  for (const c of cases<string[], string | null>('aggregate')) {
    it(c.name, () => {
      if (c.output === null) {
        expect(() => aggregate(c.input.map(h))).toThrow(/at least one signature/);
      } else {
        expect(bytesToHex(aggregate(c.input.map(h)))).toBe(strip(c.output));
      }
    });
  }
});

describe('fast_aggregate_verify (12 vectors)', () => {
  for (const c of cases<{ pubkeys: string[]; message: string; signature: string }, boolean>('fast_aggregate_verify')) {
    it(`${c.name} -> ${String(c.output)}`, () => {
      expect(fastAggregateVerify(c.input.pubkeys.map(h), h(c.input.message), h(c.input.signature))).toBe(c.output);
    });
  }
});

describe('aggregate_verify (5 vectors)', () => {
  for (const c of cases<{ pubkeys: string[]; messages: string[]; signature: string }, boolean>('aggregate_verify')) {
    it(`${c.name} -> ${String(c.output)}`, () => {
      expect(aggregateVerify(c.input.pubkeys.map(h), c.input.messages.map(h), h(c.input.signature))).toBe(c.output);
    });
  }
});

describe('G1 public-key deserialization / KeyValidate (13 vectors)', () => {
  for (const c of cases<{ pubkey: string }, boolean>('deserialization_G1')) {
    // The fixtures test point decoding + subgroup membership. KeyValidate additionally rejects the
    // identity (draft section 2.5), which is the one documented difference.
    const isInfinity = /^c0+$/.test(c.input.pubkey);
    it(`${c.name} -> ${String(c.output)}${isInfinity ? ' (but identity rejected by KeyValidate)' : ''}`, () => {
      const expected = c.output && !isInfinity;
      expect(keyValidate(h(c.input.pubkey))).toBe(expected);
    });
  }
});

describe('G2 signature deserialization (15 vectors): malformed encodings never verify', () => {
  const pk = h('a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a');
  for (const c of cases<{ signature: string }, boolean>('deserialization_G2')) {
    it(`${c.name} -> ${String(c.output)}`, () => {
      const r = verify(pk, new Uint8Array(32), h(c.input.signature));
      // A signature that fails to decode (or is off-subgroup) can never verify; a decodable
      // one is merely a valid point, not a valid signature for this key/message.
      expect(r).toBe(false);
    });
  }
});

describe('rogue-key and proof-of-possession negatives', () => {
  const sk1 = h('263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3');
  const sk2 = h('47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138');
  const msg = h('5656565656565656565656565656565656565656565656565656565656565656');

  it('PoP: a proof by the key holder verifies; the same bytes for another key do not', () => {
    const pk1 = publicKeyOf(sk1);
    const pk2 = publicKeyOf(sk2);
    const pop1 = popProve(sk1);
    expect(popVerify(pk1, pop1)).toBe(true);
    expect(popVerify(pk2, pop1)).toBe(false);
  });

  it('PoP domain separation: a message signature over the public key is not a valid PoP, and a PoP is not a message signature', () => {
    const pk1 = publicKeyOf(sk1);
    expect(popVerify(pk1, sign(sk1, pk1))).toBe(false);
    expect(verify(pk1, pk1, popProve(sk1))).toBe(false);
  });

  it('rogue-key attack: pk_adv = g^a - pk_victim yields a forged same-message aggregate under plain verification, but cannot produce a valid PoP', async () => {
    const { bls12_381 } = await import('@noble/curves/bls12-381');
    const G1 = bls12_381.G1.ProjectivePoint;
    const pkV = G1.fromHex(publicKeyOf(sk1));
    const a = 123456789n;
    // rogue key chosen as a function of the victim's key: pk_adv = a*G - pk_victim
    const pkAdv = G1.BASE.multiply(a).subtract(pkV);
    const pkAdvBytes = pkAdv.toRawBytes(true);
    expect(keyValidate(pkAdvBytes)).toBe(true); // it is a perfectly valid-looking key
    // The aggregate key of {victim, adversary} is a*G, so the adversary alone can sign for "both":
    const forged = sign(numberTo32(a), msg);
    const keys = [publicKeyOf(sk1), pkAdvBytes];
    expect(bytesToHex(aggregatePublicKeys(keys))).toBe(bytesToHex(publicKeyOf(numberTo32(a))));
    // Without PoP this forgery would verify (that is exactly the attack):
    expect(fastAggregateVerify(keys, msg, forged)).toBe(true);
    // ...which is why admission requires a PoP. The adversary cannot make one: it does not know
    // the discrete log of pk_adv. The best it can do is a PoP from some other key, which fails.
    expect(popVerify(pkAdvBytes, popProve(numberTo32(a)))).toBe(false);
    expect(popVerify(pkAdvBytes, popProve(sk2))).toBe(false);
  });
});

function numberTo32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
