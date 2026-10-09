/**
 * Official fixtures for draft-irtf-cfrg-bbs-signatures (ciphersuite BLS12-381-SHA-256), vendored in
 * `test-vectors/draft-irtf-cfrg-bbs-signatures/` with provenance (repository commit, per-file SHA-256).
 * Every file is byte-identical across draft revisions -06 through -12.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes, numberToBytesBE } from '@noble/curves/abstract/utils';
import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve';
import { sha256 } from '@noble/hashes/sha256';
import {
  createGenerators,
  hashToScalar,
  keyGen,
  mapMessageToScalarAsHash,
  proofGen,
  proofVerifyDetailed,
  R,
  sign,
  skToBytes,
  skToPk,
  verifyDetailed,
  type RejectReason,
} from './bbs';

const ROOT = join(__dirname, '../test-vectors/draft-irtf-cfrg-bbs-signatures');
const SUITE = join(ROOT, 'bls12-381-sha-256');
const load = <T>(rel: string): T => JSON.parse(readFileSync(join(SUITE, rel), 'utf8')) as T;
const h = (s: string): Uint8Array => hexToBytes(s);
const hx = (b: Uint8Array): string => bytesToHex(b);
const dstString = (hexDst: string): string => new TextDecoder().decode(h(hexDst));

interface Provenance {
  commit: string;
  files_sha256: Record<string, string>;
}
interface SigFixture {
  caseName: string;
  signerKeyPair: { secretKey: string; publicKey: string };
  header: string;
  messages: string[];
  signature: string;
  result: { valid: boolean; reason?: string };
  trace: { B: string; domain: string };
}
interface ProofFixture {
  caseName: string;
  signerPublicKey: string;
  signature: string;
  header: string;
  presentationHeader: string;
  messages: string[];
  disclosedIndexes: number[];
  proof: string;
  result: { valid: boolean; reason?: string };
  trace?: {
    random_scalars: { r1: string; r2: string; e_tilde: string; r1_tilde: string; r3_tilde: string; m_tilde_scalars: string[] };
    domain: string;
    challenge: string;
  };
}

const sigFixtures = Array.from({ length: 10 }, (_, i) =>
  load<SigFixture>(`signature/signature${String(i + 1).padStart(3, '0')}.json`),
);
const proofFixtures = Array.from({ length: 15 }, (_, i) =>
  load<ProofFixture>(`proof/proof${String(i + 1).padStart(3, '0')}.json`),
);

describe('fixture integrity', () => {
  const prov = JSON.parse(readFileSync(join(ROOT, 'PROVENANCE.json'), 'utf8')) as Provenance;
  it('records a pinned repository commit', () => {
    expect(prov.commit).toMatch(/^[0-9a-f]{40}$/);
  });
  it('every vendored file matches its recorded SHA-256 (31 files)', () => {
    const entries = Object.entries(prov.files_sha256);
    expect(entries.length).toBe(31);
    for (const [rel, sha] of entries) {
      const bytes = readFileSync(join(ROOT, rel));
      expect(createHash('sha256').update(bytes).digest('hex'), rel).toBe(sha);
    }
  });
});

describe('draft fixtures: KeyGen / SkToPk / hash_to_scalar / map_message_to_scalar / generators', () => {
  it('KeyGen(key_material, key_info) and SkToPk reproduce the published key pair', () => {
    const k = load<{ keyMaterial: string; keyInfo: string; keyDst: string; keyPair: { secretKey: string; publicKey: string } }>('keypair.json');
    const sk = keyGen(h(k.keyMaterial), h(k.keyInfo));
    expect(hx(skToBytes(sk))).toBe(k.keyPair.secretKey);
    expect(hx(skToPk(sk))).toBe(k.keyPair.publicKey);
    expect(dstString(k.keyDst)).toBe('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_KEYGEN_DST_');
  });

  it('hash_to_scalar reproduces the published value', () => {
    const f = load<{ message: string; dst: string; scalar: string }>('h2s.json');
    expect(hx(numberToBytesBE(hashToScalar(h(f.message), dstString(f.dst)), 32))).toBe(f.scalar);
  });

  it('map_message_to_scalar_as_hash reproduces all published message scalars', () => {
    const f = load<{ dst: string; cases: { message: string; scalar: string }[] }>('MapMessageToScalarAsHash.json');
    expect(f.cases.length).toBeGreaterThanOrEqual(10);
    for (const c of f.cases) {
      expect(hx(numberToBytesBE(mapMessageToScalarAsHash(h(c.message)), 32))).toBe(c.scalar);
    }
  });

  it('create_generators reproduces Q1 and all published message generators', () => {
    const f = load<{ P1: string; Q1: string; MsgGenerators: string[] }>('generators.json');
    const gens = createGenerators(f.MsgGenerators.length + 1);
    expect(hx(gens[0]?.toRawBytes(true) ?? new Uint8Array())).toBe(f.Q1);
    f.MsgGenerators.forEach((g, i) => expect(hx(gens[i + 1]?.toRawBytes(true) ?? new Uint8Array())).toBe(g));
  });

  it('the mocked-RNG expand_message output matches the fixture (validates the test harness itself)', () => {
    const f = load<{ seed: string; dst: string; count: number; mockedScalars: string[] }>('mockedRng.json');
    const out = expand_message_xmd(h(f.seed), h(f.dst), f.count * 48, sha256);
    f.mockedScalars.forEach((sc, i) => {
      const v = BigInt('0x' + hx(out.subarray(i * 48, (i + 1) * 48))) % R;
      expect(hx(numberToBytesBE(v, 32))).toBe(sc);
    });
  });
});

describe('draft fixtures: Sign / Verify (10 official cases)', () => {
  for (const f of sigFixtures) {
    it(f.caseName, () => {
      const messages = f.messages.map(h);
      const pk = h(f.signerKeyPair.publicKey);
      const r = verifyDetailed(pk, h(f.signature), h(f.header), messages);
      if (f.result.valid) {
        expect(r).toEqual({ ok: true });
        // Sign is deterministic: it must reproduce the published signature byte-for-byte.
        const sk = BigInt('0x' + f.signerKeyPair.secretKey);
        expect(hx(sign(sk, pk, h(f.header), messages))).toBe(f.signature);
      } else {
        // The published signature is over a DIFFERENT statement: the failure must be the pairing check
        // (the inputs are all well-formed), never a parse error.
        expect(r).toEqual({ ok: false, reason: 'pairing-mismatch' });
      }
    });
  }
});

describe('draft fixtures: ProofGen / ProofVerify (15 official cases)', () => {
  const disclosedOf = (f: ProofFixture): Uint8Array[] =>
    f.disclosedIndexes.map((i) => h(f.messages[i] ?? ''));

  // Where the published failure mode maps onto a stable verifier stage.
  const expectedReason: Record<string, RejectReason> = {
    'different presentation header': 'challenge-mismatch',
    'different header': 'challenge-mismatch',
    'modified messages': 'challenge-mismatch',
    // the published "re-ordered" vector repeats index 4 in the disclosed index list
    're-ordered messages': 'invalid-disclosed-indexes',
    'wrong public key': 'challenge-mismatch',
    'truncated proof, one less undisclosed message': 'challenge-mismatch',
  };

  for (const f of proofFixtures) {
    it(f.caseName, () => {
      const pk = h(f.signerPublicKey);
      const r = proofVerifyDetailed(pk, h(f.proof), h(f.header), h(f.presentationHeader), disclosedOf(f), f.disclosedIndexes);
      if (f.result.valid) {
        expect(r).toEqual({ ok: true });
        const t = f.trace;
        if (t === undefined) throw new Error('valid proof fixtures carry a trace');
        const scalars = [
          t.random_scalars.r1,
          t.random_scalars.r2,
          t.random_scalars.e_tilde,
          t.random_scalars.r1_tilde,
          t.random_scalars.r3_tilde,
          ...t.random_scalars.m_tilde_scalars,
        ].map((x) => BigInt('0x' + x));
        // ProofGen with the published randomness reproduces the published proof byte-for-byte.
        const regen = proofGen(pk, h(f.signature), h(f.header), h(f.presentationHeader), f.messages.map(h), f.disclosedIndexes, scalars);
        expect(hx(regen)).toBe(f.proof);
        expect(hx(numberToBytesBE(BigInt('0x' + hx(h(f.proof).subarray(-32))), 32))).toBe(t.challenge);
      } else {
        expect(r.ok).toBe(false);
        const reason = f.result.reason ?? '';
        const want = expectedReason[reason];
        if (want !== undefined && r.ok === false) expect(r.reason, reason).toBe(want);
        // Every published invalid case is rejected for a verifier-stage reason, never accepted.
        if (r.ok === false) {
          expect(['challenge-mismatch', 'pairing-mismatch', 'invalid-disclosed-indexes', 'malformed-proof', 'disclosed-length-mismatch']).toContain(r.reason);
        }
      }
    });
  }
});

describe('negative cases assert the rejection reason', () => {
  const sig = sigFixtures[3];
  const prf = proofFixtures[2];
  if (sig === undefined || prf === undefined) throw new Error('fixtures missing');
  const pk = h(sig.signerKeyPair.publicKey);
  const header = h(sig.header);
  const msgs = sig.messages.map(h);
  const flip = (b: Uint8Array, i: number): Uint8Array => {
    const c = Uint8Array.from(b);
    c[i] = (c[i] as number) ^ 0x01;
    return c;
  };

  it('truncated / extended signature -> malformed-signature', () => {
    const s = h(sig.signature);
    expect(verifyDetailed(pk, s.subarray(0, 79), header, msgs)).toEqual({ ok: false, reason: 'malformed-signature' });
    expect(verifyDetailed(pk, new Uint8Array([...s, 0]), header, msgs)).toEqual({ ok: false, reason: 'malformed-signature' });
  });
  it('signature scalar e = 0 or >= r -> malformed-signature', () => {
    const s = h(sig.signature);
    const zeroE = Uint8Array.from(s);
    zeroE.fill(0, 48);
    const bigE = Uint8Array.from(s);
    bigE.fill(0xff, 48);
    expect(verifyDetailed(pk, zeroE, header, msgs)).toEqual({ ok: false, reason: 'malformed-signature' });
    expect(verifyDetailed(pk, bigE, header, msgs)).toEqual({ ok: false, reason: 'malformed-signature' });
  });
  it('signature point = identity -> malformed-signature', () => {
    const s = Uint8Array.from(h(sig.signature));
    s.fill(0, 0, 48);
    s[0] = 0xc0; // compressed + infinity flag
    expect(verifyDetailed(pk, s, header, msgs)).toEqual({ ok: false, reason: 'malformed-signature' });
  });
  it('bit-flipped signature -> malformed-signature (off curve) or pairing-mismatch, never ok', () => {
    for (const i of [0, 5, 47, 60, 79]) {
      const r = verifyDetailed(pk, flip(h(sig.signature), i), header, msgs);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(['malformed-signature', 'pairing-mismatch']).toContain(r.reason);
    }
  });
  it('malformed / identity public key -> malformed-public-key', () => {
    expect(verifyDetailed(new Uint8Array(96), h(sig.signature), header, msgs)).toEqual({ ok: false, reason: 'malformed-public-key' });
    const inf = new Uint8Array(96);
    inf[0] = 0xc0;
    expect(verifyDetailed(inf, h(sig.signature), header, msgs)).toEqual({ ok: false, reason: 'malformed-public-key' });
  });
  it('one changed message / different header -> pairing-mismatch', () => {
    const m2 = msgs.map((m, i) => (i === 1 ? new Uint8Array([...m, 0]) : m));
    expect(verifyDetailed(pk, h(sig.signature), header, m2)).toEqual({ ok: false, reason: 'pairing-mismatch' });
    expect(verifyDetailed(pk, h(sig.signature), new Uint8Array([1]), msgs)).toEqual({ ok: false, reason: 'pairing-mismatch' });
  });

  const ppk = h(prf.signerPublicKey);
  const proof = h(prf.proof);
  const ph = h(prf.presentationHeader);
  const dis = prf.disclosedIndexes.map((i) => h(prf.messages[i] ?? ''));
  const pv = (p: Uint8Array, d = dis, ix = prf.disclosedIndexes) =>
    proofVerifyDetailed(ppk, p, h(prf.header), ph, d, ix);

  it('empty / short / ragged proof -> malformed-proof', () => {
    expect(pv(new Uint8Array(0))).toEqual({ ok: false, reason: 'malformed-proof' });
    expect(pv(proof.subarray(0, 100))).toEqual({ ok: false, reason: 'malformed-proof' });
    expect(pv(proof.subarray(0, proof.length - 1))).toEqual({ ok: false, reason: 'malformed-proof' });
  });
  it('proof scalar >= r -> malformed-proof', () => {
    const p = Uint8Array.from(proof);
    p.fill(0xff, 144, 176); // eHat
    expect(pv(p)).toEqual({ ok: false, reason: 'malformed-proof' });
  });
  it('proof with Abar = identity -> malformed-proof', () => {
    const p = Uint8Array.from(proof);
    p.fill(0, 0, 48);
    p[0] = 0xc0;
    expect(pv(p)).toEqual({ ok: false, reason: 'malformed-proof' });
  });
  it('flipping a scalar byte of a valid proof -> challenge-mismatch', () => {
    for (const i of [150, 190, 230, proof.length - 1]) {
      expect(pv(flip(proof, i))).toEqual({ ok: false, reason: 'challenge-mismatch' });
    }
  });
  it('a disclosed message that differs from the proven one -> challenge-mismatch', () => {
    const d2 = dis.map((m, i) => (i === 0 ? new Uint8Array([9, 9]) : m));
    expect(pv(proof, d2)).toEqual({ ok: false, reason: 'challenge-mismatch' });
  });
  it('disclosed message / index count mismatch -> disclosed-length-mismatch', () => {
    expect(pv(proof, dis.slice(1))).toEqual({ ok: false, reason: 'disclosed-length-mismatch' });
  });
  it('out-of-range or duplicate disclosed indexes -> invalid-disclosed-indexes', () => {
    expect(pv(proof, dis, [0, 2, 4, 99])).toEqual({ ok: false, reason: 'invalid-disclosed-indexes' });
    expect(pv(proof, dis, [0, 2, 4, 4])).toEqual({ ok: false, reason: 'invalid-disclosed-indexes' });
    expect(pv(proof, dis, [-1, 2, 4, 6])).toEqual({ ok: false, reason: 'invalid-disclosed-indexes' });
  });
  it('ProofGen refuses the wrong number of fixed random scalars', () => {
    expect(() => proofGen(ppk, h(prf.signature), h(prf.header), ph, prf.messages.map(h), prf.disclosedIndexes, [1n])).toThrow(/expected 11 random scalars, got 1/);
  });
  it('ProofGen rejects an out-of-range disclosed index', () => {
    expect(() => proofGen(ppk, h(prf.signature), h(prf.header), ph, prf.messages.map(h), [10])).toThrow(/out of range/);
  });
});
