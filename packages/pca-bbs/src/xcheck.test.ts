/**
 * Cross-implementation checks against the independent Rust crate `zkryptium` v0.7.1
 * (Cybersecurity-LINKS; implements draft-irtf-cfrg-bbs-signatures-12 on `bls12_381_plus`), a different
 * codebase and curve implementation from `@noble/curves`.
 *
 *  - Direction 1 (fixture): `test-vectors/zkryptium-0.7.1-corpus.json` was produced by the crate. This
 *    package must derive the same keys, produce the same deterministic signatures byte-for-byte, and
 *    accept every crate-produced (randomized) proof.
 *  - Direction 2 (live, optional): with `PCA_BBS_XCHECK_BIN` pointing at the built `xcheck-zkryptium`
 *    binary, signatures and proofs produced HERE are verified by the crate, and tampered ones rejected.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';
import { keyGen, proofGen, proofVerifyDetailed, sign, skToBytes, skToPk, verifyDetailed } from './bbs';

interface ProofCase {
  disclosedIndexes: number[];
  proof: string;
}
interface Case {
  keyMaterial: string;
  keyInfo: string;
  secretKey: string;
  publicKey: string;
  header: string;
  presentationHeader: string;
  messages: string[];
  signature: string;
  proofs: ProofCase[];
}

const corpus = JSON.parse(
  readFileSync(join(__dirname, '../test-vectors/zkryptium-0.7.1-corpus.json'), 'utf8'),
) as { cases: Case[] };
const h = (s: string): Uint8Array => hexToBytes(s);
const hx = (b: Uint8Array): string => bytesToHex(b);

describe('cross-check vs zkryptium 0.7.1 (draft-12): crate-produced corpus', () => {
  it('covers empty/binary/long/unicode messages and none/some/all disclosure selections', () => {
    expect(corpus.cases.length).toBe(4);
    const sizes = corpus.cases.map((c) => c.messages.length);
    expect(sizes).toEqual([1, 3, 5, 12]);
    const selections = corpus.cases.flatMap((c) => c.proofs.map((p) => p.disclosedIndexes.length));
    expect(selections).toContain(0);
  });

  corpus.cases.forEach((c, i) => {
    it(`case ${i} (${c.messages.length} messages): keys, signature and proofs agree`, () => {
      const sk = keyGen(h(c.keyMaterial), h(c.keyInfo));
      expect(hx(skToBytes(sk))).toBe(c.secretKey);
      const pk = skToPk(sk);
      expect(hx(pk)).toBe(c.publicKey);

      const messages = c.messages.map(h);
      // Sign is deterministic: identical bytes to the independent implementation.
      expect(hx(sign(sk, pk, h(c.header), messages))).toBe(c.signature);
      expect(verifyDetailed(pk, h(c.signature), h(c.header), messages)).toEqual({ ok: true });

      for (const p of c.proofs) {
        const disclosed = p.disclosedIndexes.map((ix) => messages[ix] ?? new Uint8Array());
        expect(
          proofVerifyDetailed(pk, h(p.proof), h(c.header), h(c.presentationHeader), disclosed, p.disclosedIndexes),
          `disclosed ${JSON.stringify(p.disclosedIndexes)}`,
        ).toEqual({ ok: true });
        // negative: wrong presentation header -> challenge mismatch (not a parse error)
        expect(
          proofVerifyDetailed(pk, h(p.proof), h(c.header), new TextEncoder().encode('other'), disclosed, p.disclosedIndexes),
        ).toEqual({ ok: false, reason: 'challenge-mismatch' });
      }
    });
  });
});

const bin = process.env.PCA_BBS_XCHECK_BIN;
describe.skipIf(bin === undefined || bin === '')('cross-check vs zkryptium 0.7.1: live, TS-produced artifacts', () => {
  const te = new TextEncoder();
  const run = (cases: unknown[]): { signature: string; proofs: string[] }[] => {
    const r = spawnSync(bin as string, ['verify'], { input: JSON.stringify({ cases }), encoding: 'utf8' });
    expect(r.status).toBe(0);
    return (JSON.parse(r.stdout) as { results: { signature: string; proofs: string[] }[] }).results;
  };

  function make(n: number, sel: number[]) {
    const sk = keyGen(new Uint8Array(32).fill(n + 1), te.encode(`ts-${n}`));
    const pk = skToPk(sk);
    const header = te.encode('ts header');
    const ph = te.encode('ts presentation');
    const messages = Array.from({ length: n }, (_, i) => te.encode(`message-${i}-${'y'.repeat(i)}`));
    const signature = sign(sk, pk, header, messages);
    const proof = proofGen(pk, signature, header, ph, messages, sel);
    return { sk, pk, header, ph, messages, signature, proof, sel };
  }
  const toCase = (m: ReturnType<typeof make>, proof: Uint8Array = m.proof) => ({
    publicKey: hx(m.pk), header: hx(m.header), presentationHeader: hx(m.ph),
    messages: m.messages.map(hx), signature: hx(m.signature),
    proofs: [{ disclosedIndexes: m.sel, proof: hx(proof) }],
  });

  it('zkryptium accepts signatures and proofs produced here (random proof nonces)', () => {
    const made = [make(1, [0]), make(4, [1, 3]), make(7, []), make(7, [0, 1, 2, 3, 4, 5, 6])];
    const results = run(made.map((m) => toCase(m)));
    for (const r of results) {
      expect(r.signature).toBe('ok');
      expect(r.proofs).toEqual(['ok']);
    }
  });

  it('negative: zkryptium rejects a proof with a flipped byte, and a signature over other messages', () => {
    const m = make(4, [1, 3]);
    const bad = Uint8Array.from(m.proof);
    bad[200] = (bad[200] as number) ^ 1;
    const [r] = run([toCase(m, bad)]);
    expect(r?.signature).toBe('ok');
    expect(r?.proofs[0]).not.toBe('ok');

    const swapped = { ...toCase(m), messages: m.messages.map((x, i) => hx(i === 0 ? te.encode('other') : x)) };
    const [r2] = run([swapped]);
    expect(r2?.signature).not.toBe('ok');
  });
});
