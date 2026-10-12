/**
 * Official RFC 9497 Appendix A.1 (ristretto255-SHA512) test vectors, loaded from
 * `test-vectors/rfc9497-ristretto255-sha512.json` (provenance recorded in that file).
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bytesToNumberLE, hexToBytes, numberToBytesLE } from '@noble/curves/abstract/utils';
import {
  blind,
  blindEvaluate,
  blindEvaluatePoprf,
  blindPoprf,
  deriveKeyPair,
  evaluate,
  evaluatePoprf,
  finalize,
  finalizePoprf,
  hashToGroup,
  deserializeElement,
  deserializeScalar,
  serializeElement,
  serializeScalar,
  toHex,
} from './oprf';

interface Provenance {
  url: string;
  sourceSha256: string;
  retrievedOn: string;
}
interface KeyBlock {
  Seed: string;
  KeyInfo: string;
  skSm: string;
  pkSm?: string;
}
interface Vec {
  mode: 'OPRF' | 'VOPRF' | 'POPRF';
  n: number;
  batch: number;
  Input: string;
  Info?: string;
  Blind: string;
  BlindedElement: string;
  EvaluationElement: string;
  Proof?: string;
  ProofRandomScalar?: string;
  Output: string;
}
interface Fixture {
  provenance: Provenance;
  modes: Record<'OPRF' | 'VOPRF' | 'POPRF', KeyBlock>;
  vectors: Vec[];
}

const fixture = JSON.parse(
  readFileSync(join(__dirname, '../test-vectors/rfc9497-ristretto255-sha512.json'), 'utf8'),
) as Fixture;

const h = (s: string): Uint8Array => hexToBytes(s);
const split = (s: string): string[] => s.split(',');

function expectThrowsWith(fn: () => unknown, reason: RegExp): void {
  let err: unknown;
  try {
    fn();
  } catch (e) {
    err = e;
  }
  expect(err).toBeInstanceOf(Error);
  expect((err as Error).message).toMatch(reason);
}

describe('RFC 9497 Appendix A.1 fixture provenance', () => {
  it('records its source and has all 8 vectors across the 3 modes', () => {
    expect(fixture.provenance.url).toBe('https://www.rfc-editor.org/rfc/rfc9497.txt');
    expect(fixture.provenance.sourceSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(fixture.vectors.map((v) => `${v.mode}:${v.n}`)).toEqual([
      'OPRF:1', 'OPRF:2', 'VOPRF:1', 'VOPRF:2', 'VOPRF:3', 'POPRF:1', 'POPRF:2', 'POPRF:3',
    ]);
  });
});

describe('RFC 9497 A.1 DeriveKeyPair', () => {
  for (const mode of ['OPRF', 'VOPRF', 'POPRF'] as const) {
    it(`${mode}: seed + info derive the published skSm (and pkSm)`, () => {
      const k = fixture.modes[mode];
      const kp = deriveKeyPair(h(k.Seed), h(k.KeyInfo), mode.toLowerCase() as 'oprf' | 'voprf' | 'poprf');
      expect(toHex(kp.secretKey)).toBe(k.skSm);
      if (k.pkSm !== undefined) expect(toHex(kp.publicKey)).toBe(k.pkSm);
    });
  }

  it('a different mode derives a different key (mode is domain-separated)', () => {
    const k = fixture.modes.OPRF;
    const kp = deriveKeyPair(h(k.Seed), h(k.KeyInfo), 'voprf');
    expect(toHex(kp.secretKey)).not.toBe(k.skSm);
  });
});

describe('RFC 9497 A.1 OPRF (mode 0x00) vectors', () => {
  for (const v of fixture.vectors.filter((x) => x.mode === 'OPRF')) {
    it(`vector ${v.n} (batch ${v.batch})`, () => {
      const sk = h(fixture.modes.OPRF.skSm);
      const inputs = split(v.Input);
      const blinds = split(v.Blind);
      const blinded = split(v.BlindedElement);
      const evald = split(v.EvaluationElement);
      const outs = split(v.Output);
      inputs.forEach((inp, i) => {
        const b = blind(h(inp), 'oprf', h(blinds[i] as string));
        expect(toHex(b.blindedElement)).toBe(blinded[i]);
        const e = blindEvaluate(sk, h(blinded[i] as string), 'oprf');
        expect(toHex(e.evaluatedElement)).toBe(evald[i]);
        expect(toHex(finalize(h(inp), b.blind, h(evald[i] as string), 'oprf'))).toBe(outs[i]);
        expect(toHex(evaluate(sk, h(inp), 'oprf'))).toBe(outs[i]);
      });
    });
  }
});

describe('RFC 9497 A.1 VOPRF (mode 0x01) vectors', () => {
  const pk = h(fixture.modes.VOPRF.pkSm as string);
  const sk = h(fixture.modes.VOPRF.skSm);
  for (const v of fixture.vectors.filter((x) => x.mode === 'VOPRF')) {
    it(`vector ${v.n} (batch ${v.batch})`, () => {
      const inputs = split(v.Input);
      const blinds = split(v.Blind);
      const blinded = split(v.BlindedElement);
      const evald = split(v.EvaluationElement);
      const outs = split(v.Output);
      inputs.forEach((inp, i) => {
        const b = blind(h(inp), 'voprf', h(blinds[i] as string));
        expect(toHex(b.blindedElement)).toBe(blinded[i]);
        const e = blindEvaluate(sk, h(blinded[i] as string), 'voprf', pk);
        expect(toHex(e.evaluatedElement)).toBe(evald[i]);
        expect(toHex(evaluate(sk, h(inp), 'voprf'))).toBe(outs[i]);
        if (v.batch === 1) {
          // Single-element batch: the proof is reproducible byte-for-byte with the published nonce...
          const fixed = blindEvaluate(sk, h(blinded[i] as string), 'voprf', pk, h(v.ProofRandomScalar as string));
          expect(toHex(fixed.proof as Uint8Array)).toBe(v.Proof);
          // ...and the published proof verifies and finalizes to the published output.
          const out = finalize(h(inp), b.blind, h(evald[i] as string), 'voprf', {
            proof: h(v.Proof as string),
            publicKey: pk,
            blindedElement: h(blinded[i] as string),
          });
          expect(toHex(out)).toBe(outs[i]);
        }
      });
    });
  }

  const v1 = fixture.vectors.find((x) => x.mode === 'VOPRF' && x.n === 1) as Vec;
  const base = {
    proof: h(v1.Proof as string),
    publicKey: pk,
    blindedElement: h(v1.BlindedElement),
  };
  const run = (o: typeof base): Uint8Array =>
    finalize(h(v1.Input), h(v1.Blind), h(v1.EvaluationElement), 'voprf', o);

  it('negative: a flipped bit in the proof is rejected as a DLEQ failure', () => {
    for (const idx of [0, 31, 32, 63]) {
      const bad = Uint8Array.from(base.proof);
      bad[idx] = (bad[idx] as number) ^ 0x01;
      expectThrowsWith(() => run({ ...base, proof: bad }), /DLEQ proof verification failed|expected 32 bytes/);
    }
  });
  it('negative: a proof from a different vector is rejected', () => {
    const v2 = fixture.vectors.find((x) => x.mode === 'VOPRF' && x.n === 2) as Vec;
    expectThrowsWith(() => run({ ...base, proof: h(v2.Proof as string) }), /DLEQ proof verification failed/);
  });
  it('negative: the wrong public key is rejected', () => {
    const wrongPk = h(fixture.modes.POPRF.pkSm as string);
    expectThrowsWith(() => run({ ...base, publicKey: wrongPk }), /DLEQ proof verification failed/);
  });
  it('negative: a tampered evaluated element is rejected', () => {
    const v2 = fixture.vectors.find((x) => x.mode === 'VOPRF' && x.n === 2) as Vec;
    expectThrowsWith(
      () => finalize(h(v1.Input), h(v1.Blind), h(v2.EvaluationElement), 'voprf', base),
      /DLEQ proof verification failed/,
    );
  });
  it('negative: a truncated proof is rejected', () => {
    expectThrowsWith(() => run({ ...base, proof: base.proof.subarray(0, 63) }), /DLEQ proof verification failed/);
  });
  it('negative: missing verification inputs fail closed', () => {
    expectThrowsWith(
      () => finalize(h(v1.Input), h(v1.Blind), h(v1.EvaluationElement), 'voprf'),
      /proof, publicKey and blindedElement are required/,
    );
  });
});

describe('RFC 9497 A.1 POPRF (mode 0x02) vectors', () => {
  const pk = h(fixture.modes.POPRF.pkSm as string);
  const sk = h(fixture.modes.POPRF.skSm);
  for (const v of fixture.vectors.filter((x) => x.mode === 'POPRF')) {
    it(`vector ${v.n} (batch ${v.batch})`, () => {
      const info = h(v.Info as string);
      const inputs = split(v.Input);
      const blinds = split(v.Blind);
      const blinded = split(v.BlindedElement);
      const evald = split(v.EvaluationElement);
      const outs = split(v.Output);
      inputs.forEach((inp, i) => {
        const b = blindPoprf(h(inp), info, pk, h(blinds[i] as string));
        expect(toHex(b.blindedElement)).toBe(blinded[i]);
        const e = blindEvaluatePoprf(sk, h(blinded[i] as string), info);
        expect(toHex(e.evaluatedElement)).toBe(evald[i]);
        expect(toHex(evaluatePoprf(sk, h(inp), info))).toBe(outs[i]);
        if (v.batch === 1) {
          const fixed = blindEvaluatePoprf(sk, h(blinded[i] as string), info, h(v.ProofRandomScalar as string));
          expect(toHex(fixed.proof as Uint8Array)).toBe(v.Proof);
          const out = finalizePoprf(h(inp), b.blind, h(evald[i] as string), info, {
            proof: h(v.Proof as string),
            blindedElement: h(blinded[i] as string),
            tweakedKey: b.tweakedKey,
          });
          expect(toHex(out)).toBe(outs[i]);
        }
      });
    });
  }

  const v1 = fixture.vectors.find((x) => x.mode === 'POPRF' && x.n === 1) as Vec;
  const b1 = blindPoprf(h(v1.Input), h(v1.Info as string), pk, h(v1.Blind));
  const good = (info: Uint8Array, proof: Uint8Array): Uint8Array =>
    finalizePoprf(h(v1.Input), h(v1.Blind), h(v1.EvaluationElement), info, {
      proof,
      blindedElement: h(v1.BlindedElement),
      tweakedKey: b1.tweakedKey,
    });

  it('negative: a different public info makes the proof fail (info is bound into the tweaked key)', () => {
    const wrong = blindPoprf(h(v1.Input), h('00'), pk, h(v1.Blind));
    expectThrowsWith(
      () =>
        finalizePoprf(h(v1.Input), h(v1.Blind), h(v1.EvaluationElement), h('00'), {
          proof: h(v1.Proof as string),
          blindedElement: h(v1.BlindedElement),
          tweakedKey: wrong.tweakedKey,
        }),
      /DLEQ proof verification failed/,
    );
  });
  it('negative: a flipped proof bit is rejected', () => {
    const bad = h(v1.Proof as string);
    bad[10] = (bad[10] as number) ^ 0x80;
    expectThrowsWith(() => good(h(v1.Info as string), bad), /DLEQ proof verification failed/);
  });
  it('negative: info is bound into the output (same proof, different info, different tweaked key)', () => {
    const o1 = toHex(evaluatePoprf(sk, h(v1.Input), h('7465737420696e666f')));
    const o2 = toHex(evaluatePoprf(sk, h(v1.Input), h('7465737420696e666e')));
    expect(o1).toBe(v1.Output);
    expect(o2).not.toBe(o1);
  });
});

describe('RFC 9497 A.1 encodings and group edge cases', () => {
  it('HashToGroup output re-serializes canonically', () => {
    const p = hashToGroup(h('00'), 'oprf');
    expect(toHex(serializeElement(deserializeElement(serializeElement(p))))).toBe(toHex(serializeElement(p)));
  });
  it('rejects the identity element (all-zero encoding)', () => {
    expectThrowsWith(() => deserializeElement(new Uint8Array(32)), /identity element/);
  });
  it('rejects a non-canonical ristretto255 encoding (value >= p)', () => {
    const nonCanon = h('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f');
    expect(() => deserializeElement(nonCanon)).toThrow();
  });
  it('rejects an element with the low (sign) bit set - negative field element', () => {
    // 0x01 00..00 is a negative (odd) field element and so is not a valid ristretto255 encoding
    const odd = new Uint8Array(32);
    odd[0] = 1;
    expect(() => deserializeElement(odd)).toThrow();
  });
  it('rejects a wrong-length element', () => {
    expect(() => deserializeElement(new Uint8Array(31))).toThrow();
  });
  it('rejects a wrong-length scalar', () => {
    expectThrowsWith(() => deserializeScalar(new Uint8Array(31)), /expected 32 bytes, got 31/);
  });
  it('rejects a non-canonical scalar (value >= group order), so a proof scalar cannot be malleated by +L', () => {
    const L = 2n ** 252n + 27742317777372353535851937790883648493n;
    expectThrowsWith(() => deserializeScalar(numberToBytesLE(L, 32)), /non-canonical scalar/);
    expectThrowsWith(() => deserializeScalar(new Uint8Array(32).fill(0xff)), /non-canonical scalar/);
    expect(deserializeScalar(numberToBytesLE(L - 1n, 32))).toBe(L - 1n);
  });
  it('negative: a published proof with s replaced by s+L is rejected, not accepted as a malleated twin', () => {
    const L = 2n ** 252n + 27742317777372353535851937790883648493n;
    const v1 = fixture.vectors.find((x) => x.mode === 'VOPRF' && x.n === 1) as Vec;
    const proof = h(v1.Proof as string);
    const sPlusL = bytesToNumberLE(proof.subarray(32)) + L;
    if (sPlusL >= 2n ** 256n) throw new Error('fixture assumption: s + L fits in 32 bytes');
    const mall = new Uint8Array(64);
    mall.set(proof.subarray(0, 32), 0);
    mall.set(numberToBytesLE(sPlusL, 32), 32);
    expectThrowsWith(
      () =>
        finalize(h(v1.Input), h(v1.Blind), h(v1.EvaluationElement), 'voprf', {
          proof: mall,
          publicKey: h(fixture.modes.VOPRF.pkSm as string),
          blindedElement: h(v1.BlindedElement),
        }),
      /non-canonical scalar/,
    );
  });
  it('a scalar is encoded little-endian and reduced mod the group order', () => {
    expect(toHex(serializeScalar(1n))).toBe('01' + '00'.repeat(31));
    expect(toHex(serializeScalar(0n))).toBe('00'.repeat(32));
  });
});
