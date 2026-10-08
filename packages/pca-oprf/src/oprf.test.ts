import { describe, expect, it } from 'vitest';
import { hexToBytes } from '@noble/curves/abstract/utils';
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
  publicKeyFor,
  randomKeyPair,
  toHex,
} from './oprf';

const te = new TextEncoder();

describe('OPRF (base, mode 0x00) — RFC 9497 ristretto255-SHA512', () => {
  it('blind → blindEvaluate → finalize equals the server direct evaluate(sk, input)', () => {
    const { secretKey } = randomKeyPair();
    for (const msg of ['', 'cap_abc', 'a longer capability identifier string']) {
      const input = te.encode(msg);
      const b = blind(input, 'oprf');
      const res = blindEvaluate(secretKey, b.blindedElement, 'oprf');
      const out = finalize(input, b.blind, res.evaluatedElement, 'oprf');
      const direct = evaluate(secretKey, input, 'oprf');
      expect(toHex(out)).toBe(toHex(direct));
      expect(out.length).toBe(64);
    }
  });

  it('different inputs yield different outputs; same input is stable', () => {
    const { secretKey } = randomKeyPair();
    const a = toHex(evaluate(secretKey, te.encode('x'), 'oprf'));
    const a2 = toHex(evaluate(secretKey, te.encode('x'), 'oprf'));
    const b = toHex(evaluate(secretKey, te.encode('y'), 'oprf'));
    expect(a).toBe(a2);
    expect(a).not.toBe(b);
  });

  it('a wrong key produces a different output (so membership is key-bound)', () => {
    const k1 = randomKeyPair();
    const k2 = randomKeyPair();
    const input = te.encode('cap_abc');
    expect(toHex(evaluate(k1.secretKey, input, 'oprf'))).not.toBe(
      toHex(evaluate(k2.secretKey, input, 'oprf')),
    );
  });
});

describe('VOPRF (verifiable, mode 0x01)', () => {
  it('a valid DLEQ proof verifies and finalize matches evaluate', () => {
    const { secretKey, publicKey } = randomKeyPair();
    const input = te.encode('cap_verifiable');
    const b = blind(input, 'voprf');
    const res = blindEvaluate(secretKey, b.blindedElement, 'voprf', publicKey);
    expect(res.proof).toBeDefined();
    const out = finalize(input, b.blind, res.evaluatedElement, 'voprf', {
      proof: res.proof ?? new Uint8Array(),
      publicKey,
      blindedElement: b.blindedElement,
    });
    expect(toHex(out)).toBe(toHex(evaluate(secretKey, input, 'voprf')));
  });

  it('rejects a forged / tampered proof', () => {
    const { secretKey, publicKey } = randomKeyPair();
    const input = te.encode('cap_verifiable');
    const b = blind(input, 'voprf');
    const res = blindEvaluate(secretKey, b.blindedElement, 'voprf', publicKey);
    const proof = res.proof ?? new Uint8Array();
    const forged = Uint8Array.from(proof);
    forged[0] = forged[0] === 1 ? 2 : 1; // flip a byte of the challenge scalar
    expect(() =>
      finalize(input, b.blind, res.evaluatedElement, 'voprf', {
        proof: forged,
        publicKey,
        blindedElement: b.blindedElement,
      }),
    ).toThrow(/proof verification failed/);
  });

  it('rejects a proof made under the wrong key (wrong public key)', () => {
    const server = randomKeyPair();
    const attacker = randomKeyPair();
    const input = te.encode('cap_verifiable');
    const b = blind(input, 'voprf');
    // Server evaluates with its real key but advertises the attacker's public key.
    const res = blindEvaluate(server.secretKey, b.blindedElement, 'voprf', server.publicKey);
    expect(() =>
      finalize(input, b.blind, res.evaluatedElement, 'voprf', {
        proof: res.proof ?? new Uint8Array(),
        publicKey: attacker.publicKey,
        blindedElement: b.blindedElement,
      }),
    ).toThrow(/proof verification failed/);
  });
});

describe('POPRF (partially oblivious, mode 0x02)', () => {
  it('blind → blindEvaluate → finalize equals evaluate(sk, input, info); proof binds info', () => {
    const { secretKey, publicKey } = randomKeyPair();
    const input = te.encode('user-42');
    const info = te.encode('2026-10-08T12');
    const b = blindPoprf(input, info, publicKey);
    const res = blindEvaluatePoprf(secretKey, b.blindedElement, info);
    expect(res.proof).toBeDefined();
    const out = finalizePoprf(input, b.blind, res.evaluatedElement, info, {
      proof: res.proof ?? new Uint8Array(),
      blindedElement: b.blindedElement,
      tweakedKey: b.tweakedKey,
    });
    expect(toHex(out)).toBe(toHex(evaluatePoprf(secretKey, input, info)));
  });

  it('different info (window) yields a different, unlinkable output for the same input', () => {
    const { secretKey } = randomKeyPair();
    const input = te.encode('user-42');
    const a = toHex(evaluatePoprf(secretKey, input, te.encode('w1')));
    const b = toHex(evaluatePoprf(secretKey, input, te.encode('w2')));
    expect(a).not.toBe(b);
  });

  it('rejects a POPRF proof forged for the wrong info', () => {
    const { secretKey, publicKey } = randomKeyPair();
    const input = te.encode('user-42');
    const realInfo = te.encode('w1');
    const b = blindPoprf(input, realInfo, publicKey);
    const res = blindEvaluatePoprf(secretKey, b.blindedElement, realInfo);
    // Client believes the window is "w2": its tweakedKey/info won't match the proof.
    const wrong = blindPoprf(input, te.encode('w2'), publicKey);
    expect(() =>
      finalizePoprf(input, b.blind, res.evaluatedElement, te.encode('w2'), {
        proof: res.proof ?? new Uint8Array(),
        blindedElement: b.blindedElement,
        tweakedKey: wrong.tweakedKey,
      }),
    ).toThrow(/proof verification failed/);
  });
});

describe('RFC 9497 Appendix A.1.1 test vector (OPRF ristretto255-SHA512, base)', () => {
  const seed = hexToBytes('a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3');
  const keyInfo = hexToBytes('74657374206b6579'); // "test key"
  const skSm = '5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e';

  it('DeriveKeyPair reproduces the RFC secret key', () => {
    const kp = deriveKeyPair(seed, keyInfo, 'oprf');
    expect(toHex(kp.secretKey)).toBe(skSm);
    // sanity: the derived public key is consistent with the secret
    expect(toHex(kp.publicKey)).toBe(toHex(publicKeyFor(kp.secretKey)));
  });

  it('reproduces BlindedElement, EvaluationElement and Output for Input=00', () => {
    const kp = deriveKeyPair(seed, keyInfo, 'oprf');
    const input = hexToBytes('00');
    const fixedBlind = hexToBytes('64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706');
    const b = blind(input, 'oprf', fixedBlind);
    expect(toHex(b.blindedElement)).toBe(
      '609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c',
    );
    const res = blindEvaluate(kp.secretKey, b.blindedElement, 'oprf');
    expect(toHex(res.evaluatedElement)).toBe(
      '7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e',
    );
    const out = finalize(input, b.blind, res.evaluatedElement, 'oprf');
    expect(toHex(out)).toBe(
      '527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6',
    );
  });
});
