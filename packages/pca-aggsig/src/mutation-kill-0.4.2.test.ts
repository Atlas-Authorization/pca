/** 0.4.2 mutation kills: the raw BLS guards answer a strict `false` (never undefined) on every malformed or throwing input. */
import { describe, expect, it } from 'vitest';
import { aggregate, aggregatePublicKeys, aggregateVerify, fastAggregateVerify, isCanonicalSignature, keyGen, popProve, popVerify, sign } from './core';

const te = new TextEncoder();
const G2ZERO = (() => { const o = new Uint8Array(96); o[0] = 0xc0; return o; })();
/** 96 bytes with the compression bit set whose x coordinate is not on the curve (decoding throws). */
const OFF_CURVE = (() => { const o = new Uint8Array(96); o[0] = 0x80; o[95] = 0x05; return o; })();

describe('isCanonicalSignature', () => {
  it('a compressed-looking value that is not a point is exactly false (the decoder throws; the guard answers false)', () => {
    expect(isCanonicalSignature(OFF_CURVE)).toBe(false);
  });
  it('a genuine signature is true; a wrong length, a cleared compression bit and a non-array are false', () => {
    const k = keyGen();
    const sig = sign(k.secretKey, te.encode('m'));
    expect(isCanonicalSignature(sig)).toBe(true);
    expect(isCanonicalSignature(sig.slice(0, 95))).toBe(false);
    const cleared = sig.slice(); cleared[0]! &= 0x7f;
    expect(isCanonicalSignature(cleared)).toBe(false);
    expect(isCanonicalSignature('x')).toBe(false);
  });
});

describe('throwing inputs are a strict false', () => {
  const k = keyGen();
  const msg = te.encode('m');
  const sig = sign(k.secretKey, msg);
  it('aggregateVerify: a message the pairing rejects with an exception', () => {
    expect(aggregateVerify([k.publicKey], ['zz' as never], sig)).toBe(false);
    expect(aggregateVerify([k.publicKey], [msg], OFF_CURVE)).toBe(false);
    expect(aggregateVerify([k.publicKey], [msg], G2ZERO)).toBe(false);
  });
  it('fastAggregateVerify: a message the pairing rejects with an exception', () => {
    expect(fastAggregateVerify([k.publicKey], 'zz' as never, sig)).toBe(false);
    expect(fastAggregateVerify([k.publicKey], msg, OFF_CURVE)).toBe(false);
    expect(fastAggregateVerify([k.publicKey], msg, G2ZERO)).toBe(false);
    expect(fastAggregateVerify([k.publicKey], msg, sig)).toBe(true);
  });
  it('popVerify: the infinity "proof" and an off-curve proof are false, a real one is true', () => {
    expect(popVerify(k.publicKey, G2ZERO)).toBe(false);
    expect(popVerify(k.publicKey, OFF_CURVE)).toBe(false);
    expect(popVerify(k.publicKey, popProve(k.secretKey))).toBe(true);
  });
  it('aggregate helpers stay consistent', () => {
    expect(aggregate([sig]).length).toBe(96);
    expect(aggregatePublicKeys([k.publicKey]).length).toBe(48);
  });
});
