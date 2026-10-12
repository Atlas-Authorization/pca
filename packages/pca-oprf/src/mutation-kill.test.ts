/** Mutation kills for @atlasauth/pca-oprf: exact error messages/labels, mode defaults, bytesEqual, strict UTF-16, POPRF zero tweak. */
import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve';
import { sha512 } from '@noble/hashes/sha512';
import { describe, expect, it } from 'vitest';
import {
  RateWindowCounter, blind, blindEvaluate, blindEvaluatePoprf, blindPoprf, buildRevocationSet, bytesEqual, deriveKeyPair, deserializeElement,
  deserializeScalar, evaluate, evaluatePoprf, finalize, finalizePoprf, isRevokedPrivate, makeRateEvaluator, makeRevocationEvaluator,
  privateRateToken, rateToken, randomKeyPair, serializeScalar,
} from './index';

const te = new TextEncoder();
const err = (f: () => unknown): Error => {
  try { f(); } catch (e) { return e as Error; }
  throw new Error('no throw');
};
const big = new Uint8Array(0x10000);
const LIM = (what: string) => `${what}: 65536 bytes exceeds the 65535-byte limit (RFC 9497 2-byte length framing)`;
const NOTBYTES = (what: string) => `${what}: expected a Uint8Array`;
const kp = randomKeyPair();
const b0 = blind(te.encode('x'));

describe('assertBytes labels and limits', () => {
  it.each([
    ['Blind(input)', (v: never) => blind(v)],
    ['Finalize(input)', (v: never) => finalize(v, b0.blind, b0.blindedElement)],
    ['Evaluate(input)', (v: never) => evaluate(kp.secretKey, v)],
    ['Blind(input)', (v: never) => blindPoprf(v, te.encode('i'), kp.publicKey)],
    ['Evaluate(input)', (v: never) => evaluatePoprf(kp.secretKey, v, te.encode('i'))],
    ['Finalize(input)', (v: never) => finalizePoprf(v, b0.blind, b0.blindedElement, te.encode('i'), { proof: new Uint8Array(64), blindedElement: b0.blindedElement, tweakedKey: b0.blindedElement })],
  ])('%s', (what, f) => {
    expect(err(() => f('x' as never)).message).toBe(NOTBYTES(what));
    expect(err(() => f('x' as never))).toBeInstanceOf(TypeError);
    const e = err(() => f(big as never));
    expect(e.message).toBe(LIM(what));
    expect(e).toBeInstanceOf(RangeError);
    expect(() => f(new Uint8Array(0xffff) as never)).not.toThrow(LIM(what));
  });
  it('info is labelled and bounded (blindPoprf, finalizePoprf, evaluatePoprf, blindEvaluatePoprf)', () => {
    for (const f of [
      (i: never) => blindPoprf(te.encode('a'), i, kp.publicKey),
      (i: never) => evaluatePoprf(kp.secretKey, te.encode('a'), i),
      (i: never) => blindEvaluatePoprf(kp.secretKey, b0.blindedElement, i),
      (i: never) => finalizePoprf(te.encode('a'), b0.blind, b0.blindedElement, i, { proof: new Uint8Array(64), blindedElement: b0.blindedElement, tweakedKey: b0.blindedElement }),
    ]) {
      expect(err(() => f('x' as never)).message).toBe(NOTBYTES('info'));
      expect(err(() => f(big as never)).message).toBe(LIM('info'));
    }
  });
  it('Deserialize labels', () => {
    expect(err(() => deserializeElement('x' as never)).message).toBe(NOTBYTES('DeserializeElement'));
    expect(err(() => deserializeScalar('x' as never)).message).toBe(NOTBYTES('DeserializeScalar'));
  });
});

describe('modes and guards', () => {
  it('scalarInvert refuses zero (finalize with a zero blind)', () => {
    const zero = serializeScalar(0n);
    expect(err(() => finalize(te.encode('x'), zero, b0.blindedElement)).message).toBe('scalarInvert: inverse of zero');
    expect(err(() => finalizePoprf(te.encode('x'), zero, b0.blindedElement, te.encode('i'), { proof: new Uint8Array(64), blindedElement: b0.blindedElement, tweakedKey: b0.blindedElement })).message).not.toBe('');
  });
  it('blind and blindEvaluate default to plain OPRF (no proof) and finalize default round-trips', () => {
    const r = blindEvaluate(kp.secretKey, b0.blindedElement);
    expect(r.proof).toBeUndefined();
    expect(Buffer.from(finalize(te.encode('x'), b0.blind, r.evaluatedElement)).toString('hex')).toBe(Buffer.from(evaluate(kp.secretKey, te.encode('x'))).toString('hex'));
    // the default mode of blind() is the 'oprf' domain, not voprf
    const v = blind(te.encode('x'), 'voprf', b0.blind);
    expect(Buffer.from(v.blindedElement).toString('hex')).not.toBe(Buffer.from(b0.blindedElement).toString('hex'));
    expect(Buffer.from(blind(te.encode('x'), 'oprf', b0.blind).blindedElement).toString('hex')).toBe(Buffer.from(b0.blindedElement).toString('hex'));
  });
  it('voprf finalize requires proof, publicKey and blindedElement, each individually', () => {
    const b = blind(te.encode('x'), 'voprf');
    const r = blindEvaluate(kp.secretKey, b.blindedElement, 'voprf', kp.publicKey);
    const full = { proof: r.proof!, publicKey: kp.publicKey, blindedElement: b.blindedElement };
    expect(() => finalize(te.encode('x'), b.blind, r.evaluatedElement, 'voprf', full)).not.toThrow();
    for (const drop of ['proof', 'publicKey', 'blindedElement'] as const) {
      const o = { ...full } as Record<string, unknown>;
      delete o[drop];
      expect(err(() => finalize(te.encode('x'), b.blind, r.evaluatedElement, 'voprf', o as never)).message).toBe('Finalize(voprf): proof, publicKey and blindedElement are required');
    }
    expect(err(() => finalize(te.encode('x'), b.blind, r.evaluatedElement, 'voprf')).message).toBe('Finalize(voprf): proof, publicKey and blindedElement are required');
  });
  it('POPRF refuses a key that cancels the info tweak (t = 0)', () => {
    const info = te.encode('window-1');
    const ctx = Buffer.concat([te.encode('OPRFV1-'), Buffer.from([2]), te.encode('-ristretto255-SHA512')]);
    const dst = Buffer.concat([te.encode('HashToScalar-'), ctx]);
    const framed = Buffer.concat([te.encode('Info'), Buffer.from([0, info.length]), info]);
    const u = expand_message_xmd(framed, dst, 64, sha512);
    let n = 0n;
    for (let i = u.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(u[i]!);
    const ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;
    const sk = serializeScalar(ORDER - (n % ORDER));
    expect(err(() => evaluatePoprf(sk, te.encode('x'), info)).message).toBe('Evaluate(poprf): inverse of zero (bad info/key)');
    expect(err(() => blindEvaluatePoprf(sk, b0.blindedElement, info)).message).toBe('BlindEvaluate(poprf): inverse of zero (bad info/key)');
  });
  it('bytesEqual', () => {
    const a = Uint8Array.of(1, 2, 3);
    expect(bytesEqual(a, Uint8Array.of(1, 2, 3))).toBe(true);
    expect(bytesEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
    expect(bytesEqual(a, Uint8Array.of(1, 2, 4))).toBe(false);
    expect(bytesEqual(a, Uint8Array.of(0, 2, 3))).toBe(false);
    expect(bytesEqual(a, Uint8Array.of(1, 2))).toBe(false);
    expect(bytesEqual(Uint8Array.of(1, 2), a)).toBe(false);
    expect(bytesEqual(Uint8Array.of(1, 2, 0), Uint8Array.of(1, 2))).toBe(false);
    expect(bytesEqual(Uint8Array.of(0, 0), Uint8Array.of(0, 1))).toBe(false);
    expect(bytesEqual(Uint8Array.of(1, 1), Uint8Array.of(1, 1))).toBe(true);
    expect(bytesEqual(Uint8Array.of(5), Uint8Array.of(5, 0, 0, 0))).toBe(false);
  });
  it('deriveKeyPair needs an exactly 32-byte seed', () => {
    expect(() => deriveKeyPair(new Uint8Array(32), new Uint8Array(0), 'oprf')).not.toThrow();
    expect(err(() => deriveKeyPair(new Uint8Array(31), new Uint8Array(0), 'oprf')).message).toBe('DeriveKeyPair: seed must be exactly 32 bytes');
  });
});

describe('PCA layer', () => {
  it('strict UTF-16: only well-formed strings; exact messages and labels', () => {
    const ok = ['', 'a', '', '𐀀', '􏿿', 'x😀y', '￿'];
    for (const s of ok) expect(() => rateToken(kp.secretKey, s, 'w')).not.toThrow();
    const bad = ['\ud800', 'a\ud800', '\ud800a', '\ud800', '\udbff', '\udc00', '\udfff', 'a\udc00b', '\ud800\ud800'];
    for (const s of bad) {
      const e = err(() => rateToken(kp.secretKey, s, 'w'));
      expect(e).toBeInstanceOf(RangeError);
      expect(e.message).toBe('identifier contains an unpaired surrogate (ill-formed UTF-16)');
    }
    expect(err(() => rateToken(kp.secretKey, 'a', '\udc00')).message).toBe('window contains an unpaired surrogate (ill-formed UTF-16)');
    expect(err(() => rateToken(kp.secretKey, 5 as never, 'w'))).toBeInstanceOf(TypeError);
    expect(err(() => rateToken(kp.secretKey, 5 as never, 'w')).message).toBe('identifier must be a string');
    expect(err(() => rateToken(kp.secretKey, 'a', 5 as never)).message).toBe('window must be a string');
    expect(err(() => buildRevocationSet(kp.secretKey, [5 as never])).message).toBe('capability id must be a string');
    expect(err(() => buildRevocationSet(kp.secretKey, ['\ud800'])).message).toBe('capability id contains an unpaired surrogate (ill-formed UTF-16)');
    const set = buildRevocationSet(kp.secretKey, ['c1']);
    expect(err(() => isRevokedPrivate(5 as never, { blindEval: makeRevocationEvaluator(kp.secretKey), revokedSet: set })).message).toBe('capability id must be a string');
    expect(err(() => makeRateEvaluator(kp.secretKey)(b0.blindedElement, 5 as never)).message).toBe('window must be a string');
    const pe = makeRateEvaluator(kp.secretKey);
    expect(err(() => privateRateToken(5 as never, 'w', { blindEval: pe, publicKey: kp.publicKey })).message).toBe('identifier must be a string');
    expect(err(() => privateRateToken('a', 5 as never, { blindEval: pe, publicKey: kp.publicKey })).message).toBe('window must be a string');
  });
  it('revocation set carries a public key only in voprf mode; evaluator defaults to oprf', () => {
    expect(buildRevocationSet(kp.secretKey, ['a']).publicKey).toBeUndefined();
    expect(buildRevocationSet(kp.secretKey, ['a']).mode).toBe('oprf');
    expect(buildRevocationSet(kp.secretKey, ['a'], 'voprf').publicKey).toStrictEqual(kp.publicKey);
    expect(makeRevocationEvaluator(kp.secretKey)(b0.blindedElement).proof).toBeUndefined();
    const vs = buildRevocationSet(kp.secretKey, ['a', 'b'], 'voprf');
    const ev = makeRevocationEvaluator(kp.secretKey, 'voprf');
    expect(ev(blind(te.encode('q'), 'voprf').blindedElement).proof).toBeDefined();
    expect(isRevokedPrivate('a', { blindEval: ev, revokedSet: vs })).toBe(true);
    expect(isRevokedPrivate('zz', { blindEval: ev, revokedSet: vs })).toBe(false);
    const os = buildRevocationSet(kp.secretKey, ['a']);
    expect(isRevokedPrivate('a', { blindEval: makeRevocationEvaluator(kp.secretKey), revokedSet: os })).toBe(true);
    expect(isRevokedPrivate('b', { blindEval: makeRevocationEvaluator(kp.secretKey), revokedSet: os })).toBe(false);
  });
  it('RateWindowCounter accepts limit 1 and rejects 0 / non-integers', () => {
    expect(() => new RateWindowCounter(1)).not.toThrow();
    for (const l of [0, -1, 1.5, NaN]) expect(err(() => new RateWindowCounter(l)).message).toBe('RateWindowCounter: limit must be a positive integer');
    const c = new RateWindowCounter(1);
    expect(c.hit(Uint8Array.of(1))).toEqual({ count: 1, allowed: true });
    expect(c.hit(Uint8Array.of(1))).toEqual({ count: 2, allowed: false });
  });
});
