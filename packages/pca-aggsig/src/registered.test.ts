/**
 * Rogue-key safety is structural: the public aggregate verifiers accept ONLY `RegisteredKey`s, and a
 * `RegisteredKey` can only come from a verified proof of possession.
 */
import { bls12_381 } from '@noble/curves/bls12-381';
import { describe, expect, it } from 'vitest';
import * as pub from './index';
import {
  KeyRegistry,
  RegisteredKey,
  aggregate,
  aggregateVerify,
  checkRegistered,
  fastAggregateVerify,
  keyGen,
  popProve,
  registerKey,
  sign,
} from './bls';
import { POP_DST, fastAggregateVerify as rawFastAggregateVerify } from './core';

const G1 = bls12_381.G1.ProjectivePoint;
const msg = new TextEncoder().encode('statement');

function reg(k: { publicKey: Uint8Array; secretKey: Uint8Array }): RegisteredKey {
  const r = registerKey(k.publicKey, popProve(k.secretKey));
  if (!r.ok) throw new Error(r.reason);
  return r.key;
}

/** The classic rogue-key construction: pk_adv = g^x - sum(honest), then sig = sign_x(msg). */
function rogue(honest: Uint8Array[]) {
  const x = bls12_381.utils.randomPrivateKey();
  const sum = honest.map((h) => G1.fromHex(h)).reduce((a, b) => a.add(b));
  const pkAdv = G1.fromPrivateKey(x).subtract(sum).toRawBytes(true);
  return { x, pkAdv, forged: sign(x, msg) };
}

describe('registered keys', () => {
  it('the package index exposes no raw-key aggregate surface', () => {
    expect('aggregatePublicKeys' in pub).toBe(false);
    expect('popVerify' in pub).toBe(false);
    expect('RegisteredKey' in pub && 'registerKey' in pub && 'KeyRegistry' in pub).toBe(true);
  });

  it('honest keys with a PoP register and aggregate-verify', () => {
    const ks = [keyGen(), keyGen(), keyGen()];
    const rks = ks.map(reg);
    const agg = aggregate(ks.map((k) => sign(k.secretKey, msg)));
    expect(fastAggregateVerify(rks, msg, agg)).toBe(true);
    const ms = [new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3])];
    expect(aggregateVerify(rks, ms, aggregate(ks.map((k, i) => sign(k.secretKey, ms[i] as Uint8Array))))).toBe(true);
  });

  it('a RegisteredKey cannot be constructed directly', () => {
    const k = keyGen();
    expect(() => new (RegisteredKey as unknown as new (...a: unknown[]) => RegisteredKey)(Symbol('x'), k.publicKey)).toThrow();
    expect(() => new (RegisteredKey as unknown as new (...a: unknown[]) => RegisteredKey)()).toThrow();
  });

  it('registerKey refuses a missing, wrong, replayed or message-signature PoP with a reason', () => {
    const a = keyGen();
    const b = keyGen();
    expect(registerKey(a.publicKey, popProve(b.secretKey))).toMatchObject({ ok: false, reason: expect.stringContaining('proof of possession') });
    expect(registerKey(a.publicKey, sign(a.secretKey, a.publicKey))).toMatchObject({ ok: false }); // signature DST, not PoP DST
    expect(registerKey(a.publicKey, new Uint8Array(96))).toMatchObject({ ok: false });
    expect(registerKey(new Uint8Array(48), popProve(a.secretKey))).toMatchObject({ ok: false, reason: expect.stringContaining('KeyValidate') });
  });

  it('ROGUE-KEY ATTACK: pk_adv = g^x - sum(honest) cannot be registered, so it cannot reach the public verifiers', () => {
    const honest = [keyGen(), keyGen()];
    const { x, pkAdv, forged } = rogue(honest.map((h) => h.publicKey));
    // The attacker's best PoP candidates: a PoP-DST signature of pk_adv under x (it is NOT the dlog of pk_adv),
    // the forged aggregate signature itself, and each honest party's own PoP.
    const candidates = [
      bls12_381.sign(pkAdv, x, { DST: POP_DST }),
      forged,
      ...honest.map((h) => popProve(h.secretKey)),
    ];
    for (const pop of candidates) {
      const r = registerKey(pkAdv, pop);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toMatch(/proof of possession does not verify/);
    }
    const reg2 = new KeyRegistry();
    for (const h of honest) expect(reg2.register(h.publicKey, popProve(h.secretKey)).ok).toBe(true);
    expect(reg2.register(pkAdv, forged).ok).toBe(false);
    expect(reg2.size).toBe(2);
    expect(reg2.get(pkAdv)).toBeUndefined();
  });

  it('FORCED VIA INTERNALS: the raw verifier is fooled by the rogue key (the attack is real) but a forged RegisteredKey is refused with a clear reason', () => {
    const honest = [keyGen(), keyGen()];
    const { pkAdv, forged } = rogue(honest.map((h) => h.publicKey));
    // 1. Control: the raw, PoP-less check accepts the forgery - this is exactly the attack the type closes.
    expect(rawFastAggregateVerify([...honest.map((h) => h.publicKey), pkAdv], msg, forged)).toBe(true);
    // 2. Public verifier with honest registered keys + an object cast to RegisteredKey: refused.
    const castForgery = { bytes: pkAdv } as unknown as RegisteredKey;
    const fake = Object.create(RegisteredKey.prototype) as RegisteredKey;
    for (const bad of [castForgery, fake, pkAdv as unknown as RegisteredKey]) {
      const keys = [...honest.map(reg), bad];
      expect(fastAggregateVerify(keys, msg, forged)).toBe(false);
      expect(checkRegistered(keys)).toMatch(/not a registered key|proof of possession/);
    }
    // 3. A structuredClone / JSON round trip loses registration.
    const r0 = reg(honest[0] as { publicKey: Uint8Array; secretKey: Uint8Array });
    expect(checkRegistered([structuredClone(r0)])).toMatch(/not a registered key/);
    expect(checkRegistered([r0])).toBeNull();
  });

  it('public verifiers fail closed on empty / non-array input', () => {
    expect(fastAggregateVerify([], msg, new Uint8Array(96))).toBe(false);
    expect(aggregateVerify([], [], new Uint8Array(96))).toBe(false);
    expect(fastAggregateVerify(null as unknown as RegisteredKey[], msg, new Uint8Array(96))).toBe(false);
  });
});
