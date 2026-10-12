/**
 * Mutation-kill tests for pq.ts (part 2): the PinnedPqKey choke point (R3-01), pq bindings/pins (R3-06),
 * verifyPinnedSuite, wire validation and the LAMPS composite format.
 */
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { b64u, unb64u, utf8 } from './hash';
import { generateKeyPair, sign as edSign, verify as edVerify } from './keys';
import {
  COMPOSITE_LABEL,
  COMPOSITE_PREFIX,
  COMPOSITE_SIGNATURE_BYTES,
  PinnedPqKey,
  type PqBinding,
  compositeRepresentative,
  compositeSign,
  compositeVerify,
  holderPqCommitment,
  isPinnedPqKey,
  isWellFormedPqPublicKey,
  mlDsa65Keygen,
  mlDsa65Sign,
  mlDsa65Verify,
  pqPinFor,
  resolvePqVerifyKey,
  signPqBinding,
  signWithSuite,
  validateSignatureWire,
  verifyPinnedSuite,
  slhDsa128fKeygen,
  encodeSlhDsaPublicKey,
  encodeMlDsaPublicKey,
  type SigAlg,
  SIG_SUITES,
} from './pq';

const MSG = utf8('mutation-kill pq-2 message');
const ED = generateKeyPair();
const ED2 = generateKeyPair();
const EDPUB = b64u(ED.publicKey);
const ML = mlDsa65Keygen(new Uint8Array(32).fill(1));
const ML2 = mlDsa65Keygen(new Uint8Array(32).fill(2));
const SLH = slhDsa128fKeygen(new Uint8Array(48).fill(4));
const PK = encodeMlDsaPublicKey(ML.publicKey);
const PK2 = encodeMlDsaPublicKey(ML2.publicKey);
const PKSLH = encodeSlhDsaPublicKey(SLH.publicKey);
const sha256 = (b: Uint8Array): Uint8Array => new Uint8Array(createHash('sha256').update(b).digest());
const cat = (...xs: Uint8Array[]): Uint8Array => Uint8Array.from(xs.flatMap((x) => Array.from(x)));
const bytesEq = (a: Uint8Array, b: Uint8Array): boolean => Buffer.from(a).equals(Buffer.from(b));
function thrown(fn: () => unknown): Error {
  try {
    fn();
  } catch (e) {
    return e as Error;
  }
  throw new Error('expected a throw');
}
const flipB64 = (s: string, at = 0): string => {
  const b = unb64u(s);
  b[at] = (b[at] ?? 0) ^ 1;
  return b64u(b);
};

// ---- holderPqCommitment ---------------------------------------------------------------------------
describe('holderPqCommitment', () => {
  it('is b64u(sha256("atlas-pca/holder-pq/v1\\0" ‖ pk))', () => {
    for (const k of [PK, 'a', '', PK2]) {
      expect(holderPqCommitment(k)).toBe(b64u(sha256(cat(utf8('atlas-pca/holder-pq/v1\0'), utf8(k)))));
    }
    expect(holderPqCommitment('a')).not.toBe(holderPqCommitment('b'));
    expect(holderPqCommitment('a')).not.toBe(b64u(sha256(utf8('a'))));
  });
  it('pins one concrete value (domain + order are part of the wire)', () => {
    expect(holderPqCommitment('abc')).toBe(b64u(sha256(utf8('atlas-pca/holder-pq/v1\0abc'))));
  });
});

// ---- PinnedPqKey / isPinnedPqKey -----------------------------------------------------------------
describe('PinnedPqKey: unforgeable, immutable, minted only by the resolver', () => {
  it('direct construction throws TypeError (wrong or missing token)', () => {
    const Ctor = PinnedPqKey as unknown as new (k: string, s: string, t?: unknown) => PinnedPqKey;
    for (const tok of [undefined, Symbol('atlas-pca/pinned-pq-key'), 'atlas-pca/pinned-pq-key', null, {}]) {
      const e = thrown(() => new Ctor('k', 'trusted', tok));
      expect(e).toBeInstanceOf(TypeError);
      expect(e.message).toBe('PinnedPqKey can only be created by resolvePqVerifyKey');
    }
    expect(thrown(() => new Ctor('k', 'trusted')).message).toBe('PinnedPqKey can only be created by resolvePqVerifyKey');
  });
  it('a minted key carries exactly b64u + source, is frozen, and registers as minted', () => {
    const k = resolvePqVerifyKey('', undefined, { trustedPk: PK })!;
    expect(k).toBeInstanceOf(PinnedPqKey);
    expect(k.b64u).toBe(PK);
    expect(k.source).toBe('trusted');
    expect(Object.keys(k).sort()).toEqual(['b64u', 'source']);
    expect(Object.isFrozen(k)).toBe(true);
    expect(() => {
      (k as { b64u: string }).b64u = 'evil';
    }).toThrow(TypeError);
    expect(() => {
      (k as { source: string }).source = 'pin';
    }).toThrow(TypeError);
    expect(() => {
      (k as unknown as { extra: number }).extra = 1;
    }).toThrow(TypeError);
    expect(k.b64u).toBe(PK);
    expect(isPinnedPqKey(k)).toBe(true);
  });
  it('isPinnedPqKey is true ONLY for keys minted here', () => {
    const k = resolvePqVerifyKey('', undefined, { trustedPk: PK })!;
    const proto = Object.getPrototypeOf(k) as object;
    const forged: unknown[] = [
      { b64u: PK, source: 'trusted' },
      Object.create(proto),
      Object.assign(Object.create(proto), { b64u: PK, source: 'trusted' }),
      { ...k },
      JSON.parse(JSON.stringify(k)),
      structuredClone({ ...k }),
      Object.freeze({ b64u: PK, source: 'pin' }),
      PK,
      '',
      0,
      1,
      true,
      false,
      null,
      undefined,
      Symbol('x'),
      () => k,
      [k],
      [],
      {},
      new PinnedPqKeyLike(),
    ];
    for (const f of forged) expect(isPinnedPqKey(f), String(typeof f)).toBe(false);
  });
  it('every minting route yields a registered key (trusted / pin / holder-commitment / unbound)', () => {
    const ks = [
      resolvePqVerifyKey('i', PK, { trustedPk: PK2 }),
      resolvePqVerifyKey('i', PK, { pqPins: { i: PK } }),
      resolvePqVerifyKey('i', PK, { holderPq: holderPqCommitment(PK) }),
      resolvePqVerifyKey('i', PK, { allowUnboundPq: true }),
    ];
    expect(ks.map((k) => k && isPinnedPqKey(k))).toEqual([true, true, true, true]);
    expect(ks.map((k) => k!.source)).toEqual(['trusted', 'pin', 'holder-commitment', 'unbound']);
  });
});
class PinnedPqKeyLike {
  b64u = PK;
  source = 'trusted';
}

// ---- resolvePqVerifyKey ---------------------------------------------------------------------------
describe('resolvePqVerifyKey: the R3-01 choke point', () => {
  it('no source / null source => refuse', () => {
    expect(resolvePqVerifyKey('i', PK)).toBeNull();
    expect(resolvePqVerifyKey('i', PK, undefined)).toBeNull();
    expect(resolvePqVerifyKey('i', PK, null as never)).toBeNull();
    expect(resolvePqVerifyKey('i', PK, {})).toBeNull();
  });
  it('trustedPk wins outright; the artifact key is not consulted', () => {
    const k = resolvePqVerifyKey('i', undefined, { trustedPk: PK2 })!;
    expect(k.b64u).toBe(PK2);
    expect(k.source).toBe('trusted');
    // trusted beats a mismatching pin, a holderPq and allowUnbound; artifactPk can be anything
    const k2 = resolvePqVerifyKey('i', 'attacker', { trustedPk: PK2, pqPins: { i: PK }, holderPq: 'x', allowUnboundPq: true })!;
    expect(k2.b64u).toBe(PK2);
    expect(k2.source).toBe('trusted');
    expect(resolvePqVerifyKey('i', 5, { trustedPk: PK2 })!.b64u).toBe(PK2);
  });
  it('an empty / non-string trustedPk is NOT a trust source (falls through)', () => {
    expect(resolvePqVerifyKey('i', PK, { trustedPk: '' })).toBeNull();
    expect(resolvePqVerifyKey('i', PK, { trustedPk: 5 as never })).toBeNull();
    expect(resolvePqVerifyKey('i', PK, { trustedPk: null as never })).toBeNull();
    expect(resolvePqVerifyKey('i', PK, { trustedPk: '', allowUnboundPq: true })!.source).toBe('unbound');
    expect(resolvePqVerifyKey('i', PK, { trustedPk: '', allowUnboundPq: true })!.b64u).toBe(PK);
    expect(resolvePqVerifyKey('i', PK, { trustedPk: 7 as never, pqPins: { i: PK } })!.source).toBe('pin');
  });
  it('the artifact key must be a non-empty string for every non-trusted route', () => {
    const src = { pqPins: { i: PK }, holderPq: holderPqCommitment(PK), allowUnboundPq: true };
    for (const bad of [undefined, null, 5, '', {}, [PK], true]) expect(resolvePqVerifyKey('i', bad, src), String(bad)).toBeNull();
    // ...and a single char is enough to get past the length gate (it then fails on its own merits)
    expect(resolvePqVerifyKey('i', 'x', { allowUnboundPq: true })!.b64u).toBe('x');
  });
  it('a pin for the identity: artifact key must equal it exactly', () => {
    const k = resolvePqVerifyKey('i', PK, { pqPins: { i: PK } })!;
    expect(k.b64u).toBe(PK);
    expect(k.source).toBe('pin');
    expect(resolvePqVerifyKey('i', PK2, { pqPins: { i: PK } })).toBeNull();
    expect(resolvePqVerifyKey('i', PK + 'A', { pqPins: { i: PK } })).toBeNull();
    expect(resolvePqVerifyKey('i', PK.slice(1), { pqPins: { i: PK } })).toBeNull();
  });
  it('a MISMATCHING pin is a hard refusal: neither allowUnboundPq nor a matching holderPq rescues it', () => {
    expect(resolvePqVerifyKey('i', PK2, { pqPins: { i: PK }, allowUnboundPq: true })).toBeNull();
    expect(resolvePqVerifyKey('i', PK2, { pqPins: { i: PK }, holderPq: holderPqCommitment(PK2) })).toBeNull();
    expect(resolvePqVerifyKey('i', PK2, { pqPins: { i: PK }, holderPq: holderPqCommitment(PK2), allowUnboundPq: true })).toBeNull();
  });
  it('a pin for ANOTHER identity does not apply (falls through to the other sources)', () => {
    expect(resolvePqVerifyKey('i', PK2, { pqPins: { other: PK } })).toBeNull();
    expect(resolvePqVerifyKey('i', PK2, { pqPins: { other: PK }, allowUnboundPq: true })!.source).toBe('unbound');
    expect(resolvePqVerifyKey('i', PK2, { pqPins: { other: PK }, holderPq: holderPqCommitment(PK2) })!.source).toBe('holder-commitment');
  });
  it('pin lookup is own-property only (prototype names never select a pin)', () => {
    for (const id of ['constructor', 'toString', '__proto__', 'hasOwnProperty', 'valueOf']) {
      const r = resolvePqVerifyKey(id, PK, { pqPins: {}, allowUnboundPq: true });
      expect(r, id).not.toBeNull();
      expect(r!.source, id).toBe('unbound');
      expect(resolvePqVerifyKey(id, PK, { pqPins: {} }), id).toBeNull();
    }
  });
  it('pin lookup requires a string identity (a number never coerces onto a "5" pin)', () => {
    const r = resolvePqVerifyKey(5 as never, PK, { pqPins: { '5': PK2 }, allowUnboundPq: true })!;
    expect(r.source).toBe('unbound');
    expect(r.b64u).toBe(PK);
    expect(resolvePqVerifyKey(5 as never, PK2, { pqPins: { '5': PK2 } })).toBeNull();
    expect(resolvePqVerifyKey(undefined as never, PK, { pqPins: { undefined: PK2 }, allowUnboundPq: true })!.source).toBe('unbound');
  });
  it('an own pin whose value is undefined behaves as "no pin" (falls through)', () => {
    const pins = { i: undefined } as unknown as Record<string, string>;
    expect(resolvePqVerifyKey('i', PK, { pqPins: pins })).toBeNull();
    expect(resolvePqVerifyKey('i', PK, { pqPins: pins, allowUnboundPq: true })!.source).toBe('unbound');
  });
  it('holder_pq commitment route: artifact key must hash to the committed value', () => {
    const k = resolvePqVerifyKey('i', PK, { holderPq: holderPqCommitment(PK) })!;
    expect(k.source).toBe('holder-commitment');
    expect(k.b64u).toBe(PK);
    expect(resolvePqVerifyKey('i', PK2, { holderPq: holderPqCommitment(PK) })).toBeNull();
    expect(resolvePqVerifyKey('i', PK, { holderPq: holderPqCommitment(PK2) })).toBeNull();
    expect(resolvePqVerifyKey('i', PK, { holderPq: '' })).toBeNull();
    expect(resolvePqVerifyKey('i', PK, { holderPq: 5 as never })).toBeNull();
    expect(resolvePqVerifyKey('i', PK, { holderPq: null as never })).toBeNull();
    // a non-matching holderPq falls through to allowUnbound
    expect(resolvePqVerifyKey('i', PK, { holderPq: 'nope', allowUnboundPq: true })!.source).toBe('unbound');
    // a matching holderPq outranks allowUnbound
    expect(resolvePqVerifyKey('i', PK, { holderPq: holderPqCommitment(PK), allowUnboundPq: true })!.source).toBe('holder-commitment');
    // a matching pin outranks a matching holderPq
    expect(resolvePqVerifyKey('i', PK, { pqPins: { i: PK }, holderPq: holderPqCommitment(PK) })!.source).toBe('pin');
  });
  it('allowUnboundPq is honoured ONLY when strictly === true', () => {
    for (const v of [false, undefined, 1, 'true', 'yes', {}, [], null, 0, '']) {
      expect(resolvePqVerifyKey('i', PK, { allowUnboundPq: v as never }), String(v)).toBeNull();
    }
    const k = resolvePqVerifyKey('i', PK, { allowUnboundPq: true })!;
    expect(k.source).toBe('unbound');
    expect(k.b64u).toBe(PK);
  });
  it('with only a pin config and no matching source the default is REFUSE', () => {
    expect(resolvePqVerifyKey('i', PK, { pqPins: {} })).toBeNull();
    expect(resolvePqVerifyKey('i', PK, { pqPins: { j: PK } })).toBeNull();
  });
});

// ---- isWellFormedPqPublicKey ----------------------------------------------------------------------
describe('isWellFormedPqPublicKey', () => {
  const lens = [1952, 32, 2592, 64, 897, 1793, 97484];
  it('accepts canonical b64u of exactly each registered public-key length', () => {
    for (const n of lens) expect(isWellFormedPqPublicKey(b64u(new Uint8Array(n).fill(7))), String(n)).toBe(true);
  });
  it('rejects every neighbouring length and every non-registered length', () => {
    for (const n of lens) {
      expect(isWellFormedPqPublicKey(b64u(new Uint8Array(n - 1).fill(7))), `${n}-1`).toBe(false);
      expect(isWellFormedPqPublicKey(b64u(new Uint8Array(n + 1).fill(7))), `${n}+1`).toBe(false);
    }
    for (const n of [0, 1, 31, 33, 63, 65, 96, 128, 1000, 3309]) expect(isWellFormedPqPublicKey(b64u(new Uint8Array(n).fill(7))), String(n)).toBe(false);
  });
  it('rejects non-strings and non-canonical encodings', () => {
    for (const v of [undefined, null, 5, {}, [PK], true]) expect(isWellFormedPqPublicKey(v), String(v)).toBe(false);
    expect(isWellFormedPqPublicKey(PK + '=')).toBe(false);
    expect(isWellFormedPqPublicKey(PK + '!')).toBe(false);
    expect(isWellFormedPqPublicKey('')).toBe(false);
    expect(isWellFormedPqPublicKey(PK.replace(/./, '+'))).toBe(false);
    expect(isWellFormedPqPublicKey(PK)).toBe(true);
    expect(isWellFormedPqPublicKey(PKSLH)).toBe(true);
  });
});

// ---- bindings --------------------------------------------------------------------------------------
function bindingMessage(ed: string, pq: string, epoch: number, aud: string): Uint8Array {
  return cat(utf8('atlas-pca/pq-binding/v2\0'), utf8(`${ed}\0${pq}\0${epoch}\0${aud}`));
}
describe('signPqBinding', () => {
  it('produces { ed, pq, epoch, aud, sig } with sig = Ed25519(domain ‖ ed\\0pq\\0epoch\\0aud)', () => {
    const b = signPqBinding(ED.secretKey, EDPUB, PK, 3, 'aud-1');
    expect(Object.keys(b).sort()).toEqual(['aud', 'ed', 'epoch', 'pq', 'sig']);
    expect(b).toMatchObject({ ed: EDPUB, pq: PK, epoch: 3, aud: 'aud-1' });
    expect(b.sig).toBe(b64u(edSign(ED.secretKey, bindingMessage(EDPUB, PK, 3, 'aud-1'))));
    expect(edVerify(ED.publicKey, bindingMessage(EDPUB, PK, 3, 'aud-1'), unb64u(b.sig))).toBe(true);
  });
  it('epoch must be a positive safe integer (exact message, RangeError)', () => {
    for (const bad of [0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '1' as never, null as never, undefined as never]) {
      const e = thrown(() => signPqBinding(ED.secretKey, EDPUB, PK, bad, 'a'));
      expect(e, String(bad)).toBeInstanceOf(RangeError);
      expect(e.message).toBe('signPqBinding: epoch must be a positive safe integer');
    }
    expect(() => signPqBinding(ED.secretKey, EDPUB, PK, 1, 'a')).not.toThrow();
    expect(() => signPqBinding(ED.secretKey, EDPUB, PK, Number.MAX_SAFE_INTEGER, 'a')).not.toThrow();
  });
  it('aud must be a non-empty string (exact message, TypeError)', () => {
    for (const bad of ['', undefined, null, 5, {}] as unknown[]) {
      const e = thrown(() => signPqBinding(ED.secretKey, EDPUB, PK, 1, bad as string));
      expect(e, String(bad)).toBeInstanceOf(TypeError);
      expect(e.message).toBe('signPqBinding: aud (the instance/audience id) is required');
    }
    expect(() => signPqBinding(ED.secretKey, EDPUB, PK, 1, 'x')).not.toThrow();
  });
  it('the epoch check runs before the aud check', () => {
    expect(thrown(() => signPqBinding(ED.secretKey, EDPUB, PK, 0, '')).message).toBe('signPqBinding: epoch must be a positive safe integer');
  });
});

describe('pqPinFor', () => {
  const good = (): PqBinding => signPqBinding(ED.secretKey, EDPUB, PK, 2, 'aud');
  it('a good binding for the right audience yields exactly { [ed]: pq }', () => {
    const pin = pqPinFor(good(), 'aud');
    expect(pin).toStrictEqual({ [EDPUB]: PK });
  });
  it('the pin it yields is directly usable by resolvePqVerifyKey', () => {
    const pins = pqPinFor(good(), 'aud')!;
    expect(resolvePqVerifyKey(EDPUB, PK, { pqPins: pins })!.source).toBe('pin');
    expect(resolvePqVerifyKey(EDPUB, PK2, { pqPins: pins })).toBeNull();
  });
  it('refuses a structurally broken binding without throwing', () => {
    const g = good();
    for (const bad of [null, undefined, 0, '', {}, [], { ...g, ed: undefined }, { ...g, ed: 5 }, { ...g, pq: undefined }, { ...g, pq: 5 }, { ...g, sig: undefined }, { ...g, sig: 5 }]) {
      expect(() => pqPinFor(bad as never, 'aud')).not.toThrow();
      expect(pqPinFor(bad as never, 'aud'), JSON.stringify(bad)).toBeNull();
    }
  });
  it('audience must be a non-empty string equal to the binding\'s', () => {
    expect(pqPinFor(good(), 'other')).toBeNull();
    expect(pqPinFor(good(), 'aud ')).toBeNull();
    expect(pqPinFor(good(), '')).toBeNull();
    expect(pqPinFor(good(), undefined as never)).toBeNull();
    expect(pqPinFor(good(), 5 as never)).toBeNull();
    // an EMPTY / non-string audience is refused even when the binding is correctly SIGNED for it
    const mk = (aud: unknown): PqBinding => ({ ed: EDPUB, pq: PK, epoch: 2, aud: aud as string, sig: b64u(edSign(ED.secretKey, bindingMessage(EDPUB, PK, 2, aud as string))) });
    expect(pqPinFor(mk(''), '')).toBeNull();
    expect(pqPinFor(mk(5), 5 as never)).toBeNull();
    expect(pqPinFor(mk('x'), 'x')).toStrictEqual({ [EDPUB]: PK });
  });
  it('epoch must be a positive safe integer', () => {
    // forge bindings with validly-signed bad epochs to prove the epoch gate (not the signature) refuses them
    for (const e of [0, -3, 1.5, NaN, Number.MAX_SAFE_INTEGER + 1, Infinity]) {
      const forged: PqBinding = { ed: EDPUB, pq: PK, epoch: e, aud: 'aud', sig: b64u(edSign(ED.secretKey, bindingMessage(EDPUB, PK, e, 'aud'))) };
      expect(pqPinFor(forged, 'aud'), String(e)).toBeNull();
    }
    for (const e of [1, 2, Number.MAX_SAFE_INTEGER]) {
      const ok: PqBinding = { ed: EDPUB, pq: PK, epoch: e, aud: 'aud', sig: b64u(edSign(ED.secretKey, bindingMessage(EDPUB, PK, e, 'aud'))) };
      expect(pqPinFor(ok, 'aud'), String(e)).toStrictEqual({ [EDPUB]: PK });
    }
    expect(pqPinFor({ ...good(), epoch: '2' as never }, 'aud')).toBeNull();
  });
  it('the pq key must be a well-formed key of some registered suite (even if correctly signed)', () => {
    for (const n of [0, 1, 31, 33, 1951, 3309]) {
      const bogus = b64u(new Uint8Array(n).fill(9));
      const b = signPqBinding(ED.secretKey, EDPUB, bogus, 1, 'aud');
      expect(pqPinFor(b, 'aud'), String(n)).toBeNull();
    }
    const nonCanon = signPqBinding(ED.secretKey, EDPUB, PK + '=', 1, 'aud');
    expect(pqPinFor(nonCanon, 'aud')).toBeNull();
    expect(pqPinFor(signPqBinding(ED.secretKey, EDPUB, PKSLH, 1, 'aud'), 'aud')).toStrictEqual({ [EDPUB]: PKSLH });
  });
  it('the signature is verified over (ed, pq, epoch, aud) with the identity key: any tamper refuses', () => {
    const g = good();
    expect(pqPinFor({ ...g, sig: flipB64(g.sig) }, 'aud')).toBeNull();
    expect(pqPinFor({ ...g, sig: 'AAAA' }, 'aud')).toBeNull();
    expect(pqPinFor({ ...g, pq: PK2 }, 'aud')).toBeNull();
    expect(pqPinFor({ ...g, epoch: 3 }, 'aud')).toBeNull();
    expect(pqPinFor({ ...g, ed: b64u(ED2.publicKey) }, 'aud')).toBeNull();
    // signed by another identity but claiming this one
    const impostor = signPqBinding(ED2.secretKey, EDPUB, PK, 2, 'aud');
    expect(pqPinFor(impostor, 'aud')).toBeNull();
    // a valid binding for audience X replayed to audience Y
    expect(pqPinFor(good(), 'aud2')).toBeNull();
  });
});

// ---- verifyPinnedSuite ----------------------------------------------------------------------------
describe('verifyPinnedSuite', () => {
  const hy = signWithSuite('hybrid-ed25519-ml-dsa-65', { edSecret: ED.secretKey, mlDsa: ML }, MSG);
  const pure = signWithSuite('ml-dsa-65', { mlDsa: ML }, MSG);
  const ed = signWithSuite('ed25519', { edSecret: ED.secretKey }, MSG);
  it('ed25519 / default: verifies under the identity; PQ policy is irrelevant', () => {
    expect(verifyPinnedSuite('ed25519', EDPUB, undefined, MSG, ed)).toBe(true);
    expect(verifyPinnedSuite(undefined, EDPUB, undefined, MSG, ed)).toBe(true);
    expect(verifyPinnedSuite('ed25519', EDPUB, 'whatever', MSG, ed, { pqPins: {} })).toBe(true);
    expect(verifyPinnedSuite('ed25519', b64u(ED2.publicKey), undefined, MSG, ed)).toBe(false);
    expect(verifyPinnedSuite('ed25519', EDPUB, undefined, utf8('other'), ed)).toBe(false);
  });
  it('unknown alg => false', () => {
    for (const a of ['nope', null, 5, '']) expect(verifyPinnedSuite(a, EDPUB, PK, MSG, ed, { allowUnboundPq: true })).toBe(false);
  });
  it('a PQ suite with no policy / empty policy is REFUSED (fail-closed default)', () => {
    expect(verifyPinnedSuite('hybrid-ed25519-ml-dsa-65', EDPUB, PK, MSG, hy)).toBe(false);
    expect(verifyPinnedSuite('hybrid-ed25519-ml-dsa-65', EDPUB, PK, MSG, hy, {})).toBe(false);
    expect(verifyPinnedSuite('ml-dsa-65', EDPUB, PK, MSG, pure, { pqPins: {} })).toBe(false);
  });
  it('accepted under a matching pin; refused under a mismatched one', () => {
    expect(verifyPinnedSuite('hybrid-ed25519-ml-dsa-65', EDPUB, PK, MSG, hy, { pqPins: { [EDPUB]: PK } })).toBe(true);
    expect(verifyPinnedSuite('ml-dsa-65', EDPUB, PK, MSG, pure, { pqPins: { [EDPUB]: PK } })).toBe(true);
    expect(verifyPinnedSuite('hybrid-ed25519-ml-dsa-65', EDPUB, PK, MSG, hy, { pqPins: { [EDPUB]: PK2 } })).toBe(false);
    expect(verifyPinnedSuite('hybrid-ed25519-ml-dsa-65', EDPUB, PK, MSG, hy, { pqPins: { [EDPUB]: PK2 }, allowUnboundPq: true })).toBe(false);
  });
  it('allowUnboundPq opt-out accepts the artifact key; a wrong artifact key still fails the signature', () => {
    expect(verifyPinnedSuite('hybrid-ed25519-ml-dsa-65', EDPUB, PK, MSG, hy, { allowUnboundPq: true })).toBe(true);
    expect(verifyPinnedSuite('hybrid-ed25519-ml-dsa-65', EDPUB, PK2, MSG, hy, { allowUnboundPq: true })).toBe(false);
    expect(verifyPinnedSuite('ml-dsa-65', EDPUB, PK, MSG, pure, { allowUnboundPq: true })).toBe(true);
    expect(verifyPinnedSuite('ml-dsa-65', EDPUB, PK, utf8('x'), pure, { allowUnboundPq: true })).toBe(false);
  });
  it('the identity (not the artifact) selects the pin: an attacker naming a pinned victim with their own PQ key is refused', () => {
    const victimPins = { [EDPUB]: PK2 };
    const attackerSig = signWithSuite('ml-dsa-65', { mlDsa: ML }, MSG);
    expect(verifyPinnedSuite('ml-dsa-65', EDPUB, PK, MSG, attackerSig, { pqPins: victimPins })).toBe(false);
  });
  it('only pqPins / allowUnboundPq are forwarded: trustedPk / holderPq on the policy never reach the resolver', () => {
    const evil = signWithSuite('ml-dsa-65', { mlDsa: ML }, MSG); // signed under ML, artifact key PK
    const spreadPolicy = { trustedPk: PK, holderPq: holderPqCommitment(PK) } as never;
    expect(verifyPinnedSuite('ml-dsa-65', EDPUB, PK, MSG, evil, spreadPolicy)).toBe(false);
    expect(verifyPinnedSuite('ml-dsa-65', EDPUB, PK, MSG, evil, { trustedPk: PK } as never)).toBe(false);
    expect(verifyPinnedSuite('ml-dsa-65', EDPUB, PK, MSG, evil, { holderPq: holderPqCommitment(PK) } as never)).toBe(false);
    expect(verifyPinnedSuite('ml-dsa-65', EDPUB, PK, MSG, evil, { ...(spreadPolicy as object), pqPins: { [EDPUB]: PK } })).toBe(true);
  });
  it('dispatches on the resolved suite for both halves of a hybrid and passes the identity as edPub', () => {
    const wrongEd = b64u(ED2.publicKey);
    expect(verifyPinnedSuite('hybrid-ed25519-ml-dsa-65', wrongEd, PK, MSG, hy, { allowUnboundPq: true })).toBe(false);
    expect(verifyPinnedSuite('hybrid-ed25519-ml-dsa-65', EDPUB, PK, MSG, { sig: hy.sig }, { allowUnboundPq: true })).toBe(false);
    expect(verifyPinnedSuite('hybrid-ed25519-ml-dsa-65', EDPUB, PK, MSG, { sig: hy.sig, pq_sig: flipB64(hy.pq_sig!) }, { allowUnboundPq: true })).toBe(false);
  });
});

// ---- validateSignatureWire ------------------------------------------------------------------------
const rnd = (n: number): string => b64u(new Uint8Array(n).fill(0x55));
function wireOf(alg: SigAlg | undefined): Record<string, unknown> {
  const s = SIG_SUITES[alg ?? 'ed25519'];
  const p: Record<string, unknown> = {};
  if (alg !== undefined) p.alg = alg;
  p.sig = rnd(s.sigBytes);
  if (s.needsPqPk) p.pq_pk = rnd(s.pqPkBytes);
  if (s.needsPqSig) p.pq_sig = rnd(s.pqSigBytes);
  return p;
}
const ALGS = Object.keys(SIG_SUITES) as SigAlg[];
describe('validateSignatureWire', () => {
  it('well-formed wire for every suite (and absent alg) => null', () => {
    expect(validateSignatureWire(wireOf(undefined))).toBeNull();
    for (const a of ALGS) expect(validateSignatureWire(wireOf(a)), a).toBeNull();
  });
  it("'alg' must be a string when present; unknown alg reason names it", () => {
    for (const bad of [5, null, true, {}, ['ed25519']]) {
      expect(validateSignatureWire({ ...wireOf(undefined), alg: bad }), String(bad)).toBe("'alg' must be a string");
    }
    expect(validateSignatureWire({ ...wireOf(undefined), alg: 'nope' })).toBe("unknown signature alg 'nope'");
    expect(validateSignatureWire({ ...wireOf(undefined), alg: '' })).toBe("unknown signature alg ''");
    expect(validateSignatureWire({ ...wireOf(undefined), alg: 'toString' })).toBe("unknown signature alg 'toString'");
  });
  it("'sig' reason: exact text with the suite's byte length (fixed-length suites)", () => {
    for (const a of ALGS.filter((x) => !SIG_SUITES[x].varLen)) {
      const s = SIG_SUITES[a];
      const w = wireOf(a);
      const want = `'sig' is not canonical base64url (${s.sigBytes} bytes) for alg '${a}'`;
      expect(validateSignatureWire({ ...w, sig: rnd(s.sigBytes - 1) }), a).toBe(want);
      expect(validateSignatureWire({ ...w, sig: rnd(s.sigBytes + 1) }), a).toBe(want);
      expect(validateSignatureWire({ ...w, sig: undefined }), a).toBe(want);
      expect(validateSignatureWire({ ...w, sig: 5 }), a).toBe(want);
      expect(validateSignatureWire({ ...w, sig: (w.sig as string) + '=' }), a).toBe(want);
      const { sig: _drop, ...noSig } = w;
      expect(validateSignatureWire(noSig), a).toBe(want);
    }
    // absent-alg path reports 'ed25519'
    expect(validateSignatureWire({ sig: 'x' })).toBe("'sig' is not canonical base64url (64 bytes) for alg 'ed25519'");
  });
  it("'pq_pk' reasons: required+exact length for PQ suites, forbidden for ed25519", () => {
    for (const a of ALGS.filter((x) => SIG_SUITES[x].needsPqPk)) {
      const s = SIG_SUITES[a];
      const w = wireOf(a);
      const want = `'pq_pk' is not canonical base64url (${s.pqPkBytes} bytes) for alg '${a}'`;
      expect(validateSignatureWire({ ...w, pq_pk: rnd(s.pqPkBytes - 1) }), a).toBe(want);
      expect(validateSignatureWire({ ...w, pq_pk: rnd(s.pqPkBytes + 1) }), a).toBe(want);
      expect(validateSignatureWire({ ...w, pq_pk: undefined }), a).toBe(want);
      expect(validateSignatureWire({ ...w, pq_pk: 5 }), a).toBe(want);
    }
    expect(validateSignatureWire({ ...wireOf(undefined), pq_pk: rnd(32) })).toBe("'pq_pk' must be absent for alg 'ed25519'");
    expect(validateSignatureWire({ ...wireOf('ed25519'), pq_pk: '' })).toBe("'pq_pk' must be absent for alg 'ed25519'");
    expect(validateSignatureWire({ ...wireOf('ed25519'), pq_pk: null })).toBe("'pq_pk' must be absent for alg 'ed25519'");
    // an explicit-undefined key is "absent"
    expect(validateSignatureWire({ ...wireOf('ed25519'), pq_pk: undefined })).toBeNull();
  });
  it("'pq_sig' reasons: required+exact length for hybrids, forbidden otherwise", () => {
    for (const a of ALGS.filter((x) => SIG_SUITES[x].needsPqSig && !SIG_SUITES[x].varLen)) {
      const s = SIG_SUITES[a];
      const w = wireOf(a);
      const want = `'pq_sig' is not canonical base64url (${s.pqSigBytes} bytes) for alg '${a}'`;
      expect(validateSignatureWire({ ...w, pq_sig: rnd(s.pqSigBytes - 1) }), a).toBe(want);
      expect(validateSignatureWire({ ...w, pq_sig: rnd(s.pqSigBytes + 1) }), a).toBe(want);
      expect(validateSignatureWire({ ...w, pq_sig: undefined }), a).toBe(want);
      expect(validateSignatureWire({ ...w, pq_sig: 5 }), a).toBe(want);
    }
    for (const a of ALGS.filter((x) => !SIG_SUITES[x].needsPqSig)) {
      expect(validateSignatureWire({ ...wireOf(a), pq_sig: rnd(64) }), a).toBe(`'pq_sig' must be absent for alg '${a}'`);
      expect(validateSignatureWire({ ...wireOf(a), pq_sig: '' }), a).toBe(`'pq_sig' must be absent for alg '${a}'`);
      expect(validateSignatureWire({ ...wireOf(a), pq_sig: null }), a).toBe(`'pq_sig' must be absent for alg '${a}'`);
    }
  });
  it('checks run in order: sig, then pq_pk, then pq_sig', () => {
    const w = { ...wireOf('hybrid-ed25519-ml-dsa-65'), sig: 'x', pq_pk: 'x', pq_sig: 'x' };
    expect(validateSignatureWire(w)).toMatch(/^'sig' /);
    expect(validateSignatureWire({ ...w, sig: rnd(64) })).toMatch(/^'pq_pk' /);
    expect(validateSignatureWire({ ...w, sig: rnd(64), pq_pk: rnd(1952) })).toMatch(/^'pq_sig' /);
    // the alg check precedes all
    expect(validateSignatureWire({ ...w, alg: 'zz' })).toBe("unknown signature alg 'zz'");
  });
  it('rejects non-canonical base64url in every field', () => {
    const w = wireOf('hybrid-ed25519-ml-dsa-65');
    expect(validateSignatureWire({ ...w, sig: (w.sig as string).replace(/.$/, '!') })).toMatch(/^'sig' /);
    expect(validateSignatureWire({ ...w, pq_pk: (w.pq_pk as string) + '=' })).toMatch(/^'pq_pk' /);
    expect(validateSignatureWire({ ...w, pq_sig: (w.pq_sig as string) + '=' })).toMatch(/^'pq_sig' /);
  });
  it('the decoder is injectable and is called with (value, expectedBytes)', () => {
    const calls: Array<[unknown, number | undefined]> = [];
    const dec = (v: unknown, len?: number): Uint8Array | null => {
      calls.push([v, len]);
      return new Uint8Array(len ?? 0);
    };
    expect(validateSignatureWire({ alg: 'hybrid-ed25519-ml-dsa-65', sig: 'S', pq_pk: 'K', pq_sig: 'Q' }, dec)).toBeNull();
    expect(calls).toEqual([['S', 64], ['K', 1952], ['Q', 3309]]);
    const none = (): null => null;
    expect(validateSignatureWire({ sig: 'x' }, none)).toMatch(/^'sig' /);
  });
  describe('LESS variable-length components', () => {
    // a fake decoder maps a decimal string to a buffer of that many bytes, so no 100 kB blobs are needed
    const dec = (v: unknown, len?: number): Uint8Array | null => {
      if (typeof v !== 'string') return null;
      const n = Number(v);
      if (!Number.isInteger(n)) return null;
      if (len !== undefined && n !== len) return null;
      return new Uint8Array(n);
    };
    const pure = (sig: string): Record<string, unknown> => ({ alg: 'less-cat1', sig, pq_pk: '97484' });
    const hyb = (pq_sig: string): Record<string, unknown> => ({ alg: 'hybrid-ed25519-less-cat1', sig: '64', pq_pk: '97484', pq_sig });
    it('pure: sig valid iff min <= n <= max and (max - n) % 16 === 0', () => {
      for (const n of [1153, 1169, 1233, 1329, 1313]) expect(validateSignatureWire(pure(String(n)), dec), String(n)).toBeNull();
      for (const n of [1152, 1137, 1154, 1160, 1328, 1330, 1345, 1361, 0, 1, 64, 2000, 1169.5]) {
        expect(validateSignatureWire(pure(String(n)), dec), String(n)).toBe("'sig' is not canonical base64url (1153..1329 bytes) for alg 'less-cat1'");
      }
      expect(validateSignatureWire(pure('abc'), dec)).toMatch(/^'sig' .*1153\.\.1329 bytes/);
      expect(validateSignatureWire({ alg: 'less-cat1', pq_pk: '97484' }, dec)).toMatch(/^'sig' /);
    });
    it('pure: the variable-length decoder is called WITHOUT a length', () => {
      const seen: Array<number | undefined> = [];
      const spy = (v: unknown, len?: number): Uint8Array | null => {
        seen.push(len);
        return dec(v, len);
      };
      validateSignatureWire(pure('1329'), spy);
      expect(seen).toEqual([undefined, 97484]);
    });
    it('hybrid: sig is exactly 64 bytes; pq_sig follows the variable-length rule', () => {
      for (const n of [1153, 1329, 1217]) expect(validateSignatureWire(hyb(String(n)), dec), String(n)).toBeNull();
      for (const n of [1152, 1330, 1345, 1154, 1137, 0]) {
        expect(validateSignatureWire(hyb(String(n)), dec), String(n)).toBe("'pq_sig' is not canonical base64url (1153..1329 bytes) for alg 'hybrid-ed25519-less-cat1'");
      }
      expect(validateSignatureWire({ ...hyb('1329'), sig: '65' }, dec)).toBe("'sig' is not canonical base64url (64 bytes) for alg 'hybrid-ed25519-less-cat1'");
      expect(validateSignatureWire({ ...hyb('1329'), pq_sig: undefined }, dec)).toMatch(/^'pq_sig' /);
    });
    it('hybrid: the pq_sig decoder is called WITHOUT a length; sig and pq_pk with theirs', () => {
      const seen: Array<[unknown, number | undefined]> = [];
      const spy = (v: unknown, len?: number): Uint8Array | null => {
        seen.push([v, len]);
        return dec(v, len);
      };
      validateSignatureWire(hyb('1329'), spy);
      expect(seen).toEqual([['64', 64], ['97484', 97484], ['1329', undefined]]);
    });
    it('the real strict decoder accepts real LESS-shaped base64url on the grid and rejects off-grid', () => {
      const real = (n: number): Record<string, unknown> => ({ alg: 'less-cat1', sig: rnd(n), pq_pk: rnd(97484) });
      for (const n of [1153, 1169, 1329]) expect(validateSignatureWire(real(n)), String(n)).toBeNull();
      for (const n of [1152, 1154, 1330, 1345]) expect(validateSignatureWire(real(n)), String(n)).toMatch(/^'sig' /);
      expect(validateSignatureWire({ alg: 'less-cat1', sig: rnd(1329) + '=', pq_pk: rnd(97484) })).toMatch(/^'sig' /);
    });
  });
});

// ---- LAMPS composite -------------------------------------------------------------------------------
describe('composite wire format', () => {
  it('constants', () => {
    expect(COMPOSITE_PREFIX).toBe('CompositeAlgorithmSignatures2025');
    expect(COMPOSITE_LABEL).toBe('COMPSIG-MLDSA65-Ed25519-SHA512');
    expect(COMPOSITE_SIGNATURE_BYTES).toBe(3373);
    expect(utf8(COMPOSITE_PREFIX).length).toBe(32);
  });
  const sha512 = (b: Uint8Array): Uint8Array => new Uint8Array(createHash('sha512').update(b).digest());
  it('M\' = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA-512(M), byte for byte', () => {
    expect(bytesEq(compositeRepresentative(MSG), cat(utf8('CompositeAlgorithmSignatures2025'), utf8('COMPSIG-MLDSA65-Ed25519-SHA512'), Uint8Array.of(0), sha512(MSG)))).toBe(true);
    const ctx = utf8('app-ctx');
    expect(bytesEq(compositeRepresentative(MSG, ctx), cat(utf8('CompositeAlgorithmSignatures2025'), utf8('COMPSIG-MLDSA65-Ed25519-SHA512'), Uint8Array.of(7), ctx, sha512(MSG)))).toBe(true);
    expect(bytesEq(compositeRepresentative(MSG, 'app-ctx'), compositeRepresentative(MSG, ctx))).toBe(true);
    expect(compositeRepresentative(MSG).length).toBe(32 + 30 + 1 + 64);
    expect(bytesEq(compositeRepresentative(MSG, ''), compositeRepresentative(MSG))).toBe(true);
    expect(bytesEq(compositeRepresentative(MSG, new Uint8Array(0)), compositeRepresentative(MSG))).toBe(true);
    expect(bytesEq(compositeRepresentative(MSG, 'a'), compositeRepresentative(MSG, 'b'))).toBe(false);
    expect(bytesEq(compositeRepresentative(MSG), compositeRepresentative(utf8('x')))).toBe(false);
  });
  it('ctx: 255 bytes is the maximum (RangeError beyond, exact message); multibyte strings count in bytes', () => {
    const ok = new Uint8Array(255).fill(3);
    expect(compositeRepresentative(MSG, ok)[62]).toBe(255);
    const e = thrown(() => compositeRepresentative(MSG, new Uint8Array(256)));
    expect(e).toBeInstanceOf(RangeError);
    expect(e.message).toBe('compositeRepresentative: ctx exceeds 255 bytes');
    expect(() => compositeRepresentative(MSG, 'x'.repeat(255))).not.toThrow();
    expect(() => compositeRepresentative(MSG, 'x'.repeat(256))).toThrow(RangeError);
    // 128 two-byte chars = 256 bytes
    expect(() => compositeRepresentative(MSG, 'é'.repeat(128))).toThrow(RangeError);
    expect(() => compositeRepresentative(MSG, 'é'.repeat(127))).not.toThrow();
  });
  const sk = { ed25519Secret: ED.secretKey, mlDsa: ML, message: MSG };
  const pub = { ed25519Pub: ED.publicKey, mlDsaPub: ML.publicKey, message: MSG };
  it('compositeSign: mldsaSig ‖ tradSig over M\' (3309 + 64)', () => {
    const sig = compositeSign(sk);
    expect(sig.length).toBe(3373);
    const mp = compositeRepresentative(MSG);
    expect(mlDsa65Verify(ML.publicKey, mp, sig.slice(0, 3309))).toBe(true);
    expect(edVerify(ED.publicKey, mp, sig.slice(3309))).toBe(true);
    expect(bytesEq(sig.slice(0, 3309), mlDsa65Sign(ML.secretKey, mp))).toBe(true);
    expect(bytesEq(sig.slice(3309), edSign(ED.secretKey, mp))).toBe(true);
    // neither half signs the bare message
    expect(mlDsa65Verify(ML.publicKey, MSG, sig.slice(0, 3309))).toBe(false);
    expect(edVerify(ED.publicKey, MSG, sig.slice(3309))).toBe(false);
  });
  it('compositeSign: ctx is bound into M\'', () => {
    const sig = compositeSign({ ...sk, ctx: 'c1' });
    const mp = compositeRepresentative(MSG, 'c1');
    expect(mlDsa65Verify(ML.publicKey, mp, sig.slice(0, 3309))).toBe(true);
    expect(edVerify(ED.publicKey, mp, sig.slice(3309))).toBe(true);
  });
  it('compositeSign: missing key material throws TypeError with the exact message', () => {
    for (const bad of [undefined, null, 'x', [1, 2]]) {
      const e = thrown(() => compositeSign({ ...sk, ed25519Secret: bad as never }));
      expect(e).toBeInstanceOf(TypeError);
      expect(e.message).toBe('compositeSign: ed25519Secret required');
    }
    for (const bad of [undefined, null, {}, { secretKey: 'x' }, { secretKey: [1] }]) {
      const e = thrown(() => compositeSign({ ...sk, mlDsa: bad as never }));
      expect(e).toBeInstanceOf(TypeError);
      expect(e.message).toBe('compositeSign: mlDsa key material required');
    }
    expect(thrown(() => compositeSign({ ...sk, ctx: new Uint8Array(256) }))).toBeInstanceOf(RangeError);
  });
  it('compositeVerify accepts a genuine signature (ctx string and bytes are equivalent)', () => {
    const sig = compositeSign(sk);
    expect(compositeVerify({ ...pub, signature: sig })).toBe(true);
    const sigC = compositeSign({ ...sk, ctx: 'c' });
    expect(compositeVerify({ ...pub, signature: sigC, ctx: 'c' })).toBe(true);
    expect(compositeVerify({ ...pub, signature: sigC, ctx: utf8('c') })).toBe(true);
    const max = compositeSign({ ...sk, ctx: new Uint8Array(255).fill(1) });
    expect(compositeVerify({ ...pub, signature: max, ctx: new Uint8Array(255).fill(1) })).toBe(true);
  });
  it('compositeVerify refuses: ctx mismatch, message change, wrong keys, wrong lengths, ctx > 255', () => {
    const sig = compositeSign(sk);
    const sigC = compositeSign({ ...sk, ctx: 'c' });
    expect(compositeVerify({ ...pub, signature: sigC })).toBe(false);
    expect(compositeVerify({ ...pub, signature: sig, ctx: 'c' })).toBe(false);
    expect(compositeVerify({ ...pub, signature: sigC, ctx: 'd' })).toBe(false);
    expect(compositeVerify({ ...pub, signature: sig, message: utf8('other') })).toBe(false);
    expect(compositeVerify({ ...pub, signature: sig, ed25519Pub: ED2.publicKey })).toBe(false);
    expect(compositeVerify({ ...pub, signature: sig, mlDsaPub: ML2.publicKey })).toBe(false);
    expect(compositeVerify({ ...pub, signature: sig.slice(0, 3372) })).toBe(false);
    expect(compositeVerify({ ...pub, signature: cat(sig, Uint8Array.of(0)) })).toBe(false);
    expect(compositeVerify({ ...pub, signature: Array.from(sig) as unknown as Uint8Array })).toBe(false);
    expect(compositeVerify({ ...pub, signature: undefined as never })).toBe(false);
    expect(compositeVerify({ ...pub, signature: sig, ctx: new Uint8Array(256) })).toBe(false);
    expect(compositeVerify({ ...pub, signature: sig, ctx: 'x'.repeat(256) })).toBe(false);
  });
  it('compositeVerify needs BOTH halves, and the split is at byte 3309', () => {
    const sig = compositeSign(sk);
    const flipAt = (i: number): Uint8Array => {
      const c = Uint8Array.from(sig);
      c[i] = c[i]! ^ 1;
      return c;
    };
    expect(compositeVerify({ ...pub, signature: flipAt(0) })).toBe(false);
    expect(compositeVerify({ ...pub, signature: flipAt(3308) })).toBe(false);
    expect(compositeVerify({ ...pub, signature: flipAt(3309) })).toBe(false);
    expect(compositeVerify({ ...pub, signature: flipAt(3372) })).toBe(false);
    // halves swapped (same total length) never verify
    expect(compositeVerify({ ...pub, signature: cat(sig.slice(3309), sig.slice(0, 3309)) })).toBe(false);
    // a good ML-DSA half with a signature by ANOTHER ed key, and vice versa
    const other = compositeSign({ ...sk, ed25519Secret: ED2.secretKey });
    expect(compositeVerify({ ...pub, signature: cat(sig.slice(0, 3309), other.slice(3309)) })).toBe(false);
    expect(compositeVerify({ ...pub, signature: cat(other.slice(0, 3309), sig.slice(3309)) })).toBe(true);
  });
  it('compositeVerify never throws on garbage keys', () => {
    const sig = compositeSign(sk);
    expect(() => compositeVerify({ ...pub, signature: sig, ed25519Pub: new Uint8Array(3) })).not.toThrow();
    expect(compositeVerify({ ...pub, signature: sig, ed25519Pub: new Uint8Array(3) })).toBe(false);
    expect(compositeVerify({ ...pub, signature: sig, mlDsaPub: new Uint8Array(3) })).toBe(false);
    expect(compositeVerify({ ...pub, signature: sig, mlDsaPub: undefined as never })).toBe(false);
    expect(compositeVerify({ ...pub, signature: sig, ed25519Pub: undefined as never })).toBe(false);
    expect(compositeVerify(undefined as never)).toBe(false);
  });
});
