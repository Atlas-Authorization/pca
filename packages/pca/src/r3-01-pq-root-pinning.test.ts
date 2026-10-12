import { describe, expect, it } from 'vitest';
import { b64u, utf8 } from './hash';
import { generateKeyPair } from './keys';
import { capHash, delegate, holderPqCommitment, mintRoot, verifyChain, type Capability } from './capability';
import {
  PinnedPqKey,
  encodeMlDsaPublicKey,
  isPinnedPqKey,
  mlDsa65Keygen,
  pqPinFor,
  resolvePqVerifyKey,
  signPqBinding,
  signSuiteArtifact,
  verifyLeafSuite,
  verifyPinnedSuite,
  verifyWithSuite,
} from './pq';
import { verifyWithSuite as legacyVerifyWithSuite } from './pq-test-support';
import { decide } from './policy-vm';
import { describeEnvelope } from './agent-native';
import { translateCapability } from './mesh';
import { goalCommitOf } from './envelope';
import { DEFAULT_RISK_POLICY } from './risk';

/**
 * R3-01 (CRITICAL) regression. A root capability signed with a pure-PQ alg used to be verified under the capability's OWN
 * `pq_pk`; the expected Ed25519 root issuer was only string-compared, so any root grant for any principal was forgeable.
 * The fix is structural: verifyWithSuite takes only an opaque PinnedPqKey that resolvePqVerifyKey alone can mint.
 */
const ML = 'ml-dsa-65' as const;
const HY = 'hybrid-ed25519-ml-dsa-65' as const;
const ml = (n: number) => mlDsa65Keygen(new Uint8Array(32).fill(n));
const pk = (m: ReturnType<typeof ml>) => encodeMlDsaPublicKey(m.publicKey);
const caveats = [{ type: 'allow', verbs: ['*'] }];

const victim = generateKeyPair();
const vPub = b64u(victim.publicKey);
const vMl = ml(7);
const atk = generateKeyPair();
const aPub = b64u(atk.publicKey);
const aMl = ml(9);

/** The PoC: the attacker signs a root "issued by" the victim's Ed25519 key under its OWN ML-DSA key. */
const forgedRoot = (): Capability => mintRoot({ principalSecret: atk.secretKey, principalPublic: vPub, holder: aPub, caveats: caveats as never, suite: { alg: ML, mlDsa: aMl } });
const genuineRoot = (alg: typeof ML | typeof HY): Capability =>
  mintRoot({ principalSecret: victim.secretKey, principalPublic: vPub, holder: aPub, caveats: caveats as never, suite: { alg, mlDsa: vMl } });

describe('R3-01: chain root PQ key authority', () => {
  it('the round-3 PoC forgery (pure-PQ root issued by the victim, signed under its own pq_pk) is REJECTED', () => {
    const root = forgedRoot();
    expect(root.issuer).toBe(vPub);
    expect(root.alg).toBe(ML);
    const r = verifyChain([root], vPub);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/PQ key pinned|stored grant/);
    const child = delegate(root, aPub, [], atk.secretKey);
    expect(verifyChain([root, child], vPub).ok).toBe(false);
  });

  it('still rejected when the victim HAS a pin (the attacker\'s own key is not the pin) or a different trustedRoot', () => {
    const root = forgedRoot();
    expect(verifyChain([root], vPub, { pqPins: { [vPub]: pk(vMl) } }).ok).toBe(false);
    expect(verifyChain([root], vPub, { trustedRoot: genuineRoot(ML) }).ok).toBe(false);
    // a pin for a different identity does not help
    expect(verifyChain([root], vPub, { pqPins: { [aPub]: pk(aMl) } }).ok).toBe(false);
    // a prototype-chain key is not a pin
    expect(verifyChain([root], 'constructor', { pqPins: {} }).ok).toBe(false);
  });

  it('the genuine pure-PQ / hybrid root verifies only under the issuer pin or the verifier\'s stored copy', () => {
    for (const alg of [ML, HY] as const) {
      const root = genuineRoot(alg);
      expect(verifyChain([root], vPub).ok).toBe(false); // no pin: BREAKING - unbound PQ roots are refused
      expect(verifyChain([root], vPub, { pqPins: { [vPub]: pk(vMl) } }).ok).toBe(true);
      expect(verifyChain([root], vPub, { pqPins: { [vPub]: pk(ml(8)) } }).ok).toBe(false); // wrong pin
      expect(verifyChain([root], vPub, { trustedRoot: root }).ok).toBe(true);
      // the legacy opt-out is explicit
      expect(verifyChain([root], vPub, { allowUnboundPq: true }).ok).toBe(true);
    }
    // the forged root passes ONLY with the explicit legacy opt-out (documented as unsafe)
    expect(verifyChain([forgedRoot()], vPub, { allowUnboundPq: true }).ok).toBe(true);
  });

  it('an ed25519 root is unchanged (no pin needed, byte-identical behaviour)', () => {
    const root = mintRoot({ principalSecret: victim.secretKey, principalPublic: vPub, holder: aPub, caveats: caveats as never });
    expect(verifyChain([root], vPub).ok).toBe(true);
    expect(verifyChain([root, delegate(root, aPub, [], atk.secretKey)], vPub).ok).toBe(true);
  });

  it('delegated PQ hops stay bound to the parent holder_pq commitment (F-2) and never to a pin', () => {
    const root = mintRoot({ principalSecret: victim.secretKey, principalPublic: vPub, holder: aPub, caveats: caveats as never, holderPq: pk(aMl) });
    const child = delegate(root, aPub, [], atk.secretKey, { alg: ML, mlDsa: aMl });
    expect(verifyChain([root, child], vPub).ok).toBe(true);
    const evil = delegate(root, aPub, [], atk.secretKey, { alg: ML, mlDsa: ml(66) });
    expect(verifyChain([root, evil], vPub).ok).toBe(false);
  });

  it('the surfaces that verify chains through their own options refuse the forged root too (policy-vm, agent-native, mesh translate)', () => {
    const root = forgedRoot();
    const envCav = { type: 'envelope', goal_commit: goalCommitOf('g', 's'), predicates: [{ verb: '*', resource: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY };
    const eroot = mintRoot({ principalSecret: atk.secretKey, principalPublic: vPub, holder: aPub, caveats: [envCav] as never, suite: { alg: ML, mlDsa: aMl } });
    const env = decide({ grant: eroot, action: { action: { verb: 'x', resource: 'y' } } as never, risk: {}, budget: { B: 0, tau: 0 }, now: Date.now() } as never);
    expect(JSON.stringify(env)).toMatch(/capability chain unverified/);
    expect(describeEnvelope([root], undefined, vPub).ok).toBe(false);
    expect(() => translateCapability([root], { fromGuardian: 'a', toGuardian: 'b', bridgeSecret: atk.secretKey, issued_at: 0 })).toThrow(/invalid source chain/);
    // with the victim's real pin, the FORGED root is still refused and the genuine one is accepted
    expect(describeEnvelope([root], undefined, vPub, { pqPins: { [vPub]: pk(vMl) } }).ok).toBe(false);
    expect(describeEnvelope([genuineRoot(ML)], undefined, vPub, { pqPins: { [vPub]: pk(vMl) } }).reason ?? '').not.toMatch(/PQ key pinned/);
  });
});

describe('R3-01: the choke point is structural', () => {
  const msg = utf8('m');

  it('verifyWithSuite refuses any PQ key that was not minted by resolvePqVerifyKey (raw string, look-alike object, as any)', () => {
    const s = signSuiteArtifact(ML, { mlDsa: aMl }, msg);
    const asAny = verifyWithSuite as (a: unknown, k: unknown, m: Uint8Array, s: unknown) => boolean;
    expect(asAny(ML, { pq: s.pq_pk }, msg, s)).toBe(false);
    expect(asAny(ML, { pq: { b64u: s.pq_pk, source: 'trusted' } }, msg, s)).toBe(false);
    expect(asAny(ML, { mlDsaPub: s.pq_pk }, msg, s)).toBe(false); // the removed per-slot string API verifies nothing
    expect(legacyVerifyWithSuite(ML, { mlDsaPub: s.pq_pk }, msg, s)).toBe(true); // only the TEST wrapper mints a trusted key
  });

  it('PinnedPqKey cannot be constructed directly', () => {
    expect(() => new (PinnedPqKey as unknown as new (k: string, s: string, t: symbol) => PinnedPqKey)('k', 'trusted', Symbol('x'))).toThrow(/resolvePqVerifyKey/);
    const k = resolvePqVerifyKey(vPub, pk(vMl), { pqPins: { [vPub]: pk(vMl) } });
    expect(k).not.toBeNull();
    expect(isPinnedPqKey(k)).toBe(true);
    expect(isPinnedPqKey({ ...k })).toBe(false);
    expect(Object.isFrozen(k)).toBe(true);
  });

  it('resolvePqVerifyKey: pin must equal the artifact key; holder commitment; trusted; unbound only when asked; else null', () => {
    const key = pk(vMl);
    expect(resolvePqVerifyKey(vPub, key)).toBeNull();
    expect(resolvePqVerifyKey(vPub, key, {})).toBeNull();
    expect(resolvePqVerifyKey(vPub, key, { pqPins: { [vPub]: key } })?.source).toBe('pin');
    expect(resolvePqVerifyKey(vPub, pk(aMl), { pqPins: { [vPub]: key } })).toBeNull();
    expect(resolvePqVerifyKey(vPub, pk(aMl), { pqPins: { [vPub]: key }, allowUnboundPq: true })).toBeNull(); // a pin that disagrees always wins
    expect(resolvePqVerifyKey(vPub, key, { holderPq: holderPqCommitment(key) })?.source).toBe('holder-commitment');
    expect(resolvePqVerifyKey(vPub, pk(aMl), { holderPq: holderPqCommitment(key) })).toBeNull();
    expect(resolvePqVerifyKey(vPub, key, { trustedPk: key })?.source).toBe('trusted');
    expect(resolvePqVerifyKey(vPub, key, { allowUnboundPq: true })?.source).toBe('unbound');
    expect(resolvePqVerifyKey(vPub, undefined, { allowUnboundPq: true })).toBeNull();
    expect(resolvePqVerifyKey(vPub, '', { allowUnboundPq: true })).toBeNull();
    expect(resolvePqVerifyKey('constructor', key, { pqPins: {} })).toBeNull();
    expect(resolvePqVerifyKey(vPub, key, undefined)).toBeNull();
  });

  it('verifyLeafSuite takes the opaque key, never the artifact pq_pk string', () => {
    const s = signSuiteArtifact(ML, { mlDsa: aMl }, msg);
    expect(verifyLeafSuite({ alg: ML, holder: aPub, message: msg, sig: s.sig })).toBe(false); // no key at all
    const k = resolvePqVerifyKey(aPub, s.pq_pk, { holderPq: holderPqCommitment(s.pq_pk!) })!;
    expect(verifyLeafSuite({ alg: ML, holder: aPub, pq: k, message: msg, sig: s.sig })).toBe(true);
    expect(verifyLeafSuite({ alg: ML, holder: aPub, pq: k, message: utf8('other'), sig: s.sig })).toBe(false);
  });
});

describe('R3-06: pq binding v2 (epoch + audience)', () => {
  const sk = victim.secretKey;
  it('a binding yields a pin only for its audience, with a positive epoch, and a well-formed registered-suite key', () => {
    const b = signPqBinding(sk, vPub, pk(vMl), 1, 'ins_a');
    expect(pqPinFor(b, 'ins_a')).toEqual({ [vPub]: pk(vMl) });
    expect(pqPinFor(b, 'ins_b')).toBeNull(); // another instance
    expect(pqPinFor({ ...b, epoch: 2 }, 'ins_a')).toBeNull(); // epoch is signed
    expect(pqPinFor({ ...b, epoch: 0 }, 'ins_a')).toBeNull();
    expect(pqPinFor({ ...b, epoch: 1.5 }, 'ins_a')).toBeNull();
    expect(pqPinFor({ ...b, aud: 'ins_b' }, 'ins_b')).toBeNull(); // aud is signed
    expect(pqPinFor(signPqBinding(sk, vPub, 'AAAA', 1, 'ins_a'), 'ins_a')).toBeNull(); // junk key even when signed
    expect(pqPinFor(signPqBinding(sk, vPub, 'not base64url!', 1, 'ins_a'), 'ins_a')).toBeNull();
    expect(pqPinFor(b, '')).toBeNull();
    expect(() => signPqBinding(sk, vPub, pk(vMl), 0, 'ins_a')).toThrow();
    expect(() => signPqBinding(sk, vPub, pk(vMl), 1, '')).toThrow();
  });
  it('capHash is unaffected (sanity: the pure root hash differs per signer key)', () => {
    expect(capHash(forgedRoot())).not.toBe(capHash(genuineRoot(ML)));
  });
});

describe('R3-01: verifyPinnedSuite forwards only pqPins / allowUnboundPq', () => {
  it('an options object carrying trustedPk or holderPq cannot authorise an artifact key', () => {
    const msg = utf8('m');
    const s = signSuiteArtifact(ML, { edSecret: atk.secretKey, mlDsa: aMl }, msg);
    const opts = { trustedPk: s.pq_pk, holderPq: holderPqCommitment(s.pq_pk!) } as never;
    expect(verifyPinnedSuite(ML, vPub, s.pq_pk, msg, s, opts)).toBe(false);
    expect(verifyPinnedSuite(ML, vPub, s.pq_pk, msg, s, { pqPins: { [vPub]: s.pq_pk! } })).toBe(true);
  });
});
