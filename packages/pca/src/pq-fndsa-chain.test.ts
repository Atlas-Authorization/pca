import { describe, expect, it } from 'vitest';
import { delegate, verifyChain } from './capability';
import { b64u } from './hash';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { buildPCActn, signPCActnSuite } from './pcactn';
import {
  type FnDsaSuiteKey,
  type SigAlg,
  encodeFnDsaPublicKey,
  fnDsa1024Keygen,
  fnDsa512Keygen,
  isFnDsaBackendActive,
} from './pq';
import { buildQuorumSet, quorumActionDigest, assembleQuorumProof, signQuorumShare, verifyQuorum } from './pq-threshold';
import { DEFAULT_RISK_POLICY } from './risk';
import { verifyPCActn as verifyPCActn05 } from './server/verify';
const verifyPCActn = (p: Parameters<typeof verifyPCActn05>[0], o: Parameters<typeof verifyPCActn05>[1]): ReturnType<typeof verifyPCActn05> => verifyPCActn05(p, 'require' in o ? o : Object.create(o, { require: { value: [], enumerable: true } })); // report-only: these tests are not about the 0.5 default required checks (see breaking-05.test.ts)


/** FN-DSA (Falcon, FIPS 206) on capability hops, the PCActn leaf and quorum shares, with the same F-2/F-4 rules as ML-DSA. */
const NOW = Date.now();
const safeRisk = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
const seed = () => crypto.getRandomValues(new Uint8Array(32));

type Variant = { alg: 'fn-dsa-512' | 'fn-dsa-1024'; field: 'fnDsa512' | 'fnDsa1024'; gen: (s: Uint8Array) => { verifyingKey: Uint8Array; signingKey: Uint8Array } };
const VARIANTS: Variant[] = [
  { alg: 'fn-dsa-512', field: 'fnDsa512', gen: fnDsa512Keygen },
  { alg: 'fn-dsa-1024', field: 'fnDsa1024', gen: fnDsa1024Keygen },
];
const key = (v: Variant): FnDsaSuiteKey => ({ ...v.gen(seed()), signSeed: seed() });

describe('FN-DSA backend', () => {
  it('is active (else these tests are meaningless)', () => expect(isFnDsaBackendActive()).toBe(true));
});

describe.each(VARIANTS)('$alg on capability chains and PCActn leaf', (v) => {
  function setup(bindPq: boolean) {
    const P = generateKeyPair();
    const A = generateKeyPair();
    const agent = key(v);
    const { grant } = mintGrant({
      principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), goal: 'g',
      ...(bindPq ? { holderPq: encodeFnDsaPublicKey(agent.verifyingKey) } : {}),
      envelope: { predicates: [{ verb: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
    });
    const nodes = [{ id: 'n1', verb: 'wire', resource: 'bank', reversibility_class: 'reversible' }];
    const body = (): never => {
      const legit = buildPCActn({ aud: 'x', now: NOW, grant, chain: [grant], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: A.secretKey, riskClaim: { r: 0, inputs: {} } });
      const { sig: _s, ...b } = legit as never as Record<string, unknown>;
      return b as never;
    };
    const verify = (p: unknown, extra: Record<string, unknown> = {}) =>
      verifyPCActn(p as never, { grant, audience: 'x', now: NOW, context: { risk: safeRisk, budget: { B: 1, tau: NOW } }, ...extra });
    return { A, agent, grant, body, verify };
  }

  it('delegate hop with holder_pq binding verifies; carries alg + pq_pk', () => {
    const s = setup(true);
    const sub = generateKeyPair();
    const hop = delegate(s.grant, encodeKey(sub.publicKey), [{ type: 'task' }], s.A.secretKey, { alg: v.alg, [v.field]: s.agent });
    expect(hop.alg).toBe(v.alg);
    expect(hop.pq_pk).toBe(encodeFnDsaPublicKey(s.agent.verifyingKey));
    expect(verifyChain([s.grant, hop], s.grant.issuer)).toEqual({ ok: true });
  });

  it('wrong (unbound) fn-dsa key on a hop is rejected; allowUnboundPq is the loud opt-out', () => {
    const s = setup(true);
    const sub = generateKeyPair();
    const bad = delegate(s.grant, encodeKey(sub.publicKey), [{ type: 'task' }], s.A.secretKey, { alg: v.alg, [v.field]: key(v) });
    expect(verifyChain([s.grant, bad], s.grant.issuer).ok).toBe(false);
    expect(verifyChain([s.grant, bad], s.grant.issuer, { allowUnboundPq: true }).ok).toBe(true);
  });

  it('a holder with no committed PQ key cannot present an fn-dsa hop', () => {
    const s = setup(false);
    const sub = generateKeyPair();
    const hop = delegate(s.grant, encodeKey(sub.publicKey), [{ type: 'task' }], s.A.secretKey, { alg: v.alg, [v.field]: key(v) });
    expect(verifyChain([s.grant, hop], s.grant.issuer).ok).toBe(false);
  });

  it('tampered hop sig / swapped pq_pk is rejected; allowedSuites excludes it', () => {
    const s = setup(true);
    const sub = generateKeyPair();
    const hop = delegate(s.grant, encodeKey(sub.publicKey), [{ type: 'task' }], s.A.secretKey, { alg: v.alg, [v.field]: s.agent });
    const raw = Buffer.from(hop.sig, 'base64url');
    raw[raw.length - 1]! ^= 1;
    expect(verifyChain([s.grant, { ...hop, sig: b64u(raw) }], s.grant.issuer).ok).toBe(false);
    const other = encodeFnDsaPublicKey(key(v).verifyingKey);
    expect(verifyChain([s.grant, { ...hop, pq_pk: other }], s.grant.issuer).ok).toBe(false);
    expect(verifyChain([s.grant, hop], s.grant.issuer, { allowedSuites: ['ed25519'] }).ok).toBe(false);
  });

  it('missing key material throws a typed error naming the fn-dsa family', () => {
    const s = setup(true);
    expect(() => delegate(s.grant, s.grant.holder, [], s.A.secretKey, { alg: v.alg })).toThrow(new RegExp(`requires an ${v.field} key`));
    expect(() => signPCActnSuite(s.body(), { alg: v.alg })).toThrow(new RegExp(`requires ${v.field} key material`));
  });

  it('PCActn leaf under the holder\'s committed fn-dsa key is accepted; allowedSuites can deny', async () => {
    const s = setup(true);
    const ok = signPCActnSuite(s.body(), { alg: v.alg, [v.field]: s.agent });
    const r = await s.verify(ok);
    expect(r.checks.leaf_signature, r.reasons.join('|')).toBe('pass');
    expect(r.allow).toBe(true);
    const denied = await s.verify(ok, { allowedSuites: ['ed25519'] });
    expect(denied.allow).toBe(false);
  });

  it('PCActn leaf: forged fn-dsa key, unbound holder, and tampered sig are rejected', async () => {
    const s = setup(true);
    const forged = signPCActnSuite(s.body(), { alg: v.alg, [v.field]: key(v) });
    expect((await s.verify(forged)).checks.leaf_signature).toBe('fail');
    const un = setup(false);
    const f2 = signPCActnSuite(un.body(), { alg: v.alg, [v.field]: key(v) });
    expect((await un.verify(f2)).allow).toBe(false);
    const good = signPCActnSuite(s.body(), { alg: v.alg, [v.field]: s.agent });
    const raw = Buffer.from(good.sig, 'base64url');
    raw[raw.length - 1]! ^= 1;
    expect((await s.verify({ ...good, sig: b64u(raw) })).allow).toBe(false);
  });
});

describe.each(VARIANTS)('$alg quorum shares', (v) => {
  it('t-of-n quorum with fn-dsa signers: t passes, t-1 fails, wrong key fails', () => {
    const ks = [key(v), key(v), key(v)];
    const set = buildQuorumSet(ks.map((k) => ({ alg: v.alg as SigAlg, keys: { [`${v.field}Pub`]: encodeFnDsaPublicKey(k.verifyingKey) } })), 2);
    expect(set.ok).toBe(true);
    if (!set.ok) return;
    const action = quorumActionDigest(new TextEncoder().encode('transfer'));
    const secretFor = (i: number) => ks.find((k) => encodeFnDsaPublicKey(k.verifyingKey) === set.set.signers[i]!.pq)!;
    const share = (i: number, k = secretFor(i)) => signQuorumShare(set.set, i, 0, action, { [v.field]: k } as never);
    const run = (shares: ReturnType<typeof share>[]) => verifyQuorum({ set: set.set, proof: assembleQuorumProof(set.set, shares), epoch: 0, actionDigest: action });
    expect(run([share(0), share(1)]).ok).toBe(true);
    expect(run([share(0)]).ok).toBe(false);
    expect(run([share(0), share(1, key(v))]).ok).toBe(false);
  });
});
