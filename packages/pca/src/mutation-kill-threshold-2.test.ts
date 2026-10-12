/** Second round of threshold.ts mutation-kill tests (each test names the guard it pins). */
import { describe, expect, it } from 'vitest';
import { b64u, utf8 } from './hash';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair, sign } from './keys';
import { buildPCActn, signPCActnSuite } from './pcactn';
import { DEFAULT_RISK_POLICY } from './risk';
import { signShare, verifyThreshold, type Signer } from './threshold';

const MSG = utf8('mk2');
const enc = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);
const trio = () => {
  const agent = generateKeyPair(), guardian = generateKeyPair(), principal = generateKeyPair();
  const set: Signer[] = [
    { role: 'agent', publicKey: enc(agent) },
    { role: 'guardian', publicKey: enc(guardian) },
    { role: 'principal', publicKey: enc(principal) },
  ];
  return { agent, guardian, principal, set };
};

describe('verifyThreshold guards, round 2', () => {
  it('a non-array signer set is an EMPTY set (not malformed): no key can satisfy t', () => {
    for (const bad of [undefined, null, 'x', 7, {}] as unknown as Signer[][]) {
      expect(verifyThreshold({ shares: [] }, MSG, bad as never, 1)).toEqual({ ok: false, count: 0, roles: [], reason: 'only 0 distinct valid key(s), need 1' });
    }
  });
  it('a share with a non-string role is "malformed share" (not "role not in the signer set")', () => {
    const { agent, set } = trio();
    const good = signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 1 });
    const v = verifyThreshold({ shares: [{ ...good, role: 123 as never }] }, MSG, set, 1);
    expect(v).toEqual({ ok: false, count: 0, roles: [], reason: 'malformed share' });
  });
  it('a share with a non-string publicKey is "malformed share" (not "key not registered")', () => {
    const { agent, set } = trio();
    const good = signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 1 });
    const v = verifyThreshold({ shares: [{ ...good, publicKey: 5 as never }] }, MSG, set, 1);
    expect(v.reason).toBe('malformed share');
  });
  it('a share with a non-string sig never throws and reports an invalid signature', () => {
    const { agent, set } = trio();
    const good = signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 1 });
    for (const s of [undefined, 5, null, {}, []]) {
      const v = verifyThreshold({ shares: [{ ...good, sig: s as never }] }, MSG, set, 1);
      expect(v).toEqual({ ok: false, count: 0, roles: [], reason: 'invalid signature for role agent' });
    }
  });
  it('baseline: a valid signature by the registered agent does NOT admit a baseline whose declared holder is another key', () => {
    const { agent, guardian, set } = trio();
    const sigByAgent = b64u(sign(agent.secretKey, MSG));
    const v = verifyThreshold({ shares: [] }, MSG, set, 1, { holder: enc(guardian), sig: sigByAgent });
    expect(v).toEqual({ ok: false, count: 0, roles: [], reason: 'only 0 distinct valid key(s), need 1' });
    // sanity: the same signature with the right holder is admitted
    expect(verifyThreshold({ shares: [] }, MSG, set, 1, { holder: enc(agent), sig: sigByAgent })).toEqual({ ok: true, count: 1, roles: ['agent'] });
  });
  it('baseline with an explicit valid agent share: roles lists agent exactly once', () => {
    const { agent, set } = trio();
    const explicit = signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 1 });
    const v = verifyThreshold({ shares: [explicit] }, MSG, set, 1, { holder: enc(agent), sig: b64u(sign(agent.secretKey, MSG)) });
    expect(v).toEqual({ ok: true, count: 1, roles: ['agent'] });
  });
});

import { holderPqCommitment } from './capability';
import { encodeMlDsaPublicKey, mlDsa65Keygen, signWithSuite } from './pq';
import { createThresholdVerifier } from './threshold';

describe('verifyThreshold: F-2 binding of the agent baseline PQ key', () => {
  const ALG = 'hybrid-ed25519-ml-dsa-65';
  const rnd = () => crypto.getRandomValues(new Uint8Array(32));
  const setup = (register: boolean) => {
    const { agent, guardian, principal } = trio();
    const real = mlDsa65Keygen(rnd());
    const attacker = mlDsa65Keygen(rnd());
    const realPk = encodeMlDsaPublicKey(real.publicKey);
    const set: Signer[] = [
      { role: 'agent', publicKey: enc(agent), ...(register ? { pq_pk: realPk } : {}) },
      { role: 'guardian', publicKey: enc(guardian) },
      { role: 'principal', publicKey: enc(principal) },
    ];
    const base = (kp: typeof real, over: Record<string, unknown> = {}) => {
      const parts = signWithSuite(ALG, { edSecret: agent.secretKey, mlDsa: kp }, MSG);
      return { holder: enc(agent), sig: parts.sig, alg: ALG, pqPk: encodeMlDsaPublicKey(kp.publicKey), pqSig: parts.pq_sig, ...over };
    };
    return { set, real, attacker, realPk, base };
  };
  const NONE = { ok: false, count: 0, roles: [] as string[], reason: 'only 0 distinct valid key(s), need 1' };

  it('registered agent pq_pk: admitted with the registered key even when the artifact carries no pq_pk', () => {
    const s = setup(true);
    expect(verifyThreshold({ shares: [] }, MSG, s.set, 1, s.base(s.real, { pqPk: undefined }))).toEqual({ ok: true, count: 1, roles: ['agent'] });
  });
  it('registered agent pq_pk: the REGISTERED key is used, an attacker pq_pk in the artifact is ignored', () => {
    const s = setup(true);
    expect(verifyThreshold({ shares: [] }, MSG, s.set, 1, s.base(s.attacker))).toEqual(NONE);
    // attacker signs but names the real key: the signature does not verify under it
    expect(verifyThreshold({ shares: [] }, MSG, s.set, 1, s.base(s.attacker, { pqPk: s.realPk }))).toEqual(NONE);
  });
  it('unregistered: admitted only if holder_pq commits to the artifact pq_pk', () => {
    const s = setup(false);
    const b = s.base(s.real);
    expect(verifyThreshold({ shares: [] }, MSG, s.set, 1, { ...b, holderPq: holderPqCommitment(s.realPk) })).toEqual({ ok: true, count: 1, roles: ['agent'] });
    expect(verifyThreshold({ shares: [] }, MSG, s.set, 1, { ...b, holderPq: holderPqCommitment(encodeMlDsaPublicKey(s.attacker.publicKey)) })).toEqual(NONE);
    expect(verifyThreshold({ shares: [] }, MSG, s.set, 1, b)).toEqual(NONE); // no commitment at all
  });
  it('unregistered and uncommitted: allowUnboundPq is the loud legacy opt-out', () => {
    const s = setup(false);
    const b = s.base(s.real);
    expect(verifyThreshold({ shares: [] }, MSG, s.set, 1, { ...b, allowUnboundPq: true })).toEqual({ ok: true, count: 1, roles: ['agent'] });
    expect(verifyThreshold({ shares: [] }, MSG, s.set, 1, { ...b, allowUnboundPq: false })).toEqual(NONE);
  });
  it('createThresholdVerifier forwards allowUnboundPq and the leaf holder_pq commitment (real hybrid PCActn)', () => {
    const P = generateKeyPair();
    const A = generateKeyPair();
    const pq = mlDsa65Keygen(rnd());
    const mk = (bind: boolean) => {
      const { grant } = mintGrant({
        principalSecret: P.secretKey, principalPublic: enc(P), holder: enc(A), goal: 'g',
        ...(bind ? { holderPq: encodeMlDsaPublicKey(pq.publicKey) } : {}),
        envelope: { predicates: [{ verb: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
      });
      const legit = buildPCActn({ aud: 'x', now: 1_800_000_000_000, grant, chain: [grant], plan: [{ id: 'n1', verb: 'v', resource: 'r', reversibility_class: 'reversible' }], nodeId: 'n1', counter: 1, signerSecret: A.secretKey, riskClaim: { r: 0, inputs: {} } });
      const { sig: _s, ...body } = legit as never as Record<string, unknown>;
      const p = signPCActnSuite(body as never, { alg: 'hybrid-ed25519-ml-dsa-65', edLeafSecret: A.secretKey, mlDsa: pq });
      return { p, grant };
    };
    const signerSet: Signer[] = [{ role: 'agent', publicKey: enc(A) }];
    const run = (bind: boolean, extra: object) => {
      const { p, grant } = mk(bind);
      return createThresholdVerifier({ signerSet, t: 1, ...extra })({ pcactn: p, grant, nowEpoch: 1 }) as { ok: boolean; reason?: string };
    };
    expect(run(true, {}).ok).toBe(true);
    expect(run(false, {}).ok).toBe(false);
    expect(run(false, { allowUnboundPq: false }).ok).toBe(false);
    expect(run(false, { allowUnboundPq: true }).ok).toBe(true);
  });
});

describe('verifyThreshold: registered pq_pk shape is validated fail-closed and never throws', () => {
  it.each([['!!not-b64u!!'], [123], [null], [{}], ['AAAA'], ['']])('pq_pk %j is a malformed signer set', (bad) => {
    const { agent } = trio();
    const set = [{ role: 'agent', publicKey: enc(agent), pq_pk: bad }] as unknown as Signer[];
    expect(verifyThreshold({ shares: [] }, MSG, set, 1)).toEqual({ ok: false, count: 0, roles: [], reason: 'malformed signer set (pq_pk)' });
  });
});
