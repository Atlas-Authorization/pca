import { describe, expect, it } from 'vitest';
import { attenuate, delegate } from './capability';
import { mintGrant } from './envelope';
import { b64u, utf8 } from './hash';
import { encodeKey, generateKeyPair, sign } from './keys';
import { commitPlan, type PlanNode } from './merkle';
import { buildPCActn, thresholdMessage, verifyPCActnCore } from './pcactn';
import { DEFAULT_RISK_POLICY } from './risk';
import {
  type Signer,
  assembleThreshold,
  createThresholdVerifier,
  signShare,
  verifyThreshold,
} from './threshold';

const NOW = Date.now();
const MSG = utf8('the-same-canonical-message');

function keys() {
  return {
    agent: generateKeyPair(),
    guardian: generateKeyPair(),
    principal: generateKeyPair(),
  };
}

describe('verifyThreshold (t-of-n multi-signature)', () => {
  it('t=1 agent-only passes (v2.1: the agent share is signerSetHash‖t-bound like every role)', () => {
    const { agent } = keys();
    const signerSet: Signer[] = [{ role: 'agent', publicKey: encodeKey(agent.publicKey) }];
    const sig = assembleThreshold([signShare('agent', agent.secretKey, MSG, { signerSet, t: 1 })]);
    const r = verifyThreshold(sig, MSG, signerSet, 1);
    expect(r.ok).toBe(true);
    expect(r.count).toBe(1);
    expect(r.roles).toEqual(['agent']);
  });

  it('t=2 requires a second valid role', () => {
    const { agent, guardian } = keys();
    const signerSet: Signer[] = [
      { role: 'agent', publicKey: encodeKey(agent.publicKey) },
      { role: 'guardian', publicKey: encodeKey(guardian.publicKey) },
    ];
    const agentOnly = assembleThreshold([signShare('agent', agent.secretKey, MSG, { signerSet, t: 2 })]);
    expect(verifyThreshold(agentOnly, MSG, signerSet, 2).ok).toBe(false);

    const both = assembleThreshold([
      signShare('agent', agent.secretKey, MSG, { signerSet, t: 2 }),
      signShare('guardian', guardian.secretKey, MSG, { signerSet, t: 2 }),
    ]);
    const r = verifyThreshold(both, MSG, signerSet, 2);
    expect(r.ok).toBe(true);
    expect(r.count).toBe(2);
    expect(new Set(r.roles)).toEqual(new Set(['agent', 'guardian']));
  });

  it('insufficient shares fail with a reason', () => {
    const { agent, guardian, principal } = keys();
    const signerSet: Signer[] = [
      { role: 'agent', publicKey: encodeKey(agent.publicKey) },
      { role: 'guardian', publicKey: encodeKey(guardian.publicKey) },
      { role: 'principal', publicKey: encodeKey(principal.publicKey) },
    ];
    const two = assembleThreshold([
      signShare('agent', agent.secretKey, MSG, { signerSet, t: 3 }),
      signShare('guardian', guardian.secretKey, MSG, { signerSet, t: 3 }),
    ]);
    const r = verifyThreshold(two, MSG, signerSet, 3);
    expect(r.ok).toBe(false);
    expect(r.count).toBe(2);
    expect(r.reason).toMatch(/need 3/);
  });

  it('a duplicate role does not double-count', () => {
    const { agent } = keys();
    const signerSet: Signer[] = [{ role: 'agent', publicKey: encodeKey(agent.publicKey) }];
    const dup = assembleThreshold([
      signShare('agent', agent.secretKey, MSG, { signerSet, t: 2 }),
      signShare('agent', agent.secretKey, MSG, { signerSet, t: 2 }),
    ]);
    const r = verifyThreshold(dup, MSG, signerSet, 2);
    expect(r.ok).toBe(false);
    expect(r.count).toBe(1);
    expect(r.roles).toEqual(['agent']);
  });

  it('a share signed by a key not in the signer set is rejected', () => {
    const { agent, guardian } = keys();
    const impostor = generateKeyPair();
    const signerSet: Signer[] = [
      { role: 'agent', publicKey: encodeKey(agent.publicKey) },
      { role: 'guardian', publicKey: encodeKey(guardian.publicKey) },
    ];
    // guardian-role share, but signed by an unregistered key.
    const sig = assembleThreshold([
      signShare('agent', agent.secretKey, MSG, { signerSet, t: 2 }),
      signShare('guardian', impostor.secretKey, MSG, { signerSet, t: 2 }),
    ]);
    const r = verifyThreshold(sig, MSG, signerSet, 2);
    expect(r.ok).toBe(false);
    expect(r.count).toBe(1);
    expect(r.reason).toMatch(/not registered/);
  });

  it('a share over a tampered message is rejected', () => {
    const { agent, guardian } = keys();
    const signerSet: Signer[] = [
      { role: 'agent', publicKey: encodeKey(agent.publicKey) },
      { role: 'guardian', publicKey: encodeKey(guardian.publicKey) },
    ];
    const sig = assembleThreshold([
      signShare('agent', agent.secretKey, MSG, { signerSet, t: 2 }),
      // guardian signed a DIFFERENT message than the one being verified.
      signShare('guardian', guardian.secretKey, utf8('a-different-message'), { signerSet, t: 2 }),
    ]);
    const r = verifyThreshold(sig, MSG, signerSet, 2);
    expect(r.ok).toBe(false);
    expect(r.count).toBe(1);
    expect(r.roles).toEqual(['agent']);
    expect(r.reason).toMatch(/invalid signature/);
  });

  it('role-binding: a guardian share cannot be replayed as a principal share, at another t, or in another signer set', () => {
    const { agent, guardian, principal } = keys();
    const mk = (role: 'agent' | 'guardian' | 'principal', k: { publicKey: Uint8Array }) => ({ role, publicKey: encodeKey(k.publicKey) });
    const signerSet: Signer[] = [mk('agent', agent), mk('guardian', guardian), mk('principal', principal)];
    // v2.1: the agent share is signerSetHash‖t-bound too, so it is also t-specific.
    const agent2 = signShare('agent', agent.secretKey, MSG, { signerSet, t: 2 });
    const agent3 = signShare('agent', agent.secretKey, MSG, { signerSet, t: 3 });
    // same key re-labelled with another role is not registered for it
    const g3 = signShare('guardian', guardian.secretKey, MSG, { signerSet, t: 3 });
    const asPrincipal = { ...g3, role: 'principal' as const };
    expect(verifyThreshold(assembleThreshold([agent2, asPrincipal]), MSG, signerSet, 2).ok).toBe(false);
    // a share minted for t=3 does not verify at t=2 (and vice versa)
    expect(verifyThreshold(assembleThreshold([agent2, g3]), MSG, signerSet, 2).ok).toBe(false);
    expect(verifyThreshold(assembleThreshold([agent3, g3]), MSG, signerSet, 3).count).toBe(2);
    // a share minted for a different signer set does not verify
    const other = [...signerSet.slice(0, 2), mk('principal', generateKeyPair())];
    const gOther = signShare('guardian', guardian.secretKey, MSG, { signerSet: other, t: 2 });
    expect(verifyThreshold(assembleThreshold([agent2, gOther]), MSG, signerSet, 2).ok).toBe(false);
    // the signer-set hash is order-insensitive
    const gRev = signShare('guardian', guardian.secretKey, MSG, { signerSet: [...signerSet].reverse(), t: 2 });
    expect(verifyThreshold(assembleThreshold([agent2, gRev]), MSG, signerSet, 2).ok).toBe(true);
    // v2.1: the agent share minted for t=2 does NOT verify at t=3 (binding is symmetric with the others)
    expect(verifyThreshold(assembleThreshold([agent2, g3]), MSG, signerSet, 3).roles).not.toContain('agent');
    // EVERY role's explicit share (agent included) requires a binding
    expect(() => signShare('guardian', guardian.secretKey, MSG)).toThrow(/bind/);
    expect(() => signShare('agent', agent.secretKey, MSG)).toThrow(/bind/);
  });

  it('signer set must give each role ONE key and no key two roles (holder==principal collapse); t in {1,2,3}', () => {
    const { agent, guardian } = keys();
    const a = encodeKey(agent.publicKey);
    const collapsed: Signer[] = [{ role: 'agent', publicKey: a }, { role: 'principal', publicKey: a }];
    const sig = assembleThreshold([signShare('agent', agent.secretKey, MSG, { signerSet: collapsed, t: 2 }), signShare('principal', agent.secretKey, MSG, { signerSet: collapsed, t: 2 })]);
    const r = verifyThreshold(sig, MSG, collapsed, 2);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/two roles/);
    const twoKeys: Signer[] = [{ role: 'agent', publicKey: a }, { role: 'agent', publicKey: encodeKey(guardian.publicKey) }];
    expect(verifyThreshold(assembleThreshold([]), MSG, twoKeys, 1).reason).toMatch(/more than one key/);
    const ok: Signer[] = [{ role: 'agent', publicKey: a }];
    const one = assembleThreshold([signShare('agent', agent.secretKey, MSG, { signerSet: ok, t: 1 })]);
    for (const bad of [0, 4, 1.5, NaN, Infinity, -1]) expect(verifyThreshold(one, MSG, ok, bad).ok).toBe(false);
    expect(verifyThreshold(one, MSG, ok, 1).ok).toBe(true);
  });

  it('counts distinct KEYS: a duplicated share (same key, relabelled or repeated) never double-counts', () => {
    const { agent, guardian } = keys();
    const signerSet: Signer[] = [
      { role: 'agent', publicKey: encodeKey(agent.publicKey) },
      { role: 'guardian', publicKey: encodeKey(guardian.publicKey) },
    ];
    const g = signShare('guardian', guardian.secretKey, MSG, { signerSet, t: 2 });
    const r = verifyThreshold(assembleThreshold([g, g, { ...g, role: 'agent' }]), MSG, signerSet, 2);
    expect(r.count).toBe(1);
    expect(r.ok).toBe(false);
  });

  it('never throws on garbage input', () => {
    expect(() => verifyThreshold({ shares: undefined } as never, MSG, undefined as never, 1)).not.toThrow();
    const r = verifyThreshold({ shares: [{} as never] }, MSG, [], 1);
    expect(r.ok).toBe(false);
  });

  it('v2.1 agent-leaf binding: a bound agent share verifies; the OLD bare-message agent share is rejected', () => {
    const { agent, guardian } = keys();
    const signerSet: Signer[] = [
      { role: 'agent', publicKey: encodeKey(agent.publicKey) },
      { role: 'guardian', publicKey: encodeKey(guardian.publicKey) },
    ];
    // Positive: the new signerSetHash‖t-bound agent share verifies.
    const bound = signShare('agent', agent.secretKey, MSG, { signerSet, t: 1 });
    expect(verifyThreshold(assembleThreshold([bound]), MSG, signerSet, 1).ok).toBe(true);
    // Negative: the OLD bare-message agent share (sig over `message` itself) is REJECTED — reconstruct the
    // pre-v2.1 wire form by hand (signShare no longer produces it).
    const bare = { role: 'agent' as const, publicKey: encodeKey(agent.publicKey), sig: b64u(sign(agent.secretKey, MSG)) };
    expect(verifyThreshold(assembleThreshold([bare]), MSG, signerSet, 1).ok).toBe(false);
    // Replay defence: a bound agent share for signer set A does not verify in signer set B.
    const other: Signer[] = [{ role: 'agent', publicKey: encodeKey(agent.publicKey) }, { role: 'guardian', publicKey: encodeKey(generateKeyPair().publicKey) }];
    expect(verifyThreshold(assembleThreshold([bound]), MSG, other, 1).roles).not.toContain('agent');
  });
});

// ---- integration with the PCActn object + verifyPCActnCore hook --------------------------

function buildLoop() {
  const P = generateKeyPair(); // principal (device share)
  const A = generateKeyPair(); // agent (leaf holder)
  const guardian = generateKeyPair(); // guardian (Policy VM cosigner)
  const { grant } = mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'secure my account',
    envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  });
  // Chain: grant (holder A) -> attenuate (still A) == leaf holder is the agent key.
  const c1 = attenuate(grant, [{ type: 'task' }], A.secretKey);
  const nodes: PlanNode[] = [
    { id: 'n1', verb: 'list_sessions', resource: 'sessions', reversibility_class: 'R0' },
  ];
  // Each PCActn is freshly SIGNED, so the agent-leaf `sig` always covers the right canonical message.
  const mkActn = (r: number) =>
    buildPCActn({ aud: 'test-aud',
      now: NOW,
      grant,
      chain: [grant, c1],
      plan: nodes,
      nodeId: 'n1',
      counter: 1,
      signerSecret: A.secretKey, // the agent leaf signs `sig`
      riskClaim: { r, inputs: {} },
    });
  const pcactn = mkActn(0.1);
  const signerSet: Signer[] = [
    { role: 'agent', publicKey: c1.holder },
    { role: 'guardian', publicKey: encodeKey(guardian.publicKey) },
    { role: 'principal', publicKey: encodeKey(P.publicKey) },
  ];
  return { grant, pcactn, mkActn, signerSet, P, A, guardian, c1 };
}

describe('createThresholdVerifier + PCActn', () => {
  it('t=1: the agent-leaf baseline (sig only, no threshold field) passes', async () => {
    const { grant, pcactn, signerSet } = buildLoop();
    const verifier = createThresholdVerifier({ signerSet, t: 1 });
    const res = await verifyPCActnCore(pcactn, { grant, audience: 'test-aud', nowEpoch: NOW, hooks: { threshold: verifier } });
    expect(res.allow).toBe(true);
    expect(res.checks.threshold).toBe('pass');
  });

  it('t=2: fails with the agent leaf alone, passes once a guardian share is added', async () => {
    const { grant, pcactn, signerSet, guardian } = buildLoop();
    const verifier = createThresholdVerifier({ signerSet, t: 2 });

    const fail = await verifyPCActnCore(pcactn, { grant, audience: 'test-aud', nowEpoch: NOW, hooks: { threshold: verifier } });
    expect(fail.allow).toBe(false);
    expect(fail.checks.threshold).toBe('fail');
    expect(fail.reason).toMatch(/threshold|need 2/);

    // Guardian co-signs the SAME canonical message via thresholdMessage().
    const guardianShare = signShare('guardian', guardian.secretKey, thresholdMessage(pcactn), { signerSet, t: 2 });
    const withGuardian = { ...pcactn, threshold: assembleThreshold([guardianShare]) };
    const ok = await verifyPCActnCore(withGuardian, { grant, audience: 'test-aud', nowEpoch: NOW, hooks: { threshold: verifier } });
    expect(ok.allow).toBe(true);
    expect(ok.checks.threshold).toBe('pass');
  });

  it('t=3: requires agent + guardian + principal shares', async () => {
    const { grant, pcactn, signerSet, guardian, P } = buildLoop();
    const verifier = createThresholdVerifier({ signerSet, t: 3 });

    const msg = thresholdMessage(pcactn);
    const bind = { signerSet, t: 3 };
    const twoShares = { ...pcactn, threshold: assembleThreshold([signShare('guardian', guardian.secretKey, msg, bind)]) };
    expect((await verifyPCActnCore(twoShares, { grant, audience: 'test-aud', nowEpoch: NOW, hooks: { threshold: verifier } })).checks.threshold).toBe('fail');

    const threeShares = {
      ...pcactn,
      threshold: assembleThreshold([
        signShare('guardian', guardian.secretKey, msg, bind),
        signShare('principal', P.secretKey, msg, bind),
      ]),
    };
    const res = await verifyPCActnCore(threeShares, { grant, audience: 'test-aud', nowEpoch: NOW, hooks: { threshold: verifier } });
    expect(res.allow).toBe(true);
    expect(res.checks.threshold).toBe('pass');
  });

  it('threshold is not-enforced when no verifier hook is supplied (unchanged M0 behavior)', async () => {
    const { grant, pcactn } = buildLoop();
    const res = await verifyPCActnCore(pcactn, { grant, audience: 'test-aud', nowEpoch: NOW });
    expect(res.allow).toBe(true);
    expect(res.checks.threshold).toBe('not-enforced');
  });

  it('risk-derived t: low-r action needs only the agent; a high-r claim demands more shares', async () => {
    const { grant, pcactn, mkActn, signerSet, guardian } = buildLoop();
    // default resolver reads risk_claim.r against the grant's risk_policy.
    const verifier = createThresholdVerifier({ signerSet });

    // r = 0.1 <= theta1 (0.25) => t=1 => agent leaf alone suffices.
    expect((await verifyPCActnCore(pcactn, { grant, audience: 'test-aud', nowEpoch: NOW, hooks: { threshold: verifier } })).checks.threshold).toBe('pass');

    // A properly-signed high-r action: r = 0.5 > theta1 so t climbs to 2; agent leaf alone fails.
    const highR = mkActn(0.5);
    expect((await verifyPCActnCore(highR, { grant, audience: 'test-aud', nowEpoch: NOW, hooks: { threshold: verifier } })).checks.threshold).toBe('fail');

    // Adding a guardian share over highR's canonical message satisfies t=2.
    const withGuardian = {
      ...highR,
      threshold: assembleThreshold([signShare('guardian', guardian.secretKey, thresholdMessage(highR), { signerSet, t: 2 })]),
    };
    expect((await verifyPCActnCore(withGuardian, { grant, audience: 'test-aud', nowEpoch: NOW, hooks: { threshold: verifier } })).checks.threshold).toBe('pass');
  });
});
