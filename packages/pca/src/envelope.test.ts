import { describe, expect, it } from 'vitest';
import { goalCommitOf, mintGrant, readEnvelope, verifyGoalCommit, type Envelope } from './envelope';
import { verifyChain, attenuate, type Capability } from './capability';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY } from './risk';

function setup() {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const envelope: Omit<Envelope, 'goal_commit'> = {
    predicates: [{ verb: 'revoke_session', where: [{ field: 'action.params.device', op: 'ne', ref: 'env.current_device' }] }],
    caveats: [{ type: 'expires', at: 9e12 }, { type: 'rate', max: 10, per_secs: 3600 }],
    agent_binding: { model_allowlist: ['m1'], operator: undefined },
    risk_policy: DEFAULT_RISK_POLICY,
  };
  const out = mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    envelope,
    goal: 'secure my account',
    salt: 'fixed-salt',
  });
  return { P, A, envelope, ...out };
}

describe('envelope / grant', () => {
  it('mint -> read roundtrip', () => {
    const { grant, envelope, goalCommit } = setup();
    const e = readEnvelope(grant)!;
    expect(e.goal_commit).toBe(goalCommit);
    expect(e.predicates).toEqual(envelope.predicates);
    expect(e.caveats).toEqual(envelope.caveats);
    expect(e.agent_binding).toEqual({ model_allowlist: ['m1'] }); // undefined stripped
    expect(e.risk_policy).toEqual(DEFAULT_RISK_POLICY);
  });
  it('new agent_binding fields (require_hardware, { svn } min_measurement) survive mint -> read', () => {
    const P = generateKeyPair();
    const A = generateKeyPair();
    const out = mintGrant({
      principalSecret: P.secretKey,
      principalPublic: encodeKey(P.publicKey),
      holder: encodeKey(A.publicKey),
      envelope: {
        predicates: [],
        caveats: [],
        agent_binding: { require_hardware: true, min_measurement: { svn: 7 } },
        risk_policy: DEFAULT_RISK_POLICY,
      },
      goal: 'g',
    });
    const e = readEnvelope(out.grant)!;
    expect(e.agent_binding).toEqual({ require_hardware: true, min_measurement: { svn: 7 } });
    expect(verifyChain([out.grant], encodeKey(P.publicKey))).toEqual({ ok: true });
  });
  it('require_measured_weights (hardware-rooted weights pin) survives mint -> read', () => {
    const P = generateKeyPair();
    const A = generateKeyPair();
    const out = mintGrant({
      principalSecret: P.secretKey,
      principalPublic: encodeKey(P.publicKey),
      holder: encodeKey(A.publicKey),
      envelope: {
        predicates: [],
        caveats: [],
        agent_binding: { weights_allowlist: ['w-sha-1'], require_measured_weights: true },
        risk_policy: DEFAULT_RISK_POLICY,
      },
      goal: 'g',
    });
    const e = readEnvelope(out.grant)!;
    expect(e.agent_binding).toEqual({ weights_allowlist: ['w-sha-1'], require_measured_weights: true });
    expect(verifyChain([out.grant], encodeKey(P.publicKey))).toEqual({ ok: true });
  });
  it('provenance-beyond-weights agent_binding fields (system_prompt_allowlist, tool_manifest_allowlist) survive mint -> read', () => {
    const P = generateKeyPair();
    const A = generateKeyPair();
    const out = mintGrant({
      principalSecret: P.secretKey,
      principalPublic: encodeKey(P.publicKey),
      holder: encodeKey(A.publicKey),
      envelope: {
        predicates: [],
        caveats: [],
        agent_binding: { system_prompt_allowlist: ['sp-1', 'sp-2'], tool_manifest_allowlist: ['tm-1'] },
        risk_policy: DEFAULT_RISK_POLICY,
      },
      goal: 'g',
    });
    const e = readEnvelope(out.grant)!;
    expect(e.agent_binding).toEqual({ system_prompt_allowlist: ['sp-1', 'sp-2'], tool_manifest_allowlist: ['tm-1'] });
    expect(verifyChain([out.grant], encodeKey(P.publicKey))).toEqual({ ok: true });
  });
  it('goal commit is salted, openable, and deterministic for a given salt', () => {
    const { goalCommit, goalSalt } = setup();
    expect(goalSalt).toBe('fixed-salt');
    expect(verifyGoalCommit(goalCommit, 'secure my account', 'fixed-salt')).toBe(true);
    expect(verifyGoalCommit(goalCommit, 'secure my account!', 'fixed-salt')).toBe(false);
    expect(verifyGoalCommit(goalCommit, 'secure my account', 'other')).toBe(false);
    expect(goalCommitOf('g', 's1')).not.toBe(goalCommitOf('g', 's2'));
  });
  it('random salt differs per mint (goal not guessable from commit)', () => {
    const P = generateKeyPair();
    const mk = () =>
      mintGrant({
        principalSecret: P.secretKey,
        principalPublic: encodeKey(P.publicKey),
        holder: encodeKey(P.publicKey),
        envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
        goal: 'same',
      });
    expect(mk().goalCommit).not.toBe(mk().goalCommit);
  });
  it('verifies as a root chain and can be attenuated', () => {
    const { grant, P, A } = setup();
    expect(verifyChain([grant], encodeKey(P.publicKey))).toEqual({ ok: true });
    const child = attenuate(grant, [{ type: 'max_blast_radius', max: 0.1 }], A.secretKey);
    expect(verifyChain([grant, child], encodeKey(P.publicKey))).toEqual({ ok: true });
    expect(readEnvelope(child)).toEqual(readEnvelope(grant));
  });
  it('tampering with the envelope caveat breaks the root signature', () => {
    const { grant } = setup();
    const t: Capability = JSON.parse(JSON.stringify(grant));
    (t.caveats[0]!.predicates as { verb: string }[])[0]!.verb = '*';
    expect(verifyChain([t]).ok).toBe(false);
    const t2: Capability = JSON.parse(JSON.stringify(grant));
    (t2.caveats[0]!.risk_policy as { theta1: number }).theta1 = 0.99;
    expect(verifyChain([t2]).ok).toBe(false);
  });
  it('rejects invalid input; readEnvelope tolerates junk', () => {
    const P = generateKeyPair();
    const base = {
      principalSecret: P.secretKey,
      principalPublic: encodeKey(P.publicKey),
      holder: encodeKey(P.publicKey),
    };
    const ok = { predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY };
    expect(() => mintGrant({ ...base, envelope: ok, goal: '' })).toThrow();
    expect(() => mintGrant({ ...base, envelope: { ...ok, risk_policy: { ...DEFAULT_RISK_POLICY, kappa: 0 } }, goal: 'g' })).toThrow();
    expect(readEnvelope(null as never)).toBeNull();
    const { grant } = setup();
    expect(readEnvelope({ ...grant, caveats: [{ type: 'ttl' }] })).toBeNull();
    expect(readEnvelope({ ...grant, caveats: [{ type: 'envelope', goal_commit: 1 }] })).toBeNull();
  });
});
