import { describe, expect, it } from 'vitest';
import {
  type Capability,
  type PCActn,
  type PlanNode,
  type VerifyResult,
  buildPCActn,
  delegate,
  encodeKey,
  generateKeyPair,
  mintRoot,
  verifyPCActnCore,
} from '@atlasauth/pca';
import {
  CAEP_EVENT_TYPES,
  InMemoryRevocationStore,
  RevocationRegistry,
  ingestCaepEvent,
  isActiveAt,
  isRevoked,
  verifyWithRevocation,
} from './index';

const AUD = 'rs-under-test';
const NOW = Date.UTC(2026, 9, 8, 12, 0, 0);

interface Scenario {
  principalPub: string;
  agentPub: string;
  subAPub: string;
  leafPub: string;
  siblingPub: string;
  grant: Capability;
  mid: Capability;
  leaf: Capability;
  sibling: Capability; // a second mid hop under the same grant (NOT through `mid`)
  chain: Capability[]; // [grant, mid, leaf]
  siblingChain: Capability[]; // [grant, sibling]
  pcactn: PCActn; // valid action over `chain`, signed by the leaf holder
  siblingPcactn: PCActn; // valid action over `siblingChain`
}

/** A real 3-hop delegation chain (principal -> agent -> sub-agent -> leaf) plus a sibling branch. */
function makeScenario(): Scenario {
  const principal = generateKeyPair();
  const agent = generateKeyPair();
  const subA = generateKeyPair();
  const leafKey = generateKeyPair();
  const sibling = generateKeyPair();

  const principalPub = encodeKey(principal.publicKey);
  const agentPub = encodeKey(agent.publicKey);
  const subAPub = encodeKey(subA.publicKey);
  const leafPub = encodeKey(leafKey.publicKey);
  const siblingPub = encodeKey(sibling.publicKey);

  const grant = mintRoot({ principalSecret: principal.secretKey, principalPublic: principalPub, holder: agentPub, caveats: [] });
  const mid = delegate(grant, subAPub, [], agent.secretKey);
  const leaf = delegate(mid, leafPub, [], subA.secretKey);
  const siblingCap = delegate(grant, siblingPub, [], agent.secretKey);

  const chain = [grant, mid, leaf];
  const siblingChain = [grant, siblingCap];

  const plan: PlanNode[] = [{ id: 'n1', verb: 'read', resource: 'doc:1' }];
  const pcactn = buildPCActn({ grant, chain, plan, nodeId: 'n1', counter: 1, signerSecret: leafKey.secretKey, aud: AUD, now: NOW });
  const siblingPcactn = buildPCActn({
    grant,
    chain: siblingChain,
    plan,
    nodeId: 'n1',
    counter: 1,
    signerSecret: sibling.secretKey,
    aud: AUD,
    now: NOW,
  });

  return {
    principalPub,
    agentPub,
    subAPub,
    leafPub,
    siblingPub,
    grant,
    mid,
    leaf,
    sibling: siblingCap,
    chain,
    siblingChain,
    pcactn,
    siblingPcactn,
  };
}

function coreVerify(p: PCActn, grant: Capability, audience: string | null = AUD): Promise<VerifyResult> {
  return verifyPCActnCore(p, { grant, audience, nowEpoch: NOW });
}

describe('core builders sanity', () => {
  it('produces a PCActn the core verifier accepts', async () => {
    const s = makeScenario();
    const v = await coreVerify(s.pcactn, s.grant);
    expect(v.allow).toBe(true);
    const vs = await coreVerify(s.siblingPcactn, s.grant);
    expect(vs.allow).toBe(true);
  });
});

describe('RevocationRegistry: revoke a leaf capability id', () => {
  it('denies the action whose chain contains the revoked leaf', async () => {
    const s = makeScenario();
    const reg = new RevocationRegistry();
    const entry = reg.revoke({ kind: 'cap', value: s.leaf.id, reason: 'leaf compromised' });
    expect(entry.kind).toBe('cap');

    const r = isRevoked(s.pcactn, reg, { now: NOW });
    expect(r.revoked).toBe(true);
    expect(r.matched?.value).toBe(s.leaf.id);
    expect(r.reason).toMatch(/leaf compromised/);

    const core = await coreVerify(s.pcactn, s.grant);
    const combined = verifyWithRevocation(s.pcactn, core, reg, { now: NOW });
    expect(combined.coreAllow).toBe(true);
    expect(combined.allow).toBe(false);
    expect(combined.reason).toMatch(/revoked/);

    // a sibling branch that does NOT include the leaf is unaffected
    expect(isRevoked(s.siblingPcactn, reg, { now: NOW }).revoked).toBe(false);
  });
});

describe('RevocationRegistry: revoke a mid-chain hop (subtree)', () => {
  it('revokeSubtree(midCapId) denies every descendant chain but not a sibling branch', async () => {
    const s = makeScenario();
    const reg = new RevocationRegistry();
    reg.revokeSubtree(s.mid.id, { reason: 'sub-agent branch quarantined' });

    const r = isRevoked(s.pcactn, reg, { now: NOW });
    expect(r.revoked).toBe(true);
    expect(r.matched?.value).toBe(s.mid.id);

    // the sibling chain [grant, sibling] does not pass through `mid`
    expect(isRevoked(s.siblingPcactn, reg, { now: NOW }).revoked).toBe(false);
  });

  it('revokeSubtree([grant.id, mid.id]) as an explicit chain-prefix matches the exact subtree only', async () => {
    const s = makeScenario();
    const reg = new RevocationRegistry();
    const entry = reg.revokeSubtree([s.grant.id, s.mid.id]);
    expect(entry.kind).toBe('prefix');
    expect(entry.prefix).toEqual([s.grant.id, s.mid.id]);

    expect(isRevoked(s.pcactn, reg, { now: NOW }).revoked).toBe(true);
    // the sibling path is [grant.id, sibling.id] — does NOT start with [grant.id, mid.id]
    expect(isRevoked(s.siblingPcactn, reg, { now: NOW }).revoked).toBe(false);
  });
});

describe('RevocationRegistry: revoke an agent holder key', () => {
  it('denies EVERY action whose chain includes a capability that agent holds', async () => {
    const s = makeScenario();
    const reg = new RevocationRegistry();
    // agentPub is the holder of the root grant → present in both the main chain and the sibling chain
    reg.revoke({ kind: 'holder', value: s.agentPub, reason: 'agent key leaked' });

    const r1 = isRevoked(s.pcactn, reg, { now: NOW });
    expect(r1.revoked).toBe(true);
    expect(r1.matched?.kind).toBe('holder');
    expect(isRevoked(s.siblingPcactn, reg, { now: NOW }).revoked).toBe(true);
  });

  it('revoking the root issuer (principal) kills everything under it', () => {
    const s = makeScenario();
    const reg = new RevocationRegistry();
    reg.revoke({ kind: 'issuer', value: s.principalPub, reason: 'principal revoked' });
    expect(isRevoked(s.pcactn, reg, { now: NOW }).revoked).toBe(true);
    expect(isRevoked(s.siblingPcactn, reg, { now: NOW }).revoked).toBe(true);
  });
});

describe('kill-switch', () => {
  it('killAgent denies an otherwise-valid action mid-run', async () => {
    const s = makeScenario();
    const reg = new RevocationRegistry();

    // action is valid and allowed BEFORE the kill-switch
    const core = await coreVerify(s.pcactn, s.grant);
    expect(verifyWithRevocation(s.pcactn, core, reg, { now: NOW }).allow).toBe(true);

    // operator flips the kill-switch mid-run on the leaf agent
    reg.killAgent(s.leafPub);

    const combined = verifyWithRevocation(s.pcactn, core, reg, { now: NOW });
    expect(combined.coreAllow).toBe(true); // the PCActn is still cryptographically valid
    expect(combined.allow).toBe(false); // but revocation bites immediately
    expect(combined.revocation.revoked).toBe(true);
    expect(combined.revocation.matched?.kind).toBe('holder');
  });

  it('killSubtree instantly denies the subtree rooted at a cap id', () => {
    const s = makeScenario();
    const reg = new RevocationRegistry();
    reg.killSubtree(s.grant.id);
    expect(isRevoked(s.pcactn, reg, { now: NOW }).revoked).toBe(true);
    expect(isRevoked(s.siblingPcactn, reg, { now: NOW }).revoked).toBe(true);
  });
});

describe('future-dated revocation (notBefore)', () => {
  it('does not bite before notBefore, then bites after', async () => {
    const s = makeScenario();
    const reg = new RevocationRegistry();
    const future = NOW + 1_000_000;
    const entry = reg.revoke({ kind: 'cap', value: s.leaf.id, reason: 'scheduled', notBefore: future });
    expect(isActiveAt(entry, NOW)).toBe(false);
    expect(isActiveAt(entry, future)).toBe(true);

    // at NOW: not yet revoked
    expect(isRevoked(s.pcactn, reg, { now: NOW }).revoked).toBe(false);
    const core = await coreVerify(s.pcactn, s.grant);
    expect(verifyWithRevocation(s.pcactn, core, reg, { now: NOW }).allow).toBe(true);

    // at notBefore and beyond: it bites
    expect(isRevoked(s.pcactn, reg, { now: future }).revoked).toBe(true);
    expect(isRevoked(s.pcactn, reg, { now: future + 5 }).revoked).toBe(true);
  });
});

describe('non-revoked valid action', () => {
  it('passes the combined gate when the registry is empty', async () => {
    const s = makeScenario();
    const reg = new RevocationRegistry();
    const core = await coreVerify(s.pcactn, s.grant);
    const combined = verifyWithRevocation(s.pcactn, core, reg, { now: NOW });
    expect(combined.coreAllow).toBe(true);
    expect(combined.revocation.revoked).toBe(false);
    expect(combined.allow).toBe(true);
    expect(combined.reason).toBeUndefined();
  });
});

describe('verifyWithRevocation fails closed', () => {
  it('denies when the core verify itself failed, regardless of an empty registry', async () => {
    const s = makeScenario();
    const reg = new RevocationRegistry();
    // wrong audience => core denies
    const core = await verifyPCActnCore(s.pcactn, { grant: s.grant, audience: 'some-other-rs', nowEpoch: NOW });
    expect(core.allow).toBe(false);

    const combined = verifyWithRevocation(s.pcactn, core, reg, { now: NOW });
    expect(combined.coreAllow).toBe(false);
    expect(combined.revocation.revoked).toBe(false);
    expect(combined.allow).toBe(false);
    expect(combined.reason).toBe(core.reason);
  });

  it('denies when BOTH core failed and the chain is revoked (reports the core reason first)', async () => {
    const s = makeScenario();
    const reg = new RevocationRegistry();
    reg.revoke({ kind: 'cap', value: s.leaf.id });
    const core = await verifyPCActnCore(s.pcactn, { grant: s.grant, audience: 'some-other-rs', nowEpoch: NOW });
    const combined = verifyWithRevocation(s.pcactn, core, reg, { now: NOW });
    expect(combined.allow).toBe(false);
    expect(combined.reason).toBe(core.reason);
  });
});

describe('registry bookkeeping', () => {
  it('unrevoke removes a revocation; list reflects the current set', () => {
    const s = makeScenario();
    const reg = new RevocationRegistry();
    reg.revoke({ kind: 'cap', value: s.leaf.id });
    reg.revokeSubtree([s.grant.id, s.mid.id]);
    expect(reg.list()).toHaveLength(2);
    expect(isRevoked(s.pcactn, reg, { now: NOW }).revoked).toBe(true);

    expect(reg.unrevoke({ kind: 'cap', value: s.leaf.id })).toBe(true);
    expect(reg.unrevoke({ kind: 'prefix', prefix: [s.grant.id, s.mid.id] })).toBe(true);
    expect(reg.unrevoke({ kind: 'cap', value: s.leaf.id })).toBe(false); // already gone
    expect(reg.list()).toHaveLength(0);
    expect(isRevoked(s.pcactn, reg, { now: NOW }).revoked).toBe(false);

    reg.revoke({ kind: 'cap', value: s.leaf.id });
    reg.clear();
    expect(reg.list()).toHaveLength(0);
  });

  it('accepts a custom pluggable store', () => {
    const s = makeScenario();
    const reg = new RevocationRegistry(new InMemoryRevocationStore());
    reg.killAgent(s.leafPub);
    expect(isRevoked(s.pcactn, reg, { now: NOW }).revoked).toBe(true);
  });

  it('rejects a malformed prefix revocation', () => {
    const reg = new RevocationRegistry();
    expect(() => reg.revoke({ kind: 'prefix', prefix: [] })).toThrow();
    expect(() => reg.revoke({ kind: 'cap', value: '' })).toThrow();
  });
});

describe('Shared-Signals / CAEP bridge', () => {
  it('maps grant-revoked into a cap revocation of the grant subtree', () => {
    const s = makeScenario();
    const reg = new RevocationRegistry();
    const added = ingestCaepEvent(
      { type: CAEP_EVENT_TYPES.grantRevoked, payload: { grant_ref: s.grant.id, reason: 'policy', event_timestamp: NOW / 1000 } },
      reg,
    );
    expect(added).toHaveLength(1);
    expect(added[0]?.kind).toBe('cap');
    expect(added[0]?.revokedAt).toBe(NOW);
    expect(isRevoked(s.pcactn, reg, { now: NOW }).revoked).toBe(true);
    expect(isRevoked(s.siblingPcactn, reg, { now: NOW }).revoked).toBe(true);
  });

  it('maps kill-switch into an agent-holder kill (and an explicit grant_ref)', () => {
    const s = makeScenario();
    const reg = new RevocationRegistry();
    const added = ingestCaepEvent(
      { type: CAEP_EVENT_TYPES.killSwitch, payload: { agent: s.leafPub, grant_ref: s.grant.id, reason: 'anomaly' } },
      reg,
    );
    expect(added).toHaveLength(2);
    expect(added.map((e) => e.kind).sort()).toEqual(['cap', 'holder']);
    expect(isRevoked(s.pcactn, reg, { now: NOW }).revoked).toBe(true);
  });

  it('maps session-revoked into a holder kill when the subject carries an agent key', () => {
    const s = makeScenario();
    const reg = new RevocationRegistry();
    const added = ingestCaepEvent(
      { type: CAEP_EVENT_TYPES.sessionRevoked, payload: { subject: { format: 'opaque', holder: s.leafPub }, reason_admin: 'session killed' } },
      reg,
    );
    expect(added).toHaveLength(1);
    expect(added[0]?.kind).toBe('holder');
    const r = isRevoked(s.pcactn, reg, { now: NOW });
    expect(r.revoked).toBe(true);
    expect(r.reason).toMatch(/session killed/);
  });

  it('is a no-op when a session-revoked subject carries no agent/holder key', () => {
    const reg = new RevocationRegistry();
    const added = ingestCaepEvent(
      { type: CAEP_EVENT_TYPES.sessionRevoked, payload: { subject: { format: 'email', email: 'x@example.com' } } },
      reg,
    );
    expect(added).toHaveLength(0);
    expect(reg.list()).toHaveLength(0);
  });
});
