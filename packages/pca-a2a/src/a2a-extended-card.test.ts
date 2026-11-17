import { describe, expect, it } from 'vitest';
import { whatMayIDo, type PolicyInput, type VerbShape } from '@atlasauth/pca-analyzer';
import { PCA_A2A_EXTENSION_URI, extendedAgentCard, pcaExtensionDeclaration, readPcaExtension, type AgentCard } from './index';

const policy: PolicyInput = {
  predicates: [{ verb: 'tickets.read', where: [] }, { verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'lte', value: 500 }] }],
  vetoes: [{ id: 'big', kind: 'approval', when: { verb: 'stripe.refund' }, over: { path: 'action.params.amount', threshold: 200 }, unless: [{ field: 'env.approved', op: 'eq', value: true }] }],
  caveats: [],
};
const shapes: VerbShape[] = [
  { verb: 'tickets.read', params: {} },
  { verb: 'stripe.refund', params: { amount: { type: 'number', min: 0, max: 10000 } } },
  { verb: 'stripe.payout', params: {} },
];
const skill = (id: string, verb?: string) => ({ id, name: id, description: id, tags: verb ? [`pca-verb:${verb}`] : [] });
const pub = {
  name: 'support',
  capabilities: { extensions: [pcaExtensionDeclaration({ aud: 'support.example' })] },
  skills: [{ id: 'chat', name: 'chat', description: 'chat', tags: [] }],
  signatures: [{ protected: 'x', signature: 'y' }],
} as unknown as AgentCard;
const hidden = [skill('read', 'tickets.read'), skill('refund', 'stripe.refund'), skill('payout', 'stripe.payout'), skill('mystery', 'no.such.verb'), skill('untagged')];

describe('extended Agent Card from a residual policy - T-591', () => {
  const envs = whatMayIDo(policy, shapes, {});
  it('the analyzer says what the caller may attempt, the card lists exactly that', () => {
    expect(envs.map((e) => [e.verb, e.status])).toEqual([['tickets.read', 'autonomous'], ['stripe.refund', 'autonomous'], ['stripe.payout', 'denied']]);
    const card = extendedAgentCard(pub, { authenticated: true, hiddenSkills: hidden, envelopes: envs });
    const ids = (card.skills as Array<{ id: string }>).map((s) => s.id);
    expect(ids).toEqual(['chat', 'read', 'refund']);
    // denied, unmapped (no envelope) and untagged skills are simply absent: indistinguishable from a skill that does not exist
    expect(ids).not.toContain('payout');
    expect(ids).not.toContain('mystery');
    expect(ids).not.toContain('untagged');
  });
  it('marks approval-only skills and records the policy digest in the PCA extension', () => {
    const approvalEnvs = envs.map((e) => (e.verb === 'stripe.refund' ? { ...e, status: 'needs-approval' as const } : e));
    const card = extendedAgentCard(pub, { authenticated: true, hiddenSkills: hidden, envelopes: approvalEnvs });
    const refund = (card.skills as Array<{ id: string; tags: string[] }>).find((s) => s.id === 'refund');
    expect(refund?.tags).toContain('pca:needs-approval');
    const ext = readPcaExtension(card);
    expect(ext).toMatchObject({ ok: true });
    expect(ext.ok && ext.params.policy_digest).toBe(envs[0]?.policyDigest);
    expect(JSON.stringify(card.capabilities)).toContain(PCA_A2A_EXTENSION_URI);
  });
  it('drops the now-stale signatures, leaves the public card untouched and requires authentication', () => {
    const card = extendedAgentCard(pub, { authenticated: true, hiddenSkills: hidden, envelopes: envs });
    expect(card.signatures).toBeUndefined();
    expect((pub.skills as unknown[]).length).toBe(1);
    expect(pub.signatures).toBeDefined();
    expect(() => extendedAgentCard(pub, { authenticated: false, hiddenSkills: hidden, envelopes: envs })).toThrow(/authenticated/);
    expect(() => extendedAgentCard(pub, { authenticated: 'yes' as never, hiddenSkills: hidden, envelopes: envs })).toThrow();
  });
  it('refuses envelopes from different policies and no envelopes reveal nothing', () => {
    const mixed = [envs[0]!, { ...envs[1]!, policyDigest: 'other' }];
    expect(() => extendedAgentCard(pub, { authenticated: true, hiddenSkills: hidden, envelopes: mixed })).toThrow(RangeError);
    const none = extendedAgentCard(pub, { authenticated: true, hiddenSkills: hidden, envelopes: [] });
    expect((none.skills as unknown[]).length).toBe(1);
  });
  it('a custom verb mapping is honoured', () => {
    const card = extendedAgentCard(pub, { authenticated: true, hiddenSkills: [{ id: 'x', tags: [] }], envelopes: envs, verbOf: () => 'tickets.read' });
    expect((card.skills as unknown[]).length).toBe(2);
  });
});
