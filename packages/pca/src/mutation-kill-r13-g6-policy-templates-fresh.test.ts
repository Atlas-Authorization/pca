/**
 * r13 mutation kills for policy-templates.ts. TEMPLATES is built at module load (static mutants), so every test re-evaluates
 * the module (vi.resetModules + dynamic import). Pins the exact template table, the unknown-template messages, and that each
 * optional input of fromTemplate / PolicyBuilder.agent (aud, holder, now, riskPolicy, agentBinding, budgetModel) reaches the
 * minted agent.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPair } from './keys';

/** Capture an outcome so a thrown error is compared (name + message) instead of failing the test as an error. */
type Settled<T> = { ok: true; value: T } | { ok: false; error: { name: string; message: string } };
function settle<T>(f: () => T): Settled<T> {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    const x = e as Error;
    return { ok: false, error: { name: x?.name, message: x?.message } };
  }
}
const ok = <T>(value: T) => ({ ok: true as const, value });

async function fresh() {
  vi.resetModules();
  return import('./policy-templates');
}

const EXPECTED = {
  'read-only': {
    name: 'read-only',
    description: 'Read access only — no side effects anywhere.',
    permissions: { github: ['read'], slack: ['read'], files: ['read'], http: ['get'] },
  },
  'support-agent': {
    name: 'support-agent',
    description: 'Draft + send customer email and post to Slack, rate-limited.',
    permissions: { gmail: ['draft', 'send'], slack: ['post_message'] },
    limits: { send: '50/day', post_message: '100/day' },
  },
  'finance-bot': {
    name: 'finance-bot',
    description: 'Issue reversible refunds within a daily cap; no payouts.',
    permissions: { stripe: ['refund'] },
    limits: { refund: '$500/day' },
  },
  'dev-assistant': {
    name: 'dev-assistant',
    description: 'Read repos, open PRs and comment — never merge or delete.',
    permissions: { github: ['read', 'create_pr', 'comment'] },
    limits: { create_pr: '20/day' },
  },
};

const envelopeOf = (a: { grant: { caveats: unknown[] } }) =>
  a.grant.caveats.find((c) => (c as { type: string }).type === 'envelope') as { agent_binding: unknown };

let added: string | undefined;
afterEach(async () => {
  if (added) {
    const m = await import('./policy-templates');
    delete m.TEMPLATES[added];
    added = undefined;
  }
});

describe('policy-templates: template table (fresh module)', () => {
  it('TEMPLATES and listTemplates are exactly the documented roles', async () => {
    const m = await fresh();
    expect(m.TEMPLATES).toStrictEqual(EXPECTED);
    expect(m.listTemplates()).toStrictEqual(Object.values(EXPECTED));
  });
  it('PolicyBuilder.from seeds permissions and limits from each template', async () => {
    const m = await fresh();
    expect(settle(() => m.PolicyBuilder.from('read-only').build())).toEqual(ok({ permissions: EXPECTED['read-only'].permissions, limits: {} }));
    expect(m.PolicyBuilder.from('support-agent').build()).toStrictEqual({
      permissions: EXPECTED['support-agent'].permissions,
      limits: EXPECTED['support-agent'].limits,
    });
  });
});

describe('policy-templates: unknown names', () => {
  it('fromTemplate names the unknown template and lists the known ones', async () => {
    const m = await fresh();
    expect(() => m.fromTemplate('nope', { principal: generateKeyPair(), goal: 'g' })).toThrow(
      new Error("fromTemplate: unknown template 'nope' (have: read-only, support-agent, finance-bot, dev-assistant)"),
    );
  });
  it('PolicyBuilder.from names the unknown template', async () => {
    const m = await fresh();
    expect(() => m.PolicyBuilder.from('nope')).toThrow(new Error("PolicyBuilder.from: unknown template 'nope'"));
  });
  it('an empty builder refuses to build', async () => {
    const m = await fresh();
    expect(() => m.policy().build()).toThrow(new Error('PolicyBuilder: no permissions added'));
  });
});

describe('policy-templates: fromTemplate options reach the agent', () => {
  it('aud: given -> the default audience of act; absent -> act requires one', async () => {
    const m = await fresh();
    const withAud = m.fromTemplate('read-only', { principal: generateKeyPair(), goal: 'g', aud: 'ins_a' });
    expect(settle(() => withAud.act('github.read', 'repo:x').pcactn.aud)).toEqual(ok('ins_a'));
    const noAud = m.fromTemplate('read-only', { principal: generateKeyPair(), goal: 'g' });
    expect(() => noAud.act('github.read', 'repo:x')).toThrow(/aud .* is required/);
  });
  it('holder and now are used as given', async () => {
    const m = await fresh();
    const holder = generateKeyPair();
    const a = m.fromTemplate('read-only', { principal: generateKeyPair(), goal: 'g', holder, now: 1_000_000 });
    expect(a.holder).toBe(holder);
    expect(a.budget.tau).toBe(1_000_000);
    expect(a.budget.asOf).toBe(1_000_000);
  });
  it('an overrides.riskPolicy is applied even when the template has none', async () => {
    const m = await fresh();
    const a = m.fromTemplate('read-only', { principal: generateKeyPair(), goal: 'g', overrides: { riskPolicy: { theta1: 0.11 } } });
    expect(a.policy.riskPolicy.theta1).toBe(0.11);
  });
  it("a template's own riskPolicy is applied when there are no overrides (and seeds PolicyBuilder.from)", async () => {
    const m = await fresh();
    added = 'r13-risky';
    m.TEMPLATES[added] = { name: added, description: 'd', permissions: { github: ['read'] }, riskPolicy: { theta1: 0.12 } };
    expect(settle(() => m.fromTemplate(added!, { principal: generateKeyPair(), goal: 'g' }).policy.riskPolicy.theta1)).toEqual(ok(0.12));
    expect(m.PolicyBuilder.from(added).build()).toStrictEqual({
      permissions: { github: ['read'] },
      limits: {},
      riskPolicy: { theta1: 0.12 },
    });
  });
  it('overrides.agentBinding lands in the grant envelope; overrides.budgetModel wins over auto', async () => {
    const m = await fresh();
    const binding = { operator: 'op-1' };
    const a = m.fromTemplate('finance-bot', {
      principal: generateKeyPair(), goal: 'g', overrides: { agentBinding: binding, budgetModel: 'risk' },
    });
    expect(envelopeOf(a).agent_binding).toStrictEqual(binding);
    expect(a.policy.budgetModel).toBe('risk');
    const d = m.fromTemplate('finance-bot', { principal: generateKeyPair(), goal: 'g' });
    expect(envelopeOf(d).agent_binding).toStrictEqual({});
    expect(d.policy.budgetModel).toBe('dollars');
  });
});

describe('policy-templates: PolicyBuilder', () => {
  it('risk() merges successive partials; build() returns them', async () => {
    const m = await fresh();
    const b = m.policy().allow('github', ['read']).risk({ theta1: 0.2 }).risk({ theta2: 0.7 });
    expect(b.build()).toStrictEqual({ permissions: { github: ['read'] }, limits: {}, riskPolicy: { theta1: 0.2, theta2: 0.7 } });
  });
  it('agent(): riskPolicy, aud, holder and now reach the minted agent', async () => {
    const m = await fresh();
    const holder = generateKeyPair();
    const a = m.policy().allow('github', ['read']).risk({ theta1: 0.13 })
      .agent({ principal: generateKeyPair(), goal: 'g', aud: 'ins_b', holder, now: 2_000_000 });
    expect(a.policy.riskPolicy.theta1).toBe(0.13);
    expect(settle(() => a.act('github.read', 'repo:x').pcactn.aud)).toEqual(ok('ins_b'));
    expect(a.holder).toBe(holder);
    expect(a.budget.tau).toBe(2_000_000);
    const n = m.policy().allow('github', ['read']).agent({ principal: generateKeyPair(), goal: 'g' });
    expect(() => n.act('github.read', 'repo:x')).toThrow(/aud .* is required/);
  });
});
