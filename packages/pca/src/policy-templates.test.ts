import { describe, expect, it } from 'vitest';
import { PolicyBuilder, TEMPLATES, fromTemplate, listTemplates, policy } from './policy-templates';
import { generateKeyPair } from './keys';
import { verifyChain } from './capability';
import { lintPolicy } from './policy-sim';
import { compilePolicy } from './facade';

const AUD = 'ins_test';

describe('templates', () => {
  it('lists built-in role templates', () => {
    const names = listTemplates().map((t) => t.name).sort();
    expect(names).toEqual(['dev-assistant', 'finance-bot', 'read-only', 'support-agent']);
  });

  it('fromTemplate mints a valid, well-bounded agent', () => {
    const a = fromTemplate('finance-bot', { principal: generateKeyPair(), goal: 'refunds', aud: AUD });
    expect(verifyChain(a.chain, a.principalPublic).ok).toBe(true);
    expect(a.policy.actions.map((s) => s.verb)).toEqual(['stripe.refund']);
    expect(a.policy.budgetModel).toBe('dollars');
    // the finance-bot template is lint-clean of errors
    expect(lintPolicy(a.policy).filter((l) => l.level === 'error')).toHaveLength(0);
  });

  it('read-only template grants no side-effecting verbs', () => {
    const t = TEMPLATES['read-only']!;
    const compiled = compilePolicy({ permissions: t.permissions });
    for (const spec of compiled.actions) expect(spec.reversibility).toBe('reversible');
  });

  it('overrides narrow the template', () => {
    const a = fromTemplate('dev-assistant', {
      principal: generateKeyPair(),
      goal: 'g',
      aud: AUD,
      overrides: { permissions: { github: ['read'] } },
    });
    expect(a.policy.actions.map((s) => s.verb)).toEqual(['github.read']);
  });

  it('throws on an unknown template', () => {
    expect(() => fromTemplate('nope', { principal: generateKeyPair(), goal: 'g' })).toThrow();
  });
});

describe('PolicyBuilder', () => {
  it('composes permissions, limits and risk and mints an agent', () => {
    const a = policy()
      .allow('stripe', ['refund'])
      .allow('gmail', ['send'])
      .limit('refund', '$200/day')
      .risk({ lambda: 0 })
      .agent({ principal: generateKeyPair(), goal: 'g', aud: AUD });
    expect(a.policy.actions.map((s) => s.verb).sort()).toEqual(['gmail.send', 'stripe.refund']);
    expect(a.policy.riskPolicy.kappa).toBe(200);
    expect(verifyChain(a.chain, a.principalPublic).ok).toBe(true);
  });

  it('allow() dedupes and build() requires at least one permission', () => {
    const b = policy().allow('gmail', ['send', 'send']);
    expect(b.build().permissions.gmail).toEqual(['send']);
    expect(() => policy().build()).toThrow();
  });

  it('PolicyBuilder.from seeds from a template then extends', () => {
    const built = PolicyBuilder.from('support-agent').allow('slack', ['read']).build();
    expect(built.permissions.slack).toContain('read');
    expect(built.permissions.slack).toContain('post_message');
    expect(built.permissions.gmail).toEqual(['draft', 'send']);
  });
});
