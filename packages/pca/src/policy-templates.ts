/**
 * Policy templates + a fluent authoring builder (spec Part 2.3 "authoring + the standing Policy
 * Agent"). The deterministic backbone of "NL → policy": instead of asking a model to invent policy,
 * a request maps onto a named ROLE template (read-only, support agent, finance bot, dev assistant)
 * or is composed with a typed builder, both of which compile through the facade's `compilePolicy` —
 * so what you author is exactly what the verifier enforces. Pure.
 */

import { type Agent, type AgentOptions, type Limits, type PermissionMap, agent } from './facade';
import type { KeyPair } from './keys';
import type { RiskPolicy } from './risk';

export interface PolicyTemplate {
  name: string;
  description: string;
  permissions: PermissionMap;
  limits?: Limits;
  riskPolicy?: Partial<RiskPolicy>;
}

/** Built-in role templates — conservative starting points, meant to be narrowed, not widened. */
export const TEMPLATES: Record<string, PolicyTemplate> = {
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

export function listTemplates(): PolicyTemplate[] {
  return Object.values(TEMPLATES);
}

export interface FromTemplateOptions {
  principal: KeyPair;
  goal: string;
  aud?: string;
  holder?: KeyPair;
  now?: number;
  /** Narrow/extend the template before minting (merged over the template). */
  overrides?: Partial<Pick<AgentOptions, 'permissions' | 'limits' | 'riskPolicy' | 'agentBinding' | 'budgetModel'>>;
}

/** Mint an agent from a named template. Throws on an unknown template. */
export function fromTemplate(name: string, opts: FromTemplateOptions): Agent {
  const t = TEMPLATES[name];
  if (!t) throw new Error(`fromTemplate: unknown template '${name}' (have: ${Object.keys(TEMPLATES).join(', ')})`);
  return agent({
    principal: opts.principal,
    goal: opts.goal,
    permissions: opts.overrides?.permissions ?? t.permissions,
    ...(opts.overrides?.limits ?? t.limits ? { limits: opts.overrides?.limits ?? t.limits } : {}),
    ...(opts.overrides?.riskPolicy ?? t.riskPolicy ? { riskPolicy: opts.overrides?.riskPolicy ?? t.riskPolicy } : {}),
    ...(opts.overrides?.agentBinding ? { agentBinding: opts.overrides.agentBinding } : {}),
    ...(opts.overrides?.budgetModel ? { budgetModel: opts.overrides.budgetModel } : {}),
    ...(opts.aud !== undefined ? { aud: opts.aud } : {}),
    ...(opts.holder ? { holder: opts.holder } : {}),
    ...(opts.now !== undefined ? { now: opts.now } : {}),
  });
}

// ---- fluent builder -------------------------------------------------------------------------------

export interface BuiltPolicy {
  permissions: PermissionMap;
  limits: Limits;
  riskPolicy?: Partial<RiskPolicy>;
}

/** A typed, chainable policy builder. `policy().allow('stripe', ['refund']).limit('refund', '$500/day')`. */
export class PolicyBuilder {
  private perms: PermissionMap = {};
  private lims: Limits = {};
  private riskOverride?: Partial<RiskPolicy>;

  /** Start from a named template (its permissions/limits/risk seed the builder). */
  static from(name: string): PolicyBuilder {
    const t = TEMPLATES[name];
    if (!t) throw new Error(`PolicyBuilder.from: unknown template '${name}'`);
    const b = new PolicyBuilder();
    for (const [c, acts] of Object.entries(t.permissions)) b.allow(c, acts);
    if (t.limits) for (const [k, v] of Object.entries(t.limits)) b.limit(k, v);
    if (t.riskPolicy) b.risk(t.riskPolicy);
    return b;
  }

  allow(connector: string, actions: string[]): this {
    // Own-key read: a connector named like an Object.prototype member (`constructor`, `toString`, …)
    // would otherwise read the inherited (non-array) value and blow up the spread below.
    const cur = Object.prototype.hasOwnProperty.call(this.perms, connector) ? this.perms[connector]! : [];
    this.perms[connector] = [...new Set([...cur, ...actions])];
    return this;
  }

  limit(verbOrAction: string, spec: string): this {
    this.lims[verbOrAction] = spec;
    return this;
  }

  risk(partial: Partial<RiskPolicy>): this {
    this.riskOverride = { ...this.riskOverride, ...partial };
    return this;
  }

  build(): BuiltPolicy {
    if (Object.keys(this.perms).length === 0) throw new Error('PolicyBuilder: no permissions added');
    return {
      permissions: structuredClone(this.perms),
      limits: structuredClone(this.lims),
      ...(this.riskOverride ? { riskPolicy: { ...this.riskOverride } } : {}),
    };
  }

  /** Mint an agent directly from the built policy. */
  agent(opts: { principal: KeyPair; goal: string; aud?: string; holder?: KeyPair; now?: number }): Agent {
    const b = this.build();
    return agent({
      principal: opts.principal,
      goal: opts.goal,
      permissions: b.permissions,
      limits: b.limits,
      ...(b.riskPolicy ? { riskPolicy: b.riskPolicy } : {}),
      ...(opts.aud !== undefined ? { aud: opts.aud } : {}),
      ...(opts.holder ? { holder: opts.holder } : {}),
      ...(opts.now !== undefined ? { now: opts.now } : {}),
    });
  }
}

/** Entry point for the fluent builder. */
export function policy(): PolicyBuilder {
  return new PolicyBuilder();
}
