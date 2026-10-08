import { describe, expect, it } from 'vitest';
import { evaluatePredicates, type ActionContext } from '@atlasauth/pca';
import { cedarToPca } from './cedar';
import { decide } from './types';

const allow = (preds: Parameters<typeof evaluatePredicates>[0], ctx: ActionContext) =>
  evaluatePredicates(preds, ctx).allowed;

describe('cedarToPca', () => {
  const policy = `
    // read is open to everyone, but only for the readme
    permit (
      principal,
      action == Action::"view",
      resource == Doc::"readme"
    );

    // alice may edit or delete anything, but only with MFA
    permit (
      principal == User::"alice",
      action in [Action::"edit", Action::"delete"],
      resource
    ) when { context.mfa == true };

    // an owner may edit their own resource
    permit (
      principal,
      action == Action::"edit",
      resource
    ) when { resource.owner == principal };
  `;

  it('translates permits into predicates that the core evaluator honours', () => {
    const { predicates, report } = cedarToPca(policy);
    expect(report.errors).toEqual([]);
    expect(predicates.length).toBe(3);

    // view readme: allowed for anyone
    expect(allow(predicates, { action: { verb: 'view', resource: 'Doc::readme' } })).toBe(true);
    // view a different doc: denied
    expect(allow(predicates, { action: { verb: 'view', resource: 'Doc::other' } })).toBe(false);
  });

  it('enforces action-list + condition scoping', () => {
    const { predicates } = cedarToPca(policy);
    const base = { action: { verb: 'edit', resource: 'Doc::x' } };
    // alice + mfa => allowed
    expect(allow(predicates, { ...base, subject: { id: 'User::alice' }, env: { mfa: true } })).toBe(true);
    // alice without mfa => denied
    expect(allow(predicates, { ...base, subject: { id: 'User::alice' }, env: { mfa: false } })).toBe(false);
    // bob (not alice) + mfa, non-owner => denied
    expect(allow(predicates, { ...base, subject: { id: 'User::bob' }, env: { mfa: true } })).toBe(false);
    // delete is allowed for alice with mfa, not for bob
    const del = { action: { verb: 'delete', resource: 'Doc::x' } };
    expect(allow(predicates, { ...del, subject: { id: 'User::alice' }, env: { mfa: true } })).toBe(true);
    expect(allow(predicates, { ...del, subject: { id: 'User::bob' }, env: { mfa: true } })).toBe(false);
  });

  it('maps a right-hand variable to a ref (resource.owner == principal)', () => {
    const { predicates } = cedarToPca(policy);
    const ctxOwner: ActionContext = {
      action: { verb: 'edit', resource: 'Doc::y' },
      subject: { id: 'User::carol' },
      env: { resource: { owner: 'User::carol' } },
    };
    const ctxOther: ActionContext = {
      action: { verb: 'edit', resource: 'Doc::y' },
      subject: { id: 'User::carol' },
      env: { resource: { owner: 'User::dave' } },
    };
    expect(allow(predicates, ctxOwner)).toBe(true);
    expect(allow(predicates, ctxOther)).toBe(false);
  });

  it('forbid becomes a deny that overrides permit under decide()', () => {
    const withForbid = `
      permit (
        principal == User::"alice",
        action == Action::"delete",
        resource
      ) when { context.mfa == true };

      forbid (
        principal,
        action == Action::"delete",
        resource
      ) when { resource.classification == "secret" };
    `;
    const result = cedarToPca(withForbid);
    expect(result.report.errors).toEqual([]);
    expect(result.predicates.length).toBe(1);
    expect(result.denies.length).toBe(1);

    const secret: ActionContext = {
      action: { verb: 'delete', resource: 'Doc::s' },
      subject: { id: 'User::alice' },
      env: { mfa: true, resource: { classification: 'secret' } },
    };
    const normal: ActionContext = {
      action: { verb: 'delete', resource: 'Doc::n' },
      subject: { id: 'User::alice' },
      env: { mfa: true, resource: { classification: 'public' } },
    };
    // permit alone would allow the secret delete...
    expect(evaluatePredicates(result.predicates, secret).allowed).toBe(true);
    // ...but the forbid overrides it.
    expect(decide(result, secret).allowed).toBe(false);
    // non-secret delete: permit stands.
    expect(decide(result, normal).allowed).toBe(true);
  });

  it('unless negates a single condition', () => {
    const p = `
      permit (
        principal,
        action == Action::"run",
        resource
      ) unless { context.env == "test" };
    `;
    const { predicates, report } = cedarToPca(p);
    expect(report.errors).toEqual([]);
    expect(allow(predicates, { action: { verb: 'run', resource: 'x' }, env: { env: 'prod' } })).toBe(true);
    expect(allow(predicates, { action: { verb: 'run', resource: 'x' }, env: { env: 'test' } })).toBe(false);
  });

  it('translates entity-hierarchy `in` to member_of (bounded closure over env.entity_parents)', () => {
    const p = `permit ( principal in Group::"admins", action == Action::"view", resource );`;
    const { predicates, report } = cedarToPca(p);
    expect(report.errors).toEqual([]);
    expect(predicates.length).toBe(1);
    const parents = { 'User::bob': ['Group::staff'], 'Group::staff': ['Group::admins'], 'Group::admins': [] };
    // bob is transitively a member of admins
    expect(allow(predicates, { action: { verb: 'view', resource: 'x' }, subject: { id: 'User::bob' }, env: { entity_parents: parents } })).toBe(true);
    // carol is not a member
    expect(allow(predicates, { action: { verb: 'view', resource: 'x' }, subject: { id: 'User::carol' }, env: { entity_parents: parents } })).toBe(false);
    // no hierarchy supplied => fails closed
    expect(allow(predicates, { action: { verb: 'view', resource: 'x' }, subject: { id: 'User::bob' } })).toBe(false);
  });

  it('translates `resource in Folder` and `principal is User`', () => {
    const p = `permit ( principal is User, action == Action::"read", resource in Folder::"shared" );`;
    const { predicates, report } = cedarToPca(p);
    expect(report.errors).toEqual([]);
    const parents = { 'Doc::readme': ['Folder::shared'], 'Folder::shared': [] };
    const env = { entity_parents: parents };
    expect(allow(predicates, { action: { verb: 'read', resource: 'Doc::readme' }, subject: { id: 'User::alice' }, env })).toBe(true);
    // wrong principal type
    expect(allow(predicates, { action: { verb: 'read', resource: 'Doc::readme' }, subject: { id: 'Service::bot' }, env })).toBe(false);
    // resource not under the folder
    expect(allow(predicates, { action: { verb: 'read', resource: 'Doc::other' }, subject: { id: 'User::alice' }, env })).toBe(false);
  });

  it('translates a disjunctive when-condition to any_of', () => {
    const p = `
      permit ( principal, action == Action::"view", resource )
      when { context.a == 1 || context.b == 2 };
    `;
    const { predicates, report } = cedarToPca(p);
    expect(report.errors).toEqual([]);
    expect(predicates.length).toBe(1);
    expect(allow(predicates, { action: { verb: 'view', resource: 'x' }, env: { a: 1 } })).toBe(true);
    expect(allow(predicates, { action: { verb: 'view', resource: 'x' }, env: { b: 2 } })).toBe(true);
    expect(allow(predicates, { action: { verb: 'view', resource: 'x' }, env: { a: 9, b: 9 } })).toBe(false);
  });

  it('translates attribute comparisons, like, has, and multi-condition unless (not + all_of)', () => {
    const p = `
      permit ( principal, action == Action::"spend", resource )
      when { context.amount <= 1000 && resource.name like "*.pdf" && principal has verified }
      unless { context.region == "xx" && context.sanctioned == true };
    `;
    const { predicates, report } = cedarToPca(p);
    expect(report.errors).toEqual([]);
    const base = (over: Record<string, unknown>) => ({
      action: { verb: 'spend', resource: 'r' },
      subject: { id: 'u', verified: true },
      env: { resource: { name: 'report.pdf' }, amount: 500, region: 'eu', sanctioned: false, ...over },
    });
    expect(allow(predicates, base({}))).toBe(true);
    // over the amount ceiling
    expect(allow(predicates, base({ amount: 5000 }))).toBe(false);
    // unless fires only when BOTH region==xx AND sanctioned (multi-condition unless → not(all_of))
    expect(allow(predicates, base({ region: 'xx' }))).toBe(true); // sanctioned=false, so unless does not fire
    expect(allow(predicates, base({ region: 'xx', sanctioned: true }))).toBe(false);
    // missing `verified` attribute => has() false => denied
    const noVerified = { action: { verb: 'spend', resource: 'r' }, subject: { id: 'u' }, env: { resource: { name: 'report.pdf' }, amount: 500, region: 'eu', sanctioned: false } };
    expect(allow(predicates, noVerified)).toBe(false);
  });

  it('still fails closed on genuinely unmodeled constructs (arithmetic / method calls)', () => {
    const p = `permit ( principal, action, resource ) when { resource.tags.contains("x") };`;
    const { predicates, report } = cedarToPca(p);
    expect(predicates).toEqual([]);
    expect(report.skipped.length).toBeGreaterThan(0);
    // a dropped forbid is an error (fail closed)
    const f = cedarToPca(`forbid ( principal, action, resource ) when { resource.a + 1 < 10 };`);
    expect(f.report.errors.length).toBeGreaterThan(0);
  });
});
