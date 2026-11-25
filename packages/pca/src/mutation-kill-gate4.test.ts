/**
 * Mutation kills for module-level constants that statically-importing tests never see mutated (Stryker applies a static
 * mutant before any test runs): the envelope name and parameter-path patterns, the accumulator scope list and the v3 goal
 * prefix. Each test re-evaluates the module (vi.resetModules + dynamic import) and pins exact outcomes.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';

async function fresh<T>(load: () => Promise<T>): Promise<T> {
  vi.resetModules();
  return load();
}

describe('envelope-rules: the name pattern (fresh module)', () => {
  it('accepts names of 1, 2+ and exactly 64 characters; refuses a bad first character, junk before or after, 65 characters', async () => {
    const { tightenListError, templateRefError } = await fresh(() => import('./envelope-rules'));
    const idOk = (id: string) => tightenListError([{ id, when: {}, signal: 'deny' }]) === null;
    const tplOk = (template_id: string) => templateRefError({ template_id, version_digest: 'd'.repeat(43), slots: {} }) === null;
    for (const ok of [idOk, tplOk]) {
      for (const good of ['a', 'ab', 'ab_9', 'a'.repeat(64)]) expect(ok(good), good).toBe(true);
      for (const bad of ['1ab', '_a', 'ab-', 'X-ab', 'a'.repeat(65), '']) expect(ok(bad), bad).toBe(false);
    }
    expect(tightenListError([{ id: '1ab', when: {}, signal: 'deny' }])).toBe('tighten[0].id must match ^[a-z][a-z0-9_]{0,63}$');
  });
});

describe('envelope-rules: the parameter-path pattern (fresh module)', () => {
  it('is anchored at both ends', async () => {
    const { PARAM_PATH_RE, unitTagsError } = await fresh(() => import('./envelope-rules'));
    const tag = { kind: 'k' };
    expect(unitTagsError({ 'action.params.a': tag })).toBeNull();
    expect(unitTagsError({ [`action.params.${'a'.repeat(64)}`]: tag })).toBeNull();
    for (const bad of ['x.action.params.a', 'action.params.a.b', 'action.params.a!', `action.params.${'a'.repeat(65)}`]) {
      expect(PARAM_PATH_RE.test(bad), bad).toBe(false);
      expect(unitTagsError({ [bad]: tag })).toBe(`units key '${bad}' must be an action.params.<name> path`);
    }
  });
});

describe('intent-acc: the scope list (fresh module)', () => {
  it('accepts each of session, principal, org, fleet; refuses an unknown scope and the empty string', async () => {
    const { ACC_SCOPES, accumulatorDeclError } = await fresh(() => import('./intent-acc'));
    expect(ACC_SCOPES).toEqual(['session', 'principal', 'org', 'fleet']);
    const decl = { id: 'q', agg: 'count', sel: { event: 'intent_required' }, win: { kind: 'task' }, key: null, cap: 6, holder: { kind: 'wallet' }, domain_max: 10 };
    expect(accumulatorDeclError({ ...decl, scope: 'session' })).toBeNull();
    // past the scope check, a wider scope then fails on its wallet holder (not on the scope)
    for (const scope of ['principal', 'org', 'fleet']) {
      expect(accumulatorDeclError({ ...decl, scope }), scope).toBe(`accumulator 'q': a ${scope}-scoped accumulator has a site_local holder (the ledger is the holder)`);
    }
    for (const scope of ['galaxy', '']) expect(accumulatorDeclError({ ...decl, scope }), scope).toBe("accumulator 'q': unknown scope");
  });
});

describe('intent-binding: the v3 goal prefix (fresh module)', () => {
  it('reproduces the cross-language goal-commit vector', async () => {
    const { intentGoalV3, intentGoalCommitV3 } = await fresh(() => import('./intent-binding'));
    const doc = JSON.parse(readFileSync(join(__dirname, '..', 'conformance', 'goal-commit-vectors.json'), 'utf8')) as {
      commit: { name: string; goal_digest: string; policy_digest: string; salt: string; goal: string; commit: string }[];
    };
    const v = doc.commit.find((c) => c.name === 'basic')!;
    const ref = { goal_digest: v.goal_digest, policy_digest: v.policy_digest };
    expect(intentGoalV3(ref)).toBe(`pca-intent:v3:${v.goal_digest}:${v.policy_digest}`);
    expect(intentGoalV3(ref)).toBe(v.goal);
    expect(intentGoalCommitV3(ref, v.salt)).toBe(v.commit);
  });
});
