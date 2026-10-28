import { bindContext, decideWithMissing, type SupplierTable } from '../missing-context';
import { classVerdictsError, decideClasses } from '../policy-classes';

/**
 * Shared vectors for typed missing context, the stored-wins merge and policy classes
 * (conformance/missing-context-vectors.json, conformance/policy-classes-vectors.json). Expectations are hand-written and proved
 * against the reference before the files are written. Reason text IS compared (it is the typed wire form of the refusal).
 * Regenerate: K8_VECTORS_WRITE=1 vitest run src/k8-ops-vectors.test.ts
 */
const ctx = (over: Record<string, unknown> = {}) => ({ action: { verb: 'refund', resource: '/acct/a1', params: { amount: 50 } }, subject: { id: 'u1' }, env: { tier: 'gold' }, ...over });
const eq = (field: string, value: unknown) => ({ field, op: 'eq', value });
const T: SupplierTable = { 'env.risk_score': 'rs_observation', 'env.kyc': 'discharge_issuer', 'action.params.note': 'agent_declared_untrusted' };

export function buildMissingContextVectors() {
  const dec: { name: string; where: unknown; bound: unknown; supplied?: unknown; suppliers?: SupplierTable; expect: Record<string, unknown> }[] = [
    { name: 'true-allows', where: [eq('env.tier', 'gold')], bound: ctx(), expect: { decision: 'allow', missing: [] } },
    { name: 'false-denies', where: [eq('env.tier', 'silver')], bound: ctx(), expect: { decision: 'deny', reason: 'condition_false', missing: [] } },
    { name: 'empty-list-denies', where: [], bound: ctx(), expect: { decision: 'deny', reason: 'condition_false', missing: [] } },
    { name: 'not-a-list-denies', where: { field: 'env.tier' }, bound: ctx(), expect: { decision: 'deny', reason: 'condition_false', missing: [] } },
    { name: 'missing-defaults-to-the-principal', where: [eq('env.approved', true)], bound: ctx(), expect: { decision: 'escalate', reason: 'escalate: missing_context principal:env.approved', missing: [{ path: 'env.approved', supplier: 'principal' }] } },
    { name: 'missing-paths-are-typed-and-sorted', where: [eq('env.risk_score', 1), eq('env.kyc', 'ok'), eq('env.approved', true)], bound: ctx(), suppliers: T, expect: { decision: 'escalate', reason: 'escalate: missing_context principal:env.approved,discharge_issuer:env.kyc,rs_observation:env.risk_score', missing: [{ path: 'env.approved', supplier: 'principal' }, { path: 'env.kyc', supplier: 'discharge_issuer' }, { path: 'env.risk_score', supplier: 'rs_observation' }] } },
    { name: 'agent-only-missing-denies', where: [eq('action.params.note', 'x')], bound: ctx(), suppliers: T, expect: { decision: 'deny', reason: 'missing_context_untrusted: action.params.note', missing: [{ path: 'action.params.note', supplier: 'agent_declared_untrusted' }] } },
    { name: 'one-agent-only-path-makes-the-whole-deny', where: [eq('action.params.note', 'x'), eq('env.kyc', 'ok')], bound: ctx(), suppliers: T, expect: { decision: 'deny', reason: 'missing_context_untrusted: action.params.note', missing: [{ path: 'action.params.note', supplier: 'agent_declared_untrusted' }, { path: 'env.kyc', supplier: 'discharge_issuer' }] } },
    { name: 'a-supplied-value-fills-the-gap', where: [eq('env.kyc', 'ok')], bound: ctx(), supplied: { env: { kyc: 'ok' } }, suppliers: T, expect: { decision: 'allow', missing: [] } },
    { name: 'a-supplied-value-for-an-agent-only-path-is-dropped', where: [eq('action.params.note', 'x')], bound: ctx(), supplied: { action: { params: { note: 'x' } } }, suppliers: T, expect: { decision: 'deny', reason: 'missing_context_untrusted: action.params.note', missing: [{ path: 'action.params.note', supplier: 'agent_declared_untrusted' }] } },
    { name: 'supplied-never-shadows-a-bound-value', where: [eq('env.tier', 'silver')], bound: ctx(), supplied: { env: { tier: 'silver' } }, expect: { decision: 'deny', reason: 'context_shadow: env.tier', missing: [] } },
    { name: 'supplied-equal-to-bound-is-no-conflict', where: [eq('env.tier', 'gold')], bound: ctx(), supplied: { env: { tier: 'gold' } }, expect: { decision: 'allow', missing: [] } },
    { name: 'supplied-under-a-bound-leaf-is-a-conflict', where: [eq('env.tier', 'gold')], bound: ctx(), supplied: { env: { tier: { level: 'x' } } }, expect: { decision: 'deny', reason: 'context_shadow: env.tier.level', missing: [] } },
    { name: 'conflicts-are-listed-sorted', where: [eq('env.tier', 'gold')], bound: ctx(), supplied: { subject: { id: 'u2' }, env: { tier: 'x' } }, expect: { decision: 'deny', reason: 'context_shadow: env.tier,subject.id', missing: [] } },
    { name: 'a-wrong-typed-present-value-is-ill-typed', where: [{ field: 'env.tier', op: 'lt', value: 5 }], bound: ctx(), expect: { decision: 'deny', reason: 'ill_typed_context', missing: [] } },
    { name: 'false-beats-missing', where: [eq('env.tier', 'silver'), eq('env.approved', true)], bound: ctx(), expect: { decision: 'deny', reason: 'condition_false', missing: [] } },
    { name: 'a-true-branch-beats-missing', where: [{ any_of: [eq('env.tier', 'gold'), eq('env.approved', true)] }], bound: ctx(), expect: { decision: 'allow', missing: [] } },
    { name: 'params-unavailable-names-the-field', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }], bound: { action: { verb: 'refund', resource: '/acct/a1' }, env: {} }, expect: { decision: 'escalate', reason: 'escalate: missing_context principal:action.params.amount', missing: [{ path: 'action.params.amount', supplier: 'principal' }] } },
    { name: 'a-missing-ref-is-named', where: [{ field: 'env.tier', op: 'eq', ref: 'env.expected_tier' }], bound: ctx(), expect: { decision: 'escalate', reason: 'escalate: missing_context principal:env.expected_tier', missing: [{ path: 'env.expected_tier', supplier: 'principal' }] } },
    { name: 'the-longest-prefix-names-the-supplier', where: [eq('env.obs.load', 1)], bound: ctx(), suppliers: { env: 'principal', 'env.obs': 'rs_observation' }, expect: { decision: 'escalate', reason: 'escalate: missing_context rs_observation:env.obs.load', missing: [{ path: 'env.obs.load', supplier: 'rs_observation' }] } },
    { name: 'a-prefix-must-end-on-a-segment', where: [eq('env.observed', 1)], bound: ctx(), suppliers: { 'env.obs': 'rs_observation' }, expect: { decision: 'escalate', reason: 'escalate: missing_context principal:env.observed', missing: [{ path: 'env.observed', supplier: 'principal' }] } },
    { name: 'a-bad-supplier-table-denies', where: [eq('env.tier', 'gold')], bound: ctx(), suppliers: { foo: 'principal' } as never, expect: { decision: 'deny', reason: "bad supplier table: bad supplier path 'foo'", missing: [] } },
    { name: 'a-bad-supplier-name-denies', where: [eq('env.tier', 'gold')], bound: ctx(), suppliers: { 'env.x': 'everyone' } as never, expect: { decision: 'deny', reason: "bad supplier table: bad supplier for 'env.x'", missing: [] } },
    { name: 'a-bound-context-without-an-action-denies', where: [eq('env.tier', 'gold')], bound: { env: { tier: 'gold' } }, expect: { decision: 'deny', reason: 'bad_context', missing: [] } },
    { name: 'a-null-bound-context-denies', where: [eq('env.tier', 'gold')], bound: null, expect: { decision: 'deny', reason: 'bad_context', missing: [] } },
    { name: 'a-not-of-a-missing-value-is-still-undecided', where: [{ not: eq('env.approved', true) }], bound: ctx(), expect: { decision: 'escalate', reason: 'escalate: missing_context principal:env.approved', missing: [{ path: 'env.approved', supplier: 'principal' }] } },
  ];
  const bind: { name: string; bound: unknown; supplied?: unknown; suppliers?: SupplierTable; expect: { context: unknown; conflicts: string[]; dropped: string[] } }[] = [
    { name: 'nothing-supplied', bound: ctx(), expect: { context: ctx(), conflicts: [], dropped: [] } },
    { name: 'a-new-value-is-added', bound: ctx(), supplied: { env: { kyc: 'ok' } }, expect: { context: ctx({ env: { tier: 'gold', kyc: 'ok' } }), conflicts: [], dropped: [] } },
    { name: 'a-differing-value-keeps-the-bound-one-and-conflicts', bound: ctx(), supplied: { env: { tier: 'x' } }, expect: { context: ctx(), conflicts: ['env.tier'], dropped: [] } },
    { name: 'params-are-created-when-the-bound-side-has-none', bound: { action: { verb: 'v', resource: 'r' } }, supplied: { action: { params: { a: { b: 1 } } } }, expect: { context: { action: { verb: 'v', resource: 'r', params: { a: { b: 1 } } } }, conflicts: [], dropped: [] } },
    { name: 'the-verb-and-resource-are-never-taken-from-the-request', bound: ctx(), supplied: { action: { verb: 'delete', resource: '/x' } } as never, expect: { context: ctx(), conflicts: [], dropped: [] } },
    { name: 'an-agent-only-value-is-dropped', bound: ctx(), supplied: { action: { params: { note: 'hi' } } }, suppliers: T, expect: { context: ctx(), conflicts: [], dropped: ['action.params.note'] } },
    { name: 'a-value-under-a-bound-leaf-conflicts', bound: ctx(), supplied: { subject: { id: { x: 1 } } }, expect: { context: ctx(), conflicts: ['subject.id.x'], dropped: [] } },
    { name: 'a-non-object-supplied-is-ignored', bound: ctx(), supplied: 5 as never, expect: { context: ctx(), conflicts: [], dropped: [] } },
  ];
  for (const v of dec) {
    const r = decideWithMissing({ where: v.where, bound: v.bound as never, ...(v.supplied !== undefined ? { supplied: v.supplied as never } : {}), ...(v.suppliers ? { suppliers: v.suppliers } : {}) });
    same(r, v.expect, `decide ${v.name}`);
  }
  for (const v of bind) same(bindContext(v.bound as never, v.supplied as never, v.suppliers ?? {}), v.expect, `bind ${v.name}`);
  return {
    format: 'pca-missing-context-vectors',
    ver: 1,
    about: 'Typed missing context and the stored-wins merge. decide: a permit condition list over the bound context plus request-supplied context (merged by bind; supplied never replaces a bound value, a differing one is a context_shadow deny, agent_declared_untrusted paths are dropped). Result {decision, reason?, missing[]}; reason text is part of the expectation. bind: {context, conflicts, dropped} (sorted by path). Suppliers: path or prefix -> principal | discharge_issuer | rs_observation | agent_declared_untrusted; the longest matching prefix at a segment boundary wins; unmatched is principal. Generated by src/test-support/k8-ops-vectors.ts.',
    decide: dec,
    bind,
  };
}

const cv = (cls: string, revision: number, decision: string) => ({ class: cls, revision, digest: `d-${cls}-${revision}`, decision });
export function buildPolicyClassVectors() {
  const validate: { name: string; input: unknown; expect: { ok: boolean } }[] = [
    { name: 'one-class', input: [cv('org', 3, 'allow')], expect: { ok: true } },
    { name: 'all-five', input: [cv('constitution', 1, 'allow'), cv('regulatory', 2, 'allow'), cv('org', 3, 'allow'), cv('blueprint', 4, 'allow'), cv('user', 5, 'allow')], expect: { ok: true } },
    { name: 'not-an-array', input: { class: 'org' }, expect: { ok: false } },
    { name: 'unknown-class', input: [cv('partner', 1, 'allow')], expect: { ok: false } },
    { name: 'duplicate-class', input: [cv('org', 1, 'allow'), cv('org', 2, 'deny')], expect: { ok: false } },
    { name: 'unknown-member', input: [{ ...cv('org', 1, 'allow'), extra: 1 }], expect: { ok: false } },
    { name: 'bad-revision', input: [cv('org', -1, 'allow')], expect: { ok: false } },
    { name: 'fractional-revision', input: [cv('org', 1.5, 'allow')], expect: { ok: false } },
    { name: 'empty-digest', input: [{ ...cv('org', 1, 'allow'), digest: '' }], expect: { ok: false } },
    { name: 'bad-decision', input: [cv('org', 1, 'maybe')], expect: { ok: false } },
    { name: 'six-entries', input: [cv('constitution', 1, 'allow'), cv('regulatory', 1, 'allow'), cv('org', 1, 'allow'), cv('blueprint', 1, 'allow'), cv('user', 1, 'allow'), cv('user', 2, 'allow')], expect: { ok: false } },
  ];
  const e = (decision: string, classes: unknown[], denied_by: string[], escalated_by: string[], reason?: string) => ({ decision, classes, denied_by, escalated_by, ...(reason ? { reason } : {}) });
  const decide: { name: string; input: unknown; expect: Record<string, unknown> }[] = [
    { name: 'all-allow', input: [cv('user', 5, 'allow'), cv('org', 3, 'allow')], expect: e('allow', [cv('org', 3, 'allow'), cv('user', 5, 'allow')], [], []) },
    { name: 'one-deny-names-who-said-no', input: [cv('user', 5, 'allow'), cv('constitution', 1, 'deny'), cv('org', 3, 'allow')], expect: e('deny', [cv('constitution', 1, 'deny'), cv('org', 3, 'allow'), cv('user', 5, 'allow')], ['constitution'], []) },
    { name: 'deny-beats-escalate', input: [cv('org', 3, 'escalate'), cv('regulatory', 2, 'deny')], expect: e('deny', [cv('regulatory', 2, 'deny'), cv('org', 3, 'escalate')], ['regulatory'], ['org']) },
    { name: 'escalate-is-absorbing-against-allow', input: [cv('org', 3, 'escalate'), cv('user', 5, 'allow')], expect: e('escalate', [cv('org', 3, 'escalate'), cv('user', 5, 'allow')], [], ['org']) },
    { name: 'several-deny-in-canonical-order', input: [cv('user', 1, 'deny'), cv('blueprint', 1, 'deny'), cv('regulatory', 1, 'deny')], expect: e('deny', [cv('regulatory', 1, 'deny'), cv('blueprint', 1, 'deny'), cv('user', 1, 'deny')], ['regulatory', 'blueprint', 'user'], []) },
    { name: 'no-class-consulted-denies', input: [], expect: e('deny', [], [], [], 'no_policy_class') },
    { name: 'a-malformed-list-denies', input: [cv('partner', 1, 'allow')], expect: e('deny', [], [], [], 'malformed policy classes: policy_classes[0].class is not a known class') },
    { name: 'a-duplicate-class-denies', input: [cv('org', 1, 'allow'), cv('org', 1, 'allow')], expect: e('deny', [], [], [], "malformed policy classes: policy class 'org' appears twice") },
    { name: 'not-an-array-denies', input: null, expect: e('deny', [], [], [], 'malformed policy classes: policy classes must be an array') },
  ];
  for (const v of validate) same({ ok: classVerdictsError(v.input) === null }, v.expect, `validate ${v.name}`);
  for (const v of decide) same(decideClasses(v.input), v.expect, `decide ${v.name}`);
  return {
    format: 'pca-policy-classes-vectors',
    ver: 1,
    about: 'Policy classes consulted for a decision. validate: ok iff a closed list of known classes (constitution, regulatory, org, blueprint, user), each at most once, with a non-negative integer revision, a digest and a decision. decide: the meet of the class decisions; classes are reported in the order constitution, regulatory, org, blueprint, user; denied_by / escalated_by name them; an empty list is a deny (no_policy_class); a malformed list is a deny with the reason shown. Generated by src/test-support/k8-ops-vectors.ts.',
    validate,
    decide,
  };
}

function same(a: unknown, b: unknown, what: string): void {
  if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${what}: ${JSON.stringify(a)} != ${JSON.stringify(b)}`);
}
