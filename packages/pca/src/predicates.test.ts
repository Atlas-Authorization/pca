import { describe, expect, it } from 'vitest';
import {
  envelopeCaveatEvaluator,
  evaluateCaveats,
  evaluateCondition,
  evaluateConditionTri,
  evaluatePredicates,
  isGroupCondition,
  isLeafCondition,
  isSafeRegexSource,
  MAX_PATTERN_SUBJECT_LEN,
  MAX_RE_RESOURCE_LEN,
  resolvePath,
  type ActionContext,
  type Condition,
  type Predicate,
} from './predicates';

const ctx = (over: Partial<ActionContext> = {}): ActionContext => ({
  action: { verb: 'revoke_session', resource: '/acct/42/sessions/s1', params: { session: { device: 'laptop' }, n: 5 } },
  subject: { id: 'u1', tags: ['a', 'b'] },
  env: { current_device: 'phone', region: 'eu' },
  ...over,
});

describe('predicates', () => {
  it('verb match: string, list, wildcard, mismatch', () => {
    expect(evaluatePredicates([{ verb: 'revoke_session' }], ctx()).allowed).toBe(true);
    expect(evaluatePredicates([{ verb: ['x', 'revoke_session'] }], ctx()).allowed).toBe(true);
    expect(evaluatePredicates([{ verb: '*' }], ctx()).allowed).toBe(true);
    const r = evaluatePredicates([{ verb: 'delete_account' }], ctx());
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/no predicate permits/);
  });
  it('resource: exact, prefix, regex, bad regex', () => {
    const v = 'revoke_session';
    expect(evaluatePredicates([{ verb: v, resource: '/acct/42/sessions/s1' }], ctx()).allowed).toBe(true);
    expect(evaluatePredicates([{ verb: v, resource: '/acct/42/*' }], ctx()).allowed).toBe(true);
    expect(evaluatePredicates([{ verb: v, resource: '/acct/43/*' }], ctx()).allowed).toBe(false);
    expect(evaluatePredicates([{ verb: v, resource: 're:/acct/\\d+/sessions/.+' }], ctx()).allowed).toBe(true);
    expect(evaluatePredicates([{ verb: v, resource: 're:/acct/\\d+' }], ctx()).allowed).toBe(false); // full match
    expect(evaluatePredicates([{ verb: v, resource: 're:(' }], ctx()).allowed).toBe(false);
  });
  it('spec example: revoke_session WHERE session.device != current_device', () => {
    const p: Predicate = {
      verb: 'revoke_session',
      where: [{ field: 'action.params.session.device', op: 'ne', ref: 'env.current_device' }],
    };
    expect(evaluatePredicates([p], ctx()).allowed).toBe(true);
    const same = ctx({ env: { current_device: 'laptop' } });
    expect(evaluatePredicates([p], same).allowed).toBe(false);
    const noEnv = ctx({ env: {} });
    expect(evaluatePredicates([p], noEnv).allowed).toBe(false); // missing ref => fail closed
  });
  it('dotted path resolution incl. arrays and forbidden segments', () => {
    expect(resolvePath(ctx(), 'subject.tags.1')).toEqual({ found: true, value: 'b' });
    expect(resolvePath(ctx(), 'subject.tags.9').found).toBe(false);
    expect(resolvePath(ctx(), 'action.params.session.device').value).toBe('laptop');
    expect(resolvePath(ctx(), 'other.x').found).toBe(false);
    expect(resolvePath(ctx(), 'action.__proto__.x').found).toBe(false);
    expect(resolvePath(ctx(), 'action.params.constructor').found).toBe(false);
    expect(resolvePath(ctx(), 'subject.toString').found).toBe(false);
    expect(resolvePath(ctx(), '').found).toBe(false);
  });
  it('operators', () => {
    const t = (c: Parameters<typeof evaluateCondition>[0]) => evaluateCondition(c, ctx());
    expect(t({ field: 'action.params.n', op: 'eq', value: 5 })).toBe(true);
    expect(t({ field: 'action.params.n', op: 'lt', value: 6 })).toBe(true);
    expect(t({ field: 'action.params.n', op: 'lte', value: 5 })).toBe(true);
    expect(t({ field: 'action.params.n', op: 'gt', value: 5 })).toBe(false);
    expect(t({ field: 'action.params.n', op: 'gte', value: 5 })).toBe(true);
    expect(t({ field: 'env.region', op: 'in', value: ['eu', 'us'] })).toBe(true);
    expect(t({ field: 'env.region', op: 'nin', value: ['us'] })).toBe(true);
    expect(t({ field: 'env.region', op: 'nin', value: ['eu'] })).toBe(false);
    expect(t({ field: 'action.resource', op: 'prefix', value: '/acct/' })).toBe(true);
    expect(t({ field: 'subject.id', op: 'exists' })).toBe(true);
    expect(t({ field: 'subject.nope', op: 'exists' })).toBe(false);
    expect(t({ field: 'subject.nope', op: 'exists', value: false })).toBe(true);
    expect(t({ field: 'subject.tags', op: 'eq', value: ['a', 'b'] })).toBe(true);
  });
  it('unknown op, missing field, type mismatch, bad shapes are safe (false, no throw)', () => {
    const t = (c: unknown) => evaluateCondition(c as never, ctx());
    expect(t({ field: 'env.region', op: 'nonsense_op', value: 'e.' })).toBe(false);
    expect(t({ field: 'env.zzz', op: 'eq', value: 1 })).toBe(false);
    expect(t({ field: 'env.zzz', op: 'ne', value: 1 })).toBe(false);
    expect(t({ field: 'env.region', op: 'lt', value: 5 })).toBe(false);
    expect(t({ field: 'env.region', op: 'in', value: 'eu' })).toBe(false);
    expect(t({ field: 'env.region', op: 'eq' })).toBe(false);
    expect(t(null)).toBe(false);
    expect(evaluatePredicates(null as never, ctx()).allowed).toBe(false);
    expect(evaluatePredicates([null as never, { verb: 5 as never }], ctx()).allowed).toBe(false);
    expect(evaluatePredicates([{ verb: '*' }], { action: null } as never).allowed).toBe(false);
    expect(evaluatePredicates([], ctx()).reason).toMatch(/no predicates/);
  });
  it('all where-conditions must hold; any predicate may match', () => {
    const p1: Predicate = { verb: 'revoke_session', where: [{ field: 'env.region', op: 'eq', value: 'us' }] };
    const p2: Predicate = { verb: 'revoke_session', where: [{ field: 'env.region', op: 'eq', value: 'eu' }, { field: 'action.params.n', op: 'lt', value: 10 }] };
    const r = evaluatePredicates([p1, p2], ctx());
    expect(r.allowed).toBe(true);
    expect(r.matched).toBe(p2);
  });
});

describe('envelope caveat evaluator', () => {
  const base = { now: 1_000_000 };
  const ev = (cv: Record<string, unknown> & { type: string }, c: object = {}) => envelopeCaveatEvaluator(cv, { ...base, ...c });
  it('expires / not_before', () => {
    expect(ev({ type: 'expires', at: 2_000_000 })).toBe(true);
    expect(ev({ type: 'expires', at: 1_000_000 })).toBe(false);
    expect(ev({ type: 'not_before', at: 1_000_000 })).toBe(true);
    expect(ev({ type: 'not_before', at: 1_000_001 })).toBe(false);
  });
  it('rate window', () => {
    const cv = { type: 'rate', max: 2, per_secs: 60 };
    expect(ev(cv, { recentActionTimes: [] })).toBe(true);
    expect(ev(cv, { recentActionTimes: [999_000] })).toBe(true);
    expect(ev(cv, { recentActionTimes: [999_000, 999_500] })).toBe(false);
    expect(ev(cv, { recentActionTimes: [900_000, 999_500] })).toBe(true); // 900_000 outside window
    expect(ev(cv)).toBe(false); // missing data
  });
  it('max_blast_radius / reversibility_max / delegation_depth', () => {
    expect(ev({ type: 'max_blast_radius', max: 0.3 }, { blastRadius: 0.3 })).toBe(true);
    expect(ev({ type: 'max_blast_radius', max: 0.3 }, { blastRadius: 0.31 })).toBe(false);
    expect(ev({ type: 'max_blast_radius', max: 0.3 })).toBe(false);
    expect(ev({ type: 'reversibility_max', class: 'rate_limited' }, { reversibilityClass: 'reversible' })).toBe(true);
    expect(ev({ type: 'reversibility_max', class: 'rate_limited' }, { reversibilityClass: 'irreversible' })).toBe(false);
    expect(ev({ type: 'reversibility_max', class: 'rate_limited' }, { reversibilityClass: 'weird' })).toBe(false);
    expect(ev({ type: 'delegation_depth', max: 1 }, { delegationDepth: 1 })).toBe(true);
    expect(ev({ type: 'delegation_depth', max: 1 }, { delegationDepth: 2 })).toBe(false);
  });
  it('unknown caveat / bad ctx fail closed; evaluateCaveats aggregates', () => {
    expect(ev({ type: 'mystery' })).toBe(false);
    expect(envelopeCaveatEvaluator({ type: 'expires', at: 1 }, null)).toBe(false);
    const r = evaluateCaveats([{ type: 'expires', at: 2_000_000 }, { type: 'delegation_depth', max: 0 }], { ...base, delegationDepth: 3 });
    expect(r).toEqual({ ok: false, failed: ['delegation_depth'] });
    expect(evaluateCaveats([], base).ok).toBe(true);
  });
});

describe('predicates hardening (P5-3)', () => {
  const rx = (re: string, resource: string) => evaluatePredicates([{ verb: '*', resource: `re:${re}` }], ctx({ action: { verb: 'x', resource } })).allowed;

  it('well-formed re: patterns keep their semantics', () => {
    expect(rx('/acct/[^/]+/sessions/\\d+', '/acct/42/sessions/7')).toBe(true);
    expect(rx('/acct/[^/]+/sessions/\\d+', '/acct/42/sessions/x')).toBe(false);
    expect(rx('(?:GET|POST) /x', 'POST /x')).toBe(true);
    expect(rx('/a/(?:b|c)/.*', '/a/c/zzz')).toBe(true);
    expect(rx('(ab)+c', 'ababc')).toBe(true);
    expect(rx('a{1,5}b', 'aaab')).toBe(true);
  });

  it('rejects nested-quantifier / ambiguous-alternation patterns (ReDoS) without evaluating them', () => {
    const evil = 'a'.repeat(40) + '!';
    const t0 = Date.now();
    for (const p of ['(a+)+$', '(a*)*b', '(a|aa)+$', '(.*a){10}', '(a+)*', '(?:a+)+']) {
      expect(rx(p, evil)).toBe(false);
      expect(isSafeRegexSource(p)).toBe(false);
    }
    expect(Date.now() - t0).toBeLessThan(500);
  });

  it('rejects backreferences, lookaround, too many unbounded quantifiers, huge repeats, and overlong resources', () => {
    for (const p of ['(a)\\1', '(?=a)a', '(?<=a)a', '(?<n>a)\\k<n>', '.*.*.*.*', 'a{1,1000}', '*a', '(a']) {
      expect(isSafeRegexSource(p)).toBe(false);
    }
    expect(rx('.*', 'a'.repeat(MAX_RE_RESOURCE_LEN + 1))).toBe(false);
    expect(rx('.*', 'a'.repeat(MAX_RE_RESOURCE_LEN))).toBe(true);
  });

  it('params-rooted conditions fail closed when params were not supplied (exists:false is not vacuous)', () => {
    const noParams = { action: { verb: 'v', resource: '/r' } } as ActionContext;
    expect(evaluateCondition({ field: 'action.params.secret', op: 'exists', value: false }, noParams)).toBe(false);
    expect(evaluateCondition({ field: 'action.params.x', op: 'nin', value: [1] }, noParams)).toBe(false);
    expect(evaluateCondition({ field: 'env.region', op: 'eq', value: 'x', ref: 'action.params.y' }, noParams)).toBe(false);
    // With params supplied, "absent" still works as before.
    const withParams = { action: { verb: 'v', resource: '/r', params: {} } } as ActionContext;
    expect(evaluateCondition({ field: 'action.params.secret', op: 'exists', value: false }, withParams)).toBe(true);
    // Non-params roots are unaffected.
    expect(evaluateCondition({ field: 'env.nothing', op: 'exists', value: false }, noParams)).toBe(true);
  });
});

describe('DSL extensions — new leaf ops', () => {
  const t = (c: Condition, over: Partial<ActionContext> = {}) =>
    evaluateCondition(c, {
      action: { verb: 'v', resource: '/acct/42/items/7', params: { name: 'report-final.pdf', path: '/a/b/c', code: 'AB-12' } },
      subject: { id: 'User::alice', principal: { type: 'User', tags: ['admin', 'eu'] }, groups: ['team:core'] },
      env: {
        region: 'eu',
        wildcard: 'eu-*',
        parents: { 'team:core': ['team:eng'], 'team:eng': ['org:acme'], 'org:acme': [] },
        cyclic: { a: ['b'], b: ['c'], c: ['a'] },
      },
      ...over,
    });

  it('like: anchored glob with * and ? and escaping', () => {
    expect(t({ field: 'action.params.name', op: 'like', value: '*.pdf' })).toBe(true);
    expect(t({ field: 'action.params.name', op: 'like', value: 'report-*' })).toBe(true);
    expect(t({ field: 'action.params.name', op: 'like', value: '*.txt' })).toBe(false);
    expect(t({ field: 'action.params.code', op: 'like', value: 'AB-??' })).toBe(true);
    expect(t({ field: 'action.params.code', op: 'like', value: 'AB-?' })).toBe(false); // anchored: needs exactly one more
    // escaping: a literal star / question mark
    expect(t({ field: 'action.params.name', op: 'like', value: 'report-final.pd?' })).toBe(true);
    expect(t({ field: 'action.params.code', op: 'like', value: 'AB\\-12' })).toBe(true);
    expect(evaluateConditionTri({ field: 'action.params.code', op: 'like', value: 'A*' }, {
      action: { verb: 'v', resource: '/r', params: { code: 'A*literal' } },
    } as ActionContext)).toBe('true');
    // escaped literal star must NOT act as a wildcard
    expect(t({ field: 'action.params.code', op: 'like', value: 'A\\*' })).toBe(false);
    // non-string value / operand => unknown => false (fails closed)
    expect(t({ field: 'action.params.name', op: 'like', value: 5 })).toBe(false);
    expect(t({ field: 'env.region', op: 'like', ref: 'subject.groups' })).toBe(false);
  });

  it('like: oversized subject fails closed', () => {
    const big = 'a'.repeat(MAX_PATTERN_SUBJECT_LEN + 1);
    expect(
      evaluateCondition({ field: 'action.params.x', op: 'like', value: '*' }, {
        action: { verb: 'v', resource: '/r', params: { x: big } },
      } as ActionContext),
    ).toBe(false);
  });

  it('matches: anchored safe regex, fail-closed on regex-bomb / invalid / non-string', () => {
    expect(t({ field: 'action.params.code', op: 'matches', value: '[A-Z]{2}-\\d{2}' })).toBe(true);
    expect(t({ field: 'action.params.code', op: 'matches', value: '\\d+' })).toBe(false); // anchored full-match
    expect(t({ field: 'env.region', op: 'matches', value: 'e.' })).toBe(true);
    // ReDoS construct rejected (unsafe source) => unknown => false, and does NOT hang
    const t0 = Date.now();
    expect(
      evaluateCondition({ field: 'action.params.x', op: 'matches', value: '(a+)+$' }, {
        action: { verb: 'v', resource: '/r', params: { x: 'a'.repeat(40) + '!' } },
      } as ActionContext),
    ).toBe(false);
    expect(Date.now() - t0).toBeLessThan(500);
    // invalid regex / non-string
    expect(t({ field: 'env.region', op: 'matches', value: '(' })).toBe(false);
    expect(t({ field: 'subject.groups', op: 'matches', value: '.*' })).toBe(false);
  });

  it('is_a: Type::id string prefix, object type, tags, ref operand', () => {
    expect(t({ field: 'subject.id', op: 'is_a', value: 'User' })).toBe(true);
    expect(t({ field: 'subject.id', op: 'is_a', value: 'Group' })).toBe(false);
    expect(t({ field: 'action.resource', op: 'is_a', value: 'User' })).toBe(false);
    expect(t({ field: 'subject.principal', op: 'is_a', value: 'User' })).toBe(true); // object.type
    expect(t({ field: 'subject.principal', op: 'is_a', value: 'admin' })).toBe(true); // object.tags
    expect(t({ field: 'subject.principal', op: 'is_a', value: 'nope' })).toBe(false);
    // provided value via ref
    expect(
      t({ field: 'subject.id', op: 'is_a', ref: 'env.expected_type' }, { env: { expected_type: 'User' } }),
    ).toBe(true);
    // a value with no decidable type/tag => unknown => false
    expect(t({ field: 'action.params.code', op: 'is_a', value: 'AB-12::x' })).toBe(false);
    expect(t({ field: 'action.params', op: 'is_a', value: 'Anything' })).toBe(false);
  });

  it('member_of: reflexive bounded transitive closure, cycle-guarded, array targets', () => {
    const mo = (value: unknown, collection = 'env.parents') =>
      t({ field: 'subject.groups.0', op: 'member_of', value, collection });
    expect(mo('team:core')).toBe(true); // reflexive
    expect(mo('team:eng')).toBe(true); // one hop
    expect(mo('org:acme')).toBe(true); // transitive
    expect(mo('org:other')).toBe(false); // not reachable (cleanly false)
    expect(mo(['org:other', 'org:acme'])).toBe(true); // any-of targets
    // cycle guard: resolve against a cyclic adjacency without hanging
    expect(
      t({ field: 'env.start', op: 'member_of', value: 'c', collection: 'env.cyclic' }, { env: { start: 'a', cyclic: { a: ['b'], b: ['c'], c: ['a'] } } }),
    ).toBe(true);
    expect(
      t({ field: 'env.start', op: 'member_of', value: 'z', collection: 'env.cyclic' }, { env: { start: 'a', cyclic: { a: ['b'], b: ['c'], c: ['a'] } } }),
    ).toBe(false);
    // missing / non-object collection, non-string field => fail closed
    expect(t({ field: 'subject.groups.0', op: 'member_of', value: 'x', collection: 'env.nope' })).toBe(false);
    expect(t({ field: 'subject.groups', op: 'member_of', value: 'x', collection: 'env.parents' })).toBe(false);
    expect(t({ field: 'subject.groups.0', op: 'member_of', value: 'x' })).toBe(false); // no collection
    // prototype-pollution key is never traversed
    expect(
      t({ field: 'env.start', op: 'member_of', value: 'polluted', collection: 'env.adj' }, { env: { start: '__proto__', adj: { x: ['y'] } } }),
    ).toBe(false);
  });
});

describe('DSL extensions — boolean groupings (all_of / any_of / not)', () => {
  const ctx = (over: Partial<ActionContext> = {}): ActionContext => ({
    action: { verb: 'pay', resource: '/acct/42', params: { amount: 500, currency: 'usd' } },
    subject: { id: 'u1' },
    env: { region: 'eu' },
    ...over,
  });
  const t = (c: Condition, over: Partial<ActionContext> = {}) => evaluateCondition(c, ctx(over));

  it('all_of is conjunction; any_of is disjunction', () => {
    const amtOk: Condition = { field: 'action.params.amount', op: 'lte', value: 1000 };
    const eu: Condition = { field: 'env.region', op: 'eq', value: 'eu' };
    const us: Condition = { field: 'env.region', op: 'eq', value: 'us' };
    expect(t({ all_of: [amtOk, eu] })).toBe(true);
    expect(t({ all_of: [amtOk, us] })).toBe(false);
    expect(t({ any_of: [us, eu] })).toBe(true);
    expect(t({ any_of: [us, { field: 'env.region', op: 'eq', value: 'ap' }] })).toBe(false);
  });

  it('not negates a cleanly-decided condition and FAILS CLOSED on an undecidable child', () => {
    expect(t({ not: { field: 'env.region', op: 'eq', value: 'us' } })).toBe(true); // region != us
    expect(t({ not: { field: 'env.region', op: 'eq', value: 'eu' } })).toBe(false);
    // inner is UNKNOWN (missing field) => not must NOT grant
    expect(t({ not: { field: 'env.missing', op: 'eq', value: 'x' } })).toBe(false);
    // inner is UNKNOWN (unknown op) => not must NOT grant
    expect(t({ not: { field: 'env.region', op: 'bogus' as never, value: 'x' } })).toBe(false);
    // inner is UNKNOWN (regex bomb) => not must NOT grant
    expect(t({ not: { field: 'env.region', op: 'matches', value: '(a+)+$' } })).toBe(false);
  });

  it('nesting: arbitrary boolean logic', () => {
    const c: Condition = {
      all_of: [
        { field: 'action.params.amount', op: 'gt', value: 0 },
        { any_of: [{ field: 'env.region', op: 'eq', value: 'eu' }, { field: 'env.region', op: 'eq', value: 'us' }] },
        { not: { field: 'action.params.currency', op: 'eq', value: 'xxx' } },
      ],
    };
    expect(t(c)).toBe(true);
    expect(t(c, { action: { verb: 'pay', resource: '/acct/42', params: { amount: 500, currency: 'xxx' } } })).toBe(false);
  });

  it('empty / malformed groupings fail closed', () => {
    expect(evaluateConditionTri({ all_of: [] }, ctx())).toBe('unknown');
    expect(evaluateConditionTri({ any_of: [] }, ctx())).toBe('unknown');
    expect(t({ all_of: 'x' as never })).toBe(false);
    expect(t({ any_of: 5 as never })).toBe(false);
    // an all_of whose child is unknown is unknown (not granted)
    expect(evaluateConditionTri({ all_of: [{ field: 'env.region', op: 'eq', value: 'eu' }, { field: 'env.x', op: 'eq', value: 1 }] }, ctx())).toBe('unknown');
    // an any_of with one true short-circuits past an unknown
    expect(evaluateConditionTri({ any_of: [{ field: 'env.region', op: 'eq', value: 'eu' }, { field: 'env.x', op: 'eq', value: 1 }] }, ctx())).toBe('true');
  });

  it('groupings compose with predicates (where is an implicit AND over groupings)', () => {
    const p: Predicate = {
      verb: 'pay',
      where: [{ any_of: [{ field: 'env.region', op: 'eq', value: 'eu' }, { field: 'env.region', op: 'eq', value: 'us' }] }],
    };
    expect(evaluatePredicates([p], ctx()).allowed).toBe(true);
    expect(evaluatePredicates([p], ctx({ env: { region: 'ap' } })).allowed).toBe(false);
  });

  it('type guards distinguish leaves from groupings', () => {
    expect(isLeafCondition({ field: 'env.region', op: 'eq', value: 'eu' })).toBe(true);
    expect(isGroupCondition({ field: 'env.region', op: 'eq', value: 'eu' })).toBe(false);
    expect(isGroupCondition({ all_of: [] })).toBe(true);
    expect(isGroupCondition({ not: { field: 'x', op: 'exists' } })).toBe(true);
    expect(isLeafCondition({ any_of: [] })).toBe(false);
  });
});
