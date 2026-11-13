import { describe, expect, it } from 'vitest';
import { validatePolicyAgainstSchema, verbShapes, type PolicyInput, type SchemaFinding, type ValidateOptions, type VerbShape } from './index';
import { refundShape } from './k2-fixtures';

const cond = (name: string, op: string, value: unknown, extra: Record<string, unknown> = {}) => ({ field: `action.params.${name}`, op, value, ...extra }) as never;
const brief = (fs: SchemaFinding[]): string[] => fs.map((f) => `${f.severity}:${f.code}`);
const pick = (fs: SchemaFinding[], ...codes: string[]): SchemaFinding[] => fs.filter((f) => codes.includes(f.code));
const at = (code: SchemaFinding['code'], severity: SchemaFinding['severity'], where: string, message: string): SchemaFinding => ({ code, severity, where, message });
const W0 = 'predicates[0].where[0]';

const num: VerbShape = {
  verb: 't.num',
  params: {
    n: { type: 'integer', min: 10, max: 20 },
    lo: { type: 'integer', min: 10 },
    hi: { type: 'integer', max: 20 },
    free: {},
    ub: { min: 0, max: 10 },
    flag: { type: 'boolean' },
    tags: { type: 'set' },
    when: { type: 'date' },
    label: { type: 'string', values: ['a', 'b', 'c'] },
  },
};
const lint = (where: unknown[], shape: VerbShape = num, o: ValidateOptions = {}): SchemaFinding[] => validatePolicyAgainstSchema({ predicates: [{ verb: shape.verb, where: where as never }] }, [shape], o).findings;

describe('validate: integer bounds', () => {
  const E = 'error:out-of-range';
  const I = 'info:redundant-bound';
  const table: Array<[string, number, string[]]> = [
    ['eq', 21, [E]], ['eq', 9, [E]], ['eq', 20, []], ['eq', 10, []], ['eq', 15, []],
    ['gt', 25, [E]], ['gt', 20, [E]], ['gt', 19, []], ['gt', 15, []], ['gt', 5, []],
    ['gte', 21, [E]], ['gte', 20, []], ['gte', 11, []], ['gte', 10, [I]], ['gte', 9, [I]],
    ['lt', 5, [E]], ['lt', 10, [E]], ['lt', 11, []], ['lt', 15, []], ['lt', 25, []],
    ['lte', 9, [E]], ['lte', 10, []], ['lte', 15, []], ['lte', 19, []], ['lte', 20, [I]], ['lte', 21, [I]],
  ];
  it.each(table)('n %s %i', (op, v, expected) => {
    expect(brief(pick(lint([cond('n', op, v)]), 'out-of-range', 'redundant-bound'))).toEqual(expected);
  });

  it('spells the open side of a one-sided bound, and both sides of a two-sided one', () => {
    expect(pick(lint([cond('lo', 'eq', 5)]), 'out-of-range')).toEqual([at('out-of-range', 'error', W0, "'lo' eq 5 can never hold: the schema bounds it to [10, inf]")]);
    expect(pick(lint([cond('hi', 'eq', 25)]), 'out-of-range')).toEqual([at('out-of-range', 'error', W0, "'hi' eq 25 can never hold: the schema bounds it to [-inf, 20]")]);
    expect(pick(lint([cond('n', 'eq', 25)]), 'out-of-range')).toEqual([at('out-of-range', 'error', W0, "'n' eq 25 can never hold: the schema bounds it to [10, 20]")]);
    expect(pick(lint([cond('n', 'lte', 20)]), 'redundant-bound')).toEqual([at('redundant-bound', 'info', W0, "'n' lte 20 never binds: the schema already bounds it to [10, 20]")]);
    expect(pick(lint([cond('hi', 'lte', 30)]), 'redundant-bound')).toEqual([at('redundant-bound', 'info', W0, "'hi' lte 30 never binds: the schema already bounds it to [-inf, 20]")]);
    expect(pick(lint([cond('lo', 'gte', 5)]), 'redundant-bound')).toEqual([at('redundant-bound', 'info', W0, "'lo' gte 5 never binds: the schema already bounds it to [10, inf]")]);
  });

  it('checks bounds only for integer parameters compared with a plain number', () => {
    expect(pick(lint([cond('ub', 'eq', 50)]), 'out-of-range')).toEqual([]);
    expect(pick(lint([cond('n', 'gt', 999, { ref: 'env.q' })]), 'out-of-range')).toEqual([]);
    expect(pick(lint([cond('n', 'gt', '200000')]), 'out-of-range')).toEqual([]);
    expect(brief(pick(lint([cond('n', 'gt', '200000')]), 'type-mismatch'))).toEqual(['error:type-mismatch']);
  });
});

describe('validate: types and operators', () => {
  const mismatch = (where: unknown[]) => pick(lint(where), 'type-mismatch');

  it('compares an integer parameter with numbers only, whatever the operator', () => {
    expect(mismatch([cond('n', 'lte', '500')])).toEqual([at('type-mismatch', 'error', W0, "'n' is integer but is compared (lte) with string")]);
    expect(mismatch([cond('n', 'ne', 'x')])).toHaveLength(1);
    expect(mismatch([cond('n', 'in', ['x'])])).toHaveLength(1);
    expect(mismatch([cond('n', 'nin', ['x'])])).toHaveLength(1);
    expect(mismatch([cond('n', 'nin', [11, 12])])).toEqual([]);
    expect(mismatch([cond('n', 'in', [11, 12])])).toEqual([]);
    expect(mismatch([cond('n', 'like', 'x%')])).toEqual([]);
    expect(mismatch([cond('n', 'lte', 'x', { ref: 'env.q' })])).toEqual([]);
    expect(mismatch([cond('n', 'lte', Infinity)])).toEqual([at('type-mismatch', 'error', W0, "'n' is integer but is compared (lte) with number")]);
  });

  it('compares booleans, dates and strings with their own type; sets and untyped parameters take anything', () => {
    expect(mismatch([cond('flag', 'eq', true)])).toEqual([]);
    expect(mismatch([cond('flag', 'eq', 'yes')])).toEqual([at('type-mismatch', 'error', W0, "'flag' is boolean but is compared (eq) with string")]);
    expect(mismatch([cond('when', 'eq', '2026-01-01')])).toEqual([]);
    expect(mismatch([cond('when', 'eq', 5)])).toEqual([at('type-mismatch', 'error', W0, "'when' is date but is compared (eq) with number")]);
    expect(mismatch([cond('tags', 'eq', 5)])).toEqual([]);
    expect(mismatch([cond('tags', 'eq', 'x')])).toEqual([]);
    expect(mismatch([cond('free', 'eq', 5)])).toEqual([]);
    expect(mismatch([cond('label', 'eq', 'a')])).toEqual([]);
    expect(mismatch([cond('label', 'eq', ['a'])])).toEqual([at('type-mismatch', 'error', W0, "'label' is string but is compared (eq) with object")]);
  });

  it('spreads the members of in and nin only', () => {
    const typed = (op: string, v: unknown) => pick(lint([cond('label', op, v)]), 'type-mismatch', 'value-not-in-enum');
    expect(typed('in', 'a')).toEqual([]);
    expect(typed('in', ['a', 'b'])).toEqual([]);
    expect(typed('nin', ['a', 'b'])).toEqual([]);
  });

  it('orders only strings and dates; anything else typed is an error, an untyped parameter is left alone', () => {
    expect(pick(lint([cond('free', 'lte', 5)]), 'type-mismatch', 'ordering-on-string')).toEqual([]);
    expect(pick(lint([cond('tags', 'lte', 'x')]), 'type-mismatch')).toEqual([at('type-mismatch', 'error', W0, "ordering operator lte on set parameter 'tags'")]);
    expect(pick(lint([cond('flag', 'lte', true)]), 'type-mismatch', 'ordering-on-string')).toEqual([at('type-mismatch', 'error', W0, "ordering operator lte on boolean parameter 'flag'")]);
    expect(pick(lint([cond('when', 'lte', '2026-01-01')]), 'type-mismatch', 'ordering-on-string')).toEqual([at('ordering-on-string', 'warn', W0, "'when' is date: ordering follows UTF-8 byte order")]);
    expect(pick(lint([cond('label', 'lte', 'b')]), 'type-mismatch', 'ordering-on-string')).toEqual([at('ordering-on-string', 'warn', W0, "'label' is string: ordering follows UTF-8 byte order")]);
  });
});

describe('validate: closed value sets', () => {
  const enums = (v: unknown, op = 'in') => pick(lint([cond('label', op, v)]), 'value-not-in-enum');

  it('reports a set none of whose members exists as an error and a partial miss as a warning', () => {
    expect(enums('zzz', 'eq')).toEqual([at('value-not-in-enum', 'error', W0, `no value of eq ["zzz"] is in the schema's set for 'label'`)]);
    expect(enums(['x', 'zzz'])).toEqual([at('value-not-in-enum', 'error', W0, `no value of in ["x","zzz"] is in the schema's set for 'label'`)]);
    expect(enums(['a', 'zzz'])).toEqual([at('value-not-in-enum', 'warn', W0, `["zzz"] are not in the schema's set for 'label'`)]);
    expect(enums(['a', 'b'])).toEqual([]);
    expect(enums('a', 'eq')).toEqual([]);
  });

  it('judges the members by the first one being a string, and counts only string members as missing', () => {
    const typed = (v: unknown) => brief(pick(lint([cond('label', 'in', v)]), 'type-mismatch', 'value-not-in-enum'));
    expect(typed([5, 'zzz'])).toEqual(['error:type-mismatch']);
    expect(typed(['zzz', 5])).toEqual(['error:type-mismatch', 'warn:value-not-in-enum']);
  });
});

describe('validate: declared verbs and parameters', () => {
  const multi: VerbShape[] = [{ verb: 'm.a', params: { x: { type: 'integer' } } }, { verb: 'm.b', params: {} }, { verb: 'm.c', params: {} }];
  const run = (predicates: unknown[], o: ValidateOptions = {}, shapes = multi) => validatePolicyAgainstSchema({ predicates: predicates as never }, shapes, o);

  it('names the verbs that do not declare a parameter, in schema order', () => {
    expect(run([{ verb: '*', where: [cond('x', 'lte', 5)] }]).findings).toEqual([at('undeclared-param', 'warn', W0, "parameter 'x' is not declared by m.b, m.c")]);
    expect(run([{ verb: '*', where: [cond('nope', 'eq', 1)] }]).findings).toEqual([at('undeclared-param', 'error', W0, "parameter 'nope' is declared by none of m.a, m.b, m.c")]);
  });

  it('checks every verb a wildcard or a list names, and only those', () => {
    expect(run([{ verb: ['*'], where: [cond('x', 'lte', 5)] }]).findings).toEqual([at('undeclared-param', 'warn', W0, "parameter 'x' is not declared by m.b, m.c")]);
    expect(run([{ verb: ['m.a'], where: [cond('x', 'lte', 5)] }]).findings).toEqual([]);
    expect(run([{ verb: ['m.a', 'm.nope'], where: [cond('x', 'lte', 5)] }]).findings).toEqual([at('undeclared-verb', 'error', 'predicates[0]', "verb 'm.nope' is not declared by the schema")]);
    expect(run([{ verb: 'm.*' }]).findings).toEqual([at('undeclared-verb', 'error', 'predicates[0]', "verb 'm.*' is not declared by the schema")]);
  });

  it('reports an undeclared verb once, and does not look at its conditions', () => {
    expect(run([{ verb: 'm.a' }, { verb: 'm.nope', where: [cond('x', 'eq', 1)] }]).findings).toEqual([at('undeclared-verb', 'error', 'predicates[1]', "verb 'm.nope' is not declared by the schema")]);
  });

  it('looks inside all_of, any_of and not, and only at action parameters', () => {
    const msg = "parameter 'nope' is declared by none of m.a";
    for (const group of [{ all_of: [cond('nope', 'eq', 1)] }, { any_of: [cond('nope', 'eq', 1)] }, { not: cond('nope', 'eq', 1) }, { all_of: [{ any_of: [{ not: cond('nope', 'eq', 1) }] }] }]) {
      expect(run([{ verb: 'm.a', where: [group] }]).findings).toEqual([at('undeclared-param', 'error', W0, msg)]);
    }
    expect(run([{ verb: 'm.a', where: [{ field: 'env.region', op: 'eq', value: 'x' }] }]).findings).toEqual([]);
  });

  it('skips predicates that are not objects', () => {
    expect(run([null, 'x', { verb: 'm.a' }])).toEqual({ ok: true, findings: [] });
  });

  it('flags an unsatisfiable predicate and an undeclared verb in a prohibition at their positions', () => {
    const dead = run([{ verb: 'm.a' }, { verb: 'm.a', where: [cond('x', 'gte', 50), cond('x', 'lte', 10)] }]);
    expect(dead.findings).toEqual([at('unreachable-predicate', 'warn', 'predicates[1]', 'no action can ever match this predicate')]);
    expect(dead.ok).toBe(true);
    const veto = validatePolicyAgainstSchema({ predicates: [{ verb: 'm.a' }], vetoes: [{ id: 'v', kind: 'deny', when: { verb: 'm.nope' } }] }, multi);
    expect(veto).toEqual({ ok: true, findings: [at('undeclared-verb', 'warn', 'vetoes[0]', "verb 'm.nope' is not declared by the schema")] });
  });

  it('is not ok when any finding is an error', () => {
    expect(run([{ verb: 'm.nope' }]).ok).toBe(false);
    expect(run([{ verb: 'm.a' }]).ok).toBe(true);
  });
});

describe('validate: unit tags (rule 20)', () => {
  const uShape: VerbShape = { verb: 'u.v', params: { amount: { type: 'integer', unit: 'usd' } } };
  const usd = { kind: 'money', currency: 'USD', exponent: 2 };
  const schemaUnits = { usd };
  const run = (c: unknown, o: ValidateOptions) => validatePolicyAgainstSchema({ predicates: [{ verb: 'u.v', where: [c as never] }] }, [uShape], o).findings;

  it('requires a tag for ordering and equality conditions only', () => {
    expect(run(cond('amount', 'eq', 5), { units: {}, schemaUnits })).toEqual([at('unit-missing', 'error', W0, "'amount' carries unit 'usd' but the policy has no unit tag for it (rule 20)")]);
    expect(run(cond('amount', 'lte', 5), { units: {}, schemaUnits })).toHaveLength(1);
    expect(run(cond('amount', 'ne', 5), { units: {}, schemaUnits })).toEqual([]);
    expect(run(cond('amount', 'in', [5]), { units: {}, schemaUnits })).toEqual([]);
  });

  it('finds the tag under the parameter name when the condition reads a nested path', () => {
    expect(run(cond('amount.x', 'lte', 5), { units: { 'action.params.amount': usd }, schemaUnits })).toEqual([]);
    expect(run(cond('amount.x', 'lte', 5), { units: {}, schemaUnits })).toHaveLength(1);
  });

  it('accepts a tag when the schema has no unit table, and compares kind, currency and exponent', () => {
    expect(run(cond('amount', 'lte', 5), { units: { 'action.params.amount': usd } })).toEqual([]);
    const other = { kind: 'other', currency: 'USD', exponent: 2 };
    expect(run(cond('amount', 'lte', 5), { units: { 'action.params.amount': other }, schemaUnits })).toEqual([
      at('unit-mismatch', 'error', W0, `'amount': policy unit {"kind":"other","currency":"USD","exponent":2} differs from the schema's {"kind":"money","currency":"USD","exponent":2} (rule 20)`),
    ]);
  });

  it('takes the unit table from a signed action schema', () => {
    const doc = {
      v: 1,
      kind: 'pca-action-schema',
      site: 's',
      aud: 'a',
      version: '1',
      units: { usd_cents: usd },
      verbs: [{ verb: 'stripe.refund', kind: 'write', params: { amount: { type: 'integer', semantic: 'money.amount', sensitivity: 'material', unit: 'usd_cents', max: 1000 } } }],
      sig: { alg: 'ed25519', kid: 'k', value: 'x' },
    };
    const policy: PolicyInput = { predicates: [{ verb: 'stripe.refund', where: [cond('amount', 'lte', 500)] }] };
    const eur = { kind: 'money', currency: 'EUR', exponent: 2 };
    expect(brief(validatePolicyAgainstSchema(policy, doc as never, { units: { 'action.params.amount': eur } }).findings)).toEqual(['error:unit-mismatch']);
    expect(validatePolicyAgainstSchema(policy, doc as never, { units: { 'action.params.amount': usd } }).findings).toEqual([]);
  });
});

describe('validate: money ceilings and ungranted verbs', () => {
  const schema: VerbShape[] = [refundShape, { verb: 'stripe.list', params: { limit: { type: 'integer', min: 1, max: 100 } } }];
  const run = (predicates: unknown[], o: ValidateOptions = {}) => validatePolicyAgainstSchema({ predicates: predicates as never }, schema, o).findings;
  const unbounded = at('unbounded-money', 'warn', 'stripe.refund', "'stripe.refund' can move 'amount' with no per-action ceiling in at least one granting predicate");
  const refundWith = (...where: unknown[]) => ({ verb: 'stripe.refund', where });

  it('warns when a predicate that grants the money verb has no ceiling', () => {
    expect(run([{ verb: 'stripe.refund' }])).toEqual([unbounded]);
    expect(run([{ verb: '*' }])).toEqual([unbounded]);
    expect(run([{ verb: ['stripe.refund'] }])).toEqual([unbounded]);
    expect(run([{ verb: ['*'] }])).toEqual([unbounded]);
  });

  it('does not count predicates of other verbs as granting it', () => {
    expect(run([{ verb: 'stripe.list' }])).toEqual([]);
    expect(run([{ verb: ['stripe.list'] }])).toEqual([]);
    expect(run([{ verb: 'stripe.refund.extra' }]).map((f) => f.code)).toEqual(['undeclared-verb']);
    expect(run([{ verb: 'stripe.re*' }]).map((f) => f.code)).toEqual(['undeclared-verb']);
    expect(pick(run([{ verb: [''] }]), 'undeclared-verb', 'unbounded-money')).toEqual([at('undeclared-verb', 'error', 'predicates[0]', "verb '' is not declared by the schema")]);
  });

  it('accepts lt, lte, eq and in as ceilings, also inside all_of', () => {
    expect(run([refundWith(cond('amount', 'lt', 500))])).toEqual([]);
    expect(run([refundWith(cond('amount', 'lte', 500))])).toEqual([]);
    expect(run([refundWith(cond('amount', 'eq', 500))])).toEqual([]);
    expect(run([refundWith(cond('amount', 'in', [1, 2]))])).toEqual([]);
    expect(run([refundWith({ all_of: [cond('amount', 'lte', 500)] })])).toEqual([]);
  });

  it('does not accept a lower bound, another parameter, or a ceiling that only some alternatives carry', () => {
    expect(run([refundWith(cond('amount', 'gte', 5))])).toEqual([unbounded]);
    expect(run([refundWith(cond('reason', 'eq', 'fraud'))])).toEqual([unbounded]);
    expect(run([refundWith({ any_of: [cond('amount', 'lte', 500), cond('reason', 'eq', 'fraud')] })])).toEqual([unbounded]);
    expect(run([refundWith({ not: cond('amount', 'lte', 500) })])).toEqual([unbounded]);
  });

  it('needs the ceiling in every granting predicate', () => {
    expect(run([refundWith(cond('amount', 'lte', 500)), { verb: 'stripe.refund' }])).toEqual([unbounded]);
    expect(run([refundWith(cond('amount', 'lte', 500)), refundWith(cond('amount', 'lt', 9))])).toEqual([]);
  });

  it('lists schema verbs that nothing grants, a money verb once', () => {
    const ungranted = at('verb-not-granted', 'info', 'stripe.refund', "the schema declares 'stripe.refund' but no predicate grants it");
    expect(run([{ verb: 'stripe.list' }], { listUngranted: true })).toEqual([ungranted]);
    expect(run([{ verb: 'stripe.list' }])).toEqual([]);
  });

  it('lists ungranted verbs without money parameters', () => {
    const ng: VerbShape[] = [{ verb: 'x.a', params: { n: { type: 'integer' } } }, { verb: 'x.b', params: { n: { type: 'integer' } } }];
    const where = (predicates: unknown[]) => validatePolicyAgainstSchema({ predicates: predicates as never }, ng, { listUngranted: true }).findings.map((f) => [f.code, f.severity, f.where, f.message]);
    const miss = (v: string) => ['verb-not-granted', 'info', v, `the schema declares '${v}' but no predicate grants it`];
    expect(where([{ verb: 'x.a' }, { verb: 'x.b' }])).toEqual([]);
    expect(where([{ verb: '*' }])).toEqual([]);
    expect(where([{ verb: ['*'] }])).toEqual([]);
    expect(where([{ verb: ['x.a', 'x.b'] }])).toEqual([]);
    expect(where([{ verb: 'x.a' }])).toEqual([miss('x.b')]);
    expect(where([{ verb: ['x.a'] }])).toEqual([miss('x.b')]);
    expect(where([{ verb: ['x.b'] }])).toEqual([miss('x.a')]);
    expect(where([{ verb: 'x.a' }, { verb: ['x.a'] }])).toEqual([miss('x.b')]);
    expect(where([])).toEqual([miss('x.a'), miss('x.b')]);
  });
});

describe('verbShapes (exact)', () => {
  it('names a definition without verb or id with the empty verb', () => {
    expect(verbShapes([{ params: {} } as never])).toEqual([{ verb: '', params: {} }]);
  });

  it('keeps the semantic and the unit of shape-style parameters, and adds neither key to the others', () => {
    const out = verbShapes([{ verb: 'a', params: { x: { type: 'integer', semantic: 'money.amount', unit: 'usd' }, y: { type: 'string' } } }]);
    expect(out).toStrictEqual([{ verb: 'a', params: { x: { type: 'integer', semantic: 'money.amount', unit: 'usd' }, y: { type: 'string' } } }]);
  });
});

describe('validate: malformed groups', () => {
  it('a group whose all_of or any_of is not a list contributes no conditions', () => {
    for (const group of [{ all_of: 'x' }, { any_of: 'x' }, { all_of: [{ any_of: 'x' }] }]) {
      expect(pick(lint([group]), 'undeclared-param', 'type-mismatch', 'out-of-range'), JSON.stringify(group)).toEqual([]);
    }
  });

  it('a malformed all_of next to a list-valued any_of: the any_of members are checked', () => {
    expect(pick(lint([{ all_of: 'x', any_of: [cond('nope', 'eq', 1)] }]), 'undeclared-param')).toEqual([at('undeclared-param', 'error', W0, "parameter 'nope' is declared by none of t.num")]);
  });
});
