// Oracle (extra, Java lane): the parts of @atlasauth/pca-policy-ci that run on the analyzer and that policy-ci.mts leaves out:
// lintPolicy with a schema (rule schema-mismatch over validatePolicyAgainstSchema), and the authoring `test` and `coverage` commands run to
// their results (runPolicyTests, coverage, coverageGate). Every case keeps its reference result, internal errors included.
// PORTING: lintPolicy(input, opts) -> PolicyCi.lintPolicy (default analyzer validator); testCommand(policy, doc, opts) / coverageCommand(policy, traffic, opts)
// -> Authoring.testCommand / coverageCommand with Authoring.ANALYZER_BACKEND ({ok, exitCode, lines}); all compared by JSON value.
// Writes out/ref-policy-ci-java-extra.json.gz.
import * as CI0 from '../../../packages/pca-policy-ci/src/index';
import * as AU0 from '../../../packages/pca-policy-ci/src/authoring';
import * as AN0 from '../../../packages/pca-analyzer/src/index';
import { Oracle, refWrite } from './lib.mjs';

const CI: any = (CI0 as any).default ?? CI0;
const AU: any = (AU0 as any).default ?? AU0;
const AN: any = (AN0 as any).default ?? AN0;
const o = new Oracle('policy-ci-java-extra', 'tools/pca-audit/oracles/policy-ci-java-extra.mts', 'TS-reference oracle for policy-ci schema, test and coverage (Java lane).');
const FUTURE = 4_000_000_000_000;
const P = (verb: any, resource?: any, where?: any[]) => ({ verb, ...(resource !== undefined ? { resource } : {}), ...(where ? { where } : {}) });
const W = (field: string, op: string, value: any) => ({ field, op, value });
const EXP = { type: 'expires', at: FUTURE };
const GATE = { type: 'max_blast_radius', max: 0.1 };
let n = 0;
const J = (x: any) => JSON.parse(JSON.stringify(x));
const run = (fn: string, ref: (...a: any[]) => any, args: any[]) => o.run(fn, `#${n++}`, ref, args);

const POL: any[] = [
  { predicates: [P('docs.read', '/docs/*', [W('action.params.size', 'lte', 100)])], caveats: [EXP, GATE] },
  { predicates: [P('db.delete', '/t/users', [W('action.params.n', 'lte', 10)]), P('gmail.send', '*')], caveats: [EXP, GATE] },
  { predicates: [P('pay.charge', '*', [W('action.params.amount', 'lte', 500), W('action.params.currency', 'eq', 'USD')])], caveats: [EXP] },
  { predicates: [P('pay.charge', '*', [W('action.params.amount', 'gte', 5000), W('action.params.amount', 'lte', 10)])], caveats: [EXP] },
  { predicates: [P('pay.charge', '*')] }, { predicates: [P('unknown.verb', '*', [W('action.params.zzz', 'eq', 1)])], caveats: [EXP, GATE] },
  { predicates: [P('docs.read', '/docs/x', [W('action.params.kind', 'eq', 'secret'), W('action.params.size', 'lte', 99999)])], caveats: [EXP] },
  { predicates: [P('*', '*')] }, { predicates: [] },
];
const SCHEMAS: any[] = [
  [{ verb: 'docs.read', params: { size: { type: 'integer', min: 0, max: 1000 }, kind: { type: 'string', values: ['public', 'internal'] } } }, { verb: 'pay.charge', params: { amount: { type: 'integer', min: 0, max: 100000, semantic: 'money.amount', unit: 'cents' }, currency: { type: 'string', values: ['USD', 'EUR'] } } },
    { verb: 'db.delete', params: { n: { type: 'integer', min: 0, max: 5 } } }, { verb: 'gmail.send', params: {} }],
  [{ verb: 'docs.read', params: { size: { type: 'string' } } }], [], [{ verb: 'pay.charge', params: { amount: { type: 'integer', semantic: 'money.amount' } } }],
  [{ verb: 'docs.read', params: { size: { type: 'integer' }, extra: { type: 'boolean', required: true } } }, { verb: 'granted.never', params: {} }],
  [{ verb: 'docs.read', params: { size: { type: 'integer', min: 0, max: 50 } } }],
];
for (const [i, p] of POL.entries()) for (const [j, s] of SCHEMAS.entries()) {
  await run('lintPolicy', CI.lintPolicy, [p, { schema: s }]);
  if (j < 2) await run('lintPolicy', CI.lintPolicy, [p, { schema: s, schemaOptions: { listUngranted: true } }]);
  if (j === 0) await run('lintPolicy', CI.lintPolicy, [p, { schema: s, schemaOptions: { units: { 'action.params.amount': 'dollars' } } }]);
}

// test: documents over every policy; the expectation is flipped for some cases so that failures are covered
const ACTS: any[] = [{ verb: 'docs.read', resource: '/docs/a', params: { size: 5 } }, { verb: 'docs.read', resource: '/docs/a', params: { size: 500 } }, { verb: 'db.delete', resource: '/t/users', params: { n: 3 } },
  { verb: 'db.delete', resource: '/t/users', params: { n: 30 } }, { verb: 'gmail.send', resource: 'x' }, { verb: 'pay.charge', resource: 'm', params: { amount: 100, currency: 'USD' } },
  { verb: 'pay.charge', resource: 'm', params: { amount: 900, currency: 'USD' } }, { verb: 'other.thing', resource: 'x' }];
const toolsDoc = (policy: any, flip: number) => {
  const pol = { predicates: policy.predicates, caveats: policy.caveats ?? [] };
  const cases = ACTS.map((a, i) => {
    let expect = 'deny';
    try { expect = AN.decide?.(pol, a)?.decision ?? AN.witnessOf?.(AN.toModel?.(pol), a)?.decision ?? 'deny'; } catch { /* default */ }
    if (flip && i % flip === 0) expect = expect === 'allow' ? 'deny' : 'allow';
    return { name: `case ${i}`, action: a, expect };
  });
  return AN.policyTestsDoc(pol, cases);
};
for (const [i, p] of POL.entries()) for (const flip of [0, 2, 3]) {
  const doc = J(toolsDoc(p, flip));
  await run('testCommand', AU.testCommand, [p, doc, {}]);
  if (flip === 0) await run('testCommand', AU.testCommand, [p, doc, { requireDigest: true }]);
  if (flip === 2) await run('testCommand', AU.testCommand, [{ ...p, caveats: [...(p.caveats ?? []), { type: 'max_blast_radius', max: 0.9 }] }, doc, { requireDigest: true }]);
}
for (const [i, p] of POL.entries()) {
  await run('coverageCommand', AU.coverageCommand, [p, J(ACTS), {}]);
  await run('coverageCommand', AU.coverageCommand, [p, J(toolsDoc(p, 0)), {}]);
  await run('coverageCommand', AU.coverageCommand, [p, J(ACTS.slice(0, 3)), { minClauses: 0.5 }]);
  await run('coverageCommand', AU.coverageCommand, [p, J(ACTS), { minClauses: 1, minBoundaries: 1, minMutation: 1, maxSurvivors: 0 }]);
}
console.log('cases', o.cases.length);
refWrite(o, 'policy-ci-java-extra');
