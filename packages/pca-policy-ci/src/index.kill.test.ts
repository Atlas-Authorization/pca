import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_RISK_POLICY, type Caveat, type Predicate } from '@atlasauth/pca';

vi.mock('./rules', () => ({
  ruleOverBroadGrant: vi.fn(),
  rulePrivilegeEscalation: vi.fn(),
  ruleRedundantCaveat: vi.fn(),
  ruleDangerousReachability: vi.fn(),
  ruleMissingSafetyFloor: vi.fn(),
  ruleSchemaMismatch: vi.fn(),
}));

import { checkLintRulesPin, lintChain, lintPolicies, lintPolicy, summarize } from './index';
import {
  ruleDangerousReachability,
  ruleMissingSafetyFloor,
  ruleOverBroadGrant,
  rulePrivilegeEscalation,
  ruleRedundantCaveat,
  ruleSchemaMismatch,
} from './rules';
import { DEFAULT_DANGEROUS_VERBS, type Finding } from './types';

const ob = vi.mocked(ruleOverBroadGrant);
const pe = vi.mocked(rulePrivilegeEscalation);
const rc = vi.mocked(ruleRedundantCaveat);
const dr = vi.mocked(ruleDangerousReachability);
const sf = vi.mocked(ruleMissingSafetyFloor);
const sm = vi.mocked(ruleSchemaMismatch);

const mark = (rule: Finding['rule'], message: string): Finding => ({ rule, severity: 'info', message });
const M_OB = mark('over-broad-grant', 'ob');
const M_PE = mark('privilege-escalation', 'pe');
const M_RC = mark('redundant-caveat', 'rc');
const M_DR = mark('dangerous-reachability', 'dr');
const M_SF = mark('missing-safety-floor', 'sf');
const M_SM = mark('schema-mismatch', 'sm');

beforeEach(() => {
  ob.mockReset().mockReturnValue([M_OB]);
  pe.mockReset().mockReturnValue([M_PE]);
  rc.mockReset().mockReturnValue([M_RC]);
  dr.mockReset().mockReturnValue([M_DR]);
  sf.mockReset().mockReturnValue([M_SF]);
  sm.mockReset().mockReturnValue([M_SM]);
});

const pred: Predicate = { verb: 'docs.read', resource: '/docs/*' };
const exp: Caveat = { type: 'expires', at: 4_000_000_000_000 };
const bare = { predicates: [pred], caveats: [exp] };
const NORMAL = { predicates: [pred], caveats: [exp], kind: 'bare' as const };
const hopOf = (p: Predicate) => ({ predicates: [p], caveats: [], kind: 'chain-hop' as const });

describe('lintPolicy: every rule runs by default, in order, on the normalized policy', () => {
  it('passes the policy, the default dangerous verbs, the targets and the analyzer options to each rule', () => {
    expect(lintPolicy(bare)).toStrictEqual([M_OB, M_RC, M_DR, M_SF]);
    expect(ob.mock.calls).toStrictEqual([[NORMAL, DEFAULT_DANGEROUS_VERBS, {}]]);
    expect(rc.mock.calls).toStrictEqual([[NORMAL]]);
    expect(dr.mock.calls).toStrictEqual([[NORMAL, DEFAULT_DANGEROUS_VERBS, [], {}]]);
    expect(sf.mock.calls).toStrictEqual([[NORMAL, { enabled: true, requireExpiry: true, requireScopeGate: true }, DEFAULT_DANGEROUS_VERBS]]);
    expect(pe).not.toHaveBeenCalled();
    expect(sm).not.toHaveBeenCalled();
  });

  it('a schema adds the schema rule last, with the schema and its options', () => {
    const schema = [{ verb: 'docs.read', params: {} }] as never;
    const so = { strict: true } as never;
    expect(lintPolicy(bare, { schema, schemaOptions: so })).toStrictEqual([M_OB, M_RC, M_DR, M_SF, M_SM]);
    expect(sm.mock.calls[0]![1]).toBe(schema);
    expect(sm.mock.calls[0]![2]).toBe(so);
    expect(sm.mock.calls[0]![0]).toStrictEqual(NORMAL);
  });

  it('a malformed policy runs no rule and is one error', () => {
    expect(lintPolicy(5)).toEqual([{ rule: 'malformed-policy', severity: 'error', message: expect.stringMatching(/^unrecognized policy shape/) }]);
    expect(ob).not.toHaveBeenCalled();
  });

  it('each rule can be switched off on its own', () => {
    expect(lintPolicy(bare, { rules: { overBroadGrant: false } })).toStrictEqual([M_RC, M_DR, M_SF]);
    expect(lintPolicy(bare, { rules: { redundantCaveat: false } })).toStrictEqual([M_OB, M_DR, M_SF]);
    expect(lintPolicy(bare, { rules: { dangerousReachability: false } })).toStrictEqual([M_OB, M_RC, M_SF]);
    expect(lintPolicy(bare, { rules: { missingSafetyFloor: false } })).toStrictEqual([M_OB, M_RC, M_DR]);
    expect(lintPolicy(bare, { rules: { overBroadGrant: false, redundantCaveat: false, dangerousReachability: false, missingSafetyFloor: false, privilegeEscalation: false } })).toStrictEqual([]);
  });

  it('true and omitted mean enabled', () => {
    expect(lintPolicy(bare, { rules: { overBroadGrant: true, redundantCaveat: true, dangerousReachability: true, missingSafetyFloor: true } })).toStrictEqual([M_OB, M_RC, M_DR, M_SF]);
    expect(lintPolicy(bare, { rules: {} })).toStrictEqual([M_OB, M_RC, M_DR, M_SF]);
  });

  it('forwards maxCombinations (including 0) and nothing else to the analyzer', () => {
    lintPolicy(bare, { maxCombinations: 0 });
    expect(ob.mock.calls[0]![2]).toStrictEqual({ maxCombinations: 0 });
    expect(dr.mock.calls[0]![3]).toStrictEqual({ maxCombinations: 0 });
    lintPolicy(bare, { maxCombinations: 500 });
    expect(ob.mock.calls[1]![2]).toStrictEqual({ maxCombinations: 500 });
    lintPolicy(bare, { maxCombinations: undefined });
    expect(ob.mock.calls[2]![2]).toStrictEqual({});
    lintPolicy(bare, undefined);
    expect(ob.mock.calls[3]![2]).toStrictEqual({});
  });
});

describe('rule configuration', () => {
  it('custom dangerous verbs and targets reach the rules; an object without them falls back to the defaults', () => {
    const targets = [{ verb: 'x.y', resource: '/r' }];
    lintPolicy(bare, { rules: { overBroadGrant: { dangerousVerbs: ['zap'] }, dangerousReachability: { dangerousVerbs: ['zip'], targets } } });
    expect(ob.mock.calls[0]![1]).toStrictEqual(['zap']);
    expect(dr.mock.calls[0]![1]).toStrictEqual(['zip']);
    expect(dr.mock.calls[0]![2]).toBe(targets);
    // the safety-floor rule judges "non-trivial" with the over-broad rule's list
    expect(sf.mock.calls[0]![2]).toStrictEqual(['zap']);

    lintPolicy(bare, { rules: { overBroadGrant: {}, dangerousReachability: {} } });
    expect(ob.mock.calls[1]![1]).toStrictEqual(DEFAULT_DANGEROUS_VERBS);
    expect(dr.mock.calls[1]![1]).toStrictEqual(DEFAULT_DANGEROUS_VERBS);
    expect(dr.mock.calls[1]![2]).toStrictEqual([]);
    expect(sf.mock.calls[1]![2]).toStrictEqual(DEFAULT_DANGEROUS_VERBS);

    lintPolicy(bare, { rules: { overBroadGrant: true, dangerousReachability: true } });
    expect(ob.mock.calls[2]![1]).toStrictEqual(DEFAULT_DANGEROUS_VERBS);
    expect(dr.mock.calls[2]![1]).toStrictEqual(DEFAULT_DANGEROUS_VERBS);
    expect(dr.mock.calls[2]![2]).toStrictEqual([]);
  });

  it('only targets can be given on their own, and only dangerous verbs on their own', () => {
    lintPolicy(bare, { rules: { dangerousReachability: { targets: [{ verb: 'a' }] } } });
    expect(dr.mock.calls[0]![1]).toStrictEqual(DEFAULT_DANGEROUS_VERBS);
    expect(dr.mock.calls[0]![2]).toStrictEqual([{ verb: 'a' }]);
    lintPolicy(bare, { rules: { dangerousReachability: { dangerousVerbs: ['q'] } } });
    expect(dr.mock.calls[1]![1]).toStrictEqual(['q']);
    expect(dr.mock.calls[1]![2]).toStrictEqual([]);
  });

  it('safety floor options default to on and are independent', () => {
    const cfgs = (rules: object) => {
      sf.mockClear();
      lintPolicy(bare, { rules: { missingSafetyFloor: rules as never } });
      return sf.mock.calls[0]![1];
    };
    expect(cfgs({})).toStrictEqual({ enabled: true, requireExpiry: true, requireScopeGate: true });
    expect(cfgs({ requireExpiry: false })).toStrictEqual({ enabled: true, requireExpiry: false, requireScopeGate: true });
    expect(cfgs({ requireScopeGate: false })).toStrictEqual({ enabled: true, requireExpiry: true, requireScopeGate: false });
    expect(cfgs({ requireExpiry: true, requireScopeGate: true })).toStrictEqual({ enabled: true, requireExpiry: true, requireScopeGate: true });
    expect(cfgs({ requireExpiry: false, requireScopeGate: false })).toStrictEqual({ enabled: true, requireExpiry: false, requireScopeGate: false });
    sf.mockClear();
    lintPolicy(bare, { rules: { missingSafetyFloor: true } });
    expect(sf.mock.calls[0]![1]).toStrictEqual({ enabled: true, requireExpiry: true, requireScopeGate: true });
  });
});

describe('a rule that throws is an internal error naming the rule', () => {
  const boom = () => {
    throw new Error('boom');
  };
  const msg = (rule: string, detail = 'boom') => ({ rule: 'internal-error', severity: 'error', message: `rule ${rule} could not run: ${detail}` });

  it('lintPolicy names each rule', () => {
    ob.mockImplementation(boom);
    expect(lintPolicy(bare)).toStrictEqual([msg('over-broad-grant'), M_RC, M_DR, M_SF]);
    ob.mockReturnValue([M_OB]);
    rc.mockImplementation(boom);
    expect(lintPolicy(bare)).toStrictEqual([M_OB, msg('redundant-caveat'), M_DR, M_SF]);
    rc.mockReturnValue([M_RC]);
    dr.mockImplementation(boom);
    expect(lintPolicy(bare)).toStrictEqual([M_OB, M_RC, msg('dangerous-reachability'), M_SF]);
    dr.mockReturnValue([M_DR]);
    sf.mockImplementation(boom);
    expect(lintPolicy(bare)).toStrictEqual([M_OB, M_RC, M_DR, msg('missing-safety-floor')]);
    sf.mockReturnValue([M_SF]);
    sm.mockImplementation(boom);
    expect(lintPolicy(bare, { schema: [] })).toStrictEqual([M_OB, M_RC, M_DR, M_SF, msg('schema-mismatch')]);
  });

  it('a thrown non-Error is stringified', () => {
    ob.mockImplementation(() => {
      throw 'plain text';
    });
    expect(lintPolicy(bare)[0]).toStrictEqual(msg('over-broad-grant', 'plain text'));
    ob.mockImplementation(() => {
      throw 42;
    });
    expect(lintPolicy(bare)[0]).toStrictEqual(msg('over-broad-grant', '42'));
  });

  it('lintChain names each rule', () => {
    const chain = [bare, bare];
    pe.mockImplementation(boom);
    expect(lintChain(chain)).toStrictEqual([msg('privilege-escalation'), M_OB, M_RC, M_DR, M_SF]);
    pe.mockReturnValue([M_PE]);
    ob.mockImplementation(boom);
    expect(lintChain(chain)).toStrictEqual([M_PE, msg('over-broad-grant'), M_RC, M_DR, M_SF]);
    ob.mockReturnValue([M_OB]);
    rc.mockImplementation(boom);
    expect(lintChain(chain)).toStrictEqual([M_PE, M_OB, msg('redundant-caveat'), M_DR, M_SF]);
    rc.mockReturnValue([M_RC]);
    dr.mockImplementation(boom);
    expect(lintChain(chain)).toStrictEqual([M_PE, M_OB, M_RC, msg('dangerous-reachability'), M_SF]);
    dr.mockReturnValue([M_DR]);
    sf.mockImplementation(boom);
    expect(lintChain(chain)).toStrictEqual([M_PE, M_OB, M_RC, M_DR, msg('missing-safety-floor')]);
  });
});

describe('lintChain', () => {
  const a: Predicate = { verb: 'a.read', resource: '/a' };
  const b: Predicate = { verb: 'b.read', resource: '/b' };

  it('checks escalation across all hops, then lints the LEAF only', () => {
    expect(lintChain([{ predicates: [a] }, { predicates: [b] }])).toStrictEqual([M_PE, M_OB, M_RC, M_DR, M_SF]);
    expect(pe.mock.calls).toStrictEqual([[[hopOf(a), hopOf(b)], {}]]);
    expect(ob.mock.calls).toStrictEqual([[hopOf(b), DEFAULT_DANGEROUS_VERBS, {}]]);
    expect(rc.mock.calls).toStrictEqual([[hopOf(b)]]);
    expect(dr.mock.calls).toStrictEqual([[hopOf(b), DEFAULT_DANGEROUS_VERBS, [], {}]]);
    expect(sf.mock.calls).toStrictEqual([[hopOf(b), { enabled: true, requireExpiry: true, requireScopeGate: true }, DEFAULT_DANGEROUS_VERBS]]);
  });

  it('a single hop is its own leaf', () => {
    expect(lintChain([{ predicates: [a] }])).toStrictEqual([M_PE, M_OB, M_RC, M_DR, M_SF]);
    expect(ob.mock.calls[0]![0]).toStrictEqual(hopOf(a));
  });

  it('every rule is switchable in a chain', () => {
    const chain = [{ predicates: [a] }, { predicates: [b] }];
    expect(lintChain(chain, { rules: { privilegeEscalation: false } })).toStrictEqual([M_OB, M_RC, M_DR, M_SF]);
    expect(lintChain(chain, { rules: { overBroadGrant: false } })).toStrictEqual([M_PE, M_RC, M_DR, M_SF]);
    expect(lintChain(chain, { rules: { redundantCaveat: false } })).toStrictEqual([M_PE, M_OB, M_DR, M_SF]);
    expect(lintChain(chain, { rules: { dangerousReachability: false } })).toStrictEqual([M_PE, M_OB, M_RC, M_SF]);
    expect(lintChain(chain, { rules: { missingSafetyFloor: false } })).toStrictEqual([M_PE, M_OB, M_RC, M_DR]);
    expect(lintChain(chain, { rules: { privilegeEscalation: true } })).toStrictEqual([M_PE, M_OB, M_RC, M_DR, M_SF]);
  });

  it('forwards the analyzer options and rule configuration to the chain rules', () => {
    const targets = [{ verb: 'x' }];
    lintChain([{ predicates: [a] }, { predicates: [b] }], { maxCombinations: 9, rules: { overBroadGrant: { dangerousVerbs: ['zap'] }, dangerousReachability: { dangerousVerbs: ['zip'], targets }, missingSafetyFloor: { requireExpiry: false } } });
    expect(pe.mock.calls[0]![1]).toStrictEqual({ maxCombinations: 9 });
    expect(ob.mock.calls[0]![1]).toStrictEqual(['zap']);
    expect(ob.mock.calls[0]![2]).toStrictEqual({ maxCombinations: 9 });
    expect(dr.mock.calls[0]![1]).toStrictEqual(['zip']);
    expect(dr.mock.calls[0]![2]).toBe(targets);
    expect(dr.mock.calls[0]![3]).toStrictEqual({ maxCombinations: 9 });
    expect(sf.mock.calls[0]![1]).toStrictEqual({ enabled: true, requireExpiry: false, requireScopeGate: true });
    expect(sf.mock.calls[0]![2]).toStrictEqual(['zap']);
  });

  it('a malformed chain runs no rule', () => {
    expect(lintChain([])).toStrictEqual([{ rule: 'malformed-policy', severity: 'error', message: 'empty chain' }]);
    expect(pe).not.toHaveBeenCalled();
    expect(ob).not.toHaveBeenCalled();
  });

  it('a chain whose last hop is missing is checked for escalation but has no leaf to lint', () => {
    const grant = {
      id: 'i',
      issuer: 'p',
      holder: 'h',
      body_digest: 'b',
      sig: 's',
      caveats: [{ type: 'envelope', goal_commit: 'c', predicates: [a], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY }],
    };
    const chain: unknown[] = [grant];
    chain.length = 2;
    const out = lintChain(chain);
    expect(out).toStrictEqual([M_PE]);
    expect(pe).toHaveBeenCalledTimes(1);
    expect(ob).not.toHaveBeenCalled();
    expect(rc).not.toHaveBeenCalled();
    expect(dr).not.toHaveBeenCalled();
    expect(sf).not.toHaveBeenCalled();
  });
});

describe('lintPolicies labels', () => {
  it('uses the given label, or policy[index]', () => {
    const s = lintPolicies([{ policy: bare }, { label: 'mine', policy: bare }, { label: '', policy: bare }, { policy: bare }]);
    expect(s.results.map((r) => r.label)).toEqual(['policy[0]', 'mine', '', 'policy[3]']);
  });
});

describe('summarize threshold counting', () => {
  it('reports ok only when nothing reaches the threshold, however many findings there are', () => {
    const f = (severity: Finding['severity']): Finding => ({ rule: 'redundant-caveat', severity, message: 'm' });
    const many = [{ label: 'x', findings: [f('error'), f('error'), f('warn'), f('info')] }];
    expect(summarize(many)).toMatchObject({ ok: false, exitCode: 1, counts: { error: 2, warn: 1, info: 1 } });
    expect(summarize([{ label: 'x', findings: [f('warn'), f('info')] }])).toMatchObject({ ok: true, exitCode: 0, counts: { error: 0, warn: 1, info: 1 } });
    expect(summarize([{ label: 'x', findings: [] }])).toMatchObject({ ok: true, exitCode: 0 });
  });
});

describe('checkLintRulesPin', () => {
  const D = 'A'.repeat(43);
  const NOT_DIGEST = { ok: false, message: 'the lint rules pin is not a digest (expected 43 base64url characters)' };
  it('rejects anything that is not exactly one 43-character digest', () => {
    expect(checkLintRulesPin('', D)).toStrictEqual(NOT_DIGEST);
    expect(checkLintRulesPin('A'.repeat(42), D)).toStrictEqual(NOT_DIGEST);
    expect(checkLintRulesPin('A'.repeat(44), D)).toStrictEqual(NOT_DIGEST);
    expect(checkLintRulesPin(`!${D}`, D)).toStrictEqual(NOT_DIGEST);
    expect(checkLintRulesPin(`${D}!`, D)).toStrictEqual(NOT_DIGEST);
    expect(checkLintRulesPin(`junk ${D}`, D)).toStrictEqual(NOT_DIGEST);
    expect(checkLintRulesPin(`${D} junk`, D)).toStrictEqual(NOT_DIGEST);
    expect(checkLintRulesPin(`${D}\n${D}`, D)).toStrictEqual(NOT_DIGEST);
    expect(checkLintRulesPin(`${'A'.repeat(42)}+`, D)).toStrictEqual(NOT_DIGEST);
  });
  it('ignores surrounding whitespace and compares with the actual digest', () => {
    expect(checkLintRulesPin(`  \n${D}\n`, D)).toStrictEqual({ ok: true, message: `lint rules digest ${D} matches the pin` });
    const other = `${'B'.repeat(42)}-`;
    expect(checkLintRulesPin(other, D)).toStrictEqual({ ok: false, message: `lint rules digest ${D} differs from the pin ${other}: the rule list changed; review it and update the pin` });
    expect(checkLintRulesPin(`${'a-_Z9'.repeat(8)}abc`, D).message).toContain('differs from the pin');
  });
});
