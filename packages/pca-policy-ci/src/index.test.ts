import { describe, expect, it } from 'vitest';
import { DEFAULT_RISK_POLICY, compilePolicy, type Capability, type Envelope } from '@atlasauth/pca';
import { lint, lintChain, lintPolicies, lintPolicy, summarize, type Finding } from './index';

const future = Date.now() + 3_600_000;
const hasRule = (fs: Finding[], rule: Finding['rule'], sev?: Finding['severity']) =>
  fs.some((f) => f.rule === rule && (sev === undefined || f.severity === sev));

describe('over-broad grant', () => {
  it('a wildcard verb/resource grant is a hard error', () => {
    const findings = lintPolicy({ predicates: [{ verb: '*', resource: '*' }] });
    expect(hasRule(findings, 'over-broad-grant', 'error')).toBe(true);
    expect(findings.some((f) => f.rule === 'over-broad-grant' && /wildcard verb/i.test(f.message))).toBe(true);
  });

  it('a semantically-total verb (no where, universal resource) is proven always-allow', () => {
    const findings = lintPolicy({ predicates: [{ verb: 'gmail.send', resource: '*' }] });
    expect(findings.some((f) => f.rule === 'over-broad-grant' && /always-allow/i.test(f.message))).toBe(true);
  });

  it('a dangerous verb granted with no narrowing where or caveat is a hard error', () => {
    const findings = lintPolicy({ predicates: [{ verb: 'account.transfer', resource: '/acct/123' }], caveats: [] });
    const f = findings.find((x) => x.rule === 'over-broad-grant' && /dangerous verb 'account.transfer'/.test(x.message));
    expect(f).toBeDefined();
    expect(f?.severity).toBe('error');
  });
});

describe('dangerous reachability', () => {
  it('a reachable dangerous verb with no gate is a hard error', () => {
    const findings = lintPolicy({ predicates: [{ verb: 'db.delete', resource: '/t/users', where: [{ field: 'action.params.n', op: 'lte', value: 10 }] }] });
    expect(hasRule(findings, 'dangerous-reachability', 'error')).toBe(true);
  });

  it('a reachable dangerous verb WITH a blast-radius gate is downgraded to info', () => {
    const findings = lintPolicy({
      predicates: [{ verb: 'db.delete', resource: '/t/users', where: [{ field: 'action.params.n', op: 'lte', value: 10 }] }],
      caveats: [{ type: 'max_blast_radius', max: 0.1 }, { type: 'expires', at: future }],
    });
    expect(hasRule(findings, 'dangerous-reachability', 'info')).toBe(true);
    expect(hasRule(findings, 'dangerous-reachability', 'error')).toBe(false);
  });
});

describe('redundant / unused caveat', () => {
  it('a looser same-type caveat subsumed by a stricter one is a warning', () => {
    const findings = lintPolicy({
      predicates: [{ verb: 'docs.read', resource: '/docs/x', where: [{ field: 'action.params.size', op: 'lte', value: 10 }] }],
      caveats: [{ type: 'expires', at: future }, { type: 'expires', at: future + 1000 }],
    });
    const f = findings.find((x) => x.rule === 'redundant-caveat' && /subsumed by a stricter/.test(x.message));
    expect(f).toBeDefined();
    expect(f?.severity).toBe('warn');
  });

  it('an unsatisfiable predicate (dead policy) is flagged', () => {
    const findings = lintPolicy({
      predicates: [
        {
          verb: 'docs.read',
          resource: '/docs/x',
          where: [
            { field: 'action.params.amount', op: 'gte', value: 100 },
            { field: 'action.params.amount', op: 'lte', value: 10 },
          ],
        },
      ],
      caveats: [{ type: 'expires', at: future }],
    });
    expect(findings.some((f) => f.rule === 'redundant-caveat' && /can never match/.test(f.message))).toBe(true);
  });

  it('a non-binding numeric bound is reported as info', () => {
    const findings = lintPolicy({
      predicates: [
        {
          verb: 'docs.read',
          resource: '/docs/x',
          where: [
            { field: 'action.params.size', op: 'lte', value: 10 },
            { field: 'action.params.size', op: 'lte', value: 100 },
          ],
        },
      ],
      caveats: [{ type: 'expires', at: future }],
    });
    expect(findings.some((f) => f.rule === 'redundant-caveat' && f.severity === 'info' && /does not tighten/.test(f.message))).toBe(true);
  });
});

describe('a well-formed least-privilege policy is clean', () => {
  it('yields zero findings', () => {
    const findings = lintPolicy({
      predicates: [{ verb: 'docs.read', resource: '/docs/*', where: [{ field: 'action.params.size', op: 'lte', value: 100 }] }],
      caveats: [
        { type: 'expires', at: future },
        { type: 'max_blast_radius', max: 0.1 },
        { type: 'reversibility_max', class: 'reversible' },
      ],
    });
    expect(findings).toEqual([]);
  });
});

describe('privilege escalation in a chain', () => {
  it('a child that admits more than its parent is a hard error', () => {
    const parent = { predicates: [{ verb: 'pay', resource: '*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }], caveats: [] };
    const child = { predicates: [{ verb: 'pay', resource: '*', where: [{ field: 'action.params.amount', op: 'lte', value: 1000 }] }], caveats: [] };
    const findings = lintChain([parent, child], { rules: { overBroadGrant: false, dangerousReachability: false, missingSafetyFloor: false, redundantCaveat: false } });
    const f = findings.find((x) => x.rule === 'privilege-escalation');
    expect(f).toBeDefined();
    expect(f?.severity).toBe('error');
    expect(f?.message).toMatch(/ESCALATES|not a subset/);
  });

  it('a well-attenuated chain has no escalation finding', () => {
    const parent = { predicates: [{ verb: 'pay', resource: '*', where: [{ field: 'action.params.amount', op: 'lte', value: 1000 }] }], caveats: [] };
    const child = { predicates: [{ verb: 'pay', resource: '*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }], caveats: [] };
    const findings = lintChain([parent, child], { rules: { overBroadGrant: false, dangerousReachability: false, missingSafetyFloor: false, redundantCaveat: false } });
    expect(hasRule(findings, 'privilege-escalation')).toBe(false);
  });
});

describe('soundness: undecidable features never raise a false hard error', () => {
  it('an undecidable resource matcher downgrades dangerous-reachability to a warning, not an error', () => {
    const findings = lintPolicy({
      predicates: [{ verb: 'secret.rotate', resource: 're:/vault/[a-z]+' }],
      caveats: [{ type: 'max_blast_radius', max: 0.1 }, { type: 'expires', at: future }],
    });
    expect(hasRule(findings, 'dangerous-reachability', 'warn')).toBe(true);
    expect(findings.every((f) => f.severity !== 'error')).toBe(true);
    expect(findings.some((f) => f.rule === 'dangerous-reachability' && /undecidable/.test(f.message))).toBe(true);
  });

  it('an undecidable chain hop downgrades escalation to a warning, not an error', () => {
    const parent = { predicates: [{ verb: 'files.read', resource: 're:/acct/[0-9]+' }], caveats: [] };
    const child = { predicates: [{ verb: 'files.read', resource: '/acct/1' }], caveats: [] };
    const findings = lintChain([parent, child], { rules: { overBroadGrant: false, dangerousReachability: false, missingSafetyFloor: false, redundantCaveat: false } });
    expect(hasRule(findings, 'privilege-escalation', 'warn')).toBe(true);
    expect(hasRule(findings, 'privilege-escalation', 'error')).toBe(false);
  });
});

describe('input normalization', () => {
  it('reads a signed Envelope', () => {
    const env: Envelope = {
      goal_commit: 'commit',
      predicates: [{ verb: '*', resource: '*' }],
      caveats: [],
      agent_binding: {},
      risk_policy: DEFAULT_RISK_POLICY,
    };
    expect(hasRule(lintPolicy(env), 'over-broad-grant', 'error')).toBe(true);
  });

  it('reads a minted grant via its envelope caveat', () => {
    const grant: Capability = {
      id: 'i',
      issuer: 'p',
      holder: 'h',
      body_digest: 'b',
      sig: 's',
      caveats: [
        {
          type: 'envelope',
          goal_commit: 'commit',
          predicates: [{ verb: 'account.transfer', resource: '/acct/1' }],
          caveats: [{ type: 'expires', at: future }],
          agent_binding: {},
          risk_policy: DEFAULT_RISK_POLICY,
        },
      ],
    };
    const findings = lintPolicy(grant);
    expect(findings.some((f) => f.rule === 'over-broad-grant' && /account\.transfer/.test(f.message))).toBe(true);
  });

  it('a malformed grant surfaces a malformed-policy error', () => {
    const bad: Capability = { id: 'i', issuer: 'p', holder: 'h', body_digest: 'b', sig: 's', caveats: [] };
    const findings = lintPolicy(bad);
    expect(hasRule(findings, 'malformed-policy', 'error')).toBe(true);
  });

  it('lints a compilePolicy result', () => {
    const compiled = compilePolicy({ permissions: { gmail: ['send'] } });
    // gmail.send has a universal resource and no where -> proven always-allow.
    expect(hasRule(lint(compiled), 'over-broad-grant', 'error')).toBe(true);
  });
});

describe('rule toggles + summary', () => {
  it('disabling a rule removes its findings', () => {
    const policy = { predicates: [{ verb: '*', resource: '*' }] };
    expect(hasRule(lintPolicy(policy, { rules: { overBroadGrant: false } }), 'over-broad-grant')).toBe(false);
  });

  it('summarize maps error to a non-zero exit code', () => {
    const summary = lintPolicies([{ label: 'p1', policy: { predicates: [{ verb: '*', resource: '*' }] } }]);
    expect(summary.counts.error).toBeGreaterThan(0);
    expect(summary.ok).toBe(false);
    expect(summary.exitCode).toBe(1);
  });

  it('a clean policy summarizes to exit 0', () => {
    const summary = lintPolicies([
      { label: 'clean', policy: { predicates: [{ verb: 'docs.read', resource: '/docs/*', where: [{ field: 'action.params.size', op: 'lte', value: 100 }] }], caveats: [{ type: 'expires', at: future }, { type: 'max_blast_radius', max: 0.1 }] } },
    ]);
    expect(summary.exitCode).toBe(0);
    expect(summary.ok).toBe(true);
  });

  it('--max-severity warn makes warnings fail the gate', () => {
    const results = [{ label: 'w', findings: [{ rule: 'missing-safety-floor', severity: 'warn', message: 'no expiry' } satisfies Finding] }];
    expect(summarize(results, { maxSeverity: 'error' }).exitCode).toBe(0);
    expect(summarize(results, { maxSeverity: 'warn' }).exitCode).toBe(1);
  });
});
