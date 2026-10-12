import { describe, expect, it } from 'vitest';
import { pcactnDigest, type Capability, type PCActn, type PolicyDecision, type VerifyResult } from '@atlasauth/pca';
import {
  COMPLIANCE_FRAMEWORKS,
  CONTROL_MAPPINGS,
  controlMappings,
  renderJson,
  renderMarkdown,
  toAuditEvent,
  toComplianceReport,
  type AuditEvent,
  type ComplianceFramework,
} from './index';
import controlsGolden from './mutation-kill-compliance.controls.json';

const NOW = 1_700_000_000_000;
const cap = (issuer: string, holder: string, caveats: unknown[]): Capability => ({ issuer, holder, caveats, sig: 's' }) as unknown as Capability;
const verifyOk = (extra: Record<string, string> = {}): VerifyResult =>
  ({ allow: true, checks: { wire: 'pass', leaf_signature: 'pass', ...extra } }) as unknown as VerifyResult;
const mkActn = (over: Record<string, unknown> = {}): PCActn =>
  ({
    cap_chain: [cap('PRINCIPAL_KEY_LONG_0123456789', 'AGENT_KEY_LONG_0123456789abcdef', [])],
    action: { verb: 'pay.send', resource: '/acct/1', params_digest: 'pd', reversibility_class: 'reversible' },
    grant_ref: 'g-ref',
    sig: 'SIG',
    alg: 'ed25519',
    plan: { root: 'PR' },
    counter: 7,
    nonce: 'n1',
    iat: 1_000,
    exp: 5_000,
    ...over,
  }) as unknown as PCActn;

describe('control table', () => {
  it('is pinned verbatim', () => {
    expect(JSON.parse(JSON.stringify(CONTROL_MAPPINGS))).toEqual(controlsGolden);
    expect(COMPLIANCE_FRAMEWORKS).toEqual(['eu-ai-act', 'iso-42001', 'soc2']);
  });
  it('controlMappings filters, copies and rejects', () => {
    const all = controlMappings();
    expect(all).toEqual([...CONTROL_MAPPINGS]);
    expect(all).not.toBe(CONTROL_MAPPINGS);
    expect(controlMappings('eu-ai-act').map((m) => m.controlId)).toEqual(['eu-ai-act:art-12', 'eu-ai-act:art-50']);
    expect(controlMappings('iso-42001').map((m) => m.controlId)).toEqual([
      'iso-42001:A.6.2.8',
      'iso-42001:A.9.2',
      'iso-42001:A.9.3',
      'iso-42001:A.6.2.2',
    ]);
    expect(controlMappings('soc2').map((m) => m.controlId)).toEqual(['soc2:CC6.1', 'soc2:CC6.2', 'soc2:CC6.3']);
    expect(() => controlMappings('nope' as ComplianceFramework)).toThrow(
      "pca-compliance: unknown framework 'nope' (have: eu-ai-act, iso-42001, soc2)",
    );
    expect(() => controlMappings('constructor' as ComplianceFramework)).toThrow(/unknown framework/);
    expect(() => toComplianceReport([], { framework: 'x' as ComplianceFramework })).toThrow(
      "pca-compliance: unknown framework 'x' (have: eu-ai-act, iso-42001, soc2)",
    );
  });
});

describe('toAuditEvent', () => {
  it('full event from rich inputs', () => {
    const chain = [
      cap('ROOTISSUER_LONG_ABCDEFGH', 'HOLDER1', [{ type: 'rate', max: 5, per_secs: 60 }, { type: 'budget_alloc', limit: 0.12345678 }]),
      cap('HOLDER1', 'LEAFHOLDER_LONG_KEY_ABCDEF', [
        { type: 'rate', max: 5, per_secs: 60 },
        { type: 'budget_alloc', limit: 0.12345678 },
        { type: 'budget_alloc', limit: 3 },
      ]),
      cap('LEAFHOLDER_LONG_KEY_ABCDEF', 'LEAFHOLDER_LONG_KEY_ABCDEF', [
        { type: 'rate', max: 5, per_secs: 60 },
        { type: 'budget_alloc', limit: 0.12345678 },
        { type: 'budget_alloc', limit: 3 },
      ]),
    ];
    const p = mkActn({ cap_chain: chain });
    const decision = {
      admit: true,
      r: 0.25,
      reasons: ['low risk', 'second'],
      requiredThreshold: { t: 2, proof: 'sig' },
      budget: { spent: 1 },
      releaseGuardianShare: false,
    } as unknown as PolicyDecision;
    const e = toAuditEvent({ pcactn: p, verify: verifyOk(), decision, now: NOW, session: 'sess' });
    expect(e.schema).toBe('atlas-pca/audit-event/v1');
    expect(e.recordedAt).toEqual({ epochMs: NOW, iso: new Date(NOW).toISOString() });
    expect(e.agent).toEqual({ holder: 'LEAFHOLDER_LONG_KEY_ABCDEF', principal: 'ROOTISSUER_LONG_ABCDEFGH', session: 'sess' });
    expect(e.delegation.depth).toBe(2);
    expect(e.delegation.hops).toHaveLength(3);
    const [h0, h1, h2] = e.delegation.hops;
    expect(h0).toEqual({
      index: 0,
      isRoot: true,
      issuer: 'ROOTISSUER_LONG_ABCDEFGH',
      holder: 'HOLDER1',
      scope: ['rate(max=5, per_secs=60)', 'budget allocation ≤ 0.1235'],
      caveats: chain[0]!.caveats,
      budgetAlloc: 0.12345678,
      narrative: 'Principal ROOTISSUER_L… granted authority to HOLDER1 under: rate(max=5, per_secs=60); budget allocation ≤ 0.1235.',
    });
    expect(h1).toEqual({
      index: 1,
      isRoot: false,
      issuer: 'HOLDER1',
      holder: 'LEAFHOLDER_LONG_KEY_ABCDEF',
      scope: ['budget allocation ≤ 3'],
      caveats: [{ type: 'budget_alloc', limit: 3 }],
      budgetAlloc: 3,
      narrative: 'HOLDER1 delegated to LEAFHOLDER_L…, narrowing scope: budget allocation ≤ 3.',
    });
    expect(h2).toEqual({
      index: 2,
      isRoot: false,
      issuer: 'LEAFHOLDER_LONG_KEY_ABCDEF',
      holder: 'LEAFHOLDER_LONG_KEY_ABCDEF',
      scope: [],
      caveats: [],
      narrative: 'LEAFHOLDER_L… delegated to LEAFHOLDER_L… (rebind only, no new constraints).',
    });
    expect('budgetAlloc' in h2!).toBe(false);
    expect(e.action).toEqual({ verb: 'pay.send', resource: '/acct/1', paramsDigest: 'pd', reversibilityClass: 'reversible', summary: 'pay.send on /acct/1' });
    expect(e.decision).toEqual({
      outcome: 'allow',
      reason: 'low risk',
      proofVerified: true,
      checks: { wire: 'pass', leaf_signature: 'pass' },
    });
    expect(e.risk).toEqual({ r: 0.25, tier: 2, proof: 'sig', budget: { spent: 1 } });
    expect(e.timestamps).toEqual({
      issuedAt: { epochMs: 1000, iso: new Date(1000).toISOString() },
      expiresAt: { epochMs: 5000, iso: new Date(5000).toISOString() },
    });
    expect(e.evidence).toEqual({
      pcactnDigest: pcactnDigest(p),
      leafSignature: 'SIG',
      signatureSuite: 'ed25519',
      planRoot: 'PR',
      paramsDigest: 'pd',
      grantRef: 'g-ref',
      counter: 7,
      nonce: 'n1',
      cryptographicallyVerifiable: true,
    });
    expect('humanOverride' in e).toBe(false);
    expect(e.narrative).toBe(
      'Agent LEAFHOLDER_L… ALLOWED to pay.send on /acct/1 (3-hop chain rooted at principal ROOTISSUER_L…; cryptographically verifiable proof). low risk',
    );
  });

  it('defaults for a bare / malformed input', () => {
    const e = toAuditEvent({ pcactn: {} as PCActn, verify: undefined as unknown as VerifyResult });
    expect(Math.abs(e.recordedAt.epochMs - Date.now())).toBeLessThan(5000);
    expect(e.agent).toEqual({ holder: '(none)', principal: undefined, session: '(none)' });
    expect(e.delegation).toEqual({ depth: 0, hops: [] });
    expect(e.action).toEqual({
      verb: '(unknown verb)',
      resource: '(unknown resource)',
      paramsDigest: '(none)',
      reversibilityClass: '(unknown)',
      summary: '(unknown verb) on (unknown resource)',
    });
    expect(e.decision).toEqual({ outcome: 'deny', reason: 'proof failed verification', proofVerified: false, checks: {} });
    expect(e.risk).toEqual({});
    expect(e.timestamps.issuedAt).toEqual({ epochMs: NaN, iso: '(unknown time)' });
    expect(e.timestamps.expiresAt).toEqual({ epochMs: NaN, iso: '(unknown time)' });
    expect(e.evidence.leafSignature).toBe('(unsigned)');
    expect(e.evidence.signatureSuite).toBe('ed25519');
    expect(e.evidence.planRoot).toBe('(none)');
    expect(e.evidence.counter).toBe(-1);
    expect(e.evidence.cryptographicallyVerifiable).toBe(false);
    expect('nonce' in e.evidence).toBe(false);
    expect(e.evidence.grantRef).toBe('(none)');
    expect(e.narrative).toBe(
      'Agent (none) DENIED to (unknown verb) on (unknown resource) (0-hop chain rooted at principal (none); proof not cryptographically verifiable). proof failed verification',
    );
    expect(() => toAuditEvent({ pcactn: undefined as unknown as PCActn, verify: undefined as unknown as VerifyResult })).not.toThrow();
  });

  it('session defaults to grant_ref; explicit session wins even when empty', () => {
    expect(toAuditEvent({ pcactn: mkActn(), verify: verifyOk(), now: 0 }).agent.session).toBe('g-ref');
    expect(toAuditEvent({ pcactn: mkActn(), verify: verifyOk(), now: 0, session: '' }).agent.session).toBe('');
    expect(toAuditEvent({ pcactn: mkActn(), verify: verifyOk(), now: 0 }).recordedAt.epochMs).toBe(0);
  });

  it('non-string / non-number fields fall back', () => {
    const p = mkActn({ sig: 5, alg: 5, plan: { root: 5 }, counter: '1', nonce: 5, grant_ref: 5, iat: '1', exp: null });
    (p as unknown as { action: Record<string, unknown> }).action = { verb: 1, resource: 2, params_digest: 3, reversibility_class: 4 };
    const e = toAuditEvent({ pcactn: p, verify: verifyOk(), now: 1 });
    expect(e.evidence).toMatchObject({ leafSignature: '(unsigned)', signatureSuite: 'ed25519', planRoot: '(none)', counter: -1, grantRef: '(none)', paramsDigest: '(none)' });
    expect('nonce' in e.evidence).toBe(false);
    expect(e.action.verb).toBe('(unknown verb)');
    expect(e.action.reversibilityClass).toBe('(unknown)');
    expect(e.timestamps.issuedAt.iso).toBe('(unknown time)');
    expect(e.timestamps.expiresAt.iso).toBe('(unknown time)');
  });

  it('alg other than ed25519 is carried; counter 0 kept', () => {
    const e = toAuditEvent({ pcactn: mkActn({ alg: 'ml-dsa-65', counter: 0 }), verify: verifyOk(), now: 1 });
    expect(e.evidence.signatureSuite).toBe('ml-dsa-65');
    expect(e.evidence.counter).toBe(0);
  });

  it('time rendering: infinite / out-of-range', () => {
    const e = toAuditEvent({ pcactn: mkActn({ iat: Infinity, exp: 1e300 }), verify: verifyOk(), now: 1 });
    expect(e.timestamps.issuedAt.iso).toBe('(unknown time)');
    expect(e.timestamps.expiresAt.iso).toBe('(unrepresentable time)');
    expect(toAuditEvent({ pcactn: mkActn(), verify: verifyOk(), now: NaN }).recordedAt.iso).toBe('(unknown time)');
  });

  it('cryptographicallyVerifiable needs both wire and leaf_signature', () => {
    const f = (checks: Record<string, string>) =>
      toAuditEvent({ pcactn: mkActn(), verify: { allow: true, checks } as unknown as VerifyResult, now: 1 }).evidence.cryptographicallyVerifiable;
    expect(f({ wire: 'pass', leaf_signature: 'pass' })).toBe(true);
    expect(f({ wire: 'pass' })).toBe(false);
    expect(f({ leaf_signature: 'pass' })).toBe(false);
    expect(f({ wire: 'fail', leaf_signature: 'pass' })).toBe(false);
    expect(f({ wire: 'pass', leaf_signature: 'fail' })).toBe(false);
    // verify without checks
    const e = toAuditEvent({ pcactn: mkActn(), verify: { allow: true } as unknown as VerifyResult, now: 1 });
    expect(e.decision.checks).toEqual({});
    expect(e.humanOverride).toBeUndefined();
  });

  it('digest failure is contained', () => {
    const bad = mkActn({ weird: 10n });
    expect(() => pcactnDigest(bad)).toThrow();
    expect(toAuditEvent({ pcactn: bad, verify: verifyOk(), now: 1 }).evidence.pcactnDigest).toBe('(undigestible)');
  });

  describe('outcome resolution', () => {
    const run = (verify: unknown, decision?: unknown) =>
      toAuditEvent({ pcactn: mkActn(), verify: verify as VerifyResult, decision: decision as PolicyDecision, now: 1 });
    it('verification failure wins', () => {
      const e = run({ allow: false, reason: 'bad sig', checks: {} }, { admit: true, reasons: ['x'] });
      expect(e.decision).toMatchObject({ outcome: 'deny', reason: 'bad sig', proofVerified: false });
      expect(run({ allow: false, checks: {} }).decision.reason).toBe('proof failed verification');
      // allow must be strictly true
      expect(run({ allow: 'yes', checks: {} }).decision).toMatchObject({ outcome: 'deny', proofVerified: false });
    });
    it('no decision', () => {
      expect(run({ allow: true, checks: {} }).decision).toMatchObject({ outcome: 'allow', reason: 'proof verified; no policy decision supplied', proofVerified: true });
      expect(run({ allow: true, checks: {} }).risk).toEqual({});
    });
    it('admit / step-up / deny with reason fallbacks', () => {
      const ok = { allow: true, checks: {} };
      expect(run(ok, { admit: true, reasons: [] }).decision).toMatchObject({ outcome: 'allow', reason: 'auto-admitted within policy and budget' });
      expect(run(ok, { admit: true, reasons: [5] }).decision.reason).toBe('auto-admitted within policy and budget');
      expect(run(ok, { admit: true, reasons: 'x' }).decision.reason).toBe('auto-admitted within policy and budget');
      expect(run(ok, { admit: true }).decision.reason).toBe('auto-admitted within policy and budget');
      expect(run(ok, { admit: true, reasons: ['first', 'second'] }).decision.reason).toBe('first');
      expect(run(ok, { admit: false, releaseGuardianShare: true, reasons: [] }).decision).toMatchObject({
        outcome: 'step-up',
        reason: 'policy satisfied but a co-signature is required',
      });
      expect(run(ok, { admit: false, releaseGuardianShare: true, reasons: ['need human'] }).decision.reason).toBe('need human');
      expect(run(ok, { admit: false, releaseGuardianShare: false, reasons: [] }).decision).toMatchObject({
        outcome: 'deny',
        reason: 'policy did not release authority (default-deny)',
      });
      expect(run(ok, { admit: false, reasons: ['nope'] }).decision.reason).toBe('nope');
    });
    it('narrative outcome words', () => {
      const ok = { allow: true, checks: { wire: 'pass', leaf_signature: 'pass' } };
      expect(run(ok, { admit: true }).narrative).toContain(' ALLOWED to ');
      expect(run(ok, { admit: false, releaseGuardianShare: true }).narrative).toContain(' STEP-UP to ');
      expect(run(ok, { admit: false }).narrative).toContain(' DENIED to ');
    });
    it('risk fields come from the decision', () => {
      const ok = { allow: true, checks: {} };
      expect(run(ok, { admit: true }).risk).toEqual({ r: undefined, tier: undefined, proof: undefined, budget: undefined });
      expect(run(ok, { admit: true, r: 0, requiredThreshold: { t: 3, proof: 'p' } }).risk).toEqual({ r: 0, tier: 3, proof: 'p', budget: undefined });
    });
  });

  describe('human override', () => {
    const shares = (roles: [string, unknown][]) => ({ shares: roles.map(([role, publicKey]) => ({ role, publicKey })) });
    const run = (threshold: unknown, check: string | undefined, decision?: unknown) =>
      toAuditEvent({
        pcactn: mkActn({ threshold }),
        verify: { allow: true, checks: check === undefined ? { wire: 'pass', leaf_signature: 'pass' } : { wire: 'pass', leaf_signature: 'pass', threshold: check } } as unknown as VerifyResult,
        decision: decision as PolicyDecision,
        now: 1,
      });
    it('absent / empty / non-array shares => none', () => {
      expect(run(undefined, 'pass').humanOverride).toBeUndefined();
      expect(run({ shares: [] }, 'pass').humanOverride).toBeUndefined();
      expect(run({ shares: 'x' }, 'pass').humanOverride).toBeUndefined();
      expect(run({}, 'pass').humanOverride).toBeUndefined();
    });
    it('unverified shares record no approval', () => {
      const th = shares([['principal', 'PK']]);
      expect(run(th, undefined).humanOverride).toEqual({
        humanApproved: false,
        approvers: [],
        guardianCosigners: [],
        roles: [],
        requiredTier: 1,
        narrative: '1 co-signature share(s) were presented but NOT verified (threshold check: absent); no human approval is recorded.',
      });
      expect(run(shares([['principal', 'PK'], ['guardian', 'G']]), 'fail', { admit: true, requiredThreshold: { t: 2, proof: 'p' } }).humanOverride).toEqual({
        humanApproved: false,
        approvers: [],
        guardianCosigners: [],
        roles: [],
        requiredTier: 2,
        narrative: '2 co-signature share(s) were presented but NOT verified (threshold check: fail); no human approval is recorded.',
      });
      expect(run(th, 'skipped').narrative).not.toContain('human-signed step-up');
    });
    it('verified: principal + guardian', () => {
      const th = shares([['agent', 'A'], ['guardian', 'GUARDIAN_KEY'], ['principal', 'PRINCIPAL_KEY_LONG_0123456789']]);
      const e = run(th, 'pass', { admit: true, requiredThreshold: { t: 3, proof: 'p' } });
      expect(e.humanOverride).toEqual({
        humanApproved: true,
        approvers: ['PRINCIPAL_KEY_LONG_0123456789'],
        guardianCosigners: ['GUARDIAN_KEY'],
        roles: ['agent', 'guardian', 'principal'],
        requiredTier: 3,
        narrative: 'Step-up approved by a signed human co-signature from principal PRINCIPAL_KE… (plus 1 guardian co-sign) at tier t=3.',
      });
      expect(e.narrative).toContain('; human-signed step-up).');
    });
    it('verified: principal only, guardian only, junk shares', () => {
      expect(run(shares([['principal', 'PK']]), 'pass').humanOverride?.narrative).toBe(
        'Step-up approved by a signed human co-signature from principal PK at tier t=1.',
      );
      const g = run(shares([['guardian', 'G1'], ['guardian', 'G2']]), 'pass', { admit: true, requiredThreshold: { t: 2, proof: 'p' } });
      expect(g.humanOverride).toEqual({
        humanApproved: false,
        approvers: [],
        guardianCosigners: ['G1', 'G2'],
        roles: ['guardian', 'guardian'],
        requiredTier: 2,
        narrative: 'Co-signed by 2 guardian share(s) at tier t=2 (no human principal signature present).',
      });
      expect(g.narrative).not.toContain('human-signed step-up');
      const junk = run({ shares: [null, { role: 5, publicKey: 'x' }, { role: 'principal', publicKey: 7 }, { role: 'guardian', publicKey: null }, { role: 'agent', publicKey: 'a' }] }, 'pass');
      expect(junk.humanOverride).toMatchObject({ humanApproved: false, approvers: [], guardianCosigners: [], roles: ['principal', 'guardian', 'agent'] });
      expect(run({ shares: [{ role: 'principal', publicKey: 'P1' }, { role: 'principal', publicKey: 'P2' }] }, 'pass').humanOverride?.narrative).toContain('from principal P1 at');
    });
  });

  describe('delegation hops', () => {
    it('non-array chain / null entries', () => {
      expect(toAuditEvent({ pcactn: mkActn({ cap_chain: 'x' }), verify: verifyOk(), now: 1 }).delegation).toEqual({ depth: 0, hops: [] });
      expect(toAuditEvent({ pcactn: mkActn({ cap_chain: [] }), verify: verifyOk(), now: 1 }).agent).toMatchObject({ holder: '(none)', principal: undefined });
      const e = toAuditEvent({ pcactn: mkActn({ cap_chain: [null, cap('I', 'H', [])] }), verify: verifyOk(), now: 1 });
      expect(e.delegation.hops).toHaveLength(1);
      expect(e.delegation.hops[0]).toMatchObject({ index: 1, isRoot: false });
      expect(e.delegation.depth).toBe(0);
    });
    it('shrinking caveat list adds nothing; non-array caveats treated as empty', () => {
      const chain = [cap('R', 'A', [{ type: 'x1' }, { type: 'x2' }]), cap('A', 'B', [{ type: 'x1' }]), { issuer: 'B', holder: 'C', caveats: 'zz' }];
      const e = toAuditEvent({ pcactn: mkActn({ cap_chain: chain }), verify: verifyOk(), now: 1 });
      expect(e.delegation.hops[1]?.caveats).toEqual([]);
      expect(e.delegation.hops[2]?.caveats).toEqual([]);
      // equal length => nothing added
      const eq = toAuditEvent({ pcactn: mkActn({ cap_chain: [cap('R', 'A', [{ type: 'x1' }]), cap('A', 'B', [{ type: 'x1' }])] }), verify: verifyOk(), now: 1 });
      expect(eq.delegation.hops[1]?.caveats).toEqual([]);
      expect(eq.delegation.hops[1]?.narrative).toBe('A delegated to B (rebind only, no new constraints).');
      // a root with non-array caveats
      const root = toAuditEvent({ pcactn: mkActn({ cap_chain: [{ issuer: 'R', holder: 'A', caveats: 5 }] }), verify: verifyOk(), now: 1 });
      expect(root.delegation.hops[0]?.narrative).toBe('Principal R granted authority to A.');
      // parent with non-array caveats counts as 0
      const par = toAuditEvent({ pcactn: mkActn({ cap_chain: [{ issuer: 'R', holder: 'A', caveats: 'q' }, cap('A', 'B', [{ type: 'k' }])] }), verify: verifyOk(), now: 1 });
      expect(par.delegation.hops[1]?.caveats).toEqual([{ type: 'k' }]);
    });
    it('caveat descriptions', () => {
      const chain = [
        cap('R', 'A', [
          null,
          { notype: 1 },
          { type: 5 },
          { type: 'envelope', predicates: [1, 2], caveats: [1] },
          { type: 'envelope' },
          { type: 'envelope', predicates: 'x', caveats: 'y' },
          { type: 'budget_alloc', limit: 1.23456 },
          { type: 'bare' },
          { type: 'multi', a: 1.5, b: { c: [1] }, d: null, e: 'str', f: NaN, g: 2.00001 },
          { type: 'many', k1: 1, k2: 2, k3: 3, k4: 4, k5: 5, k6: 6, k7: 7, k8: 8, k9: 9 },
          { type: 'tail', k1: 1, k2: 2, k3: 3, k4: 4, k5: 5, k6: 6, k7: 7 },
        ]),
      ];
      const h = toAuditEvent({ pcactn: mkActn({ cap_chain: chain }), verify: verifyOk(), now: 1 }).delegation.hops[0]!;
      expect(h.scope).toEqual([
        '(malformed caveat)',
        '(malformed caveat)',
        '(malformed caveat)',
        'policy envelope (2 predicate(s), 1 caveat(s))',
        'policy envelope (0 predicate(s), 0 caveat(s))',
        'policy envelope (0 predicate(s), 0 caveat(s))',
        'budget allocation ≤ 1.2346',
        'bare',
        'multi(a=1.5, b={"c":[1]}, d=null, e=str, f=NaN, g=2)',
        'many(k1=1, k2=2, k3=3, k4=4, k5=5, k6=6, k7=7)',
        'tail(k1=1, k2=2, k3=3, k4=4, k5=5, k6=6, k7=7)',
      ]);
      expect(h.budgetAlloc).toBe(1.23456);
    });
    it('a non-root hop lists several added caveats joined with "; "', () => {
      const chain = [cap('R', 'A', []), cap('A', 'B', [{ type: 'x1', a: 1 }, { type: 'x2' }])];
      const h = toAuditEvent({ pcactn: mkActn({ cap_chain: chain }), verify: verifyOk(), now: 1 }).delegation.hops[1]!;
      expect(h.scope).toEqual(['x1(a=1)', 'x2']);
      expect(h.narrative).toBe('A delegated to B, narrowing scope: x1(a=1); x2.');
    });
    it('callable caveats are malformed and large integers print exactly', () => {
      const fn = Object.assign(() => 0, { type: 'rate', max: 1 });
      const big = toAuditEvent({ pcactn: mkActn({ cap_chain: [cap('R', 'A', [fn, { type: 'budget_alloc', limit: 123456789012345 }])] }), verify: verifyOk(), now: 1 });
      expect(big.delegation.hops[0]!.scope).toEqual(['(malformed caveat)', 'budget allocation ≤ 123456789012345']);
    });
    it('first budget_alloc is used', () => {
      const h = toAuditEvent({
        pcactn: mkActn({ cap_chain: [cap('R', 'A', [{ type: 'budget_alloc', limit: 2 }, { type: 'budget_alloc', limit: 9 }])] }),
        verify: verifyOk(),
        now: 1,
      }).delegation.hops[0]!;
      expect(h.budgetAlloc).toBe(2);
    });
    it('short() boundary: n=12 keys displayed whole up to n+1', () => {
      const f = (k: string) => toAuditEvent({ pcactn: mkActn({ cap_chain: [cap(k, 'H', [])] }), verify: verifyOk(), now: 1 }).delegation.hops[0]!.narrative;
      expect(f('a'.repeat(13))).toContain('Principal ' + 'a'.repeat(13) + ' granted');
      expect(f('a'.repeat(14))).toContain('Principal ' + 'a'.repeat(12) + '… granted');
      expect(f('')).toContain('Principal (none) granted');
    });
  });
});

// ---- reports --------------------------------------------------------------------------------------

const ev = (o: {
  verifiable?: boolean;
  verified?: boolean;
  outcome?: 'allow' | 'deny' | 'step-up';
  human?: boolean;
  hops?: number;
  depth?: number;
  plan?: string;
  holder?: string;
  principal?: string | undefined;
  digest?: string;
  iat?: number;
}): AuditEvent =>
  ({
    schema: 'atlas-pca/audit-event/v1',
    recordedAt: { epochMs: 0, iso: 'x' },
    agent: { holder: o.holder ?? 'H', principal: 'principal' in o ? o.principal : 'P', session: 's' },
    delegation: { depth: o.depth ?? 0, hops: Array.from({ length: o.hops ?? 1 }, () => ({})) },
    action: { verb: 'v', resource: 'r', paramsDigest: 'p', reversibilityClass: 'x', summary: 's' },
    decision: { outcome: o.outcome ?? 'allow', reason: 'r', proofVerified: o.verified ?? true, checks: {} },
    risk: {},
    ...(o.human ? { humanOverride: { humanApproved: true } } : {}),
    timestamps: { issuedAt: { epochMs: o.iat ?? 1000, iso: 'i' }, expiresAt: { epochMs: 0, iso: 'e' } },
    evidence: { pcactnDigest: o.digest ?? 'DIGEST_0123456789ABCDEFGHIJ', cryptographicallyVerifiable: o.verifiable ?? true, planRoot: o.plan ?? 'root' },
    narrative: 'n',
  }) as unknown as AuditEvent;

const item = (events: AuditEvent[], framework: ComplianceFramework, id: string) =>
  toComplianceReport(events, { framework, now: NOW }).items.find((i) => i.controlId === id)!;

describe('toComplianceReport controls', () => {
  it('no events: every control not evidenced', () => {
    for (const fw of COMPLIANCE_FRAMEWORKS) {
      for (const i of toComplianceReport([], { framework: fw, now: NOW }).items) {
        expect(i.status).toBe('not-evidenced');
        expect(i.evidence).toBe('no actions in the reporting period');
        expect(i.findings).toEqual(['no events supplied — nothing to evidence']);
      }
    }
  });
  it('art-12', () => {
    const a = item([ev({}), ev({ verifiable: false }), ev({ verifiable: false })], 'eu-ai-act', 'eu-ai-act:art-12');
    expect(a.status).toBe('partial');
    expect(a.findings).toEqual(['2 of 3 entries are not cryptographically verifiable']);
    expect(a.evidence).toBe('3 actions logged; 1/3 cite a cryptographically verifiable proof (e.g. DIGEST_012345678…)');
    const b = item([ev({ digest: '(undigestible)' })], 'eu-ai-act', 'eu-ai-act:art-12');
    expect(b).toMatchObject({ status: 'satisfied', findings: [], evidence: '1 actions logged; 1/1 cite a cryptographically verifiable proof' });
    // first sample digest is used; only first 5 retained; undigestible skipped
    const c = item([ev({ digest: '(undigestible)' }), ev({ digest: 'SECOND_DIGEST_0123456789' }), ev({ digest: 'THIRD_DIGEST_0123456789' })], 'eu-ai-act', 'eu-ai-act:art-12');
    expect(c.evidence).toContain('(e.g. SECOND_DIGEST_01…)');
  });
  it('the first digestible entry is the sample (undigestible ones are skipped)', () => {
    const evs = [...Array.from({ length: 6 }, () => ev({ digest: '(undigestible)' })), ev({ digest: 'LATE_DIGEST_0123456789' })];
    expect(item(evs, 'eu-ai-act', 'eu-ai-act:art-12').evidence).toContain('(e.g. LATE_DIGEST_0123…)');
    expect(item([ev({ digest: 'SEVENTEEN_CHARS_17' })], 'eu-ai-act', 'eu-ai-act:art-12').evidence).toContain('(e.g. SEVENTEEN_CHARS_…)');
    expect(item([ev({ digest: 'SEVENTEEN_CHARS_1' })], 'eu-ai-act', 'eu-ai-act:art-12').evidence).toContain('(e.g. SEVENTEEN_CHARS_1)');
  });
  it('art-50 and A.6.2.8 always satisfied', () => {
    expect(item([ev({ principal: undefined }), ev({ principal: 'P2' }), ev({ principal: 'P2' })], 'eu-ai-act', 'eu-ai-act:art-50')).toMatchObject({
      status: 'satisfied',
      findings: [],
      evidence: '3 actions each disclose the acting agent, the principal (1 distinct) and the automated decision outcome',
    });
    expect(item([ev({})], 'iso-42001', 'iso-42001:A.6.2.8')).toMatchObject({
      status: 'satisfied',
      findings: [],
      evidence: '1 actions each carry a decision reason + risk/tier/budget reasoning trace',
    });
  });
  it('A.9.2 and CC6.2 chain coverage', () => {
    const full = [ev({}), ev({ hops: 2, depth: 1, principal: 'Q' })];
    expect(item(full, 'iso-42001', 'iso-42001:A.9.2')).toMatchObject({
      status: 'satisfied',
      findings: [],
      evidence: '2/2 actions carry an explicit delegation chain (max depth 1, 2 authorizing principal(s))',
    });
    const part = [ev({}), ev({ hops: 0 }), ev({ hops: 0 })];
    expect(item(part, 'iso-42001', 'iso-42001:A.9.2')).toMatchObject({ status: 'partial', findings: ['2 entries have no delegation chain'] });
    const none = [ev({ hops: 0 })];
    expect(item(none, 'iso-42001', 'iso-42001:A.9.2')).toMatchObject({ status: 'not-evidenced', findings: ['1 entries have no delegation chain'] });
    expect(item(full, 'soc2', 'soc2:CC6.2')).toMatchObject({
      status: 'satisfied',
      findings: [],
      evidence: '1 agent identit(ies) traceable to 2 authorizing principal(s) via signed delegation chains',
    });
    expect(item([ev({ holder: 'A' }), ev({ holder: 'B', hops: 0, principal: undefined })], 'soc2', 'soc2:CC6.2')).toMatchObject({
      status: 'partial',
      findings: ['1 entries are not traceable to an authorizing principal'],
      evidence: '2 agent identit(ies) traceable to 1 authorizing principal(s) via signed delegation chains',
    });
    expect(item(none, 'soc2', 'soc2:CC6.2')).toMatchObject({ status: 'not-evidenced', findings: ['1 entries are not traceable to an authorizing principal'] });
  });
  it('A.9.3 oversight', () => {
    expect(item([ev({ outcome: 'step-up', human: true }), ev({ outcome: 'deny' }), ev({ outcome: 'step-up' })], 'iso-42001', 'iso-42001:A.9.3')).toMatchObject({
      status: 'satisfied',
      findings: [],
      evidence: '1 step-up(s) approved by a signed human co-signature; 2 step-up(s) and 1 denial(s) show oversight enforced',
    });
    expect(item([ev({ outcome: 'step-up' })], 'iso-42001', 'iso-42001:A.9.3')).toMatchObject({
      status: 'partial',
      findings: ['no human step-up co-signature was exercised in this period'],
      evidence: 'oversight boundary enforced (1 step-up(s), 0 denial(s)) but no signed human co-signature observed in the period',
    });
    expect(item([ev({ outcome: 'deny' })], 'iso-42001', 'iso-42001:A.9.3')).toMatchObject({
      status: 'partial',
      evidence: 'oversight boundary enforced (0 step-up(s), 1 denial(s)) but no signed human co-signature observed in the period',
    });
    expect(item([ev({})], 'iso-42001', 'iso-42001:A.9.3')).toMatchObject({
      status: 'partial',
      findings: ['no higher-impact action required human oversight in this period'],
      evidence: 'all actions were auto-admitted within policy; no oversight event was triggered in the period',
    });
  });
  it('A.6.2.2 plan binding', () => {
    expect(item([ev({})], 'iso-42001', 'iso-42001:A.6.2.2')).toMatchObject({
      status: 'satisfied',
      findings: [],
      evidence: '1/1 actions are bound to a committed plan root (intended-use binding)',
    });
    expect(item([ev({}), ev({ plan: '(none)' })], 'iso-42001', 'iso-42001:A.6.2.2')).toMatchObject({
      status: 'partial',
      findings: ['1 entries are not bound to a committed plan root'],
    });
    expect(item([ev({ plan: '(none)' })], 'iso-42001', 'iso-42001:A.6.2.2').status).toBe('not-evidenced');
  });
  it('CC6.1 and CC6.3', () => {
    expect(item([ev({}), ev({ outcome: 'deny' }), ev({ outcome: 'deny' }), ev({ outcome: 'step-up' })], 'soc2', 'soc2:CC6.1')).toMatchObject({
      status: 'satisfied',
      findings: ['2 out-of-scope action(s) denied — access control actively enforced'],
      evidence: 'deny-by-default access over 4 actions (1 allowed, 1 step-up, 2 denied); all gated by signed predicates + attenuation',
    });
    expect(item([ev({})], 'soc2', 'soc2:CC6.1').findings).toEqual([]);
    expect(item([ev({ depth: 1 })], 'soc2', 'soc2:CC6.3')).toMatchObject({
      status: 'satisfied',
      findings: [],
      evidence: 'access narrowed by attenuation (max delegation depth 1) and 0 denied action(s)',
    });
    expect(item([ev({ outcome: 'deny' })], 'soc2', 'soc2:CC6.3')).toMatchObject({ status: 'satisfied', findings: [] });
    expect(item([ev({})], 'soc2', 'soc2:CC6.3')).toMatchObject({
      status: 'partial',
      findings: ['no attenuating hop or denial observed in the period'],
    });
    // maxDepth is the max, not the last
    expect(item([ev({ depth: 3 }), ev({ depth: 1 })], 'soc2', 'soc2:CC6.3').evidence).toContain('max delegation depth 3');
    expect(item([ev({ depth: 0 }), ev({ depth: 2 })], 'soc2', 'soc2:CC6.3').evidence).toContain('max delegation depth 2');
  });
  it('null events are filtered; non-array events => empty', () => {
    const r = toComplianceReport([null as never, ev({}), undefined as never], { framework: 'soc2', now: NOW });
    expect(r.eventCount).toBe(1);
    expect(toComplianceReport(undefined as never, { framework: 'soc2', now: NOW }).eventCount).toBe(0);
  });
});

describe('toComplianceReport envelope', () => {
  it('empty report', () => {
    const r = toComplianceReport([], { framework: 'soc2', now: NOW });
    expect(r.schema).toBe('atlas-pca/compliance-report/v1');
    expect(r.framework).toBe('soc2');
    expect(r.generatedAt).toEqual({ epochMs: NOW, iso: new Date(NOW).toISOString() });
    expect(r.period).toEqual({ from: { epochMs: 0, iso: new Date(0).toISOString() }, to: { epochMs: 0, iso: new Date(0).toISOString() } });
    expect(r.eventCount).toBe(0);
    expect(r.assurances).toEqual({
      cryptographicallyVerifiable: false,
      explicitDelegationChain: false,
      signedHumanOverrides: false,
      narrative: 'No events in scope.',
    });
    expect(r.coverage).toEqual({ total: 3, satisfied: 0, partial: 0, notEvidenced: 3, satisfiedFraction: 0, satisfiedPercent: 0 });
    expect(r.summary).toBe('soc2: 0/3 controls satisfied, 3 not evidenced over 0 action(s).');
    expect(Math.abs(toComplianceReport([], { framework: 'soc2' }).generatedAt.epochMs - Date.now())).toBeLessThan(5000);
  });
  it('mixed report', () => {
    const evs = [
      ev({ iat: 3000, human: true, outcome: 'step-up' }),
      ev({ iat: 1000, verifiable: false, outcome: 'deny', hops: 0, verified: false }),
      ev({ iat: NaN }),
      ev({ iat: 2000, depth: 2, hops: 3 }),
    ];
    const r = toComplianceReport(evs, { framework: 'soc2', now: NOW });
    expect(r.period).toEqual({ from: { epochMs: 1000, iso: new Date(1000).toISOString() }, to: { epochMs: 3000, iso: new Date(3000).toISOString() } });
    expect(r.eventCount).toBe(4);
    expect(r.assurances).toEqual({
      cryptographicallyVerifiable: false,
      explicitDelegationChain: false,
      signedHumanOverrides: true,
      narrative: '3/4 entries cite a cryptographically verifiable proof; 3/4 carry an explicit delegation chain; 1 step-up(s) carry a signed human co-signature.',
    });
    expect(r.coverage).toEqual({ total: 3, satisfied: 2, partial: 1, notEvidenced: 0, satisfiedFraction: 2 / 3, satisfiedPercent: 67 });
    expect(r.summary).toBe('soc2: 2/3 controls satisfied, 1 partial over 4 action(s).');
    expect(r.items.map((i) => [i.controlId, i.framework, i.controlTitle, i.clause])).toEqual(
      CONTROL_MAPPINGS.filter((m) => m.framework === 'soc2').map((m) => [m.controlId, m.framework, m.controlTitle, m.clause]),
    );
    expect(Object.keys(r.items[0]!).sort()).toEqual(['clause', 'controlId', 'controlTitle', 'evidence', 'findings', 'framework', 'pcaEvidence', 'status']);
  });
  it('assurances all true', () => {
    const r = toComplianceReport([ev({ human: true, outcome: 'step-up' }), ev({})], { framework: 'eu-ai-act', now: NOW });
    expect(r.assurances).toMatchObject({ cryptographicallyVerifiable: true, explicitDelegationChain: true, signedHumanOverrides: true });
    expect(r.summary).toBe('eu-ai-act: 2/2 controls satisfied over 2 action(s).');
    expect(r.coverage.satisfiedPercent).toBe(100);
    expect(r.coverage.satisfiedFraction).toBe(1);
  });
  it('only the verified count feeds verified stats', () => {
    // verified count is unused in output, but denied / stepUp / allowed partition outcomes
    const r = toComplianceReport([ev({ outcome: 'allow' }), ev({ outcome: 'step-up' }), ev({ outcome: 'deny' })], { framework: 'soc2', now: NOW });
    expect(r.items[0]?.evidence).toContain('(1 allowed, 1 step-up, 1 denied)');
  });
  it('partial-only summary and uniform-iat period', () => {
    const r = toComplianceReport([ev({ iat: 5 })], { framework: 'iso-42001', now: NOW });
    expect(r.period.from.epochMs).toBe(5);
    expect(r.period.to.epochMs).toBe(5);
    expect(r.summary).toBe('iso-42001: 3/4 controls satisfied, 1 partial over 1 action(s).');
    const r2 = toComplianceReport([ev({ hops: 0, plan: '(none)' })], { framework: 'iso-42001', now: NOW });
    expect(r2.summary).toBe('iso-42001: 1/4 controls satisfied, 1 partial, 2 not evidenced over 1 action(s).');
  });
});

describe('renderers', () => {
  const report = toComplianceReport([ev({ iat: 1000, human: true, outcome: 'step-up', digest: 'D1_0123456789ABCDEFGH' })], { framework: 'eu-ai-act', now: NOW });
  it('renderJson is pretty JSON of the report', () => {
    expect(renderJson(report)).toBe(JSON.stringify(report, null, 2));
  });
  it('renderMarkdown', () => {
    const md = renderMarkdown(report);
    const lines = md.split('\n');
    expect(lines[0]).toBe('# PCA compliance evidence — eu-ai-act');
    expect(lines[1]).toBe('');
    expect(lines[2]).toBe(`Generated ${new Date(NOW).toISOString()} · 1 action(s) · coverage: 2/2 satisfied (100%)`);
    expect(lines[3]).toBe('');
    expect(lines[4]).toBe(`Reporting period: ${new Date(1000).toISOString()} → ${new Date(1000).toISOString()}`);
    expect(lines[5]).toBe('');
    expect(lines[6]).toBe('## Why this trail is admissible (what PCA uniquely provides)');
    expect(lines[7]).toBe('');
    expect(lines[8]).toMatch(/^- \*\*Cryptographically verifiable\*\* — YES: every log entry cites its proof/);
    expect(lines[9]).toMatch(/^- \*\*Explicit delegation chain\*\* — YES: each action records who authorized what scope, hop by hop, rooted at a principal\.$/);
    expect(lines[10]).toMatch(/^- \*\*Signed human-overrides\*\* — YES: a step-up approval is a principal threshold co-signature naming the human approver, not a free-text note\.$/);
    expect(lines[11]).toBe('');
    expect(lines[12]).toBe(`> ${report.assurances.narrative}`);
    expect(lines.slice(13, 22)).toEqual([
      '',
      '## Coverage summary',
      '',
      '| Satisfied | Partial | Not evidenced | Total |',
      '| --- | --- | --- | --- |',
      '| 2 | 0 | 0 | 2 |',
      '',
      '## Controls',
      '',
    ]);
    expect(lines[22]).toBe('| Control | Clause | Status | Evidence in period |');
    expect(lines[23]).toBe('| --- | --- | --- | --- |');
    expect(lines[24]).toBe(
      `| ${report.items[0]!.controlTitle} (\`eu-ai-act:art-12\`) | EU AI Act, Article 12 | ✓ SATISFIED | ${report.items[0]!.evidence} |`,
    );
    expect(lines[26]).toBe('');
    expect(lines[27]).toBe('## Control detail');
    expect(lines[28]).toBe('');
    expect(lines[29]).toBe(`### eu-ai-act:art-12 — ${report.items[0]!.controlTitle}`);
    expect(lines[30]).toBe('');
    expect(lines[31]).toBe('- Clause: EU AI Act, Article 12');
    expect(lines[32]).toBe('- Status: ✓ SATISFIED');
    expect(lines[33]).toBe(`- PCA evidence basis: ${(report.items[0] as unknown as { pcaEvidence?: string }).pcaEvidence}`);
    expect(lines[34]).toBe(`- Evidence in period: ${report.items[0]!.evidence}`);
    expect(lines[35]).toBe('');
    expect(lines[36]).toBe(`### eu-ai-act:art-50 — ${report.items[1]!.controlTitle}`);
    expect(lines[lines.length - 3]).toBe('---');
    expect(lines[lines.length - 2]).toBe('');
    expect(lines[lines.length - 1]).toBe(
      '_Evidence mapping, not a legal certification: a `satisfied` status means the cryptographic evidence the control asks for is present in the supplied records._',
    );
  });
  it('renderMarkdown variants: empty, partial, findings, glyphs', () => {
    const empty = renderMarkdown(toComplianceReport([], { framework: 'soc2', now: NOW }));
    expect(empty).not.toContain('Reporting period');
    expect(empty).toContain('coverage: 0/3 satisfied (0%)');
    expect(empty).toContain('Cryptographically verifiable** — PARTIAL');
    expect(empty).toContain('Explicit delegation chain** — PARTIAL');
    expect(empty).toContain('Signed human-overrides** — none in period');
    expect(empty).toContain('| 0 | 0 | 3 | 3 |');
    expect(empty).toContain('· NOT-EVIDENCED |');
    expect(empty).toContain('  - no events supplied — nothing to evidence');
    expect(empty).toContain('- Findings:');
    const part = renderMarkdown(toComplianceReport([ev({}), ev({ verifiable: false, hops: 0 })], { framework: 'eu-ai-act', now: NOW }));
    expect(part).toContain('◐ PARTIAL |');
    expect(part).toContain('- Status: ◐ PARTIAL');
    expect(part).toContain('  - 1 of 2 entries are not cryptographically verifiable');
    expect(part).toContain('Cryptographically verifiable** — PARTIAL');
    // no findings => no Findings header for that control
    const ok = renderMarkdown(toComplianceReport([ev({})], { framework: 'eu-ai-act', now: NOW }));
    expect(ok).not.toContain('- Findings:');
  });
});
