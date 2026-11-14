import { describe, expect, it } from 'vitest';
import {
  type ActionContext,
  type Capability,
  type CaveatContext,
  type Envelope,
  type PCActn,
  type PolicyDecision,
  type VerifyResult,
  DEFAULT_RISK_POLICY,
  PCACTN_VERSION,
  b64u,
  budgetAllocCaveat,
  delegate,
  generateKeyPair,
  mintGrant,
  verifyChain,
} from '@atlasauth/pca';
import { ChainExplanation, DecisionExplanation, VERIFY_CHECK_ORDER, cleanText, explainChain, explainDecision, explainVerification } from './index';

// ---- verification -----------------------------------------------------------------------------

const pcBase = {
  ver: 99,
  aud: 'ins_1',
  iat: 1000,
  exp: 2000,
  counter: 7,
  grant_ref: 'g',
  action: { verb: 'v', resource: 'r' },
  plan: { root: 'p', node_id: 'n' },
  cap_chain: [],
} as unknown as PCActn;

const vr = (o: object): VerifyResult => o as unknown as VerifyResult;
const row = (glyph: string, name: string, detail: string, mark = ''): string => `  ${glyph} ${name.padEnd(16)} ${detail}${mark}`;
const NOT_REACHED = 'not reached (a terminal earlier check stopped evaluation)';

describe('verification text rendering', () => {
  it('renders every status glyph, the decisive mark and one fix line', () => {
    const ex = explainVerification(pcBase, vr({ allow: false, checks: { wire: 'pass', version: 'fail', audience: 'not-enforced', validity: 'unsupported', leaf_signature: 'fail' } }));
    const detail = `unsupported ver 99 (verifier requires ${PCACTN_VERSION})`;
    const expected = [
      'PCA verification — DENY',
      `Denied at the "version" check: ${detail}`,
      '',
      row('✓', 'wire', 'wire structure + strict canonical form valid'),
      row('✗', 'version', detail, ' ◀ DECISIVE'),
      `      ↳ fix: re-mint the action at wire version ${PCACTN_VERSION}.`,
      row('·', 'audience', 'not enforced by this verifier (no hook / opt-out)'),
      row('?', 'validity', 'the PCActn carries a feature this verifier does not implement (never a pass)'),
      row('–', 'cap_chain', NOT_REACHED),
      row('–', 'grant_ref_bound', NOT_REACHED),
      row('–', 'plan_inclusion', NOT_REACHED),
      row('✗', 'leaf_signature', 'no leaf capability to check the signature against (empty/invalid chain)'),
      row('–', 'counter_format', NOT_REACHED),
    ].join('\n');
    expect(ex.toText()).toBe(expected);
    expect(ex.checks.map((c) => c.status)).toEqual(['pass', 'fail', 'not-enforced', 'unsupported', 'skipped', 'skipped', 'skipped', 'fail', 'skipped']);
  });
  it('a presented pass carries only name, status, title and detail', () => {
    const ex = explainVerification(pcBase, vr({ allow: true, checks: { wire: 'pass' } }));
    expect(ex.checks[0]).toStrictEqual({ name: 'wire', status: 'pass', title: 'wire format', detail: 'wire structure + strict canonical form valid' });
  });
  it('the allow summary counts only the passed checks', () => {
    const ex = explainVerification(pcBase, vr({ allow: true, checks: { wire: 'pass', version: 'pass', audience: 'not-enforced' } }));
    expect(ex.verdict).toBe('allow');
    expect(ex.allow).toBe(true);
    expect(ex.summary).toBe('All 2 evaluated checks passed (no check failed).');
  });
  it('extra checks follow the normative nine, once each', () => {
    const ex = explainVerification(pcBase, vr({ allow: false, checks: { wire: 'pass', zzz: 'pass', replay: 'fail' } }));
    expect(ex.checks.map((c) => c.name)).toEqual([...VERIFY_CHECK_ORDER, 'zzz', 'replay']);
    expect(ex.checks.find((c) => c.name === 'zzz')?.title).toBe('zzz');
    expect(ex.decisive).toMatchObject({
      name: 'replay',
      title: 'replay',
      detail: 'replay check failed',
      remedy: 'satisfy the replay requirement (supply the corresponding verifier hook / proof).',
      decisive: true,
    });
  });
  it('a result without per-check statuses is explained from its reason', () => {
    const none = 'Denied: the verifier result carries no per-check statuses (an allow without evidence is treated as a denial).';
    expect(explainVerification(pcBase, vr({ allow: true })).summary).toBe(none);
    expect(explainVerification(pcBase, vr({ allow: true, checks: [] })).summary).toBe(none);
    expect(explainVerification(pcBase, vr({ allow: false })).summary).toBe('Denied: a check failed');
    expect(explainVerification(pcBase, vr({ allow: false, reason: 'boom' })).summary).toBe('Denied: boom');
    expect(explainVerification(pcBase, vr({ allow: false, reason: 5 })).summary).toBe('Denied: a check failed');
    expect(explainVerification(pcBase, vr({ allow: false })).allow).toBe(false);
  });
});

describe('verification fail-closed shapes', () => {
  const missing = 'the PCActn or the verifier result is missing';
  it('a missing PCActn or result is a decisive structure failure', () => {
    for (const ex of [explainVerification(null as never, vr({ allow: true, checks: {} })), explainVerification(pcBase, null as never), explainVerification(pcBase, 'x' as never)]) {
      expect(ex.verdict).toBe('deny');
      expect(ex.allow).toBe(false);
      expect(ex.summary).toBe(`Denied: ${missing}`);
      expect(ex.checks).toHaveLength(1);
      expect(ex.decisive).toBe(ex.checks[0]);
      expect(ex.decisive).toStrictEqual({
        name: 'malformed',
        status: 'fail',
        title: 'structure',
        detail: missing,
        remedy: 'pass the PCActn and the verifier result you verified.',
        decisive: true,
      });
      expect(ex.failed).toEqual(['malformed']);
    }
  });
  it('an input that throws while being explained is a malformed denial', () => {
    const hostile = { ...pcBase } as unknown as Record<string, unknown>;
    Object.defineProperty(hostile, 'ver', {
      get() {
        throw new Error('boom');
      },
    });
    const ex = explainVerification(hostile as unknown as PCActn, vr({ allow: true, checks: { version: 'pass' } }));
    expect(ex.verdict).toBe('deny');
    expect(ex.summary).toBe('Denied: the PCActn or the verifier result is malformed');
    expect(ex.decisive?.detail).toBe('the PCActn or the verifier result is malformed');
  });
});

// ---- decision ---------------------------------------------------------------------------------

const PC = {} as unknown as PCActn;
const dec = (over: object = {}): PolicyDecision =>
  ({
    admit: false,
    needStepUp: true,
    releaseGuardianShare: true,
    r: 0.4,
    requiredThreshold: { t: 2, proof: 'standard', optimisticAllowed: false },
    budget: { B: 0.5, tau: 0, asOf: 0 },
    reasons: [],
    ...over,
  }) as unknown as PolicyDecision;
const envOf = (over: object = {}): Envelope =>
  ({ predicates: [{ verb: 'v' }], caveats: [], agent_binding: {}, risk_policy: { theta1: 0.2, theta2: 0.6, kappa: 2 }, ...over }) as unknown as Envelope;
const cap = (id: string, caveats: unknown[] | undefined): Capability => ({ id, issuer: 'I'.repeat(43), holder: 'H'.repeat(43), caveats }) as unknown as Capability;
const act = (verb = 'a', resource = 'r'): ActionContext => ({ action: { verb, resource } }) as unknown as ActionContext;
const nowAt = (now: number): CaveatContext => ({ now });
const EXPIRES_1000 = { type: 'expires', at: 1000 };

describe('decision text rendering', () => {
  it('renders a granted, delegated, step-up decision line by line', () => {
    const env = envOf({ predicates: [{ verb: ['a', 'b'], where: [{ field: 'action.verb', op: 'eq', value: 'a' }] }], caveats: [{ type: 'expires', at: 5 }] });
    const chain = [cap('rootcap', [{ type: 'expires', at: 5 }]), cap('leafcap', [{ type: 'expires', at: 5 }, { type: 'delegation_depth', max: 2 }])];
    const ex = explainDecision(PC, dec({ reasons: ['caveat(s) not satisfied: delegation_depth'] }), { envelope: env, context: { action: act(), chain } });
    const reason = "caveat 'delegation_depth' narrowed the authority away: delegation_depth(max=2) NARROWED/DENIED";
    const fix = "delegation depth exceeds max 2; act from a shallower hop or raise 'delegation_depth'.";
    expect(ex.toText()).toBe(
      [
        'PCA decision — DENY (step-up)',
        `Needs step-up: ${reason}`,
        '',
        '  authority : predicate #0 of grant rootcap grants a|b on *',
        '              where action.verb eq a',
        '  caveat ✓  : expires(at=5) held',
        '  caveat ✗  : delegation_depth(max=2) NARROWED/DENIED [delegated]',
        `              ↳ fix: ${fix}`,
        '  risk      : θ1 0.2 < r 0.4 ≤ θ2 0.6 → standard band (t=2); proof=standard, optimistic=false',
        '  budget    : step-up to t=2 (standard) co-signature required, cost κ·r=0.8 (κ=2); B after=0.5',
        '',
        `  ◀ DECISIVE: ${reason}`,
        `      ↳ fix: ${fix}`,
      ].join('\n'),
    );
    expect(ex.caveats.map((c) => [c.type, c.satisfied, c.delegated])).toEqual([['expires', true, false], ['delegation_depth', false, true]]);
    expect(ex.caveats[0]).not.toHaveProperty('remedy');
    expect(ex.grant).toMatchObject({ granted: true, capabilityId: 'rootcap', predicateIndex: 0, where: 'action.verb eq a' });
    expect(ex.risk).toMatchObject({ theta1: 0.2, theta2: 0.6 });
    expect(ex.admission).toMatchObject({ cost: 0.8, kappa: 2, admit: false, needStepUp: true, releaseGuardianShare: true });
  });
  it('renders a single verb on a named resource and the matching predicate index', () => {
    const env = envOf({ predicates: [{ verb: 'zzz' }, { verb: 'v', resource: 'charge:*' }] });
    const ex = explainDecision(PC, dec(), { envelope: env, context: { action: act('v', 'charge:1'), chain: [cap('rootcap', [])] } });
    expect(ex.toText()).toContain('  authority : predicate #1 of grant rootcap grants v on charge:*\n              where any (no where-bound)\n');
  });
  it('renders a denial without a granted predicate or caveats', () => {
    const ex = explainDecision(PC, dec({ releaseGuardianShare: false, reasons: ['x'] }));
    const reason = 'action not permitted by the envelope predicates (default-deny)';
    expect(ex.toText()).toBe(
      [
        'PCA decision — DENY (denied)',
        `Denied: ${reason}`,
        '',
        '  authority : NOT granted — no predicate permits this action',
        '  caveats   : none',
        '  risk      : effective tier t=2; proof=standard, optimistic=false',
        '  budget    : guardian share withheld — policy not satisfied (no autonomous or guardian path); B after=0.5',
        '',
        `  ◀ DECISIVE: ${reason}`,
        '      ↳ fix: grant a predicate that permits this verb+resource (and satisfies its where bound).',
      ].join('\n'),
    );
    expect(ex.grant.granted).toBe(false);
    expect(ex.admission).not.toHaveProperty('cost');
    expect(ex.admission).not.toHaveProperty('kappa');
    expect(ex.risk).not.toHaveProperty('theta1');
    expect(ex.risk).not.toHaveProperty('theta2');
  });
  it('a decision without reasons explains with an empty list', () => {
    const ex = explainDecision(PC, dec({ reasons: undefined }));
    expect(ex.reasons).toEqual([]);
  });
  it('an admitted decision reports allow with no decisive reason', () => {
    const env = envOf();
    const ok = dec({ admit: true, needStepUp: false, r: 0.1, requiredThreshold: { t: 1, proof: 'claim', optimisticAllowed: true } });
    const ex = explainDecision(PC, ok, { envelope: env, context: { action: act('v') } });
    expect(ex.verdict).toBe('allow');
    expect(ex.disposition).toBe('auto-admit');
    expect(ex.decisive).toBeUndefined();
    expect(ex.summary).toBe('Auto-admitted: predicate #0 grants it, all caveats held, risk r=0.1 is in the t=1 band and the budget covers it.');
    expect(ex.admission.path).toBe('auto-admitted at t=1 (claim); metered');
    expect(ex.toText()).not.toContain('DECISIVE');
    const bare = explainDecision(PC, ok);
    expect(bare.summary).toBe('Auto-admitted: policy grants it, all caveats held, risk r=0.1 is in the t=1 band and the budget covers it.');
    expect(bare.grant.granted).toBe(true);
  });
  it('a granted decision with no predicate still renders as not granted', () => {
    const ex = explainDecision(PC, dec());
    expect(ex.grant.granted).toBe(true);
    expect(ex.toText()).toContain('  authority : NOT granted — no predicate permits this action\n');
  });
  it('prints the decisive line without a fix when there is none', () => {
    const ex = new DecisionExplanation({
      verdict: 'deny',
      disposition: 'denied',
      grant: { granted: false },
      caveats: [],
      risk: { r: 0.5, tier: 2, proof: 'standard', optimisticAllowed: false, band: 'b' },
      admission: { admit: false, needStepUp: true, releaseGuardianShare: true, budget: { B: 1, tau: 0, asOf: 0 }, path: 'p' },
      decisive: { reason: 'because' },
      reasons: [],
      summary: 's',
    });
    expect(ex.toText()).toBe(
      [
        'PCA decision — DENY (denied)',
        's',
        '',
        '  authority : NOT granted — no predicate permits this action',
        '  caveats   : none',
        '  risk      : b; proof=standard, optimistic=false',
        '  budget    : p; B after=1',
        '',
        '  ◀ DECISIVE: because',
      ].join('\n'),
    );
  });
});

describe('decision grant and path reasoning', () => {
  it('names the reason found in the decision when no envelope is given', () => {
    const ex = explainDecision(PC, dec({ releaseGuardianShare: false, reasons: ['foo', 'not permitted here', 'predicate y'] }));
    expect(ex.grant.reason).toBe('not permitted here');
    expect(ex.toText()).toContain('  authority : NOT granted — not permitted here\n');
    expect(ex.decisive?.reason).toBe('not permitted here');
    expect(ex.summary).toBe('Denied: not permitted here');
    expect(explainDecision(PC, dec({ releaseGuardianShare: false, reasons: ['predicate y'] })).grant.reason).toBe('predicate y');
    expect(explainDecision(PC, dec({ releaseGuardianShare: false, reasons: ['foo'] })).grant.reason).toBeUndefined();
  });
  it('a released share needs no reason lookup', () => {
    expect(explainDecision(PC, dec({ reasons: ['predicate y'] })).grant.reason).toBeUndefined();
  });
  it('an envelope that permits nothing explains why', () => {
    const ex = explainDecision(PC, dec({ releaseGuardianShare: false }), { envelope: envOf({ predicates: [{ verb: 'zzz' }] }), context: { action: act('a', 'r') } });
    expect(ex.grant).toMatchObject({ granted: false, reason: 'no predicate permits a on r' });
    expect(ex.decisive?.reason).toBe('no predicate permits a on r');
    const rel = explainDecision(PC, dec({ releaseGuardianShare: true }), { envelope: envOf({ predicates: [{ verb: 'zzz' }] }), context: { action: act('a', 'r') } });
    expect(rel.grant.granted).toBe(false);
  });
  it('an envelope without an action context keeps the decision verdict on the grant', () => {
    const ex = explainDecision(PC, dec(), { envelope: envOf() });
    expect(ex.grant.granted).toBe(true);
    expect(ex.grant.reason).toBeUndefined();
    expect(ex.grant.predicate).toBeUndefined();
  });
  it('an action context without an envelope is ignored', () => {
    const ex = explainDecision(PC, dec(), { context: { action: act('a', 'r') } });
    expect(ex.grant.granted).toBe(true);
    expect(ex.reasons).toEqual([]);
  });
  it('a depleted budget is named and the cost is spelled out only when known', () => {
    const d = dec({ reasons: ['other', 'budget depleted'] });
    const withEnv = explainDecision(PC, d, { envelope: envOf() });
    expect(withEnv.admission.path).toBe('trust budget cannot cover the cost — step-up to t=3 (human recharge) required');
    expect(withEnv.decisive).toEqual({
      reason: 'risk 0.4 is admissible but the trust budget cannot cover cost κ·r=0.8',
      remedy: 'recharge the budget with a human co-sign, or lower the action risk.',
    });
    expect(explainDecision(PC, d).decisive?.reason).toBe('risk 0.4 is admissible but the trust budget cannot cover cost κ·r');
    expect(explainDecision(PC, dec({ reasons: ['other'] })).admission.path).toBe('step-up to t=2 (standard) co-signature required');
  });
  it('a high-risk step-up asks for the right co-signature', () => {
    const t3 = explainDecision(PC, dec({ r: 0.9, requiredThreshold: { t: 3, proof: 'strong', optimisticAllowed: false } }));
    expect(t3.decisive).toEqual({ reason: 'risk 0.9 exceeds the auto threshold → step-up to t=3 (strong)', remedy: 'obtain a human step-up co-signature.' });
    const t2 = explainDecision(PC, dec());
    expect(t2.decisive).toEqual({ reason: 'risk 0.4 exceeds the auto threshold → step-up to t=2 (standard)', remedy: 'obtain the guardian/principal co-signature for this tier.' });
    expect(t2.summary).toBe('Needs step-up: risk 0.4 exceeds the auto threshold → step-up to t=2 (standard)');
    expect(t2.disposition).toBe('step-up');
  });
  it('a withheld share with a matching grant is still a denial', () => {
    const ex = explainDecision(PC, dec({ releaseGuardianShare: false }), { envelope: envOf({ predicates: [{ verb: 'a' }] }), context: { action: act('a') } });
    expect(ex.disposition).toBe('denied');
    expect(ex.summary).toBe('Denied: risk 0.4 exceeds the auto threshold → step-up to t=2 (standard)');
  });
  it('only a strict true admits or releases', () => {
    const ex = explainDecision(PC, dec({ admit: 1, releaseGuardianShare: 1 }));
    expect(ex.verdict).toBe('deny');
    expect(ex.disposition).toBe('denied');
  });
});

describe('risk band rendering', () => {
  const band = (r: number, rp: object) => explainDecision(PC, dec({ r }), { envelope: envOf({ risk_policy: rp }) }).risk.band;
  const both = { theta1: 0.2, theta2: 0.6, kappa: 1 };
  it('names the band and its boundaries, boundaries inclusive', () => {
    expect(band(0.1, both)).toBe('r 0.1 ≤ θ1 0.2 → claim band (t=1)');
    expect(band(0.2, both)).toBe('r 0.2 ≤ θ1 0.2 → claim band (t=1)');
    expect(band(0.3, both)).toBe('θ1 0.2 < r 0.3 ≤ θ2 0.6 → standard band (t=2)');
    expect(band(0.6, both)).toBe('θ1 0.2 < r 0.6 ≤ θ2 0.6 → standard band (t=2)');
    expect(band(0.7, both)).toBe('r 0.7 > θ2 0.6 → strong band (t=3)');
  });
  it('falls back to the effective tier when a threshold is missing', () => {
    expect(band(0.3, { theta1: 0.2, kappa: 1 })).toBe('effective tier t=2');
    expect(band(0.3, { theta2: 0.6, kappa: 1 })).toBe('effective tier t=2');
    expect(band(0.3, { kappa: 1 })).toBe('effective tier t=2');
  });
});

describe('caveat outcomes', () => {
  const failing = (types: unknown[], reasons: string[], over: object = {}) => explainDecision(PC, dec({ reasons, ...over }), { envelope: envOf({ caveats: types }) });
  it('gives each failed caveat its own fix', () => {
    const types = [
      { type: 'expires', at: 100 },
      { type: 'not_before', at: 200 },
      { type: 'rate', max: 3, per_secs: 60 },
      { type: 'reversibility_max', class: 'reversible' },
      { type: 'delegation_depth', max: 2 },
      { type: 'custom', k: 'v' },
      { type: 'fine' },
    ];
    const ex = failing(types, ['caveat(s) not satisfied: expires,not_before,rate,reversibility_max,delegation_depth,custom']);
    expect(ex.caveats.map((c) => c.remedy)).toEqual([
      "the grant expired at 100 (epoch ms); obtain a fresh grant or re-mint with a later 'expires'.",
      'the grant is not valid until 200 (epoch ms); retry after that time.',
      "rate limit 3/60s reached; wait for the window to clear or raise the 'rate' caveat.",
      "the action is more severe than the allowed class 'reversible'; only that class or lower is permitted.",
      "delegation depth exceeds max 2; act from a shallower hop or raise 'delegation_depth'.",
      "caveat 'custom' is not satisfied; check its parameters against the action/context.",
      undefined,
    ]);
    expect(ex.caveats.map((c) => c.detail)).toEqual([
      'expires(at=100) NARROWED/DENIED',
      'not_before(at=200) NARROWED/DENIED',
      'rate(max=3, per_secs=60) NARROWED/DENIED',
      'reversibility_max(class=reversible) NARROWED/DENIED',
      'delegation_depth(max=2) NARROWED/DENIED',
      'custom(k=v) NARROWED/DENIED',
      'fine held',
    ]);
    expect(ex.caveats[6]).not.toHaveProperty('remedy');
  });
  it('a caveat without fields renders just its type and verdict', () => {
    const ex = failing([{ type: 'x' }, { type: 'y' }], ['caveat(s) not satisfied: x']);
    expect(ex.caveats.map((c) => c.detail)).toEqual(['x NARROWED/DENIED', 'y held']);
  });
  it('reads the failed list from the reasons: separators, spaces and line ends', () => {
    const types = [{ type: 'a' }, { type: 'b' }, { type: 'c' }, { type: '' }, { type: 'ab' }, { type: 'd' }];
    const ex = failing(types, ['caveat(s) not satisfied: a, b, ', 'caveat(s) not satisfied: ab', 'caveat(s) not satisfied: d\nrest']);
    expect(ex.caveats.map((c) => [c.type, c.satisfied])).toEqual([['a', false], ['b', false], ['c', true], ['', true], ['ab', false], ['d', true]]);
  });
  it('with no reasons every caveat of a released decision held, and of a withheld one did not', () => {
    expect(failing([{ type: 'a' }], []).caveats[0]?.satisfied).toBe(true);
    expect(failing([{ type: 'a' }], [], { releaseGuardianShare: false }).caveats[0]?.satisfied).toBe(false);
  });
  it('a caveat named failed stays failed even when the share was released', () => {
    expect(failing([{ type: 'a' }], ['caveat(s) not satisfied: a']).caveats[0]?.satisfied).toBe(false);
  });
});

describe('individual caveat evaluation', () => {
  const run = (context: object, env: Envelope | undefined) => explainDecision(PC, dec(), { ...(env ? { envelope: env } : {}), context: context as never });
  const flags = (ex: ReturnType<typeof run>) => ex.caveats.map((c) => [c.satisfied, c.delegated]);
  const env = envOf({ caveats: [EXPIRES_1000] });
  const chain = [cap('r', []), cap('l', [EXPIRES_1000])];
  it('evaluates the grant and delegated caveats against the context when everything is supplied', () => {
    expect(flags(run({ action: act(), caveat: nowAt(2000), chain }, env))).toEqual([[false, false], [false, true]]);
    expect(flags(run({ action: act(), caveat: nowAt(10), chain }, env))).toEqual([[true, false], [true, true]]);
  });
  it('falls back to the decision when the envelope is missing', () => {
    expect(flags(run({ action: act(), caveat: nowAt(2000), chain }, undefined))).toEqual([[true, true]]);
  });
  it('falls back to the decision when the caveat context is missing', () => {
    expect(flags(run({ action: act(), chain }, env))).toEqual([[true, false], [true, true]]);
  });
  it('falls back to the decision when the action context is missing', () => {
    expect(flags(run({ caveat: nowAt(2000), chain }, env))).toEqual([[true, false], [true, true]]);
  });
});

describe('delegated caveat selection', () => {
  const chainOf = (...caps: unknown[]) => caps as Capability[];
  const delegatedOf = (chain: Capability[]) => explainDecision(PC, dec(), { context: { chain } }).caveats.map((c) => [c.type, c.delegated]);
  it('takes the leaf caveats beyond the root count', () => {
    expect(delegatedOf(chainOf(cap('r', [{ type: 'a' }]), cap('l', [{ type: 'a' }, { type: 'b' }])))).toEqual([['b', true]]);
  });
  it('a single capability or an empty chain delegates nothing', () => {
    expect(delegatedOf(chainOf(cap('r', [{ type: 'a' }])))).toEqual([]);
    expect(delegatedOf([])).toEqual([]);
    expect(explainDecision(PC, dec(), { context: { chain: [] } }).grant.capabilityId).toBeUndefined();
  });
  it('a hole at the leaf or a leaf without caveats delegates nothing', () => {
    expect(delegatedOf(chainOf(cap('r', []), cap('m', []), undefined))).toEqual([]);
    expect(delegatedOf(chainOf(cap('r', [{ type: 'a' }]), cap('l', undefined)))).toEqual([]);
  });
});

// ---- chain ------------------------------------------------------------------------------------

describe('chain trace', () => {
  const ENV = { type: 'envelope', predicates: [{}, {}], caveats: [{}] };
  const RATE = { type: 'rate', max: 3, per_secs: 60 };
  const key = (c: string) => c.repeat(43);
  const hopCap = (id: string, issuer: string, holder: string, caveats: unknown[] | undefined, alg?: string) => ({ id, issuer: key(issuer), holder: key(holder), caveats, ...(alg ? { alg } : {}) }) as unknown as Capability;
  const full = [
    hopCap('c0', 'I', '1', [ENV]),
    hopCap('c1', '1', '2', [ENV, RATE, budgetAllocCaveat(0.5)], 'ml-dsa-65'),
    hopCap('c2', '2', '3', [ENV, RATE, budgetAllocCaveat(0.5), budgetAllocCaveat(0.25), { type: 'x' }]),
    hopCap('c3', '3', '4', [ENV, RATE, budgetAllocCaveat(0.5), budgetAllocCaveat(0.25), { type: 'x' }]),
  ];
  it('describes each hop and renders the trace', () => {
    const ex = explainChain(full);
    expect(ex.hops.map((h) => h.narrowed)).toEqual([
      'grants envelope (2 predicate(s), 1 caveat(s))',
      'narrows: +rate(max=3, per_secs=60), budget_alloc(B_sub=0.5)',
      'narrows: budget_alloc(B_sub=0.25), +x',
      'rebind only (no new caveats)',
    ]);
    expect(ex.hops.map((h) => h.alg)).toEqual(['ed25519', 'ml-dsa-65', 'ed25519', 'ed25519']);
    expect(ex.hops.map((h) => h.addedCaveatTypes)).toEqual([['envelope'], ['rate', 'budget_alloc'], ['budget_alloc', 'x'], []]);
    expect(ex.hops.map((h) => h.budgetAlloc)).toEqual([undefined, 0.5, 0.25, undefined]);
    expect(ex.hops[0]).not.toHaveProperty('budgetAlloc');
    expect(ex.hops.map((h) => h.isRoot)).toEqual([true, false, false, false]);
    expect(ex.verification).toBeUndefined();
    const summary = 'IIIIIIIIII… (principal) delegated through 3 hop(s) to the acting holder 4444444444…; 2 budget node(s).';
    expect(ex.summary).toBe(summary);
    expect(ex.toText()).toBe(
      [
        'PCA delegation chain — 4 hop(s) (attenuation trace)',
        'UNVERIFIED: this trace shows what the chain claims; no signature or link was checked.',
        summary,
        '',
        '  #0 root  IIIIIIIIII… ──▶ 1111111111…   grants envelope (2 predicate(s), 1 caveat(s))',
        '  #1 deleg 1111111111… ──▶ 2222222222…   narrows: +rate(max=3, per_secs=60), budget_alloc(B_sub=0.5)',
        '  #2 deleg 2222222222… ──▶ 3333333333…   narrows: budget_alloc(B_sub=0.25), +x',
        '  #3 deleg 3333333333… ──▶ 4444444444…   rebind only (no new caveats)',
        '',
        '  budget subtree: depth 1 B_sub=0.5 → depth 2 B_sub=0.25',
      ].join('\n'),
    );
  });
  it('a chain without budget allocations has no subtree line', () => {
    const ex = explainChain([hopCap('c0', 'I', '1', [RATE])]);
    expect(ex.toText()).toBe(
      [
        'PCA delegation chain — 1 hop(s) (attenuation trace)',
        'UNVERIFIED: this trace shows what the chain claims; no signature or link was checked.',
        'IIIIIIIIII… (principal) delegated through 0 hop(s) to the acting holder 1111111111…; 0 budget node(s).',
        '',
        '  #0 root  IIIIIIIIII… ──▶ 1111111111…   grants +rate(max=3, per_secs=60)',
      ].join('\n'),
    );
  });
  it('an envelope with malformed members counts zero, a non-budget caveat is not a budget', () => {
    const ex = explainChain([hopCap('c0', 'I', '1', [{ type: 'envelope', predicates: 'x', caveats: 5 }, { type: 'budget_alloc', limit: 'x' }])]);
    expect(ex.hops[0]?.narrowed).toBe('grants envelope (0 predicate(s), 0 caveat(s)), +budget_alloc(limit=x)');
    expect(ex.hops[0]).not.toHaveProperty('budgetAlloc');
  });
  it('an empty chain and root-only variants', () => {
    const empty = explainChain([]);
    expect(empty.summary).toBe('empty chain (no authority)');
    expect(empty.depth).toBe(0);
    expect(empty.rootIssuer).toBeUndefined();
    expect(empty.leafHolder).toBeUndefined();
    expect(explainChain([hopCap('c0', 'I', '1', [])]).hops[0]?.narrowed).toBe('root grant (no caveats)');
    const noList = explainChain([hopCap('c0', 'I', '1', undefined)]);
    expect(noList.hops[0]?.narrowed).toBe('root grant (no caveats)');
    expect(noList.hops[0]?.addedCaveats).toEqual([]);
    expect(noList.rootIssuer).toBe(key('I'));
    expect(noList.leafHolder).toBe(key('1'));
  });
  it('a hop with fewer caveats than its parent adds none', () => {
    const ex = explainChain([hopCap('c0', 'I', '1', [ENV]), hopCap('c1', '1', '2', [])]);
    expect(ex.hops[1]?.addedCaveats).toEqual([]);
    expect(ex.hops[1]?.narrowed).toBe('rebind only (no new caveats)');
  });
  it('holes in the chain are skipped without throwing', () => {
    const ex = explainChain([undefined as never, hopCap('c1', '1', '2', undefined)]);
    expect(ex.hops.map((h) => h.index)).toEqual([1]);
    expect(ex.rootIssuer).toBeUndefined();
    expect(ex.summary).toBe('<none> (principal) delegated through 1 hop(s) to the acting holder 2222222222…; 0 budget node(s).');
    const mid = explainChain([hopCap('c0', 'I', '1', []), undefined as never, hopCap('c2', '2', '3', [])]);
    expect(mid.hops.map((h) => h.index)).toEqual([0, 2]);
  });
});

describe('chain verification rendering', () => {
  const mint = () => {
    const principal = generateKeyPair();
    const holder = generateKeyPair();
    const { grant } = mintGrant({
      principalSecret: principal.secretKey,
      principalPublic: b64u(principal.publicKey),
      holder: b64u(holder.publicKey),
      goal: 'g',
      envelope: { predicates: [{ verb: 'v' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } as Omit<Envelope, 'goal_commit'>,
    });
    const sub = generateKeyPair();
    return [grant, delegate(grant, b64u(sub.publicKey), [], holder.secretKey)];
  };
  it('a valid chain verifies with no reason member', () => {
    const chain = mint();
    expect(explainChain(chain, { verify: true }).verification).toStrictEqual({ ok: true });
    expect(explainChain(chain, { verify: true }).toText().split('\n')[1]).toBe('verified: signatures, links and caveat rules hold.');
  });
  it('an invalid chain carries the verifier reason', () => {
    const chain = mint();
    const expected = verifyChain(chain, 'someone-else');
    expect(expected.ok).toBe(false);
    const ex = explainChain(chain, { verify: true, expectedRootIssuer: 'someone-else' });
    expect(ex.verification).toStrictEqual({ ok: false, reason: cleanText(expected.ok ? '' : (expected.reason ?? '')) });
    expect(ex.toText().split('\n')[1]).toBe(`NOT VALID: ${ex.verification?.reason}`);
    expect(ex.depth).toBe(2);
    expect(ex.hops).toHaveLength(2);
  });
  it('a chain that is not an array is not valid', () => {
    expect(explainChain(null as never, { verify: true }).verification).toStrictEqual({ ok: false, reason: 'chain is not an array' });
  });
  it('a verification that cannot run is reported as such', () => {
    const opts = { verify: true as const };
    Object.defineProperty(opts, 'expectedRootIssuer', {
      get() {
        throw new Error('boom');
      },
    });
    expect(explainChain([], opts).verification).toStrictEqual({ ok: false, reason: 'chain could not be verified' });
  });
  it('a not-valid trace without a reason says the chain failed verification', () => {
    const ex = new ChainExplanation({ depth: 0, hops: [], rootIssuer: undefined, leafHolder: undefined, budgetNodes: [], summary: 's', verification: { ok: false } });
    expect(ex.toText().split('\n')[1]).toBe('NOT VALID: the chain failed verification');
    expect(ex.verification).toStrictEqual({ ok: false });
  });
});
