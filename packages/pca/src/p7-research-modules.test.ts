/**
 * Track 7 hardening of the research (a) modules: catalog, session, console, compliance, dlp, policy-sim,
 * policy-debug, budget-forecast, and the mesh narrowing / trust-configuration contract.
 * Every negative test here fails when the corresponding check is removed.
 */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  BUILTIN_ACTIONS,
  DEFAULT_CATALOG,
  assertCatalogPinned,
  buildCatalog,
  catalogDigest,
  defineAction,
  extendCatalog,
  resolveAction,
} from './catalog';
import { catalogRisk } from './catalog-risk';
import { EMPTY_FREEZE, buildConsole, eventFromPCActn, freezeAgent, isFrozen, unfreezeAgent, type ActivityEvent } from './console';
import { type DlpPolicy, evaluateDlp } from './dlp';
import { agent, compilePolicy } from './facade';
import { generateKeyPair } from './keys';
import { buildMeshExample, effectiveAuthority, verifyMeshProof } from './mesh';
import { explainDecision, counterfactual } from './policy-debug';
import { simulate } from './policy-sim';
import { decide, type DecideInput } from './policy-vm';
import { forecast, recommendPolicy } from './budget-forecast';
import { SESSION_MAX_DEPTH, addMember, sharesGoal, startSession, type Session } from './session';

// ---------------------------------------------------------------------------------------------- catalog
describe('catalog: fail closed and pinned', () => {
  it('an unknown verb resolves to irreversible with the maximum blast radius', () => {
    expect(resolveAction(DEFAULT_CATALOG, 'acme.launch.rocket')).toEqual({
      catalogued: false,
      spec: { connector: 'acme', action: 'launch.rocket', verb: 'acme.launch.rocket', reversibility: 'irreversible', blastRadius: 1, description: '(uncatalogued) acme.launch.rocket' },
    });
    expect(resolveAction(DEFAULT_CATALOG, 'gmail.send')).toEqual({ catalogued: true, spec: DEFAULT_CATALOG.get('gmail.send') });
  });
  it('the verifier-side risk of an unknown verb supplies nothing, so every input is priced at the worst case', () => {
    const grant = agent({ principal: generateKeyPair(), goal: 'g', permissions: { github: ['read'] }, aud: 'i' }).grant;
    expect(catalogRisk('acme.unknown', {}, grant)).toEqual({});
  });
  it('the built-in catalog is pinned by digest', () => {
    expect(catalogDigest(DEFAULT_CATALOG)).toBe(PINNED_DIGEST);
    expect(() => assertCatalogPinned(DEFAULT_CATALOG, PINNED_DIGEST)).not.toThrow();
    expect(() => assertCatalogPinned(DEFAULT_CATALOG, 'x')).toThrow('catalog does not match the pinned digest');
  });
  it('the digest ignores order and changes with any field of any action', () => {
    const base = catalogDigest(DEFAULT_CATALOG);
    expect(catalogDigest(buildCatalog([...BUILTIN_ACTIONS].reverse()))).toBe(base);
    const tweak = (patch: object) => catalogDigest(buildCatalog(BUILTIN_ACTIONS.map((a, i) => (i === 3 ? { ...a, ...patch } : a))));
    for (const patch of [{ reversibility: 'irreversible' }, { blastRadius: 0.01 }, { description: 'x' }, { amountField: 'sum' }, { resource: '/x' }]) {
      expect(tweak(patch), JSON.stringify(patch)).not.toBe(base);
    }
    expect(catalogDigest(buildCatalog(BUILTIN_ACTIONS.slice(1)))).not.toBe(base);
  });
  it('extending the catalog cannot make an existing verb less cautious', () => {
    const send = DEFAULT_CATALOG.get('gmail.send')!;
    expect(() => extendCatalog(DEFAULT_CATALOG, [{ ...send, reversibility: 'reversible' }])).toThrow("extendCatalog: 'gmail.send' would be less cautious than the existing entry");
    expect(() => extendCatalog(DEFAULT_CATALOG, [{ ...send, blastRadius: send.blastRadius - 0.1 }])).toThrow('less cautious');
    const stricter = extendCatalog(DEFAULT_CATALOG, [{ ...send, blastRadius: 1 }, defineAction({ connector: 'acme', action: 'x', reversibility: 'reversible', blastRadius: 0.1, description: 'd' })]);
    expect(stricter.get('gmail.send')!.blastRadius).toBe(1);
    expect(stricter.get('acme.x')!.verb).toBe('acme.x');
    expect(stricter.all().length).toBe(DEFAULT_CATALOG.all().length + 1);
  });
  it('defineAction validates its input', () => {
    const ok = { connector: 'c', action: 'a', reversibility: 'reversible' as const, blastRadius: 0.5, description: 'd' };
    expect(() => defineAction({ ...ok, connector: 'a.b' })).toThrow('defineAction: connector must not contain whitespace or a dot');
    expect(() => defineAction({ ...ok, connector: 'a b' })).toThrow('whitespace or a dot');
    expect(() => defineAction({ ...ok, connector: 5 as never })).toThrow('connector and action are required');
    expect(() => defineAction({ ...ok, amountField: '' })).toThrow('defineAction: amountField must be a non-empty string');
    expect(() => defineAction({ ...ok, blastRadius: Number.NaN })).toThrow('blastRadius must be in [0,1]');
    expect(() => defineAction({ ...ok, blastRadius: 1.01 })).toThrow('blastRadius must be in [0,1]');
    expect(() => defineAction({ ...ok, reversibility: 'maybe' as never })).toThrow("bad reversibility 'maybe'");
  });
});

// ---------------------------------------------------------------------------------------------- session
describe('session: depth bound and goal sharing', () => {
  const root = () => agent({ principal: generateKeyPair(), goal: 'ship', permissions: { github: ['comment'] }, aud: 'i' });
  it('refuses to grow past the depth bound', () => {
    let s = startSession(root());
    for (let i = 0; i < SESSION_MAX_DEPTH; i++) s = addMember(s).session;
    expect(s.members.length).toBe(SESSION_MAX_DEPTH + 1);
    expect(() => addMember(s)).toThrow(`addMember: a session is limited to ${SESSION_MAX_DEPTH} delegation hops`);
  });
  it('a team shares a goal only when there is a goal commitment to share', () => {
    const r = root();
    const s = startSession(r);
    expect(s.goalCommit).not.toBe('');
    expect(sharesGoal(s)).toBe(true);
    expect(sharesGoal({ ...s, goalCommit: 'tampered' })).toBe(false);
    // members that all lack an envelope all read '' - that is "no goal", not "the same goal"
    const bare = { ...r, grant: { ...r.grant, caveats: [] } } as typeof r;
    expect(startSession(bare).goalCommit).toBe('');
    expect(sharesGoal(startSession(bare))).toBe(false);
    const blank: Session = { root: r, members: [r], goalCommit: '' };
    expect(sharesGoal(blank)).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------- console
describe('console: malformed events and the kill switch', () => {
  const ev = (over: Partial<ActivityEvent>): ActivityEvent => ({ at: 1, agent: 'a', verb: 'v', resource: 'r', outcome: 'auto', ...over });
  it('events without a finite time or an agent are counted as dropped and never enter the view', () => {
    const v = buildConsole([ev({ at: 10 }), ev({ at: Number.NaN }), ev({ agent: '' }), ev({ at: Infinity, agent: 'b' }), null as never, ev({ at: 20, outcome: 'deny' })]);
    expect(v.dropped).toBe(4);
    expect(v.totals).toEqual({ actions: 2, autos: 1, stepUps: 0, denies: 1, executed: 0 });
    expect(v.window).toEqual({ from: 10, to: 20 });
    expect(v.agents.map((a) => [a.agent, a.firstSeen, a.lastSeen])).toEqual([['a', 10, 20]]);
  });
  it('an empty stream is an empty view', () => {
    expect(buildConsole([])).toEqual({ agents: [], totals: { actions: 0, autos: 0, stepUps: 0, denies: 0, executed: 0 }, window: { from: 0, to: 0 }, dropped: 0 });
  });
  it('freeze is idempotent and sorted; unfreeze removes', () => {
    let s = freezeAgent(freezeAgent(freezeAgent(EMPTY_FREEZE, 'b'), 'a'), 'b');
    expect(s).toEqual({ frozen: ['a', 'b'] });
    expect(isFrozen(s, 'a')).toBe(true);
    expect(isFrozen(s, 'c')).toBe(false);
    s = unfreezeAgent(s, 'a');
    expect(s).toEqual({ frozen: ['b'] });
  });
  it('an action with no identifiable agent, or a malformed set, counts as frozen', () => {
    expect(isFrozen(EMPTY_FREEZE, '')).toBe(true);
    expect(isFrozen(EMPTY_FREEZE, undefined as never)).toBe(true);
    expect(isFrozen(null as never, 'a')).toBe(true);
    expect(isFrozen({ frozen: 'a' } as never, 'a')).toBe(true);
    expect(() => freezeAgent(EMPTY_FREEZE, '')).toThrow('freezeAgent: agent must be a non-empty string');
  });
  it('a PCActn with no chain is attributed to "unknown"', () => {
    const e = eventFromPCActn({ cap_chain: [], action: { verb: 'v', resource: 'r' }, iat: 5 } as never, 'deny');
    expect(e.agent).toBe('unknown');
  });
});

// ---------------------------------------------------------------------------------------------- dlp
describe('dlp: malformed policy and ties fail closed', () => {
  const ctx = (taint: number, resource = 'customer:1', verb = 'send') => ({ verb, resource, taint });
  const cls = (name: string, resource: string, max: number, extra: object = {}) => ({ name, resource, maxTaintForAuto: max, ...extra });
  it('a ceiling that is not a number denies instead of allowing everything', () => {
    for (const bad of [Number.NaN, '3', null]) {
      expect(evaluateDlp({ classes: [cls('pii', '*', bad as never)] }, ctx(100))).toEqual({ outcome: 'deny', class: 'pii', reason: 'malformed DLP policy: ceilings must be numbers' });
    }
    expect(evaluateDlp({ classes: [cls('pii', '*', 0, { hardDenyAbove: Number.NaN })] }, ctx(100)).outcome).toBe('deny');
    expect(evaluateDlp({ classes: [], defaultMaxTaintForAuto: Number.NaN }, ctx(100))).toEqual({ outcome: 'deny', reason: 'malformed DLP policy: ceilings must be numbers' });
  });
  it('a malformed policy object denies', () => {
    for (const p of [null, undefined, {}, { classes: 'x' }]) expect(evaluateDlp(p as never, ctx(0))).toEqual({ outcome: 'deny', reason: 'malformed DLP policy' });
  });
  it('of two equally specific classes the strictest wins, in either order', () => {
    const lenient = cls('lenient', 'customer:*', 5);
    const strict = cls('strict', 'customer:*', 0);
    for (const classes of [[lenient, strict], [strict, lenient]]) {
      expect(evaluateDlp({ classes }, ctx(3))).toEqual({ outcome: 'step_up', class: 'strict', reason: "taint 3 > 0 for 'strict' — needs human review" });
    }
  });
  it('a more specific class still beats a stricter generic one', () => {
    const p: DlpPolicy = { classes: [cls('generic', '*', 0), cls('exact', 'customer:1', 9)] };
    expect(evaluateDlp(p, ctx(5))).toEqual({ outcome: 'allow', class: 'exact' });
  });
  it('a non-finite taint never beats a ceiling', () => {
    const p: DlpPolicy = { classes: [cls('pii', '*', 5, { hardDenyAbove: 9 })] };
    for (const t of [Number.NaN, Infinity, '1' as never]) expect(evaluateDlp(p, ctx(t)).outcome).toBe('deny');
  });
  it('a class limited to some verbs does not apply to others', () => {
    const p: DlpPolicy = { classes: [cls('send-only', '*', 0, { verbs: ['send'] })], defaultMaxTaintForAuto: 9 };
    expect(evaluateDlp(p, ctx(3, 'x', 'send')).outcome).toBe('step_up');
    expect(evaluateDlp(p, ctx(3, 'x', 'read'))).toEqual({ outcome: 'allow' });
  });
});

// ---------------------------------------------------------------------------------------------- policy-sim vs the verifier
describe('policy-sim reuses the verifier: it is never more permissive than decide()', () => {
  const perms = { stripe: ['refund', 'charge', 'payout'], gmail: ['send', 'draft'], github: ['read', 'create_pr', 'delete_repo'], files: ['read', 'write', 'delete'], acme: ['do'] };
  const specs = [...DEFAULT_CATALOG.all().filter((s) => (perms as Record<string, string[]>)[s.connector]?.includes(s.action)), resolveAction(DEFAULT_CATALOG, 'acme.do').spec];
  for (const limits of [{}, { refund: '$100/day', charge: '$500/day' }]) {
    it(`first action at a fresh budget, limits ${JSON.stringify(limits)}`, () => {
      const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: perms as never, limits: limits as never, aud: 'i' });
      const now = 1_000;
      let compared = 0;
      for (const s of specs) {
        for (const amount of s.amountField ? [1, 50, 400] : [undefined]) {
          const params = s.amountField ? { [s.amountField]: amount, currency: 'usd' } : {};
          const sim = simulate(a.policy, [{ verb: s.verb, resource: '/x/1', params, at: now }], { start: now }).results[0]!;
          const d = decide({
            grant: a.grant,
            chain: a.chain,
            action: { action: { verb: s.verb, resource: '/x/1', params, reversibility_class: s.reversibility } },
            risk: { ...catalogRisk(s.verb, params, a.grant), taint: 0, semanticDistance: 0 },
            caveatContext: { blastRadius: s.blastRadius, reversibilityClass: s.reversibility, recentActionTimes: [] },
            budget: { ...a.budget, tau: now, asOf: now },
            now,
          } as DecideInput);
          compared++;
          if (sim.outcome === 'auto') expect(d.admit, `${s.verb} ${amount}: the simulator would auto-admit what the verifier does not`).toBe(true);
        }
      }
      expect(compared).toBeGreaterThanOrEqual(15);
    });
  }
  it('an action with no usable time is denied, not skipped', () => {
    const p = compilePolicy({ permissions: { github: ['read'] } });
    const rep = simulate(p, [{ verb: 'github.read', resource: 'r', at: Number.NaN }, { verb: 'github.read', resource: 'r', at: 1 }]);
    expect(rep.results.map((r) => [r.outcome, r.reason])).toEqual([['deny', 'action has no finite time'], ['auto', undefined]]);
    expect(rep.deny).toBe(1);
  });
  it('has no side effects: the policy and the actions are untouched', () => {
    const p = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' } });
    const actions = [{ verb: 'stripe.refund', resource: 'c', params: { amount: 10 }, at: 1 }];
    const before = JSON.stringify([p, actions]);
    simulate(p, actions);
    forecast(p, actions);
    expect(JSON.stringify([p, actions])).toBe(before);
  });
});

// ---------------------------------------------------------------------------------------------- policy-debug vs decide
describe('policy-debug re-runs decide(), it does not copy it', () => {
  const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['refund'], github: ['read'] }, limits: { refund: '$100/day' }, aud: 'i' });
  const arb = fc.record({
    verb: fc.constantFrom('stripe.refund', 'github.read', 'stripe.payout'),
    amount: fc.integer({ min: 0, max: 400 }),
    B: fc.double({ min: 0, max: 100, noNaN: true }),
    at: fc.integer({ min: 0, max: 7_200_000 }),
    sd: fc.option(fc.double({ min: 0, max: 1, noNaN: true }), { nil: undefined }),
    taint: fc.option(fc.double({ min: 0, max: 1, noNaN: true }), { nil: undefined }),
    floor: fc.option(fc.double({ min: 0, max: 1, noNaN: true }), { nil: undefined }),
  });
  type Gen = { verb: string; amount: number; B: number; at: number; sd?: number | undefined; taint?: number | undefined; floor?: number | undefined };
  const mk = (x: Gen): DecideInput => ({
    grant: a.grant,
    chain: a.chain,
    action: { action: { verb: x.verb, resource: '/x', params: { amount: x.amount } } },
    risk: { ...(x.sd === undefined ? {} : { semanticDistance: x.sd }), ...(x.taint === undefined ? {} : { taint: x.taint }), blastRadius: 0.3 },
    budget: { B: x.B, tau: 0, asOf: 0 },
    now: x.at,
    ...(x.floor === undefined ? {} : { rFloor: x.floor }),
  });
  it('the explained decision is exactly decide(input), term sums match, and the input is not modified', () => {
    fc.assert(
      fc.property(arb, (x) => {
        const input = mk(x);
        const frozen = JSON.stringify(input);
        const e = explainDecision(input);
        expect(e.decision).toEqual(decide(input));
        expect(e.risk.r).toBeCloseTo(e.decision.r, 12);
        expect(e.autoAllow).toBe(e.decision.admit);
        expect(e.t).toBe(e.decision.requiredThreshold.t);
        expect(e.budget.after).toEqual(e.decision.budget);
        expect(JSON.stringify(input)).toBe(frozen);
      }),
      { numRuns: 200, seed: 7 },
    );
  });
  it('a no-op counterfactual equals the baseline and flips nothing', () => {
    fc.assert(
      fc.property(arb, (x) => {
        const rep = counterfactual(mk(x), [{}]);
        expect(rep.outcomes[0]!.explanation).toEqual(rep.baseline);
        expect(rep.flipping).toEqual([]);
        expect(rep.outcomes[0]!.rDelta).toBe(0);
      }),
      { numRuns: 60, seed: 11 },
    );
  });
  it('a grant with no envelope is explained as a fail-closed denial', () => {
    const e = explainDecision({ ...mk({ verb: 'github.read', amount: 0, B: 1, at: 1 }), grant: { ...a.grant, caveats: [] } as never });
    expect(e.envelopeValid).toBe(false);
    expect(e.autoAllow).toBe(false);
    expect(e.risk.r).toBe(1);
  });
});

// ---------------------------------------------------------------------------------------------- budget-forecast
describe('budget-forecast', () => {
  it('forecast agrees step for step with simulate', () => {
    const p = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' } });
    const plan = [1, 2, 3, 4].map((i) => ({ verb: 'stripe.refund', resource: `c${i}`, params: { amount: 40 }, at: i }));
    const f = forecast(p, plan);
    const s = simulate(p, plan);
    expect(f.steps.map((x) => [x.outcome, x.budgetAfter])).toEqual(s.results.map((x) => [x.outcome, x.budgetAfter]));
    expect(f.firstStepUpAt).toBe(s.results.findIndex((x) => x.outcome === 'step_up'));
    expect(f.cosignsNeeded).toBe(s.stepUp);
    expect(f.endBudget).toBe(s.endBudget);
  });
  it('recommendPolicy refuses inputs that would produce NaN or an infinite bound', () => {
    expect(() => recommendPolicy(Number.NaN, 0.1)).toThrow('recommendPolicy: targetActions and perActionRisk must be finite numbers');
    expect(() => recommendPolicy(5, Infinity)).toThrow('finite numbers');
    for (const kappa of [0, -1, Number.NaN, Infinity]) expect(() => recommendPolicy(5, 0.1, { kappa })).toThrow('recommendPolicy: kappa must be a positive finite number');
  });
  it('recommendPolicy: exact values and clamping', () => {
    expect(recommendPolicy(10, 0.2, { kappa: 50 })).toMatchObject({ kappa: 50, bMax: 100, autonomousBound: 2 });
    expect(recommendPolicy(-3, 0.2).bMax).toBe(0);
    expect(recommendPolicy(4, 5).autonomousBound).toBe(4);
  });
});

// ---------------------------------------------------------------------------------------------- mesh
describe('mesh: delegation only narrows; the trust configuration is required', () => {
  const caveat = fc.oneof(
    fc.record({ type: fc.constant('scope'), actions: fc.subarray(['a', 'b', 'c', 'd']) }),
    fc.record({ type: fc.constant('resource'), prefix: fc.constantFrom('/', '/x', '/x/y') }),
    fc.record({ type: fc.constant('max_amount'), max: fc.integer({ min: 0, max: 1000 }) }),
    fc.record({ type: fc.constant('expires'), at: fc.integer({ min: 0, max: 1e6 }) }),
    fc.record({ type: fc.constant('audience'), domains: fc.subarray(['d1', 'd2', 'd3']) }),
    fc.record({ type: fc.constant('max_hops'), n: fc.integer({ min: 1, max: 9 }) }),
  );
  it('appending caveats never widens any component of the effective authority', () => {
    fc.assert(
      fc.property(fc.array(caveat, { maxLength: 6 }), fc.array(caveat, { maxLength: 6 }), (parent, extra) => {
        const p = effectiveAuthority(parent as never);
        const c = effectiveAuthority([...parent, ...extra] as never);
        if ('error' in p || 'error' in c) throw new Error('well-formed caveats must not error');
        if (p.actions) expect(c.actions!.every((x) => p.actions!.includes(x))).toBe(true);
        if (p.audience) expect(c.audience!.every((x) => p.audience!.includes(x))).toBe(true);
        for (const k of ['maxAmount', 'expiresAt', 'maxHops'] as const) if (p[k] !== undefined) expect(c[k]!).toBeLessThanOrEqual(p[k]!);
        expect(p.prefixes.every((x) => c.prefixes.includes(x))).toBe(true);
      }),
      { numRuns: 300, seed: 3 },
    );
  });
  it('an unknown or malformed caveat is an error, never silently ignored', () => {
    for (const c of [{ type: 'nope' }, { type: 'scope', actions: 'a' }, { type: 'scope', actions: [1] }, { type: 'resource', prefix: 3 }, { type: 'max_amount', max: Number.NaN }, { type: 'expires', at: '1' }, { type: 'audience', domains: null }, { type: 'max_hops', n: Infinity }]) {
      expect(effectiveAuthority([c as never]), JSON.stringify(c)).toHaveProperty('error');
    }
    expect(effectiveAuthority([{ type: 'nope' } as never])).toEqual({ error: 'unknown caveat type "nope" (fail closed)' });
  });
  it('the trust anchors are required, with exact reasons', () => {
    const ex = buildMeshExample();
    const reason = (patch: object) => verifyMeshProof(ex.proof, { ...ex.trust, ...patch } as never).reason;
    expect(reason({ allowedDomains: [] })).toBe('invalid trust configuration: allowedDomains is required');
    expect(reason({ allowedDomains: undefined })).toBe('invalid trust configuration: allowedDomains is required');
    expect(reason({ rootDomain: 'org-elsewhere' })).toBe('invalid trust configuration: rootDomain is required and must be in allowedDomains');
    expect(reason({ witnesses: ['w', 'w', 'w'], threshold: 2 })).toBe('invalid trust configuration: threshold');
    expect(reason({ threshold: 0 })).toBe('invalid trust configuration: threshold');
    expect(reason({ now: Number.NaN })).toBe('invalid trust configuration: now');
    expect(verifyMeshProof(ex.proof, ex.trust).ok).toBe(true);
  });
  it('a domain that is not allowed vouches for nothing, even with valid evidence', () => {
    const ex = buildMeshExample();
    const v = verifyMeshProof(ex.proof, { ...ex.trust, allowedDomains: ex.trust.allowedDomains.filter((d) => d !== ex.domains.B.id) });
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('issuing domain not allowed by policy');
    expect(v.hop).toBe(2);
  });
});

const PINNED_DIGEST = '7pXXVTal7F5wMK-5cQUaN4e4zz0m3SF5wrv19iK6BBQ';
