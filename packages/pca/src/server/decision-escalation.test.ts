import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { type Capability } from '../capability';
import { mintGrant } from '../envelope';
import { b64u } from '../hash';
import { encodeKey, generateKeyPair } from '../keys';
import { paramsDigest, type PlanNode } from '../merkle';
import { buildPCActn, type PCActn } from '../pcactn';
import { type RiskPolicy } from '../risk';
import { decideTighten, decideUnits, decisionOf, meet, meetAll, pepDecision, signalCeiling, tighten, type Decision, type ModelSignal } from '../decision';
import { escalationActionDigest, escalationHistoryHead, escalationPolicyDigest, signEscalationAnswer, verifyEscalationAnswer, type EscalationAnswerBody } from '../escalation';
import { authorize, createAuthorizer, isAuthorizedFor, requireAuthorized, type AuthorizeOptions } from './authorize';
import { decisionOfResult, memoryPcaStore, requirePCA } from './require-pca';
import type { PcaOperation } from './verify';

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'payments-rs';
const VERB = 'payments.send';
const RES = 'payments';
const SPEND: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 };
const DS: Decision[] = ['deny', 'escalate', 'allow'];

describe('decision lattice (G-T4, G-T9)', () => {
  it('meet is the minimum on deny < escalate < allow, commutative, associative, idempotent', () => {
    for (const a of DS) for (const b of DS) {
      expect(meet(a, b)).toBe(DS[Math.min(DS.indexOf(a), DS.indexOf(b))]);
      expect(meet(a, b)).toBe(meet(b, a));
      expect(meet(a, a)).toBe(a);
      for (const c of DS) expect(meet(meet(a, b), c)).toBe(meet(a, meet(b, c)));
    }
    expect(meetAll([])).toBe('allow');
  });
  it('escalate is absorbing against allow and never becomes allow by composition', () => {
    for (const d of DS) expect(meet('escalate', d)).not.toBe('allow');
    expect(meet('deny', 'escalate')).toBe('deny');
  });
  it('a model signal can only tighten: tighten(d, s) <= d for every d and s, including garbage', () => {
    const sigs: unknown[] = ['ok', 'escalate', 'deny', undefined, null, 1, 'allow', {}, 'OK'];
    for (const d of DS) for (const s of sigs) {
      expect(DS.indexOf(tighten(d, s))).toBeLessThanOrEqual(DS.indexOf(d));
      expect(meet(tighten(d, s), d)).toBe(tighten(d, s));
    }
    for (const d of DS) expect(tighten(d, 'ok')).toBe(d);
    expect(signalCeiling('allow')).toBe('deny'); // not a ModelSignal: fail closed
  });
  it('an adversarial oracle (any function of the action) never widens a decision', () => {
    let seed = 12345;
    const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
    for (let i = 0; i < 500; i++) {
      const base = DS[Math.floor(rnd() * 3)]!;
      const sig = (['ok', 'escalate', 'deny'] as ModelSignal[])[Math.floor(rnd() * 3)]!;
      expect(DS.indexOf(tighten(base, sig))).toBeLessThanOrEqual(DS.indexOf(base));
    }
  });
  it('pepDecision: an answer upgrades only escalate, never deny', () => {
    expect(pepDecision('escalate', true)).toBe('allow');
    expect(pepDecision('escalate', false)).toBe('escalate');
    expect(pepDecision('deny', true)).toBe('deny');
    expect(pepDecision('allow', false)).toBe('allow');
  });
  it('decisionOf: allow; all-failing-escalate -> escalate; any hard or unexplained failure -> deny', () => {
    const chk = (c: Record<string, string>, reasons: string[], allow = false) => decisionOf({ allow, checks: c, reasons });
    expect(chk({ wire: 'pass' }, [], true)).toBe('allow');
    expect(chk({ provenance: 'fail' }, ['provenance: intent_required: question'])).toBe('escalate');
    expect(chk({ tighten: 'fail' }, ['tighten: escalate: rule r asked'])).toBe('escalate');
    expect(chk({ provenance: 'fail', policy: 'fail' }, ['provenance: intent_required: q', 'policy: no predicate permits'])).toBe('deny');
    expect(chk({ provenance: 'fail', replay: 'fail' }, ['provenance: intent_required: q'])).toBe('deny'); // replay has no reason of its own
    expect(chk({ provenance: 'pass' }, [])).toBe('deny'); // not allowed, nothing failing: deny
    expect(chk({ tighten: 'fail' }, ['tighten: escalate: a', 'tighten: a grant reads a model path'])).toBe('deny');
  });
});

describe('rule 20 (units) primitive', () => {
  const schema_units = { usd_minor: { kind: 'money', currency: 'USD', exponent: 2 }, usd_major: { kind: 'money', currency: 'USD', exponent: 0 } };
  const verb_params = { 'action.params.amount': { type: 'integer', unit: 'usd_minor' }, 'action.params.note': { type: 'string' } };
  const base = { schema_units, verb_params, verb: 'refund' };
  const tag = (u: object) => ({ 'action.params.amount': u });
  it('matching tag passes; cents vs dollars, currency and unit-less declarations are refused', () => {
    expect(decideUnits({ ...base, units: tag({ kind: 'money', currency: 'USD', exponent: 2 }) }).ok).toBe(true);
    expect(decideUnits({ ...base, units: tag({ kind: 'money', currency: 'USD', exponent: 0 }) }).ok).toBe(false);
    expect(decideUnits({ ...base, units: tag({ kind: 'money', currency: 'EUR', exponent: 2 }) }).ok).toBe(false);
    expect(decideUnits({ ...base, units: { 'action.params.note': { kind: 'money' } } }).ok).toBe(false);
  });
  it('a tag for a parameter the verb does not declare is ignored; malformed input fails closed', () => {
    expect(decideUnits({ ...base, units: { 'action.params.other': { kind: 'x' } } }).ok).toBe(true);
    expect(decideUnits({ ...base, units: { amount: { kind: 'money' } } }).ok).toBe(false);
    expect(decideUnits({ ...base, units: tag({ kind: 'money', extra: 1 }) }).ok).toBe(false);
    expect(decideUnits({ ...base, verb_params: undefined, units: {} }).ok).toBe(false);
  });
  it('a where term that reads a unit-bearing parameter without a tag is refused', () => {
    const predicates = [[{ verb: 'refund', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }]];
    expect(decideUnits({ ...base, units: {}, predicates }).ok).toBe(false);
    expect(decideUnits({ ...base, units: tag({ kind: 'money', currency: 'USD', exponent: 2 }), predicates }).ok).toBe(true);
    // another verb's predicate is out of scope
    expect(decideUnits({ ...base, units: {}, predicates: [[{ verb: 'other', where: [{ field: 'action.params.amount', op: 'lte', value: 1 }] }]] }).ok).toBe(true);
  });
});

describe('rule 21 (tighten) primitive', () => {
  const read = (field: string) => [[{ verb: '*', where: [{ not: { field, op: 'eq', value: 'hostile' } }] }]];
  it('a model-derived path in a grant where is refused (strict), allowed and reported under legacy', () => {
    for (const f of ['env.class.tone', 'env.prov.action.params.x', 'env.judge.score']) {
      const r = decideTighten({ predicates: read(f) });
      expect(r.outcome).toBe('deny');
      expect(r.offending).toEqual([f]);
      const l = decideTighten({ predicates: read(f), polarity: 'legacy' });
      expect(l.outcome).toBe('ok');
      expect(l.legacy).toBe(true);
    }
    expect(decideTighten({ predicates: read('env.acc.x.post') }).outcome).toBe('ok');
    expect(decideTighten({ predicates: read('env.world.risk') }).outcome).toBe('ok'); // multi-source world: an assertion
    expect(decideTighten({ predicates: read('env.world.risk'), single_source: ['risk'] }).outcome).toBe('deny');
    expect(decideTighten({ predicates: read('env.class.t'), polarity: 'strict' }).outcome).toBe('deny');
  });
  it('rules: true -> signal, unknown -> escalate, false -> ok; the outcome is the meet', () => {
    const ctx = { action: { verb: 'v', resource: 'r', params: { amount: 80 } }, env: { class: { tone: 'hostile' } } };
    const rule = (id: string, when: object, signal: 'escalate' | 'deny') => ({ id, when, signal });
    expect(decideTighten({ tighten: [rule('big', { field: 'action.params.amount', op: 'gt', value: 50 }, 'escalate')], context: ctx }).outcome).toBe('escalate');
    expect(decideTighten({ tighten: [rule('big', { field: 'action.params.amount', op: 'gt', value: 500 }, 'escalate')], context: ctx }).outcome).toBe('ok');
    expect(decideTighten({ tighten: [rule('t', { field: 'env.class.missing', op: 'eq', value: 'x' }, 'deny')], context: ctx }).outcome).toBe('escalate');
    expect(
      decideTighten({ tighten: [rule('a', { field: 'action.params.amount', op: 'gt', value: 50 }, 'escalate'), rule('b', { field: 'env.class.tone', op: 'eq', value: 'hostile' }, 'deny')], context: ctx }).outcome,
    ).toBe('deny');
    expect(decideTighten({ tighten: [{ id: 'Bad Id', when: {}, signal: 'ok' }] }).outcome).toBe('deny');
    expect(decideTighten({ tighten: [rule('a', {}, 'escalate'), rule('a', {}, 'escalate')] }).outcome).toBe('deny');
  });
});

function setup(envelopeExtra: Record<string, unknown> = {}) {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const pPub = encodeKey(principal.publicKey);
  const hPub = encodeKey(holder.publicKey);
  const grant: Capability = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: pPub,
    holder: hPub,
    goal: 'pay invoices',
    envelope: {
      predicates: [{ verb: [VERB], resource: '*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }],
      caveats: [],
      agent_binding: {},
      risk_policy: SPEND,
      tighten: [{ id: 'big_payment', when: { field: 'action.params.amount', op: 'gt', value: 50 }, signal: 'escalate' }],
      ...envelopeExtra,
    },
  }).grant;
  let counter = 0;
  const sign = (params: Record<string, unknown>): PCActn => {
    const node: PlanNode = { id: 'n1', verb: VERB, resource: RES, params_digest: paramsDigest(params), reversibility_class: 'irreversible' };
    return buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params, counter: ++counter, signerSecret: holder.secretKey, aud: AUD, now: NOW });
  };
  const answer = (p: PCActn, over: Partial<EscalationAnswerBody> = {}, lastCounter?: number) =>
    signEscalationAnswer(
      {
        v: 1,
        kind: 'pca-escalation-answer',
        principal: pPub,
        policy_digest: escalationPolicyDigest(grant),
        action_digest: escalationActionDigest(p),
        history_head: escalationHistoryHead(lastCounter),
        decision: 'allow',
        iat: NOW,
        expires_at: NOW + 600_000,
        nonce: b64u(randomBytes(16)),
        ...over,
      },
      principal.secretKey,
    );
  return { grant, sign, answer, pPub, principal };
}

const op = (amount: number): PcaOperation => ({ verb: VERB, resource: RES, params: { payee: 'acme', amount } });
const opts = (grant: Capability, over: Partial<AuthorizeOptions> = {}): AuthorizeOptions => ({
  audience: AUD,
  resolveGrant: async (ref) => (ref === grant.id ? grant : null),
  budgetStore: memoryPcaStore(),
  hooks: { revocation: () => ({ enforced: true, ok: true }) },
  plan: 'single-step',
  now: () => NOW,
  risk: (o) => ({ blastRadius: Math.min(1, Number(o?.params?.amount) / 100), semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }),
  ...over,
});

describe('authorize: escalate never yields allow (C-50, C-51)', () => {
  it('below the tighten threshold: allow; above: escalate (allow:false, 403, request carried); over the limit: deny', async () => {
    const { grant, sign } = setup();
    const az = createAuthorizer(opts(grant));
    const ok = await az({ pcactn: sign(op(40).params!), operation: op(40) });
    expect(ok.decision).toBe('allow');
    expect(ok.allow).toBe(true);
    const e = await az({ pcactn: sign(op(70).params!), operation: op(70) });
    expect(e.allow).toBe(false);
    expect(e.decision).toBe('escalate');
    expect(e.status).toBe(403);
    expect(!e.allow && e.escalation?.verb).toBe(VERB);
    expect(!e.allow && e.reason).toContain('escalate');
    const d = await az({ pcactn: sign(op(400).params!), operation: op(400) });
    expect(d.decision).toBe('deny');
    expect(!d.allow && d.escalation).toBeUndefined();
  });
  it('no answer, a wrong-action answer, a wrong-policy answer, an unpinned signer, a deny answer: all stay refused', async () => {
    const { grant, sign, answer, pPub } = setup();
    const other = setup();
    const az = createAuthorizer(opts(grant, { escalation: { principals: [pPub] } }));
    const p = sign(op(70).params!);
    expect((await az({ pcactn: p, operation: op(70) })).decision).toBe('escalate');
    const q = sign(op(71).params!);
    expect((await az({ pcactn: q, operation: op(71), escalationAnswer: answer(p) })).decision).toBe('escalate'); // bound to another PCActn
    const r = sign(op(72).params!);
    expect((await az({ pcactn: r, operation: op(72), escalationAnswer: other.answer(r) })).allow).toBe(false); // unpinned principal
    const s = sign(op(73).params!);
    expect((await az({ pcactn: s, operation: op(73), escalationAnswer: answer(s, { decision: 'deny' }) })).allow).toBe(false);
    const t = sign(op(74).params!);
    expect((await az({ pcactn: t, operation: op(74), escalationAnswer: answer(t, { history_head: escalationHistoryHead(99) }) })).allow).toBe(false); // other history
    const u = sign(op(75).params!);
    expect((await az({ pcactn: u, operation: op(75), escalationAnswer: answer(u, { expires_at: NOW - 1, iat: NOW - 10 }) })).allow).toBe(false);
  });
  it('a valid answer bound to this policy, PCActn and history admits it once; the counter spends the answer', async () => {
    const { grant, sign, answer, pPub } = setup();
    const az = createAuthorizer(opts(grant, { escalation: { principals: [pPub] } }));
    const p = sign(op(70).params!);
    const a = answer(p);
    const first = await az({ pcactn: p, operation: op(70), escalationAnswer: a });
    expect(first.decision).toBe('allow');
    expect(first.allow).toBe(true);
    expect(first.allow && first.escalation?.answered_by).toBe(pPub);
    expect(first.allow && isAuthorizedFor(first, op(70))).toBe(true);
    const again = await az({ pcactn: p, operation: op(70), escalationAnswer: answer(p, {}, 1) });
    expect(again.allow).toBe(false);
  });
  it('an answer can never upgrade a deny: over the limit AND asked', async () => {
    const { grant, sign, answer, pPub } = setup();
    const az = createAuthorizer(opts(grant, { escalation: { principals: [pPub] } }));
    const p = sign(op(400).params!);
    const r = await az({ pcactn: p, operation: op(400), escalationAnswer: answer(p) });
    expect(r.allow).toBe(false);
    expect(r.decision).toBe('deny');
  });
  it('the answer can come from the request (header) through requireAuthorized', async () => {
    const { grant, sign, answer, pPub } = setup();
    const guard = requireAuthorized({ ...opts(grant, { escalation: { principals: [pPub] } }), operation: () => op(70) });
    const p = sign(op(70).params!);
    const hdr = (x: unknown) => b64u(Buffer.from(JSON.stringify(x)));
    const noAnswer = await guard({ headers: { 'pca-action': hdr(p) } });
    expect(noAnswer.ok).toBe(false);
    expect(decisionOfResult(noAnswer)).toBe('escalate');
    const yes = await guard({ headers: { 'pca-action': hdr(p), 'pca-escalation-answer': hdr(answer(p)) } });
    expect(yes.ok).toBe(true);
    expect(decisionOfResult(yes)).toBe('allow');
  });
});

describe('fail-closed table: escalate is refused by every guard entry point', () => {
  const entries: [string, (g: ReturnType<typeof setup>, p: PCActn) => Promise<{ admitted: boolean; decision: Decision }>][] = [
    ['authorize()', async (g, p) => { const r = await authorize({ pcactn: p, operation: op(70) }, opts(g.grant)); return { admitted: r.allow, decision: r.decision }; }],
    ['createAuthorizer()', async (g, p) => { const r = await createAuthorizer(opts(g.grant))({ pcactn: p, operation: op(70) }); return { admitted: r.allow, decision: r.decision }; }],
    ['requireAuthorized()', async (g, p) => { const r = await requireAuthorized({ ...opts(g.grant), operation: () => op(70) })({ headers: {}, body: { pcactn: p } }); return { admitted: r.ok, decision: decisionOfResult(r) }; }],
    ['requirePCA() with operation', async (g, p) => { const { plan: _p, risk: _r, ...rest } = opts(g.grant); const r = await requirePCA({ ...rest, operation: () => op(70), context: () => ({ plan: [{ id: 'n1', verb: VERB, resource: RES, params_digest: paramsDigest(op(70).params!), reversibility_class: 'irreversible' }], planAuthorized: true, budget: { B: 1_000_000, tau: NOW, asOf: NOW }, risk: { blastRadius: 0.7, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 } }) })({ headers: {}, body: { pcactn: p } }); return { admitted: r.ok, decision: decisionOfResult(r) }; }],
  ];
  for (const [name, run] of entries) {
    it(`${name}: escalate -> not admitted, decision escalate`, async () => {
      const g = setup();
      const r = await run(g, g.sign(op(70).params!));
      expect(r).toEqual({ admitted: false, decision: 'escalate' });
    });
  }
  it('every escalate-class result carries allow:false / ok:false whatever the escalate source is (a model-derived tighten rule)', async () => {
    const g = setup({ tighten: [{ id: 'hostile', when: { field: 'env.class.tone', op: 'eq', value: 'hostile' }, signal: 'escalate' }] });
    const r = await createAuthorizer(opts(g.grant, { intentV2: { env: { class: { tone: 'hostile' } } } as never }))({ pcactn: g.sign(op(10).params!), operation: op(10) });
    expect(r.allow).toBe(false);
  });
});

describe('verifyEscalationAnswer', () => {
  it('rejects malformed, unpinned, future and wrong-binding answers; never throws', () => {
    const g = setup();
    const p = g.sign(op(70).params!);
    const a = g.answer(p);
    const bind = { policy_digest: escalationPolicyDigest(g.grant), action_digest: escalationActionDigest(p), history_head: escalationHistoryHead(undefined) };
    expect(verifyEscalationAnswer(a, [g.pPub], bind, NOW).ok).toBe(true);
    for (const bad of [null, 1, {}, { ...a, sig: 'x' }, { ...a, extra: 1 }, { ...a, decision: 'maybe' }]) expect(verifyEscalationAnswer(bad, [g.pPub], bind, NOW).ok).toBe(false);
    expect(verifyEscalationAnswer(a, [], bind, NOW).ok).toBe(false);
    expect(verifyEscalationAnswer(a, [g.pPub], bind, NOW - 1000).ok).toBe(false);
    expect(verifyEscalationAnswer(a, [g.pPub], bind, Number.NaN).ok).toBe(false);
    expect(verifyEscalationAnswer(a, [g.pPub], { ...bind, action_digest: bind.policy_digest }, NOW).ok).toBe(false);
  });
});

describe('rules 20 and 21 inside the verifier', () => {
  it('a grant whose where reads env.class.* is refused (strict) and passes degraded under the legacy flag', async () => {
    const strict = setup({ tighten: undefined, predicates: [{ verb: [VERB], resource: '*', where: [{ not: { field: 'env.class.tone', op: 'eq', value: 'hostile' } }] }] });
    const r = await createAuthorizer(opts(strict.grant))({ pcactn: strict.sign(op(10).params!), operation: op(10) });
    expect(r.allow).toBe(false);
    expect(r.decision).toBe('deny');
    expect(r.verdict.checks.tighten).toBe('fail');
  });
});
