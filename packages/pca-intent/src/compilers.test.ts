import { describe, expect, it } from 'vitest';
import type { Caveat, Condition, Predicate } from '@atlasauth/pca';
import {
  admitter,
  analyzeDisagreement,
  capturedSlotsCompiler,
  cellRep,
  committeeAnchors,
  compileAndCompare,
  createLearner,
  elicit,
  fixedCompiler,
  nlFacadeCompiler,
  panelFlags,
  parseSlotsJSON,
  runCompilers,
  slotsCompiler,
  type CompilerOutput,
  type IntentSlots,
} from './index';

const AMT = 'action.params.amount';
const RCP = 'action.params.recipient';
const refund = (max: number, extra: Condition[] = []): { predicates: Predicate[]; caveats: Caveat[] } => ({ predicates: [{ verb: 'stripe.refund', resource: '*', where: [{ field: AMT, op: 'gte', value: 0 }, { field: AMT, op: 'lte', value: max }, ...extra] }], caveats: [] });
const out = (id: string, family: string, policy: ReturnType<typeof refund>): CompilerOutput => ({ compiler: id, family, policy, notes: [] });

describe('slot grounding (the LLM output is never trusted)', () => {
  it('keeps catalog verbs and well-formed constraints, reports everything it drops', () => {
    const raw = 'Sure! ```json {"verbs":["stripe.refund","stripe.teleport"],"constraints":[{"path":"action.params.amount","max":200},{"path":"__proto__.x","max":1},{"path":"action.params.recipient","oneOf":["alice"]},{"verb":"stripe.payout","path":"action.params.amount","max":5},{"path":"env.hour","max":1.5}]} ```';
    const { slots, notes } = parseSlotsJSON(raw);
    expect(slots).toEqual({ verbs: ['stripe.refund'], constraints: [{ path: AMT, max: 200 }, { path: RCP, oneOf: ['alice'] }] });
    expect(notes.join('|')).toMatch(/stripe\.teleport/);
    expect(notes.join('|')).toMatch(/__proto__/);
    expect(notes.join('|')).toMatch(/ungranted verb/);
    expect(notes.join('|')).toMatch(/non-integer max/);
  });
  it('never throws on garbage', () => {
    expect(parseSlotsJSON('not json').slots).toEqual({ verbs: [], constraints: [] });
    expect(parseSlotsJSON('[1,2]').slots).toEqual({ verbs: [], constraints: [] });
  });
});

describe('compilers over nl.ts and the slot vocabulary', () => {
  it('nlFacadeCompiler runs the real nl.ts grounding + compilePolicy on a deterministic completion', async () => {
    const c = nlFacadeCompiler({ id: 'det-a', family: 'rule', complete: () => '{"permissions":{"stripe":["refund","teleport"]},"limits":{"refund":"$200"}}' });
    const [o] = await runCompilers({ text: 'Refund up to $200.' }, [c]);
    expect(o!.notes).toContain('unknown verb dropped: stripe.teleport');
    const a = admitter(o!.policy);
    const vs = { verb: 'stripe.refund', reversibility: 'rate_limited' as const, weight: 1, dims: [] };
    expect(a.admits(vs, { verb: 'stripe.refund', values: { [AMT]: 200 } })).toBe(true);
    expect(a.admits(vs, { verb: 'stripe.refund', values: { [AMT]: 201 } })).toBe(false);
  });
  it('a compiler that throws contributes an empty grant and a note', async () => {
    const bad = slotsCompiler({ id: 'boom', family: 'x', complete: () => { throw new Error('rate limited'); } });
    const [o] = await runCompilers({ text: 't' }, [bad]);
    expect(o!.policy.predicates).toEqual([]);
    expect(o!.notes[0]).toMatch(/rate limited/);
  });
});

describe('structural disagreement → Ω cuts and maximal-disagreement questions (§4.2a)', () => {
  const outputs = [out('a', 'f1', refund(200)), out('b', 'f2', refund(500)), out('c', 'f3', refund(200))];
  const r = analyzeDisagreement(outputs);
  it('every reading\'s literals become cuts of Ω', () => {
    expect(r.omega.verbs[0]!.dims[0]).toMatchObject({ path: AMT, cuts: [0, 200, 500] });
  });
  it('pairwise equivalence is exact, with a concrete counterexample', () => {
    const ab = r.pairs.find((p) => p.a === 'a' && p.b === 'b')!;
    expect(ab.equivalent).toBe(false);
    expect(ab.counterexample).toBeDefined();
    expect(ab.claimDiff.map((d) => d.kind)).toContain('tighter');
    expect(r.pairs.find((p) => p.a === 'a' && p.b === 'c')!.equivalent).toBe(true);
    expect(r.unanimous).toBe(false);
    expect(panelFlags(r)).toBe(true);
    expect(r.families).toEqual(['f1', 'f2', 'f3']);
  });
  it('the questions are exactly the split cells, i.e. amounts in (200, 500]', () => {
    const vs = r.omega.verbs[0]!;
    expect(r.questions.length).toBeGreaterThan(0);
    for (const q of r.questions) {
      const x = cellRep(vs, q.cell).values[AMT] as number;
      expect(x > 200 && x <= 500).toBe(true);
      expect(q.vote).toBeCloseTo(1 / 3, 12);
      expect(q.reasons).toEqual(['committee']);
    }
    expect(r.disagreementMass).toBeGreaterThan(0);
  });
  it('a unanimous panel that contradicts the slots still produces back-translation questions', () => {
    const slots: IntentSlots = { verbs: ['stripe.refund'], constraints: [{ path: AMT, max: 200 }, { path: RCP, oneOf: ['alice'] }] };
    const u = analyzeDisagreement([out('a', 'f1', refund(200)), out('b', 'f2', refund(200))], { slots });
    expect(u.unanimous).toBe(true);
    expect(u.backTranslation.every((b) => b.diffs.some((d) => d.path === RCP))).toBe(true);
    expect(panelFlags(u)).toBe(true);
    expect(u.questions.every((q) => q.reasons.includes('back-translation'))).toBe(true);
  });
  it('a correlated misreading (all compilers agree, slots agree) is NOT flagged: the documented failure mode', () => {
    const slots: IntentSlots = { verbs: ['stripe.refund'], constraints: [{ path: AMT, max: 500 }] };
    const s = analyzeDisagreement([out('a', 'f1', refund(500)), out('b', 'f2', refund(500))], { slots });
    expect(panelFlags(s)).toBe(false);
  });
});

describe('the committee feeds the learner', () => {
  it('seed questions + mixture prior: the truth (200) is learned with the panel\'s cut available', async () => {
    const compilers = [
      fixedCompiler('lit', 'rule', () => refund(500)),
      fixedCompiler('care', 'rule', () => refund(200)),
      capturedSlotsCompiler(),
    ];
    const slots: IntentSlots = { verbs: ['stripe.refund'], constraints: [{ path: AMT, max: 500 }] };
    const rep = await compileAndCompare({ text: 'refund small amounts', slots }, compilers);
    const l = createLearner(rep.omega, { nullMass: 0.05, anchors: committeeAnchors(rep.outputs, 4) });
    const truth = admitter(refund(200));
    const vs = rep.omega.verbs[0]!;
    const res = elicit(l, (q) => (truth.admits(vs, q.outcome) ? 1 : 0), { epsRisk: 0, epsBurden: 0, maxQuestions: 30, seed: rep.questions, audit: true });
    expect(res.seedQuestions).toBeGreaterThanOrEqual(1);
    for (const x of [0, 200, 201, 500, 501]) expect(l.admitsOutcome({ verb: 'stripe.refund', values: { [AMT]: x } })).toBe(x <= 200);
  });
});
