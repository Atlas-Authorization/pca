import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical, pcactnDigest, publicKeyOf, sha256, utf8, type PCActn } from '@atlasauth/pca';
import { intentActionDigest, signIntentRequired, verifyIntentRequired, type ActionSchemaKey, type ConformResult } from '@atlasauth/pca/ext/intent';
import {
  boxesToPredicates,
  cellFromCoords,
  createLearner,
  decideVisit,
  deltaCells,
  deltaPredicates,
  intentRequiredBody,
  mintDelta,
  signedIntentRequired,
  walletCheckIntentRequired,
  type IntentLearner,
  type IntentRequiredInput,
  type Omega,
  type Outcome,
} from './index';

const seed = (l: string) => sha256(utf8(`pca-intent-jit-kill/${l}`));
const d32 = (l: string) => b64u(seed(l));
const SITE = seed('site');
const KEYS: ActionSchemaKey[] = [{ kid: 'site-1', alg: 'ed25519', pk: b64u(publicKeyOf(SITE)) }];
const NOW = 1_800_000_000_000;

// refund is listed first so that the verb under test (pay) is never the first verb of the space
const omega: Omega = {
  v: 1,
  approximate: [],
  verbs: [
    { verb: 'refund', reversibility: 'reversible', weight: 0.5, dims: [{ kind: 'num', path: 'action.params.units', lo: 0, hi: 9, cuts: [3], dist: 'uniform' }] },
    {
      verb: 'pay',
      reversibility: 'irreversible',
      weight: 0.5,
      dims: [
        { kind: 'num', path: 'action.params.amount', lo: 0, hi: 100, cuts: [20, 50, 80], dist: 'uniform' },
        { kind: 'cat', path: 'action.params.payee', values: [{ kind: 'exact', value: 'alice' }, { kind: 'exact', value: 'bob' }, { kind: 'other', value: '⊥' }] },
      ],
    },
  ],
};
const pay = omega.verbs[1]!;
const lifted: Outcome = { verb: 'pay', values: { 'action.params.amount': 30, 'action.params.payee': 'alice' } }; // cell [2, 0]
const OK: ConformResult = { ok: true, verb: { verb: 'pay', kind: 'write', params: {} } };

describe('decideVisit', () => {
  const fake = (p: number, vetoed = false) => ({ omega, isVetoed: () => vetoed, acceptance: () => p }) as unknown as IntentLearner;

  it('a schema violation carries "<code>: <reason>"', () => {
    expect(decideVisit({ learner: fake(1), lifted, conform: { ok: false, code: 'undeclared_param', reason: 'x' }, inEffective: true })).toEqual({
      kind: 'schema_violation',
      reason: 'undeclared_param: x',
    });
  });

  it('an unknown verb and a value outside the space are both "outside Ω̃"', () => {
    const outside = { kind: 'schema_violation', reason: 'the lifted action lies outside Ω̃' };
    expect(decideVisit({ learner: fake(1), lifted: { verb: 'nope', values: {} }, conform: OK, inEffective: true })).toEqual(outside);
    expect(decideVisit({ learner: fake(1), lifted: { verb: 'pay', values: { 'action.params.amount': 101, 'action.params.payee': 'alice' } }, conform: OK, inEffective: true })).toEqual(outside);
  });

  it('the cell is computed in the space of the lifted verb, not of the first verb', () => {
    expect(decideVisit({ learner: fake(1), lifted, conform: OK, inEffective: true })).toEqual({ kind: 'admit', cell: [2, 0] });
    expect(decideVisit({ learner: fake(1), lifted: { verb: 'refund', values: { 'action.params.units': 5 } }, conform: OK, inEffective: true })).toEqual({ kind: 'admit', cell: [2] });
  });

  it('every ceiling is asked with (space, lifted outcome); one that admits does not deny, one that refuses does', () => {
    const seen: [string, Outcome][] = [];
    const yes = (vs: { verb: string }, o: Outcome) => (seen.push([vs.verb, o]), true);
    expect(decideVisit({ learner: fake(1), lifted, conform: OK, ceilings: [yes, yes], inEffective: true })).toEqual({ kind: 'admit', cell: [2, 0] });
    expect(seen).toEqual([['pay', lifted], ['pay', lifted]]);
    expect(decideVisit({ learner: fake(1), lifted, conform: OK, ceilings: [yes, () => false], inEffective: true })).toEqual({ kind: 'ceiling' });
  });

  it('a vetoed cell, or one with p = 0, is denied even inside the effective grant', () => {
    expect(decideVisit({ learner: fake(0.9, true), lifted, conform: OK, inEffective: true })).toEqual({ kind: 'intent_denied', vetoed: true });
    expect(decideVisit({ learner: fake(0), lifted, conform: OK, inEffective: true })).toEqual({ kind: 'intent_denied', vetoed: false });
    expect(decideVisit({ learner: fake(0.01), lifted, conform: OK, inEffective: false })).toEqual({ kind: 'intent_required', cell: [2, 0], p: 0.01 });
  });

  it('outside the effective grant, an uncertain cell asks one question about it', () => {
    expect(decideVisit({ learner: fake(0.3), lifted, conform: OK, inEffective: false })).toEqual({ kind: 'intent_required', cell: [2, 0], p: 0.3 });
  });
});

describe('cellFromCoords', () => {
  const amount = 'action.params.amount';
  const payee = 'action.params.payee';
  it('maps coordinates back to indices', () => {
    expect(cellFromCoords(pay, { [amount]: [2, 2], [payee]: ['alice'] })).toEqual([2, 0]);
    expect(cellFromCoords(pay, { [amount]: [0, 0], [payee]: ['bob'] })).toEqual([0, 1]);
  });
  it('a missing path (same number of keys) is refused, not dereferenced', () => {
    expect(cellFromCoords(pay, { [amount]: [2, 2], other: ['alice'] })).toBeNull();
  });
  it('a numeric dimension needs a single numeric index [i, i]', () => {
    expect(cellFromCoords(pay, { [amount]: [2, 3], [payee]: ['alice'] })).toBeNull();
    expect(cellFromCoords(pay, { [amount]: ['a', 'a'] as unknown as [number, number], [payee]: ['alice'] })).toBeNull();
  });
  it('a categorical dimension needs exactly one known value', () => {
    expect(cellFromCoords(pay, { [amount]: [2, 2], [payee]: ['alice', 'bob'] })).toBeNull();
    expect(cellFromCoords(pay, { [amount]: [2, 2], [payee]: [] })).toBeNull();
    expect(cellFromCoords(pay, { [amount]: [2, 2], [payee]: ['zed'] })).toBeNull();
  });
});

describe('the site intent_required body and the wallet check', () => {
  const pcactn = (extra: Record<string, unknown> = {}): PCActn =>
    ({ id: 'a1', action: { verb: 'pay', resource: 'acct/1', params_digest: d32('params'), reversibility_class: 'irreversible' }, ...extra }) as unknown as PCActn;
  const input = (over: Partial<IntentRequiredInput> = {}): IntentRequiredInput => ({
    session: d32('session'),
    mapDigest: d32('map'),
    schemaDigest: d32('schema'),
    pcactn: pcactn(),
    vs: pay,
    cell: [2, 0],
    questionId: 'q1',
    friction: 'tap',
    deliveredTo: 'wallet',
    expiresAt: NOW + 1000,
    ...over,
  });
  const wallet = (over: Partial<Parameters<typeof walletCheckIntentRequired>[1]> = {}): Parameters<typeof walletCheckIntentRequired>[1] => ({ keys: KEYS, now: NOW, session: d32('session'), mapDigest: d32('map'), omegaTilde: omega, lifted, pcactn: pcactn(), ...over });
  const sign = (body: ReturnType<typeof intentRequiredBody>) => signIntentRequired(body, 'site-1', SITE);
  const refused = (reason: string) => ({ ok: false, reason });

  it('the body carries every member, the digests of the PCActn and its action, and the cell as coordinates', () => {
    expect(intentRequiredBody(input())).toEqual({
      v: 1,
      kind: 'pca-intent-required',
      session: d32('session'),
      map_digest: d32('map'),
      schema: d32('schema'),
      pcactn_digest: hashCanonical(pcactn()),
      action_digest: intentActionDigest(pcactn().action),
      cell: { verb: 'pay', coords: { 'action.params.amount': [2, 2], 'action.params.payee': ['alice'] } },
      reason: 'uncertain',
      question_id: 'q1',
      friction: 'tap',
      delivered_to: 'wallet',
      expires_at: NOW + 1000,
    });
  });

  it('signedIntentRequired signs that body under the given key id and the signature verifies', () => {
    const s = signedIntentRequired(input(), 'site-1', SITE);
    expect(s).toMatchObject(intentRequiredBody(input()));
    expect(s.sig.kid).toBe('site-1');
    expect(s.sig.alg).toBe('ed25519');
    expect(verifyIntentRequired(s, KEYS, NOW)).toEqual({ ok: true });
  });

  it('a correct question is accepted and the wallet\'s own space and cell are returned', () => {
    expect(walletCheckIntentRequired(signedIntentRequired(input(), 'site-1', SITE), wallet())).toEqual({ ok: true, vs: pay, cell: [2, 0] });
  });

  it('the failure of the signature or expiry check is returned as is', () => {
    const s = signedIntentRequired(input(), 'site-1', SITE);
    expect(walletCheckIntentRequired(s, wallet({ now: NOW + 1001 }))).toEqual(refused('the question has expired'));
    expect(walletCheckIntentRequired({ ...s, question_id: 'q2' }, wallet())).toEqual(refused('site signature invalid'));
  });

  it('a question for another session, or for another map, is refused (each on its own)', () => {
    const s = signedIntentRequired(input(), 'site-1', SITE);
    const msg = refused('the question is for another session or map');
    expect(walletCheckIntentRequired(s, wallet({ session: d32('other') }))).toEqual(msg);
    expect(walletCheckIntentRequired(s, wallet({ mapDigest: d32('other') }))).toEqual(msg);
  });

  it('a question about another PCActn, or about another action digest, is refused (each on its own)', () => {
    const msg = refused('the question is about another action');
    // another PCActn with the same action: only the PCActn digest differs
    expect(walletCheckIntentRequired(signedIntentRequired(input(), 'site-1', SITE), wallet({ pcactn: pcactn({ id: 'a2' }) }))).toEqual(msg);
    // the same PCActn, a body whose action digest is for another action: only the action digest differs
    const body = intentRequiredBody(input());
    const other = sign({ ...body, action_digest: intentActionDigest({ ...pcactn().action, verb: 'refund' }) });
    expect(other.pcactn_digest).toBe(pcactnDigest(pcactn()));
    expect(walletCheckIntentRequired(other, wallet())).toEqual(msg);
  });

  it('the wallet refuses a question it cannot place in its own space', () => {
    const msg = refused('the wallet cannot place the action in Ω̃');
    const s = signedIntentRequired(input(), 'site-1', SITE);
    expect(walletCheckIntentRequired(s, wallet({ lifted: { verb: 'nope', values: {} } }))).toEqual(msg);
    expect(walletCheckIntentRequired(s, wallet({ lifted: { verb: 'pay', values: { 'action.params.amount': 101, 'action.params.payee': 'alice' } } }))).toEqual(msg);
    // the site names another verb than the one the wallet lifted
    expect(walletCheckIntentRequired(signedIntentRequired(input({ vs: { ...pay, verb: 'refund' } }), 'site-1', SITE), wallet())).toEqual(msg);
  });

  it('the wallet refuses a question whose cell differs from the cell it derives, in any one coordinate', () => {
    const msg = refused('the site cell differs from the cell the wallet derives');
    // the site cell is a different payee only
    expect(walletCheckIntentRequired(signedIntentRequired(input({ cell: [2, 1] }), 'site-1', SITE), wallet())).toEqual(msg);
    // the site cell is a different amount range only
    expect(walletCheckIntentRequired(signedIntentRequired(input({ cell: [1, 0] }), 'site-1', SITE), wallet())).toEqual(msg);
    // coordinates that name no cell of the space
    const body = intentRequiredBody(input());
    const unknown = sign({ ...body, cell: { verb: 'pay', coords: { 'action.params.amount': [2, 2], 'action.params.payee': ['zed'] } } });
    expect(walletCheckIntentRequired(unknown, wallet())).toEqual(msg);
  });
});

describe('delta grants', () => {
  const fresh = () => createLearner(omega, { eta: 0, tau: 1 });
  const yes = (l: IntentLearner, o: Outcome) => l.observe(o, 1);

  it('deltaCells lists only verbs that gained a cell, with exactly the new cells', () => {
    const prev = fresh();
    const next = fresh();
    yes(next, lifted);
    const d = deltaCells(prev, next);
    expect([...d.keys()]).toEqual(['pay']);
    const flags = [...d.get('pay')!];
    expect(flags).toHaveLength(21);
    expect(flags.map((x, i) => (x ? i : -1)).filter((i) => i >= 0)).toEqual([6]); // cell [2, 0] of pay
    // the other verb gaining a cell does not list pay, and nothing new lists nothing
    const refund = fresh();
    yes(refund, { verb: 'refund', values: { 'action.params.units': 5 } });
    const dr = deltaCells(prev, refund);
    expect([...dr.keys()]).toEqual(['refund']);
    expect([...dr.get('refund')!]).toEqual([0, 0, 1]);
    expect([...deltaCells(next, next).keys()]).toEqual([]);
  });

  it('deltaPredicates holds the boxes of the verbs in the delta and nothing for the others', () => {
    const next = fresh();
    yes(next, lifted);
    const d = deltaCells(fresh(), next);
    expect(deltaPredicates(omega, d)).toEqual(boxesToPredicates(pay, d.get('pay')!));
    expect(deltaPredicates(omega, d)).toEqual([
      {
        verb: 'pay',
        resource: '*',
        where: [
          { field: 'action.params.amount', op: 'gte', value: 21 },
          { field: 'action.params.amount', op: 'lte', value: 49 },
          { field: 'action.params.payee', op: 'eq', value: 'alice' },
        ],
      },
    ]);
    expect(deltaPredicates(omega, new Map())).toEqual([]);
  });

  describe('mintDelta checks the previous grant id it is given', () => {
    const principal = seed('principal');
    const args = (prev?: string) => ({
      principalSecret: principal,
      principalPublic: b64u(publicKeyOf(principal)),
      holder: b64u(publicKeyOf(seed('agent'))),
      session: d32('s'),
      seq: 1,
      root: d32('root'),
      mapDigest: d32('m1'),
      prevGrant: { id: d32('g0') } as Parameters<typeof mintDelta>[2]['prevGrant'],
      salt: 's1',
      ...(prev !== undefined ? { prev } : {}),
    });
    const learners = () => {
      const next = fresh();
      yes(next, lifted);
      return [fresh(), next] as const;
    };

    it('a prev that is not the id of the previous grant is refused', () => {
      const [prev, next] = learners();
      expect(() => mintDelta(prev, next, args(d32('elsewhere')))).toThrow(new Error('mintDelta: prev must be the id of the previous session grant'));
    });
    it('a prev equal to the id of the previous grant, or none, is accepted and chains to that id', () => {
      const [prev, next] = learners();
      for (const a of [args(d32('g0')), args()]) {
        const m = mintDelta(prev, next, a)!;
        expect(m.cells).toBe(1);
        expect(m.grant.caveats.find((c) => c.type === 'intent_session')).toMatchObject({ prev: d32('g0') });
      }
    });
    it('no new cell mints nothing, even with a wrong prev', () => {
      const [, next] = learners();
      expect(mintDelta(next, next, args(d32('elsewhere')))).toBeNull();
    });
  });
});
