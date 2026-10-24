/**
 * r13 mutation kills for nl.ts: the exact grounding prompt, parseNLPolicy on hostile model output (null, non-object
 * members, non-string actions and limits, trailing prose after a leading brace), policyFromNL lints with an injected
 * catalog, and agentFromNL's error message and option pass-through (catalog, aud, holder, now).
 */
import { describe, expect, it } from 'vitest';
import { buildCatalog, defineAction, DEFAULT_CATALOG } from './catalog';
import { generateKeyPair } from './keys';
import { agentFromNL, nlPrompt, parseNLPolicy, policyFromNL } from './nl';

/** Run f, capturing its value or its error (name + message), so a mutant that throws fails an assertion, not an error. */
const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};
/** Async form of settle. */
const settleAsync = async <T>(f: () => Promise<T>) => {
  try {
    return { ok: true as const, value: await f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};

const CAT = buildCatalog([
  defineAction({ connector: 'bank', action: 'wire', reversibility: 'irreversible', blastRadius: 0.9, description: 'Wire money.', amountField: 'amt' }),
  defineAction({ connector: 'bank', action: 'peek', reversibility: 'reversible', blastRadius: 0.1, description: 'Look.' }),
]);

describe('nlPrompt', () => {
  it('is exactly the documented prompt over the catalog verbs', () => {
    expect(settle(() => nlPrompt('do it', CAT))).toEqual({ ok: true, value: 
      [
        'You translate an instruction into a strict JSON agent policy. Output ONLY JSON, no prose, no code fence.',
        'Shape: {"permissions":{"<connector>":["<action>",...]},"limits":{"<action-or-verb>":"$<amount>/<period>"|"<count>/<period>"}}',
        'Rules: use ONLY the verbs below (connector.action). A limit key is a bare action (e.g. "refund") or a full verb (e.g. "stripe.refund").',
        'Monetary limits start with "$"; plain numbers are counts. Periods: hour, day, week, month. Omit limits you are unsure about.',
        '',
        'Available verbs:',
        '  - bank.wire (irreversible, amount field "amt"): Wire money.\n  - bank.peek (reversible): Look.',
        '',
        'Instruction: do it',
        'JSON:',
      ].join('\n'),
     });
  });
  it('defaults to the built-in catalog', () => {
    expect(settle(() => nlPrompt('x'))).toEqual({ ok: true, value: nlPrompt('x', DEFAULT_CATALOG) });
    expect(nlPrompt('x')).toContain('  - stripe.refund (rate_limited, amount field "amount"): ');
  });
});

describe('parseNLPolicy', () => {
  const EMPTY = { permissions: {}, limits: {}, unknownVerbs: [], droppedLimits: [] };
  it('model garbage is an empty result, never a throw', () => {
    for (const raw of ['null', 'not json', '5', '"s"', '[1]', '{"limits":{}}', '{"permissions":null}', '{"permissions":{},"limits":null}', '}{']) {
      expect(settle(() => parseNLPolicy(raw, CAT))).toEqual({ ok: true, value: EMPTY });
    }
  });
  it('a leading brace followed by prose is still extracted', () => {
    expect(settle(() => parseNLPolicy('{"permissions":{"bank":["peek"]}} that is all', CAT))).toEqual({ ok: true, value: { permissions: { bank: ['peek'] }, limits: {}, unknownVerbs: [], droppedLimits: [] } });
  });
  it('drops non-string actions silently and reports unknown string verbs', () => {
    expect(settle(() => parseNLPolicy('{"permissions":{"bank":["peek",5,null,"peek","fly"],"x":"wire"}}', CAT))).toEqual({ ok: true, value: {
      permissions: { bank: ['peek'] },
      limits: {},
      unknownVerbs: ['bank.fly'],
      droppedLimits: [],
    } });
  });
  it('limits: full verb or bare action of a granted verb; others are dropped', () => {
    const out = parseNLPolicy(JSON.stringify({ permissions: { bank: ['wire'] }, limits: { 'bank.wire': '$5/day', wire: '3/day', peek: '1/day', bad: 'lots', n: 5, o: { a: 1 } } }), CAT);
    expect(out.limits).toEqual({ 'bank.wire': '$5/day', wire: '3/day' });
    expect(out.droppedLimits).toEqual(['peek', 'bad', 'n', 'o']);
  });
  it('a non-object limits member is ignored, not iterated', () => {
    expect(settle(() => parseNLPolicy('{"permissions":{"bank":["peek"]},"limits":"abc"}', CAT))).toEqual({ ok: true, value: { permissions: { bank: ['peek'] }, limits: {}, unknownVerbs: [], droppedLimits: [] } });
  });
});

describe('policyFromNL', () => {
  it('lints against the injected catalog and returns the raw text', async () => {
    const raw = '{"permissions":{"bank":["peek"]}}';
    let prompt = '';
    const r = await policyFromNL({ instruction: 'look', catalog: CAT, complete: (p) => { prompt = p; return raw; } });
    expect(prompt).toBe(nlPrompt('look', CAT));
    expect(r).toEqual({ permissions: { bank: ['peek'] }, limits: {}, unknownVerbs: [], droppedLimits: [], raw, lints: [] });
  });
  it('lints a non-empty policy (an unbounded money action warns)', async () => {
    const r = await policyFromNL({ instruction: 'x', catalog: CAT, complete: async () => '{"permissions":{"bank":["wire"]}}' });
    expect(r.lints.map((l) => l.code)).toContain('money-unbounded');
    expect(r.lints.map((l) => l.code)).not.toContain('uncatalogued');
  });
  it('no permissions => no lints', async () => {
    const r = await policyFromNL({ instruction: 'x', catalog: CAT, complete: () => '{}' });
    expect(r.lints).toEqual([]);
  });
});

describe('agentFromNL', () => {
  const principal = generateKeyPair();
  it('names the unknown verbs, or none, when nothing is grantable', async () => {
    await expect(agentFromNL({ instruction: 'x', goal: 'g', principal, catalog: CAT, complete: () => '{"permissions":{"bank":["fly","run"]}}' })).rejects.toThrow(
      new Error('agentFromNL: the instruction yielded no grantable permissions (unknown verbs: bank.fly, bank.run)'),
    );
    await expect(agentFromNL({ instruction: 'x', goal: 'g', principal, catalog: CAT, complete: () => '{}' })).rejects.toThrow(
      new Error('agentFromNL: the instruction yielded no grantable permissions (unknown verbs: none)'),
    );
  });
  it('passes catalog, aud, holder and now through to the agent', async () => {
    const holder = generateKeyPair();
    const { agent: a } = await agentFromNL({ instruction: 'x', goal: 'g', principal, catalog: CAT, aud: 'rs.example', holder, now: 12345, complete: () => '{"permissions":{"bank":["peek"]}}' });
    expect(a.holder).toBe(holder);
    expect(a.budget.tau).toBe(12345);
    expect(settle(() => a.policy.actions.map((s) => s.verb))).toEqual({ ok: true, value: ['bank.peek'] });
    expect(a.policy.actions[0]!.reversibility).toBe('reversible');
    expect(() => a.act('bank.peek', '/r')).not.toThrow();
  });
  it('without aud, act needs one', async () => {
    const { agent: a } = await agentFromNL({ instruction: 'x', goal: 'g', principal, catalog: CAT, complete: () => '{"permissions":{"bank":["peek"]}}' });
    expect(() => a.act('bank.peek', '/r')).toThrow('act: aud');
  });
});
