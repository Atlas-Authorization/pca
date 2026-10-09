import { describe, expect, it } from 'vitest';
import { agentFromNL, nlPrompt, parseNLPolicy, policyFromNL } from './nl';
import { generateKeyPair } from './keys';
import { verifyChain } from './capability';

const AUD = 'ins_test';

describe('nlPrompt', () => {
  it('grounds the model in the catalog vocabulary', () => {
    const p = nlPrompt('let it refund customers');
    expect(p).toMatch(/stripe\.refund/);
    expect(p).toMatch(/Output ONLY JSON/);
    expect(p).toMatch(/let it refund customers/);
  });
});

describe('parseNLPolicy (grounding)', () => {
  it('keeps only catalog verbs and parseable, matched limits', () => {
    const raw = JSON.stringify({
      permissions: { stripe: ['refund', 'teleport'], gmail: ['send'] }, // teleport is not in the catalog
      limits: { refund: '$200/day', bogus: '$5', send: 'notanumber' },
    });
    const r = parseNLPolicy(raw);
    expect(r.permissions).toEqual({ stripe: ['refund'], gmail: ['send'] });
    expect(r.unknownVerbs).toEqual(['stripe.teleport']);
    expect(r.limits).toEqual({ refund: '$200/day' });
    expect(r.droppedLimits.sort()).toEqual(['bogus', 'send']); // bogus matches nothing; send unparseable
  });

  it('tolerates a code fence and leading prose', () => {
    const r = parseNLPolicy('Here is the policy:\n```json\n{"permissions":{"gmail":["send"]}}\n```');
    expect(r.permissions).toEqual({ gmail: ['send'] });
  });

  it('returns empty on model garbage (never throws)', () => {
    expect(parseNLPolicy('not json at all').permissions).toEqual({});
    expect(parseNLPolicy('42').permissions).toEqual({});
  });
});

describe('policyFromNL + agentFromNL', () => {
  const fakeModel = (json: object) => async () => JSON.stringify(json);

  it('compiles a grounded policy and lints it', async () => {
    const res = await policyFromNL({
      instruction: 'refunds up to $500/day',
      complete: fakeModel({ permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' } }),
    });
    expect(res.permissions).toEqual({ stripe: ['refund'] });
    expect(res.limits).toEqual({ refund: '$500/day' });
    expect(Array.isArray(res.lints)).toBe(true);
  });

  it('mints a verifiable agent end-to-end from NL', async () => {
    const { agent, result } = await agentFromNL({
      instruction: 'let the bot refund customers up to $500/day and send email',
      complete: fakeModel({ permissions: { stripe: ['refund'], gmail: ['send'] }, limits: { refund: '$500/day' } }),
      principal: generateKeyPair(),
      goal: 'support',
      aud: AUD,
    });
    expect(verifyChain(agent.chain, agent.principalPublic).ok).toBe(true);
    expect(agent.policy.actions.map((s) => s.verb).sort()).toEqual(['gmail.send', 'stripe.refund']);
    expect(result.unknownVerbs).toEqual([]);
  });

  it('throws when the instruction yields nothing grantable', async () => {
    await expect(
      agentFromNL({
        instruction: 'do whatever',
        complete: fakeModel({ permissions: { magic: ['teleport'] } }), // not in catalog
        principal: generateKeyPair(),
        goal: 'g',
        aud: AUD,
      }),
    ).rejects.toThrow(/no grantable permissions/);
  });
});
