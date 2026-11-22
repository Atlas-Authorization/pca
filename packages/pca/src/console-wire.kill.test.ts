// Exact-outcome tests for the console's event filter and freeze guards, the wire check's extension-slot refusals, and
// the settlement wire check's catch path.
import { describe, expect, it, vi } from 'vitest';
import { settlementWireCheck, type SettlementRecord } from './bond-settlement';
import { EMPTY_FREEZE, buildConsole, freezeAgent, isFrozen, type ActivityEvent } from './console';
import { agent } from './facade';
import { encodeKey, generateKeyPair } from './keys';
import { validateWireV2 } from './wire';

describe('console guards', () => {
  const fields = { at: 1, agent: 'x', verb: 'v', resource: 'r', outcome: 'auto' };
  it('a function carrying event fields is not an event', () => {
    const fn = Object.assign(function stray() {}, fields) as unknown as ActivityEvent;
    const v = buildConsole([fn]);
    expect([v.dropped, v.agents.length]).toEqual([1, 0]);
  });
  it('an agent id must be a string, not a one-element array', () => {
    const v = buildConsole([{ ...fields, agent: ['x'] } as unknown as ActivityEvent]);
    expect([v.dropped, v.agents.length]).toEqual([1, 0]);
  });
  it('freezeAgent refuses a non-string agent', () => {
    expect(() => freezeAgent(EMPTY_FREEZE, ['a'] as never)).toThrow(new TypeError('freezeAgent: agent must be a non-empty string'));
  });
  it('isFrozen treats a non-object set as frozen even when it carries a frozen list', () => {
    const set = Object.assign(() => undefined, { frozen: ['a'] });
    expect(isFrozen(set as never, 'b')).toBe(true);
  });
});

describe('validateWireV2: extension slots', () => {
  const mkP = (): Record<string, unknown> => {
    const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['refund'] }, aud: 'rs.example', now: 1_800_000_000_000 });
    return JSON.parse(JSON.stringify(a.subAgent().act('stripe.refund', 'ch_1', { amount: 5 }).pcactn)) as Record<string, unknown>;
  };
  const fresh = async () => {
    vi.resetModules();
    return import('./wire');
  };
  const NO_INTENT =
    "'intent' is an Intent Layer extension field and this verifier does not load the intent layer (use the root @atlasauth/pca entry, or import @atlasauth/pca/ext/intent and pass the extension)";
  it('an intent slot without the intent extension is refused with the exact reason', async () => {
    const m = await fresh();
    const P = mkP();
    expect(validateWireV2(P)).toBeNull();
    expect(m.validateWireV2(P)).toBeNull();
    expect(m.validateWireV2({ ...P, intent: {} })).toBe(NO_INTENT);
    expect(m.validateWireV2({ ...P, intent: {} }, {})).toBe(NO_INTENT);
  });
  it('an accepted fresh_at does not end the check: later slots are still validated', async () => {
    const m = await fresh();
    const P = mkP();
    const ext = { freshAt: () => null };
    expect(m.validateWireV2({ ...P, fresh_at: {} }, ext)).toBeNull();
    expect(m.validateWireV2({ ...P, fresh_at: {}, prohibition_evidence: 5 }, ext)).toBe("'prohibition_evidence' must be an object or array");
  });
});

describe('settlementWireCheck: a record that throws while being read', () => {
  it('is malformed', () => {
    const r = { get alg(): string { throw new Error('boom'); } } as unknown as SettlementRecord;
    expect(settlementWireCheck(r, encodeKey(generateKeyPair().publicKey))).toBe('malformed');
  });
});
