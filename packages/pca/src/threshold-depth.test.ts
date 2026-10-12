// verifyThreshold is TOTAL on hostile, host-parsed values of any nesting depth: the refusal reason must not
// stringify an attacker-supplied container recursively (Array.prototype.join on a 100000-deep array exhausts the stack).
import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { generateKeyPair } from './keys';
import { signShare, verifyThreshold } from './threshold';

const nest = (levels: number, leaf: unknown): unknown => {
  let v = leaf;
  for (let i = 0; i < levels; i++) v = [v];
  return v;
};
const MSG = new Uint8Array(32).fill(7);
const keys = { agent: generateKeyPair(), guardian: generateKeyPair(), principal: generateKeyPair() };
const set = (['agent', 'guardian', 'principal'] as const).map((role) => ({ role, publicKey: b64u(keys[role].publicKey) }));
const share = signShare('agent', keys.agent.secretKey, MSG, { signerSet: set, t: 1 });

describe('verifyThreshold: deeply nested hostile values are a verdict, never an exception', () => {
  it('t = a 100000-deep array: invalid threshold, no RangeError', () => {
    const r = verifyThreshold({ shares: [share] }, MSG, set, nest(100_000, 1) as number);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^invalid threshold t=/);
    expect(r.reason!.length).toBeLessThan(200);
  });
  it('t = a shallow array is still refused and named without its contents', () => {
    const r = verifyThreshold({ shares: [share] }, MSG, set, [1] as unknown as number);
    expect(r).toEqual({ ok: false, count: 0, roles: [], reason: 'invalid threshold t=<array> (must be 1, 2 or 3)' });
  });
  it('a share role / signer role nested 100000 deep is a clean refusal', () => {
    expect(verifyThreshold({ shares: [{ ...share, role: nest(100_000, 'agent') as 'agent' }] }, MSG, set, 1).ok).toBe(false);
    const badSet = [set[0]!, { ...set[1]!, role: nest(100_000, 'guardian') as 'guardian' }, set[2]!];
    expect(verifyThreshold({ shares: [share] }, MSG, badSet, 1).ok).toBe(false);
  });
});
