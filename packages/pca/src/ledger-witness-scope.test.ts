import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from './keys';
import { cosignTreeHead, signTreeHead, verifyWitnessCosignatures } from './ledger';

/** RT-15: a witness cosignature is scoped to ONE log (instance_id + principal), not just {size, root, prev_root}. */
describe('RT-15: witness cosignatures are scoped to the log instance', () => {
  const g = generateKeyPair();
  const w = generateKeyPair();
  const policy = { witnessKeys: [encodeKey(w.publicKey)], threshold: 1 };
  const head = (instance_id: string, principal: string) =>
    signTreeHead(g.secretKey, { instance_id, principal, size: 0, root: 'R', prev_root: '', timestamp: 1 });

  it('a cosignature for log A verifies on A', () => {
    const a = head('inst-a', 'grant-a');
    expect(verifyWitnessCosignatures({ ...a, witnesses: [cosignTreeHead(a, w.secretKey)] }, policy)).toBe(true);
  });

  it('the same cosignature does NOT verify on a log with identical size/root/prev_root but another instance', () => {
    const a = head('inst-a', 'grant-a');
    const cos = cosignTreeHead(a, w.secretKey);
    expect(verifyWitnessCosignatures({ ...head('inst-b', 'grant-a'), witnesses: [cos] }, policy)).toBe(false);
  });

  it('nor on another principal of the same instance', () => {
    const a = head('inst-a', 'grant-a');
    const cos = cosignTreeHead(a, w.secretKey);
    expect(verifyWitnessCosignatures({ ...head('inst-a', 'grant-b'), witnesses: [cos] }, policy)).toBe(false);
  });
});
