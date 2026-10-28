import { describe, expect, it } from 'vitest';
import { generateKeyPair, encodeKey } from '@atlasauth/pca';
import { attachReceipt, checkReceiptChain, mayTriggerNext, receiptDigest, receiptOfPayload, signTaskReceipt, verifyTaskReceipt } from './index';

const K = generateKeyPair();
const OTHER = generateKeyPair();
const SIGNER = encodeKey(K.publicKey);
const ids = ['capA', 'capB'];
const mk = (state: string, prev?: ReturnType<typeof signTaskReceipt>, taskId = 't1', chain = ids, secret = K.secretKey) =>
  signTaskReceipt(secret, { taskId, state, chainIds: chain, issuedAt: 1000, ...(prev ? { prev } : {}) });
const o = { signer: SIGNER, taskId: 't1', chainIds: ids };

describe('signed task-update receipts - T-590', () => {
  it('a working then completed chain verifies and may trigger the next step', () => {
    const r0 = mk('TASK_STATE_WORKING');
    const r1 = mk('TASK_STATE_COMPLETED', r0);
    expect(verifyTaskReceipt(r0, SIGNER)).toBe(true);
    expect(checkReceiptChain([r0, r1], o)).toMatchObject({ ok: true, terminal: true });
    expect(mayTriggerNext([r0, r1], o)).toBe(true);
  });
  it('a spoofed or unsigned completed never triggers anything', () => {
    const lone = mk('TASK_STATE_COMPLETED');
    expect(mayTriggerNext([lone], o)).toBe(true); // a single signed receipt IS a valid chain of length one
    expect(mayTriggerNext([], o)).toBe(false);
    expect(mayTriggerNext([{ ...lone, sig: 'x' }], o)).toBe(false);
    const forged = mk('TASK_STATE_COMPLETED', undefined, 't1', ids, OTHER.secretKey);
    expect(mayTriggerNext([forged], o)).toBe(false); // signed by a key the receiver did not pin
    expect(mayTriggerNext([{ ...lone, state: 'TASK_STATE_FAILED' }], o)).toBe(false); // tampered after signing
    expect(mayTriggerNext(['completed'], o)).toBe(false);
  });
  it('only a COMPLETED ending triggers; failed, canceled and working do not', () => {
    for (const s of ['TASK_STATE_FAILED', 'TASK_STATE_CANCELED', 'TASK_STATE_REJECTED', 'TASK_STATE_WORKING']) expect(mayTriggerNext([mk(s)], o)).toBe(false);
  });
  it('refuses another task, another chain, a gap, a replayed link, a bad start and anything after a terminal state', () => {
    const r0 = mk('TASK_STATE_WORKING');
    const r1 = mk('TASK_STATE_WORKING', r0);
    const r2 = mk('TASK_STATE_COMPLETED', r1);
    expect(checkReceiptChain([mk('TASK_STATE_COMPLETED', undefined, 't2')], o)).toMatchObject({ ok: false, code: 'wrong_task' });
    expect(checkReceiptChain([mk('TASK_STATE_COMPLETED', undefined, 't1', ['capZ'])], o)).toMatchObject({ ok: false, code: 'wrong_chain' });
    expect(checkReceiptChain([r0, r2], o)).toMatchObject({ ok: false, code: 'broken_link', at: 1 });
    expect(checkReceiptChain([r1], o)).toMatchObject({ ok: false, code: 'bad_start' });
    expect(checkReceiptChain([r0, r0], o)).toMatchObject({ ok: false, code: 'broken_link' });
    const done = mk('TASK_STATE_COMPLETED', r0);
    expect(() => mk('TASK_STATE_WORKING', done)).toThrow(RangeError); // cannot even sign after terminal
    const sneaky = { ...r1, seq: 2, prev: receiptDigest(done) };
    expect(checkReceiptChain([r0, done, sneaky], o)).toMatchObject({ ok: false });
    expect(checkReceiptChain([], o)).toEqual({ ok: false, code: 'empty' });
  });
  it('refuses malformed signing input', () => {
    expect(() => signTaskReceipt(K.secretKey, { taskId: '', state: 'TASK_STATE_WORKING', chainIds: ids, issuedAt: 1 })).toThrow(RangeError);
    expect(() => signTaskReceipt(K.secretKey, { taskId: 't', state: 'bogus', chainIds: ids, issuedAt: 1 })).toThrow(RangeError);
    expect(() => signTaskReceipt(K.secretKey, { taskId: 't', state: 'TASK_STATE_WORKING', chainIds: [], issuedAt: 1 })).toThrow(RangeError);
    expect(verifyTaskReceipt({ v: 1 }, SIGNER)).toBe(false);
    expect(verifyTaskReceipt(null, SIGNER)).toBe(false);
  });
  it('carries on status metadata and is read back from a push payload', () => {
    const r = mk('TASK_STATE_COMPLETED');
    const upd = attachReceipt({ taskId: 't1', status: { state: 'TASK_STATE_COMPLETED' } } as { metadata?: Record<string, unknown> }, r);
    expect(receiptOfPayload({ statusUpdate: upd })).toEqual(r);
    expect(receiptOfPayload({ statusUpdate: { taskId: 't1' } })).toBeUndefined();
    expect(receiptOfPayload('x')).toBeUndefined();
  });
});
