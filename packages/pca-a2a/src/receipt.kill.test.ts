import { describe, expect, it } from 'vitest';
import { b64u, canonicalBytesStrict, encodeKey, generateKeyPair, pcaChainDigest, sign, utf8 } from '@atlasauth/pca';
import { A2A_RECEIPT_DOMAIN, RECEIPT_KEY, attachReceipt, checkReceiptChain, receiptDigest, receiptOfPayload, signTaskReceipt, verifyTaskReceipt, type TaskReceipt } from './a2a-receipt';

const K = generateKeyPair();
const SIGNER = encodeKey(K.publicKey);
const ids = ['capA', 'capB'];
const CHAIN = pcaChainDigest(ids);
const FAKE32 = b64u(new Uint8Array(32).fill(7));

/** Sign an arbitrary body (even a defective one) the way a receipt is signed, so only the structural checks can refuse it. */
function forge(over: Record<string, unknown> = {}, secret = K.secretKey): Record<string, unknown> {
  const body: Record<string, unknown> = { v: 1, task_id: 't1', state: 'TASK_STATE_WORKING', seq: 0, prev: null, chain: CHAIN, issued_at: 1000, signer: SIGNER, ...over };
  const d = utf8(A2A_RECEIPT_DOMAIN);
  const b = canonicalBytesStrict(body);
  const m = new Uint8Array(d.length + b.length);
  m.set(d);
  m.set(b, d.length);
  return { ...body, sig: b64u(sign(secret, m)) };
}
const mk = (state: string, prev?: TaskReceipt, taskId = 't1') => signTaskReceipt(K.secretKey, { taskId, state, chainIds: ids, issuedAt: 1000, ...(prev ? { prev } : {}) });

describe('verifyTaskReceipt structural checks (each defect validly signed)', () => {
  it('a forged-but-well-formed receipt verifies, so the checks below are the only barrier', () => {
    expect(verifyTaskReceipt(forge(), SIGNER)).toBe(true);
    expect(verifyTaskReceipt(forge({ seq: 1, prev: FAKE32 }), SIGNER)).toBe(true);
    expect(verifyTaskReceipt(forge({ task_id: 'x'.repeat(4096) }), SIGNER)).toBe(true);
  });
  it('refuses each single defect', () => {
    const defects: Array<Record<string, unknown>> = [
      { v: 2 },
      { v: '1' },
      { signer: encodeKey(generateKeyPair().publicKey) },
      { task_id: 5 },
      { task_id: '' },
      { task_id: 'x'.repeat(4097) },
      { state: 'bogus' },
      { state: 5 },
      { seq: 1.5, prev: FAKE32 },
      { seq: -1, prev: FAKE32 },
      { issued_at: -1 },
      { issued_at: 1.5 },
      { issued_at: '5' },
      { issued_at: 'x' },
      { chain: 5 },
      { chain: 'abc' },
      { chain: b64u(new Uint8Array(31)) },
      { seq: 1, prev: 5 },
      { seq: 1, prev: 'abc' },
      { seq: 1, prev: b64u(new Uint8Array(31)) },
      { seq: 0, prev: FAKE32 },
      { seq: 1, prev: null },
    ];
    for (const d of defects) expect(verifyTaskReceipt(forge(d), SIGNER)).toBe(false);
  });
  it('refuses non-objects, arrays and a missing or foreign signature', () => {
    for (const x of [null, undefined, 5, 'x', [], [forge()]]) expect(verifyTaskReceipt(x, SIGNER)).toBe(false);
    const good = forge();
    expect(verifyTaskReceipt({ ...good, sig: undefined }, SIGNER)).toBe(false);
    expect(verifyTaskReceipt({ ...good, sig: 5 }, SIGNER)).toBe(false);
    expect(verifyTaskReceipt({ ...good, sig: 'abc' }, SIGNER)).toBe(false);
    expect(verifyTaskReceipt(forge({}, generateKeyPair().secretKey), SIGNER)).toBe(false);
  });
});

describe('signTaskReceipt input checks', () => {
  const base = { state: 'TASK_STATE_WORKING', chainIds: ids, issuedAt: 1 };
  it('refuses a non-string, empty or over-long task id with the exact message, and accepts 256', () => {
    for (const taskId of [5, '', 'x'.repeat(257)]) {
      let err: Error | undefined;
      try {
        signTaskReceipt(K.secretKey, { ...base, taskId: taskId as never });
      } catch (e) {
        err = e as Error;
      }
      expect(err).toBeInstanceOf(RangeError);
      expect(err!.message).toBe('signTaskReceipt: malformed input');
    }
    expect(signTaskReceipt(K.secretKey, { ...base, taskId: 'x'.repeat(256) }).task_id).toHaveLength(256);
  });
  it('refuses a previous receipt for another task or already terminal, with the exact message', () => {
    const msg = 'signTaskReceipt: prev is for another task or already terminal';
    const other = mk('TASK_STATE_WORKING', undefined, 'other');
    expect(() => signTaskReceipt(K.secretKey, { ...base, taskId: 't1', prev: other })).toThrow(msg);
    const done = mk('TASK_STATE_COMPLETED');
    expect(() => signTaskReceipt(K.secretKey, { ...base, taskId: 't1', prev: done })).toThrow(msg);
    const r1 = signTaskReceipt(K.secretKey, { ...base, taskId: 't1', prev: mk('TASK_STATE_WORKING') });
    expect(r1.seq).toBe(1);
  });
});

describe('checkReceiptChain links', () => {
  it('refuses a wrong sequence number or a wrong previous digest, each on its own', () => {
    const r0 = mk('TASK_STATE_WORKING');
    const o = { signer: SIGNER, taskId: 't1', chainIds: ids };
    const badSeq = forge({ seq: 5, prev: receiptDigest(r0) }) as unknown as TaskReceipt;
    const badPrev = forge({ seq: 1, prev: FAKE32 }) as unknown as TaskReceipt;
    const good = forge({ seq: 1, prev: receiptDigest(r0) }) as unknown as TaskReceipt;
    expect(checkReceiptChain([r0, good], o)).toMatchObject({ ok: true });
    expect(checkReceiptChain([r0, badSeq], o)).toEqual({ ok: false, code: 'broken_link', at: 1 });
    expect(checkReceiptChain([r0, badPrev], o)).toEqual({ ok: false, code: 'broken_link', at: 1 });
  });
});

describe('receipt carriers', () => {
  it('attachReceipt keeps the carrier metadata already present', () => {
    const r = mk('TASK_STATE_WORKING');
    const out = attachReceipt({ taskId: 't', metadata: { keep: 1 } }, r);
    expect(out.metadata).toEqual({ keep: 1, [RECEIPT_KEY]: r });
    expect(attachReceipt({ taskId: 't' } as { metadata?: Record<string, unknown> }, r).metadata).toEqual({ [RECEIPT_KEY]: r });
  });
  it('receiptOfPayload scans statusUpdate, task and message, skipping carriers without a receipt', () => {
    const r = mk('TASK_STATE_WORKING');
    const md = { [RECEIPT_KEY]: r };
    expect(receiptOfPayload(null)).toBeUndefined();
    expect(receiptOfPayload(undefined)).toBeUndefined();
    expect(receiptOfPayload({ task: { metadata: md } })).toEqual(r);
    expect(receiptOfPayload({ message: { metadata: md } })).toEqual(r);
    expect(receiptOfPayload({ statusUpdate: { metadata: {} }, task: { metadata: md } })).toEqual(r);
    expect(receiptOfPayload({ statusUpdate: { metadata: null }, message: { metadata: md } })).toEqual(r);
    expect(receiptOfPayload({ statusUpdate: { metadata: null } })).toBeUndefined();
    expect(receiptOfPayload({ other: { metadata: md } })).toBeUndefined();
  });
});
