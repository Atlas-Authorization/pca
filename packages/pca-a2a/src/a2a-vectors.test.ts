import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { decodePcaNeed, pcaNeedDigest } from '@atlasauth/pca';
import { checkChainExtension, checkPushNotification, pcaPushToken, resumeGate, checkReceiptChain, mayTriggerNext, verifyTaskReceipt, receiptDigest } from './index';
import { buildA2aVectors } from './test-support/a2a-vectors';

const file = join(__dirname, '..', '..', 'pca', 'conformance', 'a2a-vectors.json');
const V = JSON.parse(readFileSync(file, 'utf8'));

describe('A2A binding shared vectors - T-594', () => {
  it('the committed file is exactly what the generator writes', () => {
    expect(readFileSync(file, 'utf8')).toBe(`${JSON.stringify(buildA2aVectors(), null, 2)}\n`);
  });
  for (const c of V.need) {
    it(`need: ${c.name}`, () => {
      const r = decodePcaNeed(c.input);
      expect(r.ok).toBe(c.expect.ok);
      if (r.ok) expect(pcaNeedDigest(r.need)).toBe(c.expect.digest);
      else expect(r.code).toBe(c.expect.code);
    });
  }
  it('push tokens and weak salts', () => {
    for (const t of V.push.tokens) expect(pcaPushToken(t.task_id, t.chain_ids, t.salt)).toBe(t.token);
    for (const s of V.push.weak_salts) expect(() => pcaPushToken('t', ['a'], s)).toThrow(RangeError);
  });
  for (const c of V.push.checks) {
    it(`push: ${c.name}`, () => {
      expect(checkPushNotification({ taskId: c.expected.task_id, chainIds: c.expected.chain_ids, salt: c.expected.salt }, { token: c.delivered.token ?? undefined, payload: c.delivered.payload })).toEqual(c.expect);
    });
  }
  for (const c of V.chains) it(`chains: ${c.name}`, () => expect(checkChainExtension(c.chains)).toEqual(c.expect));
  for (const c of V.resume) {
    it(`resume: ${c.name}`, () => {
      expect(resumeGate({ state: c.state, needEncoded: c.need_encoded ?? undefined, answerNeedDigest: c.answer_need_digest, proofAction: c.proof_action ?? undefined })).toBe(c.expect);
    });
  }
  it('receipts: signatures, digests and chains', () => {
    const R = V.receipts;
    for (const v of R.verify) expect(verifyTaskReceipt(R.records[v.record], R.signer)).toBe(v.ok);
    for (const d of R.digests) expect(receiptDigest(R.records[d.record])).toBe(d.digest);
    for (const s of R.scenarios) {
      const list = s.indices.map((i: number) => R.records[i]);
      const o = { signer: R.signer, taskId: s.task_id, chainIds: s.chain_ids };
      const got = checkReceiptChain(list, o);
      const flat = got.ok ? { ok: true, terminal: got.terminal, last_state: got.last.state } : { ok: false, code: got.code, ...(got.at !== undefined ? { at: got.at } : {}) };
      expect(flat).toEqual(s.expect);
      expect(mayTriggerNext(list, o)).toBe(s.may_trigger_next);
    }
  });
});
