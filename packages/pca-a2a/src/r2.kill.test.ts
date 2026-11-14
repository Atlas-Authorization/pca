import { describe, expect, it } from 'vitest';
import { b64u, canonicalBytesStrict, encodeKey, generateKeyPair, pcaChainDigest, sign, utf8 } from '@atlasauth/pca';
import { PCA_A2A_EXTENSION_URI, readPcaExtension } from './index';
import { A2A_RECEIPT_DOMAIN, verifyTaskReceipt } from './a2a-receipt';

describe('readPcaExtension suites', () => {
  it('an array element that merely has a length in range is not a suite string', () => {
    const card = { capabilities: { extensions: [{ uri: PCA_A2A_EXTENSION_URI, params: { aud: 'a', suites: [['x']] } }] } };
    expect(readPcaExtension(card)).toEqual({ ok: false, code: 'bad_params' });
  });
});

describe('verifyTaskReceipt never throws', () => {
  it('a body with no strict canonical form is refused with false, not an exception or undefined', () => {
    const K = generateKeyPair();
    const signer = encodeKey(K.publicKey);
    const body = { v: 1, task_id: 't1', state: 'TASK_STATE_WORKING', seq: 0, prev: null, chain: pcaChainDigest(['capA']), issued_at: 1000, signer };
    const d = utf8(A2A_RECEIPT_DOMAIN);
    const b = canonicalBytesStrict(body);
    const m = new Uint8Array(d.length + b.length);
    m.set(d);
    m.set(b, d.length);
    const good = { ...body, sig: b64u(sign(K.secretKey, m)) };
    expect(verifyTaskReceipt(good, signer)).toBe(true);
    expect(verifyTaskReceipt({ ...good, task_id: '\ud800' }, signer)).toBe(false);
  });
});
