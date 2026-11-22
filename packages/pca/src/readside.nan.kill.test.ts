import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical } from './hash';
import { publicKeyOf } from './keys';
import { READ_RECEIPT_DOMAIN, readChainLabels, type ReadField } from './readside';
import { signBody } from './workflow';

const R = new Uint8Array(32).fill(73);
const RPK = b64u(publicKeyOf(R));
const NOW = 1_800_000_000_000;
const DIGEST = hashCanonical({ n: 'grant' });
const RECEIPT_KEYS = ['v', 'grant', 'verb', 'resource', 'purpose', 'seq', 'prev', 'fields', 'labels', 'issued_at', 'signer'];
const fld = (cls: string): ReadField => ({ class: cls, action: 'masked', kind: 'hash', vd: hashCanonical({ n: cls }) });
const receipt = (): Record<string, unknown> => {
  const base: Record<string, unknown> = { v: 1, grant: DIGEST, verb: 'customers.get', resource: 'customers/1', purpose: 'support', seq: 0, prev: null, fields: { a: fld('pii') }, labels: ['pii'], issued_at: NOW, signer: RPK };
  return { ...base, sig: signBody(R, READ_RECEIPT_DOMAIN, Object.fromEntries(RECEIPT_KEYS.map((k) => [k, base[k]]))) };
};

describe('a non-finite clock never accepts a read receipt chain (readside)', () => {
  it('a finite clock accepts the receipt', () => {
    expect(readChainLabels([receipt()], RPK, DIGEST, NOW)).toEqual({ labels: ['pii'] });
  });
  // old check `issued_at > now` was false for NaN, so the chain was accepted at a NaN clock
  it('NaN, +Infinity and -Infinity refuse', () => {
    // `issued_at <= +Infinity` is true, so the old check accepted the chain at an infinite clock
    expect(readChainLabels([receipt()], RPK, DIGEST, Number.POSITIVE_INFINITY)).toEqual({ code: 'bad_receipt', at: 0 });
    expect(readChainLabels([receipt()], RPK, DIGEST, Number.NaN)).toEqual({ code: 'bad_receipt', at: 0 });
    expect(readChainLabels([receipt()], RPK, DIGEST, Number.NEGATIVE_INFINITY)).toEqual({ code: 'bad_receipt', at: 0 });
  });
});
