import { describe, expect, it } from 'vitest';
import {
  DETECTOR_RECEIPT_REF_DOMAIN,
  detectorInputDigest,
  detectorPolicyError,
  detectorReceiptRef,
  detectorReceiptShapeError,
  detectorSignal,
  type DetectorInput,
  type DetectorPolicy,
} from './detector-receipt';
import { b64u, hashCanonical } from './hash';
import { encodeKey, generateKeyPair } from './keys';

const NOW = 1_800_000_000_000;
const PK = encodeKey(generateKeyPair().publicKey);
const POLICY: DetectorPolicy = {
  detectors: [
    { id: 'lakera', keys: [{ pk: PK }], on_suspicious: 'escalate', max_age_ms: 60_000 },
    { id: 'prompt_security', keys: [{ pk: PK }], on_suspicious: 'deny', categories: ['prompt_injection'], max_age_ms: 60_000 },
  ],
};
const DIG = detectorInputDigest('content');
const base = (): Record<string, unknown> => ({
  v: 1,
  kind: 'pca-detector-receipt',
  detector: 'lakera',
  version: 'guard-v2',
  input_digest: DIG,
  verdict: 'suspicious',
  categories: ['prompt_injection'],
  iat: NOW - 1000,
  sig: 'x',
});
const shape = (o: Record<string, unknown>) => detectorReceiptShapeError({ ...base(), ...o });
const entry = (o: Record<string, unknown> = {}) => ({ id: 'a', keys: [{ pk: PK }], on_suspicious: 'escalate', max_age_ms: 1000, ...o });

describe('detectorReceiptRef', () => {
  it('is the domain-separated content hash of the whole receipt', () => {
    const r1 = base();
    const r2 = { ...base(), version: 'other' };
    expect(detectorReceiptRef(r1)).toBe(hashCanonical({ d: DETECTOR_RECEIPT_REF_DOMAIN, receipt: r1 }));
    expect(detectorReceiptRef(r1)).not.toBe(detectorReceiptRef(r2));
    expect(detectorReceiptRef(r1)).not.toBe(hashCanonical({}));
  });
});

describe('detectorReceiptShapeError: exact messages', () => {
  it('the base receipt is well-formed', () => expect(shape({})).toBeNull());
  it('non-objects', () => {
    expect(detectorReceiptShapeError(null)).toBe('receipt must be an object');
    expect(detectorReceiptShapeError([])).toBe('receipt must be an object');
    expect(detectorReceiptShapeError('x')).toBe('receipt must be an object');
  });
  it('optional members are accepted as members', () => {
    expect(shape({ calibration_ref: 'dataset-1' })).toBeNull();
    expect(shape({ alg: 'ed25519' })).toBeNull();
    expect(shape({ pq_pk: 'x' })).toBe('an ed25519 artifact must not carry pq_pk / pq_sig');
    expect(shape({ pq_sig: 'x' })).toBe('an ed25519 artifact must not carry pq_pk / pq_sig');
  });
  it('version and kind, each on its own', () => {
    expect(shape({ v: 2 })).toBe('not a pca-detector-receipt v1');
    expect(shape({ kind: 'pca-other' })).toBe('not a pca-detector-receipt v1');
  });
  it('detector id: a non-string that stringifies to an id, and a string that is not an id', () => {
    expect(shape({ detector: ['lakera'] })).toBe('detector id is malformed');
    expect(shape({ detector: 'Lakera' })).toBe('detector id is malformed');
  });
  it('version and input digest', () => {
    expect(shape({ version: '' })).toBe('version must be 1..64 bytes');
    expect(shape({ input_digest: 'x' })).toBe('input_digest must be a b64u 32-byte digest');
  });
  it('categories: type, count boundary, element type, element pattern', () => {
    const ids = (n: number) => 'abcdefghi'.slice(0, n).split('');
    expect(shape({ categories: 'abc' })).toBe('categories must be 0..8 ids');
    expect(shape({ categories: ids(8) })).toBeNull();
    expect(shape({ categories: ids(9) })).toBe('categories must be 0..8 ids');
    expect(shape({ categories: [['abc']] })).toBe('categories must be 0..8 ids');
    expect(shape({ categories: ['Abc'] })).toBe('categories must be 0..8 ids');
  });
  it('categories order: sorted pairs pass, equal and descending pairs fail', () => {
    expect(shape({ categories: ['a', 'b'] })).toBeNull();
    expect(shape({ categories: ['a', 'b', 'c'] })).toBeNull();
    expect(shape({ categories: ['a', 'a'] })).toBe('categories must be sorted and distinct');
    expect(shape({ categories: ['b', 'a'] })).toBe('categories must be sorted and distinct');
  });
  it('iat boundaries', () => {
    expect(shape({ iat: 0 })).toBeNull();
    expect(shape({ iat: -1 })).toBe('iat must be a non-negative integer');
    expect(shape({ iat: 0.5 })).toBe('iat must be a non-negative integer');
  });
  it('session, calibration_ref and sig', () => {
    expect(shape({ session: b64u(new Uint8Array(32).fill(1)) })).toBeNull();
    expect(shape({ session: 'x' })).toBe('session must be a b64u 32-byte id');
    expect(shape({ calibration_ref: '' })).toBe('calibration_ref must be 1..256 bytes');
    expect(shape({ calibration_ref: 'r'.repeat(256) })).toBeNull();
    expect(shape({ calibration_ref: 'r'.repeat(257) })).toBe('calibration_ref must be 1..256 bytes');
    expect(shape({ sig: 5 })).toBe('sig must be a string');
  });
});

describe('detectorPolicyError: exact messages', () => {
  it('policy object', () => {
    expect(detectorPolicyError({ detectors: [] })).toBeNull();
    expect(detectorPolicyError(null)).toBe('policy must be {detectors}');
    expect(detectorPolicyError({ detectors: [], extra: 1 })).toBe('policy must be {detectors}');
    expect(detectorPolicyError({ detectors: 'x' })).toBe('detectors must hold at most 16 entries');
  });
  it('entries', () => {
    expect(detectorPolicyError({ detectors: [5] })).toBe('detector entry is malformed');
    expect(detectorPolicyError({ detectors: [entry()] })).toBeNull();
    expect(detectorPolicyError({ detectors: [entry({ keys: [{ pk: PK, pq_pk: 'pq' }] })] })).toBeNull();
    expect(detectorPolicyError({ detectors: [entry({ keys: [{ pk: PK, pq_pk: 5 }] })] })).toBe("detector 'a': keys must hold 1..8 pins");
    expect(detectorPolicyError({ detectors: [entry({ keys: [] })] })).toBe("detector 'a': keys must hold 1..8 pins");
    expect(detectorPolicyError({ detectors: [entry({ on_suspicious: 'block' })] })).toBe("detector 'a': on_suspicious must be escalate or deny");
    expect(detectorPolicyError({ detectors: [entry({ categories: [] })] })).toBe("detector 'a': categories must be 1+ ids");
  });
});

describe('detectorSignal: defaults and the fail-closed catch', () => {
  it('no receipts member means no receipts', () => {
    expect(detectorSignal({ policy: POLICY, input_digests: [DIG], now: NOW })).toEqual({
      signal: 'ok',
      env: { detect: { lakera: false, prompt_security: false, invalid: 0 } },
      flagged: [],
      rejected: [],
    });
  });
  it('an error while evaluating denies with the error message', () => {
    const input = {
      policy: POLICY,
      input_digests: [DIG],
      now: NOW,
      get receipts(): readonly unknown[] {
        throw new Error('boom');
      },
    } as DetectorInput;
    expect(detectorSignal(input)).toEqual({
      signal: 'deny',
      env: { detect: { lakera: false, prompt_security: false, invalid: 1 } },
      flagged: [],
      rejected: [{ index: -1, reason: 'evaluation error (fail closed): boom' }],
    });
  });
  it('a non-Error throw is reported as unknown', () => {
    const input = {
      policy: POLICY,
      input_digests: [DIG],
      now: NOW,
      get receipts(): readonly unknown[] {
        throw 'not an error';
      },
    } as DetectorInput;
    expect(detectorSignal(input).rejected).toEqual([{ index: -1, reason: 'evaluation error (fail closed): unknown' }]);
  });
});
