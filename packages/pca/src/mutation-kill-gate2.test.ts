/**
 * Mutation kills for the 0.5.0 flagship gate survivors: entropy.ts (SP 800-90B health-test boundaries, the health
 * failure message, key-buffer zeroisation under requireQuantum, the transport check's invalid-URL and loopback names),
 * detector-receipt.ts (the input digest, the receipt-list bound, category matching, flagged order, multi-pin keys,
 * session binding) and durable-state.ts (a one-fence file with no fence member).
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { detectorInputDigest, detectorSignal, MAX_DETECTOR_RECEIPTS, signDetectorReceipt, type DetectorPolicy, type DetectorPolicyEntry, type DetectorReceiptBody } from './detector-receipt';
import { DurableStateError, openDurableState } from './durable-state';
import { EntropyError, healthTestBytes, HttpQrngSource, proportionCutoff, secureSeed, type QrngFetch, type QrngSource } from './entropy';
import { hashCanonical } from './hash';
import { encodeKey, generateKeyPair } from './keys';

/** 64 distinct bytes, no two neighbours equal (37 is odd, so i*37 mod 256 never repeats within 256). */
const varied = (n = 64) => Uint8Array.from({ length: n }, (_, i) => (i * 37) & 0xff);

describe('entropy: proportionCutoff loop bounds', () => {
  it('H=1, W=20 stops exactly when the CDF reaches 1 - 2^-20 (strict <)', () => {
    // the CDF reaches the target exactly at k = 19 (only C(20,20) = 1 of 2^20 outcomes lies above it)
    expect(proportionCutoff(1, 20)).toBe(20);
    expect(proportionCutoff(5, 4)).toBe(4);
  });
  it('when the binomial mass underflows to 0 the loop stops at k = W', () => {
    // (1/2)^2000 is 0 in a double: cdf never moves, so k runs to W and the cutoff is W + 1
    expect(proportionCutoff(1, 2000)).toBe(2001);
  });
});

describe('entropy: healthTestBytes parameter and boundary cases', () => {
  const RC = { ok: false, test: 'repetition-count' };
  it('bad parameters and an empty buffer name the repetition-count test', () => {
    expect(healthTestBytes(varied(), { h: 0.5 })).toEqual(RC);
    expect(healthTestBytes(varied(), { h: 9 })).toEqual(RC);
    expect(healthTestBytes(varied(), { window: 1 })).toEqual(RC);
    expect(healthTestBytes(new Uint8Array(0))).toEqual(RC);
  });
  it('h = 1 and window = 2 are the inclusive lower bounds', () => {
    expect(healthTestBytes(varied(), { h: 1 })).toEqual({ ok: true });
    expect(healthTestBytes(varied(), { window: 2 })).toEqual({ ok: true });
  });
  it('a run of 4 (the H=8 cutoff) at the very start of the buffer is caught', () => {
    const b = Uint8Array.from([5, 5, 5, 5, ...varied(508)]);
    expect(healthTestBytes(b)).toEqual(RC);
  });
  it('a buffer shorter than the window is tested as one window of its own length', () => {
    // 64 bytes, every other one is 7: 32 hits in the window, cutoff for W=64 is 6
    expect(proportionCutoff(8, 64)).toBe(6);
    const b = Uint8Array.from({ length: 64 }, (_, i) => (i % 2 === 0 ? 7 : i + 1));
    expect(healthTestBytes(b)).toEqual({ ok: false, test: 'adaptive-proportion' });
  });
  it('the window count stops at the window edge and fails at exactly the cutoff', () => {
    expect(proportionCutoff(8, 4)).toBe(3);
    // window [9,1,9,2] holds 2 nines; the 9 that opens the next window must not count
    expect(healthTestBytes(Uint8Array.from([9, 1, 9, 2, 9, 3, 4, 5]), { window: 4 })).toEqual({ ok: true });
    // window [9,1,9,9] holds exactly 3 = the cutoff
    expect(healthTestBytes(Uint8Array.from([9, 1, 9, 9]))).toEqual({ ok: false, test: 'adaptive-proportion' });
  });
});

describe('entropy: secureSeed health options, failure message and zeroisation', () => {
  const src = (bytes: Uint8Array): QrngSource => ({ name: 'fake', fetch: async () => bytes });
  it('the caller health options are applied, and the failure names the test that failed', async () => {
    const errs: unknown[] = [];
    const r = await secureSeed({ source: src(varied(32)), healthTest: { h: 9 }, onQrngError: (e) => errs.push(e) });
    expect(r.usedQuantum).toBe(false);
    expect(errs).toHaveLength(1);
    expect(errs[0]).toBeInstanceOf(EntropyError);
    expect((errs[0] as EntropyError).code).toBe('health_test_failed');
    expect((errs[0] as Error).message).toBe('QRNG: repetition-count test failed; source rejected');
    // the same bytes pass with the default options
    expect((await secureSeed({ source: src(varied(32)) })).usedQuantum).toBe(true);
  });
  it('requireQuantum without quantum zeroes the local key material before throwing', async () => {
    const held = new Uint8Array(32).fill(0xab);
    let err: unknown;
    try {
      await secureSeed({ requireQuantum: true, randomBytesImpl: () => held });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(EntropyError);
    expect((err as EntropyError).code).toBe('quantum_required');
    expect((err as Error).message).toBe('secureSeed: quantum entropy is required but was not obtained (fail-closed)');
    expect(Array.from(held)).toEqual(new Array(32).fill(0));
  });
});

describe('entropy: HttpQrngSource transport check', () => {
  const ok: QrngFetch = async () => ({ ok: true, status: 200, json: async () => ({ data: [1, 2, 3] }), text: async () => '' });
  it('a URL that does not parse is an insecure_transport EntropyError', async () => {
    let err: unknown;
    try {
      await new HttpQrngSource({ url: 'https://q.example', buildUrl: () => 'not a url', fetchImpl: ok }).fetch(3);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(EntropyError);
    expect((err as EntropyError).code).toBe('insecure_transport');
    expect((err as Error).message).toBe('QRNG: endpoint URL is not a valid URL');
  });
  it('localhost and [::1] are loopback names for the http opt-in', async () => {
    for (const url of ['http://localhost:9/api', 'http://[::1]:9/api']) {
      await expect(new HttpQrngSource({ url, allowInsecureLoopback: true, fetchImpl: ok }).fetch(3), url).resolves.toEqual(Uint8Array.from([1, 2, 3]));
    }
  });
});

describe('detector receipts: digest, list bound, categories, order, pins, session', () => {
  const NOW = 1_800_000_000_000;
  const gw = generateKeyPair();
  const other = generateKeyPair();
  const PK = encodeKey(gw.publicKey);
  const DIG = detectorInputDigest('content');
  const body = (o: Partial<DetectorReceiptBody> = {}): DetectorReceiptBody => ({
    v: 1,
    kind: 'pca-detector-receipt',
    detector: 'guard',
    version: 'v1',
    input_digest: DIG,
    verdict: 'suspicious',
    categories: ['prompt_injection'],
    iat: NOW - 1000,
    ...o,
  });
  const det = (o: Partial<DetectorPolicyEntry> = {}): DetectorPolicyEntry => ({ id: 'guard', keys: [{ pk: PK }], on_suspicious: 'escalate', max_age_ms: 60_000, ...o });

  it('detectorInputDigest is the domain-separated canonical hash of {d, content}', () => {
    expect(detectorInputDigest('content')).toBe(hashCanonical({ d: 'atlas-pca/detector-input/v1', content: 'content' }));
    expect(detectorInputDigest({ a: 1 })).toBe(hashCanonical({ d: 'atlas-pca/detector-input/v1', content: { a: 1 } }));
  });

  it('MAX_DETECTOR_RECEIPTS receipts are evaluated; one more is the exact list refusal', () => {
    const policy: DetectorPolicy = { detectors: [det()] };
    const clean = signDetectorReceipt(body({ verdict: 'no_finding', categories: [] }), gw.secretKey);
    const at = detectorSignal({ receipts: Array(MAX_DETECTOR_RECEIPTS).fill(clean), policy, input_digests: [DIG], now: NOW });
    expect(at).toEqual({ signal: 'ok', env: { detect: { guard: false, invalid: 0 } }, flagged: [], rejected: [] });
    const over = detectorSignal({ receipts: Array(MAX_DETECTOR_RECEIPTS + 1).fill(clean), policy, input_digests: [DIG], now: NOW });
    expect(over).toEqual({ signal: 'escalate', env: { detect: { guard: false, invalid: 1 } }, flagged: [], rejected: [{ index: -1, reason: 'receipt list or clock malformed' }] });
  });

  it('a suspicious receipt with no categories acts even when the detector lists categories', () => {
    const policy: DetectorPolicy = { detectors: [det({ categories: ['prompt_injection'] })] };
    const r = signDetectorReceipt(body({ categories: [] }), gw.secretKey);
    const out = detectorSignal({ receipts: [r], policy, input_digests: [DIG], now: NOW });
    expect(out).toEqual({ signal: 'escalate', env: { detect: { guard: true, invalid: 0 } }, flagged: ['guard'], rejected: [] });
  });

  it('one acting category among others is enough', () => {
    const policy: DetectorPolicy = { detectors: [det({ categories: ['prompt_injection'] })] };
    const r = signDetectorReceipt(body({ categories: ['data_leak', 'prompt_injection'] }), gw.secretKey);
    const out = detectorSignal({ receipts: [r], policy, input_digests: [DIG], now: NOW });
    expect(out.flagged).toEqual(['guard']);
    expect(out.signal).toBe('escalate');
  });

  it('flagged is sorted, not in receipt order', () => {
    const policy: DetectorPolicy = { detectors: [det({ id: 'zeta' }), det({ id: 'alpha' })] };
    const z = signDetectorReceipt(body({ detector: 'zeta' }), gw.secretKey);
    const a = signDetectorReceipt(body({ detector: 'alpha' }), gw.secretKey);
    const out = detectorSignal({ receipts: [z, a], policy, input_digests: [DIG], now: NOW });
    expect(out.flagged).toEqual(['alpha', 'zeta']);
    expect(out.rejected).toEqual([]);
  });

  it('a receipt signed by any one of several pinned keys verifies', () => {
    const policy: DetectorPolicy = { detectors: [det({ keys: [{ pk: encodeKey(other.publicKey) }, { pk: PK }] })] };
    const r = signDetectorReceipt(body(), gw.secretKey);
    const out = detectorSignal({ receipts: [r], policy, input_digests: [DIG], now: NOW });
    expect(out).toEqual({ signal: 'escalate', env: { detect: { guard: true, invalid: 0 } }, flagged: ['guard'], rejected: [] });
  });

  it('a session-bound receipt is used in the session it names', () => {
    const S = detectorInputDigest('session-1');
    const policy: DetectorPolicy = { detectors: [det()] };
    const r = signDetectorReceipt(body({ session: S }), gw.secretKey);
    const out = detectorSignal({ receipts: [r], policy, input_digests: [DIG], session: S, now: NOW });
    expect(out).toEqual({ signal: 'escalate', env: { detect: { guard: true, invalid: 0 } }, flagged: ['guard'], rejected: [] });
  });
});

describe('durable-state: a one-fence file without a fence member', () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });
  it('is corrupt (invalid entry), not a TypeError', async () => {
    const d = mkdtempSync(join(tmpdir(), 'ds-gate2-'));
    dirs.push(d);
    writeFileSync(join(d, 'state.fence.2-abcdef'), '{"v":1}');
    let err: unknown;
    try {
      await openDurableState({ dir: d, lockTimeoutMs: 2000 });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(DurableStateError);
    expect((err as Error).message).toBe('corrupt: state.fence.2-abcdef has an invalid entry');
  });
});
