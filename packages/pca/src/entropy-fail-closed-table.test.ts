import { hkdfSync, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import {
  EntropyError,
  HttpQrngSource,
  type QrngFetch,
  type QrngFetchResponse,
  type QrngSource,
  generateKeyPairWithEntropy,
  healthTestBytes,
  mixEntropy,
  proportionCutoff,
  repetitionCutoff,
  secureSeed,
} from './entropy';

const good = (n: number) => Uint8Array.from(randomBytes(n));
const res = (body: unknown, status = 200): QrngFetchResponse => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
  text: async () => String(body),
});
const src = (f: (n: number) => Promise<Uint8Array>): QrngSource => ({ name: 'fake', fetch: f });

describe('mixEntropy known answers (independent HKDF via node:crypto)', () => {
  it('matches HKDF-SHA256 over the length-prefixed local||quantum with the fixed salt and info', () => {
    const local = Uint8Array.from({ length: 32 }, (_, i) => i);
    const quantum = Uint8Array.from({ length: 16 }, (_, i) => 255 - i);
    const ikm = Buffer.alloc(8 + 48);
    ikm.writeUInt32BE(32, 0);
    ikm.writeUInt32BE(16, 4);
    ikm.set(local, 8);
    ikm.set(quantum, 40);
    const label = Buffer.from('atlas-pca/entropy/mix/v1');
    const info = Buffer.concat([label, Buffer.from([0, 0, 0, 32])]);
    const want = Buffer.from(hkdfSync('sha256', ikm, Buffer.from('atlas-pca/entropy/salt/v1'), info, 32));
    expect(Buffer.from(mixEntropy(local, quantum)).toString('hex')).toBe(want.toString('hex'));
  });
});

describe('SP 800-90B health tests', () => {
  it('cutoffs for H=8 and window 512 are the standard values', () => {
    expect(repetitionCutoff(8)).toBe(4);
    expect(repetitionCutoff(1)).toBe(21);
    expect(proportionCutoff(8, 512)).toBe(13);
  });
  it('fails closed: constant, run, skewed, empty and bad parameters', () => {
    expect(healthTestBytes(new Uint8Array(32))).toEqual({ ok: false, test: 'repetition-count' });
    expect(healthTestBytes(Uint8Array.from([1, 2, 3, 3, 3, 3, 4]))).toEqual({ ok: false, test: 'repetition-count' });
    const skew = Uint8Array.from({ length: 512 }, (_, i) => (i % 2 === 0 ? 7 : i % 251));
    expect(healthTestBytes(skew)).toEqual({ ok: false, test: 'adaptive-proportion' });
    expect(healthTestBytes(new Uint8Array(0)).ok).toBe(false);
    expect(healthTestBytes(good(32), { h: 9 }).ok).toBe(false);
    expect(healthTestBytes(good(32), { window: 1 }).ok).toBe(false);
  });
  it('passes a varied buffer', () => {
    expect(healthTestBytes(Uint8Array.from({ length: 64 }, (_, i) => (i * 37) & 0xff))).toEqual({ ok: true });
  });
});

describe('secureSeed: missing X gives Y', () => {
  const cases: [string, QrngSource | null, (n: number) => Uint8Array][] = [
    ['source rejects (timeout/abort)', src(async () => { throw new Error('timeout'); }), () => good(32)],
    ['short read', src(async () => good(8)), () => good(32)],
    ['oversize read', src(async () => good(64)), () => good(32)],
    ['not bytes', src(async () => 'x' as unknown as Uint8Array), () => good(32)],
    ['constant bytes', src(async (n) => new Uint8Array(n).fill(9)), () => good(32)],
    ['no source', null, () => good(32)],
  ];
  for (const [name, source, rng] of cases) {
    it(`${name}: CSPRNG-only seed by default, EntropyError(quantum_required) when required`, async () => {
      const r = await secureSeed({ source, randomBytesImpl: rng });
      expect(r).toMatchObject({ usedQuantum: false, quantumByteCount: 0 });
      expect(r.seed.length).toBe(32);
      await expect(secureSeed({ source, randomBytesImpl: rng, requireQuantum: true })).rejects.toMatchObject({
        name: 'EntropyError',
        code: 'quantum_required',
      });
    });
  }
  it('a health failure is reported with its typed code', async () => {
    const errs: unknown[] = [];
    await secureSeed({ source: src(async (n) => new Uint8Array(n)), onQrngError: (e) => errs.push(e) });
    expect(errs[0]).toBeInstanceOf(EntropyError);
    expect((errs[0] as EntropyError).code).toBe('health_test_failed');
  });
  it('local CSPRNG too short is a hard error (the trust anchor)', async () => {
    await expect(secureSeed({ randomBytesImpl: () => new Uint8Array(3) })).rejects.toThrow(/fail-closed/);
    await expect(secureSeed({ localBytes: 8 })).rejects.toThrow(RangeError);
  });
  it('a healthy source is used', async () => {
    const r = await secureSeed({ source: src(async (n) => good(n)), requireQuantum: true });
    expect(r.usedQuantum).toBe(true);
  });
});

describe('HttpQrngSource transport and response table', () => {
  const ok: QrngFetch = async () => res({ data: [1, 2, 3] });
  it('http is refused, https allowed, loopback http only with the opt-in', async () => {
    const bad = new HttpQrngSource({ url: 'http://qrng.example/api', fetchImpl: ok });
    await expect(bad.fetch(3)).rejects.toMatchObject({ code: 'insecure_transport' });
    await expect(new HttpQrngSource({ url: 'http://127.0.0.1:9/api', fetchImpl: ok }).fetch(3)).rejects.toMatchObject({ code: 'insecure_transport' });
    await expect(new HttpQrngSource({ url: 'http://127.0.0.1:9/api', allowInsecureLoopback: true, fetchImpl: ok }).fetch(3)).resolves.toEqual(Uint8Array.from([1, 2, 3]));
    await expect(new HttpQrngSource({ url: 'http://qrng.example/api', allowInsecureLoopback: true, fetchImpl: ok }).fetch(3)).rejects.toMatchObject({ code: 'insecure_transport' });
  });
  it('never follows redirects', async () => {
    let seen: unknown;
    const f: QrngFetch = async (_u, init) => {
      seen = init?.redirect;
      return res({ data: [1] });
    };
    await new HttpQrngSource({ url: 'https://q.example', fetchImpl: f }).fetch(1);
    expect(seen).toBe('error');
  });
  const rows: [string, QrngFetch, RegExp][] = [
    ['non-2xx', async () => res({}, 503), /HTTP 503/],
    ['malformed body', async () => res('nope'), /not a JSON object/],
    ['short body', async () => res({ data: [1] }), /expected 3 bytes/],
    ['out-of-range byte', async () => res({ data: [1, 2, 300] }), /0\.\.255/],
    ['success=false', async () => res({ success: false, data: [1, 2, 3] }), /success=false/],
    ['transport abort', async () => { throw Object.assign(new Error('x'), { name: 'AbortError' }); }, /timeout/],
  ];
  for (const [name, f, re] of rows) {
    it(`${name} rejects`, async () => {
      await expect(new HttpQrngSource({ url: 'https://q.example', fetchImpl: f }).fetch(3)).rejects.toThrow(re);
    });
  }
  it('oversize request is refused before any I/O', async () => {
    await expect(new HttpQrngSource({ url: 'https://q.example', maxBytes: 2, fetchImpl: ok }).fetch(3)).rejects.toThrow(RangeError);
  });
});

describe('generateKeyPairWithEntropy', () => {
  it('derives a valid Ed25519 pair from the mixed seed, end to end with a fake source', async () => {
    const kp = await generateKeyPairWithEntropy({ source: src(async (n) => good(n)), requireQuantum: true });
    expect(kp.usedQuantum).toBe(true);
    expect(kp.secretKey.length).toBe(32);
    const msg = new Uint8Array([1, 2, 3]);
    expect(ed25519.verify(ed25519.sign(msg, kp.secretKey), msg, kp.publicKey)).toBe(true);
  });
  it('fails closed under requireQuantum and falls back otherwise', async () => {
    const dead = src(async () => { throw new Error('down'); });
    await expect(generateKeyPairWithEntropy({ source: dead, requireQuantum: true })).rejects.toBeInstanceOf(EntropyError);
    expect((await generateKeyPairWithEntropy({ source: dead })).usedQuantum).toBe(false);
  });
});
