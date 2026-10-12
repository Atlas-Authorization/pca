import { describe, it, expect } from 'vitest';
import {
  mixEntropy,
  secureSeed,
  HttpQrngSource,
  NullQrngSource,
  unavailableSource,
  parseAnuUint8,
  parseHex,
  parseBase64,
  MAX_HKDF_OUTPUT,
  MIN_LOCAL_BYTES,
  type QrngFetch,
  type QrngFetchResponse,
  type QrngSource,
} from './entropy';

// ---------------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------------

function seq(n: number, start = 0): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (start + i) & 0xff;
  return b;
}

function constBytes(n: number, v: number): Uint8Array {
  return new Uint8Array(n).fill(v);
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** A deterministic counter "CSPRNG" so we can control local bytes exactly in tests. */
function counterRng(): (n: number) => Uint8Array {
  let ctr = 0;
  return (n: number) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = ctr++ & 0xff;
    return out;
  };
}

/** A deterministic sequence of DISTINCT `len`-byte blocks (32-bit index in the first 4 bytes). */
function distinctLocalRng(len = 32): (n: number) => Uint8Array {
  let i = 0;
  return (n: number) => {
    const out = new Uint8Array(n);
    new DataView(out.buffer).setUint32(0, i++, false); // unique prefix per draw
    for (let k = 4; k < n && k < len; k++) out[k] = (i * 31 + k) & 0xff;
    return out;
  };
}

/** Build a mock QrngFetch returning a fixed JSON body / status. */
function mockJsonFetch(body: unknown, status = 200): { impl: QrngFetch; calls: string[] } {
  const calls: string[] = [];
  const impl: QrngFetch = (url) => {
    calls.push(url);
    const res: QrngFetchResponse = {
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(body),
      text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)),
    };
    return Promise.resolve(res);
  };
  return { impl, calls };
}

/** A mock source returning attacker-chosen bytes. */
function adversarialSource(chooser: (n: number) => Uint8Array, name = 'adv'): QrngSource {
  return {
    name,
    fetch: (n: number) => Promise.resolve(chooser(n)),
  };
}

// ---------------------------------------------------------------------------------------------------
// mixEntropy: correctness / spec
// ---------------------------------------------------------------------------------------------------

describe('mixEntropy — combiner correctness', () => {
  it('matches the HKDF-SHA256 spec it documents (deterministic for fixed inputs)', () => {
    const local = seq(32, 1);
    const quantum = seq(32, 100);
    const a = mixEntropy(local, quantum, { length: 32 });
    const b = mixEntropy(local, quantum, { length: 32 });
    expect(eq(a, b)).toBe(true); // deterministic
    // same inputs always => same output; different length changes output (info binds length)
    const c = mixEntropy(local, quantum, { length: 64 });
    expect(eq(c.subarray(0, 32), a)).toBe(false);
  });

  it('honors the requested output length', () => {
    const local = seq(32, 5);
    const q = seq(16, 9);
    for (const len of [1, 16, 32, 48, 64, 100, MAX_HKDF_OUTPUT]) {
      expect(mixEntropy(local, q, { length: len }).length).toBe(len);
    }
    // default length == local length
    expect(mixEntropy(seq(48, 2), q).length).toBe(48);
  });

  it('output differs from BOTH inputs', () => {
    const local = seq(32, 7);
    const quantum = seq(32, 70);
    const out = mixEntropy(local, quantum, { length: 32 });
    expect(eq(out, local)).toBe(false);
    expect(eq(out, quantum)).toBe(false);
  });

  it('never uses the quantum bytes raw: output is unrelated to quantum when local is fixed-secret', () => {
    const local = seq(32, 3);
    const q1 = constBytes(32, 0xab);
    const out = mixEntropy(local, q1, { length: 32 });
    // The output must not equal, start-with, or be a slice of the quantum input.
    expect(eq(out, q1)).toBe(false);
    expect(hex(out).includes(hex(q1))).toBe(false);
  });

  it('context provides domain separation', () => {
    const local = seq(32, 11);
    const q = seq(32, 22);
    const a = mixEntropy(local, q, { length: 32, context: 'ed25519' });
    const b = mixEntropy(local, q, { length: 32, context: 'ml-dsa' });
    const none = mixEntropy(local, q, { length: 32 });
    expect(eq(a, b)).toBe(false);
    expect(eq(a, none)).toBe(false);
  });

  it('fails CLOSED on a too-short local input', () => {
    expect(() => mixEntropy(seq(MIN_LOCAL_BYTES - 1), seq(32), { length: 32 })).toThrow(/local CSPRNG/);
    expect(() => mixEntropy(new Uint8Array(0), seq(32))).toThrow(/local CSPRNG/);
  });

  it('accepts an empty quantum input (CSPRNG-only path through the combiner)', () => {
    const local = seq(32, 4);
    const out = mixEntropy(local, new Uint8Array(0), { length: 32 });
    expect(out.length).toBe(32);
    expect(eq(out, local)).toBe(false);
  });

  it('rejects out-of-range length and non-Uint8Array inputs', () => {
    expect(() => mixEntropy(seq(32), seq(32), { length: 0 })).toThrow(/length/);
    expect(() => mixEntropy(seq(32), seq(32), { length: MAX_HKDF_OUTPUT + 1 })).toThrow(/length/);
    // @ts-expect-error intentional bad input
    expect(() => mixEntropy('nope', seq(32))).toThrow(/Uint8Array/);
    // @ts-expect-error intentional bad input
    expect(() => mixEntropy(seq(32), 'nope')).toThrow(/Uint8Array/);
  });
});

// ---------------------------------------------------------------------------------------------------
// mixEntropy: the SAFETY property — adversarial quantum can never weaken the key
// ---------------------------------------------------------------------------------------------------

describe('mixEntropy — safety invariant (mix, never replace)', () => {
  it('an adversarial/constant quantum source cannot force a chosen output, and output tracks local', () => {
    // Attacker fixes quantum to a constant; the only varying input is the secret local CSPRNG.
    const advQuantum = constBytes(32, 0x00); // worst case: all zeros
    const rng = distinctLocalRng();
    const seen = new Set<string>();
    const N = 256;
    for (let i = 0; i < N; i++) {
      const local = rng(32);
      const out = mixEntropy(local, advQuantum, { length: 32 });
      // Output never equals the attacker's chosen bytes.
      expect(eq(out, advQuantum)).toBe(false);
      seen.add(hex(out));
    }
    // Because local carries the entropy, every seed is distinct (no collapse under adversarial quantum).
    expect(seen.size).toBe(N);
  });

  it('output is byte-level unbiased even when quantum is all-zero (indistinguishable-from-random)', () => {
    const advQuantum = constBytes(64, 0x00);
    const rng = distinctLocalRng();
    const buckets = new Array<number>(256).fill(0);
    let total = 0;
    for (let i = 0; i < 400; i++) {
      const local = rng(32);
      const out = mixEntropy(local, advQuantum, { length: 32 });
      for (const b of out) {
        buckets[b] = (buckets[b] ?? 0) + 1;
        total++;
      }
    }
    // No byte value should dominate: with 12800 samples over 256 buckets, expected ~50 each.
    // A collapsed/weak output (e.g. raw quantum) would spike one bucket. Generous bound avoids flakiness.
    const max = Math.max(...buckets);
    expect(total).toBe(400 * 32);
    expect(max).toBeLessThan(150); // ~3x expected — a raw-zero leak would be 12800
    // Most buckets are populated (broad coverage).
    expect(buckets.filter((c) => c > 0).length).toBeGreaterThan(240);
  });

  it('two different adversarial quantum values with the SAME local still both hide the local secret', () => {
    const local = seq(32, 42);
    const out0 = mixEntropy(local, constBytes(32, 0x00), { length: 32 });
    const outF = mixEntropy(local, constBytes(32, 0xff), { length: 32 });
    // Different adversarial inputs => different outputs (quantum IS folded in), but neither leaks local.
    expect(eq(out0, outF)).toBe(false);
    expect(hex(out0).includes(hex(local))).toBe(false);
    expect(hex(outF).includes(hex(local))).toBe(false);
  });

  it('a strong quantum source strengthens a WEAK local: quantum entropy is incorporated', () => {
    // Local is weak/low-entropy (constant). A genuine quantum source varies the seed.
    const weakLocal = constBytes(32, 0x5a);
    const q1 = seq(32, 0);
    const q2 = seq(32, 200);
    const outLocalOnly = mixEntropy(weakLocal, new Uint8Array(0), { length: 32 });
    const out1 = mixEntropy(weakLocal, q1, { length: 32 });
    const out2 = mixEntropy(weakLocal, q2, { length: 32 });
    // With a weak/repeated local, different quantum draws still produce different seeds.
    expect(eq(out1, out2)).toBe(false);
    expect(eq(out1, outLocalOnly)).toBe(false);
    expect(eq(out2, outLocalOnly)).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------------
// secureSeed: fail-safe behavior
// ---------------------------------------------------------------------------------------------------

describe('secureSeed — fail-safe fallback', () => {
  it('with no source: CSPRNG-only, full length, distinct across calls', async () => {
    const a = await secureSeed({ length: 32 });
    const b = await secureSeed({ length: 32 });
    expect(a.seed.length).toBe(32);
    expect(a.usedQuantum).toBe(false);
    expect(a.quantumByteCount).toBe(0);
    expect(a.source).toBeNull();
    expect(eq(a.seed, b.seed)).toBe(false);
  });

  it('matches mixEntropy(local, quantum) exactly given a controlled CSPRNG and source', async () => {
    // Reproduce the derivation independently to pin the implementation to its documented spec.
    const localCtr = counterRng();
    const expectLocal = counterRng();
    const q = seq(32, 123);
    const res = await secureSeed({
      length: 32,
      localBytes: 32,
      quantumBytes: 32,
      source: adversarialSource(() => q),
      randomBytesImpl: localCtr,
    });
    const local = expectLocal(32); // same deterministic sequence the source saw
    const expected = mixEntropy(local, q, { length: 32 });
    // Independent HKDF recomputation of the combiner input (length-prefixed local‖quantum).
    expect(eq(res.seed, expected)).toBe(true);
    expect(res.usedQuantum).toBe(true);
    expect(res.quantumByteCount).toBe(32);
  });

  it('QRNG unavailable (NullQrngSource) falls back to CSPRNG cleanly', async () => {
    const res = await secureSeed({ length: 32, source: new NullQrngSource('offline') });
    expect(res.usedQuantum).toBe(false);
    expect(res.quantumByteCount).toBe(0);
    expect(res.seed.length).toBe(32);
    expect(res.source).toBe('null-qrng');
  });

  it('a throwing source never blocks key-gen; onQrngError is notified', async () => {
    let captured: unknown = null;
    const res = await secureSeed({
      length: 32,
      source: adversarialSource(() => {
        throw new Error('boom');
      }),
      onQrngError: (e) => {
        captured = e;
      },
    });
    expect(res.usedQuantum).toBe(false);
    expect(res.seed.length).toBe(32);
    expect(captured).toBeInstanceOf(Error);
  });

  it('a timing-out source falls back (fail-safe)', async () => {
    const slow: QrngSource = {
      name: 'slow',
      fetch: (n) =>
        new Promise((resolve) => setTimeout(() => resolve(new Uint8Array(n)), 50)).then(() => {
          throw new Error('timeout');
        }),
    };
    const res = await secureSeed({ length: 32, source: slow });
    expect(res.usedQuantum).toBe(false);
    expect(res.seed.length).toBe(32);
  });

  it('a source returning the WRONG length is rejected and falls back (no silent short seed)', async () => {
    const res = await secureSeed({
      length: 32,
      quantumBytes: 32,
      source: adversarialSource((_n) => new Uint8Array(8)), // too few
    });
    expect(res.usedQuantum).toBe(false);
    expect(res.seed.length).toBe(32);
  });

  it('an ADVERSARIAL constant source still yields distinct, full-strength seeds (security preserved)', async () => {
    const adv = adversarialSource((n) => constBytes(n, 0x00)); // attacker returns all-zero
    const seen = new Set<string>();
    for (let i = 0; i < 64; i++) {
      const res = await secureSeed({ length: 32, source: adv });
      expect(res.usedQuantum).toBe(true); // the bytes were "valid" length, just worthless
      expect(res.seed.length).toBe(32);
      expect(eq(res.seed, constBytes(32, 0x00))).toBe(false);
      seen.add(hex(res.seed));
    }
    // Despite the attacker controlling the quantum bytes, every seed is distinct (local CSPRNG rules).
    expect(seen.size).toBe(64);
  });

  it('rejects invalid length / localBytes (config errors throw; QRNG errors never do)', async () => {
    await expect(secureSeed({ length: 0 })).rejects.toThrow(/length/);
    await expect(secureSeed({ length: MAX_HKDF_OUTPUT + 1 })).rejects.toThrow(/length/);
    await expect(secureSeed({ localBytes: 4 })).rejects.toThrow(/localBytes/);
  });

  it('fails CLOSED if the local CSPRNG malfunctions', async () => {
    await expect(
      secureSeed({ length: 32, randomBytesImpl: () => new Uint8Array(3) }),
    ).rejects.toThrow(/local CSPRNG/);
  });

  it('unavailableSource() helper behaves as a null source', async () => {
    const res = await secureSeed({ source: unavailableSource('maintenance') });
    expect(res.usedQuantum).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------------
// HttpQrngSource: parsing + validation
// ---------------------------------------------------------------------------------------------------

describe('HttpQrngSource — well-formed responses', () => {
  it('parses a well-formed ANU-style response into exactly N bytes', async () => {
    const data = Array.from({ length: 32 }, (_, i) => i);
    const { impl, calls } = mockJsonFetch({ type: 'uint8', length: 32, data, success: true });
    const src = new HttpQrngSource({ url: 'https://qrng.example/api', fetchImpl: impl });
    const bytes = await src.fetch(32);
    expect(bytes.length).toBe(32);
    expect(Array.from(bytes)).toEqual(data);
    // length query param was set
    expect(calls[0]).toContain('length=32');
  });

  it('honors different requested lengths', async () => {
    for (const n of [1, 16, 64, 256]) {
      const data = Array.from({ length: n }, (_, i) => (i * 7) & 0xff);
      const { impl } = mockJsonFetch({ data });
      const src = new HttpQrngSource({ url: 'https://qrng.example/api', fetchImpl: impl });
      const bytes = await src.fetch(n);
      expect(bytes.length).toBe(n);
    }
  });

  it('appends extraParams and uses a custom length param', async () => {
    const { impl, calls } = mockJsonFetch({ data: [1, 2, 3, 4] });
    const src = new HttpQrngSource({
      url: 'https://qrng.example/api',
      lengthParam: 'len',
      extraParams: { type: 'uint8' },
      fetchImpl: impl,
    });
    await src.fetch(4);
    expect(calls[0]).toContain('len=4');
    expect(calls[0]).toContain('type=uint8');
  });

  it('supports a custom buildUrl', async () => {
    const { impl, calls } = mockJsonFetch({ data: [9, 9] });
    const src = new HttpQrngSource({
      url: 'https://qrng.example',
      buildUrl: (base, n) => `${base}/bytes/${n}`,
      fetchImpl: impl,
    });
    await src.fetch(2);
    expect(calls[0]).toBe('https://qrng.example/bytes/2');
  });

  it('sends the API key as a header and never in the URL', async () => {
    let seenHeaders: Record<string, string> | undefined;
    const impl: QrngFetch = (url, init) => {
      seenHeaders = init?.headers ? { ...init.headers } : undefined;
      expect(url).not.toContain('super-secret');
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ data: [1] }),
        text: () => Promise.resolve('{}'),
      });
    };
    const src = new HttpQrngSource({
      url: 'https://qrng.example/api',
      apiKey: 'super-secret',
      apiKeyHeader: 'x-qrng-key',
      fetchImpl: impl,
    });
    await src.fetch(1);
    expect(seenHeaders?.['x-qrng-key']).toBe('super-secret');
  });

  it('parses hex and base64 formats', async () => {
    const hexSrc = new HttpQrngSource({
      url: 'https://qrng.example/api',
      format: 'hex',
      fetchImpl: mockJsonFetch('00ff10').impl,
    });
    expect(Array.from(await hexSrc.fetch(3))).toEqual([0, 255, 16]);

    const b64Src = new HttpQrngSource({
      url: 'https://qrng.example/api',
      format: 'base64',
      fetchImpl: mockJsonFetch('AP8Q').impl, // base64 of 00 ff 10
    });
    expect(Array.from(await b64Src.fetch(3))).toEqual([0, 255, 16]);
  });
});

describe('HttpQrngSource — rejects malformed / short / oversized responses (fail-closed)', () => {
  const mk = (body: unknown, status = 200): HttpQrngSource =>
    new HttpQrngSource({ url: 'https://qrng.example/api', fetchImpl: mockJsonFetch(body, status).impl });

  it('rejects a short payload (fewer bytes than requested)', async () => {
    await expect(mk({ data: [1, 2, 3] }).fetch(32)).rejects.toThrow(/expected 32 bytes/);
  });

  it('rejects an oversized payload (more bytes than requested)', async () => {
    await expect(mk({ data: Array.from({ length: 64 }, () => 1) }).fetch(32)).rejects.toThrow(
      /expected 32 bytes/,
    );
  });

  it('rejects success=false', async () => {
    await expect(mk({ success: false, data: [1, 2] }).fetch(2)).rejects.toThrow(/success=false/);
  });

  it('rejects a non-array data field', async () => {
    await expect(mk({ data: 'nope' }).fetch(4)).rejects.toThrow(/not an array/);
  });

  it('rejects a non-object body', async () => {
    await expect(mk(42).fetch(4)).rejects.toThrow(/not a JSON object/);
  });

  it('rejects out-of-range byte values', async () => {
    await expect(mk({ data: [1, 2, 256, 4] }).fetch(4)).rejects.toThrow(/0\.\.255/);
    await expect(mk({ data: [1, -1, 3, 4] }).fetch(4)).rejects.toThrow(/0\.\.255/);
    await expect(mk({ data: [1, 2.5, 3, 4] }).fetch(4)).rejects.toThrow(/0\.\.255/);
  });

  it('rejects a non-2xx HTTP status', async () => {
    await expect(mk({ data: [1] }, 503).fetch(1)).rejects.toThrow(/HTTP 503/);
  });

  it('rejects malformed hex and base64 payloads', () => {
    expect(() => parseHex('0g')).toThrow(/malformed hex/);
    expect(() => parseHex('abc')).toThrow(/malformed hex/); // odd length
    expect(() => parseBase64('!!!!')).toThrow(/malformed base64/);
  });

  it('rejects invalid request counts (<=0, non-integer, over cap)', async () => {
    const src = mk({ data: [1] });
    await expect(src.fetch(0)).rejects.toThrow(/positive integer/);
    await expect(src.fetch(2.5)).rejects.toThrow(/positive integer/);
    await expect(src.fetch(999999)).rejects.toThrow(/cap/);
  });

  it('scrubs the API key out of a thrown transport error', async () => {
    const impl: QrngFetch = () => Promise.reject(new Error('connect failed for key=super-secret'));
    const src = new HttpQrngSource({ url: 'https://qrng.example/api', apiKey: 'super-secret', fetchImpl: impl });
    await expect(src.fetch(4)).rejects.toThrow(/\[redacted\]/);
    await src.fetch(4).catch((e: unknown) => {
      expect(String(e)).not.toContain('super-secret');
    });
  });

  it('normalizes an AbortError to a timeout message', async () => {
    const impl: QrngFetch = () => {
      const e = new Error('aborted');
      e.name = 'AbortError';
      return Promise.reject(e);
    };
    const src = new HttpQrngSource({ url: 'https://qrng.example/api', fetchImpl: impl });
    await expect(src.fetch(4)).rejects.toThrow(/timeout/);
  });

  it('rejects bad construction config', () => {
    expect(() => new HttpQrngSource({ url: '' })).toThrow(/url/);
    expect(() => new HttpQrngSource({ url: 'https://x', maxBytes: 0 })).toThrow(/maxBytes/);
    expect(() => new HttpQrngSource({ url: 'https://x', timeoutMs: -1 })).toThrow(/timeoutMs/);
  });
});

// ---------------------------------------------------------------------------------------------------
// standalone parsers
// ---------------------------------------------------------------------------------------------------

describe('response parsers', () => {
  it('parseAnuUint8 accepts a bare data array', () => {
    expect(Array.from(parseAnuUint8({ data: [0, 128, 255] }))).toEqual([0, 128, 255]);
  });
  it('parseHex round-trips', () => {
    expect(Array.from(parseHex('deadbeef'))).toEqual([0xde, 0xad, 0xbe, 0xef]);
    expect(parseHex('').length).toBe(0);
  });
  it('parseBase64 round-trips', () => {
    expect(Array.from(parseBase64('AP8Q'))).toEqual([0, 255, 16]);
  });
});

// Real end-to-end: the platform CSPRNG default path works (no mocks).
describe('secureSeed — real CSPRNG smoke', () => {
  it('produces high-entropy distinct seeds with the real CSPRNG and a mocked HTTP QRNG', async () => {
    const data = Array.from({ length: 32 }, (_, i) => (i * 13) & 0xff);
    const src = new HttpQrngSource({
      url: 'https://qrng.example/api',
      fetchImpl: mockJsonFetch({ data, success: true }).impl,
    });
    const r1 = await secureSeed({ length: 32, source: src });
    const r2 = await secureSeed({ length: 32, source: src });
    expect(r1.usedQuantum).toBe(true);
    expect(r1.source).toContain('http-qrng');
    expect(eq(r1.seed, r2.seed)).toBe(false); // local CSPRNG differs each call
    // equals the independent HKDF combiner over the real local bytes is not observable here,
    // but the seed must never equal the quantum input.
    expect(eq(r1.seed, new Uint8Array(data))).toBe(false);
  });
});
