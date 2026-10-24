/**
 * r13 mutation kills for entropy.ts: the HTTP QRNG source (defaults, headers, timeout timer, error normalisation and
 * scrubbing, the global-fetch fallback), the body parsers, the null source, mixEntropy against an independent
 * HKDF known-answer computation, and secureSeed (bounds, default draw sizes, fallback reporting, zeroisation).
 */
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  HttpQrngSource,
  MAX_HKDF_OUTPUT,
  mixEntropy,
  NullQrngSource,
  parseAnuUint8,
  parseBase64,
  parseHex,
  secureSeed,
  unavailableSource,
  type QrngFetch,
  type QrngFetchResponse,
  type QrngSource,
} from './entropy';

/** Run f, capturing its value or its error (name + message), so a mutant that throws fails an assertion, not an error. */
const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};
/** Async form of settle. */
const settleAsync = async <T>(f: () => Promise<T>) => {
  try {
    return { ok: true as const, value: await f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};

const enc = (s: string) => new TextEncoder().encode(s);
const jsonRes = (data: unknown): QrngFetchResponse => ({ ok: true, status: 200, json: async () => data, text: async () => JSON.stringify(data) });
const textRes = (t: string): QrngFetchResponse => ({ ok: true, status: 200, json: async () => JSON.parse(t), text: async () => t });

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

/** Independent reference of the documented combiner. */
function refMix(local: Uint8Array, quantum: Uint8Array, length: number, context?: string): Uint8Array {
  const ikm = new Uint8Array(8 + local.length + quantum.length);
  const dv = new DataView(ikm.buffer);
  dv.setUint32(0, local.length, false);
  dv.setUint32(4, quantum.length, false);
  ikm.set(local, 8);
  ikm.set(quantum, 8 + local.length);
  const label = context ? `atlas-pca/entropy/mix/v1/${context}` : 'atlas-pca/entropy/mix/v1';
  const lb = enc(label);
  const info = new Uint8Array(lb.length + 4);
  info.set(lb, 0);
  new DataView(info.buffer).setUint32(lb.length, length, false);
  return hkdf(sha256, ikm, enc('atlas-pca/entropy/salt/v1'), info, length);
}

describe('HttpQrngSource', () => {
  it('sends the default accept header and default x-api-key header, and builds the length URL', async () => {
    const calls: { url: string; init: unknown }[] = [];
    const fetchImpl: QrngFetch = async (url, init) => {
      calls.push({ url, init });
      return jsonRes({ data: [1, 2, 3] });
    };
    const s = new HttpQrngSource({ url: 'https://q.example:8443/api', apiKey: 'K', fetchImpl });
    expect(s.name).toBe('http-qrng(q.example:8443)');
    expect((await settleAsync(async () => Array.from(await s.fetch(3))))).toEqual({ ok: true, value: [1, 2, 3] });
    expect(calls[0]!.url).toBe('https://q.example:8443/api?length=3');
    const init = calls[0]!.init as { headers: Record<string, string> };
    expect(init.headers).toStrictEqual({ accept: 'application/json, text/plain', 'x-api-key': 'K' });
  });
  it('omits the key header when there is no key or it is empty', async () => {
    const hs: Record<string, string>[] = [];
    const fetchImpl: QrngFetch = async (_u, init) => {
      hs.push(init!.headers!);
      return jsonRes({ data: [9] });
    };
    await new HttpQrngSource({ url: 'https://q.example', fetchImpl }).fetch(1);
    await new HttpQrngSource({ url: 'https://q.example', apiKey: '', fetchImpl }).fetch(1);
    expect(hs[0]).toStrictEqual({ accept: 'application/json, text/plain' });
    expect(settle(() => Object.keys(hs[0]!))).toEqual({ ok: true, value: ['accept'] });
    expect(settle(() => Object.keys(hs[1]!))).toEqual({ ok: true, value: ['accept'] });
  });
  it('accepts exactly maxBytes and refuses one more', async () => {
    const fetchImpl: QrngFetch = async () => jsonRes({ data: [1, 2] });
    const s = new HttpQrngSource({ url: 'https://q.example', maxBytes: 2, fetchImpl });
    expect((await settleAsync(async () => Array.from(await s.fetch(2))))).toEqual({ ok: true, value: [1, 2] });
    expect(await settleAsync(async () => s.fetch(3))).toEqual({ ok: false, error: { name: 'RangeError', message: 'QRNG: requested 3 bytes exceeds per-request cap 2' } });
  });
  it('validates the constructor config', () => {
    expect(() => new HttpQrngSource({ url: ['https://q.example'] as unknown as string })).toThrow(new TypeError('HttpQrngSource: `url` must be a non-empty string'));
    expect(() => new HttpQrngSource({ url: 'https://q.example', timeoutMs: 0 })).toThrow(new TypeError('HttpQrngSource: `timeoutMs` must be a positive integer'));
    expect(() => new HttpQrngSource({ url: 'https://q.example', timeoutMs: 1 })).not.toThrow();
  });
  it('names the source unknown for a hostless or unparseable URL', () => {
    expect(settle(() => new HttpQrngSource({ url: 'file:///dev/random', fetchImpl: async () => jsonRes({}) }).name)).toEqual({ ok: true, value: 'http-qrng(unknown)' });
    expect(settle(() => new HttpQrngSource({ url: 'not a url', fetchImpl: async () => jsonRes({}) }).name)).toEqual({ ok: true, value: 'http-qrng(unknown)' });
  });
  it('falls back to the global fetch and calls it with (url, init)', async () => {
    const g = vi.fn(async () => jsonRes({ data: [7, 8] }));
    vi.stubGlobal('fetch', g);
    const s = new HttpQrngSource({ url: 'https://q.example/r' });
    expect((await settleAsync(async () => Array.from(await s.fetch(2))))).toEqual({ ok: true, value: [7, 8] });
    expect(g).toHaveBeenCalledTimes(1);
    const [u, init] = g.mock.calls[0] as unknown as [string, { headers: Record<string, string>; signal: AbortSignal }];
    expect(u).toBe('https://q.example/r?length=2');
    expect(init.headers).toStrictEqual({ accept: 'application/json, text/plain' });
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });
  it('rejects with a clear error when no fetch exists at all', async () => {
    vi.stubGlobal('fetch', undefined);
    const s = new HttpQrngSource({ url: 'https://q.example/r' });
    expect(await settleAsync(async () => s.fetch(2))).toEqual({ ok: false, error: { name: 'Error', message: 'QRNG: no fetch implementation available in this runtime' } });
  });
  it('aborts a hanging request after timeoutMs and reports a timeout', async () => {
    const fetchImpl: QrngFetch = (_u, init) =>
      new Promise((res, rej) => {
        init!.signal!.addEventListener('abort', () => rej(Object.assign(new Error('aborted'), { name: 'AbortError' })));
        // never aborted: answer late, so a missing abort shows as a wrong outcome rather than a hung test
        setTimeout(() => res(jsonRes({ data: [9] })), 1_000);
      });
    const s = new HttpQrngSource({ url: 'https://q.example', timeoutMs: 20, fetchImpl });
    expect(await settleAsync(async () => s.fetch(1))).toEqual({ ok: false, error: { name: 'Error', message: 'QRNG: fetch failed (timeout)' } });
  });
  it('clears the timer once the request settles (the signal is never aborted later)', async () => {
    let sig: AbortSignal | undefined;
    const fetchImpl: QrngFetch = async (_u, init) => {
      sig = init!.signal;
      return jsonRes({ data: [1] });
    };
    const s = new HttpQrngSource({ url: 'https://q.example', timeoutMs: 10, fetchImpl });
    await s.fetch(1);
    await new Promise((r) => setTimeout(r, 40));
    expect(sig!.aborted).toBe(false);
  });
  it('normalises transport errors, scrubs the key, and names non-Error throws', async () => {
    const s1 = new HttpQrngSource({ url: 'https://q.example', apiKey: 'SECRET', fetchImpl: async () => { throw new Error('bad SECRET here SECRET'); } });
    expect(await settleAsync(async () => s1.fetch(1))).toEqual({ ok: false, error: { name: 'Error', message: 'QRNG: fetch failed (bad [redacted] here [redacted])' } });
    const s2 = new HttpQrngSource({ url: 'https://q.example', fetchImpl: async () => { throw new Error('plain'); } });
    expect(await settleAsync(async () => s2.fetch(1))).toEqual({ ok: false, error: { name: 'Error', message: 'QRNG: fetch failed (plain)' } });
    const s3 = new HttpQrngSource({ url: 'https://q.example', fetchImpl: async () => { throw 'str'; } });
    expect(await settleAsync(async () => s3.fetch(1))).toEqual({ ok: false, error: { name: 'Error', message: 'QRNG: fetch failed (unknown error)' } });
    // an empty key scrubs nothing
    const s4 = new HttpQrngSource({ url: 'https://q.example', apiKey: '', fetchImpl: async () => { throw new Error('ab'); } });
    expect(await settleAsync(async () => s4.fetch(1))).toEqual({ ok: false, error: { name: 'Error', message: 'QRNG: fetch failed (ab)' } });
  });
  it('trims a text body before parsing (hex and base64)', async () => {
    const h = new HttpQrngSource({ url: 'https://q.example', format: 'hex', fetchImpl: async () => textRes('  0a0b\n') });
    expect((await settleAsync(async () => Array.from(await h.fetch(2))))).toEqual({ ok: true, value: [10, 11] });
    const b = new HttpQrngSource({ url: 'https://q.example', format: 'base64', fetchImpl: async () => textRes('\tAQI=\n') });
    expect((await settleAsync(async () => Array.from(await b.fetch(2))))).toEqual({ ok: true, value: [1, 2] });
  });
});

describe('parsers', () => {
  it('parseAnuUint8 refuses every non-byte element with its index', () => {
    for (const [v, i] of [[256, 1], [-1, 1], [1.5, 1], ['3', 1], [null, 1]] as const) {
      expect(settle(() => parseAnuUint8({ data: [7, v, 8] }))).toEqual({ ok: false, error: { name: 'Error', message: `QRNG: response data[${i}] is not a 0..255 integer` } });
    }
    expect(settle(() => Array.from(parseAnuUint8({ data: [0, 255] })))).toEqual({ ok: true, value: [0, 255] });
  });
  it('parseAnuUint8 refuses null with the object message', () => {
    expect(() => parseAnuUint8(null)).toThrow(new Error('QRNG: response body is not a JSON object'));
  });
  it('parseHex decodes every byte pair in order', () => {
    expect(settle(() => Array.from(parseHex('00ff10a0Bc')))).toEqual({ ok: true, value: [0, 255, 16, 160, 188] });
    expect(settle(() => parseHex('').length)).toEqual({ ok: true, value: 0 });
    // a long payload: each byte comes from its own two hex digits only
    expect(settle(() => Array.from(parseHex('ff'.repeat(40))))).toEqual({ ok: true, value: new Array(40).fill(255) });
    expect(settle(() => Array.from(parseHex('0123456789abcdef'.repeat(4))))).toEqual({ ok: true, value: new Array(4).fill([1, 35, 69, 103, 137, 171, 205, 239]).flat() });
  });
  it('parseBase64 refuses characters outside the alphabet even when atob would accept them', () => {
    expect(() => parseBase64('QQ ==')).toThrow(new Error('QRNG: malformed base64 payload'));
    expect(() => parseBase64('Q Q==')).toThrow(new Error('QRNG: malformed base64 payload'));
  });
  it('parseBase64 maps an atob failure to the malformed message', () => {
    expect(() => parseBase64('A')).toThrow(new Error('QRNG: malformed base64 payload'));
  });
  it('parseBase64 decodes exactly the bytes', () => {
    expect(settle(() => Array.from(parseBase64('AP8Q')))).toEqual({ ok: true, value: [0, 255, 16] });
    expect(settle(() => Array.from(parseBase64('/w==')))).toEqual({ ok: true, value: [255] });
  });
  it('parseBase64 refuses when no decoder exists', () => {
    vi.stubGlobal('atob', undefined);
    expect(() => parseBase64('AQI=')).toThrow(new Error('QRNG: base64 decoder unavailable in this runtime'));
  });
});

describe('null source', () => {
  it('rejects with the default or given reason', async () => {
    const n = new NullQrngSource();
    expect(n.name).toBe('null-qrng');
    expect(await settleAsync(async () => n.fetch(1))).toEqual({ ok: false, error: { name: 'Error', message: 'QRNG unavailable: no QRNG source configured' } });
    expect(await settleAsync(async () => new NullQrngSource('off').fetch(1))).toEqual({ ok: false, error: { name: 'Error', message: 'QRNG unavailable: off' } });
    const u = unavailableSource('down');
    expect(u).toBeInstanceOf(NullQrngSource);
    expect(await settleAsync(async () => u.fetch(1))).toEqual({ ok: false, error: { name: 'Error', message: 'QRNG unavailable: down' } });
    expect(await settleAsync(async () => unavailableSource().fetch(1))).toEqual({ ok: false, error: { name: 'Error', message: 'QRNG unavailable: no QRNG source configured' } });
  });
});

describe('mixEntropy known answers', () => {
  const local = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
  const quantum = Uint8Array.from({ length: 5 }, (_, i) => 200 + i);
  it('matches the documented HKDF construction', () => {
    expect(settle(() => Array.from(mixEntropy(local, quantum)))).toEqual({ ok: true, value: Array.from(refMix(local, quantum, 16)) });
    expect(settle(() => Array.from(mixEntropy(local, quantum, { length: 40 })))).toEqual({ ok: true, value: Array.from(refMix(local, quantum, 40)) });
    expect(settle(() => Array.from(mixEntropy(local, quantum, { context: 'ctx' })))).toEqual({ ok: true, value: Array.from(refMix(local, quantum, 16, 'ctx')) });
    expect(settle(() => Array.from(mixEntropy(local, quantum, { context: '' })))).toEqual({ ok: true, value: Array.from(refMix(local, quantum, 16)) });
    expect(settle(() => Array.from(mixEntropy(local, new Uint8Array(0))))).toEqual({ ok: true, value: Array.from(refMix(local, new Uint8Array(0), 16)) });
  });
  it('accepts exactly MIN_LOCAL_BYTES of local entropy', () => {
    expect(settle(() => mixEntropy(local, quantum).length)).toEqual({ ok: true, value: 16 });
    expect(() => mixEntropy(local.subarray(0, 15), quantum)).toThrow(RangeError);
  });
  it('does not modify its inputs', () => {
    const l = local.slice();
    const q = quantum.slice();
    mixEntropy(l, q);
    expect(l).toEqual(local);
    expect(q).toEqual(quantum);
  });
});

describe('secureSeed', () => {
  const counter = () => {
    const asked: number[] = [];
    const bufs: Uint8Array[] = [];
    const impl = (n: number) => {
      asked.push(n);
      const b = Uint8Array.from({ length: n }, (_, i) => (i * 7 + 3) & 0xff);
      bufs.push(b);
      return b;
    };
    return { asked, bufs, impl };
  };
  const src = (bytes: (n: number) => unknown, name = 'q'): QrngSource & { asked: number[] } => {
    const asked: number[] = [];
    return { name, asked, fetch: async (n: number) => { asked.push(n); return bytes(n) as Uint8Array; } };
  };
  it('validates length (1..MAX_HKDF_OUTPUT)', async () => {
    const msg = `secureSeed: length must be an integer in 1..${MAX_HKDF_OUTPUT}`;
    expect(await settleAsync(async () => secureSeed({ length: 0 }))).toEqual({ ok: false, error: { name: 'RangeError', message: msg } });
    expect(await settleAsync(async () => secureSeed({ length: -1 }))).toEqual({ ok: false, error: { name: 'RangeError', message: msg } });
    expect(await settleAsync(async () => secureSeed({ length: 1.5 }))).toEqual({ ok: false, error: { name: 'RangeError', message: msg } });
    expect(await settleAsync(async () => secureSeed({ length: MAX_HKDF_OUTPUT + 1 }))).toEqual({ ok: false, error: { name: 'RangeError', message: msg } });
    expect((await settleAsync(async () => (await secureSeed({ length: MAX_HKDF_OUTPUT })).seed.length))).toEqual({ ok: true, value: MAX_HKDF_OUTPUT });
    expect((await settleAsync(async () => (await secureSeed({ length: 1 })).seed.length))).toEqual({ ok: true, value: 1 });
  });
  it('validates localBytes and quantumBytes', async () => {
    expect((await settleAsync(async () => (await secureSeed({ localBytes: 16 })).seed.length))).toEqual({ ok: true, value: 32 });
    expect(await settleAsync(async () => secureSeed({ localBytes: 15 }))).toMatchObject({ ok: false, error: { name: 'RangeError' } });
    const qmsg = 'secureSeed: quantumBytes must be a positive integer';
    expect(await settleAsync(async () => secureSeed({ quantumBytes: 0 }))).toEqual({ ok: false, error: { name: 'RangeError', message: qmsg } });
    expect(await settleAsync(async () => secureSeed({ quantumBytes: -2 }))).toEqual({ ok: false, error: { name: 'RangeError', message: qmsg } });
    expect(await settleAsync(async () => secureSeed({ quantumBytes: 1.5 }))).toEqual({ ok: false, error: { name: 'RangeError', message: qmsg } });
    expect((await settleAsync(async () => (await secureSeed({ quantumBytes: 1 })).seed.length))).toEqual({ ok: true, value: 32 });
  });
  it('draws max(32, length) local and quantum bytes by default', async () => {
    const c = counter();
    const s = src((n) => new Uint8Array(n).fill(1));
    const r = await secureSeed({ length: 64, randomBytesImpl: c.impl, source: s });
    expect(c.asked).toEqual([64]);
    expect(s.asked).toEqual([64]);
    expect(r).toMatchObject({ usedQuantum: true, quantumByteCount: 64, source: 'q' });
    const c2 = counter();
    const s2 = src((n) => new Uint8Array(n).fill(1));
    await secureSeed({ length: 8, randomBytesImpl: c2.impl, source: s2 });
    expect(c2.asked).toEqual([32]);
    expect(s2.asked).toEqual([32]);
  });
  it('mixes with the requested length and context, and zeroises the local draw', async () => {
    const c = counter();
    const q = new Uint8Array(32).fill(5);
    const r = await secureSeed({ length: 20, context: 'kgen', randomBytesImpl: c.impl, source: src(() => q) });
    const expected = refMix(Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff), q, 20, 'kgen');
    expect(settle(() => Array.from(r.seed))).toEqual({ ok: true, value: Array.from(expected) });
    expect(settle(() => c.bufs[0]!.every((b) => b === 0))).toEqual({ ok: true, value: true });
  });
  it('fails closed when the local CSPRNG misbehaves', async () => {
    const msg = 'secureSeed: local CSPRNG did not return the requested bytes (fail-closed)';
    expect(await settleAsync(async () => secureSeed({ randomBytesImpl: (n) => new Uint8Array(n - 1) }))).toEqual({ ok: false, error: { name: 'Error', message: msg } });
    expect(await settleAsync(async () => secureSeed({ randomBytesImpl: (n) => new Uint8Array(n + 1) }))).toEqual({ ok: false, error: { name: 'Error', message: msg } });
    expect(await settleAsync(async () => secureSeed({ randomBytesImpl: (n) => Array.from({ length: n }, () => 1) as unknown as Uint8Array }))).toEqual({ ok: false, error: { name: 'Error', message: msg } });
  });
  it('reports a wrong-length or non-bytes quantum draw and falls back', async () => {
    const errs: unknown[] = [];
    const r1 = await secureSeed({ source: src(() => new Uint8Array(3)), onQrngError: (e) => errs.push(e) });
    expect(r1).toMatchObject({ usedQuantum: false, quantumByteCount: 0, source: 'q' });
    const r2 = await secureSeed({ source: src(() => 'nope'), onQrngError: (e) => errs.push(e) });
    expect(r2.usedQuantum).toBe(false);
    expect(settle(() => (errs[0] as Error).message)).toEqual({ ok: true, value: 'QRNG: source returned 3, expected 32' });
    expect(settle(() => (errs[1] as Error).message)).toEqual({ ok: true, value: 'QRNG: source returned non-bytes, expected 32' });
  });
});
