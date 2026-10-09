/**
 * Portability tests: the loader must not depend on node:wasi / node:*, must work from embedded bytes, raw
 * bytes, a Response and a fetched URL, and must fail closed when Web Crypto is unavailable.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { embeddedWasmBytes, initLessEmbedded, WASM_SHA256 } from './embedded.js';
import { initLess, initLessSync, isInitialized, keygen, LessError, open, seedFromEntropy, seedWith, sign, verify } from './web.js';

const ROOT = join(__dirname, '..');
const wasmBytes = new Uint8Array(readFileSync(join(ROOT, 'wasm', 'less_cat1.wasm')));
const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');
const msg = new TextEncoder().encode('portable loader');

function roundTrip(): void {
  seedWith(new Uint8Array(48).fill(5));
  const k = keygen();
  const sm = sign(k.secretKey, msg);
  const r = open(k.publicKey, sm);
  expect(r.ok).toBe(true);
  expect(Buffer.from(r.message).equals(Buffer.from(msg))).toBe(true);
  expect(verify(k.publicKey, msg, sm.slice(msg.length))).toBe(true);
}

afterEach(() => vi.unstubAllGlobals());

describe('portable loader', () => {
  it('the wasm imports exactly one host function: wasi_snapshot_preview1.random_get', async () => {
    const m = await WebAssembly.compile(wasmBytes);
    expect(WebAssembly.Module.imports(m)).toEqual([{ module: 'wasi_snapshot_preview1', name: 'random_get', kind: 'function' }]);
  });

  it('the browser-path sources import nothing from node:* and use no Node globals', () => {
    for (const f of ['core.ts', 'web.ts', 'embedded.ts']) {
      // strip comments (they legitimately mention node:*)
      const src = readFileSync(join(__dirname, f), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
      expect(src, f).not.toMatch(/node:|require\(|__dirname|process\.|\bBuffer\b/);
    }
  });

  it('embedded wasm equals the shipped file (sha256 pinned)', () => {
    expect(WASM_SHA256).toBe(sha(wasmBytes));
    expect(sha(embeddedWasmBytes())).toBe(WASM_SHA256);
  });

  it('async init from embedded bytes round-trips', async () => {
    await initLessEmbedded();
    expect(isInitialized()).toBe(true);
    roundTrip();
  }, 60_000);

  it('async init from raw bytes, from a Response (with and without application/wasm), and sync init all round-trip', async () => {
    await initLess(wasmBytes);
    roundTrip();
    await initLess(new Response(wasmBytes, { headers: { 'content-type': 'application/wasm' } }));
    roundTrip();
    await initLess(new Response(wasmBytes, { headers: { 'content-type': 'application/octet-stream' } }));
    roundTrip();
    initLessSync(wasmBytes);
    roundTrip();
  }, 120_000);

  it('async init from a fetched URL round-trips; an HTTP error fails with LessError', async () => {
    const srv = createServer((req, res) => {
      if (req.url === '/less.wasm') {
        res.writeHead(200, { 'content-type': 'application/wasm' });
        res.end(Buffer.from(wasmBytes));
      } else {
        res.writeHead(404);
        res.end();
      }
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    try {
      await initLess(`${base}/less.wasm`);
      roundTrip();
      await initLess(new URL(`${base}/less.wasm`));
      roundTrip();
      await expect(initLess(`${base}/missing.wasm`)).rejects.toBeInstanceOf(LessError);
    } finally {
      srv.close();
    }
  }, 120_000);

  it('fails closed when Web Crypto is unavailable: seedFromEntropy/keygen throw, verify still works', async () => {
    await initLess(wasmBytes);
    seedWith(new Uint8Array(48).fill(6));
    const k = keygen();
    const sig = sign(k.secretKey, msg).slice(msg.length);
    await initLess(wasmBytes); // fresh instance => unseeded
    vi.stubGlobal('crypto', undefined);
    expect(() => seedFromEntropy()).toThrow(LessError);
    expect(() => keygen()).toThrow(LessError);
    expect(verify(k.publicKey, msg, sig)).toBe(true); // verification needs no randomness
    vi.unstubAllGlobals();
    expect(() => seedFromEntropy()).not.toThrow(); // and recovers once crypto is back
  }, 120_000);

  it('entropy seeding via getRandomValues gives distinct keys', async () => {
    await initLess(wasmBytes);
    seedFromEntropy();
    const a = keygen().publicKey;
    seedFromEntropy();
    const b = keygen().publicKey;
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  }, 60_000);
});
