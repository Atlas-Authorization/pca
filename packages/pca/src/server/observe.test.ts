import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createObserver, redactParams } from './observe';
import type { PcaGuardResult } from './require-pca';

const dirs: string[] = [];
const file = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'pca-observe-'));
  dirs.push(d);
  return join(d, 'nested', 'observed.jsonl');
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const deny = { ok: false, status: 403, verdict: { reasons: ['audience: wrong aud eyJhbGciOi-secret-token-material'] } } as unknown as PcaGuardResult;
const quiet = { log: () => undefined, env: {} };

describe('observe mode', () => {
  it('records a would-deny with a short reason code, never blocks, never records the proof or body', async () => {
    const f = file();
    const o = createObserver({ file: f, ...quiet, now: () => 5 });
    const done = await o.observe({ headers: { 'pca-action': 'SECRETPROOF' }, body: { note: 'private text' } }, async () => deny, { verb: 'shop.get', resource: '/orders/1', params: { amount: 5, ok: true, note: 'private text' } } as never);
    done(200);
    const text = readFileSync(f, 'utf8');
    expect(JSON.parse(text)).toEqual({ at: 5, verb: 'shop.get', resource: '/orders/1', params: { amount: 5, ok: true }, outcome: 'allow', would: 'deny', reasons: ['audience:'], mode: 'observe' });
    expect(text).not.toMatch(/SECRETPROOF|private|eyJ/);
  });
  it('records nothing for a request that failed', async () => {
    const f = file();
    const o = createObserver({ file: f, ...quiet });
    (await o.observe({ headers: {} }, async () => deny, { verb: 'a.b', resource: '/x' } as never))(500);
    expect(() => readFileSync(f)).toThrow();
  });
  it('a verifier that throws is a would-deny, not an error', async () => {
    const f = file();
    const o = createObserver({ file: f, ...quiet });
    (await o.observe({ headers: {} }, async () => { throw new Error('boom'); }, { verb: 'a.b', resource: '/x' } as never))(200);
    expect(JSON.parse(readFileSync(f, 'utf8'))).toMatchObject({ would: 'deny', reasons: ['verifier_error'] });
  });
  it('refuses to start in production unless acknowledged, and says so loudly otherwise', () => {
    expect(() => createObserver({ file: 'x', env: { NODE_ENV: 'production' }, log: () => undefined })).toThrow(/refuses to start in a production/);
    expect(() => createObserver({ file: 'x', env: { PCA_ENV: 'prod' }, log: () => undefined })).toThrow();
    const lines: string[] = [];
    createObserver({ file: 'x', env: { NODE_ENV: 'production' }, acknowledgeProduction: true, log: (m) => lines.push(m) });
    expect(lines[0]).toContain('PCA OBSERVE MODE');
  });
  it('stops recording at the size cap', async () => {
    const f = file();
    const logs: string[] = [];
    const o = createObserver({ file: f, env: {}, log: (m) => logs.push(m), maxBytes: 200 });
    for (let i = 0; i < 5; i++) (await o.observe({ headers: {} }, async () => deny, { verb: 'a.b', resource: `/x${i}` } as never))(200);
    expect(readFileSync(f, 'utf8').split('\n').filter(Boolean).length).toBeLessThan(5);
    expect(logs.some((l) => l.includes('recording stopped'))).toBe(true);
  });
});

describe('redactParams', () => {
  it('keeps numbers, booleans and listed short enums only', () => {
    expect(redactParams({ a: 1, b: false, c: 'gold', d: 'has space', e: 'x'.repeat(30), f: NaN, g: { n: 1 }, 'bad key': 2 }, ['c', 'd', 'e'])).toEqual({ a: 1, b: false, c: 'gold' });
    expect(redactParams({ c: 'gold' }, [])).toEqual({});
  });
});
