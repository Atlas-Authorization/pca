import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { run } from './cli';
import { ControlPlane, InMemoryControlPlaneStore } from './index';
import { generateKeyPair } from '@atlasauth/pca';

describe('pca-control-plane cli', () => {
  it('keygen then sign unfreeze produces an action the engine accepts, once', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcp-'));
    const file = join(dir, 'human.key');
    const lines: string[] = [];
    expect(run(['keygen', '--out', file], (s) => lines.push(s))).toBe(0);
    const pub = lines[0]!.replace('public key: ', '');
    expect(readFileSync(file, 'utf8').trim()).toHaveLength(43);

    const now = Date.UTC(2026, 10, 17, 12);
    const cp = new ControlPlane({ store: new InMemoryControlPlaneStore(), signer: generateKeyPair().secretKey, sources: {}, humans: [pub], now: () => now });
    const f = (await cp.freeze({ kind: 'agent', id: 'A' }, 'op')).directive;
    const out: string[] = [];
    expect(run(['sign', 'unfreeze', '--directive', f.id, '--key', file], (s) => out.push(s), () => now)).toBe(0);
    const action = JSON.parse(out[0]!) as unknown;
    expect(await cp.lift(action)).toMatchObject({ ok: true });
    expect(await cp.lift(action)).toMatchObject({ ok: false });
  });

  it('refuses a key file that already exists, a missing flag and an over-long validity', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcp-'));
    const file = join(dir, 'k');
    writeFileSync(file, 'x');
    expect(() => run(['keygen', '--out', file], () => undefined)).toThrow();
    expect(run(['sign', 'unfreeze', '--key', file], () => undefined)).toBe(2);
    expect(run(['sign', 'unfreeze', '--directive', 'd', '--key', file, '--ttl-sec', '99999'], () => undefined)).toBe(2);
    expect(run(['nonsense'], () => undefined)).toBe(2);
  });
});
