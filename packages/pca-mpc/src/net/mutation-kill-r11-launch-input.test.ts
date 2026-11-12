/**
 * 0.4.2 r11 mutation kill (launch-local.ts `input: id < n ? o.vectors[id] : undefined`): only the n parties are given an
 * input; the dealer (node n) never is, even when the caller passes more vectors than parties. A scripted node program echoes
 * the config file it was handed, so the dealer's config is observable without running the protocol.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { launchLocal } from './launch-local';
import type { NodeConfig } from './party-main';

let dir = '';
let echoJs = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'pca-launch-r11-'));
  echoJs = join(dir, 'echo.js');
  writeFileSync(echoJs, `process.stdout.write(JSON.stringify(JSON.parse(require('fs').readFileSync(process.argv[2], 'utf8'))) + '\\n');\n`);
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const V = [
  { allow: 1, t: 1, rQuant: 2 },
  { allow: 0, t: 3, rQuant: 0 },
  { allow: 1, t: 2, rQuant: 1 },
] as const;

describe('launchLocal: the dealer is never given a party input', () => {
  it('a surplus vector past the n parties does not reach the dealer config', async () => {
    const r = await launchLocal({ offline: 'trusted-dealer', insecureTrustedDealer: true, n: 2, vectors: [...V], mainJs: echoJs });
    const cfgs = r.outputs.map((o) => o.json as NodeConfig);
    expect(cfgs.map((c) => c.role)).toEqual(['party', 'party', 'dealer']);
    expect(cfgs[0]!.input).toEqual(V[0]);
    expect(cfgs[1]!.input).toEqual(V[1]);
    expect('input' in cfgs[2]!).toBe(false);
  });
});
