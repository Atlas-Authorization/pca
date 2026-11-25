import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { launchLocal } from './launch-local';
import { runParty } from './protocol';
import type { NodeConfig } from './party-main';

let dir = '';
let echoJs = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'pca-launch-default-'));
  echoJs = join(dir, 'echo.js');
  writeFileSync(echoJs, `const fs = require('fs');\nconst cfg = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));\nprocess.stdout.write(JSON.stringify({ cfg }) + '\\n');\n`);
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const V = [
  { allow: 1, t: 1, rQuant: 2 },
  { allow: 0, t: 3, rQuant: 0 },
] as const;

describe('launchLocal offline mode', () => {
  it('defaults to no-dealer: exactly n parties and no dealer process', async () => {
    const r = await launchLocal({ n: 2, Q: 7, vectors: [...V], mainJs: echoJs });
    expect(r.outputs.map((o) => [o.id, o.role])).toEqual([[0, 'party'], [1, 'party']]);
    for (const o of r.outputs) expect((o.json as { cfg: NodeConfig }).cfg.offline).toBe('no-dealer');
  });
  it('refuses trusted-dealer without the opt-in, with the exact message', async () => {
    await expect(launchLocal({ n: 2, Q: 7, vectors: [...V], mainJs: echoJs, offline: 'trusted-dealer' })).rejects.toThrow(
      "launchLocal: offline 'trusted-dealer' requires insecureTrustedDealer: true",
    );
    await expect(launchLocal({ n: 2, Q: 7, vectors: [...V], mainJs: echoJs, offline: 'trusted-dealer', insecureTrustedDealer: false })).rejects.toThrow(/requires insecureTrustedDealer: true/);
  });
});

describe('runParty trusted-dealer opt-in', () => {
  it('aborts with the exact local message', async () => {
    const e = (await runParty({ id: 0, n: 2, input: V[0], mesh: {} as never, sessionId: 's', offline: 'trusted-dealer' }).catch((x: unknown) => x)) as Error;
    expect(e.message).toContain("offline 'trusted-dealer' requires insecureTrustedDealer: true (the dealer sees every share and key); the default is 'no-dealer'");
  });
});
