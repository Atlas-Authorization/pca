import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { loadPca } from './caveats';
import { checkClock, type FetchLike } from './clock';
import { loadConfigFile } from './doctor';

const T = 1_760_000_000_000; // a whole second

describe('survivor kills', () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });
  const tmp = (): string => {
    const d = mkdtempSync(join(tmpdir(), 'pca-doctor-surv-'));
    dirs.push(d);
    return d;
  };

  it('loadPca does not accept an installed-package directory that has no package.json', () => {
    const root = tmp();
    mkdirSync(join(root, 'node_modules', '@atlasauth', 'pca'), { recursive: true });
    expect(() => loadPca(root)).toThrow(`@atlasauth/pca is not installed in ${root} or any parent node_modules`);
  });

  it('a zero skew is reported with a plus sign', async () => {
    const fetchImpl: FetchLike = async () => ({
      status: 200,
      headers: { get: (n: string) => (n === 'date' ? new Date(T).toUTCString() : null) },
      arrayBuffer: async () => new ArrayBuffer(0),
    });
    // both readings at T+500 make the midpoint equal to the (Date + 500) estimate, so the offset is exactly 0
    const r = await checkClock({ url: 'https://a.example', clock: { referenceUrl: 'local' } }, { fetch: fetchImpl, now: () => T + 500 });
    expect(r.detail).toContain('deployment clock +0.0 s relative to');
    expect(r.observed).toMatchObject({ skewMs: 0 });
  });

  it('loadConfigFile reads a .json file with JSON.parse (a top-level null stays null)', async () => {
    const dir = tmp();
    const f = join(dir, 'c.json');
    writeFileSync(f, 'null');
    expect(await loadConfigFile(f)).toBeNull();
  });
});
