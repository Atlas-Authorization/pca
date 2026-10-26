import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mesh } from '@atlasauth/pca';
import { FileMeshWitnessStore } from '@atlasauth/pca/durable-mesh-witness';
import { afterAll, describe, expect, it } from 'vitest';
import { meshWitnessStoreCases } from './mesh-witness';

const { MemoryMeshWitnessStore } = mesh;

const dir = mkdtempSync(join(tmpdir(), 'mw-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
let n = 0;
const paths = new WeakMap<object, string>();

describe('memory store', () => {
  for (const c of meshWitnessStoreCases({ name: 'memory', make: () => new MemoryMeshWitnessStore() })) it(c.name, c.run);
});

describe('file store', () => {
  const make = () => {
    const p = join(dir, `w${n++}.json`);
    const s = new FileMeshWitnessStore(p);
    paths.set(s, p);
    return s;
  };
  const adapter = {
    name: 'file',
    make,
    reopen: (prev: object) => new FileMeshWitnessStore(paths.get(prev) as string),
    damage: (s: object) => {
      const p = paths.get(s) as string;
      const j = JSON.parse(readFileSync(p, 'utf8'));
      j.state.seen[0].head.size = 99; // edit without fixing the digest
      writeFileSync(p, JSON.stringify(j));
    },
  };
  for (const c of meshWitnessStoreCases(adapter as never)) it(c.name, c.run);
});

describe('the suite catches a store that forgets', () => {
  const forgetful = () => ({ load: () => undefined, save: () => {} });
  const cases = meshWitnessStoreCases({ name: 'forgetful', make: forgetful, reopen: forgetful });
  const byName = (n: string) => cases.find((c) => c.name.startsWith(n))!;
  it('fails the round trip', async () => {
    await expect(byName('save then load').run()).rejects.toThrow();
  });
  it('fails the restart-safety case: a restarted witness would cosign a fork', async () => {
    await expect(byName('a restarted witness remembers').run()).rejects.toThrow();
  });
  it('fails the persistence case', async () => {
    await expect(byName('a witness persists every cosignature').run()).rejects.toThrow();
  });
});
