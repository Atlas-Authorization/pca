import { describe, expect, it, vi } from 'vitest';
import { mesh } from '@atlasauth/pca/ext/research';
import { meshWitnessStoreCases } from './mesh-witness';

const hooks = vi.hoisted(() => ({ eager: false }));

// A witness that, when persisting fails, still commits the head to memory (the bug the failed-save case guards against).
vi.mock('@atlasauth/pca/ext/research', async (importOriginal) => {
  const orig = await importOriginal<typeof import('@atlasauth/pca/ext/research')>();
  class Eager extends orig.mesh.MeshWitness {
    override cosign(req: Parameters<InstanceType<typeof orig.mesh.MeshWitness>['cosign']>[0]) {
      try {
        return super.cosign(req);
      } catch (e) {
        if (hooks.eager) (this as unknown as { seen: Map<string, unknown> }).seen.set(req.head.head.domain, { head: { ...req.head.head }, rev: [] });
        throw e;
      }
    }
  }
  return { ...orig, mesh: { ...orig.mesh, MeshWitness: Eager } };
});

describe('a witness that commits before the save succeeded', () => {
  it('is rejected by the failed-save case, and the honest witness is not', async () => {
    const c = meshWitnessStoreCases({ name: 'memory', make: () => new mesh.MemoryMeshWitnessStore() }).find((x) => x.name.startsWith('a failed save'))!;
    hooks.eager = false;
    await expect(c.run()).resolves.toBeUndefined();
    hooks.eager = true;
    try {
      await expect(c.run()).rejects.toThrow();
    } finally {
      hooks.eager = false;
    }
  });
});
