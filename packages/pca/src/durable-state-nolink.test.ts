/** A filesystem without working hard links (NFS/SMB/FUSE/some overlays) must make openDurableState fail closed, typed, at open time. */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    linkSync: () => {
      throw Object.assign(new Error('operation not permitted'), { code: 'EPERM' });
    },
  };
});
import { openDurableState } from './durable-state';

const d = mkdtempSync(join(tmpdir(), 'pca-nolink-'));
afterAll(() => rmSync(d, { recursive: true, force: true }));

describe('durable-state: hard links unusable', () => {
  it('throws DurableStateError code link-unsupported at open time (never opens a store whose lock cannot be exclusive)', async () => {
    await expect(openDurableState({ dir: d })).rejects.toMatchObject({ name: 'DurableStateError', code: 'link-unsupported' });
  });
});
