import { describe, expect, it, vi } from 'vitest';
import { importActionDefsFromMcp } from './schema';

vi.mock('@atlasauth/pca-actions', () => {
  throw new Error('not installed');
});

describe('importActionDefsFromMcp without the optional package', () => {
  it('says what to install', async () => {
    await expect(importActionDefsFromMcp([], { ns: 'n' })).rejects.toThrow(
      new Error('importActionDefsFromMcp needs the optional package @atlasauth/pca-actions; install it, or use draftActionSchemaFromMcp for a v1 draft'),
    );
  });
});
