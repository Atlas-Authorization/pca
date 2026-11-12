import { describe, expect, it } from 'vitest';
import { FnDsaError, sizes, type FnDsaVariant } from './index';

describe('FN-DSA binding errors and tag table', () => {
  it('rejects an unsupported variant with a named FnDsaError', () => {
    let err: unknown;
    try {
      sizes('fn-dsa-256' as FnDsaVariant);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(FnDsaError);
    expect((err as FnDsaError).name).toBe('FnDsaError');
    expect((err as FnDsaError).message).toBe('unsupported FN-DSA variant: fn-dsa-256');
  });

  it('maps each variant to its own degree (sizes differ per variant)', () => {
    expect(sizes('fn-dsa-512').signature).toBe(666);
    expect(sizes('fn-dsa-1024').signature).toBe(1280);
  });
});
