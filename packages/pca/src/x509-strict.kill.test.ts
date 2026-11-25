import type { KeyObject } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { rsaKeyOk, strictChainError } from './x509-strict';

describe('x509-strict (fresh module: the recognised critical-extension sets are built at load)', () => {
  it('BasicConstraints + keyUsage, plus ExtendedKeyUsage for chains', async () => {
    vi.resetModules();
    const m = await import('./x509-strict');
    expect([...m.RECOGNISED_CRITICAL_EXTENSIONS]).toEqual(['2.5.29.19', '2.5.29.15']);
    expect([...m.CHAIN_CRITICAL_OK]).toEqual(['2.5.29.19', '2.5.29.15', '2.5.29.37']);
  });
});

describe('strictChainError fails closed when walking the chain throws', () => {
  it('reports the error message, or "invalid" for a non-Error throw', () => {
    const chain = (thrown: unknown) => Object.assign([] as Uint8Array[], { entries: () => { throw thrown; } });
    expect(strictChainError(chain(new Error('walk failed')))).toBe('certificate extension parse failed: walk failed');
    expect(strictChainError(chain('nope'))).toBe('certificate extension parse failed: invalid');
  });
});

describe('rsaKeyOk', () => {
  it('an RSA key without a modulus length is refused', () => {
    const key = { asymmetricKeyType: 'rsa', asymmetricKeyDetails: { publicExponent: 65537n } } as unknown as KeyObject;
    expect(rsaKeyOk(key)).toBe(false);
    const sized = { asymmetricKeyType: 'rsa', asymmetricKeyDetails: { modulusLength: 2048, publicExponent: 65537n } } as unknown as KeyObject;
    expect(rsaKeyOk(sized)).toBe(true);
  });
});
