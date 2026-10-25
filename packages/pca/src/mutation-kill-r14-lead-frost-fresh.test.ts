/**
 * r14 static-mutant kill for frost.ts: the RFC 9591 §6.1 ciphersuite context string, read from a freshly evaluated module (a
 * module-level mutant is only visible to a test that re-imports the module). Every FROST hash (H1..H5) is domain-separated by
 * it, so a different value would make signatures that no other RFC 9591 implementation accepts.
 */
import { describe, expect, it, vi } from 'vitest';

describe('FROST ciphersuite context string (fresh module)', () => {
  it('is exactly the RFC 9591 Ed25519/SHA-512 context string', async () => {
    vi.resetModules();
    const m = await import('./frost');
    expect(m.CONTEXT_STRING).toBe('FROST-ED25519-SHA512-v1');
  });
});
