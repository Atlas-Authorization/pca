/**
 * 0.4.2 r11 mutation kill (bbs.ts generateKeyPair): the stuck-RNG guard refuses ONLY all-zero key material. Random IKM
 * that merely contains a zero octet (about 12% of 32-byte draws) is ordinary entropy and must yield a key.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPair, keyGen, skToPk } from './bbs';

const { queue } = vi.hoisted(() => ({ queue: [] as Uint8Array[] }));
vi.mock('@noble/hashes/utils', async (importOriginal) => {
  const orig = await importOriginal<typeof import('@noble/hashes/utils')>();
  return { ...orig, randomBytes: (n?: number) => (queue.length > 0 ? queue.shift()! : orig.randomBytes(n)) };
});

afterEach(() => {
  queue.length = 0;
});

describe('r11: generateKeyPair entropy guard', () => {
  it('all-zero key material is refused', () => {
    queue.push(new Uint8Array(32));
    expect(() => generateKeyPair()).toThrow(/all zeros/);
  });
  it('key material with some zero octets is accepted and keyed from exactly those bytes', () => {
    const ikm = Uint8Array.from({ length: 32 }, (_, i) => (i % 4 === 0 ? 0 : i));
    queue.push(ikm);
    const kp = generateKeyPair();
    expect(kp.sk).toBe(keyGen(ikm));
    expect(Buffer.from(kp.pk).toString('hex')).toBe(Buffer.from(skToPk(keyGen(ikm))).toString('hex'));
  });
});
