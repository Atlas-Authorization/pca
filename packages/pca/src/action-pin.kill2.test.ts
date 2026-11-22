import { describe, expect, it } from 'vitest';
import { generateKeyPair } from './keys';
import { registryKeyOf, signRegistryDoc } from './action-pin';

describe('classical registry signatures carry no post-quantum members', () => {
  const reg = generateKeyPair();
  it('the signature has no pq_value member', () => {
    const sig = signRegistryDoc('d', { a: 1 }, 'r1', reg.secretKey);
    expect(Object.keys(sig).sort()).toEqual(['alg', 'kid', 'value']);
  });
  it('the key entry has no pq_pk member', () => {
    const key = registryKeyOf('r1', reg.secretKey);
    expect(Object.keys(key).sort()).toEqual(['alg', 'kid', 'pk']);
  });
});
