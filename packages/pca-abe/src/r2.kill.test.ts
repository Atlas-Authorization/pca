import { describe, expect, it } from 'vitest';
import { keygenForAttributes, setup } from './abe';

describe('keygenForAttributes attribute filter', () => {
  it('a non-string value with a positive length is not an attribute', () => {
    const { msk } = setup();
    const key = keygenForAttributes(msk, ['ok', ['x'] as never, { length: 3 } as never]);
    expect(Object.keys(key.attrs)).toEqual(['ok']);
  });
});
