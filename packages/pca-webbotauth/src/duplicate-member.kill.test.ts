import { describe, expect, it } from 'vitest';
import { parseKeyDirectory } from './signed-directory';

const X = 'A'.repeat(43);
const key = (extra: string) => `{"kty":"OKP","crv":"Ed25519","kid":"k","x":"${X}"${extra}}`;

describe('key directory duplicate members', () => {
  it('refuses a duplicate member with the exact message', () => {
    expect(() => parseKeyDirectory('{"keys":[],"keys":[{"kty":"OKP"}]}')).toThrow('duplicate key "keys"');
  });
  it('accepts non-canonical numbers', () => {
    expect(parseKeyDirectory(`{"keys":[${key(',"nbf":8.0,"exp":1e10')}]}`).keys).toHaveLength(1);
  });
});
