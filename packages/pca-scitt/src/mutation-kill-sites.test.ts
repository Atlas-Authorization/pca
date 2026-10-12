/** Site kill (index.ts:492): encodeInclusionProof refuses a non-32-byte step hash with its exact TypeError. */
import { describe, expect, it } from 'vitest';
import { encodeInclusionProof } from './index';

describe('encodeInclusionProof step-hash guard', () => {
  it('a bad sibling hash throws the exact TypeError instead of encoding a null sibling', () => {
    const bad = { index: 0, size: 2, path: [{ side: 'R', hash: 'bad' }] } as never;
    expect(() => encodeInclusionProof(bad)).toThrow(TypeError);
    expect(() => encodeInclusionProof(bad)).toThrow(/^scitt: proof step hash is not a 32-byte b64u hash$/);
  });
});
