import { describe, expect, it } from 'vitest';
import { explainRefusal, PCA_DOCS } from './refusal-help';

const REF = `${PCA_DOCS}/reference/refusals.md`;
const UNKNOWN = {
  check: 'unknown',
  meaning: 'The guard refused and the reason is not in the table.',
  fix: 'Read the reason as written; every refusal names the check that failed.',
  docs: REF,
};

describe('explainRefusal: lookup order and the unknown entry', () => {
  it('the leading check wins over an earlier table entry named later in the text', () => {
    // `operation` comes before `policy` in the table; the leading token must decide
    expect(explainRefusal('policy: operation: verb mismatch').check).toBe('policy');
    expect(explainRefusal('policy: operation: verb mismatch').docs).toBe(`${REF}#policy`);
  });

  it('only a leading lowercase run counts as the head; otherwise the first "<check>:" in the text decides', () => {
    // no leading [a-z_] run: falls back to the scan, which finds `operation:` (not the unanchored `policy`)
    expect(explainRefusal('Xpolicy operation: y').check).toBe('operation');
    // a leading run that is not a table key: the scan finds `policy:`
    expect(explainRefusal('refused policy: amount over limit').check).toBe('policy');
    // the head is the WHOLE leading run (a single letter would miss the table)
    expect(explainRefusal('replay operation: x').check).toBe('replay');
  });

  it('the unknown entry is exact, for unknown text and for every non-string reason', () => {
    expect(explainRefusal('nothing matches here')).toEqual(UNKNOWN);
    expect(explainRefusal(undefined)).toEqual(UNKNOWN);
    expect(explainRefusal(null)).toEqual(UNKNOWN);
    expect(explainRefusal({ toString: () => 'policy: x' })).toEqual(UNKNOWN);
  });
});
