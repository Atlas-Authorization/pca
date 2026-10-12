import { describe, expect, it } from 'vitest';
import { ARTIFACT_SIZE_REASON, MAX_ARTIFACT_BYTES, artifactTooLarge, decodePCActn } from './pcactn';

/** Shared PCActn raw wire-size cap: 512 KiB of UTF-8 bytes, checked before any parsing, same reason string in every verifier. */
describe('PCActn raw artifact size cap', () => {
  it('is exactly 524288 bytes with the shared reason string', () => {
    expect(MAX_ARTIFACT_BYTES).toBe(524_288);
    expect(ARTIFACT_SIZE_REASON).toBe('artifact exceeds size limit (max 524288 bytes)');
  });
  const doc = (n: number) => '{}' + ' '.repeat(n - 2);
  it('limit-1 and limit reach the parser; limit+1 is refused with the shared reason BEFORE parsing', () => {
    expect(() => decodePCActn(doc(MAX_ARTIFACT_BYTES - 1))).not.toThrow();
    expect(() => decodePCActn(doc(MAX_ARTIFACT_BYTES))).not.toThrow();
    expect(() => decodePCActn(doc(MAX_ARTIFACT_BYTES + 1))).toThrow(ARTIFACT_SIZE_REASON);
    // garbage over the cap fails with the SIZE reason, proving the size check precedes the parse
    expect(() => decodePCActn('x'.repeat(MAX_ARTIFACT_BYTES + 1))).toThrow(ARTIFACT_SIZE_REASON);
  });
  it('counts UTF-8 bytes, not UTF-16 units', () => {
    const euro = '€'.repeat(Math.floor(MAX_ARTIFACT_BYTES / 3));
    expect(euro.length).toBeLessThan(MAX_ARTIFACT_BYTES);
    expect(artifactTooLarge(euro)).toBe(false); // 524286 bytes
    expect(artifactTooLarge(euro + '€')).toBe(true); // 524289 bytes, 174764 units
    expect(artifactTooLarge('\u{1F600}'.repeat(131_073))).toBe(true); // 4 bytes each
    expect(artifactTooLarge('\u{1F600}'.repeat(131_072))).toBe(false); // exactly the cap
  });
  it('a 760 KB document is refused in well under 100 ms', () => {
    const t = performance.now();
    expect(() => decodePCActn('{"a":' + '1,'.repeat(380_000) + '1}')).toThrow(ARTIFACT_SIZE_REASON);
    expect(performance.now() - t).toBeLessThan(100);
  });
});
