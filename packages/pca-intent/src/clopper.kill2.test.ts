import { describe, expect, it } from 'vitest';
import { certifyBracket, clopperPearsonCertified } from './clopper';

const A = 1n << 52n;

describe('certifyBracket: clamping and the lower-end walk', () => {
  it('the upper walk is clamped to 2^52 and never overshoots it', () => {
    expect(certifyBracket(0n, (a) => a < A)).toEqual({ hi: A, lo: A - 256n });
  });
  it('the lower end starts one tolerance BELOW a certified start', () => {
    expect(certifyBracket(300n, (a) => a <= 0n)).toEqual({ hi: 44n, lo: 0n });
  });
  it('the unreachable refusal is only for a bracket that reached 0', () => {
    // exceeds is true only at 256: the walk stops at lo = 256 > 0 and must not look at exceeds(0)
    expect(certifyBracket(512n, (a) => a === 256n)).toEqual({ hi: 512n, lo: 256n });
  });
  it('the starting point sits one tolerance ABOVE the floating-point guess', () => {
    const c = clopperPearsonCertified(1, 3, 1 - 2 ** -10);
    expect(c.upperUnits).toBe(81750990423335n);
    expect(c.lowerUnits).toBe(81750990423164n);
    const d = clopperPearsonCertified(3, 4, 1 - 2 ** -10);
    expect(d.upperUnits).toBe(796131459065962n);
    expect(d.lowerUnits).toBe(796131459065706n);
  });
});
