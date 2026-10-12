/**
 * Site kills for the per-site ledger migration: the four `typeof` guards of vdfVerifyDetailed (vdf.ts:405) and
 * vdfVerifyCanonicalDetailed (vdf.ts:458) each produce 'malformed-input' on their own. Dropping one guard lets a
 * non-bigint fall through to a LATER check with a different, observable reason ('bad-modulus' / 'non-canonical-pi').
 */
import { describe, expect, it } from 'vitest';
import { vdfVerifyCanonicalDetailed, vdfVerifyDetailed } from './vdf';

const num = (n: number) => n as unknown as bigint;
const verifiers = [['vdfVerifyDetailed', vdfVerifyDetailed], ['vdfVerifyCanonicalDetailed', vdfVerifyCanonicalDetailed]] as const;

describe.each(verifiers)('%s: each typeof guard is the one that refuses', (_name, V) => {
  it('x a Number (N = 2n would otherwise give bad-modulus)', () => {
    expect(V(num(5), 1n, 1n, 1, 2n)).toEqual({ ok: false, reason: 'malformed-input' });
  });
  it('pi a Number (N = 2n would otherwise give bad-modulus)', () => {
    expect(V(5n, 1n, num(5), 1, 2n)).toEqual({ ok: false, reason: 'malformed-input' });
  });
  it('pi a Number with a valid modulus (isUnit(0, N) would otherwise give non-canonical-pi)', () => {
    expect(V(5n, 1n, num(0), 1, 15n)).toEqual({ ok: false, reason: 'malformed-input' });
  });
  it('N a Number (2 <= 3n is a legal mixed comparison and would give bad-modulus)', () => {
    expect(V(5n, 1n, 1n, 1, num(2))).toEqual({ ok: false, reason: 'malformed-input' });
  });
  it('y a Number', () => {
    expect(V(5n, num(1), 1n, 1, 2n)).toEqual({ ok: false, reason: 'malformed-input' });
  });
});
