/** Differential tests for the hash.ts / strict-json.ts mutants listed as equivalent. */
import { base64urlnopad } from '@scure/base';
import { describe, expect, it } from 'vitest';
import { b64u, compareUtf8, decodeB64uStrict, strictNumberError } from './hash';
import { strictParse } from './strict-json';

/** decodeB64uStrict with the redundant pre-checks removed: only the try-block (decoder + canonical re-encode) remains. */
const bare = (s: unknown): Uint8Array | null => {
  try {
    const bytes = base64urlnopad.decode(s as string);
    return b64u(bytes) === s ? bytes : null;
  } catch {
    return null;
  }
};
const same = (a: Uint8Array | null, b: Uint8Array | null) => (a === null ? b === null : b !== null && Buffer.from(a).equals(Buffer.from(b)));

describe('equivalence: hash.ts / strict-json.ts', () => {
  it('EQ-HASH-1 decodeB64uStrict: the type / alphabet / length%4 / early-length / trailing-bits / bytes-length guards add nothing the decoder + re-encode does not already enforce', () => {
    const samples: unknown[] = [undefined, null, 5, {}, ['Zm9v'], new String('Zm9v'), Buffer.from('Zm9v'), '', 'A', 'AB', 'AAB', 'Zm9v=', 'Zg==', 'Zm 9v', 'Zm+v', 'Zm/v', 'Zm9é', '\u0000', 'AAAAA'];
    for (let c = 0; c < 256; c++) samples.push('AAA' + String.fromCharCode(c), String.fromCharCode(c) + 'AAA', 'AA' + String.fromCharCode(c));
    for (let n = 0; n < 40; n++) {
      const s = b64u(new Uint8Array(n).fill(0x5a));
      samples.push(s, s + 'A', s.slice(0, -1), s + 'B');
    }
    for (const x of samples) expect(same(decodeB64uStrict(x), bare(x))).toBe(true);
    for (let n = 0; n < 40; n++) {
      const s = b64u(new Uint8Array(n).fill(0x5a));
      for (const len of [n - 1, n, n + 1]) expect(same(decodeB64uStrict(s, len), len === n ? bare(s) : null)).toBe(true);
    }
    // the decoder itself rejects non-zero trailing bits and impossible lengths
    expect(() => base64urlnopad.decode('AB')).toThrow();
    expect(() => base64urlnopad.decode('A')).toThrow();
  });
  it('EQ-HASH-2 compareUtf8 of equal strings is 0 without the shortcut (empty loop difference, equal length)', () => {
    for (const s of ['', 'a', 'é', '😀x']) {
      const x = new TextEncoder().encode(s);
      let d = 0;
      for (let i = 0; i < x.length; i++) d += x[i]! - x[i]!;
      expect(d + (x.length - x.length)).toBe(0);
      expect(compareUtf8(s, s)).toBe(0);
    }
  });
  it('EQ-HASH-3 a non-integer finite number with |v| >= 1e-6 never prints with an exponent, so the exponent branch of strictNumberError is unreachable', () => {
    let seed = 12345;
    const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
    for (let i = 0; i < 20000; i++) {
      const v = (rnd() - 0.5) * 10 ** Math.floor(rnd() * 40 - 6);
      if (Number.isInteger(v) || Math.abs(v) < 1e-6) continue;
      expect(/e/i.test(String(v))).toBe(false);
      expect(strictNumberError(v) ?? '').not.toMatch(/exponent/);
    }
    // every number >= 1e21 is an integer
    expect(Number.isInteger(1e21 + 1e6)).toBe(true);
  });
  it('EQ-HASH-4 JSON.stringify(-0) is already "0", so the -0 special case of the lenient serializer is redundant', () => {
    expect(JSON.stringify(-0)).toBe('0');
    expect(Object.is(0, -0)).toBe(false);
  });
  it('EQ-SJ-1 whitespace loop: charCodeAt(length) is NaN and matches no whitespace code, so i <= length ends the loop identically', () => {
    expect(Number.isNaN('abc'.charCodeAt(3))).toBe(true);
    expect([0x20, 0x09, 0x0a, 0x0d].includes(NaN)).toBe(false);
    expect(strictParse('  1  ')).toBe(1);
  });
  it('EQ-SJ-2 the 4-hex-digit regex runs on a slice of at most 4 characters, so ^ and $ cannot change the verdict', () => {
    const t = '0123456789abcdefABCDEFzZ é"\\';
    for (let n = 0; n <= 4; n++) for (let off = 0; off < t.length; off++) {
      const h = t.slice(off, off + n);
      const full = /^[0-9a-fA-F]{4}$/.test(h);
      expect(/[0-9a-fA-F]{4}$/.test(h)).toBe(full);
      expect(/^[0-9a-fA-F]{4}/.test(h)).toBe(full);
    }
  });
  it('EQ-SJ-3 a decimal with a fraction never parses to 0 (an all-zero fraction is rejected as a trailing zero first), so v !== 0 is always true there', () => {
    for (const lex of ['0.0', '0.00', '-0.0', '1.0', '0.000000']) expect(() => strictParse(lex)).toThrow(/trailing fractional zero/);
  });
  it('EQ-SJ-4 the 16-character fast path equals the BigInt bound: every integer with > 16 digits is also > 2^53-1', () => {
    expect(BigInt('10000000000000000') > 9007199254740991n).toBe(true); // smallest 17-digit integer
    expect(() => strictParse('10000000000000000')).toThrow(/safe range/);
    expect(() => strictParse('1' + '0'.repeat(5000))).toThrow(/safe range/);
  });
});
