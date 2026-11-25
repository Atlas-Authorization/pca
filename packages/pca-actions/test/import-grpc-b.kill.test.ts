// Descriptor-set decoding: unknown fields must be skipped by their declared length, never re-read as known fields.
import { describe, expect, it } from 'vitest';
import { parseDescriptorSet } from '../src';

const vi = (n: number): number[] => { const o: number[] = []; let v = n; while (v >= 128) { o.push((v % 128) | 128); v = Math.floor(v / 128); } o.push(v); return o; };
const tg = (f: number, wt: number): number[] => vi(f * 8 + wt);
const ld = (f: number, b: number[]): number[] => [...tg(f, 2), ...vi(b.length), ...b];
const S = (f: number, s: string): number[] => ld(f, [...new TextEncoder().encode(s)]);
const I = (f: number, n: number): number[] => [...tg(f, 0), ...vi(n)];

describe('descriptor set: unknown length-delimited fields hide their payload', () => {
  // each unknown field carries bytes that would parse as a real field (a name, a package) if they were not skipped whole
  const field = [...S(1, 'real'), ...ld(99, S(1, 'zz')), ...I(5, 9)];
  const message = [...S(1, 'M'), ...ld(2, field)];
  const file = [...S(2, 'pk'), ...ld(99, S(2, 'zz')), ...ld(4, message)];
  const m = parseDescriptorSet(Uint8Array.from(ld(1, file)));

  it('an unknown field inside a file does not rename the package', () => {
    expect([...m.messages.keys()]).toEqual(['pk.M']);
  });
  it('an unknown field inside a field descriptor does not rename the field', () => {
    expect(m.messages.get('pk.M')!.fields).toEqual([{ name: 'real', scope: 'pk.M', repeated: false, optional: false, type: 'string', behavior: [] }]);
  });
});
