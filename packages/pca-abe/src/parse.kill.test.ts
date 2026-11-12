import { describe, expect, it } from 'vitest';
import { ABE_ALG, parseCiphertext } from './abe';
import { MAX_POLICY_DEPTH, MAX_POLICY_NODES } from './policy';

const B = 'AAAA';
const tri = (): [string, string, string] => [B, B, B];
const leaf = (attr: string) => ({ kind: 'leaf', attr });
const gate = (t: number, of: unknown[]) => ({ kind: 'gate', t, of });
const mk = (tree: unknown, nRows: number, over: Record<string, unknown> = {}): Record<string, unknown> => ({
  v: 2, alg: ABE_ALG, salt: B, ct0: tri(), tree, rows: Array.from({ length: nRows }, tri), iv: B, ct: B, tag: B, ...over,
});
const ok = (x: unknown) => parseCiphertext(x) !== null;
const nest = (d: number): unknown => (d === 0 ? leaf('a') : gate(1, [nest(d - 1)]));
const wide = (n: number): unknown => gate(1, Array.from({ length: n }, (_, i) => leaf(`a${i}`)));

describe('parseCiphertext envelope', () => {
  it('accepts a well-formed ciphertext and returns exactly its fields', () => {
    const x = mk(leaf('a'), 1);
    expect(parseCiphertext(x)).toEqual(x);
  });
  it('refuses a wrong version, algorithm or non-object', () => {
    for (const bad of [null, 5, 'x', [], mk(leaf('a'), 1, { v: 3 }), mk(leaf('a'), 1, { alg: 'other' })]) expect(parseCiphertext(bad)).toBeNull();
  });
  it('each of salt, iv, ct, tag must be present, a string and base64url', () => {
    for (const k of ['salt', 'iv', 'ct', 'tag']) {
      for (const v of [undefined, 5, '!', 'AAA=']) expect(parseCiphertext(mk(leaf('a'), 1, { [k]: v }))).toBeNull();
      expect(ok(mk(leaf('a'), 1, { [k]: '' }))).toBe(true);
    }
  });
  it('ct0 must be exactly three base64url strings', () => {
    for (const v of [undefined, 'x', [B, B], [B, B, B, B], [B, B, 5], [B, B, '!'], ['!', B, B], [B, '!', B], [5, B, B]]) expect(parseCiphertext(mk(leaf('a'), 1, { ct0: v }))).toBeNull();
  });
  it('rows must be an array with one base64url triple per leaf', () => {
    expect(parseCiphertext(mk(leaf('a'), 1, { rows: 'x' }))).toBeNull();
    expect(parseCiphertext(mk(leaf('a'), 0))).toBeNull();
    expect(parseCiphertext(mk(leaf('a'), 2))).toBeNull();
    expect(parseCiphertext(mk(leaf('a'), 1, { rows: [[B, B]] }))).toBeNull();
    expect(parseCiphertext(mk(leaf('a'), 1, { rows: [[B, B, B, B]] }))).toBeNull();
    expect(parseCiphertext(mk(leaf('a'), 1, { rows: [[B, '!', B]] }))).toBeNull();
    expect(parseCiphertext(mk(leaf('a'), 1, { rows: [[B, B, 5]] }))).toBeNull();
    expect(parseCiphertext(mk(gate(2, [leaf('a'), leaf('b')]), 2, { rows: [tri(), [B, B, '!']] }))).toBeNull();
  });
});

describe('parseCiphertext tree', () => {
  it('a leaf needs a non-empty well-formed string attr and nothing else', () => {
    for (const t of [{ kind: 'leaf' }, { kind: 'leaf', attr: 5 }, { kind: 'leaf', attr: '' }, { kind: 'leaf', attr: 'a\ud800' }, { kind: 'leaf', attr: 'a', extra: 1 }, { kind: 'leaf', attr: 'a', t: 1 }]) {
      expect(parseCiphertext(mk(t, 1))).toBeNull();
    }
  });
  it('an unknown node kind is refused, even shaped like a gate', () => {
    expect(parseCiphertext(mk({ kind: 'foo', t: 1, of: [leaf('a')] }, 1))).toBeNull();
    expect(parseCiphertext(mk({ t: 1, of: [leaf('a')] }, 1))).toBeNull();
    expect(parseCiphertext(mk([leaf('a')], 1))).toBeNull();
  });
  it('a gate needs exactly kind, t and of; t a positive integer within the branch count; of a non-empty array', () => {
    const g = (over: Record<string, unknown>) => ({ kind: 'gate', t: 1, of: [leaf('a')], ...over });
    expect(ok(mk(g({}), 1))).toBe(true);
    for (const over of [{ t: 0 }, { t: -1 }, { t: 1.5 }, { t: '1' }, { t: undefined }, { t: 2 }, { of: [] }, { of: 'a' }, { of: { length: 2 } }, { of: undefined }, { extra: 1 }]) {
      expect(parseCiphertext(mk(g(over), 1))).toBeNull();
    }
    expect(parseCiphertext(mk({ kind: 'gate', of: [leaf('a')] }, 1))).toBeNull();
    expect(parseCiphertext(mk({ kind: 'gate', t: 1, of: [leaf('a')], x: 1, y: 2 }, 1))).toBeNull();
  });
  it('a bad child anywhere refuses the whole tree', () => {
    expect(parseCiphertext(mk(gate(1, [leaf('a'), leaf('')]), 2))).toBeNull();
    expect(parseCiphertext(mk(gate(1, [leaf('a'), 5]), 2))).toBeNull();
    expect(parseCiphertext(mk(gate(2, [leaf('a'), gate(1, [{ kind: 'leaf', attr: '' }])]), 2))).toBeNull();
  });
  it('an attribute named by two leaves is refused', () => {
    expect(parseCiphertext(mk(gate(2, [leaf('a'), leaf('a')]), 2))).toBeNull();
    expect(ok(mk(gate(2, [leaf('a'), leaf('b')]), 2))).toBe(true);
  });
  it('the gate depth bound is exact', () => {
    expect(ok(mk(nest(MAX_POLICY_DEPTH), 1))).toBe(true);
    expect(parseCiphertext(mk(nest(MAX_POLICY_DEPTH + 1), 1))).toBeNull();
  });
  it('the node bound is exact', () => {
    expect(ok(mk(wide(MAX_POLICY_NODES - 1), MAX_POLICY_NODES - 1))).toBe(true);
    expect(parseCiphertext(mk(gate(1, [wide(MAX_POLICY_NODES - 1)]), MAX_POLICY_NODES - 1))).toBeNull();
    expect(parseCiphertext(mk(wide(MAX_POLICY_NODES), MAX_POLICY_NODES))).toBeNull();
  });
});
