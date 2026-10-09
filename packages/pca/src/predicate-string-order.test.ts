/**
 * T-044 / T-045: string order in the lt / lte / gt / gte predicates is the byte-wise order of the UTF-8 encoding
 * (== Unicode code point order). It is NOT UTF-16 code-unit order (what JavaScript `<` gives), NOT normalised, NOT
 * locale-aware. The vectors are shared with the Rust predicate engine (sdks/zkvm-pca/core/tests/predicate_string_order.rs)
 * so both implementations are held to one table.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { evaluateCondition, evaluatePredicates, type ActionContext, type Condition, type Predicate } from './predicates';

interface Vec {
  name: string;
  a: string;
  b: string;
  cmp: -1 | 0 | 1;
}
const VECTORS = (JSON.parse(readFileSync(resolve(__dirname, '..', '..', 'pca-conformance', 'predicate-string-order.json'), 'utf8')) as { vectors: Vec[] }).vectors;

const ctxOf = (s: unknown): ActionContext => ({ action: { verb: 'v', resource: '/r', params: { s } }, subject: {}, env: {} });
const holds = (op: 'lt' | 'lte' | 'gt' | 'gte', field: unknown, operand: unknown): boolean => evaluateCondition({ field: 'action.params.s', op, value: operand } as Condition, ctxOf(field));

describe('predicate string order = UTF-8 byte order (code point order)', () => {
  it('the shared table is non-trivial', () => {
    expect(VECTORS.length).toBeGreaterThanOrEqual(20);
    expect(VECTORS.some((v) => v.cmp === 1)).toBe(true);
    expect(VECTORS.some((v) => v.cmp === -1)).toBe(true);
  });
  for (const v of VECTORS) {
    it(`${v.name}: field=a operand=b`, () => {
      expect(holds('lt', v.a, v.b)).toBe(v.cmp < 0);
      expect(holds('lte', v.a, v.b)).toBe(v.cmp <= 0);
      expect(holds('gt', v.a, v.b)).toBe(v.cmp > 0);
      expect(holds('gte', v.a, v.b)).toBe(v.cmp >= 0);
    });
    it(`${v.name}: agrees with Buffer byte order`, () => {
      expect(Buffer.compare(Buffer.from(v.a, 'utf8'), Buffer.from(v.b, 'utf8'))).toBe(v.cmp);
    });
  }
  it('the astral/BMP split is exactly the case JavaScript < gets wrong (U+FFFF vs U+10000)', () => {
    expect('￿' < '\u{10000}').toBe(false); // UTF-16 code-unit order (the bug)
    expect(holds('lt', '￿', '\u{10000}')).toBe(true); // required: U+FFFF < U+10000
    expect(holds('gt', '\u{1f600}', '')).toBe(true);
  });
  it('is not normalised: canonically-equivalent NFC / NFD strings are unequal and ordered by bytes', () => {
    expect(holds('gt', 'é', 'é')).toBe(true);
    expect(holds('lte', 'é', 'é')).toBe(false);
    expect(holds('gte', 'é', 'é'.normalize('NFC'))).toBe(true);
  });
  it('a LONE surrogate has no UTF-8 encoding: the comparison has no order, so every ordering op is false (fail closed)', () => {
    const lone = '\ud800';
    for (const op of ['lt', 'lte', 'gt', 'gte'] as const) {
      expect(holds(op, lone, 'a')).toBe(false);
      expect(holds(op, 'a', lone)).toBe(false);
      expect(holds(op, lone, lone)).toBe(false);
      expect(holds(op, 'x\udc00y', 'xyz')).toBe(false);
      expect(holds(op, 'a\ud800', '\ud800')).toBe(false);
    }
  });
  it('a well-formed surrogate PAIR is one code point (not two lone halves)', () => {
    expect(holds('lt', '😀', '😁')).toBe(true);
  });
  it('mixed types and non-finite numbers still have no order', () => {
    expect(holds('lt', 'a', 5)).toBe(false);
    expect(holds('lt', 5, 'a')).toBe(false);
    expect(holds('gt', Number.POSITIVE_INFINITY, 1)).toBe(false);
  });
  it('end to end through evaluatePredicates: a policy bounding a string field by code point', () => {
    const p: Predicate[] = [{ verb: 'v', resource: '/r', where: [{ field: 'action.params.s', op: 'lt', value: '\u{10000}' }] }];
    expect(evaluatePredicates(p, ctxOf('￿')).allowed).toBe(true);
    expect(evaluatePredicates(p, ctxOf('\u{10001}')).allowed).toBe(false);
  });
});
