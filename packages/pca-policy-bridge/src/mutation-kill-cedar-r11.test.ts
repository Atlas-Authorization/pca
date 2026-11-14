/**
 * 0.4.2 r11 mutation kills (cedar.ts parseExpr: `if (t.startsWith('(') && matchParen(t, 0) === t.length - 1)`). A single
 * term is unwrapped only when it STARTS with '(' and that paren closes at the very end. A term that merely ENDS with the
 * paren matching index 0 (here a junk left-hand side whose first character is not '(') must stay one atom - and that atom is
 * outside the subset (`Zcontext.a` is not a path), so the policy is skipped. Unwrapping it would drop the first and last
 * characters and translate `context.a == (X::"q"` into a condition the policy never stated.
 */
import { describe, expect, it } from 'vitest';
import { translateCedar } from './cedar';
const cedarToPca = (text: string) => translateCedar(text, false); // structure tests: bare expressions, no error guards


describe('r11: only a fully-enclosing parenthesis is stripped from a single term', () => {
  it('a term that does not start with "(" is not unwrapped', () => {
    const r = cedarToPca('permit(principal, action, resource) when { Zcontext.a == (X::"q") };');
    expect(r.predicates).toEqual([]);
    expect(r.denies).toEqual([]);
    expect(r.report.skipped.length + r.report.errors.length).toBeGreaterThan(0);
  });
  it('control: the well-formed condition (with and without enclosing parens) translates', () => {
    const a = cedarToPca('permit(principal, action, resource) when { context.a == X::"q" };');
    const b = cedarToPca('permit(principal, action, resource) when { (context.a == X::"q") };');
    expect(a.predicates.length).toBe(1);
    expect(b.predicates).toEqual(a.predicates);
  });
});
