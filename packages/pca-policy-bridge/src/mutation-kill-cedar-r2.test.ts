/**
 * Round-2 adversarial kills (cedar.ts). The ledger called these regex anchors redundant "because statements are
 * trimmed", but `\S*` (and an unanchored `.+`) also match NON-whitespace prefixes. Without them a malformed
 * statement such as `xpermit(...)` would be translated as a wildcard permit instead of being skipped.
 */
import { describe, expect, it } from 'vitest';
import { translateCedar } from './cedar';
const cedarToPca = (text: string) => translateCedar(text, false); // structure tests: bare expressions, no error guards


describe('r2: malformed statement heads are skipped, never translated', () => {
  it('a junk prefix before permit/forbid does not yield a grant', () => {
    for (const s of ['xpermit(principal, action, resource);', 'forbidpermit(principal, action, resource);', 'x@id("a")permit(principal, action, resource);', 'junk@id("a") permit(principal, action, resource);']) {
      const r = cedarToPca(s);
      expect(r.predicates).toEqual([]);
      expect(r.denies).toEqual([]);
      expect(r.report.skipped.length + r.report.errors.length).toBeGreaterThan(0);
    }
    expect(cedarToPca('@id("a") permit(principal, action, resource);').predicates).toEqual([{ verb: '*' }]);
  });
  it('an entity reference split by a newline is not re-anchored onto its last line', () => {
    const r = cedarToPca('permit(principal, action, resource == Foo\nBar::"p1");');
    expect(r.predicates.some((p) => (p as { resource?: unknown }).resource === 'Bar::p1')).toBe(false);
    const ok = cedarToPca('permit(principal, action, resource == Bar::"p1");');
    expect(ok.predicates).toEqual([{ verb: '*', resource: 'Bar::p1' }]);
  });
});
