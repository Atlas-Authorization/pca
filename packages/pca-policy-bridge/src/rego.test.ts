import { describe, expect, it } from 'vitest';
import { evaluatePredicates, type ActionContext } from '@atlasauth/pca';
import { regoToPca } from './rego';

const allow = (preds: Parameters<typeof evaluatePredicates>[0], ctx: ActionContext) =>
  evaluatePredicates(preds, ctx).allowed;

describe('regoToPca', () => {
  const mod = `
    package authz

    default allow = false

    # read a specific doc
    allow {
      input.action == "read"
      input.resource == "doc1"
    }

    # admins can do anything
    allow {
      input.role == "admin"
    }

    # list/watch for sufficiently high tier
    allow {
      input.action in {"list", "watch"}
      input.tier >= 3
    }
  `;

  it('translates allow rules into OR-ed predicates', () => {
    const { predicates, report } = regoToPca(mod);
    expect(report.errors).toEqual([]);
    expect(predicates.length).toBe(3);

    // rule 1: read doc1
    expect(allow(predicates, { action: { verb: 'read', resource: 'doc1' } })).toBe(true);
    expect(allow(predicates, { action: { verb: 'read', resource: 'doc2' } })).toBe(false);
  });

  it('honours the admin catch-all rule', () => {
    const { predicates } = regoToPca(mod);
    expect(allow(predicates, { action: { verb: 'anything', resource: 'r' }, env: { role: 'admin' } })).toBe(true);
    expect(allow(predicates, { action: { verb: 'anything', resource: 'r' }, env: { role: 'viewer' } })).toBe(false);
  });

  it('handles `in` set membership and numeric comparison', () => {
    const { predicates } = regoToPca(mod);
    expect(allow(predicates, { action: { verb: 'list', resource: 'r' }, env: { tier: 5 } })).toBe(true);
    expect(allow(predicates, { action: { verb: 'watch', resource: 'r' }, env: { tier: 3 } })).toBe(true);
    // tier too low
    expect(allow(predicates, { action: { verb: 'list', resource: 'r' }, env: { tier: 1 } })).toBe(false);
    // verb not in the set
    expect(allow(predicates, { action: { verb: 'delete', resource: 'r' }, env: { tier: 9 } })).toBe(false);
  });

  it('drops an entire rule containing an unmodeled construct (fail closed)', () => {
    const m = `
      package authz
      default allow = false
      allow {
        count(input.items) > 0
      }
      allow {
        input.action == "ping"
      }
    `;
    const { predicates, report } = regoToPca(m);
    // only the ping rule survives; the count(...) rule is dropped
    expect(predicates.length).toBe(1);
    expect(report.skipped.some((s) => s.includes('count'))).toBe(true);
    expect(allow(predicates, { action: { verb: 'ping', resource: 'r' } })).toBe(true);
    // the dropped rule grants nothing
    expect(allow(predicates, { action: { verb: 'whatever', resource: 'r' }, env: { items: [1, 2] } })).toBe(false);
  });

  it('still drops BARE-truthiness negation `not input.flag` (fail closed)', () => {
    const m = `
      package authz
      default allow = false
      allow {
        not input.banned
      }
    `;
    const { predicates, report } = regoToPca(m);
    expect(predicates).toEqual([]);
    expect(report.skipped.length).toBeGreaterThan(0);
  });

  it('translates `not <comparison>` to a `not` grouping', () => {
    const m = `
      package authz
      default allow = false
      allow {
        input.action == "read"
        not input.classification == "secret"
      }
    `;
    const { predicates, report } = regoToPca(m);
    expect(report.errors).toEqual([]);
    expect(predicates.length).toBe(1);
    expect(allow(predicates, { action: { verb: 'read', resource: 'r' }, env: { classification: 'public' } })).toBe(true);
    expect(allow(predicates, { action: { verb: 'read', resource: 'r' }, env: { classification: 'secret' } })).toBe(false);
    // classification unknown => `not` fails closed (does not grant)
    expect(allow(predicates, { action: { verb: 'read', resource: 'r' } })).toBe(false);
  });

  it('translates pure anchored matcher builtins: startswith → prefix, glob.match → like', () => {
    const m = `
      package authz
      default allow = false
      allow {
        input.action == "get"
        startswith(input.path, "/public/")
      }
      allow {
        input.action == "open"
        glob.match("*.pdf", [], input.name)
      }
    `;
    const { predicates, report } = regoToPca(m);
    expect(report.errors).toEqual([]);
    expect(predicates.length).toBe(2);
    expect(allow(predicates, { action: { verb: 'get', resource: 'r' }, env: { path: '/public/x' } })).toBe(true);
    expect(allow(predicates, { action: { verb: 'get', resource: 'r' }, env: { path: '/private/x' } })).toBe(false);
    expect(allow(predicates, { action: { verb: 'open', resource: 'r' }, env: { name: 'a.pdf' } })).toBe(true);
    expect(allow(predicates, { action: { verb: 'open', resource: 'r' }, env: { name: 'a.txt' } })).toBe(false);
  });

  it('still fails closed on regex.match (unanchored) and glob character classes', () => {
    const m = `
      package authz
      default allow = false
      allow { regex.match("^/x/", input.path) }
      allow { glob.match("f[0-9].txt", [], input.name) }
    `;
    const { predicates, report } = regoToPca(m);
    expect(predicates).toEqual([]);
    expect(report.skipped.length).toBeGreaterThan(0);
  });

  it('reports `default allow = true` and does not emit a blanket allow', () => {
    const m = `
      package authz
      default allow = true
      allow { input.action == "x" }
    `;
    const { predicates, report } = regoToPca(m);
    expect(report.skipped.some((s) => s.includes('default allow = true'))).toBe(true);
    // no catch-all: only the explicit x rule is a predicate
    expect(predicates.length).toBe(1);
    expect(allow(predicates, { action: { verb: 'y', resource: 'r' } })).toBe(false);
  });
});
