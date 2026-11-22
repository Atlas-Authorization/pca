// Two behaviours of the test runner the other tests leave open: a policy that matches nothing grants no pre-authorization, and the
// schema round trip conforms against the derived schema with the fixed example site.
import { describe, expect, it, vi } from 'vitest';

const H = vi.hoisted(() => ({ conform: undefined as undefined | ((...a: unknown[]) => unknown) }));
vi.mock('@atlasauth/pca/ext/intent', async (orig) => {
  const m = await orig<typeof import('@atlasauth/pca/ext/intent')>();
  return { ...m, conformAction: (...a: Parameters<typeof m.conformAction>) => (H.conform ? H.conform(...a) : m.conformAction(...a)) as ReturnType<typeof m.conformAction> };
});

import { CORE_REGISTRY, decideExample, loadActionsText, runDefTests, type ActionDef } from '../src';

const READ = loadActionsText('ns: acme\nactions:\n  - {verb: acme.invoice.get, effects: read, resource: "acme.invoice:inv_*", params: {invoice: "id:acme.invoice"}}\n').defs[0]!;
type Ex = Parameters<typeof decideExample>[1];

describe('the example policy: a policy that matches nothing', () => {
  it('does not pre-authorize: the escalation tier is still what the floor needs', () => {
    H.conform = () => ({ ok: true });
    const d = { ...READ, traits: ['pca.regulated_data'] } as unknown as ActionDef;
    const ex = { params: { invoice: 'inv_12345678' }, under: { allow: { trait: 'bulk' } }, expect: 'allow' } as unknown as Ex;
    expect(decideExample(d, ex, CORE_REGISTRY, [d])).toEqual({ got: 'escalate', why: 'floor needs escalation tier 1' });
    H.conform = undefined;
  });
});

describe('runDefTests: the schema round trip', () => {
  it('every conformance check, the round trip included, uses the derived schema with the fixed example site', () => {
    const docs: unknown[] = [];
    H.conform = (doc: unknown) => { docs.push(doc); return { ok: true }; };
    const d = { ...READ, examples: [{ params: { invoice: 'inv_12345678' }, expect: 'allow' }] } as unknown as ActionDef;
    runDefTests([d], CORE_REGISTRY);
    H.conform = undefined;
    // 6 = decideExample (1) + the round trip's example (1) + 4 mutations of the one id param (extra param, missing, type swap, too long)
    expect(docs).toHaveLength(6);
    for (const doc of docs) expect(doc).toMatchObject({ kind: 'pca-action-schema', site: 'https://example.invalid', aud: 'example', version: '0' });
  });
});
