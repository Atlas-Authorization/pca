/**
 * r13 mutation kills for catalog.ts. BUILTIN_ACTIONS and DEFAULT_CATALOG are built at module load, so every literal in the
 * built-in table is a static mutant: each test re-evaluates the module (vi.resetModules + dynamic import) and pins the exact
 * catalog contents, the defineAction validation (bounds and messages) and the catalog lookups.
 */
import { describe, expect, it, vi } from 'vitest';

/** Capture an outcome so a thrown error is compared (name + message) instead of failing the test as an error. */
type Settled<T> = { ok: true; value: T } | { ok: false; error: { name: string; message: string } };
function settle<T>(f: () => T): Settled<T> {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    const x = e as Error;
    return { ok: false, error: { name: x?.name, message: x?.message } };
  }
}
const ok = <T>(value: T) => ({ ok: true as const, value });

async function fresh() {
  vi.resetModules();
  return import('./catalog');
}

// The pinned built-in table. The rows are DERIVED from the reviewed action definitions (`@atlasauth/pca-actions`) and written by
// its generator; this literal is the independent pin of what that derivation yields (class and blast are the effective values:
// declared joined with the trait floors; a refund and a charge are irreversible; aliases and the trait closure ride along).
const expected = [
  { connector: "stripe", action: "charge", verb: "stripe.charge", reversibility: "irreversible", blastRadius: 0.9, amountField: "amount", description: "Charge a customer. Refundable in practice, but a charge is treated as final.", aliases: ["bill","charge_customer"], traits: ["pca.irreversible","pca.money_moving"] },
  { connector: "stripe", action: "refund", verb: "stripe.refund", reversibility: "irreversible", blastRadius: 0.9, amountField: "amount", description: "Returns money for a charge to the customer.", aliases: ["issue_refund","refund","refund_charge","reimburse"], traits: ["pca.irreversible","pca.money_moving"] },
  { connector: "stripe", action: "payout", verb: "stripe.payout", reversibility: "irreversible", blastRadius: 0.9, amountField: "amount", description: "Moves funds from a Stripe balance to a bank account.", aliases: ["pay_out","payout"], traits: ["pca.irreversible","pca.money_moving"] },
  { connector: "stripe", action: "create_customer", verb: "stripe.create_customer", reversibility: "rate_limited", blastRadius: 0.2, description: "Creates a customer record.", traits: ["pca.pii_access"] },
  { connector: "gmail", action: "send", verb: "gmail.send", reversibility: "irreversible", blastRadius: 0.8, description: "Sends an email to people outside your organisation.", aliases: ["send_email"], traits: ["pca.external_communication","pca.irreversible","pca.pii_access"] },
  { connector: "gmail", action: "draft", verb: "gmail.draft", reversibility: "reversible", blastRadius: 0.2, description: "Saves an email draft without sending it.", traits: ["pca.pii_access"] },
  { connector: "gmail", action: "delete", verb: "gmail.delete", reversibility: "irreversible", blastRadius: 0.8, description: "Permanently deletes a message.", traits: ["pca.destructive","pca.irreversible"] },
  { connector: "github", action: "read", verb: "github.read", reversibility: "reversible", blastRadius: 0.05, description: "Reads files from a repository.", traits: [] },
  { connector: "github", action: "create_pr", verb: "github.create_pr", reversibility: "irreversible", blastRadius: 0.2, description: "Opens a pull request, which is visible to everyone with access to the repository.", traits: ["pca.external_communication","pca.irreversible"] },
  { connector: "github", action: "comment", verb: "github.comment", reversibility: "irreversible", blastRadius: 0.2, description: "Posts a comment, visible to everyone with access to the repository.", traits: ["pca.external_communication","pca.irreversible"] },
  { connector: "github", action: "merge_pr", verb: "github.merge_pr", reversibility: "irreversible", blastRadius: 0.5, description: "Merges a pull request, which can trigger deploys and other downstream effects.", traits: ["pca.irreversible"] },
  { connector: "github", action: "delete_repo", verb: "github.delete_repo", reversibility: "irreversible", blastRadius: 0.8, description: "Deletes a repository and everything in it.", traits: ["pca.destructive","pca.irreversible"] },
  { connector: "slack", action: "post_message", verb: "slack.post_message", reversibility: "irreversible", blastRadius: 0.5, description: "Posts a message that members of the channel can read.", traits: ["pca.bulk","pca.external_communication","pca.irreversible"] },
  { connector: "slack", action: "read", verb: "slack.read", reversibility: "reversible", blastRadius: 0.05, description: "Reads the message history of a channel.", traits: [] },
  { connector: "calendar", action: "create_event", verb: "calendar.create_event", reversibility: "irreversible", blastRadius: 0.2, description: "Creates an event and sends invitations to its attendees.", traits: ["pca.external_communication","pca.irreversible","pca.pii_access"] },
  { connector: "calendar", action: "delete_event", verb: "calendar.delete_event", reversibility: "rate_limited", blastRadius: 0.5, description: "Deletes a calendar event.", traits: ["pca.destructive"] },
  { connector: "files", action: "read", verb: "files.read", reversibility: "reversible", blastRadius: 0.05, description: "Reads files.", traits: ["pca.bulk"] },
  { connector: "files", action: "write", verb: "files.write", reversibility: "rate_limited", blastRadius: 0.5, description: "Writes or overwrites files.", traits: ["pca.bulk"] },
  { connector: "files", action: "delete", verb: "files.delete", reversibility: "irreversible", blastRadius: 0.8, description: "Deletes files.", traits: ["pca.bulk","pca.destructive","pca.irreversible"] },
  { connector: "http", action: "get", verb: "http.get", reversibility: "reversible", blastRadius: 0.05, description: "Fetches a URL.", traits: ["pca.bulk","pca.network_egress"] },
  { connector: "http", action: "post", verb: "http.post", reversibility: "rate_limited", blastRadius: 0.5, description: "Posts a body to a URL.", traits: ["pca.bulk","pca.network_egress"] },
];

describe('catalog: built-in table (fresh module)', () => {
  it('BUILTIN_ACTIONS is exactly the documented table', async () => {
    const c = await fresh();
    expect(c.BUILTIN_ACTIONS).toStrictEqual(expected);
  });
  it('DEFAULT_CATALOG serves every built-in by verb, by connector and in full', async () => {
    const c = await fresh();
    expect(c.DEFAULT_CATALOG.all()).toStrictEqual(expected);
    for (const e of expected) expect(c.DEFAULT_CATALOG.get(e.verb)).toStrictEqual(e);
    expect(c.DEFAULT_CATALOG.forConnector('stripe').map((a) => a.verb)).toStrictEqual([
      'stripe.charge', 'stripe.refund', 'stripe.payout', 'stripe.create_customer',
    ]);
    expect(c.DEFAULT_CATALOG.forConnector('slack').map((a) => a.verb)).toStrictEqual(['slack.post_message', 'slack.read']);
    expect(c.DEFAULT_CATALOG.forConnector('nope')).toStrictEqual([]);
    expect(c.DEFAULT_CATALOG.get('nope.x')).toBeUndefined();
  });
});

describe('catalog: defineAction validation (fresh module)', () => {
  const base = { connector: 'acme', action: 'do', reversibility: 'reversible' as const, blastRadius: 0.3, description: 'd' };
  it('missing connector or action is refused with the exact message', async () => {
    const c = await fresh();
    expect(() => c.defineAction({ ...base, connector: '' })).toThrow(new Error('defineAction: connector and action are required'));
    expect(() => c.defineAction({ ...base, action: '' })).toThrow(new Error('defineAction: connector and action are required'));
  });
  it('every reversibility class is accepted; anything else is refused by name', async () => {
    const c = await fresh();
    for (const r of ['reversible', 'rate_limited', 'irreversible'] as const) {
      expect(settle(() => c.defineAction({ ...base, reversibility: r }))).toEqual(ok({ ...base, reversibility: r, verb: 'acme.do' }));
    }
    expect(() => c.defineAction({ ...base, reversibility: 'maybe' as never })).toThrow(new Error("defineAction: bad reversibility 'maybe'"));
  });
  it('blastRadius must be a number in the closed interval [0,1]', async () => {
    const c = await fresh();
    expect(settle(() => c.defineAction({ ...base, blastRadius: 0 }))).toEqual(ok({ ...base, blastRadius: 0, verb: 'acme.do' }));
    expect(settle(() => c.defineAction({ ...base, blastRadius: 1 }))).toEqual(ok({ ...base, blastRadius: 1, verb: 'acme.do' }));
    const msg = new Error('defineAction: blastRadius must be in [0,1]');
    expect(() => c.defineAction({ ...base, blastRadius: -0.1 })).toThrow(msg);
    expect(() => c.defineAction({ ...base, blastRadius: -1 })).toThrow(msg);
    expect(() => c.defineAction({ ...base, blastRadius: 1.01 })).toThrow(msg);
    expect(() => c.defineAction({ ...base, blastRadius: '0.5' as never })).toThrow(msg);
  });
  it('verb defaults to connector.action and an explicit verb is kept', async () => {
    const c = await fresh();
    expect(c.defineAction(base)).toStrictEqual({ ...base, verb: 'acme.do' });
    expect(c.defineAction({ ...base, verb: 'x.y' }).verb).toBe('x.y');
  });
  it('buildCatalog: later specs override earlier ones by verb; forConnector filters', async () => {
    const c = await fresh();
    const a = c.defineAction(base);
    const b = c.defineAction({ ...base, description: 'second' });
    const o = c.defineAction({ ...base, connector: 'other' });
    const cat = c.buildCatalog([a, o, b]);
    expect(cat.all()).toStrictEqual([b, o]);
    expect(cat.get('acme.do')).toBe(b);
    expect(cat.forConnector('acme')).toStrictEqual([b]);
    expect(cat.forConnector('other')).toStrictEqual([o]);
  });
});
