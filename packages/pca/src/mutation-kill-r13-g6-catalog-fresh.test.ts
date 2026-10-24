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

type Row = [string, string, string, number, string, Record<string, string>?];
const TABLE: Row[] = [
  ['stripe', 'charge', 'reversible', 0.9, 'Charge a customer (reversible via refund).', { amountField: 'amount' }],
  ['stripe', 'refund', 'rate_limited', 0.9, 'Refund a charge (hard to undo; rate-limit).', { amountField: 'amount' }],
  ['stripe', 'payout', 'irreversible', 0.9, 'Pay out funds to a bank account (irreversible).', { amountField: 'amount' }],
  ['stripe', 'create_customer', 'reversible', 0.2, 'Create a customer record.'],
  ['gmail', 'send', 'irreversible', 0.8, 'Send an email (cannot be unsent).'],
  ['gmail', 'draft', 'reversible', 0.2, 'Create a draft (not sent).'],
  ['gmail', 'delete', 'irreversible', 0.8, 'Permanently delete a message.'],
  ['github', 'read', 'reversible', 0.05, 'Read repository contents.', { resource: '*' }],
  ['github', 'create_pr', 'reversible', 0.2, 'Open a pull request.'],
  ['github', 'comment', 'reversible', 0.2, 'Comment on an issue or PR.'],
  ['github', 'merge_pr', 'rate_limited', 0.5, 'Merge a pull request.'],
  ['github', 'delete_repo', 'irreversible', 0.8, 'Delete a repository (irreversible).'],
  ['slack', 'post_message', 'rate_limited', 0.5, 'Post a message to a channel.'],
  ['slack', 'read', 'reversible', 0.05, 'Read channel history.'],
  ['calendar', 'create_event', 'reversible', 0.2, 'Create a calendar event.'],
  ['calendar', 'delete_event', 'rate_limited', 0.5, 'Delete a calendar event.'],
  ['files', 'read', 'reversible', 0.05, 'Read a file.', { resource: '*' }],
  ['files', 'write', 'rate_limited', 0.5, 'Write/overwrite a file.'],
  ['files', 'delete', 'irreversible', 0.8, 'Delete a file (irreversible).'],
  ['http', 'get', 'reversible', 0.05, 'HTTP GET (read-only).', { resource: '*' }],
  ['http', 'post', 'rate_limited', 0.5, 'HTTP POST (side-effecting).'],
];
const expected = TABLE.map(([connector, action, reversibility, blastRadius, description, extra]) => ({
  connector, action, verb: `${connector}.${action}`, reversibility, blastRadius, description, ...(extra ?? {}),
}));

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
