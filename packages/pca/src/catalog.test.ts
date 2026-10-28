import { describe, expect, it } from 'vitest';
import { BUILTIN_ACTIONS, DEFAULT_CATALOG, buildCatalog, defineAction } from './catalog';

describe('catalog', () => {
  it('resolves built-in actions by verb and connector', () => {
    // one definition: a refund is a new payment, not an undo, so the catalog and the Goal IR ontology agree on irreversible
    expect(DEFAULT_CATALOG.get('stripe.refund')?.reversibility).toBe('irreversible');
    expect(DEFAULT_CATALOG.get('stripe.charge')?.reversibility).toBe('irreversible');
    expect(DEFAULT_CATALOG.get('slack.post_message')?.reversibility).toBe('irreversible');
    expect(DEFAULT_CATALOG.get('gmail.send')?.reversibility).toBe('irreversible');
    expect(DEFAULT_CATALOG.get('stripe.refund')?.amountField).toBe('amount');
    expect(DEFAULT_CATALOG.forConnector('github').length).toBeGreaterThan(1);
    expect(DEFAULT_CATALOG.get('nope.nope')).toBeUndefined();
  });

  it('resolves an alias of exactly one action of the connector, never a guess', () => {
    expect(DEFAULT_CATALOG.resolve?.('stripe', 'issue_refund')?.verb).toBe('stripe.refund');
    expect(DEFAULT_CATALOG.resolve?.('stripe', 'refund')?.verb).toBe('stripe.refund');
    expect(DEFAULT_CATALOG.resolve?.('gmail', 'send_email')?.verb).toBe('gmail.send');
    expect(DEFAULT_CATALOG.resolve?.('gmail', 'issue_refund')).toBeUndefined();
    const twice = buildCatalog([
      defineAction({ connector: 'x', action: 'a', reversibility: 'reversible', blastRadius: 0.1, description: '', aliases: ['same'] }),
      defineAction({ connector: 'x', action: 'b', reversibility: 'reversible', blastRadius: 0.1, description: '', aliases: ['same'] }),
    ]);
    expect(twice.resolve?.('x', 'same')).toBeUndefined();
  });

  it('every built-in has a well-formed blast radius and known reversibility', () => {
    for (const a of BUILTIN_ACTIONS) {
      expect(a.blastRadius).toBeGreaterThanOrEqual(0);
      expect(a.blastRadius).toBeLessThanOrEqual(1);
      expect(['reversible', 'rate_limited', 'irreversible']).toContain(a.reversibility);
      expect(a.verb).toBe(`${a.connector}.${a.action}`);
    }
  });

  it('defineAction validates shape', () => {
    expect(() => defineAction({ connector: '', action: 'x', reversibility: 'reversible', blastRadius: 0.1, description: '' })).toThrow();
    // @ts-expect-error bad reversibility
    expect(() => defineAction({ connector: 'c', action: 'x', reversibility: 'maybe', blastRadius: 0.1, description: '' })).toThrow();
    expect(() => defineAction({ connector: 'c', action: 'x', reversibility: 'reversible', blastRadius: 2, description: '' })).toThrow();
    const ok = defineAction({ connector: 'notion', action: 'create_page', reversibility: 'reversible', blastRadius: 0.2, description: 'x' });
    expect(ok.verb).toBe('notion.create_page');
  });

  it('buildCatalog lets a custom action extend/override the built-ins', () => {
    const custom = defineAction({ connector: 'notion', action: 'create_page', reversibility: 'reversible', blastRadius: 0.2, description: 'x' });
    const cat = buildCatalog([...BUILTIN_ACTIONS, custom]);
    expect(cat.get('notion.create_page')).toBeDefined();
    // later entry wins by verb
    const override = defineAction({ connector: 'gmail', action: 'send', reversibility: 'reversible', blastRadius: 0.1, description: 'overridden' });
    const cat2 = buildCatalog([...BUILTIN_ACTIONS, override]);
    expect(cat2.get('gmail.send')?.reversibility).toBe('reversible');
  });
});
