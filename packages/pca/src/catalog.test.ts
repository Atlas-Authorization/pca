import { describe, expect, it } from 'vitest';
import { BUILTIN_ACTIONS, DEFAULT_CATALOG, buildCatalog, defineAction } from './catalog';

describe('catalog', () => {
  it('resolves built-in actions by verb and connector', () => {
    expect(DEFAULT_CATALOG.get('stripe.refund')?.reversibility).toBe('rate_limited');
    expect(DEFAULT_CATALOG.get('gmail.send')?.reversibility).toBe('irreversible');
    expect(DEFAULT_CATALOG.get('stripe.refund')?.amountField).toBe('amount');
    expect(DEFAULT_CATALOG.forConnector('github').length).toBeGreaterThan(1);
    expect(DEFAULT_CATALOG.get('nope.nope')).toBeUndefined();
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
