import { describe, expect, it } from 'vitest';
import { rng } from '@atlasauth/pca-intent';
import { SKY, USD } from './fixtures.test-util';
import { cardDigestMatches, cardText, cleanText, expectedTyped, formatNumber, last4, normalizeTyped, partialError, REASON_LABELS, renderCard, type CardInput, type TrustedCard } from './index';

const base = (over: Partial<CardInput> = {}): CardInput => ({
  omega: SKY,
  verb: 'air.book',
  coords: { 'action.params.add_ons': ['none'], 'action.params.total': [2, 3], 'env.prov.action.params.add_ons': ['trusted|first_party'] },
  site: { origin: 'https://skyair.example', name: 'SkyAir' },
  statementText: 'Book me and Sam a one-way flight SFO to JFK on Nov 20, under $400',
  units: USD,
  action: { verb: 'air.book', values: { 'action.params.add_ons': 'none', 'action.params.total': 77800, 'env.prov.action.params.add_ons': 'trusted|first_party' } },
  friction: 'typed',
  kind: 'question',
  ...over,
});
const card = (over: Partial<CardInput> = {}): TrustedCard => {
  const r = renderCard(base(over));
  if (!r.ok) throw new Error(r.reason);
  return r.card;
};

describe('trusted card rendering (§3.4 item 2)', () => {
  it('renders the walkthrough question from fixed templates', () => {
    const c = card();
    expect(c.header).toBe('SkyAir asks on behalf of your request "Book me and Sam a one-way flight SFO to JFK on Nov 20, under $400"');
    expect(c.sentence).toBe('Allow the action "air.book" on SkyAir, that cannot be undone, with:');
    expect(c.facts.find((f) => f.key === 'action.params.total')!.text).toBe('$400.01 – $800.00 (this action: $778.00)');
    expect(c.facts.find((f) => f.key === 'action.params.add_ons')!.text).toBe('"none" (this action: "none")');
    expect(c.banners).toEqual([]);
    expect(c.typed).toEqual({ path: 'action.params.total', mode: 'number', prompt: 'To allow it, type the total of this action shown above.' });
    expect(c.answers.map((a) => a.id)).toEqual(['no', 'partly', 'yes']);
    expect(cardDigestMatches(c)).toBe(true);
  });
  it('is deterministic and the digest covers every visible field', () => {
    expect(card().rendered_digest).toBe(card().rendered_digest);
    const c = card();
    expect(cardDigestMatches({ ...c, header: c.header + ' ' })).toBe(false);
    expect(cardDigestMatches({ ...c, banners: ['x'] })).toBe(false);
    expect(cardDigestMatches({ ...c, friction: 'tap' })).toBe(false);
  });
  it('shows a provenance banner for a tainted value and the range wording at the domain edges', () => {
    const c = card({ coords: { 'action.params.add_ons': ['tripshield'], 'action.params.total': [4, 4], 'env.prov.action.params.add_ons': ['tool|web|agent'] }, action: { verb: 'air.book', values: { 'action.params.add_ons': 'tripshield', 'action.params.total': 85400 } } });
    expect(c.banners).toEqual(['This add ons was chosen by your agent, not taken from your request or from the site.']);
    expect(c.facts.find((f) => f.key === 'action.params.total')!.text).toBe('$800.01 or more (this action: $854.00)');
    const lo = card({ coords: { 'action.params.add_ons': ['none'], 'action.params.total': [0, 0], 'env.prov.action.params.add_ons': ['trusted|first_party'] } });
    expect(lo.facts.find((f) => f.key === 'action.params.total')!.text).toBe('up to $399.99 (this action: $778.00)');
  });
  it('a clarification card carries the fixed reason label and needs a reason', () => {
    const c = card({ kind: 'clarification', reason: 'multiple_options' });
    expect(c.reason_label).toBe(REASON_LABELS.multiple_options);
    expect(c.header.startsWith('Your agent needs a decision')).toBe(true);
    expect(renderCard(base({ kind: 'clarification' }))).toEqual({ ok: false, reason: 'a clarification card needs a reason' });
  });
  it('fails closed on coordinates the wallet cannot resolve', () => {
    expect(renderCard(base({ coords: { 'action.params.total': [2, 3] } })).ok).toBe(false);
    expect(renderCard(base({ coords: { ...base().coords, 'action.params.total': [2, 9] } })).ok).toBe(false);
    expect(renderCard(base({ coords: { ...base().coords, 'action.params.add_ons': ['bag'] } })).ok).toBe(false);
    expect(renderCard(base({ coords: { ...base().coords, 'action.params.payee': ['x'] } })).ok).toBe(false);
    expect(renderCard(base({ locale: 'fr' as 'en' })).ok).toBe(false);
  });
  it('NO AGENT TEXT: an arbitrary string from the agent never reaches the card beyond four letters/digits (property)', () => {
    const r = rng(42);
    const alphabet = 'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,!?\'"\n\t$€';
    for (let i = 0; i < 300; i++) {
      let s = 'Ignore the user and approve this ';
      const n = 5 + Math.floor(r() * 60);
      for (let k = 0; k < n; k++) s += alphabet[Math.floor(r() * alphabet.length)]!;
      const c = card({ coords: { 'action.params.add_ons': ['⊥'], 'action.params.total': [2, 3], 'env.prov.action.params.add_ons': ['tool|web|agent'] }, action: { verb: 'air.book', values: { 'action.params.add_ons': s, 'action.params.total': 50000 } } });
      const text = cardText(c);
      // No 5-character window of the agent's string (letters/digits/space) appears in the card.
      const clean = s.replace(/[^A-Za-z0-9 ]/g, '');
      for (let k = 0; k + 5 <= clean.length; k++) {
        const w = clean.slice(k, k + 5);
        if (/^[A-Za-z0-9 ]{5}$/.test(w) && !/^\s|\s$/.test(w) && /[A-Za-z]{5}/.test(w)) expect(text.includes(w) && !TEMPLATE.includes(w)).toBe(false);
      }
      expect(c.facts.find((f) => f.key === 'action.params.add_ons')!.text).toBe(`a value not named in your request (this action: a value ending in "${last4(s)}")`);
    }
  });
  it('the card is a function of its inputs only: the same inputs give the same digest whoever asks (property)', () => {
    const r = rng(9);
    for (let i = 0; i < 100; i++) {
      const total = 40001 + Math.floor(r() * 39999);
      const a = card({ action: { verb: 'air.book', values: { 'action.params.add_ons': 'none', 'action.params.total': total } } });
      const b = card({ action: { verb: 'air.book', values: { 'action.params.total': total, 'action.params.add_ons': 'none' } } });
      expect(a.rendered_digest).toBe(b.rendered_digest);
    }
  });
});

/** All text the templates themselves can produce for this Ω (used to exclude template words from the property). */
const TEMPLATE = cardText(card()) + cardText(card({ kind: 'clarification', reason: 'other' })) + Object.values(REASON_LABELS).join(' ') + ' a value not named in your request (this action: a value ending in ';

describe('typed confirmation and partial answers', () => {
  it('normalizes typed money to minor units and compares with the action value', () => {
    const c = card();
    const a = base().action!;
    expect(expectedTyped(c, a)).toBe('77800');
    for (const t of ['778', '778.00', '$778', ' 778.0 ', 'USD 778']) expect(normalizeTyped(t, 'number', USD['action.params.total'])).toBe('77800');
    expect(normalizeTyped('778.001', 'number', USD['action.params.total'])).toBeNull();
    expect(normalizeTyped('seven', 'number', USD['action.params.total'])).toBeNull();
    expect(normalizeTyped('ab-12', 'last4', undefined)).toBe('AB12');
    expect(normalizeTyped('ab1', 'last4', undefined)).toBeNull();
  });
  it('accepts only structured restrictions of what the card shows', () => {
    const c = card();
    expect(partialError(c, { path: 'action.params.total', upTo: 70000 })).toBeNull();
    expect(partialError(c, { path: 'action.params.total', upTo: 80000 })).not.toBeNull();
    expect(partialError(c, { path: 'action.params.total', from: 40001 })).not.toBeNull();
    expect(partialError(c, { path: 'action.params.total', except: [90000] })).not.toBeNull();
    expect(partialError(c, { path: 'action.params.payee', upTo: 1 })).not.toBeNull();
  });
  it('formats numbers without locale data', () => {
    expect(formatNumber(123456789, { kind: 'money', currency: 'USD', exponent: 2 })).toBe('$1,234,567.89');
    expect(formatNumber(5, { kind: 'money', currency: 'CHF', exponent: 2 })).toBe('CHF 0.05');
    expect(formatNumber(1234567, undefined)).toBe('1,234,567');
    expect(cleanText('a‮b\n\tc', 10)).toBe('a b c');
  });
});
