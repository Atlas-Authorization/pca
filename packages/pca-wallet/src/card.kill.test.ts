import { describe, expect, it } from 'vitest';
import type { Catalog } from '@atlasauth/pca/ext/research';
import type { Dim, Omega } from '@atlasauth/pca-intent';
import {
  cardText,
  cleanText,
  expectedTyped,
  formatNumber,
  last4,
  normalizeTyped,
  partialError,
  renderCard,
  REASON_LABELS,
  type CardInput,
  type CellCoords,
  type ClarifyReason,
  type PartialSpec,
  type TrustedCard,
  type Unit,
} from './index';

type CatVals = Extract<Dim, { kind: 'cat' }>['values'];
const num = (path: string, lo: number, hi: number, cuts: number[] = []): Dim => ({ kind: 'num', path, lo, hi, cuts, dist: 'uniform' });
const cat = (path: string, values: CatVals): Dim => ({ kind: 'cat', path, values });
const ex = (value: string) => ({ kind: 'exact' as const, value });
const OTHER = { kind: 'other' as const, value: '⊥' };
const omega = (dims: Dim[], reversibility: 'reversible' | 'rate_limited' | 'irreversible' = 'reversible'): Omega => ({
  v: 1,
  approximate: [],
  verbs: [{ verb: 'v.do', reversibility, weight: 1, dims }],
});
const site = { origin: 'https://s.example', name: 'Shop' };
const run = (om: Omega, coords: CellCoords, over: Partial<CardInput> = {}) => renderCard({ omega: om, verb: 'v.do', coords, site, friction: 'tap', kind: 'question', ...over });
const render = (om: Omega, coords: CellCoords, over: Partial<CardInput> = {}): TrustedCard => {
  const r = run(om, coords, over);
  if (!r.ok) throw new Error(r.reason);
  return r.card;
};
const MONEY: Unit = { kind: 'money', currency: 'USD', exponent: 2 };

describe('text helpers', () => {
  it('cleanText collapses, trims and truncates at the boundary', () => {
    expect(cleanText('  a   b  ', 20)).toBe('a b');
    expect(cleanText('\u0001x\u007fy', 20)).toBe('x y');
    expect(cleanText('abcde', 5)).toBe('abcde');
    expect(cleanText('abcdef', 5)).toBe('abcd…');
  });
  it('last4 keeps the last four alphanumerics, upper-cased', () => {
    expect(last4('xx-ab12')).toBe('AB12');
    expect(last4('ab!?cd')).toBe('ABCD');
    expect(last4('a')).toBe('A');
    expect(last4('abcdefgh')).toBe('EFGH');
  });
  it('formatNumber signs, zero and exponent', () => {
    expect(formatNumber(-5, MONEY)).toBe('-$0.05');
    expect(formatNumber(0, MONEY)).toBe('$0.00');
    expect(formatNumber(1234, { kind: 'money', currency: 'JPY', exponent: 0 })).toBe('¥1,234');
    expect(formatNumber(-1234, undefined)).toBe('-1,234');
    expect(formatNumber(0, undefined)).toBe('0');
  });
});

describe('dimension labels', () => {
  it('lifted paths get their fixed wording, only on a whole-path match', () => {
    const dims = [
      num('env.acc.spent_total.x.post', 0, 1),
      num('env.world.fx_rate.v', 0, 1),
      cat('env.mon.door_lock.state', [ex('open'), ex('closed'), OTHER]),
      num('zenv.acc.a.post', 0, 1),
      num('env.acc.b.post.x', 0, 1),
      num('zenv.world.a', 0, 1),
      num('env.world.k l', 0, 1),
      num('zenv.mon.a.state', 0, 1),
      num('env.mon.b.state.x', 0, 1),
    ];
    const coords: CellCoords = { 'env.mon.door_lock.state': ['open'] };
    for (const d of dims) if (d.kind === 'num') coords[d.path] = [0, 0];
    const c = render(omega(dims), coords);
    expect(c.facts.map((f) => f.label)).toEqual([
      'spent total x (running total for this task)',
      'fx rate v (from a signed fact)',
      'state of door lock',
      'post',
      'x',
      'a',
      'k l',
      'state',
      'x',
    ]);
  });
});

describe('numeric facts', () => {
  const om = omega([num('action.params.qty', 0, 1000, [1, 5])]);
  const qty = (r: [number, number], over: Partial<CardInput> = {}) => render(om, { 'action.params.qty': r }, over).facts[0]!.text;
  it('words each range shape', () => {
    expect(qty([1, 1])).toBe('exactly 1');
    expect(qty([3, 3])).toBe('exactly 5');
    expect(qty([0, 4])).toBe('any value');
    expect(qty([0, 3])).toBe('up to 5');
    expect(qty([2, 4])).toBe('2 or more');
    expect(qty([1, 3])).toBe('1 – 5');
    expect(qty([1, 3], { units: { 'action.params.qty': MONEY } })).toBe('$0.01 – $0.05');
  });
  it('shows the action value only when it is a finite number', () => {
    const act = (v: number | string) => qty([0, 4], { action: { verb: 'v.do', values: { 'action.params.qty': v } } });
    expect(act(3)).toBe('any value (this action: 3)');
    expect(act(NaN)).toBe('any value');
    expect(act(Infinity)).toBe('any value');
    expect(act('abc')).toBe('any value');
  });
});

describe('categorical facts and partial slots', () => {
  const om = omega([cat('env.mon.door_lock.state', [ex('open'), ex('closed'), OTHER]), cat('action.params.dest', [ex('a b'), { kind: 'prefix', value: 'acct-' }, OTHER])]);
  const co = (mon: string[], dest: string[]): CellCoords => ({ 'env.mon.door_lock.state': mon, 'action.params.dest': dest });
  it('lists the values and the open-ended ones', () => {
    const c = render(om, co(['open', 'closed', '⊥'], ['a b', 'acct-', '⊥']));
    expect(c.facts).toEqual([
      { key: 'env.mon.door_lock.state', label: 'state of door lock', text: '"open", "closed" or a value not named in your request' },
      { key: 'action.params.dest', label: 'dest', text: '"a b", anything starting with "acct-" or a value not named in your request' },
    ]);
    expect(c.partial).toEqual([{ path: 'env.mon.door_lock.state', kind: 'cat', options: ['open', 'closed'] }]);
    expect(c.banners).toEqual([]);
  });
  it('two values read "a or b"; one exact value has no partial slot', () => {
    const two = render(om, co(['open', 'closed'], ['a b']));
    expect(two.facts[0]!.text).toBe('"open" or "closed"');
    expect(two.partial).toEqual([{ path: 'env.mon.door_lock.state', kind: 'cat', options: ['open', 'closed'] }]);
    const one = render(om, co(['open'], ['a b']));
    expect(one.facts[0]!.text).toBe('"open"');
    expect(one.partial).toEqual([]);
  });
  it('names the action value only when the outcome space names it', () => {
    const c = render(om, co(['open'], ['acct-']), { action: { verb: 'v.do', values: { 'env.mon.door_lock.state': 'open', 'action.params.dest': 'acct-' } } });
    expect(c.facts[0]!.text).toBe('"open" (this action: "open")');
    expect(c.facts[1]!.text).toBe('anything starting with "acct-" (this action: a value ending in "ACCT")');
    const n = render(om, co(['open'], ['acct-']), { action: { verb: 'v.do', values: { 'action.params.dest': 5 } } });
    expect(n.facts[1]!.text).toBe('anything starting with "acct-"');
  });
});

describe('provenance banners', () => {
  const om = omega([
    cat('env.prov.action.params.dest', [ex('tool'), ex('web'), ex('agent'), ex('trusted|first_party'), OTHER]),
    cat('env.prov.env.acc.spent.post', [ex('agent'), ex('trusted')]),
    num('env.prov.plain', 0, 5),
  ]);
  const banners = (dest: string, acc: string) => render(om, { 'env.prov.action.params.dest': [dest], 'env.prov.env.acc.spent.post': [acc], 'env.prov.plain': [0, 0] }).banners;
  it('words each level and stays silent when trusted', () => {
    expect(banners('tool', 'trusted')).toEqual(['This dest came from a tool result, not from you.']);
    expect(banners('web', 'trusted')).toEqual(['This dest was suggested by content on a web page, not by you.']);
    expect(banners('agent', 'trusted')).toEqual(['This dest was chosen by your agent, not taken from your request or from the site.']);
    expect(banners('trusted|first_party', 'trusted')).toEqual([]);
  });
  it('labels a lifted dimension by its own path and keeps provenance out of the facts', () => {
    expect(banners('trusted|first_party', 'agent')).toEqual(['This spent (running total for this task) was chosen by your agent, not taken from your request or from the site.']);
    expect(render(om, { 'env.prov.action.params.dest': ['tool'], 'env.prov.env.acc.spent.post': ['trusted'], 'env.prov.plain': [0, 0] }).facts).toEqual([]);
  });
});

describe('typed target', () => {
  const om = omega([num('env.prov.x', 0, 5), num('action.params.amount', 0, 100, [10]), num('action.params.fee', 0, 100, [10]), cat('action.params.who', [ex('abcd1234'), OTHER])]);
  const co: CellCoords = { 'env.prov.x': [0, 0], 'action.params.amount': [0, 2], 'action.params.fee': [0, 2], 'action.params.who': ['⊥'] };
  const typed = (values: Record<string, number | string>, over: Partial<CardInput> = {}) => render(om, co, { friction: 'typed', action: { verb: 'v.do', values }, ...over }).typed;
  it('picks the first numeric value, preferring money, never a provenance dimension', () => {
    const v = { 'env.prov.x': 3, 'action.params.amount': 50, 'action.params.fee': 7, 'action.params.who': 'zzzz9999' };
    expect(typed(v)).toEqual({ path: 'action.params.amount', mode: 'number', prompt: 'To allow it, type the amount of this action shown above.' });
    expect(typed(v, { units: { 'action.params.fee': MONEY } })).toEqual({ path: 'action.params.fee', mode: 'number', prompt: 'To allow it, type the fee of this action shown above.' });
    expect(typed(v, { units: { 'action.params.amount': { kind: 'count' }, 'action.params.fee': MONEY } })?.path).toBe('action.params.fee');
  });
  it('falls back to the last four of a categorical value', () => {
    expect(typed({ 'env.prov.x': 3, 'action.params.amount': 'x', 'action.params.fee': 'y', 'action.params.who': 'zzzz9999' })).toEqual({
      path: 'action.params.who',
      mode: 'last4',
      prompt: 'To allow it, type the last 4 letters or digits of the who.',
    });
  });
  it('has no target when nothing qualifies', () => {
    expect(typed({ 'action.params.who': 12345 })).toBeUndefined();
    expect(typed({ 'action.params.who': 'ab' })).toBeUndefined();
    expect(typed({ 'action.params.amount': 'abcd1234', 'action.params.who': 'zz' })).toBeUndefined();
    expect(render(om, co, { friction: 'typed' }).typed).toBeUndefined();
  });
  it('only from the typed tier up', () => {
    const action = { verb: 'v.do', values: { 'action.params.amount': 50 } };
    expect(render(om, co, { friction: 'tap', action }).typed).toBeUndefined();
    expect(render(om, co, { friction: 'hold', action }).typed).toBeUndefined();
    expect(render(om, co, { friction: 'typed', action }).typed?.path).toBe('action.params.amount');
    expect(render(om, co, { friction: 'device', action }).typed?.path).toBe('action.params.amount');
  });
});

describe('renderCard envelope', () => {
  const om = omega([num('action.params.qty', 0, 1000, [1, 5])]);
  const co: CellCoords = { 'action.params.qty': [0, 4] };
  it('refuses with the exact reason', () => {
    expect(run(om, co, { locale: 'fr' as 'en' })).toEqual({ ok: false, reason: 'unsupported locale fr' });
    expect(run(om, co, { reason: 'bogus' as ClarifyReason })).toEqual({ ok: false, reason: 'unknown clarification reason' });
    expect(run(om, co, { action: { verb: 'other', values: {} } })).toEqual({ ok: false, reason: 'the action is for another verb' });
  });
  it('headers', () => {
    expect(render(om, co).header).toBe('Shop asks for your confirmation');
    expect(render(om, co, { statementText: 'hi' }).header).toBe('Shop asks on behalf of your request "hi"');
    expect(render(om, co, { kind: 'clarification', reason: 'other' }).header).toBe('Your agent needs a decision');
    expect(render(om, co, { kind: 'clarification', reason: 'other', statementText: 'hi' }).header).toBe('Your agent needs a decision for your request "hi"');
  });
  it('sentence, site and reason label', () => {
    const c = render(om, co);
    expect(c.sentence).toBe('Allow the action "v.do" on Shop, that can be undone, with:');
    expect(c.site).toEqual({ origin: 'https://s.example', name: 'Shop' });
    expect(c).not.toHaveProperty('reason_label');
    expect(render(om, co, { kind: 'clarification', reason: 'price_changed' }).reason_label).toBe(REASON_LABELS.price_changed);
    expect(render(om, co, { reversibility: 'irreversible' }).sentence).toBe('Allow the action "v.do" on Shop, that cannot be undone, with:');
    expect(render(om, co, { site: { origin: 'https://o.example', name: '  ' } }).site).toEqual({ origin: 'https://o.example', name: 'https://o.example' });
  });
  it('describes a catalogued verb in lower case without its final full stop', () => {
    type Spec = NonNullable<ReturnType<Catalog['get']>>;
    const spec = (description: string): Spec => ({ connector: 'v', action: 'do', verb: 'v.do', reversibility: 'reversible', blastRadius: 0.1, description });
    const cat1 = (description: string): Catalog => ({ get: (v) => (v === 'v.do' ? spec(description) : undefined), forConnector: () => [], all: () => [] });
    expect(render(om, co, { catalog: cat1('Book A flight v1.2 now.') }).sentence).toBe('Allow book A flight v1.2 now, that can be undone, with:');
    expect(render(om, co, { catalog: cat1('\nABC') }).sentence).toBe('Allow \nABC, that can be undone, with:');
  });
});

describe('cardText', () => {
  it('joins the lines in order', () => {
    const om = omega([num('action.params.qty', 0, 1000, [1, 5])]);
    const co: CellCoords = { 'action.params.qty': [0, 4] };
    const q = render(om, co);
    expect(cardText(q)).toBe([q.header, q.sentence, '- qty: any value', '[No] [Partly…] [Yes]'].join('\n'));
    const t = render(om, co, { friction: 'typed', kind: 'clarification', reason: 'other', action: { verb: 'v.do', values: { 'action.params.qty': 3 } } });
    expect(cardText(t)).toBe(
      [t.header, REASON_LABELS.other, t.sentence, '- qty: any value (this action: 3)', 'To allow it, type the qty of this action shown above.', '[No] [Partly…] [Yes, type the value to confirm]'].join('\n'),
    );
    const b = render(omega([num('action.params.qty', 0, 1000, [1, 5]), cat('env.prov.p', [ex('web')])]), { ...co, 'env.prov.p': ['web'] });
    expect(cardText(b)).toBe([b.header, b.sentence, '- qty: any value', 'This p was suggested by content on a web page, not by you.', '[No] [Partly…] [Yes]'].join('\n'));
  });
});

describe('partialError', () => {
  const om = omega([num('action.params.qty', 0, 1000, [1, 5])]);
  const base = render(om, { 'action.params.qty': [0, 4] });
  const c: TrustedCard = {
    ...base,
    partial: [
      { path: 'who', kind: 'cat', options: ['a', 'b', 'c'] },
      { path: 'n', kind: 'num', lo: 2, hi: 9 },
    ],
  };
  const err = (p: PartialSpec) => partialError(c, p);
  it('refuses a field the card does not show', () => {
    expect(err({ path: 'nope', upTo: 3 })).toBe('the card has no field nope');
  });
  it('numeric: upTo, from, except with exact bounds', () => {
    expect(err({ path: 'n', upTo: 5 })).toBeNull();
    expect(err({ path: 'n', upTo: 1 })).toBe('upTo must be an integer in [2, 8]');
    expect(err({ path: 'n', upTo: 9 })).toBe('upTo must be an integer in [2, 8]');
    expect(err({ path: 'n', from: 5 })).toBeNull();
    expect(err({ path: 'n', from: 9 })).toBeNull();
    expect(err({ path: 'n', from: 2 })).toBe('from must be an integer in [3, 9]');
    expect(err({ path: 'n', from: 10 })).toBe('from must be an integer in [3, 9]');
    expect(err({ path: 'n', except: [3] })).toBeNull();
    expect(err({ path: 'n', except: [9] })).toBeNull();
    expect(err({ path: 'n', except: [] })).toBe('except values must be integers in [2, 9]');
    expect(err({ path: 'n', except: [3, 99] })).toBe('except values must be integers in [2, 9]');
    expect(err({ path: 'n' } as PartialSpec)).toBe('a numeric partly answer needs upTo, from or except');
  });
  it('categorical: notFor only, and only values shown, never all of them', () => {
    expect(err({ path: 'who', upTo: 3 })).toBe('a categorical partly answer needs notFor');
    expect(err({ path: 'who', notFor: ['a'] })).toBeNull();
    expect(err({ path: 'who', notFor: ['a', 'a', 'b'] })).toBeNull();
    expect(err({ path: 'who', notFor: [] })).toBe('notFor must name values shown on the card');
    expect(err({ path: 'who', notFor: ['a', 'zzz'] })).toBe('notFor must name values shown on the card');
    expect(err({ path: 'who', notFor: ['a', 'b', 'c'] })).toBe('excluding every value is a "No"');
  });
});

describe('normalizeTyped and expectedTyped', () => {
  it('anchors the currency prefix and the number', () => {
    expect(normalizeTyped('5USD', 'number', undefined)).toBeNull();
    expect(normalizeTyped('x12', 'number', undefined)).toBeNull();
    expect(normalizeTyped('12x', 'number', undefined)).toBeNull();
    expect(normalizeTyped('5', 'number', undefined)).toBe('5');
    expect(normalizeTyped('5', 'number', { kind: 'count' })).toBe('5');
  });
  it('money minor units and signs', () => {
    expect(normalizeTyped('12.5', 'number', MONEY)).toBe('1250');
    expect(normalizeTyped('-5.25', 'number', MONEY)).toBe('-525');
    expect(normalizeTyped('-5', 'number', undefined)).toBe('-5');
    expect(normalizeTyped('-0', 'number', undefined)).toBe('0');
    expect(normalizeTyped('-0.00', 'number', MONEY)).toBe('0');
  });
  it('expectedTyped by mode', () => {
    const om = omega([num('action.params.amount', 0, 100, [10]), cat('action.params.who', [ex('abcd1234'), OTHER])]);
    const co: CellCoords = { 'action.params.amount': [0, 2], 'action.params.who': ['⊥'] };
    const plain = render(om, co);
    expect(expectedTyped(plain, { verb: 'v.do', values: { 'action.params.amount': 5 } })).toBeNull();
    const num1 = render(om, co, { friction: 'typed', action: { verb: 'v.do', values: { 'action.params.amount': 5 } } });
    expect(expectedTyped(num1, { verb: 'v.do', values: { 'action.params.amount': 5 } })).toBe('5');
    expect(expectedTyped(num1, { verb: 'v.do', values: { 'action.params.amount': 1.5 } })).toBeNull();
    expect(expectedTyped(num1, { verb: 'v.do', values: { 'action.params.amount': '5' } })).toBeNull();
    const l4: TrustedCard = { ...num1, typed: { path: 'action.params.who', mode: 'last4', prompt: 'p' } };
    expect(expectedTyped(l4, { verb: 'v.do', values: { 'action.params.who': 'abcd1234' } })).toBe('1234');
    expect(expectedTyped(l4, { verb: 'v.do', values: { 'action.params.who': 'ab' } })).toBeNull();
    expect(expectedTyped(l4, { verb: 'v.do', values: { 'action.params.who': 12345 } })).toBeNull();
  });
});
