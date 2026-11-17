import { describe, expect, it } from 'vitest';
import { ingestText } from './ingest';
import { includedTraces, intact, propose } from './synth';
import { DAY, NOW, benign, jsonl, row } from './test-support/fixtures';

const set = (rows: string[]) => ingestText(jsonl(rows));
const resources = (p: ReturnType<typeof propose>) => p.policy.predicates.map((x) => `${String(x.verb)} ${x.resource}`);

describe('propose', () => {
  it('generalizes siblings one level, caps numbers from the observed max plus the margin, and is reproducible', () => {
    const p = propose(set(benign()), { now: NOW });
    expect(p.policy.predicates).toHaveLength(1);
    const pred = p.policy.predicates[0]!;
    expect(pred.verb).toBe('gmail.draft');
    expect(pred.resource).toBe('/drafts/*');
    expect(pred.where).toContainEqual({ field: 'action.params.recipients', op: 'lte', value: 4 }); // max 3 * 1.2 = 3.6, integers round up
    expect(pred.where).toContainEqual({ field: 'action.params.recipients', op: 'gte', value: 0 });
    expect(p.policy.caveats).toContainEqual({ type: 'reversibility_max', class: 'reversible' });
    expect(p.policy.caveats).toContainEqual({ type: 'expires', at: NOW + 30 * DAY });
    expect(p.policy.caveats).toContainEqual({ type: 'rate', max: 8, per_secs: 3600 });
    expect(p.rules[0]!.rung).toBe(1);
    expect(propose(set(benign()), { now: NOW }).digest).toBe(p.digest);
    expect(intact(p)).toBe(true);
    expect(intact({ ...p, margin: 9 })).toBe(false);
  });

  it('margin 0 gives the exact observed maximum; a margin is the only slack', () => {
    const p = propose(set(benign()), { now: NOW, margin: 0 });
    expect(p.policy.predicates[0]!.where).toContainEqual({ field: 'action.params.recipients', op: 'lte', value: 3 });
  });

  it('refuses non-finite, negative or absurd options', () => {
    for (const margin of [NaN, Infinity, -1, 11]) expect(() => propose(set(benign()), { now: NOW, margin })).toThrow(RangeError);
    expect(() => propose(set(benign()), { now: NaN })).toThrow(RangeError);
    expect(() => propose(set(benign()), { now: NOW, minDistinct: 1 })).toThrow(RangeError);
    expect(() => propose(set(benign()), { now: NOW, ttlMs: 0 })).toThrow(RangeError);
  });

  it('never generalizes across parents, below the minimum, or to a bare wildcard', () => {
    const rs = ['/a/1', '/a/2', '/a/3', '/b/1', '/b/2', 'x', 'y', '/solo'];
    const p = propose(set(rs.map((r, i) => row(i, { verb: 'docs.read', resource: r, params: {} }))), { now: NOW });
    expect(resources(p)).toEqual(['docs.read /a/*', 'docs.read /b/1', 'docs.read /b/2', 'docs.read /solo', 'docs.read x', 'docs.read y']);
    expect(p.policy.predicates.every((x) => x.resource !== '*' && x.resource !== '/*')).toBe(true);
  });

  it('pins low-cardinality strings and leaves high-cardinality ones free, saying so', () => {
    const rows = Array.from({ length: 9 }, (_, i) => row(i, { verb: 'docs.read', resource: `/d/${i}`, params: { fmt: i % 2 ? 'pdf' : 'md', who: `u${i}` } }));
    const p = propose(set(rows), { now: NOW });
    const w = p.policy.predicates[0]!.where!;
    expect(w).toContainEqual({ field: 'action.params.fmt', op: 'in', value: ['md', 'pdf'] });
    expect(w.some((c) => (c as { field: string }).field === 'action.params.who')).toBe(false);
    expect(p.rules[0]!.params.join('\n')).toMatch(/who: 9 different values, left unconstrained/);
  });

  it('puts a param that was not always sent out of the policy rather than denying the traces that lacked it', () => {
    const rows = [row(0, { params: { recipients: 1 } }), row(1, { params: {} }), row(2, { params: { recipients: 2 } })];
    const p = propose(set(rows), { now: NOW, minDistinct: 3 });
    expect(p.policy.predicates.every((x) => (x.where ?? []).length === 0)).toBe(true);
  });

  it('a trace flood of distinct shapes fails closed instead of emitting hundreds of rules', () => {
    const rows = Array.from({ length: 600 }, (_, i) => row(i, { resource: `/p${i}/x` }));
    expect(() => propose(set(rows), { now: NOW })).toThrow(/maxRules/);
  });

  it('many repeats of one action change nothing about the caps', () => {
    const one = propose(set(benign(6)), { now: NOW, margin: 0 });
    const many = propose(set([...benign(6), ...Array.from({ length: 3000 }, (_, i) => row(i % 6, { at: NOW - DAY + 100_000 + i }))]), { now: NOW, margin: 0 });
    expect(many.policy.predicates).toEqual(one.policy.predicates);
  });

  it('proposes nothing from an empty or fully-held set', () => {
    expect(() => propose(set([]), { now: NOW })).toThrow(/nothing to propose/);
    expect(() => propose(set([row(1, { verb: 'gmail.delete' })]), { now: NOW })).toThrow(/nothing to propose/);
  });
});

describe('poisoned traces', () => {
  const poisoned = () => set([...benign(), row(20, { verb: 'gmail.delete', resource: '/drafts/1', params: {} })]);

  it('a dangerous action seen during observation is held back, never auto-included', () => {
    const p = propose(poisoned(), { now: NOW });
    expect(p.policy.predicates.map((x) => x.verb)).toEqual(['gmail.draft']);
    expect(p.heldBack).toHaveLength(1);
    expect(p.heldBack[0]).toMatchObject({ verb: 'gmail.delete', kind: 'sensitive', count: 1 });
    expect(p.heldBack[0]!.reasons).toEqual(expect.arrayContaining(['dangerous-verb', 'irreversible-action']));
    expect(p.confirmedSensitive).toEqual([]);
  });

  it('it comes in only when its id is confirmed by name, and the proposal then lists it', () => {
    const id = propose(poisoned(), { now: NOW }).heldBack[0]!.id;
    const p = propose(poisoned(), { now: NOW, confirmed: [id] });
    expect(p.policy.predicates.map((x) => x.verb)).toContain('gmail.delete');
    expect(p.confirmedSensitive).toEqual([id]);
    expect(p.heldBack).toHaveLength(0);
    expect(p.digest).not.toBe(propose(poisoned(), { now: NOW }).digest);
  });

  it('confirming an id that is not a sensitive action in the traces is an error (typos and blind confirms fail)', () => {
    expect(() => propose(poisoned(), { now: NOW, confirmed: ['0123456789abcdef'] })).toThrow(/not a confirmable/);
    const benignId = set(benign()).traces[0]!.id;
    expect(() => propose(set(benign()), { now: NOW, confirmed: [benignId] })).toThrow(/not a confirmable/);
  });

  it('an action the enforcer denied while observing is never included by propose', () => {
    const p = propose(set([...benign(), row(30, { resource: '/drafts/zzz', outcome: 'deny' })]), { now: NOW });
    expect(p.rules[0]!.observed).toBe(6);
    expect(p.heldBack).toEqual([expect.objectContaining({ kind: 'blocked', resource: '/drafts/zzz' })]);
  });

  it('an amount outlier is held, so one poisoned huge value cannot lift the cap', () => {
    const rows = [...Array.from({ length: 6 }, (_, i) => row(i, { verb: 'quotes.create', resource: `/q/${i}`, params: { amount: 10 + i } })), row(9, { verb: 'quotes.create', resource: '/q/9', params: { amount: 5000 } })];
    const p = propose(set(rows), { now: NOW });
    const cap = p.policy.predicates[0]!.where!.find((c) => (c as { op: string }).op === 'lte') as { value: number };
    expect(cap.value).toBeLessThan(100);
    expect(p.heldBack[0]!.reasons).toContain('amount-outlier:amount');
  });
});

describe('tenant boundaries', () => {
  const two = () => set([...benign().map((r) => JSON.stringify({ ...JSON.parse(r), tenant: 'a' })), row(50, { tenant: 'b', resource: '/drafts/b1' }), row(51, { tenant: 'b', resource: '/drafts/b2' })]);

  it('refuses to build across tenants without being told which', () => {
    expect(() => propose(two(), { now: NOW })).toThrow(/several tenants/);
  });

  it('builds one tenant from its own traces only', () => {
    const p = propose(two(), { now: NOW, tenant: 'a' });
    expect(p.tenant).toBe('a');
    expect(p.basis.included).toBe(6);
    expect(includedTraces(two(), p).every((t) => t.tenant === 'a')).toBe(true);
  });

  it('a resource that names another tenant is held back and never generalized into the grant', () => {
    const rows = [...benign().map((r) => JSON.stringify({ ...JSON.parse(r), tenant: 'a' })), row(60, { tenant: 'a', resource: '/t/b/docs' }), row(61, { tenant: 'b', resource: '/x/1' })];
    const p = propose(set(rows), { now: NOW, tenant: 'a' });
    expect(p.policy.predicates.map((x) => x.resource)).toEqual(['/drafts/*']);
    expect(p.heldBack[0]!.reasons).toContain('cross-tenant-resource');
    expect(() => propose(set(rows), { now: NOW, tenant: 'a', confirmed: [p.heldBack[0]!.id] })).toThrow(/not a confirmable/);
  });
});
