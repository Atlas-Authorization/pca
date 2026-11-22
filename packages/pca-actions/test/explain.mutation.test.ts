// Exact text of explainDef: the blast formatting, the reversibility words, the optional lines and the unreviewed hint.
import { describe, expect, it } from 'vitest';
import { CORE_REGISTRY, explainDef, type ActionDef } from '../src';

const def = (over: Partial<ActionDef> = {}): ActionDef => ({
  v: 1, kind: 'pca-action-def', verb: 'a.b.c', title: 'Read thing', effects: ['read'], resource: { type: 'a.b', id: '*', scope: 'one' }, params: {},
  review: { state: 'confirmed' }, ...over,
});
const yes = { attestationVerified: () => true };
const lines = (d: ActionDef, opts = yes) => explainDef(d, CORE_REGISTRY, opts).split('\n');

describe('explainDef: a confirmed read-only def', () => {
  it('is five exact lines', () => {
    expect(lines(def())).toEqual([
      'Read thing. This action only reads.',
      'effective: risk 0, reversible, blast 50k, escalation: auto',
      'grant must carry: nothing',
      'traits: none',
      'review: confirmed',
    ]);
  });
  it.each([
    ['rate_limited', 'rate limited'],
    ['irreversible', 'irreversible'],
    ['reversible', 'reversible'],
  ])('names a %s action as "%s"', (rev, word) => {
    expect(lines(def({ reversibility: rev as never }))[1]).toMatch(new RegExp(`^effective: risk \\d, ${word}, blast `));
  });
  it('writes a blast that is not a whole thousand in ppm, and a whole thousand in k', () => {
    expect(lines(def({ blast: { radius: 'one', ppm: 123_456 } }))[1]).toBe('effective: risk 0, reversible, blast 123456ppm, escalation: auto');
    expect(lines(def({ blast: { radius: 'one', ppm: 125_000 } }))[1]).toBe('effective: risk 0, reversible, blast 125k, escalation: auto');
  });
  it('adds a line for the context a call must carry, comma separated, right after the grant line', () => {
    const l = lines(def({ context: ['dry_run_first', 'approval_ref'] }));
    expect(l[2]).toBe('grant must carry: nothing');
    expect(l[3]).toBe('call must carry: approval_ref, dry_run_first');
    expect(l).toHaveLength(6);
    expect(lines(def()).some((x) => x.startsWith('call must carry'))).toBe(false);
  });
});

describe('explainDef: an unconfirmed def', () => {
  it('ends with the review state and what the def would be if a reviewer signed it as written', () => {
    const l = lines(def({ review: { state: 'unreviewed' } }), {} as never);
    expect(l[l.length - 2]).toBe('review: unreviewed, not confirmed by a signed review');
    expect(l[l.length - 1]).toBe('until a reviewer signs it this action is treated as the most dangerous kind of action; as written it would be: risk 0, escalation tier 0, traits: none');
  });
});
