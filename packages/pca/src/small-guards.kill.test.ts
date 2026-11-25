/**
 * Small guards pinned by exact outcomes: a read grant with one bad read entry, the read-side sort comparator, the
 * settlement-to-dispute mapping only resolving string claim ids, an RFC 9162 proof that is not a real array, and the
 * predicate denial wording when the action view disappears between reads.
 */
import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { publicKeyOf } from './keys';
import { evaluatePredicates, type ActionContext } from './predicates';
import { verifyRfc9162Inclusion } from './provenance-gate';
import { redactRead, signReadGrant, validReadGrantBody, type ReadGrantBody } from './readside';
import { disputesFromSettlements } from './reputation-evidence';

type Cmp = (a: unknown, b: unknown) => number;
// Records the comparator of the first sort whose first element is `first`.
const captureSort = (first: string, run: () => void): Cmp => {
  const orig = Array.prototype.sort;
  let got: Cmp | undefined;
  Array.prototype.sort = function (this: unknown[], fn?: Cmp) {
    if (fn && !got && this[0] === first) got = fn;
    return orig.call(this, fn);
  } as typeof orig;
  try {
    run();
  } finally {
    Array.prototype.sort = orig;
  }
  if (!got) throw new Error('no comparator captured');
  return got;
};

const P = new Uint8Array(32).fill(71);
const PK = b64u(publicKeyOf(P));
const NOW = 1_800_000_000_000;
const entry = { verb: 'customers.get', resource_prefix: 'customers/', purposes: ['support'], modes: { pii: 'last4' }, default_mode: 'drop' };
const body: ReadGrantBody = { v: 1, id: 'rg', principal: PK, issued_at: NOW - 1000, expires_at: NOW + 1000, reads: [entry], caps: {}, sinks: {} } as ReadGrantBody;

describe('read grants and the read-side order', () => {
  it('every read entry must be valid (one bad entry among good ones rejects the grant)', () => {
    expect(validReadGrantBody({ ...body, reads: [entry, entry] })).toBe(true);
    expect(validReadGrantBody({ ...body, reads: [entry, { ...entry, verb: '' }] })).toBe(false);
    expect(validReadGrantBody({ ...body, reads: [{ ...entry, extra: 1 }, entry] })).toBe(false);
  });
  it('record paths are ordered by a total order with ties at 0', () => {
    const grant = signReadGrant(P, body);
    const cmp = captureSort('zz_last', () =>
      redactRead({ grant, principal: PK, now: NOW, verb: 'customers.get', resource: 'customers/1', purpose: 'support', schema: { fields: {}, required: [] }, record: { zz_last: 1, aa_first: 2 }, tighten: {}, salt: 'a-per-read-secret-salt', counts: {} }),
    );
    expect([cmp('a', 'b'), cmp('b', 'a'), cmp('a', 'a')]).toEqual([-1, 1, 0]);
  });
});

describe('disputesFromSettlements', () => {
  it('a record without a string claim id is rejected without asking for its subject', () => {
    const asked: unknown[] = [];
    const r = disputesFromSettlements([{ claimId: 5 } as never, null as never, { claimId: { id: 'x' } } as never], PK, (id) => (asked.push(id), 'subject'));
    expect(asked).toEqual([]);
    expect(r).toEqual({ disputes: [], rejected: 3 });
  });
  it('a string claim id is resolved', () => {
    const asked: unknown[] = [];
    const r = disputesFromSettlements([{ claimId: 'c1' } as never], PK, (id) => (asked.push(id), undefined));
    expect(asked).toEqual(['c1']);
    expect(r).toEqual({ disputes: [], rejected: 1 });
  });
});

describe('verifyRfc9162Inclusion: the proof must be a real array of at most 64 nodes', () => {
  it('an array-like object with its own every/iterator is refused even when it would fold to the root', () => {
    const leaf = new Uint8Array(32).fill(9);
    const fake = { length: 0, every: () => true, *[Symbol.iterator]() {} };
    expect(verifyRfc9162Inclusion(leaf, 0, 1, [], leaf)).toBe(true);
    expect(verifyRfc9162Inclusion(leaf, 0, 1, fake as never, leaf)).toBe(false);
  });
  it('65 nodes are refused', () => {
    const leaf = new Uint8Array(32).fill(9);
    expect(verifyRfc9162Inclusion(leaf, 0, 2, Array.from({ length: 65 }, () => new Uint8Array(32)), leaf)).toBe(false);
  });
});

describe('evaluatePredicates: the action view read for the wording', () => {
  it('when the action view is gone at the wording read, the reason names undefined (never an evaluation error)', () => {
    const action = { verb: 'pay', resource: 'acct/1', params: { amount: 9 } };
    // the getter answers undefined only to the read made by the reason builder itself (the matcher and the limit finder see the action)
    const ctx = {
      get action() {
        const caller = (new Error().stack ?? '').split('\n')[2] ?? '';
        return caller.includes('evaluatePredicatesInner') ? undefined : action;
      },
    } as unknown as ActionContext;
    const r = evaluatePredicates([{ verb: 'pay', resource: 'acct/*', where: [{ field: 'action.params.amount', op: 'lte', value: 1 }] }], ctx);
    expect(r).toEqual({ allowed: false, reason: 'amount <= 1 not satisfied for undefined on undefined' });
  });
});
