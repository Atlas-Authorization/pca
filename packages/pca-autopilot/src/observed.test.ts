import { describe, expect, it } from 'vitest';
import { agent, appendReceipt, generateKeyPair, type Receipt } from '@atlasauth/pca';
import { checkObservedChain, fromReceipts, observedContentDigest, observedHash, type ObservedRecord } from './ingest';
import { propose } from './synth';
import { NOW } from './test-support/fixtures';

const params = (i: number): ObservedRecord['params'] => ({ recipients: 1 + (i % 3), note: 'x'.repeat(100) });

/** What the proxy's observe mode writes: receipts carrying obs1/obs2, plus one chained line of observed parameters per receipt. */
function logs(n: number, o: { allowed?: (i: number) => string; drop?: number[]; noFacts?: number[] } = {}) {
  const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { gmail: ['draft'] }, aud: 'inst' });
  let receipts: Receipt[] = [];
  const observed: ObservedRecord[] = [];
  let prev = '';
  for (let i = 0; i < n; i++) {
    const pc = a.act('gmail.draft', `/drafts/${i}`, {}, { now: NOW + i }).pcactn;
    const d = observedContentDigest({ seq: i, verb: 'gmail.draft', resource: `/drafts/${i}`, params: params(i), omitted: [] });
    const facts = o.noFacts?.includes(i) ? {} : { obs1: d.slice(0, 22), obs2: d.slice(22) };
    receipts = appendReceipt(receipts, pc, { allow: true, checks: { allowed: o.allowed?.(i) ?? 'true', code: 'ok', ...facts } as never });
    if (o.drop?.includes(i)) continue;
    const r = receipts[i]!;
    const body = { v: 1 as const, seq: r.seq, receipt: r.hash, verb: r.verb, resource: r.resource, params: params(i), omitted: [], prev };
    const rec = { ...body, hash: observedHash(body) };
    observed.push(rec);
    prev = rec.hash;
  }
  return { receipts, observed };
}

/** An attacker who edits lines and then repairs the line chain so it verifies on its own. */
function rechain(lines: ObservedRecord[]): ObservedRecord[] {
  let prev = '';
  return lines.map((l) => {
    const { hash: _h, ...rest } = l;
    void _h;
    const body = { ...rest, prev };
    prev = observedHash(body);
    return { ...body, hash: prev };
  });
}

describe('observed parameters beside receipts', () => {
  it('lets amount caps be learned from an audit log (long strings are dropped)', () => {
    const { receipts, observed } = logs(6);
    const s = fromReceipts(receipts, {}, observed);
    expect(s.traces[0]!.params).toEqual({ recipients: 1 });
    const p = propose(s, { now: NOW, margin: 0 });
    expect(p.policy.predicates[0]!.where).toContainEqual({ field: 'action.params.recipients', op: 'lte', value: 3 });
  });

  it('without the side log the receipts carry no parameters, and the proposal says so', () => {
    const { receipts } = logs(6);
    const p = propose(fromReceipts(receipts), { now: NOW });
    expect(p.notes.join()).toMatch(/NOT bounded/);
  });

  it('tolerates a missing tail and lines for receipts that carried nothing', () => {
    const { receipts, observed } = logs(6, { drop: [5] });
    expect(fromReceipts(receipts, {}, observed).traces.filter((t) => Object.keys(t.params).length > 0)).toHaveLength(5);
  });

  it('pins the digest to the proxy: one literal vector (the proxy test asserts the same value)', () => {
    expect(observedContentDigest({ seq: 3, verb: 'gmail.draft', resource: '/drafts/3', params: { recipients: 2 }, omitted: ['note'] })).toBe('gYyEqXcrbkrreGLl8RXo_Srwt-M6BENxTR4bSUTRat0');
  });

  it('refuses a whole line chain rewritten together (values changed, chain repaired): the receipts still carry the real digests', () => {
    const { receipts, observed } = logs(6);
    const forged = rechain(observed.map((r) => ({ ...r, params: { recipients: 99 } })));
    expect(checkObservedChain(forged).ok).toBe(true);
    expect(() => fromReceipts(receipts, {}, forged)).toThrow(/does not match the digest its receipt carries/);
  });

  it('refuses a deletion in the middle, even with the chain repaired, but accepts a lost tail', () => {
    const { receipts, observed } = logs(6);
    const middle = rechain(observed.filter((_, i) => i !== 2));
    expect(checkObservedChain(middle).ok).toBe(true);
    expect(() => fromReceipts(receipts, {}, middle)).toThrow(/receipt 2 carries a parameters digest but its line is missing/);
    const tail = observed.slice(0, 5);
    expect(fromReceipts(receipts, {}, tail).traces.filter((t) => Object.keys(t.params).length > 0)).toHaveLength(5);
    expect(() => fromReceipts(receipts, {}, observed.slice(0, 4))).toThrow(/receipt 4 carries/); // two lost is not a crash tail
  });

  it('refuses a line whose receipt carries no digest', () => {
    const { receipts, observed } = logs(6, { noFacts: [1] });
    expect(() => fromReceipts(receipts, {}, observed)).toThrow(/has no digest on its receipt/);
  });

  it('refuses an edited value, a re-pointed line, a dropped middle line and an orphan', () => {
    const { receipts, observed } = logs(6);
    const edited = observed.map((r, i) => (i === 2 ? { ...r, params: { recipients: 99 } } : r));
    expect(() => fromReceipts(receipts, {}, edited)).toThrow(/observed-parameters log is not an intact chain/);
    expect(checkObservedChain(edited).ok).toBe(false);
    const gap = observed.filter((_, i) => i !== 2);
    expect(() => fromReceipts(receipts, {}, gap)).toThrow(/intact chain/);
    const other = logs(6);
    expect(() => fromReceipts(receipts, {}, other.observed)).toThrow(/does not belong/);
    expect(() => fromReceipts(receipts.slice(0, 3), {}, observed)).toThrow(/does not belong/);
  });

  it('reads an observe-mode receipt whose allowed fact is false as a denial', () => {
    const { receipts } = logs(4, { allowed: (i) => (i === 3 ? 'false' : 'true') });
    expect(fromReceipts(receipts).traces.map((t) => t.outcome).sort()).toEqual(['allow', 'allow', 'allow', 'deny']);
  });
});
