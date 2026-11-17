import { describe, expect, it } from 'vitest';
import { appendReceipt, agent, generateKeyPair, type Receipt } from '@atlasauth/pca';
import { fromOtelSpans, fromReceipts, ingestText } from './ingest';
import { NOW, benign, jsonl, row } from './test-support/fixtures';

describe('ingest', () => {
  it('reads JSONL into a deterministic, sorted set', () => {
    const a = ingestText(jsonl(benign()));
    const b = ingestText(jsonl([...benign()].reverse()));
    expect(a.traces).toHaveLength(6);
    expect(a.rejected).toHaveLength(0);
    expect(a.digest).toBe(b.digest);
    expect(a.traces.map((t) => t.at)).toEqual([...a.traces.map((t) => t.at)].sort((x, y) => x - y));
  });

  it('rejects records an attacker could use to smuggle a pattern, a traversal or a non-finite number', () => {
    const bad = [
      row(1, { resource: '/drafts/*' }),
      row(2, { resource: 're:.*' }),
      row(3, { resource: '/a/../etc' }),
      row(4, { resource: '/a/\u0000b' }),
      row(5, { at: 'soon' }),
      row(6, { verb: 'a b' }),
      row(7, { outcome: 'maybe' }),
      row(8, { tenant: 'a b' }),
      '{"at":1,"verb":"a.b","resource":"/x","params":{"amount":1e999}}',
      '{"at":1,"verb":"a.b","resource":"/x","params":{"__proto__":1}}',
      'not json',
    ];
    const s = ingestText(jsonl(bad));
    expect(s.traces).toHaveLength(0);
    expect(s.rejected).toHaveLength(bad.length);
    expect(s.rejected.find((r) => r.index === 8)?.reason).toMatch(/finite/);
  });

  it('drops nested params instead of guessing, and keeps primitives', () => {
    const s = ingestText(jsonl([row(1, { params: { n: 1, s: 'x', b: true, nested: { a: 1 }, nul: null } })]));
    expect(s.traces[0]!.params).toEqual({ n: 1, s: 'x', b: true });
  });

  it('caps a flood and reports how much it dropped', () => {
    const s = ingestText(jsonl(Array.from({ length: 25 }, (_, i) => row(i))), 'jsonl', { maxTraces: 10 });
    expect(s.traces).toHaveLength(10);
    expect(s.truncated).toBe(15);
  });

  it('flags sensitive actions at ingest and never leaves the flag to a later stage', () => {
    const s = ingestText(jsonl([row(1, { verb: 'gmail.delete' }), row(2, { resource: '/secrets/key' }), row(3), row(4, { actor: 'mallory' })]), 'jsonl', { trustedActors: ['agent-1'] });
    const by = (i: number) => s.traces.find((t) => t.at === NOW - 86_400_000 + i * 1000)!;
    expect(by(1).sensitive).toEqual(expect.arrayContaining(['dangerous-verb', 'irreversible-action']));
    expect(by(2).sensitive).toContain('sensitive-resource');
    expect(by(4).sensitive).toContain('untrusted-actor');
    expect(by(3).sensitive).toContain('untrusted-actor'); // no actor is not a trusted actor
  });

  it('flags an amount far above the rest of its group', () => {
    const rows = [...Array.from({ length: 6 }, (_, i) => row(i, { verb: 'quotes.create', params: { amount: 10 + i } })), row(9, { verb: 'quotes.create', params: { amount: 5000 } })];
    const s = ingestText(jsonl(rows));
    expect(s.traces.filter((t) => t.sensitive.includes('amount-outlier:amount'))).toHaveLength(1);
  });

  it('reads OpenTelemetry spans (attribute bag and OTLP list) and rejects a span without a decision', () => {
    const s = fromOtelSpans([
      { startTimeUnixNano: String(NOW * 1e6), attributes: { 'pca.verb': 'gmail.draft', 'pca.resource': '/drafts/1', 'pca.decision': 'allow', 'pca.param.recipients': 2 } },
      { startTime: NOW, attributes: [{ key: 'pca.verb', value: { stringValue: 'gmail.draft' } }, { key: 'pca.resource', value: { stringValue: '/drafts/2' } }, { key: 'pca.decision', value: { stringValue: 'deny' } }] },
      { startTime: NOW, attributes: { 'pca.verb': 'gmail.draft', 'pca.resource': '/drafts/3' } },
    ]);
    expect(s.traces).toHaveLength(2);
    expect(s.traces.find((t) => t.outcome === 'allow')!.params).toEqual({ recipients: 2 });
    expect(s.traces.filter((t) => t.outcome === 'deny')).toHaveLength(1);
    expect(s.rejected).toHaveLength(1);
  });

  describe('receipts', () => {
    const log = (): Receipt[] => {
      const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { gmail: ['draft'] }, aud: 'inst' });
      let l: Receipt[] = [];
      for (let i = 0; i < 3; i++) l = appendReceipt(l, a.act('gmail.draft', `/drafts/${i}`, {}, { now: NOW + i }).pcactn, { allow: true, checks: {} });
      return l;
    };
    it('ingests an intact hash-chained log', () => {
      const s = fromReceipts(log());
      expect(s.traces).toHaveLength(3);
      expect(s.traces[0]!.source).toBe('receipt');
    });
    it('refuses an edited log', () => {
      const l = log();
      l[1] = { ...l[1]!, resource: '/drafts/evil' };
      expect(() => fromReceipts(l)).toThrow(/intact chain/);
    });
  });
});
