import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkObservedChain, fromReceipts, observedHash, parseObservedParams } from '@atlasauth/pca-autopilot';
import type { ActionDef } from '@atlasauth/pca-actions';
import { describe, expect, it } from 'vitest';
import { readReceipts } from './audit';
import { Engine } from './engine';
import { ObservedParamsLog, checkLines, observedLineHash, readLines, selectParams, verifyObserved, type ObservedLine } from './observed';
import { rules } from './test-support/fakes';
import { setup } from './test-support/harness';

const def = (params: Record<string, unknown>): ActionDef => ({ params }) as unknown as ActionDef;
const dir = (): string => mkdtempSync(join(tmpdir(), 'pcap-obs-'));

describe('which parameters may be recorded', () => {
  const d = def({
    count: { type: 'integer' },
    flag: { type: 'boolean' },
    kind: { type: 'string', values: ['a', 'b'] },
    amount: { type: 'integer', sensitivity: 'material' },
    wire: { type: 'integer', sensitivity: 'critical' },
    note: { type: 'string' },
    long: { type: 'string', values: ['x'.repeat(65)] },
    email: { type: 'integer', role: 'contact.email' },
    ssn: { type: 'integer', tags: ['pii'] },
    key: { type: 'integer', tags: ['secret'] },
    where: { type: 'integer', role: 'path.file' },
    sql: { type: 'integer', tags: ['sql'] },
    when: { type: 'datetime' },
    list: { type: 'set', values: ['p'] },
    'nested.n': { type: 'integer' },
  });
  const args = { count: 3, flag: true, kind: 'a', amount: 500, wire: 9, note: 'hello world secret', long: 'x'.repeat(65), email: 1, ssn: 2, key: 3, where: 4, sql: 5, when: '2026-01-01T00:00:00Z', list: ['p'], nested: { n: 7 } };

  it('records free integers, booleans and short enum strings only', () => {
    const r = selectParams(d, args, []);
    expect(r.params).toEqual({ count: 3, flag: true, kind: 'a', 'nested.n': 7 });
  });

  it('a material parameter needs an explicit include; a critical one never', () => {
    expect(selectParams(d, args, ['amount']).params.amount).toBe(500);
    expect(selectParams(d, args, ['amount', 'wire']).params).not.toHaveProperty('wire');
  });

  it('credential, personal, path, query, code and text parameters are never recorded, include or not', () => {
    const r = selectParams(d, args, ['email', 'ssn', 'key', 'where', 'sql', 'amount', 'wire', 'note']);
    for (const n of ['email', 'ssn', 'key', 'where', 'sql', 'wire', 'note', 'when', 'list']) expect(r.params).not.toHaveProperty(n);
    expect(r.omitted).toEqual(expect.arrayContaining(['email', 'ssn', 'key', 'where', 'sql', 'wire', 'note', 'when', 'list']));
  });

  it('only the NAME of what is left out is written, never the value', () => {
    const r = selectParams(d, args, []);
    expect(JSON.stringify(r)).not.toMatch(/hello world|secret|2026/);
  });

  it('a value outside its declared domain, or a float, is not recorded', () => {
    expect(selectParams(d, { count: 1.5, kind: 'zzz' }, []).params).toEqual({});
    expect(selectParams(d, { count: Number.MAX_SAFE_INTEGER + 2 }, []).params).toEqual({});
  });

  it('writes at most 32 parameters and 32 names', () => {
    const many = def(Object.fromEntries(Array.from({ length: 64 }, (_, i) => [`p${i}`, { type: 'integer' }])));
    const r = selectParams(many, Object.fromEntries(Array.from({ length: 64 }, (_, i) => [`p${i}`, i])), []);
    expect(Object.keys(r.params)).toHaveLength(32);
    expect(r.omitted).toHaveLength(32);
  });
});

describe('the log through the proxy', () => {
  function run(over: Record<string, unknown> = {}) {
    const d = dir();
    const audit = join(d, 'a.jsonl');
    const t = setup({ mode: 'observe', audit: { path: audit, observedParams: { enabled: true, include: [] } }, ...over }, rules(), undefined, (cfg, candidates) => Engine.create({ cfg, candidates }));
    return { t, audit, params: `${audit}.params.jsonl` };
  }

  it('is off by default', async () => {
    const d = dir();
    const audit = join(d, 'a.jsonl');
    const t = setup({ mode: 'observe', audit: { path: audit } });
    await t.call('read_issue', { id: 1 });
    expect(existsSync(`${audit}.params.jsonl`)).toBe(false);
    expect(readReceipts(audit)[0]!.checks).not.toHaveProperty('obs1');
  });

  it('refuses to start in enforce mode', async () => {
    const t = setup({ mode: 'enforce', audit: { path: join(dir(), 'a.jsonl'), observedParams: { enabled: true } } });
    expect(t.denied(await t.call('read_issue', { id: 1 }))).toMatch(/upstream_unavailable/);
  });

  it('writes a line per decision, bound both ways, and the autopilot reader accepts it', async () => {
    const { t, audit, params } = run();
    await t.call('read_issue', { id: 7 });
    await t.call('create_issue', { title: 'a secret title nobody may log' });
    await t.call('dump_secrets');
    const receipts = readReceipts(audit);
    const lines = readLines(params);
    expect(lines.map((l) => l.params)).toEqual([{ id: 7 }, {}]);
    expect(lines[1]!.omitted).toEqual(['title']);
    expect(readFileSync(params, 'utf8')).not.toMatch(/secret title/);
    expect(verifyObserved(receipts, lines)).toMatchObject({ ok: true, lines: 2 });
    for (const l of lines) expect(receipts[l.seq]!.checks).toMatchObject({ obs1: expect.any(String), obs2: expect.any(String) });
    // the autopilot reader's own contract
    const recs = parseObservedParams(readFileSync(params, 'utf8'));
    expect(checkObservedChain(recs)).toEqual({ ok: true });
    for (const l of lines) expect(observedLineHash({ ...l, hash: undefined } as never)).toBe(observedHash(l as never));
    expect(() => fromReceipts(receipts, {}, recs)).not.toThrow();
  });

  it('a tampered line is refused by the reader and by the verifier', async () => {
    const { t, audit, params } = run();
    await t.call('read_issue', { id: 7 });
    await t.call('read_issue', { id: 8 });
    const receipts = readReceipts(audit);
    const lines = readLines(params);
    const edited = lines.map((l) => ({ ...l, params: { ...l.params } }));
    edited[0]!.params.id = 7_000_000;
    expect(() => fromReceipts(receipts, {}, edited as never)).toThrow(/edited line|intact chain/);
    expect(verifyObserved(receipts, edited)).toMatchObject({ ok: false });
  });

  it('a chain break (a missing or reordered line) is refused', async () => {
    const { t, audit, params } = run();
    for (const id of [1, 2, 3]) await t.call('read_issue', { id });
    const receipts = readReceipts(audit);
    const lines = readLines(params);
    expect(lines).toHaveLength(3);
    expect(checkLines([lines[0]!, lines[2]!])).toMatchObject({ ok: false });
    expect(checkLines([lines[1]!, lines[0]!, lines[2]!])).toMatchObject({ ok: false });
    expect(() => fromReceipts(receipts, {}, [lines[0]!, lines[2]!] as never)).toThrow(/intact chain/);
  });

  it('a line rewritten together with its own chain still cannot match the receipt it names', async () => {
    const { t, audit, params } = run();
    await t.call('read_issue', { id: 7 });
    await t.call('read_issue', { id: 8 });
    const receipts = readReceipts(audit);
    const lines = readLines(params);
    // an attacker who recomputes the whole line chain: the hash chain is fine, the receipt's digest is not
    const forged: ObservedLine[] = [];
    let prev = '';
    for (const l of lines) {
      const body = { v: 1 as const, seq: l.seq, receipt: l.receipt, verb: l.verb, resource: l.resource, params: l.seq === lines[0]!.seq ? { id: 90_000 } : l.params, omitted: l.omitted, prev };
      const f = { ...body, hash: observedLineHash(body) };
      forged.push(f);
      prev = f.hash;
    }
    expect(checkLines(forged)).toEqual({ ok: true });
    expect(verifyObserved(receipts, forged)).toMatchObject({ ok: false, reason: expect.stringMatching(/digest its receipt carries/) });
  });

  it('a deleted line is found, except the very last one', async () => {
    const { t, audit, params } = run();
    for (const id of [1, 2, 3]) await t.call('read_issue', { id });
    const receipts = readReceipts(audit);
    const lines = readLines(params);
    const rechain = (xs: ObservedLine[]): ObservedLine[] => {
      let prev = '';
      return xs.map((l) => {
        const body = { v: 1 as const, seq: l.seq, receipt: l.receipt, verb: l.verb, resource: l.resource, params: l.params, omitted: l.omitted, prev };
        const f = { ...body, hash: observedLineHash(body) };
        prev = f.hash;
        return f;
      });
    }
    expect(verifyObserved(receipts, rechain([lines[0]!, lines[2]!]))).toMatchObject({ ok: false, reason: expect.stringMatching(/line is missing/) });
    expect(verifyObserved(receipts, rechain([lines[0]!, lines[1]!]))).toMatchObject({ ok: true });
  });

  it('refuses to append to a file whose chain is broken, and a write failure never blocks the call', async () => {
    const { t, params } = run();
    await t.call('read_issue', { id: 1 });
    await t.call('read_issue', { id: 2 });
    const text = readFileSync(params, 'utf8').split('\n').filter(Boolean);
    writeFileSync(params, `${text[1]}\n`);
    expect(() => new ObservedParamsLog(params)).toThrow(/not an intact chain/);
    // a log that cannot be written: the receipt stands, the call goes through
    const d = dir();
    const audit = join(d, 'a.jsonl');
    const broken = new ObservedParamsLog(join(d, 'p.jsonl'));
    broken.write = () => {
      throw new Error('disk full');
    };
    const warned: string[] = [];
    const t2 = setup({ mode: 'observe', audit: { path: audit } }, rules(), undefined, async (cfg, candidates) => {
      const e = await Engine.create({ cfg, candidates, observed: broken });
      e.warn = (l) => warned.push(l);
      return e;
    });
    expect(t2.denied(await t2.call('read_issue', { id: 1 }))).toBe('');
    expect(warned).toHaveLength(1);
    expect(warned[0]).toMatch(/disk full/);
  });
});

describe('the config', () => {
  it('knows the keys and nothing else', async () => {
    const { parseConfig } = await import('./config');
    const ok = parseConfig({ mcp: { ns: 'gh', tools: {} }, audit: { path: 'a', observedParams: { enabled: true, include: ['amount'] }, observedParamsPath: 'p' } });
    expect(ok.audit.observedParams).toEqual({ enabled: true, include: ['amount'] });
    expect(() => parseConfig({ mcp: { ns: 'gh', tools: {} }, audit: { observedParams: { enabled: true, includes: [] } } })).toThrow();
    expect(() => parseConfig({ mcp: { ns: 'gh', tools: {} }, audit: { observedParams: { include: ['a b'] } } })).toThrow();
    expect(parseConfig({ mcp: { ns: 'gh', tools: {} } }).audit.observedParams).toBeUndefined();
  });
});
