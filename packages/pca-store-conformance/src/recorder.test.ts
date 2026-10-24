import { appendFileSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { FileRecorder, MemoryRecorder, clock, parseHistory } from './recorder';

describe('clock', () => {
  it('is wall-clock milliseconds with sub-millisecond resolution, non-decreasing', () => {
    const a = clock();
    const b = clock();
    expect(Math.abs(a - Date.now())).toBeLessThan(1000);
    expect(b).toBeGreaterThanOrEqual(a);
  });
});

describe('MemoryRecorder', () => {
  it('records the invocation before and the response after; unknown stays open-ended', async () => {
    const r = new MemoryRecorder();
    const a = r.invoke('c0', 'consume', 'k', 5, 9);
    expect(a).toMatchObject({ client: 'c0', kind: 'consume', key: 'k', lo: 5, w: 9, ret: Infinity, res: 'unknown' });
    await new Promise((x) => setTimeout(x, 2));
    r.complete(a, true);
    expect(a.res).toBe('true');
    expect(a.ret).toBeGreaterThan(a.call);
    const b = r.invoke('c1', 'advance', 'k', 3, 3);
    r.complete(b, false);
    expect(b.res).toBe('false');
    expect(b.ret).not.toBe(Infinity);
    const c = r.invoke('c1', 'advance', 'k', 4, 4);
    r.complete(c, 'unknown');
    expect(c).toMatchObject({ res: 'unknown', ret: Infinity });
    expect(r.ops).toEqual([a, b, c]);
  });
});

describe('FileRecorder + parseHistory', () => {
  it('round-trips: definite answers, unknown responses (open-ended) and pending invocations', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-rec-'));
    const f = join(dir, 'h.jsonl');
    const r = new FileRecorder(f, 'p0');
    const a = r.invoke('p0c0', 'consume', 'k1', 5, 9);
    r.complete(a, true);
    const b = r.invoke('p0c1', 'advance', 'k2', 3, 3);
    r.complete(b, false);
    const c = r.invoke('p0c1', 'advance', 'k2', 4, 4);
    r.complete(c, 'unknown');
    r.invoke('p0c0', 'consume', 'k1', 6, 10); // never completes (the process "died")
    r.close();
    const text = readFileSync(f, 'utf8');
    expect(text.split('\n').filter(Boolean)).toHaveLength(7);
    const h = parseHistory(text);
    expect(h.torn).toBe(0);
    expect(h.pending).toBe(1);
    expect(h.ops).toHaveLength(4);
    expect(h.ops[0]).toMatchObject({ client: 'p0c0', kind: 'consume', key: 'k1', lo: 5, w: 9, res: 'true' });
    expect(h.ops[0]!.ret).toBeGreaterThanOrEqual(h.ops[0]!.call);
    expect(h.ops[0]!.ret).not.toBe(Infinity);
    expect(h.ops[1]).toMatchObject({ kind: 'advance', key: 'k2', lo: 3, w: 3, res: 'false' });
    expect(h.ops[2]).toMatchObject({ res: 'unknown', ret: Infinity });
    expect(h.ops[3]).toMatchObject({ res: 'unknown', ret: Infinity, lo: 6, w: 10 });
  });
  it('appends (several incarnations share nothing but the directory) and ids are per process', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-rec-'));
    const f = join(dir, 'h.jsonl');
    const r1 = new FileRecorder(f, 'p0');
    r1.complete(r1.invoke('a', 'advance', 'k', 1, 1), true);
    r1.close();
    const r2 = new FileRecorder(f, 'p1');
    r2.complete(r2.invoke('b', 'advance', 'k', 2, 2), true);
    r2.close();
    const h = parseHistory(readFileSync(f, 'utf8'));
    expect(h.ops.map((o) => [o.client, o.res])).toEqual([
      ['a', 'true'],
      ['b', 'true'],
    ]);
    expect(h.pending).toBe(0);
  });
  it('counts torn / foreign lines and ignores a response without its invocation', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-rec-'));
    const f = join(dir, 'h.jsonl');
    const r = new FileRecorder(f, 'p0');
    r.complete(r.invoke('a', 'advance', 'k', 1, 1), true);
    r.close();
    appendFileSync(f, '["i","p9",1,5,"x","advance","k",2\n'); // torn mid-line (SIGKILL during write)
    appendFileSync(f, '{"not":"an array"}\nnull\n[]\n["r","p0",77,9,"true"]\n["i","p0",2,1,"a","advance","k",1]\n["r","p0",1,9,"true","extra"]\n\n');
    const h = parseHistory(readFileSync(f, 'utf8'));
    expect(h.ops).toHaveLength(1);
    expect(h.torn).toBe(7);
  });
  it('a response line naming a known invocation of ANOTHER process does not complete it', () => {
    const lines = ['["i","p0",1,1,"a","advance","k",1,1]', '["r","p1",1,2,"true"]', '["r","p0",1,3,"false"]'].join('\n');
    const h = parseHistory(lines);
    expect(h.torn).toBe(1);
    expect(h.ops[0]).toMatchObject({ res: 'false', ret: 3, call: 1 });
  });
});
