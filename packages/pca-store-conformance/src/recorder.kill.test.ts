import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { FileRecorder, parseHistory } from './recorder';

describe('FileRecorder', () => {
  const open = () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-rec-'));
    const f = join(dir, 'h.jsonl');
    return { f, r: new FileRecorder(f, 'p0') };
  };

  it('returns the recorded operation and numbers invocations from 1', () => {
    const { f, r } = open();
    const a = r.invoke('c0', 'consume', 'k1', 5, 9);
    const b = r.invoke('c1', 'advance', 'k2', 3, 3);
    expect(a).toEqual({ client: 'c0', kind: 'consume', key: 'k1', lo: 5, w: 9, call: a.call, ret: Infinity, res: 'unknown' });
    expect(typeof a.call).toBe('number');
    expect(b.res).toBe('unknown');
    r.complete(a, 'unknown');
    r.close();
    const lines = readFileSync(f, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as unknown[]);
    expect(lines.map((l) => [l[0], l[1], l[2]])).toEqual([
      ['i', 'p0', 1],
      ['i', 'p0', 2],
      ['r', 'p0', 1],
    ]);
    expect(lines[2]![4]).toBe('unknown');
  });

  it('close releases the file: later events cannot be written', () => {
    const { r } = open();
    r.close();
    expect(() => r.invoke('c', 'advance', 'k', 1, 1)).toThrow();
  });
});

describe('parseHistory: only well-formed lines count', () => {
  const inv = '["i","p0",1,1,"a","advance","k",1,1]';

  it('an invocation-shaped line with another tag is torn', () => {
    const h = parseHistory('["x","p0",1,1,"a","advance","k",1,1]');
    expect(h).toEqual({ ops: [], torn: 1, pending: 0 });
  });

  it('a response completes an open invocation only when it is tagged r and has five fields', () => {
    expect(parseHistory([inv, '["q","p0",1,5,"true"]'].join('\n'))).toMatchObject({ torn: 1, pending: 1, ops: [{ res: 'unknown', ret: Infinity }] });
    expect(parseHistory([inv, '["r","p0",1,5,"true","extra"]'].join('\n'))).toMatchObject({ torn: 1, pending: 1, ops: [{ res: 'unknown', ret: Infinity }] });
    expect(parseHistory([inv, '["r","p0",1,5,"true"]'].join('\n'))).toMatchObject({ torn: 0, pending: 0, ops: [{ res: 'true', ret: 5 }] });
  });
});
