/** Mutation-kill tests for durable-state.ts: forged journals/heads with VALID hashes so each guard fires on its own, exact messages. */
import { createHash, createHmac } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryDurableKv, DurableStateError, openDurableState } from './durable-state';

const dirs: string[] = [];
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), 'ds-mk-'));
  dirs.push(d);
  return d;
};
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});
const GEN = '0'.repeat(64);
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const KEY = new Uint8Array(32).fill(7);
const mac = (m: string, k: Uint8Array = KEY) => createHmac('sha256', k).update(m).digest('hex');
interface R { seq: number; prev: string; op: string; payload: string; ts: number; gen?: number; h: string; mac?: string }
/** gen omitted = a legacy (pre-R6-CORE-01) record, hashed exactly as older versions did. */
const mk = (seq: number, prev: string, op: 'set' | 'checkpoint', payload: string, key?: Uint8Array, ts = 1000, gen?: number): R => {
  const h = sha('pca-durable-state/v1\n' + JSON.stringify(gen === undefined ? [seq, prev, op, payload, ts] : [seq, prev, op, payload, ts, gen]));
  return { seq, prev, op, payload, ts, ...(gen === undefined ? {} : { gen }), h, ...(key ? { mac: mac(h, key) } : {}) };
};
const chain = (n: number, key?: Uint8Array): R[] => {
  const out: R[] = [];
  let prev = GEN;
  for (let i = 1; i <= n; i++) { const r = mk(i, prev, 'set', `k${i}\n${i}`, key); out.push(r); prev = r.h; }
  return out;
};
const wj = (d: string, recs: unknown[], raw?: string) => writeFileSync(join(d, 'state.journal'), raw ?? recs.map((r) => JSON.stringify(r)).join('\n') + (recs.length ? '\n' : ''));
const wh = (d: string, o: unknown) => writeFileSync(join(d, 'state.head'), typeof o === 'string' ? o : JSON.stringify(o) + '\n');
const headOf = (r: R, key?: Uint8Array, gen?: number) => ({
  seq: r.seq, h: r.h, ...(gen === undefined ? {} : { gen }),
  ...(key ? { mac: mac(gen === undefined ? `head\n${r.seq}\n${r.h}` : `head\n${r.seq}\n${r.h}\n${gen}`, key) } : {}),
});
const open = (d: string, o: Record<string, unknown> = {}) => openDurableState({ dir: d, ...o } as never);
const rej = async (p: Promise<unknown>, msg: string | RegExp) => {
  let e: unknown;
  try { await p; } catch (x) { e = x; }
  expect(e, 'expected rejection').toBeInstanceOf(DurableStateError);
  if (typeof msg === 'string') expect((e as Error).message).toBe(msg); else expect((e as Error).message).toMatch(msg);
  return e as DurableStateError;
};

describe('DurableStateError and the in-memory kv', () => {
  it('error carries code, name and a "code: message" message', () => {
    const e = new DurableStateError('corrupt', 'x');
    expect(e.code).toBe('corrupt');
    expect(e.name).toBe('DurableStateError');
    expect(e.message).toBe('corrupt: x');
    expect(e).toBeInstanceOf(Error);
  });
  it('memory kv: invalid values, unchanged update, sorted keys, snapshot is a parsed copy', async () => {
    const kv = createMemoryDurableKv();
    await rej(kv.set('a', undefined), 'invalid: value is not JSON-serialisable');
    await rej(kv.set('a', () => 1), 'invalid: value is not JSON-serialisable');
    await rej(kv.update('a', () => (() => 1) as never), 'invalid: value is not JSON-serialisable');
    expect(await kv.update('a', () => undefined)).toBeUndefined();
    await kv.set('b', { x: 1 });
    await kv.set('a', [1]);
    expect(await kv.update('b', () => undefined)).toEqual({ x: 1 });
    expect(await kv.keys()).toEqual(['a', 'b']);
    const snap = kv.snapshot();
    expect([...snap.entries()].sort()).toEqual([['a', [1]], ['b', { x: 1 }]]);
    (snap.get('b') as { x: number }).x = 9;
    expect(await kv.get('b')).toEqual({ x: 1 });
    const kv2 = createMemoryDurableKv();
    await kv2.set('z', 1); await kv2.set('m', 2); await kv2.set('a', 3);
    expect(await kv2.keys()).toEqual(['a', 'm', 'z']);
  });
});

describe('open options', () => {
  it('dir and hmacKey validation', async () => {
    for (const bad of [undefined, '', 5, null]) await rej(openDurableState({ dir: bad } as never), 'invalid: dir is required');
    await rej(openDurableState(undefined as never), 'invalid: dir is required');
    await rej(open(tmp(), { hmacKey: new Uint8Array(31) }), 'invalid: hmacKey must be at least 32 bytes');
    await (await open(tmp(), { hmacKey: new Uint8Array(32) })).verify();
  });
  it('an existing directory is tightened to 0700', async () => {
    const d = tmp();
    chmodSync(d, 0o755);
    await open(d);
    expect(statSync(d).mode & 0o777).toBe(0o700);
  });
  it('compactEvery below 2 is clamped to 2 and the default is 256', async () => {
    const d = tmp();
    const s = await open(d, { compactEvery: 0, now: () => 5 });
    for (let i = 0; i < 3; i++) await s.set('k' + i, i);
    const lines = readFileSync(join(d, 'state.journal'), 'utf8').trim().split('\n');
    expect(lines).toHaveLength(1); // 3rd record > 2 -> checkpoint
    const cp = JSON.parse(lines[0]!) as R;
    expect(cp.op).toBe('checkpoint');
    expect(cp.seq).toBe(3);
    expect(cp.ts).toBe(5);
    const d2 = tmp();
    const s2 = await open(d2);
    for (let i = 0; i < 256; i++) await s2.set('k', i);
    expect(readFileSync(join(d2, 'state.journal'), 'utf8').trim().split('\n')).toHaveLength(256);
    await s2.set('k', 999);
    expect(readFileSync(join(d2, 'state.journal'), 'utf8').trim().split('\n')).toHaveLength(1);
    expect(await s2.get('k')).toBe(999);
  }, 60000);
});

describe('commit format', () => {
  it('records, head and checkpoint are exact; sorted checkpoint entries; MAC when keyed', async () => {
    const d = tmp();
    const s = await open(d, { hmacKey: KEY, now: () => 42, compactEvery: 3 });
    await s.set('b', { v: 1 });
    const rec1 = JSON.parse(readFileSync(join(d, 'state.journal'), 'utf8').trim()) as R;
    // lock generations: open holds 1 (release 2), this set holds 3; record and head carry it (R6-CORE-01)
    expect(rec1).toEqual(mk(1, GEN, 'set', 'b\n{"v":1}', KEY, 42, 3));
    const head = JSON.parse(readFileSync(join(d, 'state.head'), 'utf8')) as Record<string, unknown>;
    expect(head).toEqual(headOf(rec1, KEY, 3));
    expect(readFileSync(join(d, 'state.head'), 'utf8').endsWith('\n')).toBe(true);
    await s.set('c', 2); await s.set('a', 3); await s.set('d', 4); // 4th > 3 -> checkpoint
    const lines = readFileSync(join(d, 'state.journal'), 'utf8').trim().split('\n');
    expect(lines).toHaveLength(1);
    const cp = JSON.parse(lines[0]!) as R;
    expect(cp).toEqual(mk(4, cp.prev, 'checkpoint', JSON.stringify([['a', '3'], ['b', '{"v":1}'], ['c', '2'], ['d', '4']]), KEY, 42, 9));
    expect(JSON.parse(readFileSync(join(d, 'state.head'), 'utf8'))).toEqual(headOf(cp, KEY, 9));
    expect(await s.keys()).toEqual(['a', 'b', 'c', 'd']);
    expect(s.position()).toEqual({ seq: 4, hash: cp.h });
    expect(await s.verify()).toEqual({ seq: 4, hash: cp.h });
    const p = s.position(); p.seq = 99;
    expect(s.position().seq).toBe(4);
    // reopen from the checkpoint-only journal
    const s2 = await open(d, { hmacKey: KEY });
    expect(await s2.get('d')).toBe(4);
  });
  it('unkeyed records carry no mac field; keys ordering uses code-unit order', async () => {
    const d = tmp();
    const s = await open(d, { compactEvery: 2, now: () => 1 });
    await s.set('B', 1); await s.set('a', 2); await s.set('A', 3);
    const cp = JSON.parse(readFileSync(join(d, 'state.journal'), 'utf8').trim()) as R;
    expect('mac' in cp).toBe(false);
    expect(JSON.parse(cp.payload)).toEqual([['A', '3'], ['B', '1'], ['a', '2']]);
  });
  it('update: unchanged value commits nothing; undefined leaves it; returns a parsed copy; set/update validate keys and values', async () => {
    const d = tmp();
    const s = await open(d);
    expect(await s.update('k', () => undefined)).toBeUndefined();
    expect(s.position().seq).toBe(0);
    expect(await s.update('k', () => ({ a: 1 }))).toEqual({ a: 1 });
    expect(s.position().seq).toBe(1);
    expect(await s.update('k', () => ({ a: 1 }))).toEqual({ a: 1 });
    expect(s.position().seq).toBe(1);
    expect(await s.update('k', () => undefined)).toEqual({ a: 1 });
    expect(await s.update('k', (p) => ({ n: (p as { a: number }).a + 1 }))).toEqual({ n: 2 });
    expect(s.position().seq).toBe(2);
    const BADK = 'invalid: key must be 1..256 chars without newlines';
    for (const k of ['', 'x'.repeat(257), 'a\nb', 5 as never]) {
      await rej(s.get(k), BADK); await rej(s.set(k, 1), BADK); await rej(s.update(k, () => 1), BADK);
    }
    await s.set('x'.repeat(256), 1);
    await rej(s.set('k', undefined), 'invalid: value is not JSON-serialisable');
    await rej(s.update('k', () => (() => 1) as never), 'invalid: value is not JSON-serialisable');
  });
  it('maxValueBytes boundary (default 1 MiB and custom) with the exact message', async () => {
    const s = await open(tmp(), { maxValueBytes: 10 });
    await s.set('k', '12345678'); // JSON length 10
    await rej(s.set('k', '123456789'), 'too-large: value exceeds maxValueBytes=10');
    await rej(s.update('k', () => '123456789'), 'too-large: value exceeds maxValueBytes=10');
    const big = await open(tmp());
    await big.set('k', 'x'.repeat(1_048_574));
    await rej(big.set('k', 'x'.repeat(1_048_575)), 'too-large: value exceeds maxValueBytes=1048576');
  });
  it('payload values may contain newlines', async () => {
    const s = await open(tmp());
    await s.set('k', 'a\nb');
    expect(await s.get('k')).toBe('a\nb');
  });
  it('set and update repair a lagging head before committing; get/keys/verify do not touch it', async () => {
    for (const via of ['set', 'update'] as const) {
      const d = tmp();
      const s = await open(d);
      await s.set('a', 1);
      const recs = readFileSync(join(d, 'state.journal'), 'utf8').trim().split('\n').map((l) => JSON.parse(l) as R);
      const r2 = mk(2, recs[0]!.h, 'set', 'b\n2', undefined, 1000, recs[0]!.gen); // same generation: not a stale writer
      wj(d, [...recs, r2]); // head still at seq 1
      expect(JSON.parse(readFileSync(join(d, 'state.head'), 'utf8')).seq).toBe(1);
      expect(await s.get('b')).toBe(2);
      expect(JSON.parse(readFileSync(join(d, 'state.head'), 'utf8')).seq).toBe(1);
      if (via === 'set') await s.set('c', 3); else await s.update('c', () => 3);
      expect(JSON.parse(readFileSync(join(d, 'state.head'), 'utf8')).seq).toBe(3);
      expect((await s.verify()).seq).toBe(3);
    }
    // head file missing while the journal is at seq 1 is repaired by set
    const d = tmp();
    const s = await open(d);
    await s.set('a', 1);
    unlinkSync(join(d, 'state.head'));
    await s.set('b', 2);
    expect(JSON.parse(readFileSync(join(d, 'state.head'), 'utf8')).seq).toBe(2);
  });
  it('opening repairs a head that lags by one, and writes a missing head', async () => {
    const d = tmp();
    const recs = chain(2);
    wj(d, recs); wh(d, headOf(recs[0]!));
    const s = await open(d);
    // the repaired head names the legacy tail and carries the repairing writer's generation (open holds generation 1)
    expect(JSON.parse(readFileSync(join(d, 'state.head'), 'utf8'))).toEqual(headOf(recs[1]!, undefined, 1));
    expect(s.position()).toEqual({ seq: 2, hash: recs[1]!.h });
    const d2 = tmp();
    const r1 = chain(1);
    wj(d2, r1);
    await open(d2);
    expect(JSON.parse(readFileSync(join(d2, 'state.head'), 'utf8'))).toEqual(headOf(r1[0]!, undefined, 1));
  });
});

describe('head file validation', () => {
  it('not JSON / bad shapes', async () => {
    const d = tmp();
    wh(d, '{nope');
    await rej(open(d), 'corrupt: state.head is not valid JSON');
    const h = chain(1)[0]!.h;
    const bad = [null, 5, [], { seq: -1, h }, { seq: 1.5, h }, { seq: '1', h }, { seq: 1, h: 5 }, { seq: 1, h: h.toUpperCase() }, { seq: 1, h: h.slice(1) }, { seq: 1, h: h + '0' }, { h }, { seq: 1 }];
    for (const b of bad) { wh(d, b); await rej(open(d), 'corrupt: state.head has an invalid shape'); }
    wh(d, { seq: 0, h }); // seq 0 is valid; no journal and seq 0: clean
    await open(d);
  });
  it('keyed: missing / wrong / non-string head mac are key-mismatch; unkeyed ignores a head mac', async () => {
    const recs = chain(1, KEY);
    const M = 'key-mismatch: state.head MAC does not verify (wrong key or forged head)';
    for (const hd of [{ seq: 1, h: recs[0]!.h }, { ...headOf(recs[0]!, KEY), mac: 'a'.repeat(64) }, { ...headOf(recs[0]!, KEY), mac: 5 }, { ...headOf(recs[0]!, KEY), mac: 'ab' }, headOf(recs[0]!, new Uint8Array(32).fill(1))]) {
      const d = tmp(); wj(d, recs); wh(d, hd);
      await rej(open(d, { hmacKey: KEY }), M);
    }
    const d = tmp(); wj(d, recs); wh(d, headOf(recs[0]!, KEY));
    await open(d, { hmacKey: KEY });
    const d2 = tmp(); const u = chain(1); wj(d2, u); wh(d2, { ...headOf(u[0]!), mac: 'whatever' });
    await open(d2);
  });
});

describe('journal validation (forged, hash-valid records)', () => {
  it('missing journal: head seq>0 is a rollback with the seq; head seq 0 / no head is clean; deleted while open', async () => {
    const d = tmp();
    wh(d, { seq: 3, h: chain(1)[0]!.h });
    await rej(open(d), 'rollback: state.journal is missing but state.head records seq 3');
    const d2 = tmp();
    const s = await open(d2);
    await s.set('a', 1);
    unlinkSync(join(d2, 'state.journal')); unlinkSync(join(d2, 'state.head'));
    await rej(s.get('a'), 'rollback: state was deleted while open');
    await rej(s.keys(), 'rollback: state was deleted while open');
    await rej(s.verify(), 'rollback: state was deleted while open');
  });
  it('no trailing newline / empty file', async () => {
    const d = tmp();
    const recs = chain(1);
    wj(d, [], JSON.stringify(recs[0]));
    await rej(open(d), 'corrupt: journal does not end with a newline (torn or truncated)');
    wj(d, [], '');
    const s = await open(d);
    expect(await s.keys()).toEqual([]);
    wh(d, { seq: 1, h: recs[0]!.h });
    await rej(open(d), /^rollback: journal is at seq 0 but state\.head recorded seq 1/);
  });
  it('line numbers are 1-based in every per-line message', async () => {
    const r = chain(1)[0]!;
    const d = tmp();
    wj(d, [], JSON.stringify(r) + '\n{bad\n');
    await rej(open(d), 'corrupt: journal line 2 is not valid JSON');
    const shapeBad = [null, 5, 'x', { ...r, seq: 'x' }, { ...r, seq: 1.5 }, { ...r, prev: 5 }, { ...r, prev: 'zz' }, { ...r, prev: GEN.toUpperCase().replace(/0/g, 'A') }, { ...r, op: 'del' }, { ...r, op: undefined }, { ...r, payload: 5 }, { ...r, ts: 'x' }, { ...r, ts: 1.5 }, { ...r, h: 5 }, { ...r, h: 'zz' }];
    for (const b of shapeBad) { wj(d, [], JSON.stringify(r) + '\n' + JSON.stringify(b) + '\n'); await rej(open(d), 'corrupt: journal line 2 has an invalid shape'); }
    // the very first line too
    wj(d, [], 'null\n');
    await rej(open(d), 'corrupt: journal line 1 has an invalid shape');
  });
  it('genesis rules for the first record', async () => {
    const d = tmp();
    const set2 = mk(2, GEN, 'set', 'a\n1');
    wj(d, [set2]); await rej(open(d), 'corrupt: journal does not start at genesis');
    const setPrev = mk(1, 'f'.repeat(64), 'set', 'a\n1');
    wj(d, [setPrev]); await rej(open(d), 'corrupt: journal does not start at genesis');
    const cp0 = mk(0, GEN, 'checkpoint', '[]');
    wj(d, [cp0]); await rej(open(d), 'corrupt: bad checkpoint seq');
    wj(d, [mk(1, GEN, 'checkpoint', '[]')]); expect(await (await open(d)).keys()).toEqual([]);
    wj(d, [mk(7, 'f'.repeat(64), 'checkpoint', '[["a","1"]]')]); wh(d, { seq: 7, h: mk(7, 'f'.repeat(64), 'checkpoint', '[["a","1"]]').h });
    expect(await (await open(d)).get('a')).toBe(1);
  });
  it('sequence gap and broken hash chain are distinguished, with line numbers', async () => {
    const [r1] = chain(1);
    const gap = mk(3, r1!.h, 'set', 'a\n1');
    const d = tmp();
    wj(d, [r1, gap]); await rej(open(d), 'corrupt: journal line 2: sequence gap');
    const broken = mk(2, 'e'.repeat(64), 'set', 'a\n1');
    wj(d, [r1, broken]); await rej(open(d), 'corrupt: journal line 2: hash chain broken');
    const [a, b, c] = chain(3);
    wj(d, [a, b, mk(5, b!.h, 'set', 'x\n1')]); await rej(open(d), 'corrupt: journal line 3: sequence gap');
    wj(d, [a, b, mk(3, 'd'.repeat(64), 'set', 'x\n1')]); await rej(open(d), 'corrupt: journal line 3: hash chain broken');
    wj(d, [a, b, c]); wh(d, headOf(c!)); await open(d);
  });
  it('edited records fail the record hash with the line number', async () => {
    const d = tmp();
    const [a, b] = chain(2);
    wj(d, [a, { ...b, payload: 'k2\n999' }]); await rej(open(d), 'corrupt: journal line 2: record hash mismatch (edited)');
    wj(d, [{ ...a, ts: 5 }]); await rej(open(d), 'corrupt: journal line 1: record hash mismatch (edited)');
  });
  it('keyed: MAC missing / wrong / wrong length; unkeyed open of a MAC-tagged journal', async () => {
    const M = (n: number) => `key-mismatch: journal line ${n}: MAC does not verify (wrong key or forged record)`;
    const recs = chain(2, KEY);
    const d = tmp();
    const noMac = recs.map(({ mac: _m, ...r }) => r);
    wj(d, noMac); await rej(open(d, { hmacKey: KEY }), M(1));
    wj(d, [recs[0], { ...recs[1], mac: 'f'.repeat(64) }]); await rej(open(d, { hmacKey: KEY }), M(2));
    wj(d, [recs[0], { ...recs[1], mac: 'ff' }]); await rej(open(d, { hmacKey: KEY }), M(2));
    wj(d, recs); wh(d, headOf(recs[1]!, KEY));
    await rej(open(d), 'key-mismatch: journal is MAC-tagged but no hmacKey was supplied');
    await open(d, { hmacKey: KEY });
    const d2 = tmp(); const r = chain(1); wj(d2, [{ ...r[0], mac: 'zz' }]);
    await rej(open(d2), 'key-mismatch: journal is MAC-tagged but no hmacKey was supplied');
  });
  it('checkpoint payload validation and state replacement', async () => {
    const d = tmp();
    const [a] = chain(1);
    const cp = (p: string) => mk(2, a!.h, 'checkpoint', p);
    wj(d, [a, cp('{nope')]); await rej(open(d), 'corrupt: checkpoint payload is not JSON');
    wj(d, [a, cp('{}')]); await rej(open(d), 'corrupt: checkpoint payload is not an array');
    wj(d, [a, cp('"x"')]); await rej(open(d), 'corrupt: checkpoint payload is not an array');
    for (const p of ['["x"]', '[["a"]]', '[["a","1","2"]]', '[[1,"2"]]', '[["a",2]]', '[null]', '[{}]', '[[]]']) {
      wj(d, [a, cp(p)]); await rej(open(d), 'corrupt: checkpoint entry is malformed');
    }
    const ok = cp('[["z","9"]]');
    wj(d, [a, ok]); wh(d, headOf(ok));
    const s = await open(d);
    expect(await s.keys()).toEqual(['z']); // the checkpoint REPLACES the earlier state (k1 gone)
    expect(await s.get('k1')).toBeUndefined();
    expect(await s.get('z')).toBe(9);
  });
  it('set payload needs a non-empty key before the newline', async () => {
    const d = tmp();
    for (const p of ['nonewline', '\nvalue']) { wj(d, [mk(1, GEN, 'set', p)]); await rej(open(d), 'corrupt: journal line 1: malformed payload'); }
    const [a] = chain(1);
    wj(d, [a, mk(2, a!.h, 'set', 'x')]); await rej(open(d), 'corrupt: journal line 2: malformed payload');
    wj(d, [mk(1, GEN, 'set', 'k\n"v"')]);
    expect(await (await open(d)).get('k')).toBe('v');
    wj(d, [mk(1, GEN, 'set', 'k\n')]); // empty value text is allowed by the framing but is not JSON on read
    await expect(open(d).then((s) => s.get('k'))).rejects.toThrow();
  });
  it('head/journal consistency: each relation has its own error', async () => {
    const [a, b, c] = chain(3);
    const d = tmp();
    wj(d, [a]); wh(d, headOf(b!));
    await rej(open(d), 'rollback: journal is at seq 1 but state.head recorded seq 2 (truncation or older copy)');
    wj(d, [a, b, c]); wh(d, headOf(a!));
    await rej(open(d), 'corrupt: journal (seq 3) is more than one record ahead of state.head (seq 1)');
    wj(d, [a, b]); wh(d, { seq: 2, h: 'a'.repeat(64) });
    await rej(open(d), 'corrupt: journal tail does not match state.head');
    wj(d, [a, b]); wh(d, { seq: 1, h: 'a'.repeat(64) });
    await rej(open(d), 'corrupt: journal tail is not chained from state.head');
    wj(d, [a, b]); wh(d, headOf(a!)); await open(d); // lag of exactly one is fine
    wj(d, [a, b]); wh(d, headOf(b!)); await open(d);
    // no head: seq 1 is a clean first run, seq>1 is a rollback
    rmSync(join(d, 'state.head'));
    wj(d, [a]); await open(d);
    rmSync(join(d, 'state.head'));
    wj(d, [a, b]);
    await rej(open(d), 'rollback: state.head is missing but the journal is at seq 2');
    const cp5 = mk(5, 'f'.repeat(64), 'checkpoint', '[]');
    wj(d, [cp5]);
    await rej(open(d), 'rollback: state.head is missing but the journal is at seq 5');
  });
  it('a running handle detects backwards movement, forks and emptying (exact messages)', async () => {
    const d = tmp();
    const s = await open(d);
    await s.set('a', 1); await s.set('b', 2);
    const cur = readFileSync(join(d, 'state.journal'), 'utf8').trim().split('\n').map((l) => JSON.parse(l) as R);
    // older but head-consistent copy
    wj(d, [cur[0]]); wh(d, headOf(cur[0]!));
    await rej(s.get('a'), 'rollback: state moved backwards from seq 2 to 1 while open');
    // forked history at the same seq
    const f1 = mk(1, GEN, 'set', 'x\n1'); const f2 = mk(2, f1.h, 'set', 'y\n2');
    wj(d, [f1, f2]); wh(d, headOf(f2));
    await rej(s.get('a'), 'rollback: state forked at seq 2 while open');
    // emptied
    wj(d, [], ''); wh(d, { seq: 0, h: GEN });
    await rej(s.get('a'), 'rollback: state was emptied while open');
    // fresh handle at seq 0 may see an empty journal
    const fresh = await open(tmp());
    expect(await fresh.keys()).toEqual([]);
  });
  it('seen only advances (>=) and a legitimately advancing journal is accepted', async () => {
    const d = tmp();
    const a = await open(d); const b = await open(d);
    await a.set('x', 1);
    expect(await b.get('x')).toBe(1);
    expect(b.position().seq).toBe(1);
    await b.set('y', 2);
    expect(await a.get('y')).toBe(2);
    expect(a.position()).toEqual(b.position());
    // observing the same seq again keeps the hash
    const before = a.position();
    await a.get('x');
    expect(a.position()).toEqual(before);
  });
});

describe('recoverFromCorruption', () => {
  it('quarantines journal and head, starts empty, flags recovered; only on explicit true', async () => {
    const d = tmp();
    const s0 = await open(d);
    await s0.set('a', 1);
    wj(d, [], 'garbage');
    await rej(open(d), 'corrupt: journal does not end with a newline (torn or truncated)');
    await rej(open(d, { recoverFromCorruption: 1 }), /^corrupt:/);
    await rej(open(d, { recoverFromCorruption: false }), /^corrupt:/);
    const s = await open(d, { recoverFromCorruption: true, now: () => 777 });
    expect(s.recovered).toBe(true);
    expect(s.position()).toEqual({ seq: 0, hash: GEN });
    expect(await s.keys()).toEqual([]);
    const names = readdirSync(d).sort();
    expect(names.filter((n) => /^state\.journal\.quarantine-777-[0-9a-f]{6}$/.test(n))).toHaveLength(1);
    expect(names.filter((n) => /^state\.head\.quarantine-777-[0-9a-f]{6}$/.test(n))).toHaveLength(1);
    expect((await open(tmp())).recovered).toBe(false);
  });
  it('only the files that exist are renamed; recovery from a rollback resets the high-water mark', async () => {
    const d = tmp();
    wh(d, { seq: 4, h: chain(1)[0]!.h });
    const s = await open(d, { recoverFromCorruption: true, now: () => 1 });
    expect(s.recovered).toBe(true);
    expect(readdirSync(d).filter((n) => n.startsWith('state.journal.quarantine'))).toHaveLength(0);
    expect(readdirSync(d).filter((n) => n.startsWith('state.head.quarantine'))).toHaveLength(1);
    await s.set('a', 1);
    expect(await s.get('a')).toBe(1);
  });
});

describe('locking', () => {
  // The age-based lock-break protocol was replaced by numbered lock generations: its tests live in
  // mutation-kill-durable-state-2.test.ts ("generation locks").
  it('the lock is released after every operation (also after an error)', async () => {
    const d = tmp(); const s = await open(d);
    await s.set('a', 1);
    expect(existsSync(join(d, 'state.lock'))).toBe(false);
    await expect(s.update('a', () => { throw new Error('boom'); })).rejects.toThrow('boom');
    expect(existsSync(join(d, 'state.lock'))).toBe(false);
  });
  it('a non-EEXIST error acquiring the lock is rethrown, not retried', async () => {
    const d = tmp(); const s = await open(d);
    rmSync(d, { recursive: true, force: true });
    await expect(s.set('a', 1)).rejects.toThrow(/ENOENT/);
  });
});

describe('crash hooks send SIGKILL (process.kill mocked so the test survives)', () => {
  it.each(['after-temp-write', 'after-journal-rename'] as const)('%s', async (point) => {
    const real = process.kill.bind(process);
    const spy = vi.spyOn(process, 'kill').mockImplementation(((pid: number, sig?: string | number) => (sig === 0 ? real(pid, 0) : true)) as never);
    const d = tmp();
    const s = await open(d, { testCrashAt: point });
    await s.set('a', 1);
    const calls = spy.mock.calls.filter((c) => c[1] === 'SIGKILL');
    expect(calls.length).toBeGreaterThan(0);
    expect(calls.every((c) => c[0] === process.pid)).toBe(true);
    spy.mockClear();
    const s2 = await open(tmp());
    await s2.set('a', 1);
    expect(spy.mock.calls.filter((c) => c[1] === 'SIGKILL')).toHaveLength(0);
  });
});
