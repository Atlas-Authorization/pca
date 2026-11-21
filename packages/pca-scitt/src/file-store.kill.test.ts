import { createHash, generateKeyPairSync } from 'node:crypto';
import { appendFileSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DurableTransparencyService, FileScittLogStore, ScittLogError, signStatement } from './index';

const ts = generateKeyPairSync('ed25519');
const issuer = generateKeyPairSync('ed25519');
const stmt = (i: number) => signStatement({ n: i }, { alg: 'EdDSA', key: issuer.privateKey, issuer: 'rs' });
const tmp = () => join(mkdtempSync(join(tmpdir(), 'scitt-kill-')), 'log.bin');
const svc = (path: string) => new DurableTransparencyService({ store: FileScittLogStore.open(path), alg: 'EdDSA', key: ts.privateKey });
const u32 = (n: number) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n, 0);
  return b;
};
const record = (payload: Buffer) => Buffer.concat([u32(payload.length), payload, createHash('sha256').update(payload).digest()]);
const thrown = (f: () => unknown): ScittLogError => {
  try {
    f();
  } catch (e) {
    return e as ScittLogError;
  }
  throw new Error('expected a throw');
};
const h32 = new Uint8Array(32).fill(7);

describe('FileScittLogStore load', () => {
  it('reads every entry back by offset after a reopen', async () => {
    const path = tmp();
    const a = svc(path);
    const sts = [stmt(0), stmt(1), stmt(2)];
    for (const s of sts) await a.register(s);
    const b = svc(path);
    for (const [i, s] of sts.entries()) expect(Buffer.from(await b.getEntry(i)).equals(Buffer.from(s))).toBe(true);
  });
  it('discards one to three stray bytes after the last record', async () => {
    const path = tmp();
    await svc(path).register(stmt(0));
    const clean = statSync(path).size;
    appendFileSync(path, Buffer.from([0xaa, 0xbb]));
    expect(await svc(path).size()).toBe(1);
    expect(statSync(path).size).toBe(clean);
    appendFileSync(path, Buffer.from([0x01]));
    expect(await svc(path).size()).toBe(1);
    expect(statSync(path).size).toBe(clean);
  });
  it('discards stray bytes in an otherwise empty file', async () => {
    const path = tmp();
    writeFileSync(path, Buffer.from([0x01, 0x02]));
    const s = FileScittLogStore.open(path);
    expect(await s.size()).toBe(0);
    expect(statSync(path).size).toBe(0);
  });
  it('treats a final record with a bad checksum as a torn tail and drops only it', async () => {
    const path = tmp();
    const a = svc(path);
    await a.register(stmt(0));
    const afterFirst = statSync(path).size;
    await a.register(stmt(1));
    const buf = readFileSync(path);
    buf[buf.length - 1] ^= 0xff;
    writeFileSync(path, buf);
    const b = svc(path);
    expect(await b.size()).toBe(1);
    expect(statSync(path).size).toBe(afterFirst);
  });
  it('a bad checksum before the last record is store_corrupt at that record offset', async () => {
    const path = tmp();
    const a = svc(path);
    await a.register(stmt(0));
    const secondAt = statSync(path).size;
    await a.register(stmt(1));
    await a.register(stmt(2));
    const buf = readFileSync(path);
    buf[secondAt + 10] ^= 0xff;
    writeFileSync(path, buf);
    const e = thrown(() => FileScittLogStore.open(path));
    expect(e).toBeInstanceOf(ScittLogError);
    expect(e.code).toBe('store_corrupt');
    expect(e.message).toBe(`the log file is corrupt at offset ${secondAt}`);
  });
  it('a complete record shorter than the 6-byte minimum is store_corrupt', () => {
    const path = tmp();
    writeFileSync(path, record(Buffer.from([0, 0, 0])));
    const e = thrown(() => FileScittLogStore.open(path));
    expect(e).toBeInstanceOf(ScittLogError);
    expect(e.code).toBe('store_corrupt');
    expect(e.message).toBe('the log file is corrupt at offset 0');
  });
  it('the 6-byte minimum record (empty entry, no nodes) is accepted', async () => {
    const path = tmp();
    writeFileSync(path, record(Buffer.alloc(6)));
    const s = FileScittLogStore.open(path);
    expect(await s.size()).toBe(1);
    expect((await s.getEntry(0))?.length).toBe(0);
  });
  it('a record whose node count disagrees with its length is store_corrupt', () => {
    const path = tmp();
    const payload = Buffer.alloc(6);
    payload.writeUInt16BE(1, 4); // claims one 40-byte node that is not there
    writeFileSync(path, record(payload));
    const e = thrown(() => FileScittLogStore.open(path));
    expect(e).toBeInstanceOf(ScittLogError);
    expect(e.code).toBe('store_corrupt');
    expect(e.message).toBe('a log record has an inconsistent length');
  });
});

describe('FileScittLogStore append validation', () => {
  const bad: [string, { level: number; index: number; hash: Uint8Array }][] = [
    ['negative level', { level: -1, index: 0, hash: h32 }],
    ['fractional level', { level: 1.5, index: 0, hash: h32 }],
    ['NaN level', { level: NaN, index: 0, hash: h32 }],
    ['level 256', { level: 256, index: 0, hash: h32 }],
    ['negative index', { level: 0, index: -1, hash: h32 }],
    ['fractional index', { level: 0, index: 0.5, hash: h32 }],
    ['index 2^32', { level: 0, index: 0x100000000, hash: h32 }],
    ['short hash', { level: 0, index: 0, hash: new Uint8Array(31) }],
    ['long hash', { level: 0, index: 0, hash: new Uint8Array(33) }],
  ];
  it.each(bad)('refuses a node with %s, with the exact error, and stores nothing', async (_n, node) => {
    const path = tmp();
    const s = FileScittLogStore.open(path);
    let err: ScittLogError | undefined;
    try {
      await s.append(0, Uint8Array.of(1), [node]);
    } catch (e) {
      err = e as ScittLogError;
    }
    expect(err).toBeInstanceOf(ScittLogError);
    expect(err?.code).toBe('store_corrupt');
    expect(err?.message).toBe('a subtree node is malformed');
    expect(await s.size()).toBe(0);
    expect(statSync(path).size).toBe(0);
  });
  it('accepts the boundary level 255 and index 0xffffffff and round-trips them across a reopen', async () => {
    const path = tmp();
    const s = FileScittLogStore.open(path);
    expect(await s.append(0, Uint8Array.of(9), [{ level: 255, index: 0xffffffff, hash: h32 }, { level: 0, index: 0, hash: h32 }])).toBe(true);
    const r = FileScittLogStore.open(path);
    expect(await r.size()).toBe(1);
    expect(Buffer.from((await r.getNode(255, 0xffffffff))!).equals(Buffer.from(h32))).toBe(true);
  });
});
