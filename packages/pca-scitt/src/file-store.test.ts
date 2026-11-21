import { generateKeyPairSync } from 'node:crypto';
import { appendFileSync, mkdtempSync, readFileSync, statSync, truncateSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DurableTransparencyService, FileScittLogStore, ScittLogError, checkScittLogStore, signStatement, verifyReceipt } from './index';
import { TransparencyService } from './testing';

const ts = generateKeyPairSync('ed25519');
const issuer = generateKeyPairSync('ed25519');
const stmt = (i: number) => signStatement({ n: i }, { alg: 'EdDSA', key: issuer.privateKey, issuer: 'rs' });
const tmp = () => join(mkdtempSync(join(tmpdir(), 'scitt-')), 'log.bin');
const svc = (path: string) => new DurableTransparencyService({ store: FileScittLogStore.open(path), alg: 'EdDSA', key: ts.privateKey });

describe('FileScittLogStore', () => {
  it('conforms to the store contract', async () => {
    expect(await checkScittLogStore(() => FileScittLogStore.open(tmp()))).toEqual([]);
  });
  it('survives a restart: same root, same entries, the log continues, receipts verify', async () => {
    const path = tmp();
    const ref = new TransparencyService({ alg: 'EdDSA', key: ts.privateKey });
    const a = svc(path);
    const sts = Array.from({ length: 11 }, (_, i) => stmt(i));
    for (let i = 0; i < 6; i++) { await a.register(sts[i]!); ref.register(sts[i]!); }
    const b = svc(path);
    expect(await b.size()).toBe(6);
    expect(await b.root()).toBe(ref.root);
    for (let i = 6; i < 11; i++) { const r = await b.register(sts[i]!); ref.register(sts[i]!); expect(r.root).toBe(ref.root); }
    const r = await b.getReceipt(4);
    expect(verifyReceipt(r.receipt, sts[4]!, { verificationKey: ts.publicKey, treeRoot: ref.root })).toBe(true);
    expect(Buffer.from(await b.getEntry(10)).equals(Buffer.from(sts[10]!))).toBe(true);
  });
  it('a torn final record (crash mid-append) is discarded and the log stays consistent', async () => {
    const path = tmp();
    const a = svc(path);
    const sts = [stmt(0), stmt(1), stmt(2)];
    for (const s of sts) await a.register(s);
    const full = statSync(path).size;
    const beforeLast = (await (async () => { const p2 = tmp(); const x = svc(p2); await x.register(sts[0]!); await x.register(sts[1]!); return statSync(p2).size; })());
    truncateSync(path, full - 10); // cut into the last record
    const b = svc(path);
    expect(await b.size()).toBe(2);
    expect(statSync(path).size).toBe(beforeLast);
    const r = await b.register(sts[2]!);
    expect(r.index).toBe(2);
    expect(await svc(path).root()).toBe(r.root);
  });
  it('garbage appended after the last record is discarded as a torn tail', async () => {
    const path = tmp();
    await svc(path).register(stmt(0));
    appendFileSync(path, Buffer.from([0, 0, 0, 200, 1, 2, 3]));
    expect(await svc(path).size()).toBe(1);
  });
  it('corruption before the end of the file is store_corrupt, never silently dropped', async () => {
    const path = tmp();
    const a = svc(path);
    for (let i = 0; i < 3; i++) await a.register(stmt(i));
    const buf = readFileSync(path);
    buf[12] ^= 0xff; // inside the first record's payload
    writeFileSync(path, buf);
    expect(() => FileScittLogStore.open(path)).toThrow(ScittLogError);
  });
  it('refuses a malformed node', async () => {
    const s = FileScittLogStore.open(tmp());
    await expect(s.append(0, Uint8Array.of(1), [{ level: 0, index: 0, hash: new Uint8Array(31) }])).rejects.toBeInstanceOf(ScittLogError);
    await expect(s.append(0, Uint8Array.of(1), [{ level: 300, index: 0, hash: new Uint8Array(32) }])).rejects.toBeInstanceOf(ScittLogError);
    expect(await s.size()).toBe(0);
  });
});
