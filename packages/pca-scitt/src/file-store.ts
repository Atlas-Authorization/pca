import { createHash } from 'node:crypto';
import { closeSync, fstatSync, fsyncSync, ftruncateSync, openSync, readSync, writeSync } from 'node:fs';
import type { ScittLogStore, StoredNode } from './durable';
import { ScittLogError } from './durable';

/**
 * A file-backed {@link ScittLogStore}: one append-only file of checksummed transactions (entry plus its new subtree hashes),
 * fsynced before `append` resolves, so a crash leaves either the whole transaction or none of it. A torn final record is
 * discarded on open; corruption anywhere else throws `store_corrupt`. SINGLE PROCESS: it does not lock the file, so run one
 * writer per directory (use a database-backed store for a fleet). Memory use is the 32-byte hash of every subtree plus one
 * offset per entry; entry bytes are read from disk on demand.
 */
export class FileScittLogStore implements ScittLogStore {
  private readonly nodes = new Map<string, Uint8Array>();
  private readonly offsets: { at: number; len: number }[] = [];
  private end = 0;

  private constructor(private readonly fd: number) {}

  /** Open (creating if absent) the log file at `path` and rebuild the index. */
  static open(path: string): FileScittLogStore {
    const fd = openSync(path, 'a+');
    closeSync(fd);
    const rw = openSync(path, 'r+');
    const s = new FileScittLogStore(rw);
    s.load();
    return s;
  }

  close(): void {
    closeSync(this.fd);
  }

  private read(at: number, len: number): Buffer {
    const b = Buffer.alloc(len);
    let got = 0;
    while (got < len) {
      const n = readSync(this.fd, b, got, len - got, at + got);
      if (n === 0) break;
      got += n;
    }
    return got === len ? b : b.subarray(0, got);
  }

  private load(): void {
    const total = fstatSync(this.fd).size;
    let pos = 0;
    while (pos < total) {
      const head = this.read(pos, 4);
      const len = head.length === 4 ? head.readUInt32BE(0) : -1;
      const recEnd = pos + 4 + len + 32;
      if (len < 6 || recEnd > total) {
        this.discardTail(pos, total, recEnd > total);
        return;
      }
      const payload = this.read(pos + 4, len);
      const sum = this.read(pos + 4 + len, 32);
      if (!createHash('sha256').update(payload).digest().equals(sum)) {
        this.discardTail(pos, total, recEnd === total);
        return;
      }
      const entryLen = payload.readUInt32BE(0);
      let p = 4 + entryLen;
      const count = payload.readUInt16BE(p);
      p += 2;
      if (p + count * 40 !== len) throw new ScittLogError('store_corrupt', 'a log record has an inconsistent length');
      this.offsets.push({ at: pos + 8, len: entryLen });
      for (let i = 0; i < count; i++, p += 40) {
        this.nodes.set(`${payload.readUInt8(p)}:${payload.readUInt32BE(p + 1)}`, new Uint8Array(payload.subarray(p + 8, p + 40)));
      }
      pos = recEnd;
    }
    this.end = pos;
  }

  private discardTail(pos: number, total: number, isTail: boolean): void {
    if (!isTail) throw new ScittLogError('store_corrupt', `the log file is corrupt at offset ${pos}`);
    ftruncateSync(this.fd, pos);
    fsyncSync(this.fd);
    this.end = pos;
    void total;
  }

  async size(): Promise<number> {
    return this.offsets.length;
  }

  async getEntry(index: number): Promise<Uint8Array | undefined> {
    const o = this.offsets[index];
    return o === undefined ? undefined : new Uint8Array(this.read(o.at, o.len));
  }

  async getNode(level: number, index: number): Promise<Uint8Array | undefined> {
    const h = this.nodes.get(`${level}:${index}`);
    return h === undefined ? undefined : new Uint8Array(h);
  }

  async append(expectedSize: number, entry: Uint8Array, nodes: readonly StoredNode[]): Promise<boolean> {
    if (this.offsets.length !== expectedSize) return false;
    for (const n of nodes) {
      if (!Number.isInteger(n.level) || n.level < 0 || n.level > 255 || !Number.isInteger(n.index) || n.index < 0 || n.index > 0xffffffff || n.hash.length !== 32) {
        throw new ScittLogError('store_corrupt', 'a subtree node is malformed');
      }
    }
    const payload = Buffer.alloc(4 + entry.length + 2 + nodes.length * 40);
    payload.writeUInt32BE(entry.length, 0);
    Buffer.from(entry).copy(payload, 4);
    let p = 4 + entry.length;
    payload.writeUInt16BE(nodes.length, p);
    p += 2;
    for (const n of nodes) {
      payload.writeUInt8(n.level, p);
      payload.writeUInt32BE(n.index, p + 1);
      payload.fill(0, p + 5, p + 8);
      Buffer.from(n.hash).copy(payload, p + 8);
      p += 40;
    }
    const head = Buffer.alloc(4);
    head.writeUInt32BE(payload.length, 0);
    const record = Buffer.concat([head, payload, createHash('sha256').update(payload).digest()]);
    let w = 0;
    while (w < record.length) w += writeSync(this.fd, record, w, record.length - w, this.end + w);
    fsyncSync(this.fd);
    this.offsets.push({ at: this.end + 8, len: entry.length });
    for (const n of nodes) this.nodes.set(`${n.level}:${n.index}`, new Uint8Array(n.hash));
    this.end += record.length;
    return true;
  }
}
