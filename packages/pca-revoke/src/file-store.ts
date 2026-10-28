/**
 * A durable {@link RevocationStore} backed by one JSON file. Every change is written to a temporary
 * file, flushed to disk, then renamed over the real file, so a crash leaves either the old or the new
 * contents, never a torn file. Single process: two processes must not share one file.
 *
 * Fail closed: a file that exists but cannot be read or does not hold a valid list of entries makes the
 * constructor throw. Silently starting empty would un-revoke everything.
 */
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, writeSync } from 'node:fs';
import { type RevocationEntry, type RevocationStore, type RevocationTargetKind } from './index';

const KINDS: readonly string[] = ['cap', 'holder', 'issuer', 'prefix'];

function validEntry(e: unknown): e is RevocationEntry {
  if (e === null || typeof e !== 'object') return false;
  const o = e as Record<string, unknown>;
  if (typeof o.kind !== 'string' || !KINDS.includes(o.kind)) return false;
  if (typeof o.value !== 'string' || o.value.length === 0) return false;
  if (typeof o.reason !== 'string') return false;
  if (typeof o.revokedAt !== 'number' || !Number.isFinite(o.revokedAt)) return false;
  if (o.notBefore !== undefined && (typeof o.notBefore !== 'number' || !Number.isFinite(o.notBefore))) return false;
  if (o.kind === 'prefix') {
    if (!Array.isArray(o.prefix) || o.prefix.length === 0 || o.prefix.some((x) => typeof x !== 'string' || x.length === 0)) return false;
    if ((o.prefix as string[]).join(',') !== o.value) return false;
  }
  return true;
}

export class FileRevocationStore implements RevocationStore {
  private readonly mem = new Map<string, RevocationEntry>();
  /** Writers run one at a time: a change is applied, flushed, and only then does the next start. */
  private tail: Promise<unknown> = Promise.resolve();

  constructor(private readonly path: string) {
    if (!existsSync(path)) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(path, 'utf8'));
    } catch {
      throw new Error('FileRevocationStore: the revocation file cannot be read as JSON; refusing to start empty');
    }
    const list = (parsed as { entries?: unknown } | null)?.entries;
    if (!Array.isArray(list) || !list.every(validEntry)) {
      throw new Error('FileRevocationStore: the revocation file is not a valid entry list; refusing to start empty');
    }
    for (const e of list) this.mem.set(key(e.kind, e.value), e);
  }

  private flush(): void {
    const tmp = `${this.path}.tmp`;
    const fd = openSync(tmp, 'w', 0o600);
    try {
      writeSync(fd, JSON.stringify({ v: 1, entries: [...this.mem.values()] }));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, this.path);
  }

  /** Apply `change` to memory and flush; on a failed flush put memory back, so memory never claims more than disk. */
  private write<T>(change: () => T): Promise<T> {
    const run = async (): Promise<T> => {
      const before = new Map(this.mem);
      const out = change();
      try {
        this.flush();
      } catch (e) {
        this.mem.clear();
        for (const [k, v] of before) this.mem.set(k, v);
        throw e;
      }
      return out;
    };
    const next = this.tail.then(run, run);
    this.tail = next.catch(() => undefined);
    return next;
  }

  add(entry: RevocationEntry): Promise<void> {
    return this.write(() => void this.mem.set(key(entry.kind, entry.value), entry));
  }

  remove(kind: RevocationTargetKind, value: string): Promise<boolean> {
    return this.write(() => this.mem.delete(key(kind, value)));
  }

  async get(kind: RevocationTargetKind, value: string): Promise<RevocationEntry | undefined> {
    await this.tail;
    return this.mem.get(key(kind, value));
  }

  async all(): Promise<RevocationEntry[]> {
    await this.tail;
    return [...this.mem.values()];
  }

  clear(): Promise<void> {
    return this.write(() => this.mem.clear());
  }
}

const key = (kind: string, value: string): string => `${kind}\u0000${value}`;
