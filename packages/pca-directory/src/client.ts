/**
 * The read side of a log as relying parties and monitors see it: wire views, the `LogClient` interface, an in-process
 * client over a `DirectoryLog`, and an HTTP client for any server speaking the directory routes.
 *
 * Nothing a client returns is trusted: every consumer re-verifies signatures, proofs and heads itself.
 */
import type { InclusionProof } from '@atlasauth/pca';
import type { ConsistencyProof, SignedTreeHead, WitnessCosignature } from '@atlasauth/pca/ext/ledger';
import type { SignedPassport } from '@atlasauth/pca/ext/attestation';
import type { DirectoryEntry, SignedRevocation } from './entry';
import type { DirectoryLog, StoredEntry } from './log';
import type { SignedKeyTransition } from './rotation';

export interface EntryView {
  index: number;
  commit: string;
  entry: DirectoryEntry;
  /** Present for `public` entries only. */
  body?: SignedPassport | SignedRevocation;
}

/** An entry with its inclusion proof against `sth` (proof.size === sth.size). */
export interface ProvedEntry {
  entry: EntryView;
  proof: InclusionProof;
  sth: SignedTreeHead;
}

export interface StatusView {
  subject: string;
  sth: SignedTreeHead;
  /** Every entry the log holds for the subject, each with a proof against `sth`. */
  entries: { entry: EntryView; proof: InclusionProof }[];
}

export const entryView = (r: StoredEntry): EntryView => ({ index: r.index, commit: r.commit, entry: r.entry, ...(r.body ? { body: r.body } : {}) });

export interface LogClient {
  /** The latest head, with the best cosignatures the log has. */
  sth(): Promise<SignedTreeHead>;
  consistency(from: number, to: number): Promise<ConsistencyProof>;
  /** The register/update entry for a passport digest, proved against a cosigned head when one covers it. Null when absent. */
  inclusion(passportDigest: string): Promise<ProvedEntry | null>;
  status(subject: string): Promise<StatusView>;
  /** The monitor feed: entries from `from`. */
  entries(from: number, limit: number): Promise<EntryView[]>;
  /** The log's key transitions, oldest first (absent on clients of logs that never rotate). */
  transitions?(): Promise<SignedKeyTransition[]>;
}

/** A client over a log in this process (tests, embedded logs, the hosted routes' own self-checks). */
export function memoryLogClient(log: DirectoryLog, o: { minCosigs?: number } = {}): LogClient {
  const minCosigs = o.minCosigs ?? 0;
  return {
    sth: () => (minCosigs > 0 ? log.cosignedSth(minCosigs) : log.sth()),
    async consistency(from, to) {
      const p = await log.consistency(from, to);
      if (!p) throw new Error('consistency: invalid sizes');
      return p;
    },
    async inclusion(digest) {
      const row = await log.byDigest(digest);
      if (!row) return null;
      const sth = await log.cosignedSth(minCosigs, row.index + 1);
      const proof = await log.inclusion(row.index, sth.size);
      return proof ? { entry: entryView(row), proof, sth } : null;
    },
    async status(subject) {
      // the newest head, cosigned or not: a revocation is evidence whatever its witness count, so never hide recent entries
      const sth = await log.sth();
      const rows = (await log.lookup(subject)).filter((r) => r.index < sth.size);
      const entries: StatusView['entries'] = [];
      for (const r of rows) {
        const proof = await log.inclusion(r.index, sth.size);
        if (proof) entries.push({ entry: entryView(r), proof });
      }
      return { subject, sth, entries };
    },
    async entries(from, limit) {
      return (await log.entries(from, limit)).map(entryView);
    },
    transitions: () => log.transitions(),
  };
}

type FetchLike = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export interface HttpLogClientOptions {
  fetch?: FetchLike;
  headers?: Record<string, string>;
  timeoutMs?: number;
}

/**
 * A client for a server exposing `GET {base}/sth`, `/consistency?from&to`, `/proof?digest`, `/status?subject`, `/entries?from&limit`
 * (the hosted API mounts these under `/v1/pca/directory`; `pca-directory-log` mounts them at its root).
 */
export function httpLogClient(base: string, o: HttpLogClientOptions = {}): LogClient {
  const f: FetchLike = o.fetch ?? ((globalThis as { fetch?: FetchLike }).fetch as FetchLike);
  const root = base.replace(/\/+$/, '');
  async function get<T>(path: string): Promise<T> {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), o.timeoutMs ?? 10_000);
    try {
      const res = await f(`${root}${path}`, { headers: { accept: 'application/json', ...(o.headers ?? {}) }, signal: ctl.signal });
      if (res.status === 404) return null as T;
      if (!res.ok) throw new Error(`log ${path}: HTTP ${res.status}`);
      return (await res.json()) as T;
    } finally {
      clearTimeout(t);
    }
  }
  const need = <T>(v: T | null, what: string): T => {
    if (v === null || v === undefined) throw new Error(`log: ${what} not found`);
    return v;
  };
  return {
    sth: async () => need(await get<{ signed_tree_head: SignedTreeHead }>('/sth'), 'sth').signed_tree_head,
    consistency: async (from, to) => need(await get<{ consistency_proof: ConsistencyProof }>(`/consistency?from=${from}&to=${to}`), 'consistency').consistency_proof,
    inclusion: async (digest) => get<ProvedEntry>(`/proof?digest=${encodeURIComponent(digest)}`),
    status: async (subject) => need(await get<StatusView>(`/status?subject=${encodeURIComponent(subject)}`), 'status'),
    entries: async (from, limit) => need(await get<{ data: EntryView[] }>(`/entries?from=${from}&limit=${limit}`), 'entries').data,
    transitions: async () => (await get<{ data: SignedKeyTransition[] }>('/key-transitions'))?.data ?? [],
  };
}

/** Post a witness cosignature to a log (`POST {base}/cosignatures`). Returns whether the log accepted it. */
export async function postCosignature(base: string, size: number, root: string, cosignature: WitnessCosignature, o: HttpLogClientOptions = {}): Promise<boolean> {
  const f: FetchLike = o.fetch ?? ((globalThis as { fetch?: FetchLike }).fetch as FetchLike);
  const res = await f(`${base.replace(/\/+$/, '')}/cosignatures`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(o.headers ?? {}) },
    body: JSON.stringify({ size, root, cosignature }),
  });
  return res.ok;
}
