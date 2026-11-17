import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { isObj, sha256hex, type Json } from './util';

export const LAYERS = ['wire', 'proof', 'capability', 'policy', 'suites', 'producer', 'stateful'] as const;
export type Layer = (typeof LAYERS)[number];

export interface CorpusItem {
  id: string;
  layer: Layer;
  kind: 'verify' | 'canon' | 'chain' | 'policy' | 'produce' | 'stateful' | 'suites';
  name: string;
  /** The driver line (without `id`). Absent for `produce` items, whose line is built from `produce` + the corpus key sets. */
  send?: Record<string, Json>;
  produce?: { op: string; args: Json; keyset: string };
  expect: Json;
  /** Registered suites the vector carries (only when non-empty). */
  suites?: string[];
  pq?: boolean;
  /** A generated item: a driver that raises instead of answering a vector the reference rejects has still not accepted it. */
  soft?: boolean;
  profiles: string[];
}

export interface ProfileInfo {
  title: string;
  description: string;
  layers: string[];
  items: number;
  layer_items: Record<string, number>;
  requires_suites?: string[];
}

export interface CorpusManifest {
  format: 'pca-verified-corpus/1';
  corpus_version: string;
  protocol_version: string;
  sha256: string;
  bytes: number;
  items: number;
  layers: Record<string, number>;
  profiles: Record<string, ProfileInfo>;
  registered_suites: string[];
  sources: Record<string, string>;
}

export interface CorpusHeader {
  version: string;
  protocol: string;
  registered_suites: string[];
  keysets: Record<string, { keys: Json; pq_keys?: Json }>;
}

export interface LoadedCorpus {
  manifest: CorpusManifest;
  header: CorpusHeader;
  items: CorpusItem[];
}

export class CorpusError extends Error {
  constructor(readonly code: 'corpus_hash_mismatch' | 'corpus_malformed' | 'corpus_manifest_mismatch', message: string) {
    super(message);
    this.name = 'CorpusError';
  }
}

/** Parse corpus text and check it against its manifest: the content hash first, then the counts. Fails closed. */
export function parseCorpus(text: string, manifest: CorpusManifest): LoadedCorpus {
  if (sha256hex(text) !== manifest.sha256) throw new CorpusError('corpus_hash_mismatch', 'the corpus content does not match its pinned sha256');
  const lines = text.split('\n').filter((l) => l.length > 0);
  let header: CorpusHeader;
  const items: CorpusItem[] = [];
  try {
    const h = (JSON.parse(lines[0] ?? '') as { corpus?: CorpusHeader }).corpus;
    if (!h || !isObj(h.keysets) || !Array.isArray(h.registered_suites)) throw new Error('bad header');
    header = h;
    const seen = new Set<string>();
    for (const l of lines.slice(1)) {
      const it = JSON.parse(l) as CorpusItem;
      if (typeof it.id !== 'string' || seen.has(it.id) || !Array.isArray(it.profiles)) throw new Error('bad item');
      seen.add(it.id);
      items.push(it);
    }
  } catch (e) {
    throw new CorpusError('corpus_malformed', `the corpus is malformed: ${(e as Error).message}`);
  }
  if (items.length !== manifest.items || header.version !== manifest.corpus_version) {
    throw new CorpusError('corpus_manifest_mismatch', 'the corpus does not match its manifest (item count or version)');
  }
  return { manifest, header, items };
}

const BUNDLED = join(__dirname, '..', 'corpus');
export function bundledManifest(): CorpusManifest {
  return JSON.parse(readFileSync(join(BUNDLED, 'manifest.json'), 'utf8')) as CorpusManifest;
}

let cached: LoadedCorpus | undefined;
/** The corpus shipped in this package (hash-checked against its manifest on first use). */
export function loadBundledCorpus(): LoadedCorpus {
  cached ??= parseCorpus(gunzipSync(readFileSync(join(BUNDLED, 'corpus.jsonl.gz'))).toString('utf8'), bundledManifest());
  return cached;
}

/** Load a corpus from a file pair (a newer or older version): the manifest's sha256 is the pin, so it must be the one you trust. */
export function loadCorpusFiles(corpusPath: string, manifestPath: string): LoadedCorpus {
  const raw = readFileSync(corpusPath);
  const text = (corpusPath.endsWith('.gz') ? gunzipSync(raw) : raw).toString('utf8');
  return parseCorpus(text, JSON.parse(readFileSync(manifestPath, 'utf8')) as CorpusManifest);
}

/** The exact line sent to the driver for an item. The expectation is never part of it. */
export function sendLine(item: CorpusItem, header: CorpusHeader): Record<string, Json> {
  if (item.kind === 'produce' && item.produce) {
    const ks = header.keysets[item.produce.keyset];
    if (!ks) throw new CorpusError('corpus_malformed', `unknown key set ${item.produce.keyset}`);
    const raw = JSON.stringify({ op: item.produce.op, args: item.produce.args, keys: ks.keys, ...(ks.pq_keys !== undefined ? { pq_keys: ks.pq_keys } : {}) });
    return { id: item.id, kind: 'produce', raw, grant: '', now: 0, aud: '' };
  }
  return { id: item.id, ...(item.send ?? {}) };
}
