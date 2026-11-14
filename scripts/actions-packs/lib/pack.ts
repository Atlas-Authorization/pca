// pack.ts - deterministic pack writer: canonical def lines, size-bounded shards, pack.json with the Merkle root.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { CORE_REGISTRY, defDigest, packRoot, tablesDigest, traitsDigest, VERB_RE, type ActionDef } from '@atlasauth/pca-actions';
import { fit } from './naming';
import { addExamples, build as build_, linkCompensation, settleClamps, type Built, type BuildOpts } from './build';
import type { RawOp, SourceDecl } from './types';

export const GENERATOR_VERSION = 'actions-packs/1';
export const SHARD_BYTES = 700 * 1024; // spec: <= 1 MB per shard; 700 KiB leaves headroom
export const PACKS_ROOT = join(__dirname, '../../../packages/pca-actions/packs');

export interface PackDef {
  name: string;
  version: string;
  /** Does the licence of every source permit redistributing derived data (names, params, traits)? */
  redistribution: 'permitted' | 'names_only' | 'digest_only' | 'ours';
  stability?: 'experimental' | 'stable';
  licence_notes: string;
  /** Source declarations (pinned in packs/<name>.sources.json). */
  sources: SourceDecl[];
  /** Files whose bytes enter the generator's rules digest, besides lib/*. */
  config_file: string;
  generate(load: (id: string) => unknown): Built[];
}

export const sha256hex = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');

/** `<ns>.<segments>` with the model's limits; null when the name cannot be made valid. */
export function verbOf(ns: string, segs: string[]): string | null {
  let s = segs.map((x) => fit(x.toLowerCase().replace(/[^a-z0-9_]+/g, '_').replace(/^_+|_+$/g, ''))).filter(Boolean);
  while (s.length > 5) s = [s[0]!, ...s.slice(2)];
  const v = [ns, ...s].join('.');
  return VERB_RE.test(v) && new TextEncoder().encode(v).length <= 128 ? v : null;
}

/** Turn RawOps into Built defs: names, collisions, build. */
export function buildAll(ns: string, ops: RawOp[], o: BuildOpts, used: Set<string> = new Set<string>()): Built[] {
  const out: Built[] = [];
  for (const op of ops) {
    if (op.path.length === 0) continue;
    const base = verbOf(ns, op.path);
    if (!base) continue;
    let verb = base;
    for (let n = 2; used.has(verb); n++) {
      const sfx = `_${n}`;
      verb = verbOf(ns, [...op.path.slice(0, -1), `${fit(op.path[op.path.length - 1]!, 32 - sfx.length)}${sfx}`]) ?? `${base}${sfx}`;
    }
    used.add(verb);
    out.push(build_(op, verb, o));
  }
  const defs = out.filter((b) => b.def).map((b) => b.def!);
  linkCompensation(defs);
  settleClamps(defs);
  addExamples(defs);
  return out;
}

export interface Stats { total: number; authored: number; unreviewed: number; skipped: Record<string, number>; dropped_params: number; by_effect: Record<string, number> }

export function writePack(p: PackDef, built: Built[], dir: string, sources: SourceDecl[]): { root: string; stats: Stats } {
  const defs = built.filter((b) => b.def).map((b) => b.def!);
  defs.sort((a, b) => (a.verb < b.verb ? -1 : a.verb > b.verb ? 1 : 0));
  const stats: Stats = { total: defs.length, authored: 0, unreviewed: 0, skipped: {}, dropped_params: 0, by_effect: {} };
  for (const b of built) {
    if (b.skip) { if (process.env.PACK_DEBUG) console.error('skip', b.verb, b.skip); const k = b.skip.replace(/^(invalid|prules): [A-Za-z0-9_.]+: /, '$1: ').replace(/'[^']*'/g, "'_'").replace(/\d+/g, 'N').slice(0, 110); stats.skipped[k] = (stats.skipped[k] ?? 0) + 1; }
    stats.dropped_params += b.dropped;
  }
  for (const d of defs) {
    if (d.review.state === 'authored') stats.authored++; else stats.unreviewed++;
    for (const e of d.effects) stats.by_effect[e] = (stats.by_effect[e] ?? 0) + 1;
  }
  const seen = new Set<string>();
  for (const d of defs) { if (seen.has(d.verb)) throw new Error(`duplicate verb ${d.verb}`); seen.add(d.verb); }
  const digests = defs.map(defDigest);
  const root = packRoot(digests);
  // shards
  const outDir = join(dir, p.version);
  if (existsSync(outDir)) rmSync(outDir, { recursive: true });
  mkdirSync(join(outDir, 'defs'), { recursive: true });
  const shards: { file: string; count: number; bytes: number; sha256: string; first: string; last: string }[] = [];
  let buf: string[] = [];
  let size = 0;
  let first = '';
  const flush = (lastVerb: string) => {
    if (!buf.length) return;
    const idx = String(shards.length).padStart(3, '0');
    const slug = first.split('.').slice(0, 2).join('_').slice(0, 40);
    const file = `defs/${idx}-${slug}.jsonl`;
    const text = buf.join('');
    writeFileSync(join(outDir, file), text);
    shards.push({ file, count: buf.length, bytes: Buffer.byteLength(text), sha256: sha256hex(text), first, last: lastVerb });
    buf = []; size = 0; first = '';
  };
  let prev = '';
  for (const d of defs) {
    const line = `${JSON.stringify(d)}\n`;
    if (size + line.length > SHARD_BYTES) flush(prev);
    if (!buf.length) first = d.verb;
    buf.push(line); size += Buffer.byteLength(line); prev = d.verb;
  }
  flush(prev);
  const nsList = [...new Set(defs.map((d) => d.verb.split('.')[0]!))].sort();
  const libDir = join(__dirname);
  const rulesDigest = sha256hex(['classify.ts', 'infer.ts', 'union.ts', 'hand.ts', 'build.ts', 'naming.ts', 'openapi.ts', 'pack.ts'].map((f) => readFileSync(join(libDir, f), 'utf8')).join('\n') + readFileSync(join(libDir, '../../../packages/pca-actions/src/import/rules.ts'), 'utf8') + readFileSync(join(libDir, '../../../packages/pca-actions/corpus/adjudication.tsv'), 'utf8') + readFileSync(p.config_file, 'utf8'));
  const manifest = {
    v: 1, kind: 'pca-action-pack', name: p.name, version: p.version, ns: nsList, count: defs.length,
    root, traits_digest: traitsDigest(CORE_REGISTRY), tables_digest: tablesDigest(),
    review: { authored: stats.authored, unreviewed: stats.unreviewed },
    stability: p.stability ?? 'experimental', redistribution: p.redistribution, licence_notes: p.licence_notes,
    sources: sources.map((s) => ({ id: s.id, kind: s.kind, uri: s.url ?? `https://github.com/${s.repo}/blob/${s.ref}/${s.path}`, spec_digest: `sha256:${s.sha256}`, licence: s.licence, licence_url: s.licence_url ?? '' })),
    generated_by: { generator: GENERATOR_VERSION, rules_digest: rulesDigest },
    shards, stats,
  };
  writeFileSync(join(outDir, 'pack.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  return { root, stats };
}

export function listShardFiles(dir: string): string[] {
  return existsSync(dir) ? readdirSync(dir).sort() : [];
}

export type { ActionDef };
