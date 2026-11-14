// verify.ts - offline checks of the committed packs: integrity (shard digests, Merkle root), the model's own validation
// and structural rules, the lint subset that applies to generated defs (LD-/LW- ids from the spec), sizes, and the licence ledger.
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  CORE_REGISTRY, defDigest, effective, packRoot, requiredPrulesViolated, tablesDigest, traitsDigest, validateDef, type ActionDef,
} from '@atlasauth/pca-actions';
import { PACKS_ROOT, sha256hex } from './pack';

export const MAX_SHARD_BYTES = 1024 * 1024;

export interface Manifest {
  name: string; version: string; ns: string[]; count: number; root: string; traits_digest: string; tables_digest: string;
  review: { authored: number; unreviewed: number }; redistribution: string; licence_notes: string; stability: string;
  sources: { id: string; kind: string; uri: string; spec_digest: string; licence: string; licence_url: string }[];
  generated_by: { generator: string; rules_digest: string };
  shards: { file: string; count: number; bytes: number; sha256: string; first: string; last: string }[];
  stats: Record<string, unknown>;
}

export function packDirs(): { name: string; version: string; dir: string }[] {
  if (!existsSync(PACKS_ROOT)) return [];
  const out: { name: string; version: string; dir: string }[] = [];
  for (const n of readdirSync(PACKS_ROOT).sort()) {
    const p = join(PACKS_ROOT, n);
    if (!statSync(p).isDirectory()) continue;
    for (const v of readdirSync(p).sort()) if (existsSync(join(p, v, 'pack.json'))) out.push({ name: n, version: v, dir: join(p, v) });
  }
  return out;
}

export function readPack(dir: string): { m: Manifest; defs: ActionDef[]; lines: string[] } {
  const m = JSON.parse(readFileSync(join(dir, 'pack.json'), 'utf8')) as Manifest;
  const defs: ActionDef[] = [];
  const lines: string[] = [];
  for (const s of m.shards) for (const l of readFileSync(join(dir, s.file), 'utf8').split('\n')) if (l) { lines.push(l); defs.push(JSON.parse(l) as ActionDef); }
  return { m, defs, lines };
}

const WRITE = (d: ActionDef): boolean => !d.effects.every((e) => e === 'read');
const DELETE_NAME = /^(delete|destroy|remove|purge|erase|wipe|drop)(_|$)/; // the action word leads the segment

/** Lint errors and (strict) warnings that can apply to a generated def. */
export function lintDef(d: ActionDef): string[] {
  const out: string[] = [];
  const last = d.verb.split('.').pop()!;
  if (DELETE_NAME.test(last) && !d.effects.includes('delete')) out.push('LD-001');
  // pack lint judges the defs as written (the hint view): in enforcement every unconfirmed def is the registry top
  const full = effective(d, CORE_REGISTRY);
  const eff = { ...full, ...full.hint };
  const ps = Object.entries(d.params);
  for (const [k, p] of ps) {
    if (p.role === 'money.amount' && (!p.unit || p.unit.kind !== 'money')) out.push(`LD-002:${k}`);
    if (p.role === 'money.currency' && p.format !== 'iso_currency') out.push(`LD-002:${k}`);
    if (p.type === 'integer' && !(p.role?.startsWith('id.')) && (p.min === undefined || p.max === undefined)) out.push(`LD-003:${k}`);
    if (p.type === 'string' && p.max_len === undefined && p.values === undefined && !p.format) out.push(`LW-002:${k}`);
    if (p.type === 'array' && p.max_items === undefined) out.push(`LW-006:${k}`);
    if (p.role === 'text.message' && d.effects.includes('send') && !(p.tags ?? []).includes('free_text_outbound')) out.push(`LW-003:${k}`);
    if (['money.amount', 'party.payee', 'credential.secret', 'credential.token', 'credential.key', 'person.national_id', 'code.command', 'query.sql'].includes(p.role ?? '') && p.provenance_min === undefined) out.push(`LW-007:${k}`);
  }
  if ((d.effects.includes('pay') || eff.closure.includes('pca.money_moving')) && (d.idempotency?.mode ?? 'none') === 'none') out.push('LD-004');
  if (d.resource.id === '*' && d.resource.scope === 'one') out.push('LD-008');
  if (WRITE(d) && d.reversibility === 'reversible' && d.compensates === undefined) out.push('LD-010');
  if (d.review.state === 'confirmed') out.push('LD-011');
  if (requiredPrulesViolated(d, eff.eff).length) out.push('LD-012');
  if (!WRITE(d) && ps.some(([, p]) => p.role === 'code.command' || p.role === 'query.sql' || (p.tags ?? []).includes('credential'))) out.push('LD-013');
  if (eff.clamps.length) out.push('LD-006');
  if (d.description === undefined || new TextEncoder().encode(d.description).length > 400) out.push('LW-001');
  if (d.since === undefined) out.push('LW-010');
  if (['pca.money_moving', 'pca.destructive', 'pca.privilege_change'].some((t) => eff.closure.includes(t)) && !(d.examples?.length)) out.push('LW-009');
  return out;
}

export async function verifyAll(only?: string): Promise<string[]> {
  const errs: string[] = [];
  const packs = packDirs().filter((p) => !only || p.name === only);
  if (!packs.length) errs.push('no packs found');
  const tr = traitsDigest(CORE_REGISTRY), tb = tablesDigest();
  const allVerbs = new Map<string, string>();
  for (const { name, dir } of packs) {
    const { m, defs, lines } = readPack(dir);
    const e = (s: string) => errs.push(`${name}: ${s}`);
    if (m.traits_digest !== tr) e('traits_digest is stale (registry changed)');
    if (m.tables_digest !== tb) e('tables_digest is stale');
    if (m.stability !== 'experimental' && m.stability !== 'stable') e('stability missing');
    for (const s of m.shards) {
      const txt = readFileSync(join(dir, s.file), 'utf8');
      if (sha256hex(txt) !== s.sha256 || Buffer.byteLength(txt) !== s.bytes) e(`shard ${s.file} digest or size differs from pack.json`);
      if (s.bytes > MAX_SHARD_BYTES) e(`shard ${s.file} exceeds 1 MiB`);
    }
    if (defs.length !== m.count) e(`count ${defs.length} != manifest ${m.count}`);
    let prev = '';
    const aliases = new Map<string, string>();
    const bindings = new Map<string, string>();
    const digests: string[] = [];
    let authored = 0;
    lines.forEach((l, i) => { if (JSON.stringify(JSON.parse(l)) !== l) e(`line ${i} is not in written form`); });
    for (const d of defs) {
      if (d.verb <= prev) e(`not sorted/unique at ${d.verb}`);
      prev = d.verb;
      const prior = allVerbs.get(d.verb);
      if (prior && prior !== name) e(`verb ${d.verb} also in pack ${prior}`);
      allVerbs.set(d.verb, name);
      const ve = validateDef(d);
      if (ve) { e(`${d.verb}: ${ve}`); continue; }
      digests.push(defDigest(d));
      if (d.review.state === 'authored') authored++;
      for (const a of d.aliases ?? []) { if (aliases.has(a)) e(`LD-009 alias ${a}`); aliases.set(a, d.verb); }
      const ob = d.bindings?.openapi;
      if (ob) { const k = `${ob.operationId}|${ob.method ?? ''}|${ob.path ?? ''}`; if (bindings.has(k)) e(`LD-014 binding of ${d.verb} duplicates ${bindings.get(k)}`); bindings.set(k, d.verb); }
      for (const f of lintDef(d)) e(`${d.verb}: ${f}`);
    }
    for (const a of aliases.keys()) if (allVerbs.has(a) && allVerbs.get(a) === name && defs.some((x) => x.verb === a)) e(`LD-009 alias ${a} equals a verb`);
    if (authored !== m.review.authored || defs.length - authored !== m.review.unreviewed) e('review counts differ from pack.json');
    if (digests.length && packRoot(digests) !== m.root) e('Merkle root does not match the defs');
    // licence ledger inputs
    if (!m.sources.length) e('no sources recorded');
    for (const s of m.sources) {
      if (s.kind !== 'table' && !/\/blob\/[0-9a-f]{40}\//.test(s.uri)) e(`source ${s.id}: not pinned to an immutable commit sha`);
      if (!s.licence || /unknown|todo/i.test(s.licence)) e(`source ${s.id}: licence not recorded`);
      if (s.kind !== 'table' && (!s.licence_url || !/^sha256:[0-9a-f]{64}$/.test(s.spec_digest))) e(`source ${s.id}: licence_url or spec digest missing`);
    }
    if (!m.licence_notes) e('licence_notes missing');
  }
  if (!only) {
    const f = join(PACKS_ROOT, 'LICENCES.md');
    if (!existsSync(f)) errs.push('LICENCES.md missing');
    else if (readFileSync(f, 'utf8') !== (await ledgerText())) errs.push('LICENCES.md is stale (run gen.ts ledger)');
  }
  return errs;
}

export async function ledgerText(): Promise<string> {
  const rows: string[] = [];
  const lines = [
    '# Pack licence ledger',
    '',
    'One section per action pack: where its definitions come from, under what licence, and whether derived data (names, parameters, traits) may be redistributed.',
    'Generated by `scripts/actions-packs/gen.ts ledger` from each pack manifest; CI fails if it is stale. Raw third-party specifications are never committed: only the digest of the exact bytes the generator read.',
    '',
    '| Pack | Version | Defs | Derived data may be redistributed |',
    '|---|---|---|---|',
  ];
  const packs = packDirs();
  for (const { name, version, dir } of packs) {
    const { m } = readPack(dir);
    lines.push(`| ${name} | ${version} | ${m.count} | ${m.redistribution} |`);
    rows.push('', `## ${name} ${version}`, '', `${m.licence_notes}`, '');
    for (const s of m.sources) rows.push(`- \`${s.id}\` (${s.kind}): ${s.uri}  `, `  licence: ${s.licence}${s.licence_url ? ` (${s.licence_url})` : ''}; ${s.kind === 'table' ? 'authored in-house' : `bytes read: ${s.spec_digest}`}`);
  }
  return `${[...lines, ...rows].join('\n')}\n`;
}
