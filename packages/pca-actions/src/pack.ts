// pack.ts - signed action packs (spec section 7.1): a versioned, hash-chained, Merkle-rooted set of ActionDefs, signed by the
// registry key, with the signed evolution since the previous version. Large packs are sharded by resource family; the root
// covers every def across shards, so one inclusion proof (digest.ts `packProof`) shows a def belongs to a pack of any size.
//
// What a verifier needs and checks (verifyPack): the signature under a PINNED registry key (suite from the key entry), the
// vocabulary digests it was built against, every def (strict structure, sorted, unique), the Merkle root recomputed from the
// defs, shard digests, and the signature of every evolution record. Rollback and chain gaps are the PackTracker's job.

import { hashCanonical } from '@atlasauth/pca';
import {
  signRegistryDoc, verifyRegistrySig, verifyEvolutionRecord, evolutionRecordError,
  type ActionSchemaKey, type EvolutionRecord, type EvolutionSig, type UnsignedEvolutionRecord,
} from '@atlasauth/pca/ext/intent';
import type { SignerSuiteOpts } from '@atlasauth/pca';
import { ACTION_PACK_KIND, ActionKitError, CAVEAT_KINDS, CONTEXT_KEYS, MAX_PACK_DEFS, PARAM_RULE_IDS, type ActionDef } from './def';
import { CORE_REGISTRY } from './core-traits';
import { defDigest, packRoot, tablesDigest, traitsDigest } from './digest';
import { evolutionError, evolutionRecords, signEvolution } from './evolve';
import { isPlainObject, validateDef } from './validate';
import type { ReviewOpts } from './effective';
import type { Registry } from './traits';

export const PACK_SIG_DOMAIN = 'atlas-pca/action-pack/v1\0';
export const PACK_REF_DOMAIN = 'atlas-pca/action-pack-ref/v1';
export const PACK_SHARD_DOMAIN = 'atlas-pca/action-pack-shard/v1';
export const RULES_DIGEST_DOMAIN = 'atlas-pca/action-rules/v1';
export const PACK_SHARD_KIND = 'pca-action-pack-shard';
export const STABILITIES = ['draft', 'beta', 'stable'] as const;
/** Largest shard the builder writes by default. */
export const DEFAULT_SHARD_DEFS = 512;
export const MAX_EVOLUTION_RECORDS = 65_536;

export interface PackSource {
  kind: string;
  uri: string;
  spec_digest: string;
  /** SPDX id or a short licence name. The licence ledger (A6) is keyed on it. */
  licence: string;
  licence_notes: string;
}
export interface ShardRef {
  name: string;
  digest: string;
  uri: string;
}
export interface PackShard {
  v: 1;
  kind: typeof PACK_SHARD_KIND;
  ns: string;
  version: string;
  name: string;
  defs: ActionDef[];
}
export interface UnsignedActionPack {
  v: 1;
  kind: typeof ACTION_PACK_KIND;
  ns: string;
  version: string;
  stability: (typeof STABILITIES)[number];
  traits_digest: string;
  roles_digest: string;
  rules_digest: string;
  /** Merkle root over the sorted def digests (all shards). */
  root: string;
  defs: ActionDef[] | { shards: ShardRef[] };
  source: PackSource;
  /** `packDigest` of the previous version, or null for the first. */
  prev: string | null;
  evolution: EvolutionRecord[];
}
export interface ActionPack extends UnsignedActionPack {
  sig: EvolutionSig;
}

const B64U_43 = /^[A-Za-z0-9_-]{43}$/;
const NS_RE = /^[a-z0-9_]+(?:\.[a-z0-9_]+){0,5}$/;
const SEMVER_RE = /^(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})$/;
const SHARD_NAME_RE = /^[a-z0-9_]+(?:[.-][a-z0-9_]+){0,7}$/;

/** `<0, 0, >0`. Plain MAJOR.MINOR.PATCH only (no pre-release): a registry's versions are totally ordered. */
export function compareVersions(a: string, b: string): number {
  const pa = SEMVER_RE.exec(a);
  const pb = SEMVER_RE.exec(b);
  if (!pa || !pb) throw new ActionKitError('bad_version', `'${!pa ? a : b}' is not MAJOR.MINOR.PATCH`);
  for (let i = 1; i <= 3; i++) {
    const d = Number(pa[i]) - Number(pb[i]);
    if (d !== 0) return d;
  }
  return 0;
}

/** Digest of the vocabularies' rule tables a pack was built against (param rules, caveat kinds, context keys). */
export const rulesDigest = (): string => hashCanonical({ d: RULES_DIGEST_DOMAIN, prules: [...PARAM_RULE_IDS], caveats: [...CAVEAT_KINDS], context: [...CONTEXT_KEYS] });

/** The pack's content address (over the whole signed document): what the next version chains to and the log records. */
export const packDigest = (p: ActionPack): string => hashCanonical({ d: PACK_REF_DOMAIN, p });
export const shardDigest = (s: PackShard): string => hashCanonical({ d: PACK_SHARD_DOMAIN, s });

const closedKeys = (o: Record<string, unknown>, allowed: readonly string[]): string | null => {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) return `unknown member '${k}'`;
  return null;
};

function sortedUniqueDefsError(defs: readonly ActionDef[]): string | null {
  for (let i = 0; i < defs.length; i++) {
    const e = validateDef(defs[i]);
    if (e) return `def ${i}: ${e}`;
    if (i > 0 && !(defs[i - 1]!.verb < defs[i]!.verb)) return `defs must be sorted by verb and unique (at '${defs[i]!.verb}')`;
  }
  return null;
}

/** Structural check of a pack document (no signature, no shard content). Null = well formed. Never throws. */
export function packShapeError(x: unknown, opts: { signed?: boolean } = {}): string | null {
  try {
    if (!isPlainObject(x)) return 'pack must be an object';
    const signed = opts.signed !== false;
    const e = closedKeys(x, ['v', 'kind', 'ns', 'version', 'stability', 'traits_digest', 'roles_digest', 'rules_digest', 'root', 'defs', 'source', 'prev', 'evolution', ...(signed ? ['sig'] : [])]);
    if (e) return `pack: ${e}`;
    if (x.v !== 1 || x.kind !== ACTION_PACK_KIND) return 'pack: bad v/kind';
    if (typeof x.ns !== 'string' || !NS_RE.test(x.ns)) return 'pack: bad ns';
    if (typeof x.version !== 'string' || !SEMVER_RE.test(x.version)) return 'pack: version must be MAJOR.MINOR.PATCH';
    if (!(STABILITIES as readonly unknown[]).includes(x.stability)) return 'pack: bad stability';
    for (const k of ['traits_digest', 'roles_digest', 'rules_digest', 'root']) if (typeof x[k] !== 'string' || !B64U_43.test(x[k] as string)) return `pack: ${k} must be a base64url digest`;
    if (x.prev !== null && (typeof x.prev !== 'string' || !B64U_43.test(x.prev))) return 'pack: bad prev';
    const s = x.source;
    if (!isPlainObject(s) || closedKeys(s, ['kind', 'uri', 'spec_digest', 'licence', 'licence_notes']) !== null) return 'pack: source must be {kind, uri, spec_digest, licence, licence_notes}';
    for (const k of ['kind', 'uri', 'spec_digest', 'licence', 'licence_notes']) if (typeof s[k] !== 'string' || (k !== 'licence_notes' && (s[k] as string).length === 0) || (s[k] as string).length > 2048) return `pack: source.${k} is not a string of 1..2048 characters`;
    const d = x.defs;
    if (Array.isArray(d)) {
      if (d.length === 0 || d.length > MAX_PACK_DEFS) return `pack: inline defs must number 1..${MAX_PACK_DEFS} (larger packs are sharded)`;
      const de = sortedUniqueDefsError(d as ActionDef[]);
      if (de) return `pack: ${de}`;
    } else {
      if (!isPlainObject(d) || closedKeys(d, ['shards']) !== null || !Array.isArray(d.shards) || d.shards.length === 0 || d.shards.length > 4096) return 'pack: defs must be a list of defs or {shards}';
      const names = new Set<string>();
      for (const r of d.shards as unknown[]) {
        if (!isPlainObject(r) || closedKeys(r, ['name', 'digest', 'uri']) !== null) return 'pack: bad shard ref';
        if (typeof r.name !== 'string' || !SHARD_NAME_RE.test(r.name) || names.has(r.name)) return 'pack: shard names must be distinct simple names';
        names.add(r.name);
        if (typeof r.digest !== 'string' || !B64U_43.test(r.digest) || typeof r.uri !== 'string' || r.uri.length === 0 || r.uri.length > 2048) return 'pack: bad shard digest or uri';
      }
    }
    if (!Array.isArray(x.evolution) || x.evolution.length > MAX_EVOLUTION_RECORDS) return 'pack: evolution must be a list of records';
    for (const r of x.evolution) {
      const re = evolutionRecordError(r);
      if (re) return `pack: ${re}`;
    }
    if (signed) {
      const g = x.sig;
      if (!isPlainObject(g) || closedKeys(g, ['alg', 'kid', 'value', 'pq_value']) !== null || typeof g.kid !== 'string' || typeof g.value !== 'string' || typeof g.alg !== 'string') return 'pack: bad sig';
    }
    const { sig: _g, ...body } = x as Record<string, unknown>;
    void _g;
    hashCanonical(body); // strict canonical form (safe integers, NFC, no lone surrogates)
    return null;
  } catch (err) {
    return `pack: ${(err as Error).message}`;
  }
}

/** Shard names are the resource family (`resource.type` first segment) of the defs, split in order into chunks of `max`. */
export function shardDefs(defs: readonly ActionDef[], max: number = DEFAULT_SHARD_DEFS): Array<{ name: string; defs: ActionDef[] }> {
  if (!Number.isSafeInteger(max) || max < 1) throw new ActionKitError('bad_shard_size', 'the shard size must be a positive integer');
  const fam = new Map<string, ActionDef[]>();
  for (const d of defs) {
    const f = d.resource.type.split('.')[0]!;
    const l = fam.get(f) ?? [];
    l.push(d);
    fam.set(f, l);
  }
  const out: Array<{ name: string; defs: ActionDef[] }> = [];
  for (const f of [...fam.keys()].sort()) {
    const l = fam.get(f)!;
    for (let i = 0, n = 1; i < l.length; i += max, n++) out.push({ name: l.length > max ? `${f}-${n}` : f, defs: l.slice(i, i + max) });
  }
  return out;
}

export interface BuildPackArgs {
  ns: string;
  version: string;
  stability: (typeof STABILITIES)[number];
  defs: readonly ActionDef[];
  source: PackSource;
  kid: string;
  secret: Uint8Array;
  suite?: SignerSuiteOpts;
  reg?: Registry;
  /** The previous version (signed pack and its shard contents): chains `prev` and derives the signed evolution. */
  prev?: { pack: ActionPack; shards?: Readonly<Record<string, PackShard>> };
  /** Shard the pack (always when it exceeds {@link MAX_PACK_DEFS}); `uri` names a shard's location. */
  shard?: { max?: number; uri?: (name: string) => string } | boolean;
  review?: ReviewOpts;
}

/** The defs a pack lists (inline, or gathered from its shards). Throws {@link ActionKitError} when a shard is missing or does not match its ref. */
export function packDefs(pack: ActionPack, shards: Readonly<Record<string, PackShard>> = {}): ActionDef[] {
  if (Array.isArray(pack.defs)) return [...pack.defs];
  const all: ActionDef[] = [];
  for (const r of pack.defs.shards) {
    const s = Object.prototype.hasOwnProperty.call(shards, r.name) ? shards[r.name] : undefined;
    if (s === undefined) throw new ActionKitError('missing_shard', `shard '${r.name}' was not supplied`);
    if (shardDigest(s) !== r.digest) throw new ActionKitError('shard_digest_mismatch', `shard '${r.name}' does not match its digest`);
    if (s.v !== 1 || s.kind !== PACK_SHARD_KIND || s.ns !== pack.ns || s.version !== pack.version || s.name !== r.name || !Array.isArray(s.defs)) throw new ActionKitError('bad_shard', `shard '${r.name}' is not a shard of this pack`);
    all.push(...s.defs);
  }
  return all.sort((a, b) => (a.verb < b.verb ? -1 : a.verb > b.verb ? 1 : 0));
}

/** Build, chain and sign a pack. Returns the pack and (when sharded) its shard documents. Throws {@link ActionKitError} on any inconsistency. */
export function buildPack(a: BuildPackArgs): { pack: ActionPack; shards: Record<string, PackShard> } {
  const reg = a.reg ?? CORE_REGISTRY;
  const defs = [...a.defs].sort((x, y) => (x.verb < y.verb ? -1 : x.verb > y.verb ? 1 : 0));
  const de = sortedUniqueDefsError(defs);
  if (de) throw new ActionKitError('bad_pack', de);
  if (defs.length === 0) throw new ActionKitError('empty_pack', 'a pack has at least one def');
  const prevDefs = a.prev ? packDefs(a.prev.pack, a.prev.shards) : [];
  if (a.prev) {
    if (a.prev.pack.ns !== a.ns) throw new ActionKitError('bad_chain', 'the previous pack is of another namespace');
    if (compareVersions(a.version, a.prev.pack.version) <= 0) throw new ActionKitError('bad_chain', 'the version must increase');
  }
  const records = evolutionRecords(a.ns, prevDefs, defs, reg, a.review ?? {});
  const evolution = signEvolution(records, a.kid, a.secret, a.suite);
  const root = packRoot(defs.map(defDigest));
  const wantShards = a.shard !== undefined && a.shard !== false ? true : defs.length > MAX_PACK_DEFS;
  const shards: Record<string, PackShard> = {};
  let body: UnsignedActionPack['defs'] = defs;
  if (wantShards) {
    const opts = typeof a.shard === 'object' ? a.shard : {};
    const refs: ShardRef[] = [];
    for (const s of shardDefs(defs, opts.max)) {
      const doc: PackShard = { v: 1, kind: PACK_SHARD_KIND, ns: a.ns, version: a.version, name: s.name, defs: s.defs };
      shards[s.name] = doc;
      refs.push({ name: s.name, digest: shardDigest(doc), uri: opts.uri ? opts.uri(s.name) : `shards/${s.name}.json` });
    }
    body = { shards: refs };
  }
  const unsigned: UnsignedActionPack = {
    v: 1, kind: ACTION_PACK_KIND, ns: a.ns, version: a.version, stability: a.stability,
    traits_digest: traitsDigest(reg), roles_digest: tablesDigest(), rules_digest: rulesDigest(),
    root, defs: body, source: a.source, prev: a.prev ? packDigest(a.prev.pack) : null, evolution,
  };
  const pe = packShapeError(unsigned, { signed: false });
  if (pe) throw new ActionKitError('bad_pack', pe);
  return { pack: { ...unsigned, sig: signRegistryDoc(PACK_SIG_DOMAIN, unsigned, a.kid, a.secret, a.suite) }, shards };
}

export type PackVerdict = { ok: true; defs: ActionDef[]; digest: string } | { ok: false; reason: string };

/**
 * Verify a pack against the pinned registry keys: shape, signature (suite from the key entry), vocabulary digests, shards, defs,
 * the recomputed Merkle root, and the signature and namespace of every evolution record. Never throws.
 */
export function verifyPack(pack: unknown, keys: readonly ActionSchemaKey[], opts: { shards?: Readonly<Record<string, PackShard>>; reg?: Registry } = {}): PackVerdict {
  try {
    const fail = (reason: string): PackVerdict => ({ ok: false, reason });
    const se = packShapeError(pack);
    if (se) return fail(se);
    const p = pack as ActionPack;
    const { sig, ...body } = p;
    const v = verifyRegistrySig(PACK_SIG_DOMAIN, body, sig, keys);
    if (!v.ok) return fail(`pack signature: ${v.reason}`);
    const reg = opts.reg ?? CORE_REGISTRY;
    if (p.traits_digest !== traitsDigest(reg)) return fail('traits_digest does not match the trait registry');
    if (p.roles_digest !== tablesDigest()) return fail('roles_digest does not match the vocabulary tables');
    if (p.rules_digest !== rulesDigest()) return fail('rules_digest does not match the rule tables');
    let defs: ActionDef[];
    try {
      defs = packDefs(p, opts.shards);
    } catch (e) {
      return fail((e as Error).message);
    }
    const de = sortedUniqueDefsError(defs);
    if (de) return fail(de);
    if (defs.length === 0 || defs.length > 1_000_000) return fail('the pack lists no defs or too many');
    const digests = defs.map(defDigest);
    if (packRoot(digests) !== p.root) return fail('the Merkle root does not match the defs');
    const have = new Set(digests);
    for (const r of p.evolution) {
      const rv = verifyEvolutionRecord(r, keys);
      if (!rv.ok) return fail(`evolution record: ${rv.reason}`);
      if (r.ns !== p.ns) return fail('evolution record of another namespace');
      if (r.to !== null && !have.has(r.to)) return fail(`evolution record for '${r.verb}' names a definition that is not in the pack`);
    }
    return { ok: true, defs, digest: packDigest(p) };
  } catch (e) {
    return { ok: false, reason: `pack verification error: ${(e as Error).message}` };
  }
}

/**
 * Verify `next` as the successor of `prev`: both verify, same namespace, `next.prev` is `prev`'s digest, the version increases, and
 * the signed evolution is EXACTLY the computed change (a registry cannot sign `narrow` for a widening def).
 */
export function verifyUpgrade(prev: ActionPack, next: ActionPack, keys: readonly ActionSchemaKey[], opts: { prevShards?: Readonly<Record<string, PackShard>>; shards?: Readonly<Record<string, PackShard>>; reg?: Registry; review?: ReviewOpts } = {}): { ok: true } | { ok: false; reason: string } {
  const a = verifyPack(prev, keys, { ...(opts.prevShards ? { shards: opts.prevShards } : {}), ...(opts.reg ? { reg: opts.reg } : {}) });
  if (!a.ok) return { ok: false, reason: `previous pack: ${a.reason}` };
  const b = verifyPack(next, keys, { ...(opts.shards ? { shards: opts.shards } : {}), ...(opts.reg ? { reg: opts.reg } : {}) });
  if (!b.ok) return { ok: false, reason: `pack: ${b.reason}` };
  if (next.ns !== prev.ns) return { ok: false, reason: 'the packs are of different namespaces' };
  if (next.prev !== a.digest) return { ok: false, reason: 'chain gap: prev does not name the previous pack' };
  if (compareVersions(next.version, prev.version) <= 0) return { ok: false, reason: 'the version does not increase' };
  const ee = evolutionError(next.ns, a.defs, b.defs, next.evolution, keys, opts.reg ?? CORE_REGISTRY, opts.review ?? {});
  return ee === null ? { ok: true } : { ok: false, reason: ee };
}

/** The unsigned record type, re-exported for callers building records by hand. */
export type { UnsignedEvolutionRecord };
