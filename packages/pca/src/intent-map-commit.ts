import { b64u, canonicalBytesStrict, compareUtf8, decodeB64uStrict, hasLoneSurrogate, sha256, utf8 } from './hash';
import { paramsDigest } from './merkle';
import { isPlainObject, isSafeInt, isSafeNonNeg, ownGet, ownHas } from './intent-strict';

/**
 * THE COMMITTED INTENT MAP AND Z0 DISCLOSURE (Intent Layer v2 §3.10, milestone V15; conformance README rule 19). NORMATIVE
 * for every verifier (TypeScript reference, the 9 native verifiers, the zkVM guest: Z1 proves the same decision without
 * revealing the disclosure).
 *
 * MAP COMMITMENT. A v2 Intent Map has a Merkle form. Its leaves, IN THIS ORDER:
 *   1. one HEADER leaf per verb, verbs sorted by UTF-8 byte order:
 *        {verb, first, cells, dims}   `first` = the leaf index of the verb's flat cell 0, `cells` = its cell count;
 *   2. for each verb in that order, one CELL leaf per flat cell index 0 .. cells-1 (row-major, last dimension fastest):
 *        {verb, cell: [i_1, ..., i_k], p_ppm, in_grant};
 *   3. one METRICS leaf (the map's claimed metrics, integers);
 *   4. one LEARNER leaf {learner_digest} (the content address of the map's learner settings).
 * Every leaf is hashed with its OWN 32-byte salt r and a domain tag for its kind (no leaf kind can be read as another, and
 * no leaf as an internal node):
 *   leaf_hash = SHA-256(TAG_kind || r || strictCanonical(leaf))        TAG_kind in {TAG_HEADER, TAG_CELL, TAG_METRICS, TAG_LEARNER}
 *   node_hash = SHA-256(TAG_NODE || left || right)
 *   tree      = RFC 6962 / 9162 shape over the n leaf hashes (split at the largest power of two < n; no duplication)
 *   map_commit = base64url(SHA-256(TAG_COMMIT || u64be(n) || tree_root))
 * The per-leaf salts make the commitment HIDING (a disclosed sibling hash reveals nothing about a low-entropy cell leaf);
 * the wallet derives them from one session secret (informative: r_i = SHA-256(TAG_SALT || secret || u64be(i))), so the same
 * map in two sessions has unrelated commitments and the sessions are not linkable by the map.
 *
 * WIRE (rule 13 amendment). A PCActn whose `intent_session.map_form` is "commit" carries `intent.map_digest` = map_commit and
 * its session grant's goal is `pca-intent:v2c:<session>:<map_commit>` (intent-binding.ts); absent `map_form` = the plain
 * map digest and the `pca-intent:v2:` goal.
 *
 * CELL OF ω. For each dimension of the verb's header, in order, the action's value at the dimension's path
 * (`action.resource`, or the OWN member `<name>` of the action params for `action.params.<name>`; any other path cannot be
 * evaluated by a relying party and fails closed):
 *   num: the value must be a safe integer; its index is the numeric cell [lo_j, hi_j] that contains it, the cells being
 *        [lo, c_1 - 1], {c_1}, [c_1 + 1, c_2 - 1], {c_2}, ..., {c_k}, [c_k + 1, hi] with empty ranges dropped;
 *   cat: the value must be a string; its index is the `exact` value equal to it, else the longest `prefix` value it starts
 *        with, else the single `other` value.
 * A value outside the dimension (absent, wrong type, outside [lo, hi]) fails closed. flat = Σ_j i_j · Π_{l > j} n_l and the
 * action's cell leaf is leaf index `first + flat`.
 *
 * CHECK `map` (Z0) is decideMapDisclosure below.
 */

export const MAP_TAG_HEADER = 'atlas-pca/intent-map/header/v1\0';
export const MAP_TAG_CELL = 'atlas-pca/intent-map/cell/v1\0';
export const MAP_TAG_METRICS = 'atlas-pca/intent-map/metrics/v1\0';
export const MAP_TAG_LEARNER = 'atlas-pca/intent-map/learner/v1\0';
export const MAP_TAG_NODE = 'atlas-pca/intent-map/node/v1\0';
export const MAP_TAG_COMMIT = 'atlas-pca/intent-map/commit/v1\0';
/** Informative: the wallet's per-leaf salt derivation. */
export const MAP_TAG_SALT = 'atlas-pca/intent-map/salt/v1\0';
/** The `intent_session.map_form` value that selects the committed form. */
export const MAP_FORM_COMMIT = 'commit';
/** The OTHER value of a categorical dimension (as in @atlasauth/pca-intent omega.ts). */
export const MAP_OTHER = '⊥';

export const MAX_MAP_LEAVES = 1 << 24;
export const MAX_VERB_CELLS = 1 << 20;
export const MAX_MAP_DIMS = 16;
export const MAX_MAP_CUTS = 256;
export const MAX_MAP_VALUES = 256;
export const MAX_MAP_STRING_BYTES = 256;
const PPM_ONE = 1_000_000;

export type MapLeafKind = 'header' | 'cell' | 'metrics' | 'learner';
export interface MapNumDim {
  kind: 'num';
  path: string;
  lo: number;
  hi: number;
  cuts: number[];
}
export interface MapCatDim {
  kind: 'cat';
  path: string;
  values: { kind: 'exact' | 'prefix' | 'other'; value: string }[];
}
export type MapDim = MapNumDim | MapCatDim;
export interface MapHeaderLeaf {
  verb: string;
  first: number;
  cells: number;
  dims: MapDim[];
}
export interface MapCellLeaf {
  verb: string;
  cell: number[];
  p_ppm: number;
  in_grant: boolean;
}
export const MAP_METRIC_FIELDS = [
  'residual_risk_ppm',
  'burden_ppm',
  'uncertainty_ppm',
  'disagreement_ppm',
  'mean_harm_ppm',
  'fidelity_est_ppm',
  'entropy_mbits',
  'questions',
  'conflicts',
] as const;
/** The metrics leaf: every member of MAP_METRIC_FIELDS (non-negative safe integers) and, when computed, `log2_vs_mbits`. */
export type MapMetricsLeaf = Record<(typeof MAP_METRIC_FIELDS)[number], number> & { log2_vs_mbits?: number };
export interface MapLearnerLeaf {
  learner_digest: string;
}

/** One disclosed leaf: its index, its salt and its audit path (sibling hashes bottom-up; sides follow from index / size). */
export interface MapDisclosedLeaf<L> {
  index: number;
  salt: string;
  leaf: L;
  path: string[];
}
/** Z0 disclosure: the verb's header, the action's cell and the metrics, against one commitment of `size` leaves. */
export interface MapDisclosure {
  size: number;
  header: MapDisclosedLeaf<MapHeaderLeaf>;
  cell: MapDisclosedLeaf<MapCellLeaf>;
  metrics: MapDisclosedLeaf<MapMetricsLeaf>;
}

export interface MapPolicy {
  /** Require every PCActn to carry a committed map (`intent_session.map_form: "commit"`) and a disclosure. */
  require?: boolean;
  /** ε: the action is admitted only if the committed metrics claim residual_risk_ppm <= ε. */
  max_residual_risk_ppm?: number;
}

const TAGS: Record<MapLeafKind, string> = { header: MAP_TAG_HEADER, cell: MAP_TAG_CELL, metrics: MAP_TAG_METRICS, learner: MAP_TAG_LEARNER };
const cat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};
const u64be = (n: number): Uint8Array => {
  const out = new Uint8Array(8);
  let x = n;
  for (let i = 7; i >= 0; i--) {
    out[i] = x % 256;
    x = Math.floor(x / 256);
  }
  return out;
};
const u8len = (s: string) => utf8(s).length;
const isStr = (v: unknown, max = MAX_MAP_STRING_BYTES): v is string => typeof v === 'string' && !hasLoneSurrogate(v) && u8len(v) <= max;
const closed = (o: Record<string, unknown>, allowed: readonly string[], required: readonly string[]): boolean =>
  Object.keys(o).every((k) => allowed.includes(k)) && required.every((k) => ownHas(o, k));

/** SHA-256(TAG_kind || salt || strictCanonical(leaf)). Throws on a leaf that has no strict canonical form. */
export function mapLeafHash(kind: MapLeafKind, salt: Uint8Array, leaf: unknown): Uint8Array {
  if (salt.length !== 32) throw new RangeError('mapLeafHash: the salt is 32 bytes');
  return sha256(cat(utf8(TAGS[kind]), salt, canonicalBytesStrict(leaf)));
}
export function mapNodeHash(l: Uint8Array, r: Uint8Array): Uint8Array {
  return sha256(cat(utf8(MAP_TAG_NODE), l, r));
}
/** map_commit of a tree of `size` leaves with root `root`. */
export function mapCommitOf(size: number, root: Uint8Array): string {
  return b64u(sha256(cat(utf8(MAP_TAG_COMMIT), u64be(size), root)));
}
/** Informative per-leaf salt derivation (wallet side). */
export function mapLeafSalt(secret: Uint8Array, index: number): Uint8Array {
  return sha256(cat(utf8(MAP_TAG_SALT), secret, u64be(index)));
}

const split = (n: number): number => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};
function treeRoot(hs: Uint8Array[]): Uint8Array {
  if (hs.length === 1) return hs[0]!;
  const k = split(hs.length);
  return mapNodeHash(treeRoot(hs.slice(0, k)), treeRoot(hs.slice(k)));
}
function auditPath(hs: Uint8Array[], idx: number, out: Uint8Array[]): void {
  if (hs.length === 1) return;
  const k = split(hs.length);
  if (idx < k) {
    auditPath(hs.slice(0, k), idx, out);
    out.push(treeRoot(hs.slice(k)));
  } else {
    auditPath(hs.slice(k), idx - k, out);
    out.push(treeRoot(hs.slice(0, k)));
  }
}

/** The tree root of the given leaf hashes and the audit path of `index` (builder side). */
export function mapTree(hashes: Uint8Array[]): { root: Uint8Array; path(index: number): string[] } {
  if (hashes.length === 0) throw new RangeError('mapTree: empty');
  const root = treeRoot(hashes);
  return {
    root,
    path(index: number) {
      const out: Uint8Array[] = [];
      auditPath(hashes, index, out);
      return out.map(b64u);
    },
  };
}

/**
 * RFC 9162 §2.1.3.2 inclusion verification with this file's node hash: the root the audit path of leaf `index` in a tree
 * of `size` leaves recomputes, or null when the path has the wrong length for (index, size). Total.
 */
export function mapRootFromPath(index: number, size: number, leafHash: Uint8Array, path: Uint8Array[]): Uint8Array | null {
  if (!(index >= 0 && index < size)) return null;
  let fn = index;
  let sn = size - 1;
  let r = leafHash;
  for (const p of path) {
    if (sn === 0) return null;
    if (fn % 2 === 1 || fn === sn) {
      r = mapNodeHash(p, r);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = mapNodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 ? r : null;
}

// ---- leaf shapes (closed and typed) -----------------------------------------------------------------------------

const PATH_RE = /^action\.params\.[A-Za-z0-9_]{1,64}$/;
const isDimPath = (p: unknown): p is string => p === 'action.resource' || (typeof p === 'string' && PATH_RE.test(p));

/** The cells of a numeric dimension as inclusive [lo, hi] ranges (empty ranges dropped). */
export function mapNumCells(d: MapNumDim): [number, number][] {
  const out: [number, number][] = [];
  let cur = d.lo;
  for (const c of d.cuts) {
    if (cur <= c - 1) out.push([cur, c - 1]);
    out.push([c, c]);
    cur = c + 1;
  }
  if (cur <= d.hi) out.push([cur, d.hi]);
  return out;
}
const dimCells = (d: MapDim): number => (d.kind === 'num' ? mapNumCells(d).length : d.values.length);

function dimError(d: unknown, j: number): string | null {
  if (!isPlainObject(d)) return `dims[${j}] must be an object`;
  if (d.kind === 'num') {
    if (!closed(d, ['kind', 'path', 'lo', 'hi', 'cuts'], ['kind', 'path', 'lo', 'hi', 'cuts'])) return `dims[${j}] must be exactly {kind, path, lo, hi, cuts}`;
    if (!isDimPath(d.path) || d.path === 'action.resource') return `dims[${j}].path must be action.params.<name>`;
    if (!isSafeInt(d.lo) || !isSafeInt(d.hi) || d.lo > d.hi) return `dims[${j}] lo / hi must be safe integers with lo <= hi`;
    if (!Array.isArray(d.cuts) || d.cuts.length > MAX_MAP_CUTS) return `dims[${j}].cuts must be an array of at most ${MAX_MAP_CUTS}`;
    let prev = -Infinity;
    for (const c of d.cuts) {
      if (!isSafeInt(c) || c <= prev || c < (d.lo as number) || c > (d.hi as number)) return `dims[${j}].cuts must be strictly increasing safe integers in [lo, hi]`;
      prev = c;
    }
    return null;
  }
  if (d.kind === 'cat') {
    if (!closed(d, ['kind', 'path', 'values'], ['kind', 'path', 'values'])) return `dims[${j}] must be exactly {kind, path, values}`;
    if (!isDimPath(d.path)) return `dims[${j}].path must be action.resource or action.params.<name>`;
    if (!Array.isArray(d.values) || d.values.length === 0 || d.values.length > MAX_MAP_VALUES) return `dims[${j}].values must be an array of 1..${MAX_MAP_VALUES}`;
    const seen = new Set<string>();
    for (const [i, v] of d.values.entries()) {
      if (!isPlainObject(v) || !closed(v, ['kind', 'value'], ['kind', 'value'])) return `dims[${j}].values[${i}] must be exactly {kind, value}`;
      if (v.kind !== 'exact' && v.kind !== 'prefix' && v.kind !== 'other') return `dims[${j}].values[${i}].kind must be exact, prefix or other`;
      if (!isStr(v.value)) return `dims[${j}].values[${i}].value must be a string of at most ${MAX_MAP_STRING_BYTES} UTF-8 bytes`;
      if (v.kind === 'other' ? i !== d.values.length - 1 || v.value !== MAP_OTHER : v.kind === 'prefix' && v.value.length === 0) {
        return `dims[${j}].values: exactly one other ('${MAP_OTHER}'), last; prefixes non-empty`;
      }
      const key = `${v.kind}:${v.value}`;
      if (seen.has(key)) return `dims[${j}].values must be distinct`;
      seen.add(key);
    }
    if ((d.values[d.values.length - 1] as { kind: unknown }).kind !== 'other') return `dims[${j}].values must end with the other value`;
    return null;
  }
  return `dims[${j}].kind must be num or cat`;
}

/** Shape of a header leaf (closed, typed; `cells` equals the product of the dimensions' cell counts). Null = well-formed. */
export function mapHeaderError(h: unknown): string | null {
  if (!isPlainObject(h) || !closed(h, ['verb', 'first', 'cells', 'dims'], ['verb', 'first', 'cells', 'dims'])) return 'the header leaf must be exactly {verb, first, cells, dims}';
  if (!isStr(h.verb, 128) || h.verb.length === 0) return 'header.verb must be a non-empty string of at most 128 UTF-8 bytes';
  if (!isSafeNonNeg(h.first) || h.first >= MAX_MAP_LEAVES) return 'header.first must be a leaf index';
  if (!isSafeInt(h.cells) || h.cells < 1 || h.cells > MAX_VERB_CELLS) return `header.cells must be a safe integer in [1, ${MAX_VERB_CELLS}]`;
  if (!Array.isArray(h.dims) || h.dims.length > MAX_MAP_DIMS) return `header.dims must be an array of at most ${MAX_MAP_DIMS}`;
  const paths = new Set<string>();
  let n = 1;
  for (const [j, d] of h.dims.entries()) {
    const e = dimError(d, j);
    if (e) return `header.${e}`;
    const dd = d as MapDim;
    if (paths.has(dd.path)) return 'header.dims paths must be distinct';
    paths.add(dd.path);
    n *= dimCells(dd);
    if (n > MAX_VERB_CELLS) return 'header: too many cells';
  }
  if (n !== h.cells) return 'header.cells is not the product of the dimensions\' cell counts';
  return null;
}

export function mapCellError(c: unknown): string | null {
  if (!isPlainObject(c) || !closed(c, ['verb', 'cell', 'p_ppm', 'in_grant'], ['verb', 'cell', 'p_ppm', 'in_grant'])) return 'the cell leaf must be exactly {verb, cell, p_ppm, in_grant}';
  if (!isStr(c.verb, 128) || c.verb.length === 0) return 'cell.verb must be a non-empty string of at most 128 UTF-8 bytes';
  if (!Array.isArray(c.cell) || c.cell.length > MAX_MAP_DIMS || !c.cell.every(isSafeNonNeg)) return 'cell.cell must be an array of non-negative safe integers';
  if (!isSafeNonNeg(c.p_ppm) || c.p_ppm > PPM_ONE) return 'cell.p_ppm must be a safe integer in [0, 1000000]';
  if (typeof c.in_grant !== 'boolean') return 'cell.in_grant must be a boolean';
  return null;
}

export function mapMetricsError(m: unknown): string | null {
  if (!isPlainObject(m) || !closed(m, [...MAP_METRIC_FIELDS, 'log2_vs_mbits'], MAP_METRIC_FIELDS)) return `the metrics leaf must be exactly {${MAP_METRIC_FIELDS.join(', ')}, log2_vs_mbits?}`;
  for (const k of [...MAP_METRIC_FIELDS, 'log2_vs_mbits']) {
    const v = ownGet(m, k);
    if (v === undefined && k === 'log2_vs_mbits') continue;
    if (!isSafeNonNeg(v)) return `metrics.${k} must be a non-negative safe integer`;
  }
  return null;
}

export function mapLearnerError(l: unknown): string | null {
  if (!isPlainObject(l) || !closed(l, ['learner_digest'], ['learner_digest'])) return 'the learner leaf must be exactly {learner_digest}';
  return decodeB64uStrict(l.learner_digest, 32) === null ? 'learner.learner_digest must be canonical base64url (32 bytes)' : null;
}

/**
 * Cell of ω: per-dimension cell indices of the action under `header`, or an error. `resource` is `action.resource`,
 * `params` the plaintext action params (own members). Total.
 */
export function mapCellOf(header: MapHeaderLeaf, resource: unknown, params: unknown): { cell: number[]; flat: number } | { error: string } {
  const cell: number[] = [];
  let flat = 0;
  for (const d of header.dims) {
    const x = d.path === 'action.resource' ? resource : isPlainObject(params) ? ownGet(params, d.path.slice('action.params.'.length)) : undefined;
    let i = -1;
    if (d.kind === 'num') {
      if (isSafeInt(x)) i = mapNumCells(d).findIndex(([lo, hi]) => x >= lo && x <= hi);
    } else if (typeof x === 'string' && !hasLoneSurrogate(x)) {
      let best = -1;
      let bestLen = -1;
      for (let k = 0; k < d.values.length; k++) {
        const v = d.values[k]!;
        if (v.kind === 'exact' && v.value === x) {
          best = k;
          bestLen = Infinity;
          break;
        }
        if (v.kind === 'prefix' && x.startsWith(v.value) && v.value.length > bestLen) {
          best = k;
          bestLen = v.value.length;
        }
      }
      i = best >= 0 ? best : d.values.length - 1;
    }
    if (i < 0) return { error: `the action's ${d.path} lies outside the committed map's dimension` };
    cell.push(i);
    flat = flat * dimCells(d) + i;
  }
  return { cell, flat };
}

function entryShape(e: unknown, what: string): string | null {
  if (!isPlainObject(e) || !closed(e, ['index', 'salt', 'leaf', 'path'], ['index', 'salt', 'leaf', 'path'])) return `disclosure.${what} must be exactly {index, salt, leaf, path}`;
  if (!isSafeNonNeg(e.index)) return `disclosure.${what}.index must be a non-negative safe integer`;
  if (decodeB64uStrict(e.salt, 32) === null) return `disclosure.${what}.salt must be canonical base64url (32 bytes)`;
  if (!Array.isArray(e.path) || e.path.length > 64 || !e.path.every((h) => decodeB64uStrict(h, 32) !== null)) return `disclosure.${what}.path must be an array of 32-byte digests`;
  return null;
}

/** Shape of a Z0 disclosure (closed, typed). Null = well-formed. */
export function mapDisclosureError(d: unknown): string | null {
  if (!isPlainObject(d) || !closed(d, ['size', 'header', 'cell', 'metrics'], ['size', 'header', 'cell', 'metrics'])) return 'the disclosure must be exactly {size, header, cell, metrics}';
  if (!isSafeInt(d.size) || d.size < 4 || d.size > MAX_MAP_LEAVES) return `disclosure.size must be a safe integer in [4, ${MAX_MAP_LEAVES}]`;
  for (const k of ['header', 'cell', 'metrics'] as const) {
    const e = entryShape(d[k], k);
    if (e) return e;
  }
  const hd = (d.header as Record<string, unknown>).leaf;
  return mapHeaderError(hd) ?? mapCellError((d.cell as Record<string, unknown>).leaf) ?? mapMetricsError((d.metrics as Record<string, unknown>).leaf);
}

/** Does `e` (kind `kind`) open `mapCommit` in a tree of `size` leaves? */
function opens(kind: MapLeafKind, e: MapDisclosedLeaf<unknown>, size: number, mapCommit: string): boolean {
  try {
    const h = mapLeafHash(kind, decodeB64uStrict(e.salt, 32)!, e.leaf);
    const root = mapRootFromPath(e.index, size, h, e.path.map((x) => decodeB64uStrict(x, 32)!));
    return root !== null && mapCommitOf(size, root) === mapCommit;
  } catch {
    return false;
  }
}

export type MapDecision = { ok: true; cell: number[]; p_ppm: number; residual_risk_ppm: number } | { ok: false; reason: string };

/**
 * Z0, the `map` check (rule 19). Input: the map commitment the PCActn's `intent.map_digest` carries, the action (`verb`,
 * `resource`, `params_digest`), the verifier's plaintext `params`, the agent's `disclosure` and the verifier's ε. First
 * failure wins:
 *   1. the disclosure is well-formed (mapDisclosureError);
 *   2. params hash to `action.params_digest`;
 *   3. header.verb == action.verb; header.index < header.first; header.first + header.cells <= size - 2;
 *   4. the header, cell and metrics leaves each open map_commit (own salt, own tag, audit path, size);
 *   5. the cell of ω under the header (above): cell.index == header.first + flat, cell.verb == verb, cell.cell == the
 *      computed indices;
 *   6. cell.in_grant is true (the action is inside the committed grant G̃_τ(m));
 *   7. metrics.index == size - 2; when ε is set, metrics.residual_risk_ppm <= ε.
 * Never throws.
 */
export function decideMapDisclosure(input: {
  mapCommit: unknown;
  action: { verb?: unknown; resource?: unknown; params_digest?: unknown };
  params: unknown;
  disclosure: unknown;
  maxResidualRiskPpm?: number;
}): MapDecision {
  try {
    const bad = (reason: string): MapDecision => ({ ok: false, reason });
    const de = mapDisclosureError(input.disclosure);
    if (de) return bad(`map disclosure malformed: ${de}`);
    if (decodeB64uStrict(input.mapCommit, 32) === null) return bad('the PCActn carries no map commitment');
    const d = input.disclosure as MapDisclosure;
    const commit = input.mapCommit as string;
    if (input.params !== undefined && !isPlainObject(input.params)) return bad('params must be an object');
    if (paramsDigest(input.params ?? {}) !== input.action.params_digest) return bad('the params do not hash to action.params_digest');
    const h = d.header.leaf;
    if (h.verb !== input.action.verb) return bad("the disclosed header is not the action's verb");
    if (!(d.header.index < h.first) || !(h.first + h.cells <= d.size - 2)) return bad('the disclosed header does not fit the committed layout');
    if (!opens('header', d.header, d.size, commit)) return bad('the header leaf does not open the map commitment');
    if (!opens('cell', d.cell, d.size, commit)) return bad('the cell leaf does not open the map commitment');
    if (!opens('metrics', d.metrics, d.size, commit)) return bad('the metrics leaf does not open the map commitment');
    const w = mapCellOf(h, input.action.resource, input.params ?? {});
    if ('error' in w) return bad(w.error);
    const c = d.cell.leaf;
    if (d.cell.index !== h.first + w.flat || c.verb !== h.verb || c.cell.length !== w.cell.length || c.cell.some((x, i) => x !== w.cell[i])) {
      return bad("the disclosed cell is not the action's cell");
    }
    if (c.in_grant !== true) return bad("the action's cell is outside the committed grant");
    if (d.metrics.index !== d.size - 2) return bad('the disclosed metrics leaf is not at its committed position');
    const eps = input.maxResidualRiskPpm;
    if (eps !== undefined && !(d.metrics.leaf.residual_risk_ppm <= eps)) {
      return bad(`the committed residual risk ${d.metrics.leaf.residual_risk_ppm} ppm exceeds ε = ${eps}`);
    }
    return { ok: true, cell: [...c.cell], p_ppm: c.p_ppm, residual_risk_ppm: d.metrics.leaf.residual_risk_ppm };
  } catch (e) {
    return { ok: false, reason: `map error (fail closed): ${(e as Error).message}` };
  }
}

// ---- builder ------------------------------------------------------------------------------------------------------

export interface CommittedMapInput {
  headers: Omit<MapHeaderLeaf, 'first' | 'cells'>[];
  /** Per verb: the cell leaves in flat order (row-major, last dimension fastest). */
  cells: Record<string, Omit<MapCellLeaf, 'verb'>[]>;
  metrics: MapMetricsLeaf;
  learner_digest: string;
}
export interface CommittedMap {
  map_commit: string;
  size: number;
  /** Z0 disclosure for an action (throws if the action lies outside the map). */
  disclose(action: { verb: string; resource?: string }, params: Record<string, unknown>): MapDisclosure;
  leaves: { kind: MapLeafKind; leaf: unknown; salt: string }[];
}

/**
 * Build the committed form (rule 19 leaf order) with per-leaf salts derived from `secret` (32 bytes) by mapLeafSalt.
 * Throws on a malformed input (the builder enforces the same shapes the verifier checks).
 */
export function commitMap(input: CommittedMapInput, secret: Uint8Array): CommittedMap {
  if (secret.length !== 32) throw new RangeError('commitMap: the secret is 32 bytes');
  const heads = [...input.headers].sort((a, b) => compareUtf8(a.verb, b.verb));
  for (let i = 1; i < heads.length; i++) if (heads[i]!.verb === heads[i - 1]!.verb) throw new Error('commitMap: duplicate verb');
  const counts = heads.map((h) => h.dims.reduce((n, d) => n * dimCells(d), 1));
  let next = heads.length;
  const full: MapHeaderLeaf[] = heads.map((h, i) => {
    const out = { verb: h.verb, first: next, cells: counts[i]!, dims: h.dims };
    next += counts[i]!;
    return out;
  });
  const leaves: { kind: MapLeafKind; leaf: unknown }[] = full.map((h) => ({ kind: 'header' as const, leaf: h }));
  for (const h of full) {
    const cs = input.cells[h.verb];
    if (!Array.isArray(cs) || cs.length !== h.cells) throw new Error(`commitMap: verb ${h.verb} needs ${h.cells} cell leaves`);
    for (const c of cs) leaves.push({ kind: 'cell', leaf: { verb: h.verb, cell: c.cell, p_ppm: c.p_ppm, in_grant: c.in_grant } });
  }
  leaves.push({ kind: 'metrics', leaf: input.metrics }, { kind: 'learner', leaf: { learner_digest: input.learner_digest } });
  for (const { kind, leaf } of leaves) {
    const e = kind === 'header' ? mapHeaderError(leaf) : kind === 'cell' ? mapCellError(leaf) : kind === 'metrics' ? mapMetricsError(leaf) : mapLearnerError(leaf);
    if (e) throw new Error(`commitMap: ${e}`);
  }
  if (leaves.length < 4 || leaves.length > MAX_MAP_LEAVES) throw new Error('commitMap: the map has too few or too many leaves');
  const salts = leaves.map((_, i) => mapLeafSalt(secret, i));
  const hashes = leaves.map((l, i) => mapLeafHash(l.kind, salts[i]!, l.leaf));
  const tree = mapTree(hashes);
  const size = leaves.length;
  const entry = <L>(i: number): MapDisclosedLeaf<L> => ({ index: i, salt: b64u(salts[i]!), leaf: JSON.parse(JSON.stringify(leaves[i]!.leaf)) as L, path: tree.path(i) });
  return {
    map_commit: mapCommitOf(size, tree.root),
    size,
    leaves: leaves.map((l, i) => ({ ...l, salt: b64u(salts[i]!) })),
    disclose(action, params) {
      const hi = full.findIndex((h) => h.verb === action.verb);
      if (hi < 0) throw new Error(`commitMap.disclose: verb ${action.verb} is not in the map`);
      const w = mapCellOf(full[hi]!, action.resource, params);
      if ('error' in w) throw new Error(`commitMap.disclose: ${w.error}`);
      return { size, header: entry(hi), cell: entry(full[hi]!.first + w.flat), metrics: entry(size - 2) };
    },
  };
}
