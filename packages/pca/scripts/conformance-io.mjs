// Shared read/write helpers for the PCA conformance corpus (used by gen-conformance*.mjs and the cross-language gate).
//
//   conformance/vectors.json              CURATED CORE: the golden vectors + a deterministic REPRESENTATIVE SAMPLE of the
//                                         adversarial families. This is what every per-language native suite and every
//                                         public mirror vendors.
//   conformance/vectors-adversarial.json.gz  the FULL adversarial set (same schema; `vectors` all adv-*, `primitives` the
//                                         adversarial json_parse / b64u / canonical entries). Vendored ONLY into the flagship
//                                         `pca` repo and consumed by the monorepo gate (scripts/pca-conformance-all.sh).
//                                         A plain `vectors-adversarial.json` is accepted wherever the .gz is (and written
//                                         by `gen-conformance-adv.mjs --plain`).
//
// Files are written one vector per line (valid JSON, ~25% smaller than 2-space indent, still diffable).
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync, gzipSync } from 'node:zlib';

export const confDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'conformance');
export const CORE_PATH = join(confDir, 'vectors.json');
export const ADV_GZ_PATH = join(confDir, 'vectors-adversarial.json.gz');
export const ADV_PLAIN_PATH = join(confDir, 'vectors-adversarial.json');

// ---- raw JSON text for values JSON.stringify would erase (README "Raw JSON text members") -------------------------
// JSON.stringify writes -0 as 0, NaN / Infinity as null, drops array holes / functions and flattens typed arrays, Dates,
// Maps. A vector whose MEANING depends on such a value would silently change on the way to the natives (the guest
// found `schema14-int-neg-zero`: `total: -0` arrived as `0`). Every corpus entry therefore passes `prepareEntry`:
//   - a primitive whose `input` holds a -0 gets `input_json`, the whole input as raw JSON text written by `rawJson`
//     (which keeps `-0`); a runner parses it with its own JSON parser and uses it INSTEAD of `input`;
//   - anything else JSON would erase (NaN, Infinity, holes, non-plain objects, bigint, functions) anywhere in an entry,
//     or a -0 outside `input`, is a generator bug and throws: such a vector must carry raw text explicitly (like
//     `pcactn_json` / `context.intent_policy_json`), which a generator writes as a string;
//   - the assertion: what the file will hold re-parses (JSON.parse, which keeps -0) to exactly what the expectation was
//     computed from (Object.is on every number).
// Integral floats (1.0), exponent forms (1e6), integers beyond 2^53 and duplicate keys cannot exist in a JS value at all,
// so a vector that needs one is ALWAYS written as raw text by its generator (the adversarial families, the M2 policy).

/** The first place JSON.stringify would change `v`, or null. Object members that are `undefined` are absent (dropped). */
export function jsonErasure(v, path = '$') {
  if (v === null || typeof v === 'string' || typeof v === 'boolean') return null;
  if (typeof v === 'number') return !Number.isFinite(v) ? `${path}: ${v} becomes null` : Object.is(v, -0) ? `${path}: -0 becomes 0` : null;
  if (typeof v !== 'object') return `${path}: a ${typeof v} is not JSON`;
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) {
      if (!(i in v) || v[i] === undefined) return `${path}[${i}]: a hole / undefined becomes null`;
      const e = jsonErasure(v[i], `${path}[${i}]`);
      if (e) return e;
    }
    return null;
  }
  const proto = Object.getPrototypeOf(v);
  if ((proto !== Object.prototype && proto !== null) || typeof v.toJSON === 'function') return `${path}: a non-plain object (${proto?.constructor?.name ?? '?'}) is not JSON`;
  for (const k of Object.keys(v)) {
    if (v[k] === undefined) continue;
    const e = jsonErasure(v[k], `${path}.${k}`);
    if (e) return e;
  }
  return null;
}

/** JSON text of a JSON value that keeps -0 as `-0` (everything else exactly as JSON.stringify). Throws on non-JSON. */
export function rawJson(v) {
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error(`rawJson: ${v} is not JSON`);
    return Object.is(v, -0) ? '-0' : JSON.stringify(v);
  }
  if (v === null || typeof v === 'string' || typeof v === 'boolean') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map((x) => rawJson(x)).join(',') + ']';
  if (typeof v === 'object') {
    const e = jsonErasure(v);
    if (e && !e.endsWith('-0 becomes 0')) throw new Error(`rawJson: ${e}`);
    return '{' + Object.keys(v).filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ':' + rawJson(v[k])).join(',') + '}';
  }
  throw new Error(`rawJson: a ${typeof v} is not JSON`);
}

/**
 * Deep copy for generators: exactly `JSON.parse(JSON.stringify(x))`, except that a -0 survives (it used to be erased
 * HERE, before the writer could see it). Every generator's `clone` is this.
 */
export function cloneJson(x) {
  if (x === undefined) return undefined;
  const er = jsonErasure(x);
  if (er && er.endsWith('-0 becomes 0')) {
    try {
      return JSON.parse(rawJson(x));
    } catch {
      /* another erasure too: plain JSON semantics below */
    }
  }
  return JSON.parse(JSON.stringify(x));
}

/** Deep equality with Object.is on numbers (so -0 != 0); `undefined` object members count as absent. */
function sameJson(a, b) {
  if (typeof a === 'number' || typeof b === 'number') return Object.is(a, b);
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return a === b;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => sameJson(x, b[i]));
  const ka = Object.keys(a).filter((k) => a[k] !== undefined).sort();
  const kb = Object.keys(b).filter((k) => b[k] !== undefined).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i] && sameJson(a[k], b[k]));
}

/** Make one corpus entry JSON-safe (see above) and assert the round trip. Returns the entry to write. */
export function prepareEntry(e) {
  if (e === null || typeof e !== 'object' || Array.isArray(e)) {
    const er = jsonErasure(e);
    if (er) throw new Error(`corpus entry: ${er}`);
    return e;
  }
  let out = e;
  let fresh = false;
  if (Object.prototype.hasOwnProperty.call(e, 'input') && !Object.prototype.hasOwnProperty.call(e, 'input_json') && jsonErasure(e.input, 'input')) {
    fresh = true;
    const text = rawJson(e.input); // throws on anything but -0
    out = {};
    for (const [k, v] of Object.entries(e)) {
      out[k] = v;
      if (k === 'input') out.input_json = text;
    }
  }
  const { input: inp, ...rest } = out;
  const er = jsonErasure(Object.prototype.hasOwnProperty.call(out, 'input_json') ? rest : out);
  if (er) throw new Error(`corpus entry ${JSON.stringify(e.name ?? '?')}: ${er}; carry it as raw JSON text (a *_json string member)`);
  if (Object.prototype.hasOwnProperty.call(out, 'input_json')) {
    // written now: the raw text must re-parse to the exact input; read back from the file (a later stage): `input` is
    // the lossy copy of it
    const parsed = typeof out.input_json === 'string' ? JSON.parse(out.input_json) : undefined;
    if (parsed === undefined || !sameJson(fresh ? parsed : JSON.parse(JSON.stringify(parsed)), inp)) throw new Error(`corpus entry ${JSON.stringify(e.name ?? '?')}: input_json does not re-parse to the input the expectation was computed from`);
  } else if (!sameJson(JSON.parse(JSON.stringify(out)), out)) throw new Error(`corpus entry ${JSON.stringify(e.name ?? '?')}: does not survive a JSON round trip`);
  return out;
}

const safeJson = (v, where) => {
  const er = jsonErasure(v, where);
  if (er) throw new Error(`corpus member: ${er}`);
  return JSON.stringify(v);
};
const arr = (a, ind) => '[\n' + a.map((x) => ind + '  ' + JSON.stringify(prepareEntry(x))).join(',\n') + '\n' + ind + ']';
/** Serialise a corpus object: top-level keys on their own line; every array element (vector / primitive) on one line. */
export function serializeCorpus(file) {
  const parts = Object.entries(file).map(([k, v]) => {
    let s;
    if (Array.isArray(v) && v.length && typeof v[0] === 'object') s = arr(v, '  ');
    else if (v && typeof v === 'object' && !Array.isArray(v) && Object.values(v).some((x) => Array.isArray(x) && x.length && typeof x[0] === 'object')) {
      s = '{\n' + Object.entries(v).map(([k2, v2]) => '    ' + JSON.stringify(k2) + ': ' + (Array.isArray(v2) && v2.length && typeof v2[0] === 'object' ? arr(v2, '    ') : safeJson(v2, k2))).join(',\n') + '\n  }';
    } else s = safeJson(v, k);
    return '  ' + JSON.stringify(k) + ': ' + s;
  });
  return '{\n' + parts.join(',\n') + '\n}\n';
}
export const writeCore = (file) => writeFileSync(CORE_PATH, serializeCorpus(file));
export const readCore = () => JSON.parse(readFileSync(CORE_PATH, 'utf8'));
/** The fixed 10-byte gzip member header every committed corpus carries (RFC 1952): magic, CM=deflate, FLG=0 (no name /
 *  comment / extra), MTIME=0, XFL=2 (max compression), OS=3 (Unix). zlib stamps OS from the BUILD platform (Linux 3, macOS
 *  19), so without this a macOS regeneration differs from a Linux one in byte 9 alone. */
export const GZ_HEADER = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03]);
/** Deterministic gzip: level 9 deflate under the fixed header above (the header is outside the CRC32/ISIZE trailer). */
export function gzipDeterministic(text) {
  const gz = gzipSync(text, { level: 9 });
  if (gz.length < 18 || gz[0] !== 0x1f || gz[1] !== 0x8b || gz[2] !== 0x08 || gz[3] !== 0x00) throw new Error('unexpected gzip header from zlib');
  GZ_HEADER.copy(gz, 0);
  return gz;
}
/** Strict comparison of a committed .gz against freshly serialised text: the header must be exactly GZ_HEADER (a single
 *  member, no FLG extras) and the decompressed bytes must equal `text`. The deflate stream itself is NOT compared, so a
 *  zlib build that picks different (equally valid) matches on another platform does not fail; the content still must
 *  be byte-identical. Returns null when it matches, else a reason. */
export function compareGz(gz, text) {
  if (gz.length < 18 || !gz.subarray(0, 10).equals(GZ_HEADER)) return `gzip header ${gz.subarray(0, 10).toString('hex')} != fixed ${GZ_HEADER.toString('hex')}`;
  const got = gunzipSync(gz);
  const want = Buffer.from(text, 'utf8');
  if (!got.equals(want)) {
    let i = 0;
    while (i < got.length && i < want.length && got[i] === want[i]) i++;
    return `decompressed content differs from a fresh generation at byte ${i} (committed ${got.length} B, fresh ${want.length} B)`;
  }
  return null;
}
/** Deterministic gzip (level 9, fixed header: no mtime/name, OS=Unix) so regeneration is byte-identical across platforms. */
export function writeAdversarial(file, { plain = false } = {}) {
  const text = serializeCorpus(file);
  if (plain) { writeFileSync(ADV_PLAIN_PATH, text); return ADV_PLAIN_PATH; }
  writeFileSync(ADV_GZ_PATH, gzipDeterministic(text));
  return ADV_GZ_PATH;
}
/** --check for the adversarial corpus: null if the committed .gz (or plain .json) matches `file`, else a reason. */
export function checkAdversarial(file) {
  const text = serializeCorpus(file);
  if (existsSync(ADV_GZ_PATH)) return compareGz(readFileSync(ADV_GZ_PATH), text);
  if (existsSync(ADV_PLAIN_PATH)) return readFileSync(ADV_PLAIN_PATH, 'utf8') === text ? null : `${ADV_PLAIN_PATH} differs from a fresh generation`;
  return 'no committed adversarial corpus';
}
/** The full adversarial document (.json.gz preferred, plain .json accepted); null if neither exists. */
export function readAdversarial() {
  if (existsSync(ADV_GZ_PATH)) return JSON.parse(gunzipSync(readFileSync(ADV_GZ_PATH)).toString('utf8'));
  if (existsSync(ADV_PLAIN_PATH)) return JSON.parse(readFileSync(ADV_PLAIN_PATH, 'utf8'));
  return null;
}
