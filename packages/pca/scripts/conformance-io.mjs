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

const arr = (a, ind) => '[\n' + a.map((x) => ind + '  ' + JSON.stringify(x)).join(',\n') + '\n' + ind + ']';
/** Serialise a corpus object: top-level keys on their own line; every array element (vector / primitive) on one line. */
export function serializeCorpus(file) {
  const parts = Object.entries(file).map(([k, v]) => {
    let s;
    if (Array.isArray(v) && v.length && typeof v[0] === 'object') s = arr(v, '  ');
    else if (v && typeof v === 'object' && !Array.isArray(v) && Object.values(v).some((x) => Array.isArray(x) && x.length && typeof x[0] === 'object')) {
      s = '{\n' + Object.entries(v).map(([k2, v2]) => '    ' + JSON.stringify(k2) + ': ' + (Array.isArray(v2) && v2.length && typeof v2[0] === 'object' ? arr(v2, '    ') : JSON.stringify(v2))).join(',\n') + '\n  }';
    } else s = JSON.stringify(v);
    return '  ' + JSON.stringify(k) + ': ' + s;
  });
  return '{\n' + parts.join(',\n') + '\n}\n';
}
export const writeCore = (file) => writeFileSync(CORE_PATH, serializeCorpus(file));
export const readCore = () => JSON.parse(readFileSync(CORE_PATH, 'utf8'));
/** Deterministic gzip (level 9, no mtime/name in the header) so regeneration is byte-identical. */
export function writeAdversarial(file, { plain = false } = {}) {
  const text = serializeCorpus(file);
  if (plain) { writeFileSync(ADV_PLAIN_PATH, text); return ADV_PLAIN_PATH; }
  writeFileSync(ADV_GZ_PATH, gzipSync(text, { level: 9 }));
  return ADV_GZ_PATH;
}
/** The full adversarial document (.json.gz preferred, plain .json accepted); null if neither exists. */
export function readAdversarial() {
  if (existsSync(ADV_GZ_PATH)) return JSON.parse(gunzipSync(readFileSync(ADV_GZ_PATH)).toString('utf8'));
  if (existsSync(ADV_PLAIN_PATH)) return JSON.parse(readFileSync(ADV_PLAIN_PATH, 'utf8'));
  return null;
}
