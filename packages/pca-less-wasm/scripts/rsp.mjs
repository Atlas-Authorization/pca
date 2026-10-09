// Minimal parser for NIST PQCgenKAT .rsp files -> [{count, seed, msg, pk, sk, smlen, sm}] (hex strings).
import { readFileSync } from 'node:fs';
export function parseRsp(path) {
  const out = [];
  let cur = null;
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const m = /^(\w+) = ?(.*)$/.exec(line.trim());
    if (!m) continue;
    const [, k, v] = m;
    if (k === 'count') { cur = { count: Number(v) }; out.push(cur); }
    else if (cur) cur[k] = v.toLowerCase();
  }
  return out;
}
