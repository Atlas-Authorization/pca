// Derive the compact committed KAT digest from the OFFICIAL upstream .rsp (20 MB, not committed).
// Usage: node make-kat-digest.mjs <PQCsignKAT_97484.rsp> <upstream_commit> > src/kat/less-252-45.digest.json
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseRsp } from './rsp.mjs';
const [rsp, commit] = process.argv.slice(2);
const sha = (hex) => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
const entries = parseRsp(rsp).map((e) => ({
  count: e.count, seed: e.seed, msg: e.msg, pkSha256: sha(e.pk), sk: e.sk,
  smlen: Number(e.smlen), smSha256: sha(e.sm),
}));
process.stdout.write(JSON.stringify({
  source: 'https://github.com/less-sig/LESS', upstreamCommit: commit,
  file: 'Utilities/KAT_Generation/KAT/PQCsignKAT_97484.rsp',
  rspSha256: createHash('sha256').update(readFileSync(rsp)).digest('hex'),
  params: 'CATEGORY=252 TARGET=45', entries,
}) + '\n');
