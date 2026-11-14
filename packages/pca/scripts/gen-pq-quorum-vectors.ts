// Generates testdata/pq-quorum-vectors.json: pq quorum blocks (v2 accepted; pre-0.5 v1 and malformed versions refused) over a fixed message
// and a fixed key pool. Run: tsx scripts/gen-pq-quorum-vectors.ts (ML-DSA signing may be hedged, so regenerating changes bytes; the test
// checks the committed file against the live verifier, it does not require byte equality).
import { writeFileSync } from 'node:fs';
import { b64u } from '../src/hash';
import { mlDsa65Keygen, mlDsa65Sign } from '../src/pq';
import { normalizePqQuorumPool, pqQuorumRepresentative, signPqQuorum, verifyPqQuorum } from '../src/frost-pq';

const message = new TextEncoder().encode('pca pq-quorum vector message');
const keys = [1, 2, 3].map((i) => mlDsa65Keygen(new Uint8Array(32).fill(i)));
const pool = normalizePqQuorumPool(keys.slice(0, 2).map((k) => k.publicKey));
const v2 = signPqQuorum(message, keys.slice(0, 2));
const bare = keys.slice(0, 2).map((k) => ({ pk: b64u(k.publicKey), sig: b64u(mlDsa65Sign(k.secretKey, message)) }));
const withoutV = { ...v2 } as Record<string, unknown>;
delete withoutV.v;
const cases: { name: string; block: unknown; pqT: number }[] = [
  { name: 'v2 two-of-two accepted', block: v2, pqT: 2 },
  { name: 'v2 below the threshold', block: signPqQuorum(message, keys.slice(0, 1), 2), pqT: 2 },
  { name: 'v2 duplicate signer counts once', block: signPqQuorum(message, [keys[0]!, keys[0]!], 2), pqT: 2 },
  { name: 'v2 signer outside the pinned pool', block: signPqQuorum(message, [keys[0]!, keys[2]!], 2), pqT: 2 },
  { name: 'v1 block (no version, bare-message co-signatures)', block: { alg: v2.alg, pqT: 2, signers: bare }, pqT: 2 },
  { name: 'v1 block labelled v:1', block: { v: 1, alg: v2.alg, pqT: 2, signers: bare }, pqT: 2 },
  { name: 'v1 co-signatures relabelled v:2', block: { ...v2, signers: bare }, pqT: 2 },
  { name: 'version missing', block: withoutV, pqT: 2 },
  { name: 'unknown version 3', block: { ...v2, v: 3 }, pqT: 2 },
  { name: 'version as a string', block: { ...v2, v: '2' }, pqT: 2 },
];
const out = {
  about: 'pq quorum block vectors: v2 is the only accepted format; every case lists the exact verdict of the verifier at generation time',
  message: b64u(message),
  pool: keys.slice(0, 2).map((k) => b64u(k.publicKey)),
  representative: b64u(pqQuorumRepresentative(message)),
  cases: cases.map((c) => ({ ...c, expect: verifyPqQuorum(c.block, message, pool, c.pqT) })),
};
writeFileSync(new URL('../testdata/pq-quorum-vectors.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log(out.cases.map((c) => `${c.name}: ${JSON.stringify(c.expect)}`).join('\n'));
