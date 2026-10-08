// Augments conformance/vectors.json with NON-LEAF post-quantum agility vectors: capability-chain hops
// signed under a hybrid (ed25519+ml-dsa-65) or a pure ml-dsa-65 suite. The base generator
// (gen-conformance.mjs) emits only the ed25519 CORE corpus; the leaf-suite PQ vectors (requires:"pq")
// and these non-leaf ones (requires:"pq-nonleaf") are APPENDED on top of it, so running this script after
// the base generator reproduces the full corpus. This script is IDEMPOTENT: it strips any previously
// appended `pq-nonleaf-*` vectors first, then re-appends the freshly generated ones.
//
// Each vector's stated intent is asserted against the TypeScript reference (verifyPCActnCore) before it is
// written, so a reference bug can never silently become a golden vector. Deterministic: fixed Ed25519 keys
// (seed = sha256(label), matching keys.json) and deterministic ML-DSA-65 keygen from a fixed 32-byte seed.
//
//   pnpm --filter @atlasauth/pca build && node packages/pca/scripts/gen-conformance-pq-nonleaf.mjs
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as pca from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, '..', 'conformance', 'vectors.json');

const NOW = 1_800_000_000_000;
const AUD = 'rs-conformance';
const CHECKS = ['version', 'audience', 'validity', 'chain', 'plan_inclusion', 'leaf_signature', 'counter'];
const KEYMAP = { chain: 'cap_chain' };
const HYBRID = 'hybrid-ed25519-ml-dsa-65';
const ML = 'ml-dsa-65';

const seed = (label) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${label}`).digest());
const edKey = (label) => {
  const secretKey = seed(label);
  return { secretKey, publicKey: pca.publicKeyOf(secretKey), pub: pca.b64u(pca.publicKeyOf(secretKey)) };
};
const mlKey = (label) => pca.mlDsa65Keygen(seed(`${label}-mldsa`));

const principal = edKey('principal');
const agent = edKey('agent');
const sub = edKey('subagent');
const agentMl = mlKey('agent'); // the agent is the ISSUER of hop 1, so its ML-DSA key signs the PQ hop

const caveatRoot = { type: 'max_spend', usd: 100 };
const caveatHop = { type: 'resource_prefix', prefix: 'db/' };
const planNodes = [
  { id: 'n1', verb: 'read', resource: 'db/users' },
  { id: 'n2', verb: 'read', resource: 'db/items' },
];

const root = pca.mintRoot({
  principalSecret: principal.secretKey,
  principalPublic: principal.pub,
  holder: agent.pub,
  caveats: [caveatRoot],
});

/** A 2-hop chain whose hop 1 (agent -> sub-agent) is signed under `suite`; leaf is ed25519 by the sub-agent. */
const buildWithHop = (suite) => {
  const hop = pca.delegate(root, sub.pub, [caveatHop], agent.secretKey, suite);
  const p = pca.buildPCActn({
    aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root, hop],
    plan: planNodes, nodeId: 'n1', counter: 1, signerSecret: sub.secretKey,
  });
  return { hop, p };
};

/** Re-sign the leaf (ed25519, sub-agent) over the current body, after mutating the chain. */
const resignLeaf = (p) => {
  const { sig: _s, ...body } = p;
  return pca.signPCActn(body, sub.secretKey);
};

/** Flip one data bit of a base64url byte field, keeping the decoded length (and thus canonicality) intact. */
const flipByte = (b64, idx = 0) => {
  const bytes = pca.unb64u(b64);
  bytes[idx] ^= 0x01;
  return pca.b64u(bytes);
};

const vectors = [];
async function add(name, description, pcactn, { falseChecks = [] } = {}) {
  const r = await pca.verifyPCActnCore(pcactn, { grant: root, nowEpoch: NOW, audience: AUD });
  const c = r.checks;
  const expectChecks = { wire: c.wire === 'pass' };
  if (c.wire === 'pass') for (const k of CHECKS) expectChecks[k] = c[KEYMAP[k] ?? k] === 'pass';
  const want = falseChecks.includes('wire')
    ? { wire: false }
    : { wire: true, ...Object.fromEntries(CHECKS.map((k) => [k, !falseChecks.includes(k)])) };
  if (JSON.stringify(expectChecks) !== JSON.stringify(want)) {
    throw new Error(`vector ${name}: reference ${JSON.stringify(expectChecks)} != intended ${JSON.stringify(want)} (${r.reason ?? ''})`);
  }
  const allow = falseChecks.length === 0;
  if (r.allow !== allow) throw new Error(`vector ${name}: allow ${r.allow} != intended ${allow}`);
  vectors.push({
    name, requires: 'pq-nonleaf', class: allow ? 'positive' : 'negative', description,
    grant: root, plan_nodes: planNodes, context: { now: NOW, aud: AUD },
    pcactn, expect: { allow, checks: expectChecks },
  });
}

// --- hybrid-signed hop ---
{
  const { p } = buildWithHop({ alg: HYBRID, mlDsa: agentMl });
  await add('pq-nonleaf-hybrid-hop-valid',
    'Capability chain whose delegation hop (agent -> sub-agent) is HYBRID ed25519+ml-dsa-65 signed; leaf is ed25519. Both hop signatures and the leaf verify: all checks pass.',
    p);
}
{
  const { p } = buildWithHop({ alg: HYBRID, mlDsa: agentMl });
  p.cap_chain[1].pq_sig = flipByte(p.cap_chain[1].pq_sig); // corrupt ONLY the ML-DSA half of the hybrid hop
  await add('pq-nonleaf-hybrid-hop-corrupt-mldsa',
    'Hybrid hop with a VALID ed25519 signature but a corrupted ML-DSA hop signature (leaf re-signed over the altered body): chain fails (a hybrid hop requires BOTH, so the ML-DSA half of a non-leaf hop is really checked).',
    resignLeaf(p), { falseChecks: ['chain'] });
}
{
  const { p } = buildWithHop({ alg: HYBRID, mlDsa: agentMl });
  // Downgrade attack: strip the suite fields so the hop looks like a plain ed25519 hop on the wire.
  delete p.cap_chain[1].alg;
  delete p.cap_chain[1].pq_pk;
  delete p.cap_chain[1].pq_sig;
  await add('pq-nonleaf-hybrid-hop-downgrade',
    'Hybrid hop stripped of alg/pq_pk/pq_sig to forge a downgrade to ed25519 (leaf re-signed): wire passes but chain fails — alg+pq_pk are bound into the signed hop body_digest, so dropping them no longer matches the stored digest.',
    resignLeaf(p), { falseChecks: ['chain'] });
}

// --- pure ml-dsa-65 hop ---
{
  const { p } = buildWithHop({ alg: ML, mlDsa: agentMl });
  await add('pq-nonleaf-mldsa65-hop-valid',
    'Capability chain whose delegation hop is PURE ml-dsa-65 signed (the 3309-byte hop sig is the ML-DSA signature under the issuer pq_pk); leaf is ed25519. All checks pass.',
    p);
}
{
  const { p } = buildWithHop({ alg: ML, mlDsa: agentMl });
  p.cap_chain[1].sig = flipByte(p.cap_chain[1].sig); // corrupt the ML-DSA hop signature
  await add('pq-nonleaf-mldsa65-hop-corrupt',
    'Pure ml-dsa-65 hop with a corrupted hop signature (leaf re-signed over the altered body): chain fails (the ML-DSA hop signature is verified under the issuer pq_pk, not skipped).',
    resignLeaf(p), { falseChecks: ['chain'] });
}

// ---- splice into vectors.json (idempotent: drop any prior pq-nonleaf-* first) --------------------------
const file = JSON.parse(readFileSync(vectorsPath, 'utf8'));
file.vectors = file.vectors.filter((v) => !(typeof v.name === 'string' && v.name.startsWith('pq-nonleaf-')));
file.vectors.push(...vectors);
writeFileSync(vectorsPath, JSON.stringify(file, null, 2) + '\n');
console.log(`appended ${vectors.length} pq-nonleaf vectors (${vectors.filter((v) => v.expect.allow).length} positive, ${vectors.filter((v) => !v.expect.allow).length} negative); corpus now ${file.vectors.length} vectors`);
