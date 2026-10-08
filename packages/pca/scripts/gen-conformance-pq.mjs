// Augments conformance/vectors.json with the FULL post-quantum + v2.1 agent-leaf-binding coverage, on top
// of the ed25519 CORE corpus written by gen-conformance.mjs. This REPLACES the older
// gen-conformance-pq-nonleaf.mjs (which covered only 2 hop suites). It appends, idempotently:
//
//   (a) LEAF verification under ALL 10 registered suites  (requires: "pq")
//         - positive per suite; corrupt-primary-sig per suite; corrupt-pqsig + missing-pqsig per hybrid;
//         - the global negatives unknown-alg, stray-pq-pk (on ed25519) and stray-pq-sig (on a pure suite).
//   (b) NON-LEAF verification: a capability-chain delegation hop signed under each of the 9 non-ed25519
//       suites (requires: "pq-nonleaf") - positive + corrupt per suite, + a downgrade negative per hybrid.
//   (c) the v2.1 AGENT-LEAF share binding (primitives.threshold_share, role "agent"): the new
//       signerSetHash|t-bound agent share (positive) + the OLD bare-threshold-message agent share (negative,
//       rejected) + a cross-signer-set replay (negative).
//   (d) representative PQ ARTIFACT vectors (primitives.pq_artifact) for the STH, revocation, beacon,
//       bond-settlement, safety-certificate, judge-verdict and software-attestation surfaces - each signed
//       through the SAME pq.ts agility seam (signSuiteArtifact / verifyWithSuite) all those surfaces route
//       through - spanning all 10 suites, positive + a tamper negative each.
//
// Every vector / primitive's stated intent is ASSERTED against the TypeScript reference before it is
// written (verifyPCActnCore for PCActns; verifyThreshold / verifyWithSuite for the threshold + artifact
// primitives), so a reference bug can never silently become a golden vector. Deterministic: fixed Ed25519
// keys (seed = sha256("atlas-pca-conformance/<label>"), matching keys.json) and deterministic PQ keygen
// from fixed seeds. Run AFTER the base generator:
//
//   pnpm --filter @atlasauth/pca build \
//     && node packages/pca/scripts/gen-conformance.mjs \
//     && node packages/pca/scripts/gen-conformance-pq.mjs
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

// ---- deterministic key material ---------------------------------------------------------------
const seed = (label) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${label}`).digest());
/** n deterministic bytes for a label (sha256 chaining), for the longer PQ seeds (SLH-DSA 48 / 96). */
const seedBytes = (label, n) => {
  const out = new Uint8Array(n);
  let i = 0;
  let blk = createHash('sha256').update(`atlas-pca-conformance/${label}`).digest();
  while (i < n) {
    for (let j = 0; j < blk.length && i < n; j++, i++) out[i] = blk[j];
    blk = createHash('sha256').update(blk).digest();
  }
  return out;
};
const edKey = (label) => {
  const secretKey = seed(label);
  return { secretKey, publicKey: pca.publicKeyOf(secretKey), pub: pca.b64u(pca.publicKeyOf(secretKey)) };
};

const principal = edKey('principal');
const agent = edKey('agent');
const sub = edKey('subagent');
const guardian = edKey('guardian');

// The agent is the leaf holder (leaf PQ) AND the issuer of hop 1 (non-leaf PQ): one PQ key set per family.
const agentMl = pca.mlDsa65Keygen(seed('agent-mldsa65'));
const agentMl87 = pca.mlDsa87Keygen(seed('agent-mldsa87'));
const agentSlh = pca.slhDsa128fKeygen(seedBytes('agent-slh128f', 48));
const agentSlh256 = pca.slhDsa256sKeygen(seedBytes('agent-slh256s', 96));

/** suite -> { field, key } : which signer-key-material family + key pair the suite uses. */
const SUITE_KEYS = {
  'ml-dsa-65': { field: 'mlDsa', key: agentMl },
  'hybrid-ed25519-ml-dsa-65': { field: 'mlDsa', key: agentMl },
  'hybrid-nested-ed25519-ml-dsa-65': { field: 'mlDsa', key: agentMl },
  'slh-dsa-sha2-128f': { field: 'slhDsa', key: agentSlh },
  'hybrid-ed25519-slh-dsa-sha2-128f': { field: 'slhDsa', key: agentSlh },
  'ml-dsa-87': { field: 'mlDsa87', key: agentMl87 },
  'hybrid-ed25519-ml-dsa-87': { field: 'mlDsa87', key: agentMl87 },
  'slh-dsa-sha2-256s': { field: 'slhDsa256s', key: agentSlh256 },
  'hybrid-ed25519-slh-dsa-sha2-256s': { field: 'slhDsa256s', key: agentSlh256 },
};
const ALL_PQ_SUITES = Object.keys(SUITE_KEYS);
const isHybrid = (alg) => pca.SIG_SUITES[alg].needsPqSig; // hybrids carry a separate pq_sig

const caveatRoot = { type: 'max_spend', usd: 100 };
const caveatHop = { type: 'resource_prefix', prefix: 'db/' };
const planNodes = [
  { id: 'n1', verb: 'read', resource: 'db/users' },
  { id: 'n2', verb: 'read', resource: 'db/items' },
];
const root = pca.mintRoot({ principalSecret: principal.secretKey, principalPublic: principal.pub, holder: agent.pub, caveats: [caveatRoot] });

/** Flip one data bit of a base64url byte field, keeping the decoded length (and thus canonicality) intact. */
const flipByte = (b64, idx = 0) => {
  const bytes = pca.unb64u(b64);
  bytes[idx] ^= 0x01;
  return pca.b64u(bytes);
};

// ---- vector assembly (asserts every vector against verifyPCActnCore before keeping it) ---------
const vectors = [];
async function add(name, requires, description, pcactn, { falseChecks = [] } = {}) {
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
    name, requires, class: allow ? 'positive' : 'negative', description,
    grant: root, plan_nodes: planNodes, context: { now: NOW, aud: AUD }, pcactn,
    expect: { allow, checks: expectChecks },
  });
}

// ======================= (a) LEAF verification under ALL 10 suites =======================
/** A leaf PCActn at n1 whose leaf is signed under `alg` (agent holder). ed25519 base body, re-signed by the suite. */
const buildLeaf = (alg) => {
  const { field, key } = SUITE_KEYS[alg];
  const base = pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root], plan: planNodes, nodeId: 'n1', counter: 1, signerSecret: agent.secretKey });
  const { sig: _drop, ...body } = base;
  return pca.signPCActnSuite(body, { alg, edLeafSecret: agent.secretKey, [field]: key });
};

for (const alg of ALL_PQ_SUITES) {
  const kind = isHybrid(alg) ? 'hybrid (classical + PQ)' : 'pure PQ';
  await add(`pq-leaf-${alg}-valid`, 'pq', `Leaf signed under the ${alg} suite (${kind}): the ${isHybrid(alg) ? 'Ed25519 + PQ' : 'PQ'} leaf signature verifies; all checks pass.`, buildLeaf(alg));
  { // corrupt the PRIMARY `sig` (Ed25519 half for hybrids; the PQ signature for a pure suite)
    const p = buildLeaf(alg); p.sig = flipByte(p.sig);
    await add(`pq-leaf-${alg}-corrupt-sig`, 'pq', `Leaf under ${alg} with a corrupted primary \`sig\` (length preserved so wire passes): leaf_signature fails.`, p, { falseChecks: ['leaf_signature'] });
  }
  if (isHybrid(alg)) {
    { const p = buildLeaf(alg); p.pq_sig = flipByte(p.pq_sig);
      await add(`pq-leaf-${alg}-corrupt-pqsig`, 'pq', `Hybrid leaf under ${alg} with a VALID Ed25519 \`sig\` but a corrupted \`pq_sig\`: a hybrid requires BOTH, so leaf_signature fails.`, p, { falseChecks: ['leaf_signature'] }); }
    { const p = buildLeaf(alg); delete p.pq_sig;
      await add(`pq-leaf-${alg}-missing-pqsig`, 'pq', `Hybrid leaf under ${alg} with \`pq_sig\` dropped: wire fails (the suite REQUIRES pq_sig).`, p, { falseChecks: ['wire'] }); }
  }
}
// global suite-shape negatives
{ const p = buildLeaf('ml-dsa-65'); p.alg = 'ml-dsa-999';
  await add('pq-leaf-unknown-alg', 'pq', 'Leaf declares an unregistered suite `ml-dsa-999`: wire fails (fail-closed on an unknown signature alg).', p, { falseChecks: ['wire'] }); }
{ const p = pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root], plan: planNodes, nodeId: 'n1', counter: 1, signerSecret: agent.secretKey });
  p.pq_pk = pca.b64u(agentMl.publicKey);
  await add('pq-leaf-ed25519-stray-pqpk', 'pq', 'An ed25519 leaf (no `alg`) that nonetheless carries a `pq_pk`: wire fails (pq_pk must be absent for ed25519).', p, { falseChecks: ['wire'] }); }
{ const p = buildLeaf('ml-dsa-65'); p.pq_sig = pca.b64u(new Uint8Array(pca.SIG_SUITES['ml-dsa-65'].sigBytes).fill(1));
  await add('pq-leaf-pure-mldsa65-stray-pqsig', 'pq', 'A pure ml-dsa-65 leaf that carries a stray `pq_sig` (only hybrids may): wire fails.', p, { falseChecks: ['wire'] }); }

// ======================= (b) NON-LEAF: a delegation hop under each non-ed25519 suite =======================
const buildHop = (alg) => {
  const { field, key } = SUITE_KEYS[alg];
  const hop = pca.delegate(root, sub.pub, [caveatHop], agent.secretKey, { alg, [field]: key });
  const p = pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root, hop], plan: planNodes, nodeId: 'n1', counter: 1, signerSecret: sub.secretKey });
  return { hop, p };
};
const resignLeaf = (p) => { const { sig: _s, ...body } = p; return pca.signPCActn(body, sub.secretKey); };

for (const alg of ALL_PQ_SUITES) {
  const kind = isHybrid(alg) ? 'hybrid' : 'pure PQ';
  { const { p } = buildHop(alg);
    await add(`pq-nonleaf-${alg}-hop-valid`, 'pq-nonleaf', `Capability chain whose delegation hop (agent -> sub-agent) is ${alg}-signed (${kind}); leaf is ed25519 by the sub-agent. Hop + leaf verify: all checks pass.`, p); }
  { const { p } = buildHop(alg); p.cap_chain[1].sig = flipByte(p.cap_chain[1].sig);
    await add(`pq-nonleaf-${alg}-hop-corrupt`, 'pq-nonleaf', `${alg} hop with a corrupted hop \`sig\` (leaf re-signed over the altered body): chain fails (the hop signature is really verified under the issuer pq_pk / holder key).`, resignLeaf(p), { falseChecks: ['chain'] }); }
  if (isHybrid(alg)) {
    const { p } = buildHop(alg);
    delete p.cap_chain[1].alg; delete p.cap_chain[1].pq_pk; delete p.cap_chain[1].pq_sig;
    await add(`pq-nonleaf-${alg}-hop-downgrade`, 'pq-nonleaf', `${alg} hop stripped of alg/pq_pk/pq_sig to forge a downgrade to ed25519 (leaf re-signed): chain fails — alg+pq_pk are bound into the signed hop body_digest, so dropping them no longer matches the stored digest.`, resignLeaf(p), { falseChecks: ['chain'] });
  }
}

// ======================= (c) v2.1 agent-leaf share binding (threshold_share primitives) =======================
const thresholdSignerSet = [
  { role: 'agent', publicKey: agent.pub },
  { role: 'guardian', publicKey: guardian.pub },
  { role: 'principal', publicKey: principal.pub },
];
const otherSignerSet = [
  { role: 'agent', publicKey: agent.pub },
  { role: 'guardian', publicKey: edKey('guardian-other').pub },
  { role: 'principal', publicKey: principal.pub },
];
const thMsg = pca.thresholdMessage(pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root], plan: planNodes, nodeId: 'n1', counter: 1, signerSecret: agent.secretKey }));

/** Verify ONE threshold share's signature over its role/set/t-bound share message, the way an SDK must. */
const shareVerifies = (role, share, signerSet, t) => {
  const sm = pca.shareMessage(role, thMsg, signerSet, t, share.alg);
  return pca.verifyWithSuite(share.alg, { edPub: share.publicKey, mlDsaPub: share.pq_pk }, sm, { sig: share.sig, pq_sig: share.pq_sig });
};

const thresholdShareAdds = [];
function addThresholdShare(name, role, signerSet, t, share, valid, description) {
  const got = shareVerifies(role, share, signerSet, t);
  if (got !== valid) throw new Error(`threshold_share ${name}: reference verifies=${got} != intended ${valid}`);
  thresholdShareAdds.push({
    name, role, t, valid, description,
    signer_set: signerSet,
    threshold_message: pca.b64u(thMsg),
    signer_set_hash: pca.b64u(pca.signerSetHash(signerSet)),
    share_message: pca.b64u(pca.shareMessage(role, thMsg, signerSet, t, share.alg)),
    share,
  });
}
// positive: the v2.1 bound agent share (ed25519) verifies over the agent share message
addThresholdShare('agent-bound-t1', 'agent', thresholdSignerSet, 1, pca.signShare('agent', agent.secretKey, thMsg, { signerSet: thresholdSignerSet, t: 1 }), true,
  'v2.1: the AGENT share now signs the signerSetHash|t-bound share message (role "agent"), exactly like guardian/principal; it verifies over share_message.');
addThresholdShare('agent-bound-t2', 'agent', thresholdSignerSet, 2, pca.signShare('agent', agent.secretKey, thMsg, { signerSet: thresholdSignerSet, t: 2 }), true,
  'v2.1 bound agent share at t=2: verifies over the t=2 share_message.');
// negative: the OLD bare-threshold-message agent share no longer verifies over the bound share message
addThresholdShare('agent-bare-rejected', 'agent', thresholdSignerSet, 1, { role: 'agent', publicKey: agent.pub, sig: pca.b64u(pca.sign(agent.secretKey, thMsg)) }, false,
  'The OLD pre-v2.1 agent share (sig over the bare threshold message) is REJECTED: it does not verify over the signerSetHash|t-bound agent share_message.');
// negative: a bound agent share for signer set A does not verify in signer set B (cross-set replay)
addThresholdShare('agent-bound-wrong-set', 'agent', otherSignerSet, 1, pca.signShare('agent', agent.secretKey, thMsg, { signerSet: thresholdSignerSet, t: 1 }), false,
  'An agent share bound to signer set A does not verify when checked against signer set B (the signerSetHash binding defeats cross-signer-set replay).');

// ======================= (d) representative PQ ARTIFACT vectors (the shared pq.ts seam) =======================
// Each surface (STH, revocation, beacon, bond-settlement, safety-cert, judge-verdict, software-attestation)
// signs through the SAME agility seam the leaf uses. A vector carries the canonical signing-input bytes and
// the suite fields; an SDK verifies the signature over those bytes with verifyWithSuite. Spans all 10 suites.
const artifactSeam = [
  ['sth', 'ed25519', { log: 'atlas-pca-sth', size: 42, root: pca.b64u(new Uint8Array(32).fill(3)) }],
  ['sth', 'hybrid-ed25519-ml-dsa-65', { log: 'atlas-pca-sth', size: 43, root: pca.b64u(new Uint8Array(32).fill(4)) }],
  ['sth', 'hybrid-nested-ed25519-ml-dsa-65', { log: 'atlas-pca-sth', size: 44, root: pca.b64u(new Uint8Array(32).fill(5)) }],
  ['revocation', 'ml-dsa-65', { epoch: 7, revoked_root: pca.b64u(new Uint8Array(32).fill(6)) }],
  ['beacon', 'hybrid-ed25519-slh-dsa-sha2-128f', { epoch: 1000, accumulator: pca.b64u(new Uint8Array(32).fill(7)) }],
  ['bond-settlement', 'slh-dsa-sha2-128f', { bond: 'bond-1', outcome: 'honored', amount: 100 }],
  ['safety-certificate', 'ml-dsa-87', { subject: 'agent-x', class: 'R0', issued: NOW }],
  ['judge-verdict', 'hybrid-ed25519-ml-dsa-87', { action: 'send-mail', verdict: 'allow', rationale_digest: pca.b64u(new Uint8Array(32).fill(8)) }],
  ['software-attestation', 'slh-dsa-sha2-256s', { measurement: pca.b64u(new Uint8Array(32).fill(9)), model: 'm-1' }],
  ['software-attestation', 'hybrid-ed25519-slh-dsa-sha2-256s', { measurement: pca.b64u(new Uint8Array(32).fill(10)), model: 'm-2' }],
];

/** Canonical signing input for an artifact: sha256( domain || canonicalize(body) ). Reproducible by SDKs. */
const artifactMessage = (artifact, body) => pca.sha256(pca.utf8(`atlas-pca/${artifact}/v1\0` + pca.canonicalize(body)));
/** Secret-key bundle + the pq_pk the suite publishes, for signing an artifact under `alg`. */
const artifactSign = (alg, msg) => {
  const sk = { edSecret: agent.secretKey };
  const pub = {};
  const sfx = pca.SIG_SUITES[alg];
  if (sfx.hasMlDsa) { sk.mlDsa = agentMl; pub.pq_pk = pca.b64u(agentMl.publicKey); }
  else if (sfx.hasSlhDsa) { sk.slhDsa = agentSlh; pub.pq_pk = pca.b64u(agentSlh.publicKey); }
  else if (sfx.hasMlDsa87) { sk.mlDsa87 = agentMl87; pub.pq_pk = pca.b64u(agentMl87.publicKey); }
  else if (sfx.hasSlhDsa256s) { sk.slhDsa256s = agentSlh256; pub.pq_pk = pca.b64u(agentSlh256.publicKey); }
  const fields = pca.signSuiteArtifact(alg, sk, msg);
  return { fields, pub };
};
/** Verify an artifact signature over `msg` the way an SDK must (pq_pk feeds every PQ slot; one suite is live). */
const artifactVerify = (alg, edPub, pqPk, msg, sig, pqSig) =>
  pca.verifyWithSuite(alg, { edPub, mlDsaPub: pqPk, slhDsaPub: pqPk, mlDsa87Pub: pqPk, slhDsa256sPub: pqPk }, msg, { sig, pq_sig: pqSig });

const pqArtifactAdds = [];
function addArtifact(artifact, alg, body) {
  const msg = artifactMessage(artifact, body);
  const { fields, pub } = artifactSign(alg, msg);
  const okPos = artifactVerify(alg, agent.pub, pub.pq_pk, msg, fields.sig, fields.pq_sig);
  if (!okPos) throw new Error(`pq_artifact ${artifact}/${alg}: reference REJECTED a valid signature`);
  const base = { artifact, alg, ed_pub: agent.pub, body, message: pca.b64u(msg), sig: fields.sig };
  if (pub.pq_pk !== undefined) base.pq_pk = pub.pq_pk;
  if (fields.pq_sig !== undefined) base.pq_sig = fields.pq_sig;
  pqArtifactAdds.push({ ...base, valid: true, description: `${artifact} artifact signed under ${alg} via the shared pq.ts agility seam; verifies over message.` });
  // tamper negative: flip the primary signature
  const badSig = flipByte(fields.sig);
  const okNeg = artifactVerify(alg, agent.pub, pub.pq_pk, msg, badSig, fields.pq_sig);
  if (okNeg) throw new Error(`pq_artifact ${artifact}/${alg}: reference ACCEPTED a tampered signature`);
  const neg = { artifact, alg, ed_pub: agent.pub, body, message: pca.b64u(msg), sig: badSig };
  if (pub.pq_pk !== undefined) neg.pq_pk = pub.pq_pk;
  if (fields.pq_sig !== undefined) neg.pq_sig = fields.pq_sig;
  pqArtifactAdds.push({ ...neg, valid: false, description: `${artifact} artifact under ${alg} with a corrupted \`sig\`: rejected (the seam verifies this surface too).` });
}
for (const [artifact, alg, body] of artifactSeam) addArtifact(artifact, alg, body);

// ---- splice into vectors.json (idempotent) -----------------------------------------------------
const file = JSON.parse(readFileSync(vectorsPath, 'utf8'));
// drop any previously appended PQ vectors (both the old `pq-nonleaf-*` names and the new `pq-leaf-*`/`pq-*`).
file.vectors = file.vectors.filter((v) => !(typeof v.name === 'string' && (v.name.startsWith('pq-leaf-') || v.name.startsWith('pq-nonleaf-') || v.name.startsWith('pq-hybrid') || v.name.startsWith('pq-mldsa') || v.name === 'pq-unknown-alg' || v.name === 'pq-ed25519-stray-pqpk')));
file.vectors.push(...vectors);

// threshold_share: keep the base (guardian/principal) entries, drop any prior agent entries, append new ones.
file.primitives.threshold_share = (file.primitives.threshold_share ?? []).filter((e) => e.role !== 'agent');
file.primitives.threshold_share.push(...thresholdShareAdds);
file.primitives.pq_artifact = pqArtifactAdds;
file.agent_leaf_binding = pca.AGENT_LEAF_SHARE_BINDING_VERSION; // "2.1" wire/version marker (GAP 2)

writeFileSync(vectorsPath, JSON.stringify(file, null, 2) + '\n');
const pos = vectors.filter((v) => v.expect.allow).length;
console.log(
  `appended ${vectors.length} PQ vectors (${pos} positive, ${vectors.length - pos} negative) ` +
    `[${vectors.filter((v) => v.requires === 'pq').length} leaf, ${vectors.filter((v) => v.requires === 'pq-nonleaf').length} non-leaf]; ` +
    `+${thresholdShareAdds.length} agent threshold_share, +${pqArtifactAdds.length} pq_artifact primitives; corpus now ${file.vectors.length} vectors`,
);
