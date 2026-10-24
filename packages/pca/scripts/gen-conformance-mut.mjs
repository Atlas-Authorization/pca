// Final stage of the conformance pipeline (run AFTER gen-conformance-r6/-depth.mjs; idempotent): the `mut-*` vectors that native
// mutation testing showed the corpus never exercised (sdks/go-pca and sdks/python-pca mutants that survived the native
// suite AND the whole corpus). Each vector is ONE mutation of a valid PCActn; the TypeScript reference decides the full
// verdict, and the generator asserts the stated intent before writing:
//   must 'allow'   the reference allows
//   must 'wire'    the wire check fails
//   must [checks]  wire passes and every listed check fails (other checks are recorded as the reference reports them)
// Mutations of signed fields are re-signed by the leaf holder, so only the targeted rule can fail.
//
//     node packages/pca/scripts/gen-conformance-mut.mjs
import { createHash } from 'node:crypto';
import * as pca from '../dist/index.js';
import { cloneJson, readCore, writeCore } from './conformance-io.mjs';

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pk: pca.publicKeyOf(sk), pub: pca.b64u(pca.publicKeyOf(sk)) }; };
const principal = mk('principal'), agent = mk('agent'), sub = mk('subagent'), rogue = mk('rogue');
const clone = cloneJson; // JSON deep copy that keeps -0 (conformance-io.mjs)
const NOW = 1_800_000_000_000;
const AUD = 'rs-conformance';
const CHECKS = ['version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter'];
const KEYMAP = { chain: 'cap_chain' };

const caveatA = { type: 'max_spend', usd: 100 };
const caveatB = { type: 'note', text: 'b' };
const caveatC = { type: 'resource_prefix', prefix: 'db/' };
const root = pca.mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats: [caveatA, caveatB] });
const plan5 = [
  { id: 'n1', verb: 'read', resource: 'db/users' },
  { id: 'n2', verb: 'write', resource: 'db/orders', params_digest: pca.paramsDigest({ qty: 3 }), reversibility_class: 'reversible' },
  { id: 'n3', verb: 'delete', resource: 'db/orders', reversibility_class: 'irreversible' },
  { id: 'n4', verb: 'send', resource: 'mail/out' },
  { id: 'n5', verb: 'read', resource: 'db/items' },
];
const plan1 = [{ id: 'only', verb: 'read', resource: 'db/users' }];
const base = { aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root], plan: plan5, nodeId: 'n2', params: { qty: 3 }, counter: 7, signerSecret: agent.sk };
/** deep copy: buildPCActn shares the chain hop objects (mutating p.cap_chain[0] must not touch `root`). */
const build = (o = {}) => clone(pca.buildPCActn({ ...base, ...o }));
const resign = (p, sk = agent.sk) => { const { sig: _s, ...body } = p; return pca.signPCActn(body, sk); };
/** mutate a fresh valid PCActn, then re-sign it (a body with no canonical form keeps the stale sig: wire fails first). */
const mutated = (mut, o = {}, sk = o.signerSecret ?? agent.sk) => { const p = build(o); mut(p); try { return resign(p, sk); } catch { return p; } };

// reseal: a validly signed hop over an ARBITRARY body (any of issuer / holder / caveats / parent).
function reseal(body, signerSecret) {
  const b = { issuer: body.issuer, holder: body.holder, caveats: body.caveats, ...(body.parent !== undefined ? { parent: body.parent } : {}) };
  const body_digest = pca.hashCanonical(b);
  const msg = new Uint8Array([...new TextEncoder().encode('atlas-pca/cap/v1\0'), ...pca.unb64u(body_digest)]);
  return { id: body_digest, ...b, body_digest, sig: pca.b64u(pca.sign(signerSecret, msg)) };
}
const child = (parent, holderPub, caveats, sk) => reseal({ issuer: parent.holder, holder: holderPub, caveats, parent: pca.capHash(parent) }, sk);

const vectors = [];
async function add(name, description, pcactn, must, { grant = root, plan = plan5, now = NOW, aud = AUD, requires } = {}) {
  const r = await pca.verifyPCActnCore(pcactn, { grant, nowEpoch: now, audience: aud });
  const c = r.checks;
  const checks = {};
  if (c.wire === 'fail') checks.wire = false;
  else { checks.wire = true; for (const k of CHECKS) checks[k] = c[KEYMAP[k] ?? k] === 'pass'; }
  const ok = must === 'allow' ? r.allow === true
    : must === 'wire' ? checks.wire === false && r.allow === false
      : checks.wire === true && r.allow === false && must.every((k) => checks[k] === false);
  if (!ok) throw new Error(`vector mut-${name}: reference ${JSON.stringify(checks)} allow=${r.allow} does not meet intent ${JSON.stringify(must)} (${r.reason ?? ''})`);
  const allow = r.allow === true;
  if (allow !== Object.values(checks).every(Boolean)) throw new Error(`vector mut-${name}: allow ${allow} disagrees with checks`);
  vectors.push({ name: 'mut-' + name, ...(requires ? { requires } : {}), class: allow ? 'positive' : 'negative', description, grant, plan_nodes: plan, context: { now, aud }, pcactn, expect: { allow, checks } });
}
const W = (name, desc, mut) => add(name, desc, mutated(mut), 'wire');

// ---- 1-4. typed attestation / provenance / freshness / risk_claim fields
for (const f of ['quote_digest', 'model_id', 'measurement', 'operator']) await W(`attestation-${f}-number`, `attestation.${f} is a number: wire fails.`, (p) => { p.attestation[f] = 7; });
await W('provenance-causal_hash-number', 'provenance.causal_hash is a number: wire fails.', (p) => { p.provenance.causal_hash = 7; });
await W('provenance-taint_level-string', 'provenance.taint_level is a string: wire fails.', (p) => { p.provenance.taint_level = '0'; });
await W('provenance-trusted_refs-object', 'provenance.trusted_refs is an object: wire fails.', (p) => { p.provenance.trusted_refs = {}; });
await W('provenance-trusted_refs-mixed', 'provenance.trusted_refs is ["a", 1] (one non-string element): wire fails.', (p) => { p.provenance.trusted_refs = ['a', 1]; });
await W('freshness-beacon_ref-number', 'freshness.beacon_ref is a number: wire fails.', (p) => { p.freshness.beacon_ref = 7; });
await W('freshness-accumulator_witness-number', 'freshness.accumulator_witness is a number: wire fails.', (p) => { p.freshness.accumulator_witness = 7; });
await W('freshness-epoch-string', 'freshness.epoch is a string: wire fails.', (p) => { p.freshness.epoch = '1'; });
await W('risk_claim-string', 'risk_claim is a string: wire fails.', (p) => { p.risk_claim = 'x'; });
await W('risk_claim-r-string', 'risk_claim.r is a string: wire fails.', (p) => { p.risk_claim.r = '0.5'; });
await W('risk_claim-inputs-array', 'risk_claim.inputs is an array: wire fails.', (p) => { p.risk_claim.inputs = []; });
// ---- 5. caution boundaries
await add('caution-0', 'caution = 0 (inclusive lower bound, re-signed): verifies.', build({ caution: 0 }), 'allow');
await add('caution-1', 'caution = 1 (inclusive upper bound, re-signed): verifies.', build({ caution: 1 }), 'allow');
await W('caution-below-0', 'caution = -0.000001: wire fails.', (p) => { p.caution = -0.000001; });
await W('caution-above-1', 'caution = 1.000001: wire fails.', (p) => { p.caution = 1.000001; });
await W('caution-string', 'caution = "0.5" (a string): wire fails.', (p) => { p.caution = '0.5'; });
// ---- 6. prohibition_evidence
await W('prohibition_evidence-string', 'prohibition_evidence = "x": wire fails (object or array only).', (p) => { p.prohibition_evidence = 'x'; });
await W('prohibition_evidence-null', 'prohibition_evidence = null: wire fails.', (p) => { p.prohibition_evidence = null; });
await add('prohibition_evidence-empty-object', 'prohibition_evidence = {} (re-signed): verifies.', build({ prohibitionEvidence: {} }), 'allow');
await add('prohibition_evidence-empty-array', 'prohibition_evidence = [] (re-signed): verifies.', build({ prohibitionEvidence: [] }), 'allow');
// ---- 7. threshold container (unsigned)
const ALPH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
/** set an unused low bit of the last base64url char of a 32-byte value: same bytes in a lax decoder, non-canonical. */
const altTail = (s) => s.slice(0, -1) + ALPH[ALPH.indexOf(s.at(-1)) ^ 1];
const okShare = { role: 'guardian', publicKey: rogue.pub, sig: pca.b64u(new Uint8Array(64).fill(1)) };
const th = (t) => ({ ...build(), threshold: t });
await add('threshold-string', 'threshold = "x": wire fails.', th('x'), 'wire');
await add('threshold-empty-object', 'threshold = {} (no shares array): wire fails.', th({}), 'wire');
await add('threshold-shares-object', 'threshold = {shares:{}}: wire fails.', th({ shares: {} }), 'wire');
await add('threshold-share-string', 'threshold.shares = ["x"]: wire fails.', th({ shares: ['x'] }), 'wire');
await add('threshold-share-role-number', 'threshold share role is a number: wire fails.', th({ shares: [{ ...okShare, role: 1 }] }), 'wire');
await add('threshold-share-publicKey-noncanonical', 'threshold share publicKey has non-canonical trailing bits: wire fails.', th({ shares: [{ ...okShare, publicKey: altTail(okShare.publicKey) }] }), 'wire');
await add('threshold-share-sig-noncanonical', 'threshold share sig is 63 bytes: wire fails.', th({ shares: [{ ...okShare, sig: pca.b64u(new Uint8Array(63).fill(1)) }] }), 'wire');
await add('threshold-share-publicKey-16-bytes', 'threshold share publicKey is canonical base64url of 16 bytes (sig 64 bytes): wire fails (the threshold container is unsigned, so only this check refuses it).', th({ shares: [{ ...okShare, publicKey: pca.b64u(new Uint8Array(16).fill(7)) }] }), 'wire');
await add('threshold-shares-empty', 'threshold = {shares:[]} (unsigned container, empty): verifies.', th({ shares: [] }), 'allow');
// ---- 8. progress_step / rationale_commitment / tool_binding
await W('progress_step-string', 'progress_step = "x": wire fails (object only).', (p) => { p.progress_step = 'x'; });
await W('rationale_commitment-noncanonical', 'rationale_commitment is 31 bytes: wire fails.', (p) => { p.rationale_commitment = pca.b64u(new Uint8Array(31)); });
await W('tool_binding-noncanonical', 'tool_binding is 31 bytes: wire fails.', (p) => { p.tool_binding = pca.b64u(new Uint8Array(31)); });
// ---- 9. aud / nonce length caps (UTF-8 bytes)
await add('aud-256', 'aud of exactly 256 bytes (the cap) equal to the verifier audience: verifies.', build({ aud: 'a'.repeat(256) }), 'allow', { aud: 'a'.repeat(256) });
await add('aud-257', 'aud of 257 bytes: wire fails.', build({ aud: 'a'.repeat(257) }), 'wire', { aud: 'a'.repeat(257) });
await add('nonce-128', 'nonce of exactly 128 bytes (the cap, re-signed): verifies.', build({ nonce: 'n'.repeat(128) }), 'allow');
await W('nonce-129', 'nonce of 129 bytes: wire fails.', (p) => { p.nonce = 'n'.repeat(129); });
await W('nonce-empty', 'nonce = "": wire fails.', (p) => { p.nonce = ''; });
// ---- 10. closed field sets and string types
for (const f of ['verb', 'resource', 'reversibility_class']) await W(`action-${f}-number`, `action.${f} is a number: wire fails.`, (p) => { p.action[f] = 7; });
await W('action-unknown-field', 'action carries an unknown field: wire fails.', (p) => { p.action.extra = 'x'; });
await W('plan-unknown-field', 'plan carries an unknown field: wire fails.', (p) => { p.plan.extra = 'x'; });
await W('inclusion_proof-unknown-field', 'plan.inclusion_proof carries an unknown field: wire fails.', (p) => { p.plan.inclusion_proof.extra = 'x'; });
await W('proof-step-side-lowercase', 'proof step side "l": wire fails (exactly "L" or "R").', (p) => { p.plan.inclusion_proof.path[0].side = 'l'; });
await W('proof-step-side-X', 'proof step side "X": wire fails.', (p) => { p.plan.inclusion_proof.path[0].side = 'X'; });
await W('proof-step-side-missing', 'proof step without a side: wire fails.', (p) => { delete p.plan.inclusion_proof.path[0].side; });
await W('cap_chain-hop-unknown-field', 'a cap_chain hop carries an unknown field: wire fails.', (p) => { p.cap_chain[0].extra = 'x'; });
await W('cap_chain-caveat-type-number', 'a capability caveat whose type is a number: wire fails.', (p) => { p.cap_chain[0].caveats = [{ type: 5 }]; });
await W('cap_chain-caveat-no-type', 'a capability caveat without a type: wire fails.', (p) => { p.cap_chain[0].caveats = [{ usd: 5 }]; });
// ---- 11. single-leaf Merkle proofs: the index/size bounds are the ONLY thing that can reject (the path is empty)
const one = (o = {}) => build({ plan: plan1, nodeId: 'only', params: undefined, ...o });
const oneMut = (mut) => { const p = one(); mut(p); return resign(p); };
await add('merkle-1leaf-valid', 'Single-leaf plan (size 1, index 0, empty path): verifies.', one(), 'allow', { plan: plan1 });
await add('merkle-1leaf-index-eq-size', 'Single-leaf plan with index 1 == size (re-signed; the empty path still hashes to the root): plan_inclusion fails.', oneMut((p) => { p.plan.inclusion_proof.index = 1; }), ['plan_inclusion'], { plan: plan1 });
await add('merkle-1leaf-index-negative', 'Single-leaf plan with index -1 (re-signed): plan_inclusion fails.', oneMut((p) => { p.plan.inclusion_proof.index = -1; }), ['plan_inclusion'], { plan: plan1 });
await add('merkle-1leaf-size-zero', 'Single-leaf plan with size 0 (re-signed): plan_inclusion fails.', oneMut((p) => { p.plan.inclusion_proof.size = 0; }), ['plan_inclusion'], { plan: plan1 });
await add('merkle-1leaf-index-string', 'Single-leaf plan with index "0" (a string; must not default to 0): wire fails.', oneMut((p) => { p.plan.inclusion_proof.index = '0'; }), 'wire', { plan: plan1 });
// ---- 12. path length vs. index/size
await add('merkle-path-one-step-too-long', 'Proof path with one extra (well-formed) step for the claimed index/size (re-signed): plan_inclusion fails.', mutated((p) => { p.plan.inclusion_proof.path.push({ side: 'R', hash: p.plan.inclusion_proof.path[0].hash }); }), ['plan_inclusion']);
await add('merkle-path-one-step-too-short', 'Proof path missing its last step for the claimed index/size (re-signed): plan_inclusion fails.', mutated((p) => { p.plan.inclusion_proof.path.pop(); }), ['plan_inclusion']);
// ---- 13. capability-chain rejection reasons, one per vector
const leafOver = (grant, chain, sk, o = {}) => build({ grant, chain, nodeId: 'n1', params: undefined, counter: 2, signerSecret: sk, ...o });
{
  const rootWithParent = reseal({ issuer: principal.pub, holder: agent.pub, caveats: [caveatA], parent: pca.capHash(root) }, principal.sk);
  await add('chain-root-has-parent', 'The root hop (== grant) carries a parent link (validly signed): chain fails.', leafOver(rootWithParent, [rootWithParent], agent.sk), ['chain'], { grant: rootWithParent });
  const rogueRoot = reseal({ issuer: rogue.pub, holder: agent.pub, caveats: [caveatA, caveatB] }, rogue.sk);
  await add('chain-root-issuer-not-grant-issuer', 'cap_chain[0] is issued by another principal than the grant (validly signed): chain fails.', leafOver(root, [rogueRoot], agent.sk), ['chain']);
  const badLink = reseal({ issuer: agent.pub, holder: sub.pub, caveats: [caveatA, caveatB, caveatC], parent: pca.capHash(rogueRoot) }, agent.sk);
  await add('chain-broken-parent-link', 'Hop 1 links to a different parent hash (validly signed by the parent holder): chain fails.', leafOver(root, [root, badLink], sub.sk), ['chain']);
  const wrongIssuer = reseal({ issuer: rogue.pub, holder: sub.pub, caveats: [caveatA, caveatB, caveatC], parent: pca.capHash(root) }, rogue.sk);
  await add('chain-issuer-not-parent-holder', 'Hop 1 is issued (and validly signed) by a key that is not the parent\'s holder: chain fails.', leafOver(root, [root, wrongIssuer], sub.sk), ['chain']);
  await add('chain-empty', 'cap_chain = [] (re-signed): chain fails.', mutated((p) => { p.cap_chain = []; }, { nodeId: 'n1', params: undefined, counter: 2 }), ['chain']);
  for (const f of ['id', 'issuer', 'holder', 'body_digest', 'sig']) {
    await W(`chain-hop-${f}-number`, `cap_chain[0].${f} is a number: wire fails.`, (p) => { p.cap_chain[0][f] = 7; });
  }
  const h1 = child(root, sub.pub, [caveatA, caveatB, caveatC], agent.sk);
  await add('chain-2hop-valid', 'Two-hop chain (reference for the monotonicity vectors below): verifies.', leafOver(root, [root, h1], sub.sk), 'allow');
  const altered1 = child(root, sub.pub, [caveatA, { type: 'note', text: 'B' }, caveatC], agent.sk);
  await add('chain-caveat-1-altered', 'Hop 1 alters the parent caveat at index 1 (not 0), validly signed: chain fails.', leafOver(root, [root, altered1], sub.sk), ['chain']);
  const sub2 = mk('hop2');
  const h2drop = child(h1, sub2.pub, [caveatA, caveatB], sub.sk);
  await add('chain-3hop-drops-appended-caveat', 'Hop 2 drops the caveat hop 1 appended (validly signed): chain fails.', leafOver(root, [root, h1, h2drop], sub2.sk), ['chain']);
  const h2swap = child(h1, sub2.pub, [caveatA, caveatC, caveatB], sub.sk);
  await add('chain-3hop-swaps-last-caveats', 'Hop 2 swaps the last two inherited caveats (validly signed): chain fails.', leafOver(root, [root, h1, h2swap], sub2.sk), ['chain']);
}
// ---- 14. counter
await add('counter-zero', 'counter = 0 (re-signed): verifies (the counter check is counter >= 0).', build({ counter: 0 }), 'allow');

// ---- 15. python-pca mutation survivors (verdict-level behaviour no vector pinned)
await W('holder_pq-short', 'cap_chain[0].holder_pq = "AAAA" (3 bytes, not 32): wire fails.', (p) => { p.cap_chain[0].holder_pq = 'AAAA'; });
await W('leaf-ml-dsa-65-pq_pk-1951', 'ml-dsa-65 leaf whose pq_pk decodes to 1951 bytes (sig 3309 bytes, otherwise well-formed): wire fails.', (p) => { p.alg = 'ml-dsa-65'; p.pq_pk = pca.b64u(new Uint8Array(1951)); p.sig = pca.b64u(new Uint8Array(3309)); });
await add('provenance-trusted_refs-string', 'provenance.trusted_refs = ["ref-1"] (re-signed): verifies.', mutated((p) => { p.provenance.trusted_refs = ['ref-1']; }), 'allow');
{
  const pml = pca.mlDsa65Keygen(seed('principal-mldsa65'));
  const pqRoot = pca.mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats: [caveatA], suite: { alg: 'ml-dsa-65', mlDsa: pml } });
  await add('pq-root-equals-grant', 'cap_chain[0] is a pure ml-dsa-65 root equal to the stored grant (no pins): the stored grant is the trusted root, verifies.', leafOver(pqRoot, [pqRoot], agent.sk), 'allow', { grant: pqRoot, requires: 'pq-nonleaf' });
}
// threshold_set additions (same schema as gen-conformance-r6.mjs; `valid` from the reference verifyThreshold)
const thMsg = new Uint8Array(createHash('sha256').update('atlas-pca-conformance/mut/thmsg').digest());
const guardian = mk('guardian');
const tset = [];
function addSet(name, description, role, ss, share, intended) {
  const v = pca.verifyThreshold({ shares: [share] }, thMsg, ss, 1);
  const valid = !!(share.role === role && v.roles.includes(role));
  if (valid !== intended) throw new Error(`threshold_set mut-${name}: reference valid=${valid} (${v.reason}) != intended ${intended}`);
  tset.push({ name: 'mut-' + name, description, role, t: 1, valid, signer_set: ss, threshold_message: pca.b64u(thMsg), share });
}
{
  const E = [{ role: 'agent', publicKey: agent.pub }, { role: 'guardian', publicKey: guardian.pub }, { role: 'principal', publicKey: principal.pub }];
  const sh = pca.signShare('agent', agent.sk, thMsg, { signerSet: E, t: 1 });
  addSet('share-explicit-alg-ed25519', 'A share carrying an explicit "alg":"ed25519" over the untagged share message counts (same as no alg).', 'agent', E, { ...sh, alg: 'ed25519' }, true);
  const D = [E[0], { ...E[0] }, E[1]];
  addSet('set-duplicate-identical-guardian-share', 'Identical duplicate agent entry; a GUARDIAN share still counts.', 'guardian', D, pca.signShare('guardian', guardian.sk, thMsg, { signerSet: D, t: 1 }), true);
}

// ------------------------------------------------------------------ splice (idempotent)
const names = new Set();
for (const v of vectors) { if (names.has(v.name)) throw new Error('duplicate ' + v.name); names.add(v.name); }
const file = readCore();
const clash = file.vectors.filter((v) => !v.name.startsWith('mut-') && names.has(v.name));
if (clash.length) throw new Error('name clash with existing vectors: ' + clash.map((v) => v.name).join(', '));
file.vectors = [...file.vectors.filter((v) => !v.name.startsWith('mut-')), ...vectors];
file.primitives.threshold_set = [...(file.primitives.threshold_set ?? []).filter((e) => !e.name.startsWith('mut-')), ...tset];
writeCore(file);
console.log(`mut vectors: ${vectors.length} (${vectors.filter((v) => v.expect.allow).length} positive); threshold_set +${tset.length}`);
for (const v of vectors) console.log((v.expect.allow ? 'ALLOW  ' : 'deny   ') + v.name + '  ' + JSON.stringify(v.expect.checks));
