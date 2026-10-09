// Generates golden conformance vectors from the BUILT @atlasauth/pca (dist). Deterministic:
// fixed keys (seed = sha256(label)); Ed25519 signatures are deterministic (RFC 8032).
// Usage: pnpm --filter @atlasauth/pca build && node packages/pca/scripts/gen-conformance.mjs
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as pca from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, '..', 'conformance');
mkdirSync(outDir, { recursive: true });

const seed = (label) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${label}`).digest());
const mk = (label) => {
  const secretKey = seed(label);
  return { label, secretKey, publicKey: pca.publicKeyOf(secretKey) };
};
const principal = mk('principal');
const agent = mk('agent');
const sub = mk('subagent');
const rogue = mk('rogue');
const keys = {};
for (const k of [principal, agent, sub, rogue]) {
  keys[k.label] = { seed: pca.b64u(k.secretKey), public: pca.b64u(k.publicKey) };
}

const clone = (x) => JSON.parse(JSON.stringify(x));
const caveatA = { type: 'max_spend', usd: 100 };
// Exercises UTF-16 key ordering (U+FF5E sorts AFTER U+1F600's surrogate pair) and non-ASCII strings.
const caveatB = { type: 'note', '～': 1, '\u{1F600}': 2, z: 3, text: 'café <&> "q" \\ \n ' };
const caveatC = { type: 'resource_prefix', prefix: 'db/' };

const root = pca.mintRoot({
  principalSecret: principal.secretKey,
  principalPublic: pca.b64u(principal.publicKey),
  holder: pca.b64u(agent.publicKey),
  caveats: [caveatA, caveatB],
});
const planNodes = [
  { id: 'n1', verb: 'read', resource: 'db/users' },
  { id: 'n2', verb: 'write', resource: 'db/orders', params_digest: pca.paramsDigest({ qty: 3, sku: 'A-1' }), reversibility_class: 'reversible' },
  { id: 'n3', verb: 'delete', resource: 'db/orders', reversibility_class: 'irreversible', pre: { exists: true }, post: { exists: false } },
  { id: 'n4', verb: 'send', resource: 'mail/out', params_digest: pca.paramsDigest({ to: 'a@b.c' }) },
  { id: 'n5', verb: 'read', resource: 'db/items' },
];

const build = (o) => pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root], plan: planNodes, nodeId: 'n2', params: { qty: 3, sku: 'A-1' }, counter: 7, signerSecret: agent.secretKey, ...o });
const resign = (p, secret) => {
  const { sig: _s, ...body } = p;
  return pca.signPCActn(body, secret);
};

const NOW = 1_800_000_000_000; // fixed verification time for every vector (epoch ms)
const AUD = 'rs-conformance';
const CHECKS = ['version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter'];
const KEYMAP = { chain: 'cap_chain' };

const vectors = [];
/**
 * `falseChecks`: the checks that MUST be false (everything else true; 'wire' => ONLY {wire:false}). The TS
 * reference result is asserted against this stated intent, so a reference bug cannot silently become a vector.
 * `pcactn` is an object, or `pcactnJson` a raw JSON string that is strict-parsed first.
 */
async function add(name, description, grant, plan, pcactn, { falseChecks = [], now = NOW, aud = AUD, cls, pcactnJson } = {}) {
  let wireErr = null;
  let obj = pcactn;
  if (pcactnJson !== undefined) {
    try { obj = pca.decodePCActn(pcactnJson); } catch (e) { wireErr = e.message; }
  }
  let r;
  if (wireErr) r = { allow: false, checks: { wire: 'fail' } };
  else r = await pca.verifyPCActnCore(obj, { grant, nowEpoch: now, audience: aud });
  const c = r.checks;
  const expectChecks = {};
  if (c.wire === 'fail') expectChecks.wire = false;
  else {
    expectChecks.wire = true;
    for (const k of CHECKS) expectChecks[k] = c[KEYMAP[k] ?? k] === 'pass';
  }
  // assert the stated intent
  const want = falseChecks.includes('wire') ? { wire: false } : { wire: true, ...Object.fromEntries(CHECKS.map((k) => [k, !falseChecks.includes(k)])) };
  if (JSON.stringify(expectChecks) !== JSON.stringify(want)) {
    throw new Error(`vector ${name}: reference result ${JSON.stringify(expectChecks)} != intended ${JSON.stringify(want)} (${r.reason ?? ''})`);
  }
  const allow = falseChecks.length === 0;
  if (r.allow !== allow) throw new Error(`vector ${name}: allow ${r.allow} != intended ${allow}`);
  const v = { name, class: cls ?? (allow ? 'positive' : 'negative'), description, grant, plan_nodes: plan, context: { now, aud } };
  if (pcactnJson !== undefined) v.pcactn_json = pcactnJson; else v.pcactn = pcactn;
  v.expect = { allow, checks: expectChecks };
  vectors.push(v);
}

await add('valid-in-plan-action', 'Valid action at plan node n2 with a 1-hop chain.', root, planNodes, build());
for (const id of ['n1', 'n3', 'n4', 'n5']) {
  const params = id === 'n4' ? { to: 'a@b.c' } : undefined;
  await add(`valid-plan-node-${id}`, `Valid action at plan node ${id} (exercises a different Merkle path in a 5-leaf tree).`, root, planNodes, build({ nodeId: id, params, counter: 1 }));
}
{ // out-of-plan: action not in the plan, but signed correctly by the holder
  const p = build();
  const body = clone(p); delete body.sig;
  body.action = { verb: 'drop', resource: 'db/everything', params_digest: pca.paramsDigest(), reversibility_class: 'irreversible' };
  await add('out-of-plan-action', 'Action not in the committed plan, correctly signed: plan_inclusion fails.', root, planNodes, pca.signPCActn(body, agent.secretKey), { falseChecks: ['plan_inclusion'] });
}
{
  const p = build(); p.action.params_digest = pca.paramsDigest({ qty: 999, sku: 'A-1' });
  await add('tampered-params', 'params_digest altered after signing: plan_inclusion and leaf_signature fail.', root, planNodes, p, { falseChecks: ['plan_inclusion', 'leaf_signature'] });
}
{
  const p = build(); p.action.params_digest = pca.paramsDigest({ qty: 999, sku: 'A-1' });
  await add('tampered-params-resigned', 'params_digest altered and re-signed by the right key: only plan_inclusion fails.', root, planNodes, resign(p, agent.secretKey), { falseChecks: ['plan_inclusion'] });
}
await add('wrong-key-leaf-signature', 'Signed by a key that is not the leaf holder: leaf_signature fails.', root, planNodes, build({ signerSecret: rogue.secretKey }), { falseChecks: ['leaf_signature'] });
{
  const p = build(); p.counter = 8;
  await add('tampered-counter-after-signing', 'counter modified after signing: leaf_signature fails.', root, planNodes, p, { falseChecks: ['leaf_signature'] });
}
{
  const p = build(); p.counter = -1;
  await add('invalid-counter', 'Negative counter (re-signed): counter check fails.', root, planNodes, resign(p, agent.secretKey), { falseChecks: ['counter'] });
}
{
  const p = build(); p.plan.inclusion_proof.path[0].hash = p.plan.inclusion_proof.path[1].hash;
  await add('tampered-merkle-proof', 'A sibling hash in the inclusion proof is replaced: plan_inclusion fails.', root, planNodes, p, { falseChecks: ['plan_inclusion', 'leaf_signature'] });
}
{
  const p = build(); p.plan.conditions_digest = pca.conditionsDigest({ x: 1 }, null);
  await add('tampered-conditions-digest', 'conditions_digest swapped for another: plan_inclusion fails.', root, planNodes, p, { falseChecks: ['plan_inclusion', 'leaf_signature'] });
}

// 2-hop delegated chain
const hop1 = pca.delegate(root, pca.b64u(sub.publicKey), [caveatC], agent.secretKey);
const chain2 = [root, hop1];
const build2 = (o) => pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: chain2, plan: planNodes, nodeId: 'n1', counter: 2, signerSecret: sub.secretKey, ...o });
await add('delegated-2-hop-chain', 'Two-hop chain (agent delegates to sub-agent, appending a caveat); leaf signed by the sub-agent.', root, planNodes, build2());
await add('delegated-leaf-signed-by-parent-holder', 'Chain is fine but the leaf was signed by the parent holder, not the sub-agent: leaf_signature fails.', root, planNodes, build2({ signerSecret: agent.secretKey }), { falseChecks: ['leaf_signature'] });
{ // validly signed hops whose caveats are NOT an append-only extension (only attenuation catches them)
  const bad = reseal(root, pca.b64u(sub.publicKey), [caveatA, caveatC], agent.secretKey);
  await add('chain-dropped-caveat', 'Child hop drops the parent caveat B (validly signed, parent-linked): chain fails.', root, planNodes, pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root, bad], plan: planNodes, nodeId: 'n1', counter: 2, signerSecret: sub.secretKey }), { falseChecks: ['chain'] });
  const reordered = reseal(root, pca.b64u(sub.publicKey), [caveatB, caveatA, caveatC], agent.secretKey);
  await add('chain-reordered-caveat', 'Child hop reorders the parent caveats (validly signed): chain fails.', root, planNodes, pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root, reordered], plan: planNodes, nodeId: 'n1', counter: 2, signerSecret: sub.secretKey }), { falseChecks: ['chain'] });
  const edited = reseal(root, pca.b64u(sub.publicKey), [{ type: 'max_spend', usd: 1000000 }, caveatB, caveatC], agent.secretKey);
  await add('chain-edited-caveat', 'Child hop widens a parent caveat (validly signed): chain fails.', root, planNodes, pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root, edited], plan: planNodes, nodeId: 'n1', counter: 2, signerSecret: sub.secretKey }), { falseChecks: ['chain'] });
}
{
  const forged = pca.delegate(root, pca.b64u(sub.publicKey), [caveatC], rogue.secretKey);
  await add('chain-hop-signed-by-wrong-key', 'Child hop signed by a key that is not the parent holder: chain fails.', root, planNodes, pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root, forged], plan: planNodes, nodeId: 'n1', counter: 2, signerSecret: sub.secretKey }), { falseChecks: ['chain'] });
}
{
  const p = build2(); p.cap_chain = [hop1, root];
  await add('chain-hops-reordered', 'The two hops are swapped: chain fails, and the first hop is no longer the root that grant_ref names (grant_ref_bound fails).', root, planNodes, p, { falseChecks: ['chain', 'grant_ref_bound', 'leaf_signature'] });
}
{
  const other = pca.mintRoot({ principalSecret: rogue.secretKey, principalPublic: pca.b64u(rogue.publicKey), holder: pca.b64u(agent.publicKey), caveats: [caveatA, caveatB] });
  await add('chain-root-not-grant', 'Chain root is a different principal\'s capability than the grant: chain fails.', root, planNodes, pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: other, chain: [other], plan: planNodes, nodeId: 'n1', counter: 1, signerSecret: agent.secretKey }), { falseChecks: ['chain'] });
}

// reseal: a validly signed child hop with arbitrary (not necessarily attenuating) caveats.
function reseal(parent, toHolder, caveats, signerSecret) {
  const body = { issuer: parent.holder, holder: toHolder, caveats, parent: pca.capHash(parent) };
  const body_digest = pca.hashCanonical({ issuer: body.issuer, holder: body.holder, caveats: body.caveats, parent: body.parent });
  const msg = new Uint8Array([...new TextEncoder().encode('atlas-pca/cap/v1\0'), ...pca.unb64u(body_digest)]);
  return { id: body_digest, issuer: body.issuer, holder: body.holder, caveats, parent: body.parent, body_digest, sig: pca.b64u(pca.sign(signerSecret, msg)) };
}

// ======================= wire v2 vectors: freshness, strict canonical form, adversarial =======================
const ALPH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
// re-sign after mutating; if the mutated body has no canonical form (so cannot be signed) keep the stale signature
// (the wire check fails first, so the signature never matters for those vectors).
const resignWith = (mut, secret = agent.secretKey) => { const p = build(); mut(p); try { return resign(p, secret); } catch { return p; } };
const raw = (p) => pca.canonicalize(p); // canonical text of a (valid) object, used as a base for raw-JSON mutations
const rawSub = (p, from, to) => { const t = raw(p); if (!t.includes(from)) throw new Error('rawSub: pattern not found: ' + from); return t.replace(from, to); };

// --- positive ---
await add('valid-with-optional-slots', 'ver-2 body carrying every optional signed slot (nonce, caution, rationale_commitment, progress_step, prohibition_evidence, tool_binding): signed, so they are part of the hash; verifies.', root, planNodes,
  build({ nonce: 'n-0001', caution: 0.4, rationaleCommitment: pca.paramsDigest({ why: 1 }), progressStep: { step: 1, d: 'x' }, prohibitionEvidence: { checked: [] }, toolBinding: pca.paramsDigest({ tool: 'write' }) }));
await add('valid-with-unsigned-threshold-container', 'A `threshold` container is NOT part of the signed body: adding shares does not break the leaf signature.', root, planNodes,
  { ...build(), threshold: { shares: [{ role: 'guardian', publicKey: pca.b64u(rogue.publicKey), sig: pca.b64u(new Uint8Array(64).fill(1)) }] } });
{
  const o = build(); const rev = {}; for (const k of Object.keys(o).reverse()) rev[k] = o[k];
  const txt = JSON.stringify(rev, null, '\t').replace('"write"', '"\\u0077rite"').replace('db/orders"', 'db\\/orders"');
  await add('valid-raw-json-format-insensitive', 'Raw JSON text with indentation, reversed key order, \\u escapes and \\/ : parses (strict profile) to the same value; format never changes the verdict.', root, planNodes, null, { pcactnJson: txt });
}
{
  const chain16 = [root]; let cur = root; let curKey = agent;
  const hopKeys = [agent];
  for (let i = 1; i < 16; i++) { const k = mk(`hop${i}`); hopKeys.push(k); cur = pca.delegate(cur, pca.b64u(k.publicKey), [], curKey.secretKey); chain16.push(cur); curKey = k; }
  await add('valid-chain-at-depth-cap-16', 'A chain of exactly 16 capabilities (the cap) verifies. Hop keys are sha256("atlas-pca-conformance/hop<i>").', root, planNodes,
    pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: chain16, plan: planNodes, nodeId: 'n1', counter: 2, signerSecret: curKey.secretKey }));
  const chain17 = [...chain16]; const k17 = mk('hop16'); chain17.push(pca.delegate(cur, pca.b64u(k17.publicKey), [], curKey.secretKey));
  await add('chain-17-hops-rejected', 'A validly signed chain of 17 capabilities exceeds the 16-hop cap: chain fails (rejected before any signature work).', root, planNodes,
    pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: chain17, plan: planNodes, nodeId: 'n1', counter: 2, signerSecret: k17.secretKey }), { falseChecks: ['chain'], cls: 'negative' });
}

// --- freshness binding (P0-5) ---
await add('ver-1-rejected', 'ver=1 (re-signed): version fails. v2 is a clean break.', root, planNodes, resignWith((p) => { p.ver = 1; }), { falseChecks: ['version'], cls: 'negative' });
await add('ver-3-rejected', 'ver=3 (re-signed): version fails.', root, planNodes, resignWith((p) => { p.ver = 3; }), { falseChecks: ['version'], cls: 'negative' });
await add('audience-mismatch', 'aud does not equal the verifier\'s audience: audience fails (cross-server / cross-instance replay).', root, planNodes, build({ aud: 'some-other-rs' }), { falseChecks: ['audience'], cls: 'negative' });
await add('expired', 'now = exp + 1: validity fails.', root, planNodes, build(), { now: NOW + 600_001, falseChecks: ['validity'], cls: 'negative' });
await add('valid-at-exp-boundary', 'now == exp is still valid (expiry is `now > exp`).', root, planNodes, build(), { now: NOW + 600_000 });
await add('iat-future-beyond-skew', 'iat is 60,001 ms in the future: validity fails.', root, planNodes, build(), { now: NOW - 60_001, falseChecks: ['validity'], cls: 'negative' });
await add('valid-iat-within-skew', 'iat is exactly 60,000 ms in the future: still valid.', root, planNodes, build(), { now: NOW - 60_000 });
await add('lifetime-too-long', 'exp - iat = 3,600,001 ms (> 1 h): validity fails.', root, planNodes, resignWith((p) => { p.exp = p.iat + 3_600_001; }), { now: NOW, falseChecks: ['validity'], cls: 'negative' });
await add('valid-max-lifetime', 'exp - iat = exactly 3,600,000 ms: valid.', root, planNodes, resignWith((p) => { p.exp = p.iat + 3_600_000; }));
await add('exp-not-after-iat', 'exp == iat: validity fails (exp must be > iat).', root, planNodes, resignWith((p) => { p.exp = p.iat; }), { falseChecks: ['validity'], cls: 'negative' });
{ const p = build(); p.exp += 1000;
  await add('tampered-exp-after-signing', 'exp extended after signing: the freshness fields are SIGNED, so leaf_signature fails.', root, planNodes, p, { falseChecks: ['leaf_signature'], cls: 'negative' }); }
{ const p = build(); p.aud = 'rs-conformance-2';
  await add('tampered-aud-after-signing', 'aud rewritten after signing: audience fails and leaf_signature fails.', root, planNodes, p, { falseChecks: ['audience', 'leaf_signature'], cls: 'negative' }); }
{ const p = build({ caution: 0.4 }); p.caution = 0.1;
  await add('tampered-optional-slot-after-signing', 'caution lowered after signing: optional slots are signed, so leaf_signature fails.', root, planNodes, p, { falseChecks: ['leaf_signature'], cls: 'negative' }); }

// --- small-order / identity-key forgeries (audit finding 1): MUST reject; no private key needed ---
const IDENTITY = pca.b64u(Uint8Array.from([1, ...new Array(31).fill(0)])); // (0,1) neutral element
const ORDER2 = pca.b64u(Uint8Array.from([0xec, ...new Array(30).fill(0xff), 0x7f])); // (0,-1), order 2
const FORGED_SIG = pca.b64u(Uint8Array.from([1, ...new Array(31).fill(0), ...new Array(32).fill(0)])); // R=identity, S=0
for (const [label, key] of [['identity', IDENTITY], ['order2', ORDER2]]) {
  const g = pca.mintRoot({ principalSecret: principal.secretKey, principalPublic: pca.b64u(principal.publicKey), holder: key, caveats: [caveatA] });
  const body = pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: g, chain: [g], plan: planNodes, nodeId: 'n1', counter: 1, signerSecret: agent.secretKey });
  await add(`forge-smallorder-leaf-${label}-holder`, `The grant's holder is the ${label} public key and the leaf signature is the forged (R=identity, S=0) value: leaf_signature MUST fail (strict RFC 8032 + reject small-order keys). Needs no private key.`, g, planNodes, { ...body, sig: FORGED_SIG }, { falseChecks: ['leaf_signature'], cls: 'negative' });
}
{
  const body = { issuer: IDENTITY, holder: pca.b64u(agent.publicKey), caveats: [caveatA], parent: null };
  const body_digest = pca.hashCanonical(body);
  const forgedRoot = { id: body_digest, issuer: IDENTITY, holder: body.holder, caveats: body.caveats, body_digest, sig: FORGED_SIG };
  await add('forge-smallorder-root-issuer', 'The grant root issuer is the identity key and its signature is the forged (R=identity, S=0) value: chain MUST fail. The leaf is genuinely signed by the holder.', forgedRoot, planNodes,
    pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: forgedRoot, chain: [forgedRoot], plan: planNodes, nodeId: 'n1', counter: 1, signerSecret: agent.secretKey }), { falseChecks: ['chain'], cls: 'negative' });
}

// --- non-canonical / malformed base64url (audit finding 2) => wire ---
const altTail = (s) => s.slice(0, -1) + ALPH[(ALPH.indexOf(s[s.length - 1]) ^ 1) & 63]; // flip an UNUSED trailing bit: same decoded bytes in a lax decoder
{ const p = build(); p.sig = altTail(p.sig);
  await add('b64u-noncanonical-sig-tail', 'sig has non-zero unused trailing bits in its last base64url char (decodes to the same 64 bytes in a lax decoder): wire fails.', root, planNodes, p, { falseChecks: ['wire'], cls: 'negative' }); }
{ const p = build(); p.plan.inclusion_proof.path[0].hash = altTail(p.plan.inclusion_proof.path[0].hash);
  await add('b64u-noncanonical-proof-hash-tail', 'A Merkle sibling hash has non-canonical trailing bits: wire fails.', root, planNodes, p, { falseChecks: ['wire'], cls: 'negative' }); }
{ const p = build(); p.cap_chain[0] = { ...p.cap_chain[0], sig: altTail(p.cap_chain[0].sig) };
  await add('b64u-noncanonical-chain-sig-tail', 'A capability signature in cap_chain has non-canonical trailing bits: wire fails.', root, planNodes, p, { falseChecks: ['wire'], cls: 'negative' }); }
{ const p = build(); p.sig = p.sig.slice(0, 40) + '\n' + p.sig.slice(40);
  await add('b64u-whitespace-in-sig', 'sig contains an embedded newline: wire fails.', root, planNodes, p, { falseChecks: ['wire'], cls: 'negative' }); }
{ const p = build(); p.sig = p.sig + '==';
  await add('b64u-padding-in-sig', 'sig carries "=" padding: wire fails (unpadded base64url only).', root, planNodes, p, { falseChecks: ['wire'], cls: 'negative' }); }
{ const p = build(); p.plan.root = p.plan.root.replace(/[-_]/, '+') === p.plan.root ? p.plan.root.slice(0, -1) + '+' : p.plan.root.replace(/[-_]/, '+');
  await add('b64u-standard-alphabet', 'plan.root uses "+" (standard base64 alphabet): wire fails.', root, planNodes, p, { falseChecks: ['wire'], cls: 'negative' }); }
{ const p = build(); p.sig = p.sig.slice(0, -2);
  await add('b64u-wrong-length-sig', 'sig decodes to the wrong byte length: wire fails.', root, planNodes, p, { falseChecks: ['wire'], cls: 'negative' }); }

// --- Merkle proof binding (audit finding 3): re-signed so ONLY plan_inclusion fails; shape errors => wire ---
const proofVec = (name, desc, mut, falseChecks) => resignVec(name, desc, mut, falseChecks);
async function resignVec(name, desc, mut, falseChecks) {
  await add(name, desc, root, planNodes, resignWith(mut), { falseChecks, cls: 'negative' });
}
await proofVec('merkle-index-plus-one', 'inclusion_proof.index + 1 (re-signed): plan_inclusion fails (index is bound to the path shape).', (p) => { p.plan.inclusion_proof.index += 1; }, ['plan_inclusion']);
await proofVec('merkle-index-minus-one', 'inclusion_proof.index = -1 (re-signed): plan_inclusion fails.', (p) => { p.plan.inclusion_proof.index = -1; }, ['plan_inclusion']);
await proofVec('merkle-index-equals-size', 'inclusion_proof.index == size (re-signed): plan_inclusion fails.', (p) => { p.plan.inclusion_proof.index = p.plan.inclusion_proof.size; }, ['plan_inclusion']);
await proofVec('merkle-size-zero', 'inclusion_proof.size = 0 (re-signed): plan_inclusion fails.', (p) => { p.plan.inclusion_proof.size = 0; }, ['plan_inclusion']);
await proofVec('merkle-size-doubled', 'inclusion_proof.size = 2*size (re-signed, path shape no longer matches): plan_inclusion fails.', (p) => { p.plan.inclusion_proof.size *= 2; }, ['plan_inclusion']);
await proofVec('merkle-size-missing', 'inclusion_proof.size absent: wire fails.', (p) => { delete p.plan.inclusion_proof.size; }, ['wire']);
await proofVec('merkle-index-non-integer', 'inclusion_proof.index = 1.5: wire fails (index/size are safe integers).', (p) => { p.plan.inclusion_proof.index = 1.5; }, ['wire']);
await proofVec('merkle-index-string', 'inclusion_proof.index is the string "1": wire fails.', (p) => { p.plan.inclusion_proof.index = '1'; }, ['wire']);
await proofVec('merkle-path-side-flipped', 'A proof step side L/R flipped (re-signed): plan_inclusion fails.', (p) => { const s0 = p.plan.inclusion_proof.path[0]; s0.side = s0.side === 'L' ? 'R' : 'L'; }, ['plan_inclusion']);

// --- type strictness (audit finding 5) => wire ---
for (const [label, val] of [['number-0', 0], ['object', {}], ['false', false], ['null', null], ['array', []]]) {
  await proofVec(`conditions-digest-${label}`, `plan.conditions_digest is ${JSON.stringify(val)} (non-string, re-signed): wire fails (no silent fallback to the default digest).`, (p) => { p.plan.conditions_digest = val; }, ['wire']);
}
await proofVec('wire-missing-aud', 'aud absent: wire fails.', (p) => { delete p.aud; }, ['wire']);
await proofVec('wire-missing-exp', 'exp absent: wire fails.', (p) => { delete p.exp; }, ['wire']);
await proofVec('wire-aud-not-string', 'aud is a number: wire fails.', (p) => { p.aud = 7; }, ['wire']);
await proofVec('wire-unknown-top-level-field', 'An unknown top-level field (signed): wire fails (closed field set).', (p) => { p.surprise = 1; }, ['wire']);
await proofVec('wire-counter-string', 'counter is the string "7": wire fails.', (p) => { p.counter = '7'; }, ['wire']);
await proofVec('wire-counter-non-integer', 'counter = 1.5 (object form): wire fails.', (p) => { p.counter = 1.5; }, ['wire']);
await proofVec('wire-caution-out-of-range', 'caution = 2: wire fails ([0,1] only).', (p) => { p.caution = 2; }, ['wire']);
await proofVec('wire-iat-float', 'iat = 1800000000000.5: wire fails (integers only).', (p) => { p.iat = NOW + 0.5; }, ['wire']);
await proofVec('wire-risk-r-too-precise', 'risk_claim.r = 0.30000000000000004 (17 significant digits): wire fails (max 15).', (p) => { p.risk_claim.r = 0.1 + 0.2; }, ['wire']);
await proofVec('wire-risk-r-exponent', 'risk_claim.r = 1e-7 (needs an exponent form): wire fails.', (p) => { p.risk_claim.r = 1e-7; }, ['wire']);
await proofVec('wire-unsafe-integer-in-caveat', 'A caveat contains the integer 9007199254740992 (2^53): wire fails (safe range).', (p) => { p.cap_chain = [{ ...p.cap_chain[0], caveats: [...p.cap_chain[0].caveats, { type: 'x', n: 9007199254740992 }] }]; }, ['wire']);
await proofVec('wire-lone-surrogate-in-string', 'aud contains a lone surrogate U+D800 (object form): wire fails.', (p) => { p.aud = 'rs-\ud800'; }, ['wire']);
await proofVec('wire-too-deep-risk-inputs', 'risk_claim.inputs nests 40 arrays deep (object form): wire fails (max depth 32).', (p) => { let d = 1; for (let i = 0; i < 40; i++) d = [d]; p.risk_claim.inputs = { d }; }, ['wire']);

// --- raw-JSON parser divergences (audit findings 6, 7) => wire ---
const base = build();
const rawVec = (name, desc, text) => add(name, desc, root, planNodes, null, { pcactnJson: text, falseChecks: ['wire'], cls: 'negative' });
await rawVec('json-counter-float-1.0', 'Raw JSON counter is 7.0 (integer-valued float literal): rejected.', rawSub(base, '"counter":7', '"counter":7.0'));
await rawVec('json-counter-exponent-7e0', 'Raw JSON counter is 7e0: rejected.', rawSub(base, '"counter":7', '"counter":7e0'));
await rawVec('json-counter-2pow53-plus-1', 'Raw JSON counter is 9007199254740993 (2^53+1; rounds to ...992 in a double): rejected.', rawSub(base, '"counter":7', '"counter":9007199254740993'));
await rawVec('json-counter-2pow53', 'Raw JSON counter is 9007199254740992 (2^53): rejected (safe range is |n| <= 2^53-1).', rawSub(base, '"counter":7', '"counter":9007199254740992'));
await rawVec('json-counter-1e21', 'Raw JSON counter is 1e21: rejected.', rawSub(base, '"counter":7', '"counter":1e21'));
await rawVec('json-counter-negative-zero', 'Raw JSON counter is -0: rejected.', rawSub(base, '"counter":7', '"counter":-0'));
await rawVec('json-counter-leading-zero', 'Raw JSON counter is 07: rejected.', rawSub(base, '"counter":7', '"counter":07'));
await rawVec('json-r-trailing-zero', 'Raw JSON risk_claim.r is 0.0 (trailing fractional zero): rejected.', rawSub(base, '"r":0', '"r":0.0'));
await rawVec('json-comment-block', 'A /* */ comment inside the document: rejected (the Ruby JSON gem accepts these).', '/* c */' + raw(base));
await rawVec('json-comment-inside', 'A /* */ comment between members: rejected.', rawSub(base, '"counter":7', '"counter":/*x*/7'));
await rawVec('json-comment-line', 'A // line comment: rejected.', raw(base).slice(0, -1) + ' // c\n}');
await rawVec('json-lone-surrogate-escape', 'aud contains the escape \\ud800 with no low surrogate: rejected.', rawSub(base, '"aud":"rs-conformance"', '"aud":"rs-\\ud800"'));
await rawVec('json-lone-low-surrogate-escape', 'aud contains a lone low surrogate escape \\udc00: rejected.', rawSub(base, '"aud":"rs-conformance"', '"aud":"rs-\\udc00x"'));
await rawVec('json-surrogate-pair-reversed', 'aud contains \\ude00\\ud83d (low then high): rejected.', rawSub(base, '"aud":"rs-conformance"', '"aud":"\\ude00\\ud83d"'));
await rawVec('json-nesting-too-deep', 'risk_claim.inputs nests 100 arrays deep: rejected (max depth 32; languages differ at 300 / 1200 otherwise).', rawSub(base, '"inputs":{}', '"inputs":{"d":' + '['.repeat(100) + '1' + ']'.repeat(100) + '}'));
await rawVec('json-duplicate-key', 'Duplicate "counter" key: rejected (languages differ on first-wins / last-wins).', rawSub(base, '"counter":7', '"counter":7,"counter":8'));
await rawVec('json-duplicate-key-escaped', 'Duplicate key spelled with a \\u escape ("coun\\u0074er"): rejected.', rawSub(base, '"counter":7', '"counter":7,"coun\\u0074er":8'));
await rawVec('json-trailing-comma', 'Trailing comma: rejected.', raw(base).slice(0, -1) + ',}');
await rawVec('json-bom', 'UTF-8 BOM (U+FEFF) before the document: rejected.', '\ufeff' + raw(base));
await rawVec('json-trailing-garbage', 'Trailing non-whitespace after the document: rejected.', raw(base) + ' x');
await rawVec('json-nonbreaking-space', 'U+00A0 as whitespace: rejected (only space, \\t, \\n, \\r).', raw(base).replace('{"', '{\u00a0"'));
await rawVec('json-raw-control-char-in-string', 'A raw U+0009 inside a string: rejected.', rawSub(base, '"aud":"rs-conformance"', '"aud":"rs-\tconformance"'));
await rawVec('json-single-quotes', 'Single-quoted strings: rejected.', raw(base).replace(/"aud"/, "'aud'"));
await rawVec('json-not-an-object', 'The document is a JSON array, not an object: rejected.', '[' + raw(base) + ']');

// Primitive vectors for byte-level agreement checks.
const primitives = {
  // Strict canonical form: key order is BYTEWISE over UTF-8 (== code point order). U+FF5E sorts BEFORE U+1F600 here
  // (UTF-16 code-unit order, used by wire v1, put them the other way round).
  canonical: [
    { value: { b: 1, a: [true, null, 'x'], c: { z: 1, y: 2 } }, expect: null },
    { value: { '～': 1, '\u{1F600}': 2 }, expect: null },
    { value: { s: 'café <&> "q" \\ \n \u0001 \u2028 \u007f' }, expect: null },
    { value: { n: [0, -1, 1.5, 100000, 0.1, -0.25, 9007199254740991] }, expect: null },
    { value: { '': 1, a: { '': 2 }, 'a\u0000': 3, aa: 4 }, expect: null },
  ],
  merkle: [3, 5, 7].map((n) => {
    const leaves = Array.from({ length: n }, (_, i) => ({ i, t: 'leaf' }));
    return { leaves, root: pca.merkleRoot(leaves), proofs: leaves.map((_, i) => pca.merkleProof(leaves, i)) };
  }),
  params_digest_empty: pca.EMPTY_PARAMS_DIGEST,
  // Strict JSON profile: `accept:false` MUST be rejected; `accept:true` MUST parse and canonicalize to `canonical`.
  json_parse: [],
  // Strict base64url: `valid:false` MUST be rejected; `len` is the required DECODED length when present.
  b64u: [],
  // Threshold share role-binding (server side; informational for verifiers that also verify threshold shares).
  threshold_share: [],
};
for (const c of primitives.canonical) {
  c.expect = pca.canonicalizeStrict(c.value);
  c.hash = b64hash(c.expect);
}
function b64hash(text) { return pca.b64u(new Uint8Array(createHash('sha256').update(text, 'utf8').digest())); }

const jp = (input, accept) => {
  let canonical = null;
  try { canonical = pca.canonicalizeStrict(pca.strictParse(input)); if (!accept) throw new Error('reference ACCEPTED ' + JSON.stringify(input)); } catch (e) { if (accept) throw new Error('reference REJECTED ' + JSON.stringify(input) + ': ' + e.message); if (String(e.message).startsWith('reference')) throw e; }
  primitives.json_parse.push(accept ? { input, accept, canonical } : { input, accept });
};
for (const t of ['{"b":1,"a":[1,-2,0.5,true,null,"x"]}', ' { "a" : "\\u00e9\\ud83d\\ude00\\/" } ', '[]', '{}', '"s"', '0', '-1', '0.5', '12345678901234.5', '9007199254740991', '-9007199254740991', '0.000001', '{"__proto__":1}',
  '{"a":"\\u0000"}', '[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]']) jp(t, true);
for (const t of ['{"a":1,"a":2}', '{"a":1}//c', '/*c*/{"a":1}', '{"a":1.0}', '{"a":7e0}', '{"a":1E5}', '{"a":1e+5}', '{"a":-0}', '{"a":-0.0}', '{"a":1.50}', '{"a":01}', '{"a":+1}', '{"a":.5}', '{"a":5.}',
  '{"a":9007199254740992}', '{"a":9007199254740993}', '{"a":-9007199254740992}', '{"a":0.1234567890123456}', '{"a":0.0000001}', '{"a":"\\ud800"}', '{"a":"\\udc00"}', '{"a":"\\ud800x"}',
  '{"a":"\\x"}', '{"a":"\t"}', '[1,]', '{"a":1,}', "{'a':1}", '{"a":NaN}', '{"a":Infinity}', '{"a":undefined}', '\ufeff{}', '{} x', '', ' ', '{"a"}', '{"a":}', '{a:1}',
  '['.repeat(33) + ']'.repeat(33), '{"a":1}\u00a0']) jp(t, false);

const b = (input, valid, len) => primitives.b64u.push(len === undefined ? { input, valid } : { input, valid, len });
const h32 = pca.b64u(new Uint8Array(32).fill(7)); // 43 chars, 4 data bits in the last char
b(h32, true, 32); b(h32, false, 31); b(h32.slice(0, -1), false, 32); b(h32 + 'A', false, 32);
b(altTail(h32), false, 32); b(h32 + '=', false, 32); b(' ' + h32, false, 32); b(h32 + '\n', false, 32); b(h32.slice(0, 20) + '+' + h32.slice(21), false, 32);
b(h32.slice(0, 20) + ' ' + h32.slice(21), false, 32); b('', true, undefined); b('A', false); b('AA', true); b('AB', false); b('AAA', true); b('AAB', false); b('AAAA', true); b('AAAAA', false);
const sig64 = pca.b64u(new Uint8Array(64).fill(9)); // 86 chars, 2 data bits in the last char
b(sig64, true, 64); b(altTail(sig64), false, 64); b(sig64 + '==', false, 64);
for (const e of primitives.b64u) { const got = pca.decodeB64uStrict(e.input, e.len) !== null; if (got !== e.valid) throw new Error('b64u vector disagrees with reference: ' + JSON.stringify(e)); }

// ---- grant_ref binding (check `grant_ref_bound`): grant_ref MUST equal the id of the ROOT capability, cap_chain[0].id ----
{
  const gr = 'grant_ref_bound';
  const withRef = (p, ref, secret = agent.secretKey) => { const q = clone(p); q.grant_ref = ref; return resign(q, secret); };
  const fresh = pca.b64u(new Uint8Array(32).fill(0x5a)); // a canonical 32-byte value that is NOT any capability id
  await add('grant-ref-bound-positive-1-hop', 'grant_ref equals the id of the chain root (1-hop chain): grant_ref_bound passes.', root, planNodes, build());
  await add('grant-ref-bound-positive-2-hop', 'grant_ref equals the id of the ROOT of a 2-hop chain (not the leaf hop id): grant_ref_bound passes.', root, planNodes, build2());
  await add('grant-ref-mismatch-resigned', 'grant_ref is a fresh canonical 32-byte value that is not the root id (validly re-signed): grant_ref_bound fails; nothing else does.', root, planNodes, withRef(build(), fresh), { falseChecks: [gr] });
  await add('grant-ref-mismatch-not-resigned', 'grant_ref swapped to a fresh value after signing: grant_ref_bound and leaf_signature fail.', root, planNodes, (() => { const q = build(); q.grant_ref = fresh; return q; })(), { falseChecks: [gr, 'leaf_signature'] });
  await add('grant-ref-equals-non-root-hop-id', 'grant_ref is the id of a NON-root hop of a 2-hop chain (re-signed by the leaf holder): grant_ref_bound fails.', root, planNodes, withRef(build2(), hop1.id, sub.secretKey), { falseChecks: [gr] });
  await add('grant-ref-equals-leaf-holder-key', 'grant_ref is the leaf holder public key (a well-formed 32-byte value, re-signed): grant_ref_bound fails.', root, planNodes, withRef(build(), pca.b64u(agent.publicKey)), { falseChecks: [gr] });
  await add('grant-ref-equals-grant-issuer-key', 'grant_ref is the grant issuer (principal) public key (re-signed): grant_ref_bound fails.', root, planNodes, withRef(build(), pca.b64u(principal.publicKey)), { falseChecks: [gr] });
  await add('grant-ref-case-variant-of-root-id', 'grant_ref is the root id with ONE letter\'s case flipped (still canonical base64url, a different 32-byte value; re-signed): compared byte-exactly, grant_ref_bound fails.', root, planNodes,
    withRef(build(), (() => { const i = [...root.id].findIndex((ch, k) => k < 40 && /[A-Za-z]/.test(ch)); const ch = root.id[i]; return root.id.slice(0, i) + (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()) + root.id.slice(i + 1); })()), { falseChecks: [gr] });
  await add('grant-ref-empty', 'grant_ref is the empty string (re-signed): wire fails.', root, planNodes, withRef(build(), ''), { falseChecks: ['wire'] });
  await add('grant-ref-absent', 'grant_ref is absent (re-signed body without it): wire fails (missing field).', root, planNodes, (() => { const { sig: _s, grant_ref: _g, ...body } = clone(build()); return pca.signPCActn(body, agent.secretKey); })(), { falseChecks: ['wire'] });
  await add('grant-ref-trailing-whitespace', 'grant_ref is the root id plus a trailing space (re-signed): not canonical base64url, wire fails.', root, planNodes, withRef(build(), root.id + ' '), { falseChecks: ['wire'] });
  await add('grant-ref-leading-whitespace', 'grant_ref is the root id with a leading TAB (re-signed): wire fails.', root, planNodes, withRef(build(), '\t' + root.id), { falseChecks: ['wire'] });
  await add('grant-ref-unicode-lookalike', 'grant_ref is the root id with its first character replaced by U+0430 CYRILLIC SMALL A (re-signed): wire fails; never normalised.', root, planNodes, withRef(build(), 'а' + root.id.slice(1)), { falseChecks: ['wire'] });
  await add('grant-ref-zero-width-joiner', 'grant_ref is the root id with a U+200B ZERO WIDTH SPACE appended (re-signed): wire fails.', root, planNodes, withRef(build(), root.id + '​'), { falseChecks: ['wire'] });
  await add('grant-ref-very-long', 'grant_ref is a 4096-char string (re-signed): wire fails (must be exactly 32 bytes).', root, planNodes, withRef(build(), 'A'.repeat(4096)), { falseChecks: ['wire'] });
  await add('grant-ref-wrong-type-number', 'grant_ref is the number 7 (re-signed): wire fails.', root, planNodes, withRef(build(), 7), { falseChecks: ['wire'] });
  await add('grant-ref-null', 'grant_ref is null (re-signed): wire fails.', root, planNodes, withRef(build(), null), { falseChecks: ['wire'] });
  await add('grant-ref-empty-chain', 'cap_chain is empty (re-signed) while grant_ref is the root id: chain, grant_ref_bound (fail-closed on no root) and leaf_signature fail.', root, planNodes, (() => { const q = clone(build()); q.cap_chain = []; return resign(q, agent.secretKey); })(), { falseChecks: ['chain', gr, 'leaf_signature'] });
}

{ // threshold share role-binding vectors
  const guardian = mk('guardian');
  const signerSet = [
    { role: 'agent', publicKey: pca.b64u(agent.publicKey) },
    { role: 'guardian', publicKey: pca.b64u(guardian.publicKey) },
    { role: 'principal', publicKey: pca.b64u(principal.publicKey) },
  ];
  const message = pca.thresholdMessage(build());
  for (const [role, key, t] of [['guardian', guardian, 2], ['guardian', guardian, 3], ['principal', principal, 3]]) {
    const share = pca.signShare(role, key.secretKey, message, { signerSet, t });
    primitives.threshold_share.push({
      role, t, signer_set: signerSet,
      threshold_message: pca.b64u(message),
      signer_set_hash: pca.b64u(pca.signerSetHash(signerSet)),
      share_message: pca.b64u(pca.shareMessage(role, message, signerSet, t)),
      share,
    });
  }
}

const limits = { max_chain_hops: 16, max_json_depth: 32, max_json_chars: 1 << 20, max_decimal_digits: 15, min_decimal_magnitude: 1e-6, max_lifetime_ms: 3_600_000, max_skew_ms: 60_000 };
const checkOrder = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter'];
writeFileSync(join(outDir, 'keys.json'), JSON.stringify(keys, null, 2) + '\n');
writeFileSync(join(outDir, 'vectors.json'), JSON.stringify({ format: 2, ver: 2, sig_domain: 'atlas-pca/actn/v2\\0', cap_domain: 'atlas-pca/cap/v1\\0', share_domain: 'atlas-pca/share/<role>\\0', check_order: checkOrder, limits, primitives, vectors }, null, 2) + '\n');
console.log(`wrote ${vectors.length} vectors`);
