// Stage 4 of the conformance pipeline (run AFTER gen-conformance-adv.mjs; idempotent): the round-6 natives coverage.
//
//   primitives.threshold_set[]    WHOLE-signer-set validation for one threshold share (R6-02, R6-03/R6-04). Same entry
//                                 schema as threshold_share ({ name, description, role, t, signer_set, threshold_message,
//                                 share, valid }) plus `requires` (a signature suite the runner must implement, else skip).
//                                 `valid` == the reference verifyThreshold({shares:[share]}, msg, signer_set, t) counts the
//                                 share for `role`. Covers: unknown roles / bad keys / empty, null or short pq_pk ANYWHERE in
//                                 the set, t outside 1..3, duplicate (role,key) entries (identical: accepted; conflicting
//                                 pq_pk: the set is refused), one key under two roles, and the R6-02 rule (a role that
//                                 registers pq_pk needs a PQ / hybrid share).
//   primitives.signer_set_hash[]  { name, signer_set, hash }: the reference signerSetHash (b64u) of a set, including
//                                 pq_pk:"" and non-BMP role strings (UTF-8 byte order, not UTF-16).
//   primitives.malformed[]        { name, description, api, input } with api in chain | threshold_share | pcactn_json.
//                                 Every entry is a DENY in the reference and must be a clean deny in every verifier: no
//                                 exception may escape the public entry point (R6-05).
//                                   chain:           input = { chain, expected_root_issuer }  -> verify_chain(...) ok=false
//                                   threshold_share: input = the threshold_share entry (ANY JSON value) -> false
//                                   pcactn_json:     input = { text, grant, now, aud } -> strict parse (failure == deny),
//                                                    then verify -> allow=false
//
//     node packages/pca/scripts/gen-conformance-r6.mjs
import { createHash } from 'node:crypto';
import * as pca from '../dist/index.js';
import { cloneJson, readCore, writeCore } from './conformance-io.mjs';

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/r6/${l}`).digest());
const ed = (l) => { const s = seed(l); return { sk: s, pub: pca.b64u(pca.publicKeyOf(s)) }; };
const agent = ed('agent'), guardian = ed('guardian'), principal = ed('principal'), stranger = ed('stranger');
const aMl = pca.mlDsa65Keygen(seed('a-ml')), xMl = pca.mlDsa65Keygen(seed('x-ml')), gMl = pca.mlDsa65Keygen(seed('g-ml'));
const pqA = pca.encodeMlDsaPublicKey(aMl.publicKey), pqX = pca.encodeMlDsaPublicKey(xMl.publicKey), pqG = pca.encodeMlDsaPublicKey(gMl.publicKey);
const thMsg = new Uint8Array(createHash('sha256').update('atlas-pca-conformance/r6/thmsg').digest());
const hyb = 'hybrid-ed25519-ml-dsa-65', pure = 'ml-dsa-65', nest = 'hybrid-nested-ed25519-ml-dsa-65';
/** suites every native implements; anything else is `requires`. */
const CROSS = new Set(['ed25519', pure, hyb]);

const set = (o = {}) => [
  { role: 'agent', publicKey: agent.pub, ...(o.pqA ? { pq_pk: o.pqA } : {}) },
  { role: 'guardian', publicKey: guardian.pub, ...(o.pqG ? { pq_pk: o.pqG } : {}) },
  { role: 'principal', publicKey: principal.pub },
];

// ------------------------------------------------------------------ threshold_set
const thresholdSet = [];
/** `msgB64` is decoded with the STRICT base64url decoder (a non-canonical / non-string threshold_message is a deny). */
function truth(role, ss, t, share, msgB64) {
  try {
    const msg = pca.decodeB64uStrict(msgB64);
    if (msg === null) return { valid: false, reason: 'threshold_message is not canonical base64url' };
    const v = pca.verifyThreshold({ shares: [share] }, msg, ss, t);
    return { valid: !!(share && share.role === role && v.roles.includes(role)), reason: v.reason ?? null };
  } catch (e) {
    throw new Error(`reference verifyThreshold THREW (it must be total): ${e}`);
  }
}
function add(name, description, role, ss, t, share, intended) {
  const { valid, reason } = truth(role, ss, t, share, pca.b64u(thMsg));
  if (intended !== undefined && valid !== intended) throw new Error(`threshold_set ${name}: reference valid=${valid} (${reason}) != intended ${intended}`);
  const alg = share && typeof share.alg === 'string' ? share.alg : 'ed25519';
  thresholdSet.push({
    name: 'r6-' + name, description, role, t, valid,
    ...(CROSS.has(alg) ? (alg === 'ed25519' ? {} : { requires: 'ml-dsa-65' }) : { requires: alg }),
    signer_set: ss, threshold_message: pca.b64u(thMsg), share,
    ...(reason && !valid ? { ts_reason: reason } : {}),
  });
}
const sh = (role, sk, ss, t, suite) => pca.signShare(role, sk, thMsg, { signerSet: ss, t }, suite);
/** a share over a hand-built share message (for t outside 1..3, which shareMessage refuses). */
const rawShare = (role, sk, ss, tByte) => {
  const m = pca.shareMessage(role, thMsg, ss, 1);
  m[m.length - 1] = tByte & 0xff;
  return { role, publicKey: pca.b64u(pca.publicKeyOf(sk)), sig: pca.b64u(pca.sign(sk, m)) };
};

const S = set({ pqA });
const E = set();
add('pos-ed25519', 'Plain ed25519 agent share over an ed25519-only signer set.', 'agent', E, 1, sh('agent', agent.sk, E, 1), true);
add('pos-hybrid-registered', 'Hybrid agent share; the set registers the agent pq_pk.', 'agent', S, 1, sh('agent', agent.sk, S, 1, { alg: hyb, mlDsa: aMl }), true);
add('pos-hybrid-registered-share-has-pq_pk', 'Hybrid share that also carries the (same) registered pq_pk.', 'agent', S, 1, { ...sh('agent', agent.sk, S, 1, { alg: hyb, mlDsa: aMl }), pq_pk: pqA }, true);
add('pos-pure-registered', 'Pure ml-dsa-65 agent share under the registered pq_pk.', 'agent', S, 1, sh('agent', agent.sk, S, 1, { alg: pure, mlDsa: aMl }), true);
add('pos-nested-registered', 'Nested hybrid share (only verifiers that implement the nested suite run it).', 'agent', S, 1, sh('agent', agent.sk, S, 1, { alg: nest, mlDsa: aMl }), true);
add('neg-ed25519-share-for-pq-role', 'R6-02: the set registers a pq_pk for the agent, so an ed25519-only share for it does not count (an Ed25519 break must not forge a hybrid-registered role).', 'agent', S, 1, sh('agent', agent.sk, S, 1), false);
add('pos-ed25519-share-for-ed-role-in-pq-set', 'R6-02 scope: guardian registers no pq_pk, so its ed25519 share counts although the agent registers one.', 'guardian', S, 1, sh('guardian', guardian.sk, S, 1), true);
add('neg-hybrid-swapped-pq_pk', 'Hybrid share signed with an attacker ML-DSA key that it names as pq_pk.', 'agent', S, 1, { ...sh('agent', agent.sk, S, 1, { alg: hyb, mlDsa: xMl }), pq_pk: pqX }, false);
// A share that NAMES a pq_pk must name exactly its role's registered one (whatever its signatures; any suite).
add('neg-hybrid-share-pq_pk-mismatch', 'Hybrid share signed under the REGISTERED keys that names a different pq_pk: refused (the named key must equal the registered one).', 'agent', S, 1, { ...sh('agent', agent.sk, S, 1, { alg: hyb, mlDsa: aMl }), pq_pk: pqX }, false);
add('neg-pure-share-pq_pk-mismatch', 'Pure ml-dsa-65 share signed under the registered key that names a different pq_pk: refused.', 'agent', S, 1, { ...sh('agent', agent.sk, S, 1, { alg: pure, mlDsa: aMl }), pq_pk: pqX }, false);
add('neg-hybrid-share-pq_pk-null', 'Hybrid share under the registered keys with pq_pk null: refused (a named pq_pk must be the registered string).', 'agent', S, 1, { ...sh('agent', agent.sk, S, 1, { alg: hyb, mlDsa: aMl }), pq_pk: null }, false);
add('neg-ed25519-share-names-pq_pk-for-ed-role', 'ed25519 guardian share (the guardian registers no pq_pk) that names a pq_pk: refused (there is no registered key it could equal).', 'guardian', S, 1, { ...sh('guardian', guardian.sk, S, 1), pq_pk: pqG }, false);
add('neg-hybrid-attacker-pq-no-pq_pk-field', 'Hybrid share whose PQ half is an attacker key.', 'agent', S, 1, sh('agent', agent.sk, S, 1, { alg: hyb, mlDsa: xMl }), false);
add('neg-stranger-ed-registered-pq', 'Hybrid share whose Ed25519 key is not the registered agent key.', 'agent', S, 1, sh('agent', stranger.sk, S, 1, { alg: hyb, mlDsa: aMl }), false);
add('neg-stranger-ed-own', 'ed25519 share by an unregistered key.', 'agent', E, 1, sh('agent', stranger.sk, E, 1), false);
{
  const untagged = pca.shareMessage('agent', thMsg, S, 1);
  add('neg-classical-relabel-hybrid-attacker-pq', 'Classical bytes relabelled hybrid with an attacker pq_pk.', 'agent', S, 1, { ...pca.signPreparedShare('agent', agent.sk, untagged, { alg: hyb, mlDsa: xMl }), pq_pk: pqX }, false);
  add('neg-classical-relabel-hybrid-registered-pq', 'Classical (untagged) bytes signed hybrid under the registered key.', 'agent', S, 1, { ...pca.signPreparedShare('agent', agent.sk, untagged, { alg: hyb, mlDsa: aMl }), pq_pk: pqA }, false);
  add('neg-classical-relabel-pure', 'Classical (untagged) bytes signed pure ml-dsa-65.', 'agent', S, 1, pca.signPreparedShare('agent', agent.sk, untagged, { alg: pure, mlDsa: aMl }), false);
  const h = sh('agent', agent.sk, S, 1, { alg: hyb, mlDsa: aMl });
  add('neg-hybrid-downgrade-strip', 'Hybrid share with alg/pq_sig stripped.', 'agent', S, 1, { role: h.role, publicKey: h.publicKey, sig: h.sig }, false);
  add('neg-hybrid-labelled-pure', 'Hybrid share relabelled ml-dsa-65.', 'agent', S, 1, { ...h, alg: pure }, false);
  add('neg-hybrid-labelled-nested', 'R6-06: hybrid share relabelled as the nested suite (the nested construction signs different bytes; verifiers without the nested suite refuse it too).', 'agent', S, 1, { ...h, alg: nest }, false);
  const p = sh('agent', agent.sk, S, 1, { alg: pure, mlDsa: aMl });
  add('neg-pure-labelled-hybrid', 'Pure share relabelled hybrid.', 'agent', S, 1, { ...p, alg: hyb }, false);
  const g = sh('guardian', guardian.sk, S, 1);
  add('neg-guardian-share-as-agent', 'A guardian share checked for the agent role.', 'agent', S, 1, g, false);
  add('neg-guardian-share-role-agent', 'A guardian share relabelled role agent.', 'agent', S, 1, { ...g, role: 'agent' }, false);
}
// ---- R6-03: the WHOLE set is validated (an entry for another role can invalidate the set)
const v = (name, desc, ss, intended, t = 1, role = 'agent', suite) => add(name, desc, role, ss, t, sh(role, role === 'agent' ? agent.sk : guardian.sk, ss, t, suite), intended);
v('set-duplicate-identical-member', 'An identical duplicate (role, key) entry is accepted (it registers nothing new).', [...E, { ...E[0] }], true);
v('set-duplicate-identical-member-with-pq', 'An identical duplicate (role, key, pq_pk) entry is accepted.', [...S, { ...S[0] }], true, 1, 'agent', { alg: hyb, mlDsa: aMl });
v('set-two-keys-one-role', 'Two keys for one role: the set is refused.', [...E, { role: 'agent', publicKey: stranger.pub }], false);
{
  const twoPq = [...S, { role: 'agent', publicKey: agent.pub, pq_pk: pqX }];
  v('set-same-key-two-pq_pk', 'Duplicate (role, key) with CONFLICTING pq_pk: the set is refused (no first-wins / last-wins ambiguity).', twoPq, false, 1, 'agent', { alg: hyb, mlDsa: aMl });
  v('set-same-key-two-pq_pk-attacker-pq', 'As above, share under the second pq_pk: refused.', twoPq, false, 1, 'agent', { alg: hyb, mlDsa: xMl });
  const twoPqRev = [{ role: 'agent', publicKey: agent.pub, pq_pk: pqX }, ...S];
  v('set-same-key-two-pq_pk-rev', 'Conflicting pq_pk, reversed order: refused.', twoPqRev, false, 1, 'agent', { alg: hyb, mlDsa: xMl });
  const pqAndNone = [...S, { role: 'agent', publicKey: agent.pub }];
  v('set-same-key-pq_pk-and-absent', 'Duplicate (role, key), one with pq_pk and one without: refused.', pqAndNone, false, 1, 'agent', { alg: hyb, mlDsa: aMl });
  v('set-same-key-pq_pk-and-absent-ed-share', 'As above with an ed25519 share: refused.', pqAndNone, false);
}
v('set-one-key-two-roles', 'One key registered under two roles: refused.', [E[0], { role: 'guardian', publicKey: agent.pub }, E[2]], false);
v('set-unknown-role-elsewhere', 'An unknown role anywhere in the set refuses the set (the agent share itself is fine).', [...E, { role: 'root', publicKey: stranger.pub }], false);
add('set-unknown-role-verified', 'A share for an unknown role never counts.', 'root', [{ role: 'root', publicKey: agent.pub }, E[1], E[2]], 1,
  { role: 'root', publicKey: agent.pub, sig: pca.b64u(pca.sign(agent.sk, (() => { const m = pca.shareMessage('agent', thMsg, [{ role: 'root', publicKey: agent.pub }, E[1], E[2]], 1); return m; })())) }, false);
v('set-empty-pq_pk', 'pq_pk "" on the verified role: refused.', [{ role: 'agent', publicKey: agent.pub, pq_pk: '' }, E[1], E[2]], false);
v('set-empty-pq_pk-elsewhere', 'pq_pk "" on ANOTHER role: the whole set is refused.', [E[0], { role: 'guardian', publicKey: guardian.pub, pq_pk: '' }, E[2]], false);
v('set-null-pq_pk', 'pq_pk null: refused.', [{ role: 'agent', publicKey: agent.pub, pq_pk: null }, E[1], E[2]], false);
v('set-null-pq_pk-elsewhere', 'pq_pk null on another role: refused.', [E[0], E[1], { role: 'principal', publicKey: principal.pub, pq_pk: null }], false);
v('set-short-pq_pk', 'pq_pk of no registered PQ key length: refused.', [{ role: 'agent', publicKey: agent.pub, pq_pk: 'AAAA' }, E[1], E[2]], false);
v('set-short-pq_pk-elsewhere', 'Short pq_pk on another role: refused.', [E[0], { role: 'guardian', publicKey: guardian.pub, pq_pk: 'AAAA' }, E[2]], false);
v('set-noncanonical-pq_pk-elsewhere', 'Non-canonical base64url pq_pk on another role: refused.', [E[0], { role: 'guardian', publicKey: guardian.pub, pq_pk: pqG.slice(0, -1) + '/' }, E[2]], false);
v('set-numeric-pq_pk-elsewhere', 'Non-string pq_pk on another role: refused.', [E[0], { role: 'guardian', publicKey: guardian.pub, pq_pk: 5 }, E[2]], false);
v('set-valid-pq_pk-elsewhere', 'A well-formed pq_pk on another role does not affect an ed25519 agent share.', [E[0], { role: 'guardian', publicKey: guardian.pub, pq_pk: pqG }, E[2]], true);
v('set-extra-field', 'Unknown fields on a set entry are ignored (not hashed).', [{ role: 'agent', publicKey: agent.pub, label: 'x' }, E[1], E[2]], true);
v('set-bad-other-key', 'A non-key publicKey on another role: refused.', [E[0], { role: 'guardian', publicKey: 'not-a-key' }, E[2]], false);
v('set-short-other-key', 'A 31-byte publicKey on another role: refused.', [E[0], { role: 'guardian', publicKey: pca.b64u(new Uint8Array(31).fill(7)) }, E[2]], false);
v('set-numeric-other-key', 'A numeric publicKey on another role: refused.', [E[0], { role: 'guardian', publicKey: 5 }, E[2]], false);
v('set-missing-other-role', 'An entry with no role: refused.', [E[0], { publicKey: guardian.pub }, E[2]], false);
v('set-null-entry', 'A null entry: refused.', [E[0], null, E[2]], false);
v('set-string-entry', 'A string entry: refused.', [E[0], 'guardian', E[2]], false);
v('set-role-case', 'Role names are case-sensitive: "Guardian" is unknown, refused.', [E[0], { role: 'Guardian', publicKey: guardian.pub }, E[2]], false);
v('set-agent-only', 'A one-entry set (agent only) is valid.', [E[0]], true);
v('set-sort-nonbmp-role', 'A non-BMP role string is unknown: refused (the set hash still sorts by UTF-8 bytes).', [...E, { role: '￿', publicKey: stranger.pub }, { role: '\u{1F600}', publicKey: pca.b64u(new Uint8Array(32).fill(9)) }], false);
// ---- R6-04: t must be exactly 1, 2 or 3
add('t-0', 't=0 is invalid.', 'agent', E, 0, rawShare('agent', agent.sk, E, 0), false);
add('t-2', 't=2: the share counts toward the threshold (one of two).', 'agent', E, 2, sh('agent', agent.sk, E, 2), true);
add('t-3', 't=3: the share counts toward the threshold.', 'agent', E, 3, sh('agent', agent.sk, E, 3), true);
add('t-4', 't=4 is invalid even with a share over the t=4 byte.', 'agent', E, 4, rawShare('agent', agent.sk, E, 4), false);
add('t-255', 't=255 is invalid.', 'agent', E, 255, rawShare('agent', agent.sk, E, 255), false);
add('t-256', 't=256 is invalid (would wrap to 0).', 'agent', E, 256, rawShare('agent', agent.sk, E, 0), false);
add('t-257', 't=257 is invalid (would wrap to 1).', 'agent', E, 257, rawShare('agent', agent.sk, E, 1), false);
add('t-negative', 't=-1 is invalid.', 'agent', E, -1, rawShare('agent', agent.sk, E, 0xff), false);
add('t-fraction', 't=1.5 is invalid.', 'agent', E, 1.5, rawShare('agent', agent.sk, E, 1), false);

// ------------------------------------------------------------------ signer_set_hash
const signerSetHash = [];
const addHash = (name, ss) => signerSetHash.push({ name: 'r6-' + name, signer_set: ss, hash: pca.b64u(pca.signerSetHash(ss)) });
addHash('ed-only', E);
addHash('ed-only-reordered', [E[2], E[0], E[1]]);
addHash('with-pq', S);
addHash('with-empty-pq_pk', [{ role: 'agent', publicKey: agent.pub, pq_pk: '' }, E[1], E[2]]);
addHash('nonbmp-vs-bmp-high-roles', [{ role: '￿', publicKey: stranger.pub }, { role: '\u{1F600}', publicKey: guardian.pub }, { role: '', publicKey: agent.pub }]);
addHash('nonbmp-vs-bmp-high-keys', [{ role: 'agent', publicKey: '￿' }, { role: 'agent', publicKey: '\u{10000}' }]);
addHash('extra-field-ignored', [{ role: 'agent', publicKey: agent.pub, label: 'x' }, E[1], E[2]]);
addHash('duplicate', [...E, E[0]]);
if (signerSetHash[0].hash !== signerSetHash[1].hash) throw new Error('signerSetHash is not order-insensitive');
if (signerSetHash[0].hash !== signerSetHash[6].hash) throw new Error('extra field changed signerSetHash');

// ------------------------------------------------------------------ malformed (R6-05)
const malformed = [];
const CAP = 'atlas-pca/cap/v1\0';
/** Sign an arbitrary (possibly ill-typed) hop body with `sk`, exactly as the reference signs a capability. */
function signHop(body, sk) {
  const digest = pca.hashCanonical({ issuer: body.issuer, holder: body.holder, caveats: body.caveats, parent: body.parent ?? null, ...(body.holder_pq !== undefined ? { holder_pq: body.holder_pq } : {}) });
  const msg = new Uint8Array([...pca.utf8(CAP), ...pca.unb64u(digest)]);
  return { id: digest, ...body, body_digest: digest, sig: pca.b64u(pca.sign(sk, msg)) };
}
const root = pca.mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats: [{ type: 'max_spend', usd: 100 }] });
const hop1 = pca.delegate(root, stranger.pub, [{ type: 'resource_prefix', prefix: 'db/' }], agent.sk);
const good = pca.verifyChain([root, hop1], principal.pub);
if (!good.ok) throw new Error('baseline chain does not verify: ' + good.reason);
const mChain = (name, description, chain) => {
  let r;
  try { r = pca.verifyChain(chain, principal.pub); } catch (e) { throw new Error(`malformed chain ${name}: reference THREW ${e}`); }
  if (r.ok) throw new Error(`malformed chain ${name}: reference ACCEPTED`);
  malformed.push({ name: 'r6-chain-' + name, description, api: 'chain', input: { chain, expected_root_issuer: principal.pub }, ts_reason: r.reason });
};
const clone = cloneJson; // JSON deep copy that keeps -0 (conformance-io.mjs)
const withHop = (f) => { const c = clone([root, hop1]); f(c); return c; };
mChain('hop1-string', 'hop 1 is a string.', [root, 'x']);
mChain('hop1-null', 'hop 1 is null.', [root, null]);
mChain('hop1-number', 'hop 1 is a number.', [root, 5]);
mChain('hop1-array', 'hop 1 is an array.', [root, []]);
mChain('hop1-bool', 'hop 1 is a boolean.', [root, true]);
mChain('root-null', 'the root is null.', [null]);
mChain('root-string', 'the root is a string.', ['x']);
mChain('root-array-chain-of-arrays', 'chain of arrays.', [[], []]);
mChain('hop1-parent-null', 'hop 1 parent is null.', withHop((c) => { c[1].parent = null; }));
mChain('hop1-parent-number', 'hop 1 parent is a number.', withHop((c) => { c[1].parent = 7; }));
mChain('root-no-caveats', 'root without caveats.', withHop((c) => { delete c[0].caveats; }));
mChain('root-caveats-number', 'root caveats is a number.', withHop((c) => { c[0].caveats = 5; }));
mChain('hop1-caveats-null', 'hop 1 caveats is null.', withHop((c) => { c[1].caveats = null; }));
mChain('hop1-caveats-string', 'hop 1 caveats is a string.', withHop((c) => { c[1].caveats = 'abc'; }));
mChain('hop1-caveat-array', 'hop 1 caveat element is an array.', withHop((c) => { c[1].caveats = [[]]; }));
mChain('root-issuer-list', 'root issuer is a list.', withHop((c) => { c[0].issuer = ['a']; }));
mChain('root-issuer-number', 'root issuer is a number.', withHop((c) => { c[0].issuer = 1e300; }));
mChain('hop1-alg-list', 'hop 1 alg is a list.', withHop((c) => { c[1].alg = ['x']; }));
mChain('hop1-holder-pq-number', 'hop 1 holder_pq is a number.', withHop((c) => { c[1].holder_pq = 5; }));
mChain('hop1-sig-number', 'hop 1 sig is a number.', withHop((c) => { c[1].sig = Number(2n ** 53n); })); // 2^53 = 9007199254740992 (exact), the first integer past MAX_SAFE_INTEGER
mChain('hop1-sig-truncated', 'hop 1 sig is truncated base64url.', withHop((c) => { c[1].sig = c[1].sig.slice(0, 30); }));
mChain('hop1-body-digest-truncated', 'hop 1 body_digest is truncated base64url.', withHop((c) => { c[1].body_digest = c[1].body_digest.slice(0, 5); c[1].id = c[1].body_digest; }));
mChain('hop1-body-digest-number', 'hop 1 body_digest is a number.', withHop((c) => { c[1].body_digest = 12; c[1].id = 12; }));
mChain('root-id-number', 'root id is a number.', withHop((c) => { c[0].id = 3; }));
mChain('hop1-pq_pk-number', 'hop 1 pq_pk is a number.', withHop((c) => { c[1].pq_pk = 3; }));
mChain('hop1-huge-int-caveat', 'hop 1 caveat carries a float far outside the safe-integer range.', withHop((c) => { c[1].caveats.push({ type: 'max_spend', usd: 1e300 }); }));
// validly SIGNED hops whose content is ill-typed: only the type check rejects them
const signedHop1 = (caveats, extra = {}) => signHop({ issuer: agent.pub, holder: stranger.pub, caveats: [...root.caveats, ...caveats], parent: pca.capHash(root), ...extra }, agent.sk);
mChain('signed-hop1-caveat-number', 'A correctly SIGNED hop 1 whose caveat element is a number: ill-typed, refused.', [root, signedHop1([5])]);
mChain('signed-hop1-caveat-null', 'A correctly SIGNED hop 1 whose caveat element is null: refused.', [root, signedHop1([null])]);
mChain('signed-hop1-caveat-array', 'A correctly SIGNED hop 1 whose caveat element is an array: refused.', [root, signedHop1([['type', 'x']])]);
mChain('signed-hop1-caveat-no-type', 'A correctly SIGNED hop 1 whose caveat has no type: refused.', [root, signedHop1([{ note: 1 }])]);
mChain('signed-hop1-caveat-type-number', 'A correctly SIGNED hop 1 whose caveat type is a number: refused.', [root, signedHop1([{ type: 5 }])]);
mChain('signed-hop1-holder-pq-number', 'A correctly SIGNED hop 1 whose holder_pq is a number: refused.', [root, signedHop1([], { holder_pq: 5 })]);
mChain('signed-hop1-holder-number', 'A correctly SIGNED hop 1 whose holder is a number: refused.', [root, signHop({ issuer: agent.pub, holder: 5, caveats: root.caveats, parent: pca.capHash(root) }, agent.sk)]);
{
  const r0 = signHop({ issuer: principal.pub, holder: agent.pub, caveats: [{ type: 'max_spend', usd: 100 }, 5] }, principal.sk);
  mChain('signed-root-caveat-number', 'A correctly SIGNED root whose caveat element is a number: refused.', [r0]);
  const r1 = signHop({ issuer: principal.pub, holder: agent.pub, caveats: { type: 'max_spend' } }, principal.sk);
  mChain('signed-root-caveats-object', 'A correctly SIGNED root whose caveats is an object: refused.', [r1]);
}
const mShare = (name, description, input) => {
  let ok;
  try {
    const e = input;
    const isObj = e !== null && typeof e === 'object' && !Array.isArray(e);
    ok = isObj && truth(e.role, e.signer_set, e.t, e.share, e.threshold_message).valid;
  } catch (err) { throw new Error(`malformed threshold_share ${name}: reference THREW ${err}`); }
  if (ok) throw new Error(`malformed threshold_share ${name}: reference ACCEPTED`);
  malformed.push({ name: 'r6-share-' + name, description, api: 'threshold_share', input });
};
const goodEntry = { role: 'agent', t: 1, signer_set: E, threshold_message: pca.b64u(thMsg), share: sh('agent', agent.sk, E, 1) };
if (!truth('agent', E, 1, goodEntry.share, goodEntry.threshold_message).valid) throw new Error('baseline share does not verify');
mShare('entry-null', 'entry is null.', null);
mShare('entry-number', 'entry is a number.', 5);
mShare('entry-string', 'entry is a string.', 'x');
mShare('entry-array', 'entry is an array.', [goodEntry]);
mShare('entry-empty', 'entry is {}.', {});
for (const k of ['role', 't', 'signer_set', 'threshold_message', 'share']) mShare('missing-' + k, `entry without ${k}.`, (({ [k]: _, ...rest }) => rest)(goodEntry));
mShare('role-number', 'role is a number.', { ...goodEntry, role: 1 });
mShare('t-string', 't is a string.', { ...goodEntry, t: '1' });
mShare('t-bool', 't is a boolean.', { ...goodEntry, t: true });
mShare('t-float-huge', 't is 1e300.', { ...goodEntry, t: 1e300 });
mShare('t-above-safe-int', 't is 2^53+2.', { ...goodEntry, t: 9007199254740994 });
mShare('t-null', 't is null.', { ...goodEntry, t: null });
mShare('signer-set-null', 'signer_set is null.', { ...goodEntry, signer_set: null });
mShare('signer-set-object', 'signer_set is an object.', { ...goodEntry, signer_set: { agent: agent.pub } });
mShare('signer-set-numbers', 'signer_set holds numbers.', { ...goodEntry, signer_set: [1, 2, 3] });
mShare('signer-set-empty', 'signer_set is empty.', { ...goodEntry, signer_set: [] });
mShare('threshold-message-number', 'threshold_message is a number.', { ...goodEntry, threshold_message: 5 });
mShare('threshold-message-truncated', 'threshold_message is truncated base64url (bad length).', { ...goodEntry, threshold_message: 'A' });
mShare('threshold-message-noncanonical', 'threshold_message is non-canonical base64url.', { ...goodEntry, threshold_message: pca.b64u(thMsg).slice(0, -1) + '/' });
mShare('share-null', 'share is null.', { ...goodEntry, share: null });
mShare('share-string', 'share is a string.', { ...goodEntry, share: 'x' });
mShare('share-array', 'share is an array.', { ...goodEntry, share: [goodEntry.share] });
mShare('share-sig-number', 'share.sig is a number.', { ...goodEntry, share: { ...goodEntry.share, sig: 5 } });
mShare('share-sig-truncated', 'share.sig is truncated base64url.', { ...goodEntry, share: { ...goodEntry.share, sig: goodEntry.share.sig.slice(0, 20) } });
mShare('share-sig-null', 'share.sig is null.', { ...goodEntry, share: { ...goodEntry.share, sig: null } });
mShare('share-publicKey-number', 'share.publicKey is a number.', { ...goodEntry, share: { ...goodEntry.share, publicKey: 5 } });
mShare('share-publicKey-truncated', 'share.publicKey is truncated base64url.', { ...goodEntry, share: { ...goodEntry.share, publicKey: agent.pub.slice(0, 10) } });
mShare('share-alg-number', 'share.alg is a number.', { ...goodEntry, share: { ...goodEntry.share, alg: 5 } });
mShare('share-alg-unknown', 'share.alg is unknown.', { ...goodEntry, share: { ...goodEntry.share, alg: 'rsa' } });
mShare('share-pq_sig-number', 'share.pq_sig is a number on a hybrid share.', { ...goodEntry, share: { ...goodEntry.share, alg: hyb, pq_sig: 5 } });
mShare('share-pq_sig-truncated', 'share.pq_sig is truncated base64url on a hybrid share over a pq set.', { role: 'agent', t: 1, signer_set: S, threshold_message: pca.b64u(thMsg), share: (() => { const h = sh('agent', agent.sk, S, 1, { alg: hyb, mlDsa: aMl }); return { ...h, pq_sig: h.pq_sig.slice(0, 50) }; })() });
mShare('share-role-number', 'share.role is a number.', { ...goodEntry, share: { ...goodEntry.share, role: 1 } });

const mText = (name, description, text) => {
  // the reference: strict parse (failure == deny), then verifyPCActnCore
  malformed.push({ name: 'r6-pcactn-' + name, description, api: 'pcactn_json', input: { text, grant: root, now: 1_800_000_000_000, aud: 'rs-conformance' } });
};
mText('null', 'the PCActn document is null.', 'null');
mText('number', 'the PCActn document is a number.', '5');
mText('huge-int', 'the PCActn document is a 40-digit integer.', '1234567890123456789012345678901234567890');
mText('array', 'the PCActn document is an array.', '[]');
mText('string', 'the PCActn document is a string.', '"x"');
mText('empty-object', 'the PCActn document is {}.', '{}');
mText('truncated', 'the PCActn document is truncated JSON.', '{"ver":2,"action":{"verb":"read"');
mText('cap-chain-null-hop', 'cap_chain holds null.', '{"ver":2,"cap_chain":[null]}');
mText('cap-chain-number', 'cap_chain is a number.', '{"ver":2,"cap_chain":5}');
mText('threshold-shares-number', 'threshold.shares holds a number.', '{"ver":2,"threshold":{"shares":[5]}}');
mText('counter-huge', 'counter is a 30-digit integer.', '{"ver":2,"counter":123456789012345678901234567890}');
mText('iat-float-huge', 'iat is 1e308.', '{"ver":2,"iat":1e308}');
mText('sig-truncated', 'sig is truncated base64url.', '{"ver":2,"sig":"AAA"}');
for (const m of malformed.filter((x) => x.api === 'pcactn_json')) {
  let tree;
  try { tree = pca.strictParse(m.input.text); } catch { continue; } // parse failure == deny
  let r;
  try { r = await pca.verifyPCActnCore(tree, { grant: root, nowEpoch: m.input.now, audience: m.input.aud }); } catch (e) { throw new Error(`malformed pcactn ${m.name}: reference THREW ${e}`); }
  if (r.allow) throw new Error(`malformed pcactn ${m.name}: reference ALLOWED`);
}

// ------------------------------------------------------------------ splice (idempotent)
const file = readCore();
file.primitives.threshold_set = thresholdSet;
file.primitives.signer_set_hash = signerSetHash;
file.primitives.malformed = malformed;
writeCore(file);
console.log(`threshold_set ${thresholdSet.length} (${thresholdSet.filter((x) => x.valid).length} valid), signer_set_hash ${signerSetHash.length}, malformed ${malformed.length}`);
for (const c of thresholdSet) console.log((c.valid ? 'VALID  ' : 'reject ') + c.name + (c.ts_reason ? '  (' + c.ts_reason + ')' : ''));
