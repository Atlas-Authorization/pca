// Stage 7 of the conformance pipeline (run AFTER gen-conformance-mut.mjs; idempotent): the 0.4.1 coverage.
//
//   vectors[]  r041-share-*     threshold share signatures validated PER SUITE on the wire (a pure post-quantum share used to
//                               be refused: `wire` demanded a 64-byte share `sig`). Full PCActns, core verdict, `requires`
//                               naming the first non-ed25519 share suite of every positive (and, for a wire negative, a
//                               suite that is not one every native implements).
//   primitives.caveat_eval[]    root caveats are policy (SECURITY fix): caveats placed on the root grant outside the envelope
//                               are evaluated exactly like the caveats delegation hops append. Each entry
//                               { name, description, grant, chain, context, expect: { allow, failed } }: a runner evaluates
//                               policy_caveats(grant, chain) = the grant's caveats minus its FIRST `envelope` caveat, then the
//                               leaf's caveats beyond the grant's, with the caveat evaluator over `context`, and must reproduce
//                               `allow` (every caveat satisfied) and `failed` (the unsatisfied types, in order). Only the
//                               baseline caveat types are used (expires, not_before, rate, max_blast_radius, reversibility_max,
//                               delegation_depth, budget_alloc, max_spend); any other type is unsatisfied (fail closed).
//   primitives.pca_header[]     { name, description, input, valid, text? }: the PCA-Action header value is strict unpadded
//                               base64url of UTF-8 text; `valid` iff the decoder accepts it, `text` the decoded text.
//
//     node packages/pca/scripts/gen-conformance-041.mjs
import { createHash } from 'node:crypto';
import * as pca from '../dist/index.js';
import { cloneJson, readCore, writeCore } from './conformance-io.mjs';

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pub: pca.b64u(pca.publicKeyOf(sk)) }; };
const principal = mk('principal'), agent = mk('agent'), sub = mk('subagent');
const g = mk('r041/guardian');
const clone = cloneJson; // JSON deep copy that keeps -0 (conformance-io.mjs)
const NOW = 1_800_000_000_000;
const AUD = 'rs-conformance';
const CHECKS = ['version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter'];
const KEYMAP = { chain: 'cap_chain' };
/** suites every native implements (when its runtime has the backend); a wire negative under anything else is `requires: <alg>`. */
const CROSS = new Set(['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65']);

// ------------------------------------------------------------------ vectors[]: per-suite share wire
const root = pca.mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats: [{ type: 'max_spend', usd: 100 }] });
const plan = [{ id: 'only', verb: 'read', resource: 'db/users' }];
const base = pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root], plan, nodeId: 'only', params: {}, counter: 1, signerSecret: agent.sk });
const msg = pca.thresholdMessage(base);
const gMl65 = pca.mlDsa65Keygen(seed('r041/g-ml65'));
const gMl87 = pca.mlDsa87Keygen(seed('r041/g-ml87'));
const gSlh = pca.slhDsa128fKeygen(new Uint8Array(createHash('sha512').update('atlas-pca-conformance/r041/g-slh').digest()).slice(0, 48));
const setFor = (pq) => [{ role: 'agent', publicKey: agent.pub }, { role: 'guardian', publicKey: g.pub, ...(pq ? { pq_pk: pq } : {}) }];
const share = (suite, pq) => pca.signShare('guardian', g.sk, msg, { signerSet: setFor(pq), t: 2 }, suite);
const ml65 = share({ alg: 'ml-dsa-65', mlDsa: gMl65 }, pca.b64u(gMl65.publicKey));
const hyb65 = share({ alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: gMl65 }, pca.b64u(gMl65.publicKey));
const ml87 = share({ alg: 'ml-dsa-87', mlDsa87: gMl87 }, pca.b64u(gMl87.publicKey));
const slh = share({ alg: 'slh-dsa-sha2-128f', slhDsa: gSlh }, pca.b64u(gSlh.publicKey));
const ed = share(undefined, undefined);
const fill = (n, b = 3) => pca.b64u(new Uint8Array(n).fill(b));

const vectors = [];
async function add(name, description, shares, must) {
  const pcactn = { ...clone(base), threshold: { shares } };
  const r = await pca.verifyPCActnCore(pcactn, { grant: root, nowEpoch: NOW, audience: AUD });
  const c = r.checks;
  const checks = {};
  if (c.wire === 'fail') checks.wire = false;
  else { checks.wire = true; for (const k of CHECKS) checks[k] = c[KEYMAP[k] ?? k] === 'pass'; }
  const ok = must === 'allow' ? r.allow === true : checks.wire === false && r.allow === false;
  if (!ok) throw new Error(`vector r041-${name}: reference ${JSON.stringify(checks)} allow=${r.allow} does not meet intent ${must} (${r.reason ?? ''})`);
  // Suite capability: a positive needs a genuine verdict under every suite its shares use, so it names the first non-ed25519
  // one (a runner whose runtime lacks it - e.g. Ruby / Python / .NET on an OpenSSL without ML-DSA - asserts the
  // unsupported_suite refusal instead of comparing). A terminal {wire:false} negative is compared everywhere, so it names
  // only a suite outside CROSS.
  const algs = shares.map((s) => (s && typeof s.alg === 'string' && pca.isKnownSigAlg(s.alg) ? s.alg : 'ed25519'))
    .filter((a) => (must === 'allow' ? a !== 'ed25519' : !CROSS.has(a)));
  vectors.push({
    name: 'r041-share-' + name, ...(algs.length ? { requires: algs[0] } : {}), class: r.allow ? 'positive' : 'negative', description,
    grant: root, plan_nodes: plan, context: { now: NOW, aud: AUD }, pcactn, expect: { allow: r.allow === true, checks },
  });
}
await add('ml-dsa-65-carried', 'A pure ML-DSA-65 guardian share (3309-byte sig) in threshold.shares: wire accepts it (0.4.1; it used to demand 64 bytes).', [ml65], 'allow');
await add('hybrid-ml-dsa-65-carried', 'A hybrid-ed25519-ml-dsa-65 share: 64-byte sig + 3309-byte pq_sig.', [hyb65], 'allow');
await add('ed25519-and-ml-dsa-65', 'An ed25519 share and a pure ML-DSA-65 share side by side.', [ed, ml65], 'allow');
await add('ml-dsa-65-pq_pk-echo', 'A pure ML-DSA-65 share carrying a pq_pk echo: the echo is judged by the threshold check, not wire.', [{ ...ml65, pq_pk: pca.b64u(gMl65.publicKey) }], 'allow');
await add('ml-dsa-87-carried', 'A pure ML-DSA-87 share (4627-byte sig).', [ml87], 'allow');
await add('slh-dsa-128f-carried', 'A pure SLH-DSA-SHA2-128f share (17088-byte sig).', [slh], 'allow');
await add('ml-dsa-65-3308', 'An ml-dsa-65 share whose sig is 3308 bytes: wire fails.', [{ ...ml65, sig: fill(3308) }], 'wire');
await add('ml-dsa-65-3310', 'An ml-dsa-65 share whose sig is 3310 bytes: wire fails.', [{ ...ml65, sig: fill(3310) }], 'wire');
await add('ml-dsa-65-64', 'An ml-dsa-65 share whose sig is 64 bytes (the old fixed length): wire fails.', [{ ...ml65, sig: fill(64) }], 'wire');
await add('ed25519-3309', 'An ed25519 share (no alg) whose sig is 3309 bytes: wire fails (ed25519 stays 64 bytes).', [{ ...ed, sig: fill(3309) }], 'wire');
await add('ed25519-explicit-3309', 'An explicit "alg":"ed25519" share whose sig is 3309 bytes: wire fails.', [{ ...ed, alg: 'ed25519', sig: fill(3309) }], 'wire');
await add('hybrid-missing-pq_sig', 'A hybrid share without pq_sig: wire fails.', [(({ pq_sig: _p, ...x }) => x)(hyb65)], 'wire');
await add('hybrid-pq_sig-3308', 'A hybrid share whose pq_sig is 3308 bytes: wire fails.', [{ ...hyb65, pq_sig: fill(3308) }], 'wire');
await add('hybrid-sig-3309', 'A hybrid share whose Ed25519 sig is 3309 bytes: wire fails.', [{ ...hyb65, sig: fill(3309) }], 'wire');
await add('ed25519-stray-pq_sig', 'An ed25519 share carrying pq_sig: wire fails.', [{ ...ed, pq_sig: fill(3309) }], 'wire');
await add('ml-dsa-65-stray-pq_sig', 'A pure ml-dsa-65 share carrying pq_sig: wire fails.', [{ ...ml65, pq_sig: fill(3309) }], 'wire');
await add('unknown-alg', 'A share with an unregistered alg: wire fails.', [{ ...ml65, alg: 'ml-dsa-66' }], 'wire');
await add('alg-number', 'A share whose alg is a number: wire fails.', [{ ...ml65, alg: 65 }], 'wire');
await add('alg-null', 'A share whose alg is null: wire fails.', [{ ...ed, alg: null }], 'wire');
await add('ml-dsa-65-padded', 'An ml-dsa-65 share whose sig carries base64 padding: wire fails.', [{ ...ml65, sig: ml65.sig + '=' }], 'wire');

// ------------------------------------------------------------------ primitives.caveat_eval: root caveats are policy
const ENV = { type: 'envelope', goal_commit: pca.b64u(new Uint8Array(32)), predicates: [{ verb: '*', resource: '*' }], caveats: [], agent_binding: {}, risk_policy: pca.DEFAULT_RISK_POLICY };
const grantWith = (caveats) => pca.mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats });
const hop = (parent, caveats) => pca.delegate(parent, sub.pub, caveats, agent.sk);
const caveatEval = [];
function cav(name, description, rootCaveats, hopCaveats, ctx, intended) {
  const grant = grantWith(rootCaveats);
  const chain = hopCaveats === null ? [grant] : [grant, hop(grant, hopCaveats)];
  const context = {
    now: NOW,
    delegation_depth: chain.length - 1,
    ...ctx,
    action: { verb: 'pay', resource: 'invoice:42', reversibility_class: 'reversible', params: {}, ...(ctx.action ?? {}) },
  };
  // reference: the policy layer's caveat list (root minus its first envelope, then the hops' appended ones), agent-native evaluator
  const caveats = pca.policyCaveats(grant, chain);
  const base = {
    now: context.now,
    delegationDepth: context.delegation_depth,
    ...(context.blast_radius !== undefined ? { blastRadius: context.blast_radius } : {}),
    ...(context.reversibility_class !== undefined ? { reversibilityClass: context.reversibility_class } : {}),
    ...(context.recent_action_times !== undefined ? { recentActionTimes: context.recent_action_times } : {}),
  };
  const r = pca.evaluateAgentCaveats(caveats, base, { action: context.action });
  if (r.ok !== intended) throw new Error(`caveat_eval r041-${name}: reference ok=${r.ok} (${r.failed.join(',')}) != intended ${intended}`);
  caveatEval.push({ name: 'r041-' + name, description, grant, chain, context, expect: { allow: r.ok, failed: r.failed } });
}
const MAX = { type: 'max_spend', usd: 100 };
const amt = (amount, extra = {}) => ({ action: { params: { amount, ...extra } } });
cav('root-max-spend-exceeded', 'Root max_spend 100 (outside any envelope), the action spends 150: DENIED (0.4.1 security fix: root caveats were never evaluated).', [MAX], [], amt(150), false);
cav('root-max-spend-within', 'Root max_spend 100, the action spends 100: ALLOWED.', [MAX], [], amt(100), true);
cav('root-max-spend-exceeded-root-only', 'Root max_spend 100 and no delegation hop, the action spends 100.5: DENIED.', [MAX], null, amt(100.5), false);
cav('root-max-spend-within-root-only', 'Root max_spend 100 and no delegation hop, the action spends 0: ALLOWED.', [MAX], null, amt(0), true);
cav('root-max-spend-currency-usd', 'currency "usd" is accepted.', [MAX], [], amt(50, { currency: 'usd' }), true);
cav('root-max-spend-currency-USD', 'currency "USD" is accepted.', [MAX], [], amt(50, { currency: 'USD' }), true);
cav('root-max-spend-currency-eur', 'currency "eur": unsatisfied.', [MAX], [], amt(50, { currency: 'eur' }), false);
cav('root-max-spend-currency-mixed-case', 'currency "Usd": unsatisfied (only "usd" / "USD").', [MAX], [], amt(50, { currency: 'Usd' }), false);
cav('root-max-spend-currency-null', 'currency null: unsatisfied.', [MAX], [], amt(50, { currency: null }), false);
cav('root-max-spend-no-amount', 'The action carries no amount: unsatisfied (fail closed).', [MAX], [], { action: { params: {} } }, false);
cav('root-max-spend-string-amount', 'amount "50" (a string): unsatisfied.', [MAX], [], amt('50'), false);
cav('root-max-spend-negative-amount', 'amount -1: unsatisfied.', [MAX], [], amt(-1), false);
cav('root-max-spend-params-array', 'params is an array: unsatisfied.', [MAX], [], { action: { params: [] } }, false);
cav('root-max-spend-limit-string', 'usd "100" (a string): unsatisfied.', [{ type: 'max_spend', usd: '100' }], [], amt(1), false);
cav('root-max-spend-limit-negative', 'usd -1: unsatisfied.', [{ type: 'max_spend', usd: -1 }], [], amt(0), false);
cav('root-max-spend-limit-missing', 'max_spend without usd: unsatisfied.', [{ type: 'max_spend' }], [], amt(0), false);
cav('root-max-spend-fraction', 'usd 0.5, amount 0.5: satisfied (inclusive).', [{ type: 'max_spend', usd: 0.5 }], [], amt(0.5), true);
cav('root-note-fail-closed', 'An unknown root caveat type ("note") is unsatisfied, exactly as on a hop.', [MAX, { type: 'note', text: 'n' }], [], amt(1), false);
cav('root-envelope-skipped', 'The FIRST envelope caveat is the policy container, not a caveat: it is skipped; the max_spend after it applies.', [ENV, MAX], [], amt(100), true);
cav('root-envelope-skipped-exceeded', 'Envelope first, root max_spend 100 after it, the action spends 101: DENIED.', [ENV, MAX], [], amt(101), false);
cav('root-second-envelope', 'A second envelope caveat on the root is an unknown caveat: unsatisfied.', [ENV, ENV], [], amt(1), false);
cav('root-envelope-not-first', 'A root caveat before the envelope is evaluated too.', [MAX, ENV], [], amt(101), false);
cav('hop-tighter', 'Root max_spend 100, hop max_spend 20, the action spends 50: the hop caveat denies.', [MAX], [{ type: 'max_spend', usd: 20 }], amt(50), false);
cav('root-tighter', 'Root max_spend 20, hop max_spend 100, the action spends 50: the root caveat denies.', [{ type: 'max_spend', usd: 20 }], [MAX], amt(50), false);
cav('both-within', 'Root max_spend 100, hop max_spend 20, the action spends 20: ALLOWED.', [MAX], [{ type: 'max_spend', usd: 20 }], amt(20), true);
cav('root-expires-past', 'Root expires at now: unsatisfied (now < at).', [{ type: 'expires', at: NOW }], [], {}, false);
cav('root-expires-future', 'Root expires one ms after now: satisfied.', [{ type: 'expires', at: NOW + 1 }], [], {}, true);
cav('root-not-before-future', 'Root not_before one ms after now: unsatisfied.', [{ type: 'not_before', at: NOW + 1 }], [], {}, false);
cav('root-not-before-now', 'Root not_before at now: satisfied.', [{ type: 'not_before', at: NOW }], [], {}, true);
cav('root-max-blast-radius', 'Root max_blast_radius 0.5 with context blast_radius 0.6: unsatisfied.', [{ type: 'max_blast_radius', max: 0.5 }], [], { blast_radius: 0.6 }, false);
cav('root-max-blast-radius-ok', 'Root max_blast_radius 0.5 with context blast_radius 0.5: satisfied.', [{ type: 'max_blast_radius', max: 0.5 }], [], { blast_radius: 0.5 }, true);
cav('root-max-blast-radius-missing', 'Root max_blast_radius without a context blast_radius: unsatisfied.', [{ type: 'max_blast_radius', max: 0.5 }], [], {}, false);
cav('root-reversibility-max', 'Root reversibility_max "reversible", context class "irreversible": unsatisfied.', [{ type: 'reversibility_max', class: 'reversible' }], [], { reversibility_class: 'irreversible' }, false);
cav('root-reversibility-max-ok', 'Root reversibility_max "rate_limited", context class "reversible": satisfied.', [{ type: 'reversibility_max', class: 'rate_limited' }], [], { reversibility_class: 'reversible' }, true);
cav('root-delegation-depth', 'Root delegation_depth max 0 with one hop (depth 1): unsatisfied.', [{ type: 'delegation_depth', max: 0 }], [], {}, false);
cav('root-delegation-depth-ok', 'Root delegation_depth max 1 with one hop: satisfied.', [{ type: 'delegation_depth', max: 1 }], [], {}, true);
cav('root-rate', 'Root rate 2 per 60 s with two actions in the window: unsatisfied.', [{ type: 'rate', max: 2, per_secs: 60 }], [], { recent_action_times: [NOW - 1000, NOW - 59_999] }, false);
cav('root-rate-ok', 'Root rate 2 per 60 s with one action in the window (one exactly at the edge, excluded): satisfied.', [{ type: 'rate', max: 2, per_secs: 60 }], [], { recent_action_times: [NOW - 1000, NOW - 60_000] }, true);
cav('root-rate-missing', 'Root rate without recent_action_times: unsatisfied.', [{ type: 'rate', max: 2, per_secs: 60 }], [], {}, false);
cav('root-budget-alloc', 'Root budget_alloc 10: satisfied (its consumption is metered elsewhere).', [{ type: 'budget_alloc', limit: 10 }], [], {}, true);
cav('root-failed-order', 'Every unsatisfied type is listed in order: root first, then the hop.', [{ type: 'note' }, MAX], [{ type: 'expires', at: NOW }], amt(500), false);

// ------------------------------------------------------------------ primitives.pca_header: strict unpadded base64url of UTF-8
const pcaHeader = [];
const enc = new TextEncoder();
function hdr(name, description, input, intended) {
  let valid = true, text;
  try { text = pca.decodePcaHeader(input); } catch { valid = false; }
  if (valid !== intended) throw new Error(`pca_header r041-${name}: reference valid=${valid} != intended ${intended}`);
  pcaHeader.push({ name: 'r041-' + name, description, input, valid, ...(valid ? { text } : {}) });
}
const pText = pca.encodePCActn(base);
const good = pca.pcaHeaders(pText)['PCA-Action'];
const b64 = (s) => Buffer.from(s).toString('base64');
const b64ub = (bytes) => Buffer.from(bytes).toString('base64url');
const must = (cond, what) => { if (!cond) throw new Error(`pca_header fixture: ${what}`); };
must(/[-_]/.test(b64ub(enc.encode('"?>?~~~"'))), 'url-alphabet carries - or _');
must(b64('"???"').includes('/'), 'standard-slash carries /');
must(b64('"~~~>"').includes('+'), 'standard-plus carries +');
hdr('pcactn', 'The canonical header for a real PCActn.', good, true);
hdr('json-1', '{"a":1} (7 bytes, 10 chars).', b64ub(enc.encode('{"a":1}')), true);
hdr('json-2', '{"a":12} (8 bytes, 11 chars).', b64ub(enc.encode('{"a":12}')), true);
hdr('json-3', '{"a":123} (9 bytes, 12 chars).', b64ub(enc.encode('{"a":123}')), true);
hdr('url-alphabet', 'Bytes that use "-" and "_" (?>? and ~~~ in UTF-8 text).', b64ub(enc.encode('"?>?~~~"')), true);
hdr('utf8-multibyte', 'Multi-byte UTF-8 text (é, 😀).', b64ub(enc.encode('"é😀"')), true);
hdr('bom-kept', 'A leading BOM is decoded and kept (the strict JSON parser then refuses it).', b64ub(enc.encode('﻿{}')), true);
hdr('padding-1', 'One "=" pad on a 10-char value: refused.', b64ub(enc.encode('{"a":12}')) + '=', false);
hdr('padding-2', '"==" padding: refused.', b64ub(enc.encode('{"a":1}')) + '==', false);
hdr('padded-standard', 'Standard base64 with padding: refused.', b64('{"a":1}'), false);
hdr('standard-slash', 'Standard alphabet "/": refused.', b64('"???"').replace(/=+$/, ''), false);
hdr('standard-plus', 'Standard alphabet "+": refused.', b64('"~~~>"').replace(/=+$/, ''), false);
hdr('leading-space', 'A leading space: refused.', ' ' + b64ub(enc.encode('{}')), false);
hdr('trailing-space', 'A trailing space: refused.', b64ub(enc.encode('{}')) + ' ', false);
hdr('trailing-tab', 'A trailing TAB: refused.', b64ub(enc.encode('{}')) + '\t', false);
hdr('inner-space', 'A space inside: refused.', 'eyJh IjoxfQ', false);
hdr('inner-newline', 'A line break inside: refused.', 'eyJhIjox\nfQ', false);
hdr('invalid-char', 'A "*" inside: refused.', 'eyJhIjox*fQ', false);
hdr('dot', 'A "." inside: refused.', 'eyJhIjox.fQ', false);
hdr('len-mod-4-is-1', 'Length 5 (mod 4 == 1): refused.', 'eyJhI', false);
hdr('noncanonical-bits-2', 'Non-zero unused bits in a 2-char tail ("QR"): refused.', 'QR', false);
hdr('noncanonical-bits-3', 'Non-zero unused bits in a 3-char tail ("QUJ"): refused.', 'QUJ', false);
hdr('empty', 'The empty value: refused.', '', false);
hdr('invalid-utf8', 'Bytes FF FE 7B (not UTF-8): refused.', b64ub([0xff, 0xfe, 0x7b]), false);
hdr('overlong-utf8', 'Overlong UTF-8 C0 AF: refused.', b64ub([0x22, 0xc0, 0xaf, 0x22]), false);
hdr('surrogate-utf8', 'A UTF-16 surrogate encoded as UTF-8 (ED A0 80): refused.', b64ub([0x22, 0xed, 0xa0, 0x80, 0x22]), false);
hdr('truncated-utf8', 'A truncated multi-byte sequence (E2 82): refused.', b64ub([0x22, 0xe2, 0x82]), false);

// ------------------------------------------------------------------ write (idempotent: replace any earlier r041 output)
const core = readCore();
core.vectors = core.vectors.filter((v) => !v.name.startsWith('r041-')).concat(vectors);
core.primitives.caveat_eval = caveatEval;
core.primitives.pca_header = pcaHeader;
writeCore(core);
console.log(`r041: ${vectors.length} share vectors, ${caveatEval.length} caveat_eval, ${pcaHeader.length} pca_header`);
