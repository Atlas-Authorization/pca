// conformance/caveat-lang-vectors.json: caveat language v2 (track K1): third-party caveats with signed discharges, `sealed`,
// the holder-signed per-action `narrow` block, the lifetime `max_uses` caveat, the bounded `derive` check and `spiffe_bound`.
//
// ONE generator owns the whole file. Every `expect` is computed by the TypeScript reference (caveat-lang.ts) AND asserted against
// the outcome the vector is meant to show (`want`), so neither a reference bug nor a native drift goes unnoticed. The Go, Rust,
// Python, Ruby, PHP, Java, Kotlin, .NET and Swift verifiers replay the same file and must reproduce each expectation, REASON TEXT
// INCLUDED where `reason_contains` is given.
//
//   primitives.discharge_verify  verifyDischarge   { ok, claims? } | { ok: false, reason_contains }
//   primitives.k1_eval           the caveats of policy_caveats(grant, chain) plus a verified narrow block: K1 types by the
//                                caveat language, every other type by the stock evaluator over `context`.
//                                expect { allow, failed } with `failed` SORTED (the types of the unsatisfied caveats)
//   primitives.caveat_shape      the well-formedness of one caveat of a K1 type: { valid }
//   primitives.uses_key          maxUsesSlotKey
//   primitives.uses_reserve      reserveMaxUses against a fresh in-memory replay store: a sequence of calls
//   primitives.spiffe_id         spiffeIdError: { valid }
//   primitives.k1_unconfigured   the same evaluation with NO k1 input at all: every K1 caveat refuses (expect { allow, failed } sorted)
//   primitives.consume_once_ttl  the replay store retention contract: steps { key, retain_until, now } -> 'true' | 'false' | 'error'
//   primitives.k1_headers        presentedK1 over request headers: { ok, value? }
// `requires_suite` names the suite a verifier must implement to reproduce an `ok` entry; one without it answers `unsupported_suite`.
// Deterministic: fixed seeds.
//
//     node packages/pca/scripts/gen-conformance-k1.mjs [--check]                 (reads ../dist)
//     PCA_SRC=1 packages/pca/node_modules/.bin/tsx packages/pca/scripts/gen-conformance-k1.mjs  (reads ../src)
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { confDir, serializeCorpus } from './conformance-io.mjs';

const pca = process.env.PCA_SRC ? await import('../src/index.ts') : await import('../dist/index.js');
const OUT = join(confDir, 'caveat-lang-vectors.json');
const NOW = 1_800_000_000_000;
const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pub: pca.b64u(pca.publicKeyOf(sk)) }; };
const principal = mk('principal'), agent = mk('agent'), sub = mk('subagent'), rogue = mk('rogue');
const human = mk('k1/human'), org = mk('k1/org'), workload = mk('k1/workload'), model = mk('k1/model'), artifact = mk('k9/artifact');
const clone = (x) => JSON.parse(JSON.stringify(x));
const nonce = (n) => pca.b64u(new Uint8Array(16).fill(n));
const dg = (c) => pca.b64u(new Uint8Array(32).fill(c.charCodeAt(0)));
const SPIFFE = 'spiffe://acme.test/ns/prod/runtime';

const pin = (label, cls, who, extra = {}) => ({ label, class: cls, pk: who.pub, ...extra });
const PINS = [pin('risk-team', 'human', human), pin('acme', 'org', org), pin('runtime', 'workload', workload, { spiffe_id: SPIFFE }), pin('screener', 'model', model), pin('provenance', 'artifact', artifact)];
const SIGNER = { 'risk-team': human, acme: org, runtime: workload, screener: model, provenance: artifact };

// ------------------------------------------------------------------ chains
const root = (caveats) => pca.mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats });
const hop = (parent, signer, to, caveats) => pca.delegate(parent, to.pub, caveats, signer.sk);
/** [root] */
const one = (caveats) => { const g = root(caveats); return { grant: g, chain: [g], leafSk: agent.sk }; };
/** root(rootCaveats) -> sub (added) */
const two = (rootCaveats, added) => { const g = root(rootCaveats); const c = hop(g, agent, sub, added); return { grant: g, chain: [g, c], leafSk: sub.sk }; };
/** root -> sub (a1) -> agent again (a2): three hops */
const three = (rootCaveats, a1, a2) => { const g = root(rootCaveats); const c1 = hop(g, agent, sub, a1); const c2 = hop(c1, sub, agent, a2); return { grant: g, chain: [g, c1, c2], leafSk: agent.sk }; };
for (const c of [one([]), two([], []), three([], [], [])]) { const r = pca.verifyChain(c.chain, principal.pub); if (!r.ok) throw new Error(`generator chain does not verify: ${r.reason}`); }

// ------------------------------------------------------------------ caveats and artifacts
const nd = (o = {}) => ({ type: 'needs_discharge', id: 'kyc', issuer: 'risk-team', issuer_class: 'human', bind: 'chain_hop', ttl_ms: 600_000, require: [{ claim: 'kyc_level', op: 'gte', value: 2 }], ...o });
const dis = (cap, o = {}, who, suite) => {
  const body = { v: 1, kind: 'pca-discharge', caveat_id: 'kyc', issuer: 'risk-team', cap_hash: cap, bind: 'chain_hop', claims: { kyc_level: 3 }, iat: NOW - 1000, not_after: NOW + 300_000, nonce: nonce(7), ...o };
  return pca.signDischarge(body, (who ?? SIGNER[body.issuer] ?? rogue).sk, suite);
};
const cap0 = (c) => pca.capHash(c.chain[0]);
const capN = (c, i) => pca.capHash(c.chain[i]);
const leafCap = (c) => pca.capHash(c.chain[c.chain.length - 1]);
const nar = (c, caveats, o = {}, who) => pca.signNarrow({ v: 1, kind: 'pca-narrow', cap_hash: leafCap(c), holder: c.chain[c.chain.length - 1].holder, caveats, iat: NOW - 1000, not_after: NOW + 300_000, nonce: nonce(9), ...o }, who ?? c.leafSk);
const ACTION = (amount, extra = {}) => ({ verb: 'refund', resource: 'orders/42', params: amount === undefined ? {} : { amount }, ...extra });
const ACT_DIGEST = dg('a');

// ------------------------------------------------------------------ discharge_verify
const DV = [];
function dv(name, description, discharge, caveat, binding, want, { requires } = {}) {
  const input = { discharge, caveat, binding: { pins: PINS, now: NOW, ...binding } };
  const r = pca.verifyDischarge(input.discharge, input.caveat, input.binding);
  if (r.ok !== want.ok) throw new Error(`${name}: the reference says ${JSON.stringify(r)}`);
  const expect = { ok: r.ok };
  if (r.ok) { expect.claims = r.claims; expect.digest = r.digest; } else {
    if (!r.reason.includes(want.reason)) throw new Error(`${name}: the reference reason is ${JSON.stringify(r.reason)}, expected it to contain ${JSON.stringify(want.reason)}`);
    expect.reason_contains = want.reason;
  }
  DV.push({ name, description, ...(requires !== undefined ? { requires_suite: requires } : {}), input, expect });
}
{
  const C = one([nd()]);
  const cap = cap0(C);
  const ok = dis(cap);
  const B = { cap_hash: cap };
  dv('dv-valid', 'a bound, signed, in-window chain_hop discharge from the pinned human issuer', ok, nd(), B, { ok: true });
  dv('dv-boundary-iat', 'now == iat is inside', ok, nd(), { ...B, now: NOW - 1000 }, { ok: true });
  dv('dv-boundary-not-after', 'now == not_after is inside', ok, nd(), { ...B, now: NOW + 300_000 }, { ok: true });
  dv('dv-future', 'now before iat', ok, nd(), { ...B, now: NOW - 1001 }, { ok: false, reason: 'from the future' });
  dv('dv-expired', 'now after not_after', ok, nd(), { ...B, now: NOW + 300_001 }, { ok: false, reason: 'has expired' });
  dv('dv-bad-clock', 'a non-integer verifier clock is refused', ok, nd(), { ...B, now: NOW + 0.5 }, { ok: false, reason: 'not a safe integer' });
  dv('dv-ttl-boundary', 'not_after - iat == ttl_ms is accepted', dis(cap, { iat: NOW, not_after: NOW + 600_000 }), nd(), B, { ok: true });
  dv('dv-ttl-exceeded', 'not_after - iat one millisecond over ttl_ms', dis(cap, { iat: NOW, not_after: NOW + 600_001 }), nd(), B, { ok: false, reason: 'lives longer than the caveat allows' });
  dv('dv-lifetime-cap', 'a discharge lives at most 24 h whatever the caveat says', { ...ok, iat: NOW, not_after: NOW + 86_400_001 }, nd({ ttl_ms: 86_400_000 }), B, { ok: false, reason: 'lives at most' });
  dv('dv-rogue-key', 'signed by a key the verifier did not pin', dis(cap, {}, rogue), nd(), B, { ok: false, reason: 'discharge signature invalid' });
  dv('dv-other-pinned-key', 'signed by another PINNED issuer: the label decides the key', dis(cap, {}, org), nd(), B, { ok: false, reason: 'discharge signature invalid' });
  dv('dv-unpinned-label', 'the caveat names an issuer label the verifier has no pin for', dis(cap, { issuer: 'stranger' }, rogue), nd({ issuer: 'stranger' }), B, { ok: false, reason: 'not pinned' });
  dv('dv-no-pins', 'an empty pin list', ok, nd(), { ...B, pins: [] }, { ok: false, reason: 'not pinned' });
  dv('dv-ambiguous-pin', 'a label pinned twice is ambiguous', ok, nd(), { ...B, pins: [...PINS, pin('risk-team', 'human', rogue)] }, { ok: false, reason: 'pinned more than once' });
  dv('dv-class-mismatch', 'the pin is a model, the caveat requires a human: a model key is never promoted', dis(cap, { issuer: 'screener' }, model), nd({ issuer: 'screener' }), B, { ok: false, reason: 'not of the class' });
  dv('dv-class-model-ok', 'a model-class issuer discharges a caveat that says model', dis(cap, { issuer: 'screener' }, model), nd({ issuer: 'screener', issuer_class: 'model' }), B, { ok: true });
  dv('dv-caveat-id', 'a discharge for another caveat id', dis(cap, { caveat_id: 'other' }), nd(), B, { ok: false, reason: 'for another caveat' });
  dv('dv-issuer-label', 'the discharge names another issuer than the caveat', dis(cap, { issuer: 'acme' }, org), nd(), B, { ok: false, reason: 'names another issuer' });
  dv('dv-other-hop', 'bound to another hop', dis(dg('z')), nd(), B, { ok: false, reason: 'bound to another hop' });
  dv('dv-bind-mismatch', 'a chain_hop discharge for a caveat that requires action binding', ok, nd({ bind: 'action' }), { ...B, action_digest: ACT_DIGEST }, { ok: false, reason: 'binds differently' });
  const act = dis(cap, { bind: 'action', action_digest: ACT_DIGEST });
  dv('dv-action-bound', 'a bind-action discharge for exactly this action', act, nd({ bind: 'action' }), { ...B, action_digest: ACT_DIGEST }, { ok: true });
  dv('dv-action-other', 'a bind-action discharge shown with another action', act, nd({ bind: 'action' }), { ...B, action_digest: dg('b') }, { ok: false, reason: 'bound to another action' });
  dv('dv-action-none', 'a bind-action discharge when the verifier has no action digest', act, nd({ bind: 'action' }), B, { ok: false, reason: 'bound to another action' });
  dv('dv-revoked', 'the discharge digest is on the verifier revocation list', ok, nd(), { ...B, revoked: [pca.dischargeDigest(ok)] }, { ok: false, reason: 'is revoked' });
  dv('dv-revoked-other', 'another digest on the list does not matter', ok, nd(), { ...B, revoked: [dg('q')] }, { ok: true });
  dv('dv-tampered-claims', 'a claim raised after signing', { ...ok, claims: { kyc_level: 9 } }, nd(), B, { ok: false, reason: 'discharge signature invalid' });
  dv('dv-claim-gte-below', 'kyc_level 1 against gte 2', dis(cap, { claims: { kyc_level: 1 } }), nd(), B, { ok: false, reason: "claim 'kyc_level' does not satisfy" });
  dv('dv-claim-absent', 'the required claim is absent', dis(cap, { claims: { other: 1 } }), nd(), B, { ok: false, reason: "claim 'kyc_level' does not satisfy" });
  dv('dv-claim-string-gte', 'a string against gte', dis(cap, { claims: { kyc_level: '3' } }), nd(), B, { ok: false, reason: "claim 'kyc_level' does not satisfy" });
  dv('dv-claim-eq', 'eq on a string', dis(cap, { claims: { tier: 'gold' } }), nd({ require: [{ claim: 'tier', op: 'eq', value: 'gold' }] }), B, { ok: true });
  dv('dv-claim-eq-type', 'eq never coerces: 1 is not true', dis(cap, { claims: { ok: 1 } }), nd({ require: [{ claim: 'ok', op: 'eq', value: true }] }), B, { ok: false, reason: "claim 'ok' does not satisfy" });
  dv('dv-claim-neq', 'neq', dis(cap, { claims: { region: 'eu' } }), nd({ require: [{ claim: 'region', op: 'neq', value: 'us' }] }), B, { ok: true });
  dv('dv-claim-in', 'in a set', dis(cap, { claims: { region: 'eu' } }), nd({ require: [{ claim: 'region', op: 'in', value: ['us', 'eu'] }] }), B, { ok: true });
  dv('dv-claim-in-miss', 'not in the set', dis(cap, { claims: { region: 'ap' } }), nd({ require: [{ claim: 'region', op: 'in', value: ['us', 'eu'] }] }), B, { ok: false, reason: "claim 'region' does not satisfy" });
  dv('dv-claim-lte', 'lte', dis(cap, { claims: { risk: 3 } }), nd({ require: [{ claim: 'risk', op: 'lte', value: 3 }] }), B, { ok: true });
  dv('dv-no-requirements', 'a caveat with no requirements only needs the signature and the binding', dis(cap, { claims: {} }), nd({ require: [] }), B, { ok: true });
  dv('dv-two-requirements', 'every requirement must hold', dis(cap, { claims: { kyc_level: 3, tier: 'silver' } }), nd({ require: [{ claim: 'kyc_level', op: 'gte', value: 2 }, { claim: 'tier', op: 'eq', value: 'gold' }] }), B, { ok: false, reason: "claim 'tier' does not satisfy" });
  dv('dv-malformed-caveat', 'a caveat without ttl_ms is malformed', ok, (({ ttl_ms, ...c }) => c)(nd()), B, { ok: false, reason: 'malformed needs_discharge caveat' });
  dv('dv-unknown-discharge-member', 'a member the format does not define', { ...ok, extra: 1 }, nd(), B, { ok: false, reason: "unknown member 'discharge.extra'" });
  dv('dv-action-digest-on-hop', 'action_digest on a chain_hop discharge', { ...ok, action_digest: ACT_DIGEST }, nd(), B, { ok: false, reason: 'action_digest is required for bind action and forbidden for chain_hop' });
  dv('dv-missing-action-digest', 'a bind-action discharge without action_digest', (({ action_digest, ...d }) => d)(act), nd({ bind: 'action' }), { ...B, action_digest: ACT_DIGEST }, { ok: false, reason: 'action_digest is required' });
  dv('dv-short-nonce', 'a nonce under 16 bytes', { ...ok, nonce: pca.b64u(new Uint8Array(8).fill(1)) }, nd(), B, { ok: false, reason: 'nonce must be canonical base64url of at least 16 bytes' });
  dv('dv-claim-name', 'a claim name that is not canonical', { ...ok, claims: { 'Kyc-Level': 3 } }, nd(), B, { ok: false, reason: "claim 'Kyc-Level' is malformed" });
  dv('dv-claim-float', 'a non-integer claim value', { ...ok, claims: { kyc_level: 2.5 } }, nd(), B, { ok: false, reason: "claim 'kyc_level' is malformed" });
  dv('dv-not-after-before-iat', 'not_after <= iat', { ...ok, not_after: NOW - 1000 }, nd(), B, { ok: false, reason: 'not_after must be greater than iat' });
  // track K9: an `artifact` attestation verifier (build provenance checked against pinned trust roots) is its own class
  const prov = (o = {}) => nd({ id: 'provenance', issuer: 'provenance', issuer_class: 'artifact', require: [{ claim: 'slsa_level', op: 'gte', value: 3 }, { claim: 'source_repo', op: 'eq', value: 'https://github.com/acme/tool' }, { claim: 'runtime_bound', op: 'eq', value: true }], ...o });
  const provDis = (o = {}, who) => dis(cap, { caveat_id: 'provenance', issuer: 'provenance', claims: { slsa_level: 3, source_repo: 'https://github.com/acme/tool', runtime_bound: true }, ...o }, who);
  dv('dv-artifact-ok', 'an artifact-class discharge carrying the provenance claims a caveat requires', provDis(), prov(), B, { ok: true });
  dv('dv-artifact-level-low', 'slsa_level 2 against gte 3', provDis({ claims: { slsa_level: 2, source_repo: 'https://github.com/acme/tool', runtime_bound: true } }), prov(), B, { ok: false, reason: "claim 'slsa_level' does not satisfy" });
  dv('dv-artifact-other-repo', 'built from another repository', provDis({ claims: { slsa_level: 3, source_repo: 'https://github.com/evil/tool', runtime_bound: true } }), prov(), B, { ok: false, reason: "claim 'source_repo' does not satisfy" });
  dv('dv-artifact-not-runtime-bound', 'the running image was not joined to the provenance subject', provDis({ claims: { slsa_level: 3, source_repo: 'https://github.com/acme/tool', runtime_bound: false } }), prov(), B, { ok: false, reason: "claim 'runtime_bound' does not satisfy" });
  dv('dv-artifact-workload-pin', 'a workload pin can never discharge a caveat that asks for an artifact verifier', dis(cap, { caveat_id: 'provenance', issuer: 'runtime', claims: { slsa_level: 3, source_repo: 'https://github.com/acme/tool', runtime_bound: true } }), prov({ issuer: 'runtime' }), B, { ok: false, reason: 'not of the class' });
  dv('dv-artifact-pin-for-human', 'an artifact pin cannot discharge a caveat that asks for a human', provDis(), prov({ issuer_class: 'human' }), B, { ok: false, reason: 'not of the class' });
  // a workload as the attested issuer
  const wl = nd({ issuer: 'runtime', issuer_class: 'workload', issuer_spiffe: SPIFFE, require: [] });
  const wd = dis(cap, { issuer: 'runtime', claims: { image: 'sha256-abc' } }, workload);
  dv('dv-spiffe-issuer', 'a workload pinned with its SPIFFE ID discharges a caveat that names that ID', wd, wl, B, { ok: true });
  dv('dv-spiffe-issuer-mismatch', 'the pin carries another SPIFFE ID than the caveat requires', wd, nd({ ...wl, issuer_spiffe: 'spiffe://acme.test/ns/prod/other' }), B, { ok: false, reason: 'does not carry the SPIFFE ID' });
  dv('dv-spiffe-issuer-unset', 'the pin carries no SPIFFE ID at all', wd, wl, { ...B, pins: PINS.map((p) => (p.label === 'runtime' ? { label: p.label, class: p.class, pk: p.pk } : p)) }, { ok: false, reason: 'does not carry the SPIFFE ID' });
  dv('dv-spiffe-issuer-invalid', 'issuer_spiffe is not a SPIFFE ID', wd, nd({ ...wl, issuer_spiffe: 'http://acme.test' }), B, { ok: false, reason: 'issuer_spiffe' });
  // suites
  const hyb = dis(cap, {}, human, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: pca.mlDsa65Keygen(seed('k1/human-ml65')) });
  const mlPin = (pq) => PINS.map((p) => (p.label === 'risk-team' ? { ...p, pq_pk: pq } : p));
  dv('dv-hybrid-valid', 'a hybrid Ed25519 + ML-DSA-65 discharge, the issuer pinned with its PQ key', hyb, nd(), { ...B, pins: mlPin(hyb.pq_pk) }, { ok: true }, { requires: 'hybrid-ed25519-ml-dsa-65' });
  dv('dv-hybrid-bare-pin', 'a hybrid discharge under a pin without the PQ key: the artifact key alone never authorises it', hyb, nd(), B, { ok: false, reason: 'discharge signature invalid' }, { requires: 'hybrid-ed25519-ml-dsa-65' });
  dv('dv-hybrid-wrong-pq-pin', 'a hybrid discharge under a pin with another PQ key', hyb, nd(), { ...B, pins: mlPin(pca.b64u(pca.mlDsa65Keygen(seed('k1/other-ml65')).publicKey)) }, { ok: false, reason: 'discharge signature invalid' }, { requires: 'hybrid-ed25519-ml-dsa-65' });
  dv('dv-alg-unknown', 'an algorithm that is not in the registry', { ...ok, alg: 'rsa-2048' }, nd(), B, { ok: false, reason: 'unsupported_suite' });
  dv('dv-ed25519-with-pq-pk', 'an ed25519 discharge must not carry pq_pk', { ...ok, pq_pk: 'AAAA' }, nd(), B, { ok: false, reason: 'an ed25519 artifact must not carry pq_pk / pq_sig' });
}

// ------------------------------------------------------------------ k1_eval
const KE = [];
function ke(name, description, c, { k1 = {}, action = ACTION(10), stock = {}, want } = {}) {
  const k1x = { pins: PINS, ...k1 };
  const context = { now: NOW, delegation_depth: c.chain.length - 1, action, ...stock };
  const input = { grant: c.grant, chain: c.chain, k1: k1x, context };
  const k = pca.evaluateK1(c.grant, c.chain, k1x, { now: NOW, action });
  const stockCaveats = [...pca.policyCaveats(c.grant, c.chain).filter((x) => !pca.isK1Caveat(x)), ...k.plain];
  const s = pca.evaluateAgentCaveats(stockCaveats, { now: NOW, delegationDepth: context.delegation_depth, ...(stock.recent_action_times ? { recentActionTimes: stock.recent_action_times } : {}) }, { action });
  const failed = [...s.failed, ...k.failed].sort();
  const allow = failed.length === 0;
  if (allow !== want.allow || JSON.stringify(failed) !== JSON.stringify([...want.failed].sort())) throw new Error(`${name}: the reference says ${JSON.stringify({ allow, failed, reasons: k.reasons })}, wanted ${JSON.stringify(want)}`);
  KE.push({ name, description, input, expect: { allow, failed } });
}
const A = (failed = []) => ({ allow: failed.length === 0, failed });
{
  // ---- needs_discharge
  let c = one([nd()]);
  ke('nd-discharged', 'a root needs_discharge with a valid discharge bound to the root hop', c, { k1: { discharges: [dis(cap0(c))] }, want: A() });
  ke('nd-missing', 'no discharge presented', c, { want: A(['needs_discharge']) });
  ke('nd-wrong-id-only', 'a discharge for another caveat id', c, { k1: { discharges: [dis(cap0(c), { caveat_id: 'other' })] }, want: A(['needs_discharge']) });
  ke('nd-extra-discharges', 'junk next to the right one: any valid discharge for the caveat is enough', c, { k1: { discharges: [{ junk: true }, dis(cap0(c), {}, rogue), dis(cap0(c))] }, want: A() });
  ke('nd-expired', 'the only discharge is expired', c, { k1: { discharges: [dis(cap0(c), { iat: NOW - 600_000, not_after: NOW - 1 })] }, want: A(['needs_discharge']) });
  ke('nd-revoked', 'the discharge is revoked', c, { k1: { discharges: [dis(cap0(c))], revoked_discharges: [pca.dischargeDigest(dis(cap0(c)))] }, want: A(['needs_discharge']) });
  ke('nd-no-pins', 'no pins configured', c, { k1: { pins: [], discharges: [dis(cap0(c))] }, want: A(['needs_discharge']) });
  ke('nd-malformed-caveat', 'a needs_discharge with an unknown member', one([{ ...nd(), extra: 1 }]), { want: A(['needs_discharge']) });
  c = two([], [nd()]);
  ke('nd-delegated', 'the caveat was added by hop 1: the discharge is bound to hop 1', c, { k1: { discharges: [dis(capN(c, 1))] }, want: A() });
  ke('nd-wrong-hop', 'a discharge bound to the ROOT hop does not satisfy a caveat hop 1 introduced', c, { k1: { discharges: [dis(capN(c, 0))] }, want: A(['needs_discharge']) });
  c = two([nd()], []);
  ke('nd-root-caveat-inherited', 'the root caveat is carried into the child: still bound to hop 0', c, { k1: { discharges: [dis(capN(c, 0))] }, want: A() });
  ke('nd-root-caveat-child-hash', 'a discharge bound to the child hop does not satisfy a root caveat', c, { k1: { discharges: [dis(capN(c, 1))] }, want: A(['needs_discharge']) });
  c = one([nd({ bind: 'action' })]);
  const ad = dis(cap0(c), { bind: 'action', action_digest: ACT_DIGEST });
  ke('nd-action-bound', 'a bind-action discharge for this action digest', c, { k1: { discharges: [ad], action_digest: ACT_DIGEST }, want: A() });
  ke('nd-action-other', 'the verifier decides another action', c, { k1: { discharges: [ad], action_digest: dg('b') }, want: A(['needs_discharge']) });
  c = one([nd({ id: 'a' }), nd({ id: 'b', issuer: 'acme', issuer_class: 'org', require: [] })]);
  ke('nd-two-caveats', 'two independent caveats, each discharged', c, { k1: { discharges: [dis(cap0(c), { caveat_id: 'a' }), dis(cap0(c), { caveat_id: 'b', issuer: 'acme', claims: {} }, org)] }, want: A() });
  ke('nd-one-of-two', 'only one of two is discharged', c, { k1: { discharges: [dis(cap0(c), { caveat_id: 'a' })] }, want: A(['needs_discharge']) });
  c = one([nd(), nd()]);
  ke('nd-duplicate-id', 'two needs_discharge caveats with one id: both refused (no discharge can pick one)', c, { k1: { discharges: [dis(cap0(c))] }, want: A(['needs_discharge', 'needs_discharge']) });
  c = one([nd(), { type: 'expires', at: NOW - 1 }]);
  ke('nd-with-expired-stock', 'the discharge is fine, an ordinary caveat is not', c, { k1: { discharges: [dis(cap0(c))] }, want: A(['expires']) });
  c = one([nd({ issuer: 'screener', issuer_class: 'model' })]);
  ke('nd-model-issuer', 'a model-class issuer discharges a caveat that says model (it can only add friction: the caveat is a restriction)', c, { k1: { discharges: [dis(cap0(c), { issuer: 'screener' }, model)] }, want: A() });
  c = one([nd({ issuer: 'screener' })]);
  ke('nd-model-for-human', 'a model key cannot discharge a caveat that requires a human', c, { k1: { discharges: [dis(cap0(c), { issuer: 'screener' }, model)] }, want: A(['needs_discharge']) });
  c = one([nd({ issuer: 'runtime', issuer_class: 'workload', issuer_spiffe: SPIFFE, require: [] })]);
  ke('nd-workload-issuer', 'a workload with the required SPIFFE ID is the attested issuer', c, { k1: { discharges: [dis(cap0(c), { issuer: 'runtime', claims: {} }, workload)] }, want: A() });
  ke('nd-workload-wrong-spiffe', 'the pin of the issuer carries another SPIFFE ID', c, { k1: { pins: PINS.map((p) => (p.label === 'runtime' ? { ...p, spiffe_id: 'spiffe://acme.test/ns/prod/impostor' } : p)), discharges: [dis(cap0(c), { issuer: 'runtime', claims: {} }, workload)] }, want: A(['needs_discharge']) });

  // ---- sealed
  c = one([{ type: 'sealed' }]);
  ke('sealed-single-hop', 'a sealed root with nothing below it', c, { want: A() });
  c = two([{ type: 'sealed' }], []);
  ke('sealed-root-delegated', 'a hop appended below a sealed root', c, { want: A(['sealed']) });
  c = two([], [{ type: 'sealed' }]);
  ke('sealed-at-leaf', 'hop 1 seals itself and is the leaf', c, { want: A() });
  c = three([], [{ type: 'sealed' }], []);
  ke('sealed-then-extended', 'hop 1 sealed, hop 2 appended anyway', c, { want: A(['sealed']) });
  ke('sealed-one-hop-extra-member', 'sealed takes no members', one([{ type: 'sealed', depth: 0 }]), { want: A(['sealed']) });
  c = two([{ type: 'sealed' }], [{ type: 'expires', at: NOW + 1000 }]);
  ke('sealed-with-other-caveats', 'sealed root, child adds an ordinary caveat: still a hop below the seal', c, { want: A(['sealed']) });

  // ---- narrow
  c = one([]);
  ke('narrow-adds-restriction-ok', 'a narrow max_spend 40 and an action spending 30', c, { action: ACTION(30), k1: { narrow: nar(c, [{ type: 'max_spend', usd: 40 }]) }, want: A() });
  ke('narrow-adds-restriction-fail', 'the same narrow block and an action spending 50', c, { action: ACTION(50), k1: { narrow: nar(c, [{ type: 'max_spend', usd: 40 }]) }, want: A(['max_spend']) });
  ke('narrow-action-bound', 'a narrow block pinned to this action digest', c, { action: ACTION(30), k1: { action_digest: ACT_DIGEST, narrow: nar(c, [{ type: 'max_spend', usd: 40 }], { action_digest: ACT_DIGEST }) }, want: A() });
  ke('narrow-action-other', 'a narrow block pinned to another action', c, { action: ACTION(30), k1: { action_digest: dg('b'), narrow: nar(c, [{ type: 'max_spend', usd: 40 }], { action_digest: ACT_DIGEST }) }, want: A(['narrow']) });
  ke('narrow-expired', 'an expired narrow block is refused (never ignored)', c, { k1: { narrow: nar(c, [{ type: 'max_spend', usd: 40 }], { iat: NOW - 600_000, not_after: NOW - 1 }) }, want: A(['narrow']) });
  ke('narrow-wrong-signer', 'signed by a key that is not the leaf holder', c, { k1: { narrow: nar(c, [{ type: 'max_spend', usd: 40 }], {}, rogue.sk) }, want: A(['narrow']) });
  ke('narrow-other-hop', 'bound to another hop', c, { k1: { narrow: nar(c, [{ type: 'max_spend', usd: 40 }], { cap_hash: dg('z') }) }, want: A(['narrow']) });
  ke('narrow-holder-mismatch', 'names a holder that is not the leaf holder', c, { k1: { narrow: nar(c, [{ type: 'max_spend', usd: 40 }], { holder: rogue.pub }, rogue.sk) }, want: A(['narrow']) });
  ke('narrow-forbidden-envelope', 'a narrow block cannot carry an envelope', c, { k1: { narrow: (() => { try { return nar(c, [{ type: 'envelope' }]); } catch { return { v: 1, kind: 'pca-narrow', caveats: [{ type: 'envelope' }] }; } })() }, want: A(['narrow']) });
  ke('narrow-tampered', 'a caveat edited after signing', c, { action: ACTION(30), k1: { narrow: { ...nar(c, [{ type: 'max_spend', usd: 40 }]), caveats: [{ type: 'max_spend', usd: 400 }] } }, want: A(['narrow']) });
  ke('narrow-not-an-object', 'a narrow value that is not an object', c, { k1: { narrow: 'x' }, want: A(['narrow']) });
  c = two([], [{ type: 'max_spend', usd: 100 }]);
  ke('narrow-leaf-is-signer', 'the narrow block is signed by the LEAF holder of a two-hop chain', c, { action: ACTION(30), k1: { narrow: nar(c, [{ type: 'max_spend', usd: 40 }]) }, want: A() });
  ke('narrow-cannot-widen', 'a narrow block cannot widen: the chain max_spend 100 still holds', c, { action: ACTION(150), k1: { narrow: nar(c, [{ type: 'max_spend', usd: 1000 }]) }, want: A(['max_spend']) });
  const cs = one([{ type: 'sealed' }]);
  ke('narrow-under-seal', 'a sealed leaf can still narrow itself (it only restricts)', cs, { action: ACTION(30), k1: { narrow: nar(cs, [{ type: 'max_spend', usd: 40 }]) }, want: A() });
  c = one([]);
  ke('narrow-needs-discharge', 'a narrow block can ask for a discharge, bound to the leaf hop', c, { k1: { narrow: nar(c, [nd({ id: 'n1' })]), discharges: [dis(leafCap(c), { caveat_id: 'n1' })] }, want: A() });
  ke('narrow-needs-discharge-missing', 'the same narrow block with no discharge', c, { k1: { narrow: nar(c, [nd({ id: 'n1' })]) }, want: A(['needs_discharge']) });
  ke('narrow-sealed-forbidden', 'a narrow block cannot seal', c, { k1: { narrow: { v: 1, kind: 'pca-narrow', caveats: [{ type: 'sealed' }] } }, want: A(['narrow']) });

  // ---- max_uses (the pure part: shape and expiry; spending is uses_reserve)
  c = one([{ type: 'max_uses', id: 'u', n: 3, until: NOW + 1000 }]);
  ke('uses-open', 'a max_uses before its horizon', c, { want: A() });
  ke('uses-expired', 'a max_uses at its horizon (now == until is out)', one([{ type: 'max_uses', id: 'u', n: 3, until: NOW }]), { want: A(['max_uses']) });
  ke('uses-n-zero', 'n: 0', one([{ type: 'max_uses', id: 'u', n: 0, until: NOW + 1000 }]), { want: A(['max_uses']) });
  ke('uses-n-too-big', 'n: 257', one([{ type: 'max_uses', id: 'u', n: 257, until: NOW + 1000 }]), { want: A(['max_uses']) });
  ke('uses-n-max', 'n: 256', one([{ type: 'max_uses', id: 'u', n: 256, until: NOW + 1000 }]), { want: A() });
  ke('uses-no-until', 'until is required', one([{ type: 'max_uses', id: 'u', n: 1 }]), { want: A(['max_uses']) });
  ke('uses-duplicate-id', 'two max_uses with one id', one([{ type: 'max_uses', id: 'u', n: 1, until: NOW + 1000 }, { type: 'max_uses', id: 'u', n: 2, until: NOW + 1000 }]), { want: A(['max_uses', 'max_uses']) });

  // ---- derive
  const refundsUnder3 = { type: 'derive', id: 'refund-cap', defs: [{ name: 'refunds', kind: 'count', verb: 'refund', window_ms: 86_400_000 }], check: { op: 'lt', a: { ref: 'refunds' }, b: { const: 3 } } };
  const H = (n, verb = 'refund') => Array.from({ length: n }, (_, i) => ({ t: NOW - 1000 * (i + 1), verb, resource: `orders/${i}` }));
  c = one([refundsUnder3]);
  ke('derive-count-under', 'two refunds in the last day, fewer than 3', c, { k1: { history: H(2) }, want: A() });
  ke('derive-count-at-limit', 'three refunds: the check is false', c, { k1: { history: H(3) }, want: A(['derive']) });
  ke('derive-count-other-verb', 'three events of another verb do not count', c, { k1: { history: H(3, 'read') }, want: A() });
  ke('derive-count-old', 'events outside the window do not count', c, { k1: { history: [...H(2), { t: NOW - 86_400_000, verb: 'refund', resource: 'o' }] }, want: A() });
  ke('derive-count-future', 'an event stamped after now does not count', c, { k1: { history: [...H(2), { t: NOW + 1, verb: 'refund', resource: 'o' }] }, want: A() });
  ke('derive-no-history', 'no history supplied: the count is unknown and unknown refuses', c, { want: A(['derive']) });
  // track K9 trace rules: `never refund,mail.send after tool:web.fetch within 1h` exactly as pca-dataflow compileTraceRules
  // lowers it (its test pins the same shape); a trace-rule check is an ordinary derive caveat for every verifier
  const traceRule = { type: 'derive', id: 'trace.no_exfil.0', defs: [{ name: 'seen', kind: 'count', window_ms: 3_600_000, verb: 'web.fetch' }, { name: 'verb', kind: 'action', field: 'verb' }, { name: 'is_b', kind: 'expr', expr: { op: 'or', args: [{ op: 'eq', a: { ref: 'verb' }, b: { const: 'mail.send' } }, { op: 'eq', a: { ref: 'verb' }, b: { const: 'refund' } }] } }], check: { op: 'not', arg: { op: 'and', args: [{ op: 'gt', a: { ref: 'seen' }, b: { const: 0 } }, { ref: 'is_b' }] } } };
  const tc = one([traceRule]);
  const fetchAt = (ago) => ({ t: NOW - ago, verb: 'web.fetch', resource: 'https://example.test/page' });
  ke('trace-b-after-a', 'a refund 10 minutes after a web fetch: refused', tc, { k1: { history: [fetchAt(600_000)] }, want: A(['derive']) });
  ke('trace-a-at-window-edge', 'the fetch exactly one hour ago is outside the window (now - w, now]', tc, { k1: { history: [fetchAt(3_600_000)] }, want: A() });
  ke('trace-a-inside-edge', 'one millisecond inside the window', tc, { k1: { history: [fetchAt(3_599_999)] }, want: A(['derive']) });
  ke('trace-no-a', 'a refund with only other history', tc, { k1: { history: H(2) }, want: A() });
  ke('trace-not-b', 'a read after a fetch is not the forbidden effect', tc, { k1: { history: [fetchAt(5)] }, action: ACTION(10, { verb: 'read' }), want: A() });
  ke('trace-b-no-history', 'a refund with no history: unknown, refused', tc, { want: A(['derive']) });
  ke('trace-not-b-no-history', 'a read with no history: the B side is false, so the check holds', tc, { action: ACTION(10, { verb: 'read' }), want: A() });
  ke('trace-resource-prefix', 'the earlier side by resource prefix', one([{ ...traceRule, defs: [{ name: 'seen', kind: 'count', window_ms: 3_600_000, resource_prefix: 'inbox/' }, ...traceRule.defs.slice(1)] }]), { k1: { history: [{ t: NOW - 5, verb: 'mail.read', resource: 'inbox/7' }] }, want: A(['derive']) });
  ke('derive-bad-event', 'a malformed history event makes the count unknown', c, { k1: { history: [{ t: 'x', verb: 'refund', resource: 'o' }] }, want: A(['derive']) });
  const amt = (op, v) => ({ type: 'derive', id: 'amt', defs: [{ name: 'amount', kind: 'param', path: 'amount' }], check: { op, a: { ref: 'amount' }, b: { const: v } } });
  ke('derive-param-ok', 'the amount parameter is at most 100', one([amt('lte', 100)]), { action: ACTION(50), want: A() });
  ke('derive-param-over', 'the amount parameter is 150', one([amt('lte', 100)]), { action: ACTION(150), want: A(['derive']) });
  ke('derive-param-absent', 'the amount parameter is absent: unknown refuses', one([amt('lte', 100)]), { action: ACTION(), want: A(['derive']) });
  ke('derive-param-string', 'a string amount cannot be ordered: unknown refuses', one([amt('lte', 100)]), { action: ACTION('50'), want: A(['derive']) });
  ke('derive-gt', 'gt', one([amt('gt', 10)]), { action: ACTION(11), want: A() });
  ke('derive-gte-boundary', 'gte at the boundary', one([amt('gte', 10)]), { action: ACTION(10), want: A() });
  ke('derive-lt-boundary', 'lt at the boundary', one([amt('lt', 10)]), { action: ACTION(10), want: A(['derive']) });
  ke('derive-eq-type', 'eq never coerces', one([{ type: 'derive', id: 'e', defs: [{ name: 'amount', kind: 'param', path: 'amount' }], check: { op: 'eq', a: { ref: 'amount' }, b: { const: '10' } } }]), { action: ACTION(10), want: A(['derive']) });
  ke('derive-neq', 'neq on different types is true', one([{ type: 'derive', id: 'e', defs: [{ name: 'amount', kind: 'param', path: 'amount' }], check: { op: 'neq', a: { ref: 'amount' }, b: { const: '10' } } }]), { action: ACTION(10), want: A() });
  ke('derive-action-field', 'the verb as a fact', one([{ type: 'derive', id: 'v', defs: [{ name: 'verb', kind: 'action', field: 'verb' }], check: { op: 'eq', a: { ref: 'verb' }, b: { const: 'refund' } } }]), { want: A() });
  // Kleene logic
  const unk = { ref: 'missing' };
  const kl = (check) => one([{ type: 'derive', id: 'k', defs: [{ name: 'missing', kind: 'param', path: 'nothing' }], check }]);
  const T = { op: 'eq', a: { const: 1 }, b: { const: 1 } };
  const F = { op: 'eq', a: { const: 1 }, b: { const: 2 } };
  ke('derive-or-true-unknown', 'true OR unknown is true', kl({ op: 'or', args: [unk, T] }), { want: A() });
  ke('derive-or-false-unknown', 'false OR unknown is unknown: refused', kl({ op: 'or', args: [F, unk] }), { want: A(['derive']) });
  ke('derive-and-false-unknown', 'false AND unknown is false: refused', kl({ op: 'and', args: [unk, F] }), { want: A(['derive']) });
  ke('derive-and-true-unknown', 'true AND unknown is unknown: refused', kl({ op: 'and', args: [T, unk] }), { want: A(['derive']) });
  ke('derive-not-false', 'NOT false is true', kl({ op: 'not', arg: F }), { want: A() });
  ke('derive-not-unknown', 'NOT unknown is unknown: refused', kl({ op: 'not', arg: { op: 'eq', a: unk, b: { const: 1 } } }), { want: A(['derive']) });
  ke('derive-const-true', 'a check that is the constant true', kl({ const: true }), { want: A() });
  ke('derive-const-false', 'a check that is the constant false', kl({ const: false }), { want: A(['derive']) });
  ke('derive-bare-number', 'a check that is a number is not true', kl({ const: 1 }), { want: A(['derive']) });
  ke('derive-bare-true', 'a def that is a boolean can be the check', one([{ type: 'derive', id: 'k', defs: [{ name: 'ok', kind: 'expr', expr: T }], check: { ref: 'ok' } }]), { want: A() });
  // facts from discharges
  const kycPlus = { type: 'derive', id: 'gate', defs: [{ name: 'kyc', kind: 'claim', caveat_id: 'kyc', claim: 'kyc_level' }, { name: 'amount', kind: 'param', path: 'amount' }], check: { op: 'or', args: [{ op: 'lte', a: { ref: 'amount' }, b: { const: 100 } }, { op: 'gte', a: { ref: 'kyc' }, b: { const: 2 } }] } };
  c = one([nd(), kycPlus]);
  ke('derive-claim-from-discharge', 'a large amount is allowed because a verified discharge says kyc_level >= 2', c, { action: ACTION(5000), k1: { discharges: [dis(cap0(c))] }, want: A() });
  ke('derive-claim-undischarged', 'without the discharge the claim is unknown: the large amount is refused (and the discharge itself)', c, { action: ACTION(5000), want: A(['needs_discharge', 'derive']) });
  ke('derive-claim-small', 'a small amount needs no claim', one([kycPlus]), { action: ACTION(50), want: A() });
  c = one([nd({ require: [] }), { type: 'derive', id: 'gate', defs: [{ name: 'kyc', kind: 'claim', caveat_id: 'kyc', claim: 'kyc_level' }], check: { op: 'gte', a: { ref: 'kyc' }, b: { const: 2 } } }]);
  ke('derive-claim-bad-discharge', 'a discharge that fails verification supplies no facts', c, { k1: { discharges: [dis(cap0(c), { claims: { kyc_level: 9 } }, rogue)] }, want: A(['needs_discharge', 'derive']) });
  ke('derive-claim-ok-no-requirement', 'a valid discharge with no requirements still supplies its claims', c, { k1: { discharges: [dis(cap0(c))] }, want: A() });
  // shape
  ke('derive-forward-ref', 'a def refers to a def that comes after it', one([{ type: 'derive', id: 'f', defs: [{ name: 'a', kind: 'expr', expr: { ref: 'b' } }, { name: 'b', kind: 'param', path: 'amount' }], check: { ref: 'a' } }]), { want: A(['derive']) });
  ke('derive-self-ref', 'a def refers to itself', one([{ type: 'derive', id: 'f', defs: [{ name: 'a', kind: 'expr', expr: { ref: 'a' } }], check: { ref: 'a' } }]), { want: A(['derive']) });
  ke('derive-duplicate-def', 'a def name defined twice', one([{ type: 'derive', id: 'f', defs: [{ name: 'a', kind: 'param', path: 'amount' }, { name: 'a', kind: 'param', path: 'amount' }], check: { const: true } }]), { want: A(['derive']) });
  ke('derive-duplicate-id', 'two derive caveats with one id', one([amt('lte', 100), amt('lte', 100)]), { action: ACTION(5), want: A(['derive', 'derive']) });
  ke('derive-unknown-member', 'an unknown member', one([{ ...amt('lte', 100), note: 'x' }]), { action: ACTION(5), want: A(['derive']) });

  // ---- spiffe_bound
  const sp = (o) => one([{ type: 'spiffe_bound', ...o }]);
  ke('spiffe-exact', 'the presenting workload is exactly the bound ID', sp({ spiffe_id: SPIFFE }), { k1: { spiffe_id: SPIFFE }, want: A() });
  ke('spiffe-exact-other', 'another workload', sp({ spiffe_id: SPIFFE }), { k1: { spiffe_id: 'spiffe://acme.test/ns/prod/other' }, want: A(['spiffe_bound']) });
  ke('spiffe-absent', 'no verified workload identity at all', sp({ spiffe_id: SPIFFE }), { want: A(['spiffe_bound']) });
  ke('spiffe-prefix', 'a workload below the bound prefix', sp({ spiffe_prefix: 'spiffe://acme.test/ns/prod' }), { k1: { spiffe_id: SPIFFE }, want: A() });
  ke('spiffe-prefix-self', 'the prefix itself is inside', sp({ spiffe_prefix: SPIFFE }), { k1: { spiffe_id: SPIFFE }, want: A() });
  ke('spiffe-prefix-lookalike', 'ns/prod2 is not below ns/prod', sp({ spiffe_prefix: 'spiffe://acme.test/ns/prod' }), { k1: { spiffe_id: 'spiffe://acme.test/ns/prod2/runtime' }, want: A(['spiffe_bound']) });
  ke('spiffe-prefix-other-domain', 'another trust domain', sp({ spiffe_prefix: 'spiffe://acme.test/ns/prod' }), { k1: { spiffe_id: 'spiffe://evil.test/ns/prod/runtime' }, want: A(['spiffe_bound']) });
  ke('spiffe-both-members', 'spiffe_id and spiffe_prefix together are malformed', sp({ spiffe_id: SPIFFE, spiffe_prefix: SPIFFE }), { k1: { spiffe_id: SPIFFE }, want: A(['spiffe_bound']) });
  ke('spiffe-neither', 'neither member is malformed', sp({}), { k1: { spiffe_id: SPIFFE }, want: A(['spiffe_bound']) });
  ke('spiffe-invalid-bound', 'the caveat names something that is not a SPIFFE ID', sp({ spiffe_id: 'spiffe://Acme.test/x' }), { k1: { spiffe_id: 'spiffe://Acme.test/x' }, want: A(['spiffe_bound']) });
  ke('spiffe-invalid-peer', 'a peer ID that is not a valid SPIFFE ID never matches', sp({ spiffe_prefix: 'spiffe://acme.test' }), { k1: { spiffe_id: 'spiffe://acme.test/a/../b' }, want: A(['spiffe_bound']) });

  // ---- combinations and unknown types
  ke('unknown-type-still-refused', 'a type nobody knows is unsatisfied, next to satisfied K1 caveats', one([{ type: 'sealed' }, { type: 'future_caveat' }]), { want: A(['future_caveat']) });
  ke('stock-caveats-unchanged', 'ordinary caveats behave as before', one([{ type: 'expires', at: NOW + 1 }, { type: 'delegation_depth', max: 0 }]), { want: A() });
}

// ------------------------------------------------------------------ caveat_shape
const CS = [];
function cs(name, description, caveat, valid) {
  const err = ({ needs_discharge: pca.needsDischargeError, max_uses: pca.maxUsesError, derive: pca.deriveError, spiffe_bound: pca.spiffeBoundError }[caveat.type])(caveat);
  if ((err === null) !== valid) throw new Error(`${name}: the reference says ${err}`);
  CS.push({ name, description, input: { caveat }, expect: { valid } });
}
{
  cs('shape-nd-ok', 'a well-formed needs_discharge', nd(), true);
  cs('shape-nd-ttl-1', 'ttl_ms 1', nd({ ttl_ms: 1 }), true);
  cs('shape-nd-artifact', 'issuer_class artifact (track K9)', nd({ issuer_class: 'artifact' }), true);
  cs('shape-nd-class-unknown', 'an issuer class nobody defined', nd({ issuer_class: 'robot' }), false);
  cs('shape-nd-ttl-max', 'ttl_ms 86400000', nd({ ttl_ms: 86_400_000 }), true);
  cs('shape-nd-ttl-0', 'ttl_ms 0', nd({ ttl_ms: 0 }), false);
  cs('shape-nd-ttl-over', 'ttl_ms 86400001', nd({ ttl_ms: 86_400_001 }), false);
  cs('shape-nd-ttl-float', 'ttl_ms 1.5', nd({ ttl_ms: 1.5 }), false);
  cs('shape-nd-class', 'issuer_class: robot', nd({ issuer_class: 'robot' }), false);
  cs('shape-nd-bind', 'bind: forever', nd({ bind: 'forever' }), false);
  cs('shape-nd-id-upper', 'an id with an upper case letter', nd({ id: 'KYC' }), false);
  cs('shape-nd-id-64', 'a 64 character id', nd({ id: 'a'.repeat(64) }), true);
  cs('shape-nd-id-65', 'a 65 character id', nd({ id: 'a'.repeat(65) }), false);
  cs('shape-nd-id-leading-dot', 'an id starting with a dot', nd({ id: '.kyc' }), false);
  cs('shape-nd-require-16', '16 requirements', nd({ require: Array.from({ length: 16 }, (_, i) => ({ claim: `c${i}`, op: 'eq', value: 1 })) }), true);
  cs('shape-nd-require-17', '17 requirements', nd({ require: Array.from({ length: 17 }, (_, i) => ({ claim: `c${i}`, op: 'eq', value: 1 })) }), false);
  cs('shape-nd-op', 'an unknown op', nd({ require: [{ claim: 'a', op: 'lt', value: 1 }] }), false);
  cs('shape-nd-gte-string', 'gte needs an integer', nd({ require: [{ claim: 'a', op: 'gte', value: '1' }] }), false);
  cs('shape-nd-in-empty', 'in with no values', nd({ require: [{ claim: 'a', op: 'in', value: [] }] }), false);
  cs('shape-nd-in-17', 'in with 17 values', nd({ require: [{ claim: 'a', op: 'in', value: Array.from({ length: 17 }, (_, i) => i) }] }), false);
  cs('shape-nd-claim-name', 'a claim name starting with a digit', nd({ require: [{ claim: '1a', op: 'eq', value: 1 }] }), false);
  cs('shape-nd-extra-member', 'an unknown member', nd({ extra: 1 }), false);
  cs('shape-nd-spiffe-bad', 'issuer_spiffe that is not a SPIFFE ID', nd({ issuer_spiffe: 'x' }), false);
  cs('shape-uses-ok', 'a well-formed max_uses', { type: 'max_uses', id: 'u', n: 5, until: NOW }, true);
  cs('shape-uses-float', 'n: 1.5', { type: 'max_uses', id: 'u', n: 1.5, until: NOW }, false);
  cs('shape-uses-negative-until', 'until: -1', { type: 'max_uses', id: 'u', n: 1, until: -1 }, false);
  cs('shape-uses-extra', 'an unknown member', { type: 'max_uses', id: 'u', n: 1, until: NOW, x: 1 }, false);
  const dr = (o) => ({ type: 'derive', id: 'd', defs: [], check: { const: true }, ...o });
  const nest = (d) => (d <= 1 ? { const: true } : { op: 'not', arg: nest(d - 1) });
  cs('shape-derive-depth-4', 'check nested 4 deep', dr({ check: nest(4) }), true);
  cs('shape-derive-depth-5', 'check nested 5 deep', dr({ check: nest(5) }), false);
  const wide = (n) => ({ op: 'and', args: Array.from({ length: n }, () => ({ const: true })) });
  cs('shape-derive-nodes-33', '33 expression nodes', dr({ check: { op: 'and', args: [wide(7), wide(7), wide(7), wide(7)] } }), false); // 1 + 4 * 8
  cs('shape-derive-nodes-32', '32 expression nodes', dr({ check: { op: 'and', args: [wide(7), wide(7), wide(7), wide(6)] } }), true); // 1 + 3 * 8 + 7
  cs('shape-derive-and-9', 'and with 9 arguments', dr({ check: wide(9) }), false);
  cs('shape-derive-and-0', 'and with no arguments', dr({ check: wide(0) }), false);
  const defs = (n) => Array.from({ length: n }, (_, i) => ({ name: `p${i}`, kind: 'param', path: 'amount' }));
  cs('shape-derive-defs-8', '8 defs', dr({ defs: defs(8) }), true);
  cs('shape-derive-defs-9', '9 defs', dr({ defs: defs(9) }), false);
  cs('shape-derive-window-1', 'window_ms 1', dr({ defs: [{ name: 'n', kind: 'count', window_ms: 1 }] }), true);
  cs('shape-derive-window-max', 'window_ms 30 days', dr({ defs: [{ name: 'n', kind: 'count', window_ms: 30 * 86_400_000 }] }), true);
  cs('shape-derive-window-over', 'window_ms over 30 days', dr({ defs: [{ name: 'n', kind: 'count', window_ms: 30 * 86_400_000 + 1 }] }), false);
  cs('shape-derive-window-0', 'window_ms 0', dr({ defs: [{ name: 'n', kind: 'count', window_ms: 0 }] }), false);
  cs('shape-derive-param-4-segments', 'a param path of 4 segments', dr({ defs: [{ name: 'p', kind: 'param', path: 'a.b.c.d' }] }), true);
  cs('shape-derive-param-5-segments', 'a param path of 5 segments', dr({ defs: [{ name: 'p', kind: 'param', path: 'a.b.c.d.e' }] }), false);
  cs('shape-derive-param-proto', 'a prototype-polluting path segment', dr({ defs: [{ name: 'p', kind: 'param', path: 'a.__proto__' }] }), false);
  cs('shape-derive-param-empty-segment', 'an empty path segment', dr({ defs: [{ name: 'p', kind: 'param', path: 'a..b' }] }), false);
  cs('shape-derive-ref-unknown', 'a ref to a name that was never defined', dr({ check: { ref: 'nope' } }), false);
  cs('shape-derive-const-object', 'a constant that is not a scalar', dr({ check: { const: { a: 1 } } }), false);
  cs('shape-derive-op-unknown', 'an unknown operator', dr({ check: { op: 'xor', args: [{ const: true }] } }), false);
  cs('shape-derive-kind-unknown', 'an unknown def kind', dr({ defs: [{ name: 'p', kind: 'sql', q: 'x' }] }), false);
  cs('shape-derive-name-upper', 'a def name with an upper case letter', dr({ defs: [{ name: 'P', kind: 'param', path: 'amount' }] }), false);
  cs('shape-spiffe-id', 'spiffe_id', { type: 'spiffe_bound', spiffe_id: SPIFFE }, true);
  cs('shape-spiffe-prefix-domain', 'a bare trust domain prefix', { type: 'spiffe_bound', spiffe_prefix: 'spiffe://acme.test' }, true);
  cs('shape-spiffe-both', 'both members', { type: 'spiffe_bound', spiffe_id: SPIFFE, spiffe_prefix: SPIFFE }, false);
  cs('shape-spiffe-trailing-slash', 'a trailing slash', { type: 'spiffe_bound', spiffe_prefix: 'spiffe://acme.test/ns/' }, false);
}

// ------------------------------------------------------------------ uses_key / uses_reserve / spiffe_id
const UK = [['uk-1', 'slot 0', dg('a'), 'budget', 0], ['uk-2', 'slot 1: a different key', dg('a'), 'budget', 1], ['uk-3', 'another id', dg('a'), 'other', 0], ['uk-4', 'another hop', dg('b'), 'budget', 0], ['uk-5', 'slot 255', dg('a'), 'budget', 255]].map(([name, description, cap_hash, id, i]) => ({ name, description, input: { cap_hash, id, i }, expect: { key: pca.maxUsesSlotKey(cap_hash, id, i) } }));
if (new Set(UK.map((e) => e.expect.key)).size !== UK.length) throw new Error('slot keys collide');

const UR = [];
{
  const mu = (id, n, until) => ({ type: 'max_uses', id, n, until });
  const bc = (caveat, cap) => ({ caveat, cap_hash: cap });
  const defs = [
    ['ur-exhaust', 'n: 2 admits two uses, the third is exhausted', [bc(mu('u', 2, NOW + 10_000), dg('a'))], [{ now: NOW }, { now: NOW + 1 }, { now: NOW + 2 }], [{ ok: true, spent: 1 }, { ok: true, spent: 1 }, { ok: false, reason: 'is exhausted' }]],
    ['ur-single-use', 'n: 1 is a one-shot delegation', [bc(mu('u', 1, NOW + 10_000), dg('a'))], [{ now: NOW }, { now: NOW }], [{ ok: true, spent: 1 }, { ok: false, reason: 'is exhausted' }]],
    ['ur-expired', 'at the horizon the caveat is out', [bc(mu('u', 2, NOW), dg('a'))], [{ now: NOW }], [{ ok: false, reason: 'has expired' }]],
    ['ur-expired-after-use', 'a use before the horizon, none after', [bc(mu('u', 5, NOW + 10), dg('a'))], [{ now: NOW }, { now: NOW + 10 }], [{ ok: true, spent: 1 }, { ok: false, reason: 'has expired' }]],
    ['ur-two-hops', 'one id carried by two hops counts separately', [bc(mu('u', 1, NOW + 10_000), dg('a')), bc(mu('u', 1, NOW + 10_000), dg('b'))], [{ now: NOW }, { now: NOW }], [{ ok: true, spent: 2 }, { ok: false, reason: 'is exhausted' }]],
    ['ur-two-caveats', 'two caveats are both spent; the tighter one runs out first', [bc(mu('a', 1, NOW + 10_000), dg('a')), bc(mu('b', 3, NOW + 10_000), dg('a'))], [{ now: NOW }, { now: NOW }], [{ ok: true, spent: 2 }, { ok: false, reason: "max_uses 'a' is exhausted" }]],
    ['ur-ignores-others', 'other caveat types are not spent', [bc({ type: 'expires', at: NOW + 1 }, dg('a')), bc(mu('u', 1, NOW + 10_000), dg('a'))], [{ now: NOW }], [{ ok: true, spent: 1 }]],
    ['ur-none', 'no max_uses caveat: nothing is spent', [], [{ now: NOW }], [{ ok: true, spent: 0 }]],
    ['ur-malformed', 'a malformed max_uses refuses', [bc(mu('u', 0, NOW + 10_000), dg('a'))], [{ now: NOW }], [{ ok: false, reason: 'malformed max_uses caveat' }]],
    ['ur-duplicate', 'one id twice on one hop refuses', [bc(mu('u', 1, NOW + 10_000), dg('a')), bc(mu('u', 1, NOW + 10_000), dg('a'))], [{ now: NOW }], [{ ok: false, reason: "duplicate max_uses id 'u'" }]],
    ['ur-bad-clock', 'a non-integer clock refuses', [bc(mu('u', 1, NOW + 10_000), dg('a'))], [{ now: NOW + 0.5 }], [{ ok: false, reason: 'not a safe integer' }]],
    ['ur-256', 'n: 256 admits 256 uses', [bc(mu('u', 256, NOW + 10_000), dg('a'))], [...Array.from({ length: 256 }, () => ({ now: NOW })), { now: NOW }], [...Array.from({ length: 256 }, () => ({ ok: true, spent: 1 })), { ok: false, reason: 'is exhausted' }]],
  ];
  for (const [name, description, bound, calls, expectList] of defs) {
    const store = new pca.InMemoryReplayStore();
    const results = [];
    for (let i = 0; i < calls.length; i++) {
      const r = await pca.reserveMaxUses(store, bound, calls[i].now);
      const w = expectList[i];
      if (r.ok !== w.ok || (r.ok && r.spent !== w.spent) || (!r.ok && !r.reason.includes(w.reason))) throw new Error(`${name} call ${i}: the reference says ${JSON.stringify(r)}, wanted ${JSON.stringify(w)}`);
      results.push(w.ok ? { ok: true, spent: w.spent } : { ok: false, reason_contains: w.reason });
    }
    UR.push({ name, description, input: { bound, calls }, expect: { results } });
  }
}
const SP = ['spiffe://acme.test', 'spiffe://acme.test/', 'spiffe://acme.test/a', 'spiffe://acme.test/ns/prod/runtime', 'spiffe://a-b_c.d/x.y_z-1', 'spiffe://Acme.test/a', 'spiffe://acme.test/a/../b', 'spiffe://acme.test/a/./b', 'spiffe://acme.test//a', 'spiffe://acme.test/a/', 'spiffe://acme.test/a b', 'spiffe://acme.test/a?x=1', 'spiffe://acme.test/a#f', 'spiffe://user@acme.test/a', 'spiffe://acme.test:8080/a', 'spiffe:///a', 'spiffe://', 'http://acme.test/a', 'SPIFFE://acme.test/a', '', ' spiffe://acme.test', `spiffe://acme.test/${'a'.repeat(2048 - 'spiffe://acme.test/'.length)}`, `spiffe://acme.test/${'a'.repeat(2049 - 'spiffe://acme.test/'.length)}`, 'spiffe://acme.test/é'].map((s, i) => {
  const valid = pca.spiffeIdError(s) === null;
  return { name: `sp-${String(i).padStart(2, '0')}`, description: JSON.stringify(s.length > 60 ? `${s.slice(0, 40)}... (${s.length} chars)` : s), input: { id: s }, expect: { valid } };
});

// ------------------------------------------------------------------ k1_unconfigured: no k1 input at all refuses every K1 caveat
const KU = [];
{
  const rq = await (process.env.PCA_SRC ? import('../src/server/require-pca.ts') : import('../dist/server/require-pca.js'));
  const un = (name, description, c, wantFailed) => {
    const context = { now: NOW, delegation_depth: c.chain.length - 1, action: ACTION(10) };
    const k = pca.evaluateK1(c.grant, c.chain, undefined, { now: NOW, action: context.action });
    const stock = [...pca.policyCaveats(c.grant, c.chain).filter((x) => !pca.isK1Caveat(x)), ...k.plain];
    const s = pca.evaluateAgentCaveats(stock, { now: NOW, delegationDepth: context.delegation_depth }, { action: context.action });
    const failed = [...s.failed, ...k.failed].sort();
    if (JSON.stringify(failed) !== JSON.stringify([...wantFailed].sort())) throw new Error(`${name}: ${JSON.stringify(failed)}`);
    KU.push({ name, description, input: { grant: c.grant, chain: c.chain, context }, expect: { allow: failed.length === 0, failed } });
  };
  un('un-sealed', 'a lone sealed hop is still refused when the verifier has no K1 input', one([{ type: 'sealed' }]), ['sealed']);
  un('un-derive-true', 'a derive whose check is the constant true is refused', one([{ type: 'derive', id: 'd', defs: [], check: { const: true } }]), ['derive']);
  un('un-needs-discharge', 'needs_discharge', one([nd()]), ['needs_discharge']);
  un('un-max-uses', 'max_uses', one([{ type: 'max_uses', id: 'u', n: 1, until: NOW + 1000 }]), ['max_uses']);
  un('un-spiffe', 'spiffe_bound', one([{ type: 'spiffe_bound', spiffe_id: SPIFFE }]), ['spiffe_bound']);
  un('un-delegated-sealed', 'a K1 caveat added by a delegated hop', two([], [{ type: 'sealed' }]), ['sealed']);
  un('un-two-types', 'two K1 types both fail', one([{ type: 'sealed' }, nd()]), ['needs_discharge', 'sealed']);
  un('un-stock-only', 'a chain with no K1 caveat is unaffected', one([{ type: 'expires', at: NOW + 1 }]), []);
  un('un-stock-fails', 'a stock caveat still fails on its own', one([{ type: 'expires', at: NOW - 1 }]), ['expires']);
  un('un-empty-object-configures', 'control: k1 = {} IS configured, a lone sealed passes (see k1_eval)', one([{ type: 'sealed' }]), ['sealed']);
  KU.pop();
}

// ------------------------------------------------------------------ consume_once_ttl: the retention contract of the replay store
const CT = [];
{
  const run = async (steps) => {
    const st = new pca.InMemoryReplayStore();
    const out = [];
    for (const x of steps) {
      try { out.push((await st.consumeOnce(x.key, x.retain_until, x.now)) ? 'true' : 'false'); } catch { out.push('error'); }
    }
    return out;
  };
  const ct = async (name, description, steps, want) => {
    const got = await run(steps);
    if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`${name}: ${JSON.stringify(got)}`);
    CT.push({ name, description, input: { steps }, expect: { results: got } });
  };
  const S = (key, retain_until, now) => ({ key, retain_until, now });
  await ct('ct-first-then-repeat', 'the first consume is true, a repeat inside the retention is false', [S('k', NOW + 10, NOW), S('k', NOW + 10, NOW + 1)], ['true', 'false']);
  await ct('ct-boundary-inclusive', 'now == retain_until is still inside the retention', [S('k', NOW + 10, NOW), S('k', NOW + 10, NOW + 10)], ['true', 'false']);
  await ct('ct-expired-slot-reusable', 'past retain_until the key may be consumed again (the store may forget it)', [S('k', NOW + 10, NOW), S('k', NOW + 20, NOW + 11)], ['true', 'true']);
  await ct('ct-keys-independent', 'another key is independent', [S('a', NOW + 10, NOW), S('b', NOW + 10, NOW)], ['true', 'true']);
  await ct('ct-horizon-in-past', 'a retention horizon before now is refused, never true', [S('k', NOW - 1, NOW)], ['error']);
  await ct('ct-horizon-equal-now', 'a retention horizon equal to now is accepted', [S('k', NOW, NOW)], ['true']);
  await ct('ct-empty-key', 'an empty key is refused', [S('', NOW + 10, NOW)], ['error']);
  await ct('ct-refused-does-not-consume', 'a refused call leaves nothing behind', [S('k', NOW - 1, NOW), S('k', NOW + 10, NOW)], ['error', 'true']);
  await ct('ct-longer-retention-wins', 'a repeat with a shorter horizon does not shorten the first', [S('k', NOW + 100, NOW), S('k', NOW + 5, NOW + 1), S('k', NOW + 100, NOW + 50)], ['true', 'false', 'false']);
}

// ------------------------------------------------------------------ k1_headers: PCA-Discharges / PCA-Narrow as a request carries them
const KH = [];
{
  const rq = await (process.env.PCA_SRC ? import('../src/server/require-pca.ts') : import('../dist/server/require-pca.js'));
  const b = (v) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
  const kh = (name, description, headers) => {
    let expect;
    try { expect = { ok: true, value: rq.presentedK1({ headers }) }; } catch { expect = { ok: false }; }
    KH.push({ name, description, input: { headers }, expect });
  };
  const d1 = dis(pca.capHash(one([]).chain[0]));
  kh('kh-none', 'no header', {});
  kh('kh-discharges', 'a base64url JSON array', { 'pca-discharges': b([d1]) });
  kh('kh-discharges-empty-array', 'an empty array', { 'pca-discharges': b([]) });
  kh('kh-narrow', 'a base64url JSON object', { 'pca-narrow': b({ v: 1, kind: 'pca-narrow' }) });
  kh('kh-both', 'both headers', { 'pca-discharges': b([d1]), 'pca-narrow': b({ a: 1 }) });
  kh('kh-empty-value', 'an empty header value is absent', { 'pca-discharges': '', 'pca-narrow': '' });
  kh('kh-not-array', 'discharges must be an array', { 'pca-discharges': b({ not: 'array' }) });
  kh('kh-bad-base64', 'not base64url', { 'pca-discharges': '!!!!' });
  kh('kh-padded', 'padding is refused', { 'pca-discharges': `${b([d1])}==` });
  kh('kh-standard-alphabet', 'the standard alphabet is refused', { 'pca-discharges': Buffer.from('[[[[?>>>]').toString('base64') });
  kh('kh-not-json', 'text that is not JSON', { 'pca-narrow': b('not json') });
  kh('kh-duplicate-keys', 'a duplicate object key is refused by the strict parser', { 'pca-narrow': b('{"a":1,"a":2}') });
  kh('kh-float-spelling', 'an integral float spelling is refused by the strict parser', { 'pca-narrow': b('{"a":1.0}') });
  kh('kh-narrow-array', 'narrow may be any JSON value at this layer (the verifier refuses a non-object)', { 'pca-narrow': b([1]) });
  kh('kh-case-insensitive', 'header names are matched case-insensitively', { 'PCA-Discharges': b([d1]) });
}

// ------------------------------------------------------------------ write / check
const primitives = { discharge_verify: DV, k1_eval: KE, caveat_shape: CS, uses_key: UK, uses_reserve: UR, spiffe_id: SP, k1_unconfigured: KU, consume_once_ttl: CT, k1_headers: KH };
const names = Object.values(primitives).flat().map((e) => e.name);
const dup = names.find((n, i) => names.indexOf(n) !== i);
if (dup) throw new Error(`duplicate vector name ${dup}`);
const file = {
  format: 'pca-caveat-lang-vectors',
  ver: 1,
  description: 'Generated by packages/pca/scripts/gen-conformance-k1.mjs from the TypeScript reference (caveat-lang.ts); do not edit. Reason text is part of every discharge_verify expectation.',
  keys: { pins: PINS, principal: principal.pub, agent: agent.pub, subagent: sub.pub },
  primitives,
};
const text = serializeCorpus(file);
const counts = Object.entries(primitives).map(([k, v]) => `${k}=${v.length}`).join(' ');
if (process.argv.includes('--check')) {
  let committed = '';
  try { committed = readFileSync(OUT, 'utf8'); } catch { /* absent */ }
  if (committed !== text) { console.error(`caveat-lang-vectors.json differs from a fresh regeneration (${counts}): re-run gen-conformance-k1.mjs and commit`); process.exit(1); }
  console.log(`caveat-lang-vectors.json up to date (${counts})`);
} else {
  writeFileSync(OUT, text);
  console.log(`wrote ${OUT}: ${counts}`);
}
