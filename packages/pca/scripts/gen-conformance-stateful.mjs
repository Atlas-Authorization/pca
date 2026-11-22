// Stateful layer vectors (conformance/LAYERS.md): conformance/stateful-vectors.json, section `stateful`.
//
// Each entry is an ordered sequence of PCActn presentations (and revocations) against ONE fresh replay / budget store,
// with the expected outcome of every step ({ allow, failed: [check...] }, no reason text), computed by the TypeScript
// reference (scripts/stateful-sequence.mjs: requirePCA over an atomic in-memory store). Families:
//   st-replay-*      the same PCActn presented again, strictly increasing counters per (grant, holder)
//   st-counter-*     counter ordering: lower / equal refused, gaps allowed, a refused step does not consume its counter
//   st-revoke-*      revocation in the middle of a sequence (leaf hop, root grant, an unrelated id)
//   st-budget-*      trust-budget depletion across calls (a replay or a refused step does not spend budget)
//   st-time-*        expiry between steps of one sequence
//   st-holder-*      separate counter streams per holder of the same grant
// Deterministic: fixed key seeds, Ed25519 signatures, fixed clock values.
//
//     node packages/pca/scripts/gen-conformance-stateful.mjs [--check]                 (reads ../dist)
//     PCA_SRC=1 packages/pca/node_modules/.bin/tsx packages/pca/scripts/gen-conformance-stateful.mjs  (reads ../src)
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { confDir, serializeCorpus } from './conformance-io.mjs';
import { runSequence } from './stateful-sequence.mjs';

const pca = process.env.PCA_SRC ? await import('../src/index.ts') : await import('../dist/index.js');
const OUT = join(confDir, 'stateful-vectors.json');
const NOW = 1_800_000_000_000;
const AUD = 'rs-conformance';

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pub: pca.b64u(pca.publicKeyOf(sk)) }; };
const principal = mk('principal'), agent = mk('agent'), holderA = mk('stateful/holder-a'), holderB = mk('stateful/holder-b');

const envelope = {
  type: 'envelope', goal_commit: pca.b64u(new Uint8Array(32)),
  predicates: [{ verb: 'read', resource: 'db/*' }, { verb: 'write', resource: 'db/*' }],
  caveats: [{ type: 'expires', at: NOW + 3_600_000 }], agent_binding: {}, risk_policy: pca.DEFAULT_RISK_POLICY,
};
const grant = pca.mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats: [envelope] });
const hopA = pca.delegate(grant, holderA.pub, [{ type: 'expires', at: NOW + 3_600_000 }], agent.sk);
const hopB = pca.delegate(grant, holderB.pub, [{ type: 'expires', at: NOW + 3_600_000 }], agent.sk);
const PARAMS = { id: 1 };
const plan = [
  { id: 'n1', verb: 'read', resource: 'db/users', params_digest: pca.hashCanonical({}), reversibility_class: 'reversible' },
  { id: 'n2', verb: 'write', resource: 'db/orders', params_digest: pca.hashCanonical(PARAMS), reversibility_class: 'reversible' },
];
const committed = pca.commitPlan(plan);
const HOLDERS = { A: { chain: [grant, hopA], sk: holderA.sk }, B: { chain: [grant, hopB], sk: holderB.sk } };

/** A PCActn for plan node `node` with `counter`, issued at `iat` (valid 10 min) by holder `h`. */
function act(counter, { h = 'A', node = 'n2', iat = NOW, edit, tamper } = {}) {
  const n = plan.find((x) => x.id === node);
  const body = {
    ver: pca.PCACTN_VERSION,
    action: { verb: n.verb, resource: n.resource, params_digest: n.params_digest, reversibility_class: n.reversibility_class },
    grant_ref: grant.id,
    cap_chain: HOLDERS[h].chain,
    plan: { root: committed.root, inclusion_proof: committed.proofFor(n.id), node_id: n.id, conditions_digest: pca.conditionsDigest(n.pre, n.post) },
    attestation: { quote_digest: '', epoch: 0, model_id: 'm', measurement: '', operator: 'o' },
    provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] },
    freshness: { beacon_ref: '', epoch: 0, accumulator_witness: '' },
    counter,
    risk_claim: { r: 0, inputs: {} },
    aud: AUD,
    iat,
    exp: iat + 600_000,
  };
  if (edit) edit(body); // before signing
  const p = pca.signPCActn(body, HOLDERS[h].sk);
  if (tamper) tamper(p); // after signing
  return p;
}
const paramsOf = (p) => (p.action.verb === 'write' ? PARAMS : {});
/** One presentation step `t` seconds into the sequence. */
const present = (p, t = 0) => ({ op: 'present', pcactn: p, params: paramsOf(p), now: NOW + t * 1000 });
const revoke = (id) => ({ op: 'revoke', id });

const NO_RISK = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
// r = alpha (0.25) * 0.4 = 0.1 <= theta1: machine-only (t=1) while the budget lasts, each admitted action costs kappa * r = 0.1
const SOME_RISK = { ...NO_RISK, semanticDistance: 0.4 };

const sequences = [];
const names = new Set();
async function seqv(name, description, steps, intended, { risk = NO_RISK, initialBudget = { B: 1, tau: NOW } } = {}) {
  if (names.has(name)) throw new Error(`duplicate sequence ${name}`);
  names.add(name);
  const setup = { audience: AUD, grants: [grant], plan_nodes: plan, risk, ...(initialBudget ? { initial_budget: initialBudget } : {}), revoked: [] };
  const seq = { name, description, layer: 'stateful', setup, steps };
  const res = await runSequence(pca, seq);
  const got = res.filter(Boolean).map((r) => (r.allow ? 'A' : 'D')).join('');
  if (got !== intended) throw new Error(`${name}: reference outcomes ${got} != intended ${intended}: ${JSON.stringify(res)}`);
  seq.steps = steps.map((s, i) => (s.op === 'present' ? { ...s, expect: res[i] } : s));
  sequences.push(seq);
}

// ---- replay
await seqv('st-replay-same-twice', 'The same PCActn presented twice: the second presentation is a replay.', [present(act(1)), present(act(1), 1)], 'AD');
await seqv('st-replay-interleaved', 'Counters 1, 1, 2, 2, 1: every repeat (and the older counter) is refused.', [present(act(1)), present(act(1), 1), present(act(2), 2), present(act(2), 3), present(act(1), 4)], 'ADADD');
await seqv('st-replay-other-node', 'A new action on another plan node with an already-used counter is still a replay.', [present(act(1, { node: 'n2' })), present(act(1, { node: 'n1' }), 1)], 'AD');
// ---- counter ordering
await seqv('st-counter-increasing', 'Strictly increasing counters 1, 2, 3: all accepted.', [present(act(1)), present(act(2), 1), present(act(3), 2)], 'AAA');
await seqv('st-counter-gaps', 'Counters may skip (5, 6, 100) but never go back (99) or repeat (5).', [present(act(5)), present(act(3), 1), present(act(5), 2), present(act(6), 3), present(act(100), 4), present(act(99), 5)], 'ADDAAD');
await seqv('st-counter-first-large', 'The first counter of a stream can be any positive integer.', [present(act(7)), present(act(8), 1)], 'AA');
await seqv('st-counter-refused-not-consumed', 'A presentation refused for a bad signature does not consume its counter: the genuine one is accepted after it.', [present(act(1)), present(act(2, { tamper: (p) => { p.sig = p.sig.slice(0, -2) + (p.sig.endsWith('AA') ? 'BA' : 'AA'); } }), 1), present(act(2), 2)], 'ADA');
await seqv('st-counter-out-of-plan-not-consumed', 'A genuinely signed action outside the authorized plan is refused by the plan check and does not consume its counter.', [present(act(1, { edit: (b) => { b.plan.node_id = 'n9'; } })), present(act(1), 1)], 'DA');
// ---- revocation mid-sequence
await seqv('st-revoke-leaf', 'The leaf delegation is revoked after the first action: every later action is refused.', [present(act(1)), revoke(hopA.id), present(act(2), 1), present(act(3), 2)], 'ADD');
await seqv('st-revoke-root', 'The root grant is revoked after two actions.', [present(act(1)), present(act(2), 1), revoke(grant.id), present(act(3), 2)], 'AAD');
await seqv('st-revoke-unrelated', 'Revoking an unrelated capability id changes nothing.', [present(act(1)), revoke('unrelated-capability-id'), present(act(2), 1)], 'AA');
await seqv('st-revoke-one-holder', 'Revoking holder A\'s delegation leaves holder B\'s stream untouched.', [present(act(1)), present(act(1, { h: 'B' }), 1), revoke(hopA.id), present(act(2), 2), present(act(2, { h: 'B' }), 3)], 'AADA');
await seqv('st-revoke-before-replay', 'After revocation a replay of an accepted action is refused for both reasons.', [present(act(1)), revoke(hopA.id), present(act(1), 1)], 'AD');
// ---- budget depletion across calls
await seqv('st-budget-depletes', 'Trust budget 0.35, each action costs 0.1: three actions are machine-admitted, the fourth and fifth need a step-up.', [present(act(1)), present(act(2), 1), present(act(3), 2), present(act(4), 3), present(act(5), 4)], 'AAADD', { risk: SOME_RISK, initialBudget: { B: 0.35, tau: NOW } });
await seqv('st-budget-replay-free', 'A replay does not spend budget: budget 0.25 admits counters 1 and 2 around a refused replay of 1, then runs out.', [present(act(1)), present(act(1), 1), present(act(2), 2), present(act(3), 3)], 'ADAD', { risk: SOME_RISK, initialBudget: { B: 0.25, tau: NOW } });
await seqv('st-budget-zero-risk', 'A zero-risk action costs nothing: an empty budget still admits every step.', [present(act(1)), present(act(2), 1), present(act(3), 2)], 'AAA', { risk: NO_RISK, initialBudget: { B: 0, tau: NOW } });
await seqv('st-budget-per-holder', 'Each holder stream has its own budget: holder B is unaffected by holder A running out (budget 0.21 covers two actions plus the passive leak).', [present(act(1)), present(act(2), 1), present(act(3), 2), present(act(1, { h: 'B' }), 3)], 'AADA', { risk: SOME_RISK, initialBudget: { B: 0.21, tau: NOW } });
await seqv('st-budget-absent', 'No budget in the store: deny-metered (B = 0), so a risky machine-only action needs a step-up from the first call.', [present(act(1)), present(act(2), 1)], 'DD', { risk: SOME_RISK, initialBudget: null });
// ---- time
await seqv('st-time-expiry', 'The same stream later in time: an action issued at the start expires after 10 minutes; a freshly issued one is accepted.', [present(act(1)), present(act(2), 601), present(act(3, { iat: NOW + 601_000 }), 601)], 'ADA');
// ---- holders
await seqv('st-holder-separate-streams', 'Two holders of one grant keep separate counter streams.', [present(act(1)), present(act(1, { h: 'B' }), 1), present(act(1), 2), present(act(2, { h: 'B' }), 3)], 'AADA');

// ------------------------------------------------------------------ write / check
const steps = sequences.reduce((n, s) => n + s.steps.filter((x) => x.op === 'present').length, 0);
const file = {
  format: 1,
  layer: 'stateful',
  description: 'Stateful-layer sequences (conformance/LAYERS.md). Generated by packages/pca/scripts/gen-conformance-stateful.mjs from the TypeScript reference; do not edit.',
  counts: { sequences: sequences.length, present_steps: steps, revoke_steps: sequences.reduce((n, s) => n + s.steps.filter((x) => x.op === 'revoke').length, 0) },
  stateful: sequences,
};
const text = serializeCorpus(file);
if (process.argv.includes('--check')) {
  let committed = '';
  try { committed = readFileSync(OUT, 'utf8'); } catch { /* absent */ }
  if (committed !== text) { console.error(`stateful-vectors.json differs from a fresh regeneration (${sequences.length} sequences): re-run gen-conformance-stateful.mjs and commit`); process.exit(1); }
  console.log(`stateful-vectors.json up to date (${sequences.length} sequences)`);
} else {
  writeFileSync(OUT, text);
  console.log(`wrote ${OUT}: ${sequences.length} sequences, ${steps} presentation steps`);
}
