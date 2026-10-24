// Oracle for the Java 0.4.2 kill tests of IntentWB.java (K042WbPcaMiscWbTest): runs the TS reference decideIntentWB
// (intent-env.ts) on targeted W-B unit inputs and writes the FULL expected result (outcome, ordered checks, reason,
// friction, env.world / env.prov / env.class, single_source), deterministic and reproducible:
//   npx tsx tools/pca-audit/java-mutate/k042-wbmisc-oracle.mjs sdks/java-pca/test-data/k042-wbmisc.json.gz
// The inputs are every W-B unit case of the Go oracle (tools/pca-audit/go-mutate/killD-oracle-gen.mjs, run to a temp
// file) plus every rule-16 / 17 / 18 decision case of that oracle lifted into a W-B unit input (committed members in
// intent_session, supplied artifacts in artifacts, the rule policy in policy), plus targeted variants (each input member
// dropped / changed, the W-B context shape rule member by member).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const pca = await import(new URL('../../../packages/pca/src/index.ts', import.meta.url).href);
const out = process.argv[2];
if (!out) throw new Error('usage: k042-wbmisc-oracle.mjs <out.json.gz>');

const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'k042wb-')), 'killD.json');
execFileSync(process.execPath, [...process.execArgv, path.join(here, '../go-mutate/killD-oracle-gen.mjs'), tmp], { stdio: ['ignore', 'ignore', 'inherit'] });
const base = JSON.parse(fs.readFileSync(tmp, 'utf8')).cases;
fs.rmSync(path.dirname(tmp), { recursive: true });

const clone = (x) => (x === undefined ? undefined : JSON.parse(JSON.stringify(x)));
const own = (o, k) => o !== null && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k);
const cases = [];
const names = new Set();
// Java contract (IntentWB.Result): on deny world / prov / cls / friction / single_source are cleared; otherwise the
// reference env members and single_source are reported (absent = null).
function wb(name, input) {
  if (names.has(name)) throw new Error(`duplicate case ${name}`);
  names.add(name);
  const r = pca.decideIntentWB(clone(input));
  const deny = r.outcome === 'deny';
  const env = r.env ?? {};
  cases.push({
    name,
    input: clone(input),
    expect: {
      outcome: r.outcome,
      checks: Object.entries(r.checks),
      reason: r.reason ?? null,
      friction: deny ? null : (r.friction ?? null),
      world: deny || !own(env, 'world') ? null : env.world,
      prov: deny || !own(env, 'prov') ? null : env.prov,
      class: deny || !own(env, 'class') ? null : env.class,
      single_source: deny ? null : (r.single_source ?? null),
    },
  });
}
const drop = (o, k) => { const r = clone(o); delete r[k]; return r; };
const set = (o, k, v) => ({ ...clone(o), [k]: clone(v) });

const lifted = [];
for (const c of base) {
  const n = c.name;
  const i = c.input;
  if (c.kind === 'wb') wb(n, i);
  else if (c.kind === 'world' && i && typeof i === 'object') {
    const s = {};
    const cm = i.committed && typeof i.committed === 'object' && !Array.isArray(i.committed) ? i.committed : {};
    if (own(cm, 'facts')) s.facts = cm.facts;
    if (own(cm, 'offer_set')) s.offer_set = cm.offer_set;
    const a = {};
    if (own(i, 'facts')) a.facts = i.facts;
    if (own(i, 'offer_set')) a.offer_set = i.offer_set;
    const w = { intent_session: s, artifacts: a, policy: own(i, 'policy') ? { world: i.policy } : {} };
    for (const k of ['now', 'aud', 'session', 'action']) if (own(i, k)) w[k] = i[k];
    wb(`lift/${n}`, w);
    lifted.push([n, w]);
  } else if (c.kind === 'prov' && i && typeof i === 'object') {
    const s = {};
    if (own(i, 'prov')) s.prov = i.prov;
    if (own(i, 'committed_labels')) s.labels = i.committed_labels;
    const a = {};
    if (own(i, 'labels')) a.labels = i.labels;
    const w = { intent_session: s, artifacts: a, policy: own(i, 'policy') ? { provenance: i.policy } : {} };
    for (const k of ['aud', 'session', 'action']) if (own(i, k)) w[k] = i[k];
    wb(`lift/${n}`, w);
    lifted.push([n, w]);
  } else if (c.kind === 'cls' && i && typeof i === 'object') {
    const s = {};
    if (own(i, 'committed')) s.classes = i.committed;
    const a = {};
    if (own(i, 'verdicts')) a.verdicts = i.verdicts;
    const pol = i.policy && typeof i.policy === 'object' && !Array.isArray(i.policy) && own(i.policy, 'classifiers') ? { classifiers: i.policy.classifiers } : {};
    const w = { intent_session: s, artifacts: a, policy: pol };
    for (const k of ['session', 'action']) if (own(i, k)) w[k] = i[k];
    wb(`lift/${n}`, w);
    lifted.push([n, w]);
  }
}

// every top-level member dropped / replaced, on the lifted passing decisions and on the W-B unit cases: each member the
// unit forwards (now, aud, session, action; committed and supplied artifacts) must reach the rule it feeds
const wbBase = base.filter((c) => c.kind === 'wb').map((c) => [c.name, c.input]);
const OTHER = { now: 1, aud: 'other.example', session: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', action: { verb: 'x', resource: 'y', params: {} } };
for (const [n, w] of [...wbBase, ...lifted.filter(([nm]) => /base|quorum$|clean|os-base|labels|two-classifiers$/.test(nm))]) {
  for (const k of ['now', 'aud', 'session', 'action']) {
    if (own(w, k)) {
      wb(`drop-${k}/${n}`, drop(w, k));
      wb(`other-${k}/${n}`, set(w, k, OTHER[k]));
    }
  }
  if (own(w, 'artifacts')) wb(`drop-artifacts/${n}`, drop(w, 'artifacts'));
  if (own(w, 'policy')) wb(`drop-policy/${n}`, drop(w, 'policy'));
  for (const k of ['facts', 'offer_set', 'prov', 'labels', 'classes']) if (own(w.intent_session, k)) wb(`drop-is-${k}/${n}`, { ...clone(w), intent_session: drop(w.intent_session, k) });
  for (const k of ['facts', 'offer_set', 'labels', 'verdicts']) if (own(w.artifacts, k)) wb(`drop-art-${k}/${n}`, { ...clone(w), artifacts: drop(w.artifacts, k) });
  for (const k of ['world', 'provenance', 'classifiers']) if (own(w.policy, k)) wb(`drop-pol-${k}/${n}`, { ...clone(w), policy: drop(w.policy, k) });
}

// a passing rule 16 (world, single_source) followed by a failing rule 17 / 18: the deny clears what rule 16 reported
for (const [n, w] of lifted) {
  if (!n.startsWith('world/')) continue;
  const r = pca.decideIntentWB(clone(w));
  if (r.outcome !== 'admit' || !r.single_source) continue;
  wb(`then-prov-deny/${n}`, { ...clone(w), intent_session: { ...clone(w.intent_session), prov: { 'action.params.nope': ['x'] } } });
  wb(`then-cls-fail/${n}`, { ...clone(w), intent_session: { ...clone(w.intent_session), classes: ['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'] } });
}

// the W-B context shape rule, member by member (absent = empty; null / the wrong JSON type = malformed; both closed)
const ctx = (name, o) => wb(`ctx/${name}`, { now: 1_800_000_000_000, aud: 'skyair.example', session: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', action: { verb: 'v', resource: 'r', params: {} }, intent_session: {}, ...o });
const BAD = { null: null, string: 'x', number: 1, bool: true, array: [], object: {} };
for (const [t, v] of Object.entries(BAD)) {
  ctx(`session-${t}`, { intent_session: v });
  ctx(`artifacts-${t}`, { artifacts: v });
  ctx(`policy-${t}`, { policy: v });
  for (const k of ['facts', 'labels', 'verdicts', 'offer_set']) ctx(`artifacts.${k}-${t}`, { artifacts: { [k]: v } });
  for (const k of ['world', 'provenance', 'classifiers']) ctx(`policy.${k}-${t}`, { policy: { [k]: v } });
}
ctx('session-absent', { intent_session: undefined });
ctx('artifacts-extra', { artifacts: { facts: [], zz: [] } });
ctx('artifacts-extra-first', { artifacts: { aa: 1 } });
ctx('policy-extra', { policy: { world: {}, zz: {} } });
ctx('policy-extra-first', { policy: { aa: 1 } });
ctx('artifacts-all-ok', { artifacts: { facts: [], labels: [], verdicts: [], offer_set: {} } });
ctx('policy-all-ok', { policy: { world: {}, provenance: { params: {} }, classifiers: [] } });
ctx('artifacts-labels-bad-after-facts-ok', { artifacts: { facts: [], labels: 1 } });
ctx('artifacts-verdicts-bad-after-ok', { artifacts: { facts: [], labels: [], verdicts: 'x' } });
ctx('artifacts-offer-bad-after-ok', { artifacts: { facts: [], labels: [], verdicts: [], offer_set: [] } });
ctx('policy-provenance-bad-after-world-ok', { policy: { world: {}, provenance: [] } });
ctx('policy-classifiers-bad-after-ok', { policy: { world: {}, provenance: {}, classifiers: {} } });
ctx('artifacts-bad-and-policy-bad', { artifacts: { facts: 1 }, policy: null });
ctx('both-ok-empty', { artifacts: {}, policy: {} });

fs.writeFileSync(out, zlib.gzipSync(Buffer.from(JSON.stringify({ about: 'TS-reference oracle for the Java K042WbPcaMiscWbTest (IntentWB.java); generated by tools/pca-audit/java-mutate/k042-wbmisc-oracle.mjs.', cases })), { level: 9 }));
console.log(`cases: ${cases.length}`);
