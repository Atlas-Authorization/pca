// Mutation-style differential oracle for OracleFacts / ParamProvenance / Predicates (Java + Kotlin 0.4.2 mutation kills).
// Starting from the existing corpora (test-data/k042-oracleprov.json.gz and k042-predjs.json), every structural path of every
// distinct input shape is replaced by each of a fixed value set (null, booleans, numbers, strings, containers, operator names),
// deleted, or given an unknown sibling, and the TS reference result is recomputed. Same case formats as the base corpora.
//   npx tsx tools/pca-audit/java-mutate/k042-oracleprov-mut-oracle.mjs    (deterministic; run from the repo root)
// writes sdks/java-pca/test-data/k042-oracleprov-mut.json.gz  { oracleprov: [...cases], predjs: { ctx, tri, preds } }
import fs from 'node:fs';
import zlib from 'node:zlib';
const P = await import(new URL('../../../packages/pca/src/index.ts', import.meta.url).href);
const ROOT = new URL('../../../', import.meta.url).pathname;
const base = JSON.parse(zlib.gunzipSync(fs.readFileSync(ROOT + 'sdks/java-pca/test-data/k042-oracleprov.json.gz')).toString('utf8')).cases;
const pj = JSON.parse(fs.readFileSync(ROOT + 'sdks/java-pca/test-data/k042-predjs.json', 'utf8'));

const DEL = Symbol('del');
const VALUES = [null, true, false, 0, 1, -1, 1.5, 9007199254740992, '', 'x', 'action.params.x', 'env.world.x', 'a.b', [], {}, [1], ['x'], { a: 1 }, DEL];
const OPS = ['eq', 'ne', 'in', 'nin', 'lt', 'lte', 'gt', 'gte', 'matches', 'like', 'prefix', 'is_a', 'exists', 'member_of'];
const clone = (x) => (x === undefined ? undefined : JSON.parse(JSON.stringify(x)));
function* walk(v, pre = []) {
  yield pre;
  if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) yield* walk(v[i], [...pre, i]); }
  else if (v && typeof v === 'object') for (const k of Object.keys(v)) yield* walk(v[k], [...pre, k]);
}
const key = (p) => p.map((s) => (typeof s === 'number' ? '#' : s)).join('\u0001');
const getAt = (r, p) => p.reduce((a, s) => a[s], r);
function setAt(root, p, val) {
  if (p.length === 0) return val === DEL ? undefined : val;
  let cur = root;
  for (let i = 0; i < p.length - 1; i++) cur = cur[p[i]];
  const last = p[p.length - 1];
  if (val === DEL) { if (Array.isArray(cur)) cur.splice(last, 1); else delete cur[last]; } else cur[last] = val;
  return root;
}
function variants(doc, path) {
  const orig = getAt(doc, path);
  const vs = VALUES.map((v, i) => [String(i), v]);
  if (orig && typeof orig === 'object' && !Array.isArray(orig)) vs.push(['extra', { ...clone(orig), zz_unknown: 1 }]);
  if (path[path.length - 1] === 'op') OPS.forEach((o) => vs.push(['op-' + o, o]));
  return vs;
}
const PERMISSIVE = (e) => /Maximum call stack/.test(String(e));

// ---- oracleprov part ------------------------------------------------------------------------------------------------
const provOut = (r) => ({ outcome: r.outcome, reason: r.reason ?? null, friction: r.friction ?? null, labels: r.labels, classes: r.classes, env: r.env });
const worldOut = (r) => (r.ok ? { ok: true, world: r.world, single_source: r.single_source } : { ok: false, reason: r.reason });
const oracleprov = [];
const seen = new Set();
function emit(kind, name, rest) { oracleprov.push({ kind, name, ...rest }); }
for (const c of base) {
  let field, fam;
  if (c.kind === 'fn') { field = 'arg'; fam = c.fn; }
  else if (c.kind === 'world' || c.kind === 'prov' || c.kind === 'read') { field = 'input'; fam = c.kind; }
  else if (c.kind === 'active') { field = 'both'; fam = 'active'; }
  else continue;
  const doc = field === 'both' ? { committed: c.committed, policy: c.policy } : c[field];
  if (doc === undefined) continue;
  for (const path of walk(doc)) {
    if (path.length === 0 && (c.kind === 'world' || c.kind === 'prov')) continue; // non-object inputs: language-specific internal-error text
    const k = fam + '\u0002' + key(path);
    if (seen.has(k)) continue;
    seen.add(k);
    for (const [vn, val] of variants(doc, path)) {
      if (path.length === 0 && val === DEL) continue;
      const m = setAt(clone(doc), path, val);
      const name = `mut/${fam}/${path.join('.') || '$'}/${vn}`;
      try {
        if (c.kind === 'fn') emit('fn', name, { fn: c.fn, arg: m, want: P[c.fn](clone(m)) });
        else if (c.kind === 'world') emit('world', name, { input: m, expect: worldOut(P.decideIntentWorld(clone(m))) });
        else if (c.kind === 'prov') emit('prov', name, { input: m, expect: provOut(P.decideParamProvenance(clone(m))) });
        else if (c.kind === 'read') {
          const i = clone(m);
          if (!i || typeof i !== 'object' || Array.isArray(i)) continue;
          emit('read', name, { input: m, expect: P.decideReadPurpose(i.fields, i.purpose, i.coverage, ...(Object.prototype.hasOwnProperty.call(i, 'on_uncovered') ? [i.on_uncovered] : [])) });
        } else if (c.kind === 'active') emit('active', name, { committed: m?.committed ?? {}, policy: m?.policy ?? {}, expect: P.intentWorldActive({ committed: clone(m?.committed ?? {}), policy: clone(m?.policy ?? {}) }) });
      } catch (e) { if (PERMISSIVE(e)) throw e; /* the reference itself threw: not a decision */ }
    }
  }
}

// ---- predicates part ------------------------------------------------------------------------------------------------
const tri = [], preds = [];
const seenT = new Set();
for (const c of pj.tri) {
  const doc = JSON.parse(c.cond);
  for (const path of walk(doc)) {
    const k = c.ctx + '\u0002' + key(path);
    if (seenT.has(k)) continue;
    seenT.add(k);
    for (const [vn, val] of variants(doc, path)) {
      if (path.length === 0 && val === DEL) continue;
      const m = setAt(clone(doc), path, val);
      try { const t = P.evaluateConditionTri(clone(m), JSON.parse(pj.ctx[c.ctx])); tri.push({ name: `mut/tri/${c.name}/${path.join('.') || '$'}/${vn}`, ctx: c.ctx, cond: JSON.stringify(m), tri: t }); } catch (e) { /* reference threw */ }
    }
  }
}
const seenP = new Set();
for (const c of pj.preds) {
  const doc = JSON.parse(c.preds);
  if (!Array.isArray(doc)) continue;
  for (const path of walk(doc)) {
    const k = c.ctx + '\u0002' + key(path);
    if (seenP.has(k)) continue;
    seenP.add(k);
    for (const [vn, val] of variants(doc, path)) {
      if (path.length === 0 && val === DEL) continue;
      const m = setAt(clone(doc), path, val);
      if (!Array.isArray(m)) continue;
      try {
        const ctx = () => JSON.parse(pj.ctx[c.ctx]);
        preds.push({ name: `mut/preds/${c.name}/${path.join('.') || '$'}/${vn}`, ctx: c.ctx, preds: JSON.stringify(m), allowed: P.evaluatePredicates(clone(m), ctx()).allowed, each: m.map((p) => P.predicateMatches(clone(p), ctx())) });
      } catch (e) { /* reference threw */ }
    }
  }
}
const out = ROOT + 'sdks/java-pca/test-data/k042-oracleprov-mut.json.gz';
fs.writeFileSync(out, zlib.gzipSync(Buffer.from(JSON.stringify({ about: 'generated by tools/pca-audit/java-mutate/k042-oracleprov-mut-oracle.mjs', oracleprov, predjs: { ctx: pj.ctx, tri, preds } })), { level: 9 }));
console.log(`oracleprov ${oracleprov.length}, tri ${tri.length}, preds ${preds.length} -> ${out}`);
