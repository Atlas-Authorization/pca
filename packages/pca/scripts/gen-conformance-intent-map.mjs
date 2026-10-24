// Stage of the conformance pipeline for Intent Layer v2 V15 (rule 19, committed map and Z0 disclosure; run AFTER
// gen-conformance-intent-wb.mjs; idempotent). Writes two primitive families:
//
//   primitives.intent_map_commit[]  { name, description, input: {leaves: [{kind, salt, leaf}]}, expect: {map_commit} }
//                                   recompute the commitment of a full leaf list (leaf / node / commit hashing, tree shape,
//                                   u64be size). Reference: src/intent-map-commit.ts mapLeafHash / mapTree / mapCommitOf.
//   primitives.intent_map[]         { name, description, input: {map_commit, action: {verb, resource, params_digest},
//                                   params?, disclosure, max_residual_risk_ppm?}, expect: {ok, cell?, p_ppm?} }
//                                   the Z0 `map` decision. Reference: src/intent-map-commit.ts decideMapDisclosure.
//                                   `params` absent = {}. Reason strings are not compared.
//
//     node packages/pca/scripts/gen-conformance-intent-map.mjs            (reads ../dist, like every stage)
//     PCA_SRC=1 packages/pca/node_modules/.bin/tsx packages/pca/scripts/gen-conformance-intent-map.mjs   (reads ../src)
import { createHash } from 'node:crypto';
import { cloneJson, readCore, writeCore } from './conformance-io.mjs';

const pca = process.env.PCA_SRC ? await import('../src/index.ts') : await import('../dist/index.js');

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const clone = cloneJson; // JSON deep copy that keeps -0 (conformance-io.mjs)

const METRICS = { residual_risk_ppm: 1200, burden_ppm: 3, uncertainty_ppm: 4, disagreement_ppm: 0, mean_harm_ppm: 10, fidelity_est_ppm: 990000, entropy_mbits: 12, questions: 2, conflicts: 0, log2_vs_mbits: 4500 };
const BOOK = {
  verb: 'air.book',
  dims: [
    { kind: 'num', path: 'action.params.total', lo: 0, hi: 100000, cuts: [40000] },
    { kind: 'cat', path: 'action.resource', values: [{ kind: 'exact', value: 'skyair.example/bookings' }, { kind: 'prefix', value: 'skyair.example/' }, { kind: 'prefix', value: 'skyair.example/b' }, { kind: 'other', value: '⊥' }] },
    { kind: 'cat', path: 'action.params.cabin', values: [{ kind: 'exact', value: 'economy' }, { kind: 'exact', value: 'business' }, { kind: 'other', value: '⊥' }] },
  ],
};
const SEARCH = { verb: 'air.search', dims: [{ kind: 'cat', path: 'action.params.from', values: [{ kind: 'exact', value: 'SFO' }, { kind: 'other', value: '⊥' }] }] };
const EMPTY = { verb: 'air.cancel', dims: [] };
// air.book: 3 total cells x 4 resource cells x 3 cabin cells = 36. In grant iff total cell < 2, resource exact or the
// longer prefix, cabin economy.
const bookCells = Array.from({ length: 36 }, (_, f) => {
  const cell = [Math.floor(f / 12), Math.floor(f / 3) % 4, f % 3];
  const g = cell[0] < 2 && (cell[1] === 0 || cell[1] === 2) && cell[2] === 0;
  return { cell, p_ppm: g ? 990000 - f : 1000 + f, in_grant: g };
});
const INPUT = {
  headers: [SEARCH, BOOK, EMPTY],
  cells: { 'air.book': bookCells, 'air.search': [{ cell: [0], p_ppm: 999000, in_grant: true }, { cell: [1], p_ppm: 500000, in_grant: false }], 'air.cancel': [{ cell: [], p_ppm: 0, in_grant: false }] },
  metrics: METRICS,
  learner_digest: pca.b64u(seed('map/learner')),
};
const CM = pca.commitMap(INPUT, seed('map/secret'));
const CM2 = pca.commitMap(INPUT, seed('map/secret-2'));
const { log2_vs_mbits: _l, ...M_NO_LOG } = METRICS;
const CM3 = pca.commitMap({ ...INPUT, metrics: M_NO_LOG }, seed('map/secret'));

// ---- primitives.intent_map_commit --------------------------------------------------------------------------------
const commits = [];
const addCommit = (name, description, cm) => commits.push({ name, description, input: { leaves: clone(cm.leaves) }, expect: { map_commit: cm.map_commit } });
addCommit('full', `A 3-verb map (${CM.size} leaves): headers in UTF-8 verb order, cells in flat order, metrics, learner.`, CM);
addCommit('resalted', 'The same map under another session secret: every salt and the commitment change.', CM2);
addCommit('no-log2', 'Metrics without log2_vs_mbits (absent: not computed).', CM3);
for (const n of [1, 2, 3, 5]) {
  // tiny maps: one verb with n cells (sizes 1 + n + 2), exercising the RFC 9162 tree shape at small sizes
  const vals = Array.from({ length: n - 1 }, (_, i) => ({ kind: 'exact', value: `v${i}` }));
  const cm = pca.commitMap({ headers: [{ verb: 'x.y', dims: [{ kind: 'cat', path: 'action.params.k', values: [...vals, { kind: 'other', value: '⊥' }] }] }], cells: { 'x.y': Array.from({ length: n }, (_, i) => ({ cell: [i], p_ppm: i, in_grant: i === 0 })) }, metrics: M_NO_LOG, learner_digest: pca.b64u(seed('map/learner')) }, seed(`map/tiny-${n}`));
  addCommit(`tiny-${n}`, `One verb with ${n} cell(s): ${cm.size} leaves.`, cm);
}

// ---- primitives.intent_map ---------------------------------------------------------------------------------------
const maps = [];
const ACTION = (params, resource = 'skyair.example/bookings', verb = 'air.book') => ({ verb, resource, params_digest: pca.paramsDigest(params) });
function addMap(name, description, input, want) {
  const d = pca.decideMapDisclosure({ mapCommit: input.map_commit, action: input.action, params: input.params, disclosure: input.disclosure, ...(input.max_residual_risk_ppm !== undefined ? { maxResidualRiskPpm: input.max_residual_risk_ppm } : {}) });
  if (d.ok !== want) throw new Error(`intent_map ${name}: reference ok=${d.ok} (${d.reason ?? ''}), wanted ${want}`);
  maps.push({ name, description, input: clone(input), expect: d.ok ? { ok: true, cell: d.cell, p_ppm: d.p_ppm } : { ok: false } });
}
const base = (params, { resource = 'skyair.example/bookings', verb = 'air.book', cm = CM, eps } = {}) => ({
  map_commit: cm.map_commit, action: ACTION(params, resource, verb), params, disclosure: cm.disclose({ verb, resource }, params), ...(eps !== undefined ? { max_residual_risk_ppm: eps } : {}),
});
const P = { total: 38900, cabin: 'economy' };
const D = base(P);
addMap('ok', 'Granted cell [0, 0, 0]: header, cell and metrics open the commitment.', D, true);
addMap('ok-eps', 'ε = 1200 equals the committed residual risk (<=).', { ...D, max_residual_risk_ppm: 1200 }, true);
addMap('eps-breach', 'ε = 1199 < residual risk 1200.', { ...D, max_residual_risk_ppm: 1199 }, false);
addMap('ok-cut', 'total = 40000 (the singleton cut cell [1]).', base({ total: 40000, cabin: 'economy' }), true);
addMap('ok-long-prefix', 'resource skyair.example/bx: the LONGER prefix wins (cell 2, granted).', base(P, { resource: 'skyair.example/bx' }), true);
addMap('short-prefix', 'resource skyair.example/x: the shorter prefix (cell 1, not granted).', base(P, { resource: 'skyair.example/x' }), false);
addMap('other-value', 'resource elsewhere.example: the other cell (not granted).', base(P, { resource: 'elsewhere.example' }), false);
addMap('exact-beats-prefix', 'resource skyair.example/bookings matches the exact value although both prefixes match.', D, true);
addMap('cabin-other', 'cabin first: the other cell of cabin (not granted).', base({ total: 1, cabin: 'first' }), false);
addMap('high-total', 'total 50000: cell [2, ...] outside the grant.', base({ total: 50000, cabin: 'economy' }), false);
addMap('ok-search', 'air.search from SFO (the second header).', base({ from: 'SFO' }, { verb: 'air.search', resource: 'r' }), true);
addMap('zero-dims', 'air.cancel has no dimensions: its single cell [] (not granted).', base({}, { verb: 'air.cancel', resource: 'r' }), false);
addMap('no-log2', 'Metrics without log2_vs_mbits.', base(P, { cm: CM3 }), true);
addMap('params-absent', 'params absent = {}: total is then outside the dimension.', (() => { const x = { ...D, action: ACTION({}) }; delete x.params; return x; })(), false);
{
  // value outside / wrong type: the disclosure of a valid cell presented for the bad value
  const bad = (name, desc, params) => addMap(name, desc, { ...D, action: ACTION(params), params }, false);
  bad('total-string', 'total "38900" (a numeric string) is outside the numeric dimension.', { total: '38900', cabin: 'economy' });
  bad('total-fraction', 'total 1.5 is not a safe integer.', { total: 1.5, cabin: 'economy' });
  bad('total-above', 'total 100001 > hi.', { total: 100001, cabin: 'economy' });
  bad('total-negative', 'total -1 < lo.', { total: -1, cabin: 'economy' });
  bad('total-null', 'total null.', { total: null, cabin: 'economy' });
  bad('cabin-number', 'cabin 1 is not a string.', { total: 38900, cabin: 1 });
  bad('cabin-absent', 'cabin absent.', { total: 38900 });
  bad('proto-param', 'An own __proto__ member is data; the dimension total is still absent.', JSON.parse('{"__proto__": {"total": 1}, "cabin": "economy"}'));
}
addMap('resource-number', 'action.resource is not a string.', { ...D, action: { ...D.action, resource: 7 } }, false);
addMap('params-digest-mismatch', 'params do not hash to action.params_digest.', { ...D, params: { ...P, total: 38901 } }, false);
addMap('params-null', 'params null (malformed).', { ...D, params: null }, false);
addMap('verb-mismatch', 'The disclosed header is for air.book but the action is air.search.', { ...D, action: { ...D.action, verb: 'air.search' } }, false);
addMap('foreign-commit', 'The disclosure opens another commitment (another session secret).', { ...D, map_commit: CM2.map_commit }, false);
addMap('commit-malformed', 'map_commit is not canonical base64url of 32 bytes.', { ...D, map_commit: 'abc' }, false);
const dd = (f) => { const x = clone(D); f(x.disclosure); return x; };
const flip = (s) => { const b = Buffer.from(s, 'base64url'); b[3] ^= 1; return b.toString('base64url'); };
addMap('cell-salt-flipped', 'The cell leaf salt is altered.', dd((x) => { x.cell.salt = flip(x.cell.salt); }), false);
addMap('header-path-flipped', 'A header audit path hash is altered.', dd((x) => { x.header.path[0] = flip(x.header.path[0]); }), false);
addMap('cell-path-short', 'The cell audit path lacks its last hash.', dd((x) => { x.cell.path.pop(); }), false);
addMap('cell-path-long', 'The cell audit path has an extra hash.', dd((x) => { x.cell.path.push(x.cell.path[0]); }), false);
addMap('size-off', 'size + 1: the paths no longer fit (and the commitment binds the size).', dd((x) => { x.size += 1; }), false);
addMap('cell-p-altered', 'The cell leaf p_ppm is altered.', dd((x) => { x.cell.leaf.p_ppm += 1; }), false);
addMap('cell-grant-flipped', 'The cell leaf in_grant flipped to true on a non-granted cell would not open; here a granted cell flipped to false does not open either.', dd((x) => { x.cell.leaf.in_grant = false; }), false);
addMap('metrics-altered', 'The metrics residual risk is lowered.', dd((x) => { x.metrics.leaf.residual_risk_ppm = 0; }), false);
addMap('header-altered', 'A header cut is moved (the header no longer opens).', dd((x) => { x.header.leaf.dims[0].cuts = [40001]; }), false);
{
  // a valid leaf of the wrong cell for this action: the disclosure of 50000 presented for 38900
  const other = CM.disclose({ verb: 'air.book', resource: 'skyair.example/bookings' }, { total: 50000, cabin: 'economy' });
  addMap('cell-swapped', "A correctly opening cell leaf that is not the action's cell.", { ...D, disclosure: { ...D.disclosure, cell: other.cell } }, false);
  // kind confusion: the cell leaf presented as the metrics entry, the learner leaf at size-1
  addMap('kind-confusion', 'The header entry presented as the cell entry (domain tags differ: it does not open as a cell).', dd((x) => { x.cell = clone(D.disclosure.header); }), false);
  const learner = CM.leaves[CM.size - 1];
  addMap('metrics-wrong-index', 'The learner leaf (index size-1) presented as the metrics entry.', dd((x) => { x.metrics = { index: CM.size - 1, salt: learner.salt, leaf: learner.leaf, path: [] }; }), false);
}
for (const [k, v] of [['size', null], ['size', '15'], ['size', 3], ['header', null], ['cell', null], ['metrics', null]]) {
  addMap(`disclosure-${k}-${v === null ? 'null' : typeof v === 'string' ? 'string' : 'small'}`, `disclosure.${k} is ${JSON.stringify(v)}.`, dd((x) => { x[k] = v; }), false);
}
addMap('disclosure-unknown-member', 'An unknown disclosure member (closed set).', dd((x) => { x.extra = 1; }), false);
addMap('entry-unknown-member', 'An unknown member of the cell entry.', dd((x) => { x.cell.extra = 1; }), false);
addMap('entry-index-string', 'The cell entry index is a string.', dd((x) => { x.cell.index = String(x.cell.index); }), false);
addMap('metrics-log2-null', 'metrics.log2_vs_mbits null (absent means not computed; null is malformed).', dd((x) => { x.metrics.leaf.log2_vs_mbits = null; }), false);
addMap('metrics-unknown', 'An unknown metrics member.', dd((x) => { x.metrics.leaf.extra = 0; }), false);
addMap('header-unknown', 'An unknown header member.', dd((x) => { x.header.leaf.note = 'x'; }), false);
addMap('cell-in-grant-number', 'cell.in_grant is 1, not a boolean.', dd((x) => { x.cell.leaf.in_grant = 1; }), false);
addMap('dim-path-env', 'A dimension path the verifier cannot evaluate (env.hour).', dd((x) => { x.header.leaf.dims[0].path = 'env.hour'; }), false);
addMap('other-not-last', 'The other value is not last.', dd((x) => { x.header.leaf.dims[2].values.reverse(); }), false);
addMap('disclosure-null', 'The disclosure is null.', { ...D, disclosure: null }, false);

const file = readCore();
file.primitives = file.primitives ?? {};
file.primitives.intent_map_commit = commits;
file.primitives.intent_map = maps;
writeCore(file);
console.log(`intent map (rule 19): ${commits.length} intent_map_commit, ${maps.length} intent_map`);
