// Oracle: @atlasauth/pca-actions lint.ts + the structural half of undo.ts. Writes out/ref-actions-lint.json.gz.
// PORTING table: fn(args) -> native entry point (ActionLint / ActionUndo)
//   lintDefs(raw[], opts)        -> ActionLint.lintDefs(raw, opts, attestationVerified); opts = {customTraits?, stability?, ns?, att?: true|false}
//                                   where att (absent = no callback) stands for attestationVerified returning that constant
//   lintFails(findings, strict)  -> lintFails        lintText(findings) -> lintText        toSarif(findings, tool) -> toSarif
//   lintRulesDigest() / LINT_RULES() -> ActionLint.lintRulesDigest / ActionLintRules.LINT_RULES (compare as {id, severity, title} rows)
//   reversibilityFor(def, params) / mayBeReversible(def) / compensationShape(orig, comp) -> ActionUndo.*
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as DM0 from '../../../packages/pca-actions/src/domain.ts';
import * as V0 from '../../../packages/pca-actions/src/validate.ts';
import * as L0 from '../../../packages/pca-actions/src/lint.ts';
import * as U0 from '../../../packages/pca-actions/src/undo.ts';
import { Oracle, variants, refWrite, clone, rng } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BI = un(B0), DM = un(DM0), V = un(V0), L = un(L0), U = un(U0);
const o = new Oracle('actions-lint', 'tools/pca-audit/oracles/actions-lint.mts', 'TS-reference oracle for pca-actions lint and undo shape.');
const R = rng(0x11117);
const ALL: any[] = [...BI.BUILTIN_DEFS, ...DM.DOMAIN_DEFS].map((d: any) => clone(d));
const lint = (raw: any, opts: any = {}) => { const { att, ...rest } = opts ?? {}; return L.lintDefs(raw, att === undefined ? rest : { ...rest, attestationVerified: () => att }); };
const LD = (name: string, raw: any, opts: any = {}) => o.run('lintDefs', name, lint, [raw, opts]);

// ---- rule list ----
await o.run('lintRulesDigest', 'digest', L.lintRulesDigest, []);
await o.run('LINT_RULES', 'rows', () => L.LINT_RULES.map((r: any) => [r.id, r.severity, r.title]), []);

// ---- every def alone, and the whole pack ----
for (const d of ALL) { await LD(d.verb, [d]); await LD(`${d.verb} stable ns`, [d], { stability: 'stable', ns: 'zz' }); }
await LD('all', ALL); await LD('all stable', ALL, { stability: 'stable', ns: 'stripe' }); await LD('empty', []);
await LD('dup', [ALL[0], ALL[0]]);
const al = clone(ALL[1]); al.aliases = [...(ALL[0].aliases ?? []), 'x_alias']; await LD('alias collision', [ALL[0], al]);
const bnd = (d: any, b: any) => { const c = clone(d); c.bindings = b; return c; };
await LD('binding shared', [bnd(ALL[0], { mcp: { tool: 't' }, http: { method: 'post', path: '/x' }, graphql: { op: 'query', field: 'f' }, grpc: { service: 's', method: 'm' }, asyncapi: { op: 'send', channel: 'c' }, openapi: { operationId: 'o' } }), bnd(ALL[1], { mcp: { tool: 't' }, http: { method: 'POST', path: '/x' }, openapi: { operationId: 'o' } })]);
const rn = (d: any, v: string) => { const c = clone(d); c.verb = v; c.aliases = []; return c; };
await LD('naming siblings', [rn(ALL[0], 'acme.create_a'), rn(ALL[1], 'acme.new_b'), rn(ALL[2], 'acme.new_c'), rn(ALL[3], 'acme.delete_d'), rn(ALL[4], 'acme.remove_e'), rn(ALL[5], 'acme.remove_f')]);

// ---- confirmed defs and attestations ----
const conf = (d: any, att: any) => { const c = clone(d); c.review = { state: 'confirmed', ...(att ? { attestation: att } : {}) }; return c; };
for (const d of ALL.slice(0, 4)) {
  await LD(`${d.verb} confirmed none`, [conf(d, null)]);
  await LD(`${d.verb} confirmed wrong digest`, [conf(d, { def_digest: 'D'.repeat(43), traits_digest: 'T'.repeat(43), facts_digest: 'F'.repeat(43), final_traits: [], dismissed: [], reviewer_kid: 'k', ts: 1, sig: 'S'.repeat(86) })]);
  const att = { def_digest: (await import('../../../packages/pca-actions/src/digest.ts')).defDigest(d), traits_digest: 'T'.repeat(43), facts_digest: 'F'.repeat(43), final_traits: [], dismissed: [{ trait: 'pca.bulk', reason: 'ok' }], reviewer_kid: 'k', ts: 1, sig: 'S'.repeat(86) };
  await LD(`${d.verb} confirmed wrong registry`, [conf(d, att)]);
  for (const a of [true, false]) await LD(`${d.verb} verified ${a}`, [conf(d, att)], { att: a });
  const withUnion = conf(d, att); withUnion.review.provenance = { union: ['pca.bulk', 'pca.destructive'] }; await LD(`${d.verb} union`, [withUnion], { att: true });
}

// ---- hostile variants of a few defs ----
let nv = 0;
for (const d of [ALL[0], ALL[5], ALL[12]]) for (const [lbl, v] of variants(d, { maxPaths: 120, hostile: [null, 0, 1.5, '', 'x', [], {}, true, ['x'], { x: 1 }] })) {
  nv++; if (nv % 2 === 0 && R.next() < 0.5) continue;
  await LD(`${d.verb} ${lbl}`, [v]);
}
// vocabulary issues and custom traits
const vocab = clone(ALL[0]); vocab.effects = ['read', 'zap', 5]; vocab.params = { ...vocab.params, p: { type: 'string', role: 'nope.role', format: 'zip', max_len: 3 } }; vocab.context = ['approval_ref', 'weird', 7]; vocab.traits = ['pca.bulk', 'acme.none', 5];
await LD('vocab', [vocab]);
await LD('non-object raw', [5, null, 'x', [], { verb: 'a.b' }, { verb: 7 }]);
await LD('custom traits ok', [ALL[0]], { customTraits: [{ id: 'acme.extra', implies: ['pca.bulk'], floor: { risk: 1, rev: 'reversible', blast_ppm: 0, esc: 0, caveats: [], context: [], prules: [] }, card_phrase: 'x' }] });
await LD('custom traits bad', [ALL[0]], { customTraits: [{ id: 'pca.mine', implies: [], floor: {}, card_phrase: 'x' }] });
const withTrait = clone(ALL[0]); withTrait.traits = ['acme.extra']; await LD('custom trait used', [withTrait], { customTraits: [{ id: 'acme.extra', implies: ['pca.bulk'], floor: { risk: 1, rev: 'reversible', blast_ppm: 0, esc: 0, caveats: [], context: [], prules: [] }, card_phrase: 'x' }] });

// ---- findings -> text / sarif / fails ----
const FS: any[][] = [[], lint(ALL.slice(0, 3)), lint(ALL), lint([ALL[0]], { stability: 'stable' }),
  [{ rule: 'LN-001', severity: 'note', message: 'n' }, { rule: 'LD-001', severity: 'error', verb: 'a.b', param: 'p', message: 'm', file: 'f.yaml', line: 3, column: 4 }, { rule: 'LW-001', severity: 'warning', verb: 'a.b', message: 'm2', file: 'g.yaml', line: 7 }, { rule: 'LD-000', severity: 'error', message: 'x', file: 'h.yaml' }],
  [{ rule: 'LW-001', severity: 'warning', message: 'only warn' }], [{ rule: 'LN-001', severity: 'note', message: 'only note' }], [{ rule: 'LD-001', severity: 'error', verb: '', param: '', message: 'empty verb', file: '', line: 0 }]];
for (const [i, fs] of FS.entries()) {
  await o.run('lintText', `fs${i}`, L.lintText, [fs]);
  await o.run('toSarif', `fs${i}`, L.toSarif, [fs]);
  await o.run('toSarif', `fs${i} tool`, L.toSarif, [fs, { name: 'x', version: '1.2' }]);
  await o.run('toSarif', `fs${i} tool noversion`, L.toSarif, [fs, { name: 'x', version: '' }]);
  for (const s of [true, false]) await o.run('lintFails', `fs${i} ${s}`, L.lintFails, [fs, s]);
}

// ---- undo shape ----
for (const d of ALL) {
  await o.run('mayBeReversible', d.verb, U.mayBeReversible, [d]);
  await o.run('reversibilityFor', `${d.verb} none`, U.reversibilityFor, [d, {}]);
  for (const [lbl, p] of [['str', { a: 'x', status: 'active' }], ['bool', { flag: true }], ['int', { n: 5 }], ['neg0', { n: -0 }], ['frac', { n: 1.5 }]] as any[]) await o.run('reversibilityFor', `${d.verb} ${lbl}`, U.reversibilityFor, [d, p]);
}
const valued = clone(ALL[0]); valued.reversibility = { by: 'mode', map: { fast: 'reversible', slow: 'irreversible', true: 'rate_limited', '5': 'reversible' }, default: 'rate_limited' };
for (const p of [{ mode: 'fast' }, { mode: 'slow' }, { mode: true }, { mode: 5 }, { mode: 'zzz' }, {}, { mode: null }, { mode: 5.5 }]) { await o.run('reversibilityFor', `valued ${JSON.stringify(p)}`, U.reversibilityFor, [valued, p]); }
await o.run('mayBeReversible', 'valued', U.mayBeReversible, [valued]);
const noDefault = clone(valued); delete noDefault.reversibility.default; await o.run('reversibilityFor', 'valued no default', U.reversibilityFor, [noDefault, {}]); await o.run('mayBeReversible', 'valued no default', U.mayBeReversible, [noDefault]);
let np = 0;
for (const a of ALL) for (const b of ALL) { if (np > 600) break; if (R.next() < 0.25) { np++; await o.run('compensationShape', `${a.verb} ${b.verb}`, U.compensationShape, [a, b]); } }
for (const a of ALL.slice(0, 6)) await o.run('compensationShape', `${a.verb} self`, U.compensationShape, [a, clone(a)]);
refWrite(o, 'actions-lint');
