// Oracle: @atlasauth/pca-rag, the pure filter core (aclsFromMetadata, compilePolicy, principalFromPCActn, filterDocuments).
// The framework-shaped wrappers (withPcaFilter and the LangChain / LlamaIndex structural ones) are adapters, not pure; natives rebuild them idiomatically.
// Deterministic: no clocks, no keys. Writes out/ref-rag.json.gz.
//
// PORTING (fn(args) -> native entry point, comparison rule; "Rag" = net.atlasauth.pca.rag.Rag, JSON by value)
//   aclsFromMetadata(acl, tags)        -> Rag.aclsFromMetadata(acl, tags): list of {relation, object} entries (the very objects given)
//   compilePolicy(policy)              -> Rag.compilePolicy(policy): {predicates, denies, incomplete, incompleteReason?, report?}; a throw (report.errors not a list) must throw
//   principalFromPCActn(p, opts)       -> Rag.principalFromPCActn(p, opts): {id, attributes?, env?}; throws without a leaf holder
//   filterDocuments(principal, docs, policy) -> {documents, decision}: Rag.filterDocuments(...) with the default readers (doc.id, doc.acl + doc.tags);
//                                         decision.digest is hashCanonical of {v:1, kind:'pca-rag/filter', principal, considered, allowedIds, allowedIndexes, droppedIds, policyIncomplete}
import { Oracle, refWrite } from './lib.mjs';

const R: any = await import('../../../packages/pca-rag/src/index.ts');
const o = new Oracle('rag', 'tools/pca-audit/oracles/rag.mts', 'TS-reference oracle for the pca-rag filter core.');

const model = {
  schema_version: '1.1',
  type_definitions: [
    { type: 'user' },
    { type: 'folder', relations: { viewer: { this: {} } } },
    { type: 'document', relations: {
      viewer: { this: {} }, parent: { this: {} },
      can_view: { union: { child: [{ computedUserset: { relation: 'viewer' } }, { tupleToUserset: { tupleset: { relation: 'parent' }, computedUserset: { relation: 'viewer' } } }] } },
    } },
  ],
};
const tuples = [
  { user: 'user:alice', relation: 'viewer', object: 'document:readme' },
  { user: 'user:alice', relation: 'viewer', object: 'folder:eng' },
  { user: 'folder:eng', relation: 'parent', object: 'document:spec' },
];
const A = (relation: string, object: string) => ({ relation, object });
const fga = { openfga: { model, tuples } };
const rawPermits = [{ verb: 'can_view', resource: 'document:*' }];
const gated = [{ verb: 'can_view', where: [{ field: 'subject.group', op: 'member_of', value: 'group:admins', collection: 'env.groupGraph' }] }];
const denyEnv = { predicates: rawPermits, denies: [{ verb: 'can_view', resource: 'document:secret' }] };
const withErr = { predicates: rawPermits, report: { source: 'x', translated: [], skipped: [], errors: ['boom'] } };
const withOk = { predicates: rawPermits, report: { source: 'x', translated: [], skipped: [], errors: [] } };

// ---- aclsFromMetadata
const ACLS: any[] = [undefined, null, 5, 'x', {}, A('v', 'o'), [A('v', 'o'), A('w', 'p')], [A('v', 'o'), { relation: '', object: 'o' }, { relation: 'v' }, null, 3, A('a', 'b')], { relation: 1, object: 'o' }, { ...A('v', 'o'), extra: 1 }, [[A('v', 'o')]]];
const TAGS: any[] = [undefined, null, 'viewer:doc', [], ['viewer:document:readme'], ['x'], [':x'], ['x:'], ['a:b', 'c:d:e', 7, null, ':', 'f:'], ['viewer:doc:1', 'viewer:'], { 0: 'a:b' }];
let n = 0;
for (const a of ACLS) for (const t of TAGS) await o.run('aclsFromMetadata', `c${n++}`, R.aclsFromMetadata, [a, t]);

// ---- compilePolicy
const POLS: any[] = [undefined, null, 5, 'x', true, [], rawPermits, {}, { predicates: 'x' }, { predicates: [], denies: 'y' }, denyEnv, withErr, withOk, { predicates: rawPermits, report: null }, { predicates: rawPermits, report: {} },
  { predicates: rawPermits, report: { errors: 'x' } }, fga, { openfga: null }, { openfga: 7 }, { openfga: [] }, { openfga: {} }, { openfga: { model } }, { openfga: { model, tuples: null } },
  { openfga: { model: 42, tuples } }, { openfga: { model, tuples: [{ user: 'u', relation: 'r' }] } },
  { predicates: [], denies: [], incomplete: true, incompleteReason: 'because' }, { predicates: rawPermits, denies: [], incomplete: false }, { incomplete: 'yes', predicates: rawPermits }];
for (const [i, p] of POLS.entries()) await o.run('compilePolicy', `p${i}`, R.compilePolicy, [p]);

// ---- principalFromPCActn
const chain = (h: any) => ({ cap_chain: [{ holder: 'root' }, { holder: h }] });
const PCS: any[] = [undefined, null, {}, { cap_chain: [] }, { cap_chain: 'x' }, { cap_chain: [null] }, { cap_chain: ['k'] }, { cap_chain: [{}] }, { cap_chain: [{ holder: '' }] }, { cap_chain: [{ holder: 3 }] }, chain('leafkey'), { cap_chain: [{ holder: 'only' }] }];
const OPTS: any[] = [undefined, null, {}, { id: 'user:alice' }, { id: null }, { id: '' }, { attributes: { g: 1 } }, { env: { e: 1 } }, { id: 'u', attributes: null, env: [1] }];
for (const [i, p] of PCS.entries()) for (const [j, op] of OPTS.entries()) await o.run('principalFromPCActn', `${i}/${j}`, R.principalFromPCActn, [p, op]);

// ---- filterDocuments
const DOCS = [
  { id: 'readme', acl: A('can_view', 'document:readme') },
  { id: 'spec', acl: A('can_view', 'document:spec') },
  { id: 'secret', acl: A('can_view', 'document:secret') },
  { id: 'orphan' },
  { id: 'tagged', tags: ['can_view:document:readme'] },
  { id: 'multi', acl: [A('can_view', 'document:secret'), A('can_view', 'document:spec')] },
  { id: 'dup', acl: A('can_view', 'document:readme') },
  { id: 'dup', acl: A('can_view', 'document:readme') },
  { acl: A('can_view', 'document:readme') },
  { id: '', acl: A('can_view', 'document:readme') },
  { id: 7, acl: A('can_view', 'document:readme') },
  { id: 'badacl', acl: { relation: 'can_view' } },
  null, 'str', 5, [],
  { id: 'extra', text: 'hello', acl: { ...A('can_view', 'document:readme'), note: 1 } },
];
const PRINCIPALS: any[] = ['user:alice', 'user:bob', '', { id: 'user:alice' }, { id: 'user:alice', attributes: { group: 'group:eng' }, env: { groupGraph: { 'group:eng': ['group:admins'] } } },
  { id: 'user:carol', attributes: { group: 'group:eng' }, env: { groupGraph: { 'group:eng': ['group:staff'] } } }, {}, { id: 5 }, null, undefined, 7, [], { id: 'user:alice', attributes: 'ab' }, { id: 'user:alice', attributes: [1] }, { id: 'user:alice', env: null }];
const FPOLS: any[] = [fga, rawPermits, gated, denyEnv, withErr, withOk, [], null, undefined, { openfga: { model: 42, tuples } }, { openfga: { model } },
  [{ verb: 'can_view', resource: 'document:readme', where: [{ field: 'subject.id', op: 'eq', value: 'user:alice' }] }],
  [{ verb: 'can_view', resource: 'document:*', where: [{ field: 'subject.group', op: 'bogus', value: 1 }] }]];
n = 0;
for (const pr of PRINCIPALS) for (const [pi, pol] of FPOLS.entries()) await o.run('filterDocuments', `c${n++}/p${pi}`, R.filterDocuments, [pr, DOCS, pol]);
// subsets and non-array candidates
for (const [di, d] of ([undefined, null, 'x', {}, [], [DOCS[0]], DOCS.slice(0, 4), [DOCS[6], DOCS[7], DOCS[6]]] as any[]).entries())
  for (const pol of [fga, rawPermits]) await o.run('filterDocuments', `cand${di}/${pol === fga ? 'fga' : 'raw'}`, R.filterDocuments, ['user:alice', d, pol]);
// an already compiled policy passes through
await o.run('filterDocuments', 'precompiled', (pr: any, d: any, p: any) => R.filterDocuments(pr, d, R.compilePolicy(p)), ['user:alice', DOCS, fga]);

refWrite(o, 'rag');
