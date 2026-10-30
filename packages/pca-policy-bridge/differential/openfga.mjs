// Decides generated OpenFGA models with a REAL OpenFGA server (in-memory datastore) and writes fixtures/openfga.jsonl.
// usage: node openfga.mjs <server-base-url> < openfga-in.jsonl
import { readFileSync, writeFileSync } from 'node:fs';

const base = process.argv[2] ?? 'http://127.0.0.1:8080';
const cases = readFileSync(0, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const post = async (path, body) => {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const j = await r.json();
  if (!r.ok) throw new Error(`${path}: ${r.status} ${JSON.stringify(j)}`);
  return j;
};
// The bridge reads the bare model; the server also needs the type restrictions of direct relations.
const withMetadata = (model) => ({
  schema_version: '1.1',
  type_definitions: model.type_definitions.map((t) => {
    if (!t.relations) return t;
    const rels = {};
    for (const [name, node] of Object.entries(t.relations)) {
      const usesThis = JSON.stringify(node).includes('"this"');
      if (!usesThis) continue;
      rels[name] = { directly_related_user_types: name === 'parent' ? [{ type: 'folder' }] : [{ type: 'user' }, { type: 'user', wildcard: {} }] };
    }
    return { ...t, metadata: { relations: rels, module: '', source_info: null } };
  }),
});
const out = [];
for (const c of cases) {
  const store = await post('/stores', { name: c.id });
  const m = await post(`/stores/${store.id}/authorization-models`, withMetadata(c.model));
  for (let i = 0; i < c.tuples.length; i += 20) await post(`/stores/${store.id}/write`, { authorization_model_id: m.authorization_model_id, writes: { tuple_keys: c.tuples.slice(i, i + 20) } });
  const expected = [];
  for (const k of c.checks) {
    const r = await post(`/stores/${store.id}/check`, { authorization_model_id: m.authorization_model_id, tuple_key: k });
    expected.push(r.allowed === true ? 'Allow' : 'Deny');
  }
  out.push(JSON.stringify({ ...c, expected }));
}
writeFileSync('fixtures/openfga.jsonl', out.join('\n') + '\n');
