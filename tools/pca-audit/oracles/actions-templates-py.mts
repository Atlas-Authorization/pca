// Oracle (python lane): @atlasauth/pca-actions templates.ts. Writes out/ref-actions-templates-py.json.gz and the data module
// sdks/python-pca/atlas_pca/actions_templates_data.py (each template's metadata plus its traits and YAML rendered under a marker namespace;
// the python module substitutes the real namespace, and the corpus proves that substitution equals the reference for several namespaces).
// PORTING table: starterTemplate(id) -> {id,title,description,ns}; templateTraits(id, ns) = starterTemplate(id).traits(ns); templateYaml(id, ns) = .yaml(ns); templateList() = ids and metadata
import fs from 'node:fs';
import * as T0 from '../../../packages/pca-actions/src/templates.ts';
import { Oracle, refWrite, ROOT } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const T = un(T0);
const o = new Oracle('actions-templates-py', 'tools/pca-audit/oracles/actions-templates-py.mts', 'TS-reference oracle for pca-actions starter templates (python lane).');
const MARK = 'zzmarkerzz';
const data = T.STARTER_TEMPLATES.map((t: any) => ({ id: t.id, title: t.title, description: t.description, ns: t.ns, traits: t.traits(MARK), yaml: t.yaml(MARK) }));
fs.writeFileSync(ROOT + 'sdks/python-pca/atlas_pca/actions_templates_data.py',
  '"""The starter templates of the TypeScript reference @atlasauth/pca-actions (metadata, custom traits and authoring YAML) rendered under a marker\nnamespace (generated; do not edit)."""\nimport json\n\nMARKER = ' + JSON.stringify(MARK) + '\nTEMPLATES = json.loads(r\'\'\'' + JSON.stringify(data) + '\'\'\')\n');
await o.run('templateList', 'all', () => T.STARTER_TEMPLATES.map((t: any) => ({ id: t.id, title: t.title, description: t.description, ns: t.ns })), []);
for (const id of ['ecommerce', 'fintech', 'healthcare', 'saas_admin', 'devtools', 'nope', '', 'ECOMMERCE']) await o.run('starterTemplate', id, (x: any) => { const t = T.starterTemplate(x); return t === undefined ? null : { id: t.id, title: t.title, description: t.description, ns: t.ns }; }, [id]);
const NSS = ['acme', 'a', 'shop_2', 'x'.repeat(32), 'x'.repeat(33), 'pca', 'Acme', '1a', '', 'a-b', 'a.b', 'zzmarker', 'ns', 'infra', 'pay'];
for (const t of T.STARTER_TEMPLATES) for (const ns of NSS) {
  await o.run('templateTraits', `${t.id} ${ns}`, (i: any, n: any) => T.starterTemplate(i).traits(n), [t.id, ns]);
  await o.run('templateYaml', `${t.id} ${ns}`, (i: any, n: any) => T.starterTemplate(i).yaml(n), [t.id, ns]);
}
for (const t of T.STARTER_TEMPLATES) for (const bad of [5, null]) await o.run('templateYaml', `${t.id} bad ${String(bad)}`, (i: any, n: any) => T.starterTemplate(i).yaml(n), [t.id, bad]);
refWrite(o, 'actions-templates-py');
