// Oracle: @atlasauth/pca-actions builtin.ts, domain.ts, builtin-review.ts and templates.ts (data modules). Writes out/ref-actions-data.json.gz.
// PORTING table (zero-argument data getters take no args; every result is JSON)
//   builtinDefs() / domainDefs() / corePackDefs()   -> ActionBuiltin.builtinDefs / domainDefs / corePackDefs
//   legacyCatalog() / legacyOntologyEffect() / resolutions() -> ActionBuiltin.legacyCatalog / legacyOntologyEffect / resolutions
//   domainBindings()                                -> ActionBuiltin.domainVerbBindings
//   coreDigests()                                   -> [[verb, Actions.defDigest(def)]] over corePackDefs, in order
//   domainVerbs(domain) / domainRoles(domain)       -> ActionBuiltin.domainVerbs(domain, null) / domainRoles(domain); an unknown domain must throw
//   releasedBuiltinDefs() / builtinConfirmed()      -> releasedBuiltinDefs(null) (== the built-ins) / builtinReviewOpts(null) == null (nothing confirmed): booleans
//   starterTemplates()                              -> ActionTemplates.starterTemplates (id, title, description, ns)
//   starterTemplate(id)                             -> ActionTemplates.starterTemplate(id) (null when unknown)
//   templateYaml(id, ns) / templateTraits(id, ns)   -> ActionTemplates.yaml / traits; a bad namespace must throw
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as DM0 from '../../../packages/pca-actions/src/domain.ts';
import * as BR0 from '../../../packages/pca-actions/src/builtin-review.ts';
import * as TP0 from '../../../packages/pca-actions/src/templates.ts';
import * as DG0 from '../../../packages/pca-actions/src/digest.ts';
import { Oracle, refWrite } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BI = un(B0), DM = un(DM0), BR = un(BR0), TP = un(TP0), DG = un(DG0);
const o = new Oracle('actions-data', 'tools/pca-audit/oracles/actions-data.mts', 'TS-reference oracle for the pca-actions data modules.');
await o.run('builtinDefs', 'all', () => BI.BUILTIN_DEFS, []);
await o.run('domainDefs', 'all', () => DM.DOMAIN_DEFS, []);
await o.run('corePackDefs', 'all', () => DM.CORE_PACK_DEFS, []);
await o.run('legacyCatalog', 'all', () => BI.LEGACY_CATALOG, []);
await o.run('legacyOntologyEffect', 'all', () => BI.LEGACY_ONTOLOGY_EFFECT, []);
await o.run('resolutions', 'all', () => BI.RESOLUTIONS, []);
await o.run('domainBindings', 'all', () => DM.DOMAIN_VERBS, []);
await o.run('coreDigests', 'all', () => DM.CORE_PACK_DEFS.map((d: any) => [d.verb, DG.defDigest(d)]), []);
for (const d of ['payments', 'email', 'code_repos', 'data_access', 'calendar_travel', 'nope', '']) {
  await o.run('domainVerbs', d || 'empty', (x: string) => DM.domainVerbs(x), [d]);
  await o.run('domainRoles', d || 'empty', (x: string) => DM.domainRoles(x), [d]);
}
await o.run('releasedBuiltinDefs', 'default', () => JSON.stringify(BR.releasedBuiltinDefs()) === JSON.stringify(BI.BUILTIN_DEFS), []);
await o.run('builtinConfirmed', 'none', () => BR.builtinReviewOpts().attestationVerified !== undefined, []);
await o.run('starterTemplates', 'all', () => TP.STARTER_TEMPLATES.map((t: any) => ({ id: t.id, title: t.title, description: t.description, ns: t.ns })), []);
const IDS = TP.STARTER_TEMPLATES.map((t: any) => t.id);
for (const id of [...IDS, 'nope', '']) await o.run('starterTemplate', id || 'empty', (x: string) => { const t = TP.starterTemplate(x); return t === undefined ? null : { id: t.id, title: t.title, description: t.description, ns: t.ns }; }, [id]);
for (const t of TP.STARTER_TEMPLATES) {
  for (const ns of [t.ns, 'acme', 'a1_b', 'x']) {
    await o.run('templateYaml', `${t.id} ${ns}`, (id: string, n: string) => TP.starterTemplate(id).yaml(n), [t.id, ns]);
    await o.run('templateTraits', `${t.id} ${ns}`, (id: string, n: string) => TP.starterTemplate(id).traits(n), [t.id, ns]);
  }
  for (const ns of ['pca', 'Bad', '', 'a-b', '1abc', 'a'.repeat(33), 5, null, 'a.b']) {
    await o.run('templateYaml', `${t.id} bad ${JSON.stringify(ns)}`, (id: string, n: any) => TP.starterTemplate(id).yaml(n), [t.id, ns]);
    await o.run('templateTraits', `${t.id} bad ${JSON.stringify(ns)}`, (id: string, n: any) => TP.starterTemplate(id).traits(n), [t.id, ns]);
  }
}
refWrite(o, 'actions-data');
