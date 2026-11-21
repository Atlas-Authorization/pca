// Generates sdks/swift-pca/Sources/AtlasPCAVerify/ActionData.swift: the built-in action defs, the domain defs, the legacy tables and the starter
// templates of pca-actions as JSON text embedded in raw string constants (parsed once by ActionBuiltin / ActionTemplates).
// A template's yaml and trait functions are captured under a placeholder namespace and checked to depend on the namespace by substitution only.
// Run: tsx --tsconfig tools/pca-audit/oracles/tsconfig.json tools/pca-audit/oracles/gen-actions-data-swift.mts
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as DM0 from '../../../packages/pca-actions/src/domain.ts';
import * as TP0 from '../../../packages/pca-actions/src/templates.ts';
import * as RL0 from '../../../packages/pca-actions/src/import/rules.ts';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BI = un(B0), DM = un(DM0), TP = un(TP0), RL = un(RL0);
const PH = 'zzzns0';

const lit = (s: string): string => {
  if (s.includes('"###')) throw new Error('a table contains the raw string terminator');
  return `###"${s}"###`;
};
const field = (name: string, text: string) => `    static let ${name}: String = ${lit(text)}\n`;

const subst = (s: string, ns: string) => s.split(PH).join(ns);
let out = `// GENERATED from the reference tables (do not edit by hand): the data of the built-in connector actions, the domain vocabularies and the starter templates.
enum ActionData {
`;
out += field('BUILTIN_DEFS', JSON.stringify(BI.BUILTIN_DEFS));
out += field('DOMAIN_DEFS', JSON.stringify(DM.DOMAIN_DEFS));
out += field('LEGACY_CATALOG', JSON.stringify(BI.LEGACY_CATALOG));
out += field('LEGACY_ONTOLOGY_EFFECT', JSON.stringify(BI.LEGACY_ONTOLOGY_EFFECT));
out += field('RESOLUTIONS', JSON.stringify(BI.RESOLUTIONS));
out += field('DOMAIN_VERBS', JSON.stringify(DM.DOMAIN_VERBS));
const tpl: any[] = [];
for (const t of TP.STARTER_TEMPLATES) {
  const y = t.yaml(PH), tr = JSON.stringify(t.traits(PH));
  for (const ns of ['qqqns9', t.ns, 'a1_b']) {
    if (t.yaml(ns) !== subst(y, ns)) throw new Error(`template ${t.id}: yaml is not a pure namespace substitution for '${ns}'`);
    if (JSON.stringify(t.traits(ns)) !== subst(tr, ns)) throw new Error(`template ${t.id}: traits are not a pure namespace substitution for '${ns}'`);
  }
  tpl.push({ id: t.id, title: t.title, description: t.description, ns: t.ns, yaml: y, traits: JSON.parse(tr) });
}
out += field('TEMPLATES', JSON.stringify(tpl));
out += `    static let PLACEHOLDER_NS = "${PH}"\n}\n`;
fs.writeFileSync(fileURLToPath(new URL('../../../sdks/swift-pca/Sources/AtlasPCAVerify/ActionData.swift', import.meta.url)), out);
// the shipped suggestion rules (the unsealed rule set) and the digest recorded when they were published
const rules = `// GENERATED from the reference tables (do not edit by hand): the shipped suggestion rule set (version ${RL.DEFAULT_RULES_VERSION}) as JSON text, and its sealed digest.
enum ImportRulesData {
    static let SEALED_DIGEST = ${JSON.stringify(RL.DEFAULT_RULES_SEALED.digest)}
    static let JSON_TEXT: String = ${lit(JSON.stringify(RL.DEFAULT_RULES))}
}
`;
fs.writeFileSync(fileURLToPath(new URL('../../../sdks/swift-pca/Sources/AtlasPCAVerify/ImportRulesData.swift', import.meta.url)), rules);
console.log(`wrote ActionData.swift (${out.length} chars, ${tpl.length} templates)`);
