// Generates sdks/java-pca/src/net/atlasauth/pca/actions/ActionData.java: the built-in action defs, the domain defs, the legacy tables and the
// starter templates of pca-actions as JSON text embedded in Java string constants (parsed once by ActionBuiltin / ActionTemplates).
// A template's yaml and trait functions are captured under a placeholder namespace and checked to depend on the namespace by substitution only.
// Run: tsx --tsconfig tools/pca-audit/oracles/tsconfig.json tools/pca-audit/oracles/gen-actions-data-java.mts
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as DM0 from '../../../packages/pca-actions/src/domain.ts';
import * as TP0 from '../../../packages/pca-actions/src/templates.ts';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BI = un(B0), DM = un(DM0), TP = un(TP0);
const PH = 'zzzns0';

const esc = (s: string): string => {
  let o = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const ch = s[i]!;
    if (ch === '\\') o += '\\\\';
    else if (ch === '"') o += '\\"';
    else if (ch === '\n') o += '\\n';
    else if (ch === '\r') o += '\\r';
    else if (ch === '\t') o += '\\t';
    else if (c < 0x20 || c > 0x7e) o += '\\u' + c.toString(16).padStart(4, '0');
    else o += ch;
  }
  return o;
};
const chunks = (s: string): string => {
  const parts: string[] = [];
  for (let i = 0; i < s.length; i += 6000) parts.push(s.slice(i, i + 6000));
  return '{\n        ' + parts.map((p) => `"${esc(p)}"`).join(',\n        ') + ',\n    }';
};
const field = (name: string, text: string) => `    static final String[] ${name} = ${chunks(text)};\n`;

const subst = (s: string, ns: string) => s.split(PH).join(ns);
let out = `package net.atlasauth.pca.actions;

// GENERATED from the reference tables (do not edit by hand): the data of the built-in connector actions, the domain vocabularies and the starter templates.
final class ActionData {
    private ActionData() {}

    static String join(String[] parts) { return String.join("", parts); }

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
out += `    static final String PLACEHOLDER_NS = "${PH}";\n}\n`;
fs.writeFileSync(fileURLToPath(new URL('../../../sdks/java-pca/src/net/atlasauth/pca/actions/ActionData.java', import.meta.url)), out);
console.log(`wrote ActionData.java (${out.length} chars, ${tpl.length} templates)`);
