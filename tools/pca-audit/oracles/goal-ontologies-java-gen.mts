// Data generator (not an oracle): writes sdks/java-pca/src/net/atlasauth/pca/goal/GoalOntologies.java, the five shipped intent ontologies
// (payments, email, calendar_travel, code_repos, data_access) and the selector catalog of each domain, as JSON embedded in the class.
// They are derived data (the ontologies read the action definitions), so a native port embeds the reference output instead of re-deriving it.
// Run from the repo root with the shared tsx env; re-run to refresh.
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import * as O0 from '../../../packages/pca-goal/src/ontologies/index';
import * as S0 from '../../../packages/pca-goal/src/selectors';
const O: any = (O0 as any).default ?? O0;
const S: any = (S0 as any).default ?? S0;
const ALL = O.ALL_ONTOLOGIES ?? O.default?.ALL_ONTOLOGIES;
const jlit = (s: string): string => '"' + [...s].map((c) => {
  const n = c.charCodeAt(0);
  if (c === '\\') return '\\\\';
  if (c === '"') return '\\"';
  if (n > 126 || n < 32) return '\\u' + n.toString(16).padStart(4, '0');
  return c;
}).join('') + '"';
const chunked = (json: string): string => {
  const parts: string[] = [];
  for (let i = 0; i < json.length; i += 6000) parts.push('        ' + jlit(json.slice(i, i + 6000)));
  return parts.join('\n        + ');
};
const names = Object.keys(ALL).sort();
let src = `package net.atlasauth.pca.goal;

import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.Json;

/** The shipped intent ontologies and the selector catalog of each domain (generated reference data; see the generator for how it is derived). */
public final class GoalOntologies {
    private GoalOntologies() {}

    /** Names of the shipped ontologies. */
    public static final java.util.List<String> NAMES = java.util.List.of(${names.map(jlit).join(', ')});
`;
const parts: string[] = [];
for (const n of names) {
  src += `
    private static final String ONT_${n.toUpperCase()} =
${chunked(JSON.stringify(ALL[n]))};
`;
  src += `
    private static final String CAT_${n.toUpperCase()} =
${chunked(JSON.stringify(S.selCatalogOfDomain(n)))};
`;
}
src += `
    @SuppressWarnings("unchecked")
    private static Map<String, Object> parse(String s) { return (Map<String, Object>) Json.parse(s); }

    /** The intent ontology of a shipped domain (a fresh parsed copy), or null for an unknown name. */
    public static Map<String, Object> ontology(String name) {
        switch (name) {
${names.map((n) => `            case ${jlit(n)}: return parse(ONT_${n.toUpperCase()});`).join('\n')}
            default: return null;
        }
    }

    /** The selector catalog of a shipped domain ({known, verbs}), or null for an unknown name. */
    public static Map<String, Object> selCatalog(String name) {
        switch (name) {
${names.map((n) => `            case ${jlit(n)}: return parse(CAT_${n.toUpperCase()});`).join('\n')}
            default: return null;
        }
    }

    /** Every shipped ontology by name (the reference's ALL_ONTOLOGIES). */
    public static Map<String, Map<String, Object>> all() {
        Map<String, Map<String, Object>> m = new LinkedHashMap<>();
        for (String n : NAMES) m.put(n, ontology(n));
        return m;
    }
}
`;
fs.writeFileSync(fileURLToPath(new URL('../../../sdks/java-pca/src/net/atlasauth/pca/goal/GoalOntologies.java', import.meta.url)), src);
console.log('ok', names, src.length);
