// Oracle: the seeded provider catalog of packages/pca-connectors/src/providers/index.ts (one exported manifest per provider + BUILTIN_MANIFESTS), TS reference.
// Writes out/ref-connectors-providers.json.gz. Complements ref-connectors (whole-catalog `catalog/all`, validate / assert / digest of every built-in, authorize, exchange,
// refresh): this corpus pins the per-provider constants natives expose by name.
//
// PORTING (fn(args) -> native entry point; JSON values)
//   provider [id]            -> {manifest, digest, valid}   the exported provider constant with that id (google, github, slack, notion, hubspot, atlassian, salesforce, microsoft,
//                               shopify, snowflake, linear, zoom, stripe, dropbox, airtable); manifest = the declared manifest; digest = manifestDigest(manifest); valid = validateManifest(manifest).ok
//   builtinManifests []      -> {ids: [..in BUILTIN_MANIFESTS order], digests: [..], catalogDigest}   the order is part of the contract (catalog digest depends on registration order only through the sorted ids, the list order is for display)
//   invariants [id]          -> {defaultScopesSubset, scopesUnique, idMatchesKey, httpsEndpoints}   structural properties every built-in holds
//   unknownProvider [id]     -> {found: false}   getProvider(id) for an id outside the catalog (case, whitespace, prototype names)
import { Oracle, refWrite } from './lib.mjs';
const C: any = await import('../../../packages/pca-connectors/src/index.ts');
const o = new Oracle('connectors-providers', 'tools/pca-audit/oracles/connectors-providers.mts', 'TS-reference oracle for the seeded connector provider catalog.');
const P: any = C.providers;
const names = ['google', 'github', 'slack', 'notion', 'hubspot', 'atlassian', 'salesforce', 'microsoft', 'shopify', 'snowflake', 'linear', 'zoom', 'stripe', 'dropbox', 'airtable'];
const J = (x: any) => JSON.parse(JSON.stringify(x));
for (const n of names) {
  const m = J(P[n]);
  o.add('provider', n, [n], { manifest: m, digest: C.manifestDigest(P[n]), valid: C.validateManifest(P[n]).ok });
  o.add('invariants', n, [n], { defaultScopesSubset: m.defaultScopes.every((s: string) => m.scopesAvailable.includes(s)), scopesUnique: new Set(m.scopesAvailable).size === m.scopesAvailable.length, idMatchesKey: m.id === n, httpsEndpoints: [m.authorizeUrl, m.tokenUrl].every((u: string) => u.startsWith('https://')) });
}
o.add('builtinManifests', 'all', [], { ids: P.BUILTIN_MANIFESTS.map((m: any) => m.id), digests: P.BUILTIN_MANIFESTS.map((m: any) => C.manifestDigest(m)), catalogDigest: C.catalogDigest() });
for (const id of ['Google', 'google ', '', 'nope', 'constructor', '__proto__', 'toString', 'GOOGLE', 'goog']) o.add('unknownProvider', JSON.stringify(id), [id], { found: C.getProvider(id) !== undefined });
(o as any).constantByDesign = { invariants: 'structural properties every built-in provider holds, one case per provider', unknownProvider: 'ids outside the catalog: never found' };
refWrite(o, 'connectors-providers');
