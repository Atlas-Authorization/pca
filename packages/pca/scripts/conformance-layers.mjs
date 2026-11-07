// The conformance layers (conformance/LAYERS.md): one definition shared by gen-conformance-layers.mjs (writes
// conformance/layers.json), the TS conformance test and the cross-language gate (scripts/pca-conformance-all.mjs), so a
// vector is tagged the same way everywhere.

export const LAYERS = [
  { id: 'wire', title: 'Wire', scope: 'strict JSON profile, canonical form, base64url, the PCA-Action header, PCActn structure and version' },
  { id: 'proof', title: 'Proof', scope: 'PCActn signatures and bindings: audience, validity window, plan inclusion, leaf signature, counter format, threshold shares, post-quantum artifacts and suites' },
  { id: 'capability', title: 'Capability', scope: 'delegation chains: chain signatures and lineage, attenuation, grant_ref binding, chain pins, depth and malformed capabilities' },
  { id: 'policy', title: 'Policy', scope: 'policy decisions: root, envelope and delegated caveats, envelope predicates, predicates / tool_schema caveats, unknown types, missing context; Intent Layer decisions' },
  { id: 'stateful', title: 'Stateful', scope: 'ordered sequences against one store: replay, counter ordering, revocation mid-sequence, trust-budget depletion' },
  { id: 'extension', title: 'Extension', scope: 'extension members that are not part of PCA Core: the optimistic path (claims, challenge window, fraud proofs, settlement records) and the transparency ledger (Merkle inclusion and consistency proofs, signed tree heads, witness cosignatures, checkpoint chains)' },
  { id: 'integration', title: 'Integration', scope: 'adapter behaviour (HTTP middleware, framework adapters, MCP); no shared vectors yet, covered by each SDK\'s own tests' },
];
export const LAYER_IDS = LAYERS.map((l) => l.id);

/** vectors.json `primitives` tables -> layer. A table missing here is an error in gen-conformance-layers.mjs. */
export const TABLE_LAYER = {
  canonical: 'wire',
  json_parse: 'wire',
  b64u: 'wire',
  pca_header: 'wire',
  merkle: 'proof',
  params_digest_empty: 'proof',
  threshold_share: 'proof',
  threshold_set: 'proof',
  signer_set_hash: 'proof',
  pq_artifact: 'proof',
  chain_pin: 'capability',
  malformed: 'capability',
  depth: 'capability',
  caveat_eval: 'policy',
  intent_schema: 'policy',
  intent_revocation: 'policy',
  intent_world: 'policy',
  intent_provenance: 'policy',
  intent_classifier: 'policy',
  intent_wb_active: 'policy',
  intent_read_purpose: 'policy',
  intent_map_commit: 'policy',
  intent_map: 'policy',
};

/** The other committed vector files of conformance/ -> layer (suite primitives are proof). */
export const FILE_LAYER = {
  'canonical-number-vectors.json': 'wire',
  'fndsa-vectors.json': 'proof',
  'frost-pq-vectors.json': 'proof',
  'allowlist-anchor-vectors.json': 'proof',
  'attestation-evidence-vectors.json': 'proof',
  'less-vectors.json': 'proof',
  'sha384-vectors.json': 'proof',
  'intent-state-vectors.json': 'policy',
  'policy-vectors.json': 'policy',
  'decision-vectors.json': 'policy',
  'goal-commit-vectors.json': 'proof',
  'model-rules-vectors.json': 'policy',
  'stateful-vectors.json': 'stateful',
  'mesh-vectors.json': 'proof',
  'passport-vectors.json': 'proof',
  'optimistic-vectors.json': 'extension',
  'ledger-vectors.json': 'extension',
  'operation-vectors.json': 'extension',
  'plan-vectors.json': 'extension',
  'staleness-vectors.json': 'extension',
  'assurance-vectors.json': 'extension',
  'caveat-lang-vectors.json': 'capability',
  'forbid-certificate-vectors.json': 'policy',
  'policy-link-vectors.json': 'policy',
  'k3-vectors.json': 'extension',
  'fresh-at-vectors.json': 'proof',
  'provenance-vectors.json': 'extension',
  'sigstore-vectors.json': 'extension',
  // K6 files (unclassified when K6 merged: the layer generator refused the whole corpus)
  'pca-grant-vectors.json': 'extension',
  'blueprint-vectors.json': 'capability',
  'a2a-vectors.json': 'extension',
  // K7-K9 files (unclassified when they merged: the layer generator refused the whole corpus)
  'break-glass-vectors.json': 'extension',
  'k4-vectors.json': 'extension',
  'lease-vectors.json': 'extension',
  'missing-context-vectors.json': 'policy',
  'obligations-vectors.json': 'policy',
  'undo-vectors.json': 'extension',
  'policy-classes-vectors.json': 'policy',
  'readside-vectors.json': 'extension',
  'runtime-claim-vectors.json': 'extension',
  'vault-aggregate-vectors.json': 'extension',
  'workflow-vectors.json': 'extension',
  'producer-vectors.json': 'proof',
  'arg-provenance-vectors.json': 'policy',
};

/** A PCActn verdict is tagged with the layer of its FIRST failing check in this order; an accepted one is `proof`. */
export const CHECK_ORDER = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter_format', 'intent'];
export const CHECK_LAYER = {
  wire: 'wire',
  version: 'wire',
  audience: 'proof',
  validity: 'proof',
  chain: 'capability',
  grant_ref_bound: 'capability',
  plan_inclusion: 'proof',
  leaf_signature: 'proof',
  counter_format: 'proof',
  intent: 'policy',
};

/** Layer of a PCActn vector from its expected (or reference) verdict `{ allow, checks: { name: bool } }`. */
export function layerOfVerdict(v) {
  if (!v || v.allow === true) return 'proof';
  const checks = v.checks ?? {};
  const first = CHECK_ORDER.find((k) => k in checks && !checks[k]);
  return first ? CHECK_LAYER[first] : 'proof';
}

/** Layer of one cross-language gate item (driver kinds) given the reference verdict for it. */
export function layerOfGateItem(kind, ref) {
  if (kind === 'canon') return 'wire';
  if (kind === 'chain') return 'capability';
  if (kind === 'policy') return 'policy';
  if (kind === 'stateful') return 'stateful';
  if (kind in TABLE_LAYER) return TABLE_LAYER[kind];
  return layerOfVerdict(ref);
}
