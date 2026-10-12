/**
 * JSON Schema (draft 2020-12) for the Proof-Carrying Authority wire types.
 *
 * These are the on-the-wire shapes a resource server receives and a client emits: the signed
 * `PCActn` (spec §7, WIRE v2), an attenuable `Capability` hop (spec §5.2 — a `cap_chain` is an array
 * of these), and the `.well-known/pca-configuration` discovery document. They are published as plain,
 * self-contained JSON Schema objects so that ANY language can consume them: feed `PCACTN_SCHEMA` to a
 * code generator (quicktype, `json-schema-to-typescript`, `datamodel-code-generator`, …) to mint native
 * types, or to a draft-2020-12 validator (ajv, `jsonschema`, `gojsonschema`, …) to validate payloads
 * before signing or after receipt.
 *
 * HONEST SCOPE: these schemas describe STRUCTURE (which fields exist, their JSON types, which are
 * required). They do NOT — and cannot — express PCA's security invariants: a schema cannot check that
 * `sig` verifies under the leaf holder key, that the capability chain only attenuates, that the action
 * is a committed plan node, or that `iat < exp`. Those are the verifier's job (`verifyPCActnCore` in
 * `@atlasauth/pca`). Passing these schemas means "well-formed", never "authorized".
 *
 * The schemas mirror the live TypeScript interfaces (`PCActn`, `Capability`, `PcaDiscoveryDocument`)
 * exactly, including the optional crypto-agility / frontier fields (`alg`, `pq_pk`, `pq_sig`,
 * `threshold`, `zk_compliance`, `caution`, …). Every object is `additionalProperties: true`: the wire
 * is deliberately extensible, so an unknown future field must never fail structural validation.
 */

// ---- a minimal JSON Schema shape (the subset these documents use) ---------------------------------

export type JsonSchemaType = 'object' | 'array' | 'string' | 'number' | 'integer' | 'boolean' | 'null';

/**
 * The slice of draft 2020-12 these schemas use. Extra keys are permitted (`[key: string]: unknown`) so
 * authors can annotate freely and downstream generators can read vocabulary this type does not name.
 */
export interface JsonSchema {
  $schema?: string;
  $id?: string;
  $ref?: string;
  $defs?: Record<string, JsonSchema>;
  title?: string;
  description?: string;
  type?: JsonSchemaType | JsonSchemaType[];
  properties?: Record<string, JsonSchema>;
  required?: string[];
  enum?: Array<string | number | boolean | null>;
  items?: JsonSchema;
  additionalProperties?: boolean | JsonSchema;
  minItems?: number;
  [key: string]: unknown;
}

const DRAFT = 'https://json-schema.org/draft/2020-12/schema';
const str: JsonSchema = { type: 'string' };

// ---- reusable sub-schemas (spec §7 nested objects) ------------------------------------------------

/** A single caveat: a conjunctive constraint tagged by `type` (§5.2). Extra keys are the caveat body. */
const caveatDef: JsonSchema = {
  type: 'object',
  required: ['type'],
  properties: { type: str },
  additionalProperties: true,
};

/** One hop of the attenuable capability chain (spec §5.2 `Capability`). */
const capabilityDef: JsonSchema = {
  type: 'object',
  required: ['id', 'issuer', 'holder', 'caveats', 'body_digest', 'sig'],
  properties: {
    id: str,
    issuer: str,
    holder: str,
    caveats: { type: 'array', items: { $ref: '#/$defs/caveat' } },
    parent: str,
    body_digest: str,
    sig: str,
    alg: { type: 'string', enum: ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'] },
    pq_pk: str,
    pq_sig: str,
  },
  additionalProperties: true,
};

/** The action being authorized: verb/resource plus the canonical digest of its params (§7). */
const actionDef: JsonSchema = {
  type: 'object',
  required: ['verb', 'resource', 'params_digest', 'reversibility_class'],
  properties: { verb: str, resource: str, params_digest: str, reversibility_class: str },
  additionalProperties: true,
};

/** A Merkle inclusion proof that the action is a committed plan node (`@atlasauth/pca` merkle.ts). */
const inclusionProofDef: JsonSchema = {
  type: 'object',
  required: ['index', 'size', 'path'],
  properties: {
    index: { type: 'integer' },
    size: { type: 'integer' },
    path: { type: 'array', items: { type: 'object', additionalProperties: true } },
  },
  additionalProperties: true,
};

/** The plan binding: committed root + inclusion proof for the acting node (§7, L1). */
const planDef: JsonSchema = {
  type: 'object',
  required: ['root', 'inclusion_proof', 'node_id'],
  properties: {
    root: str,
    inclusion_proof: { $ref: '#/$defs/inclusionProof' },
    node_id: str,
    conditions_digest: str,
  },
  additionalProperties: true,
};

/** The agent's claimed risk `r ∈ [0,1]` plus the inputs behind it (§7; monotone with `caution`). */
const riskClaimDef: JsonSchema = {
  type: 'object',
  required: ['r', 'inputs'],
  properties: { r: { type: 'number' }, inputs: { type: 'object', additionalProperties: true } },
  additionalProperties: true,
};

/**
 * M5 TEE attestation block. The schema validates STRUCTURE only (stub values pass, for back-compat), but
 * enforcement is now REAL and opt-in on the verifier: `verifyPCActnCore(..., { enforce: { attestation } })`
 * runs the full attestation verifier (`createAttestationVerifier` / the SEV-SNP hardware backend) and fails
 * closed on an absent / invalid / unbound quote. Passing this schema still means "well-formed", never "attested".
 */
const attestationDef: JsonSchema = {
  type: 'object',
  required: ['quote_digest', 'epoch', 'model_id', 'measurement', 'operator'],
  properties: {
    quote_digest: str,
    epoch: { type: 'integer' },
    model_id: str,
    measurement: str,
    operator: str,
  },
  additionalProperties: true,
};

/**
 * M1 provenance / taint block. Structure only here; the M1 taint gate is now REAL and opt-in on the
 * verifier (`verifyPCActnCore(..., { enforce: { taint } })`): declared refs are independently re-classified
 * from server-held facts and an over-tainted / unverifiable lineage fails closed.
 */
const provenanceDef: JsonSchema = {
  type: 'object',
  required: ['causal_hash', 'taint_level', 'trusted_refs'],
  properties: {
    causal_hash: str,
    taint_level: { type: 'number' },
    trusted_refs: { type: 'array', items: str },
  },
  additionalProperties: true,
};

/**
 * M3 freshness block (beacon + accumulator witness). Structure only here; the M3 freshness gate is now
 * REAL and opt-in on the verifier (`verifyPCActnCore(..., { enforce: { freshness } })`): a missing / stub /
 * stale anchor (reconstructed from `epoch`) fails closed.
 */
const freshnessDef: JsonSchema = {
  type: 'object',
  required: ['beacon_ref', 'epoch', 'accumulator_witness'],
  properties: { beacon_ref: str, epoch: { type: 'integer' }, accumulator_witness: str },
  additionalProperties: true,
};

// ---- the three published wire schemas -------------------------------------------------------------

/**
 * `PCActn` — a signed intent for ONE action (spec §7, WIRE v2). Required: the core signed body
 * (`ver`, `action`, `grant_ref`, `cap_chain`, `plan`, `attestation`, `provenance`, `freshness`,
 * `counter`, `risk_claim`) plus the freshness binding (`aud`, `iat`, `exp`) and the leaf signature
 * (`sig`). Optional: the per-action `nonce`, the frontier slots (`caution`, `rationale_commitment`,
 * `progress_step`, `prohibition_evidence`, `tool_binding`), the crypto-agility fields (`alg`, `pq_pk`,
 * `pq_sig`), the risk-adaptive `threshold` signature, `zk_compliance`, and `bond_ref`.
 */
export const PCACTN_SCHEMA: JsonSchema = {
  $schema: DRAFT,
  $id: 'https://atlasauth.net/schemas/pca/pcactn.schema.json',
  title: 'PCActn',
  description: 'Proof-Carrying Authority action object (spec §7, wire format v2).',
  type: 'object',
  required: [
    'ver',
    'action',
    'grant_ref',
    'cap_chain',
    'plan',
    'attestation',
    'provenance',
    'freshness',
    'counter',
    'risk_claim',
    'aud',
    'iat',
    'exp',
    'sig',
  ],
  properties: {
    ver: { type: 'integer' },
    action: { $ref: '#/$defs/action' },
    grant_ref: str,
    cap_chain: { type: 'array', minItems: 1, items: { $ref: '#/$defs/capability' } },
    plan: { $ref: '#/$defs/plan' },
    attestation: { $ref: '#/$defs/attestation' },
    provenance: { $ref: '#/$defs/provenance' },
    freshness: { $ref: '#/$defs/freshness' },
    counter: { type: 'integer' },
    risk_claim: { $ref: '#/$defs/riskClaim' },
    aud: str,
    iat: { type: 'integer' },
    exp: { type: 'integer' },
    nonce: str,
    caution: { type: 'number' },
    rationale_commitment: str,
    progress_step: { type: 'object', additionalProperties: true },
    prohibition_evidence: { type: ['object', 'array'] },
    tool_binding: str,
    alg: { type: 'string', enum: ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'] },
    pq_pk: str,
    sig: str,
    pq_sig: str,
    threshold: { type: 'object', additionalProperties: true },
    zk_compliance: { description: 'Opaque zk-compliance proof; shape is verifier-defined.' },
    bond_ref: str,
  },
  additionalProperties: true,
  $defs: {
    caveat: caveatDef,
    capability: capabilityDef,
    action: actionDef,
    inclusionProof: inclusionProofDef,
    plan: planDef,
    riskClaim: riskClaimDef,
    attestation: attestationDef,
    provenance: provenanceDef,
    freshness: freshnessDef,
  },
};

/** `Capability` — one hop of a `cap_chain` (spec §5.2). Standalone: validates a single hop. */
export const CAPABILITY_SCHEMA: JsonSchema = {
  $schema: DRAFT,
  $id: 'https://atlasauth.net/schemas/pca/capability.schema.json',
  title: 'Capability',
  description: 'An attenuable capability chain hop (spec §5.2).',
  ...capabilityDef,
  $defs: { caveat: caveatDef },
};

/** `PcaDiscoveryDocument` — the `.well-known/pca-configuration` resource-server descriptor. */
export const DISCOVERY_SCHEMA: JsonSchema = {
  $schema: DRAFT,
  $id: 'https://atlasauth.net/schemas/pca/discovery.schema.json',
  title: 'PcaDiscoveryDocument',
  description: 'The .well-known/pca-configuration discovery document (internet-wide integration).',
  type: 'object',
  required: ['audience', 'pca_versions', 'signature_suites', 'action_header'],
  properties: {
    audience: str,
    pca_versions: { type: 'array', items: { type: 'integer' } },
    signature_suites: { type: 'array', items: str },
    action_header: str,
    required_checks: { type: 'array', items: str },
    endpoints: { $ref: '#/$defs/endpoints' },
    trusted_roots: { type: 'array', items: str },
    metadata: { type: 'object', additionalProperties: true },
  },
  additionalProperties: true,
  $defs: {
    endpoints: {
      type: 'object',
      properties: {
        attestation_challenge: str,
        revocation_epoch: str,
        liveness_beacon: str,
        stepup: str,
        grant: str,
      },
      additionalProperties: true,
    },
  },
};

/** Every published schema, keyed by its wire-type name — handy for a codegen loop over the set. */
export const ALL_SCHEMAS: Record<string, object> = {
  PCActn: PCACTN_SCHEMA,
  Capability: CAPABILITY_SCHEMA,
  PcaDiscoveryDocument: DISCOVERY_SCHEMA,
};

// ---- a tiny, dependency-free STRUCTURAL validator -------------------------------------------------

/** The outcome of {@link validate}: `valid` plus a human-readable `errors` list (empty when valid). */
export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function jsonTypeOf(v: unknown): JsonSchemaType {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'number') return Number.isInteger(v) ? 'integer' : 'number';
  if (typeof v === 'boolean') return 'boolean';
  if (typeof v === 'string') return 'string';
  return 'object';
}

function matchesType(expected: JsonSchemaType, v: unknown): boolean {
  switch (expected) {
    case 'object':
      return isRecord(v);
    case 'array':
      return Array.isArray(v);
    case 'string':
      return typeof v === 'string';
    case 'number':
      return typeof v === 'number' && Number.isFinite(v);
    case 'integer':
      return typeof v === 'number' && Number.isInteger(v);
    case 'boolean':
      return typeof v === 'boolean';
    case 'null':
      return v === null;
  }
  return false;
}

/** Resolve a local `#/...` JSON pointer against the root schema (only own keys are walked). */
function resolveRef(root: JsonSchema, ref: string): JsonSchema | undefined {
  if (!ref.startsWith('#/')) return undefined;
  let cur: unknown = root;
  for (const token of ref.slice(2).split('/')) {
    if (!isRecord(cur) || !Object.prototype.hasOwnProperty.call(cur, token)) return undefined;
    cur = cur[token];
  }
  return isRecord(cur) ? cur : undefined;
}

function label(path: string): string {
  return path === '' ? '(root)' : path;
}

function checkNode(schema: JsonSchema, value: unknown, path: string, root: JsonSchema, errors: string[]): void {
  if (typeof schema.$ref === 'string') {
    const resolved = resolveRef(root, schema.$ref);
    if (resolved === undefined) {
      errors.push(`${label(path)}: unresolved $ref '${schema.$ref}'`);
      return;
    }
    checkNode(resolved, value, path, root, errors);
    return;
  }

  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((t) => matchesType(t, value))) {
      errors.push(`${label(path)}: expected type ${types.join('|')}, got ${jsonTypeOf(value)}`);
      return; // a wrong base type makes any deeper check meaningless
    }
  }

  if (Array.isArray(schema.enum) && !schema.enum.some((e) => e === value)) {
    errors.push(`${label(path)}: value is not one of [${schema.enum.map((e) => JSON.stringify(e)).join(', ')}]`);
  }

  if (isRecord(value)) {
    if (Array.isArray(schema.required)) {
      for (const key of schema.required) {
        if (!Object.prototype.hasOwnProperty.call(value, key)) {
          errors.push(`${path === '' ? '' : path + '.'}${key}: missing required property '${key}'`);
        }
      }
    }
    if (schema.properties) {
      for (const [key, sub] of Object.entries(schema.properties)) {
        if (Object.prototype.hasOwnProperty.call(value, key)) {
          checkNode(sub, value[key], `${path === '' ? '' : path + '.'}${key}`, root, errors);
        }
      }
    }
    if (schema.additionalProperties === false && schema.properties) {
      const allowed = new Set(Object.keys(schema.properties));
      for (const key of Object.keys(value)) {
        if (!allowed.has(key)) errors.push(`${path === '' ? '' : path + '.'}${key}: additional property not allowed`);
      }
    }
  }

  const items = schema.items;
  if (Array.isArray(value) && items) {
    value.forEach((el, i) => checkNode(items, el, `${path}[${i}]`, root, errors));
  }
}

/**
 * A LIGHTWEIGHT, dependency-free STRUCTURAL validator — just enough to catch the common mistakes
 * before signing or on receipt: wrong JSON type, a missing required property (named in the error), a
 * value outside an `enum`, and the same checks recursively through nested objects, arrays and local
 * `#/$defs/...` `$ref`s. It intentionally does NOT implement all of draft 2020-12 (no `pattern`,
 * `format`, `oneOf`/`anyOf`, numeric bounds, `$dynamicRef`, remote `$ref`, …).
 *
 * For FULL draft-2020-12 validation, feed these same schema objects to a real validator — ajv in
 * JavaScript, or the native library in any other language (`jsonschema`, `gojsonschema`, …). The
 * schemas are the source of truth; this function is a zero-dependency convenience.
 */
export function validate(schema: JsonSchema, value: unknown): ValidationResult {
  const errors: string[] = [];
  checkNode(schema, value, '', schema, errors);
  return { valid: errors.length === 0, errors };
}
