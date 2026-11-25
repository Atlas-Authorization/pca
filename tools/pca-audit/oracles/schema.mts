// Oracle: @atlasauth/pca-schema (published wire JSON Schemas + the structural validator). Deterministic.
// PORTING (net.atlasauth.pca.schema.Schema):
//   schemas()                 -> Schema.allSchemas() / PCACTN_SCHEMA / CAPABILITY_SCHEMA / DISCOVERY_SCHEMA; out is ALL_SCHEMAS, compared as JSON
//   validate(schemaOrName, v) -> Schema.validate(schema, v); a string first argument names a published schema
//                                (PCActn | Capability | PcaDiscoveryDocument), a JSON object is an ad-hoc schema.
//                                out {valid, errors}: errors compared exactly, in order.
import { Oracle, variants, refWrite } from './lib.mjs';

const M: any = await import('../../../packages/pca-schema/src/index.ts');
const o = new Oracle('schema', 'tools/pca-audit/oracles/schema.mts', 'TS-reference oracle for the PCA wire JSON Schemas and the structural validator.');

const NAMED: Record<string, any> = { PCActn: M.PCACTN_SCHEMA, Capability: M.CAPABILITY_SCHEMA, PcaDiscoveryDocument: M.DISCOVERY_SCHEMA };
// Oracle.run spreads the arguments: (schemaOrName, value)
const ref = (s: any, v: any) => M.validate(typeof s === 'string' ? NAMED[s] : s, v);
await o.run('schemas', 'all', () => M.ALL_SCHEMAS, []);

const cap = { id: 'c1', issuer: 'did:a', holder: 'did:b', caveats: [{ type: 'ttl', ms: 5 }], parent: 'c0', body_digest: 'dd', sig: 'ss', alg: 'ed25519', pq_pk: 'pk', pq_sig: 'ps' };
const act = {
  ver: 2, action: { verb: 'refund', resource: 'stripe:ch_1', params_digest: 'pd', reversibility_class: 'R2' }, grant_ref: 'g1', cap_chain: [cap],
  plan: { root: 'r', inclusion_proof: { index: 0, size: 1, path: [{ side: 'L', h: 'x' }] }, node_id: 'n', conditions_digest: 'cd' },
  attestation: { quote_digest: 'q', epoch: 3, model_id: 'm', measurement: 'ms', operator: 'op' },
  provenance: { causal_hash: 'ch', taint_level: 0.5, trusted_refs: ['a', 'b'] },
  freshness: { beacon_ref: 'b', epoch: 4, accumulator_witness: 'w' }, counter: 7, risk_claim: { r: 0.25, inputs: { a: 1 } },
  aud: 'https://rs', iat: 1_800_000_000, exp: 1_800_000_600, nonce: 'n1', caution: 0.1, rationale_commitment: 'rc', progress_step: { i: 1 },
  prohibition_evidence: [1], tool_binding: 'tb', alg: 'hybrid-ed25519-ml-dsa-65', pq_pk: 'ppk', sig: 'sig', pq_sig: 'psig', threshold: { k: 2 }, zk_compliance: { any: [1] }, bond_ref: 'bond',
};
const disc = {
  audience: 'https://rs', pca_versions: [1, 2], signature_suites: ['ed25519'], action_header: 'PCA-Action', required_checks: ['sig'],
  endpoints: { attestation_challenge: '/a', revocation_epoch: '/r', liveness_beacon: '/l', stepup: '/s', grant: '/g' }, trusted_roots: ['k'], metadata: { x: 1 },
};
const seeds: Array<[string, any, any]> = [['PCActn', act, 'act'], ['Capability', cap, 'cap'], ['PcaDiscoveryDocument', disc, 'disc']];
for (const [name, v, tag] of seeds) {
  await o.run('validate', `${tag}/valid`, ref, [name, v]);
  let i = 0;
  for (const [label, vv] of variants(v, { depth: 5, maxPaths: 400 })) await o.run('validate', `${tag}/${i++} ${label}`, ref, [name, vv]);
  // cross-schema: every seed against every schema
  for (const [n2] of seeds) await o.run('validate', `${tag}/as-${n2}`, ref, [n2, v]);
}
for (const bad of [null, 5, 'x', [], [1], true, {}, { ver: 2 }]) await o.run('validate', `root/${JSON.stringify(bad)}`, ref, ['PCActn', bad]);
for (const alg of ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65', 'rsa', '', null, 1]) await o.run('validate', `alg/${JSON.stringify(alg)}`, ref, ['Capability', { ...cap, alg }]);
for (const iat of [1, -0, 1.5, 1e21, 2 ** 53, '1', null, true]) await o.run('validate', `iat/${String(iat)}${Object.is(iat, -0) ? 'neg0' : ''}`, ref, ['PCActn', { ...act, iat }]);
for (const pe of [{}, [], 'x', null, 1, true]) await o.run('validate', `prohibition/${JSON.stringify(pe)}`, ref, ['PCActn', { ...act, prohibition_evidence: pe }]);
for (const ci of [[], [cap, cap], [null], [{}], 'x']) await o.run('validate', `capchain/${JSON.stringify(ci).slice(0, 30)}`, ref, ['PCActn', { ...act, cap_chain: ci }]);

// ad-hoc schemas exercising every keyword the validator knows
const adhoc: Array<[string, any, any[]]> = [
  ['plain-object', { type: 'object', required: ['a', 'b'], properties: { a: { type: 'string' }, b: { type: ['integer', 'null'] } }, additionalProperties: false },
    [{ a: 'x', b: 1 }, { a: 'x', b: null }, { a: 'x' }, { a: 1, b: 1.5 }, { a: 'x', b: 1, c: 2 }, [], null, { c: 1, d: 2 }, { a: 'x', b: -0 }, { a: 'x', b: 1.0 }]],
  ['addl-schema', { type: 'object', properties: { a: {} }, additionalProperties: { type: 'string' } }, [{ a: 1, b: 2 }, { b: 'x' }]],
  ['addl-noprops', { type: 'object', additionalProperties: false }, [{ a: 1 }, {}]],
  ['enum', { enum: ['a', 1, true, null, 1.5, -0, 'é\n"'] }, ['a', 1, true, null, 1.5, 0, -0, 'x', [], {}, 'é\n"', 2, false]],
  ['enum-typed', { type: 'string', enum: ['a', 'b'] }, ['a', 'c', 1]],
  ['number', { type: 'number' }, [1, 1.5, -0, 1e21, 'x', null]],
  ['integer', { type: 'integer' }, [1, 1.5, -0, 0, 1e21, 2 ** 53, 'x']],
  ['bool', { type: 'boolean' }, [true, false, 0, null]],
  ['null', { type: 'null' }, [null, 0, {}]],
  ['array-items', { type: 'array', items: { type: 'integer' } }, [[], [1, 2], [1, 'x', 2.5], 'x', [[1]]]],
  ['nested-array', { type: 'array', items: { type: 'array', items: { type: 'string' } } }, [[['a'], [1]], [[], ['b', 2]]]],
  ['ref-ok', { $defs: { s: { type: 'string' } }, type: 'object', properties: { a: { $ref: '#/$defs/s' } } }, [{ a: 'x' }, { a: 1 }]],
  ['ref-missing', { type: 'object', properties: { a: { $ref: '#/$defs/nope' } } }, [{ a: 'x' }, {}]],
  ['ref-remote', { type: 'object', properties: { a: { $ref: 'http://x/y' } } }, [{ a: 'x' }]],
  ['ref-nonschema', { $defs: { s: 5 }, properties: { a: { $ref: '#/$defs/s' } } }, [{ a: 'x' }]],
  ['ref-root', { $ref: '#/$defs/t', $defs: { t: { type: 'string' } } }, ['x', 1]],
  ['ref-proto', { properties: { a: { $ref: '#/constructor' } } }, [{ a: 1 }]],
  ['ref-array-walk', { $defs: { l: [1] }, properties: { a: { $ref: '#/$defs/l/0' } } }, [{ a: 1 }]],
  ['required-only', { required: ['x'] }, [{}, { x: 1 }, [], 5, { __proto__x: 1 }]],
  ['required-nested', { type: 'object', properties: { o: { type: 'object', required: ['k'], properties: { k: { type: 'string' } } } } }, [{ o: {} }, { o: { k: 1 } }, { o: [] }]],
  ['empty', {}, [null, 1, 'x', [], {}]],
  ['type-multi', { type: ['object', 'array'] }, [{}, [], 'x', null]],
];
for (const [name, sch, vals] of adhoc) {
  let i = 0;
  for (const v of vals) await o.run('validate', `adhoc/${name}/${i++}`, ref, [sch, v]);
}
refWrite(o, 'schema');
