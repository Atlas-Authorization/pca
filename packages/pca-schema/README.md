# @atlasauth/pca-schema

> Maturity: **stable** (stable core). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

JSON Schema (draft 2020-12) for the Proof-Carrying Authority wire types — **PCActn**,
**capability / grant**, and the **discovery document** — so any language can codegen types and
validate payloads.

## Install

```sh
npm i @atlasauth/pca-schema
```

## Usage

```ts
import { PCACTN_SCHEMA, CAPABILITY_SCHEMA, DISCOVERY_SCHEMA, ALL_SCHEMAS, validate } from '@atlasauth/pca-schema';

const { valid, errors } = validate(PCACTN_SCHEMA, incomingPcactn);
if (!valid) throw new Error(errors.join('; '));
```

`validate` is a small, dependency-free structural checker (type / required / nested objects / `$ref`
into `$defs`) — enough to catch obvious malformations. For full draft-2020-12 validation, feed the
exported schema objects to [ajv](https://ajv.js.org) or your language's validator; `ALL_SCHEMAS` maps
every schema by name for codegen pipelines.

`ALL_SCHEMAS` is keyed `PCActn`, `Capability`, `PcaDiscoveryDocument`.

## Status

The schemas describe structure only (fields, JSON types, required properties). They cannot express PCA's security invariants: that `sig` verifies, that the capability chain only attenuates, or that the action is a committed plan node. Passing validation means "well-formed", never "authorized"; use `verifyPCActnCore` from [`@atlasauth/pca`](https://www.npmjs.com/package/@atlasauth/pca) for that. Objects allow additional properties so future wire fields do not fail validation.

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| A top-level value that is not an object (string, array, null) | `valid: false`, error `(root): expected type object, got <type>` |
| A required property absent | `valid: false`, an error naming the property |
| A property of the wrong JSON type, or a value outside an `enum` | `valid: false`, an error naming the path |
| A `$ref` that is not a local `#/...` pointer, or that names a missing definition | `valid: false`, `unresolved $ref` |
| A `NaN` or infinite number where `number` is expected | `valid: false` |
| A schema type name the checker does not know | no value matches it, so `valid: false` |
| An extra property | accepted, unless the schema sets `additionalProperties: false` |

`validate` never throws on a malformed value; it returns the list of errors.

## Limits

- It is a structural checker only: no `pattern`, `format`, `oneOf` / `anyOf`, numeric bounds, `$dynamicRef` or remote `$ref`. Use a full draft 2020-12 validator when you need those.
- A valid result is "well-formed", never "authorized": it does not verify signatures, attenuation or plan membership.
- Objects allow additional properties by default, so an unknown field is not an error.

## License

MIT - see LICENSE
