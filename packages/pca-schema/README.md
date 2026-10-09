# @atlasauth/pca-schema

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

## License

MIT - see LICENSE
