# @atlasauth/pca-sandbox

> Maturity: **production**. Breaking changes to APIs or defaults are never made in a patch release. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Optional runtime containment for Proof-Carrying Authority. A verifier decides whether an action may happen; this package removes the ambient authority an agent's tools would otherwise have, so a bypassed check is bounded by what was authorized.

- **Capability sandbox.** A WebAssembly host whose only imports are handles minted from verified PCActns. No network, filesystem, clock or environment. It runs plain modules in Node or components through the canonical ABI under wasmtime, where an instruction budget (fuel) bounds the work as well as a wall-clock timeout. Each handle is bound to the signed verb, resource and params, single-use by default, derives only narrower, revokes by derivation, and every use leaves a chained receipt.
- **Egress proxy.** For tools that are not WebAssembly: every outbound request must equal an admitted action; default deny; private addresses refused.
- **OS profiles.** seccomp, Landlock and macOS sandbox profiles generated from what was authorized, with a reference Linux helper (`linux/pca-confine.c`) that applies them to a process.
- **Runtime class is evidence.** The class a receipt records comes from a signed claim by an attestor you pin, tied to the signed passport and to attestation evidence your verifier checked. Anything unverifiable is `none`. All nine native verifiers check the claim against the same vectors.

```sh
npm i @atlasauth/pca-sandbox
```

```ts
import { createSandbox } from '@atlasauth/pca-sandbox';

const sandbox = createSandbox({ executors: { 'notes.read': async (op) => readNote(String(op.params.id)) } });
sandbox.table.mint(result, { verb: 'notes.read', resource: 'notes', params: { id: 'n-7' } }); // result: authorize(...) for exactly this operation
const out = await sandbox.runAsync(toolBytes); // the tool can only invoke its handles
```

See the [runtime containment guide](https://github.com/Atlas-Authorization/pca/blob/main/docs/guides/runtime-containment.md). The package makes no hardware-level claim, does not decide policy, and is outside the verified core.
