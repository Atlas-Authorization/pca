---
title: Run an agent's tool in a sandbox
order: 17
---

# Run an agent's tool in a sandbox

**Problem.** A check at the door cannot help if the tool behind the door already has the network, your files and your environment. A tool that a prompt injection steers, or that has a bug, can reach all of that without ever asking.

**Fix.** Run the tool as a WebAssembly module whose only way to do anything is a table of **handles**. A handle exists only for an operation that a verifier already allowed. The tool cannot change the parameters, cannot use a handle twice (by default), and every use is written to a hash-chained receipt log.

```bash
npm install @atlasauth/pca @atlasauth/pca-sandbox
```

This page is the short path. The whole design, the egress proxy for tools you cannot compile to WebAssembly, fuel-metered components and the OS profiles are in [Runtime containment](./runtime-containment.md).

## 1. Decide, then mint

You already have a verifier decision for the operation. In a server that is the result of `authorize` or `requireAuthorized`:

```ts
import { createSandbox } from '@atlasauth/pca-sandbox';

const sandbox = createSandbox({
  executors: {
    // host code. It receives the SIGNED parameters, frozen. The tool never supplies them.
    'notes.read': async (op) => new TextEncoder().encode(`note ${String(op.params.id)}: buy milk`),
  },
});

const op = { verb: 'notes.read', resource: 'notes', params: { id: 'n-7' } };
const handle = sandbox.table.mint(decision, op); // decision = what authorize() returned for exactly this operation
// handle === 1
```

`mint` throws unless the decision allows exactly this verb, this resource and parameters that hash to the signed digest:

```ts
sandbox.table.mint(decision, { ...op, params: { id: 'n-8' } });
// Error: not_authorized: result does not allow exactly this operation
```

A denied decision, a different verb and a different resource fail the same way.

## 2. Run the tool

The tool is a `.wasm` module that imports only `invoke`, `handle_count` and `handle_verb` from the module `pca:act`. Build yours from the WIT file that ships with the package, or use `buildTool` to assemble a tiny one for a first try:

```ts
import { buildTool } from '@atlasauth/pca-sandbox';

// call handle 1 with a 64-byte output window, return the first byte received
const tool = buildTool({ calls: [{ handle: 1, ptr: 0, cap: 64 }], returns: 'byte0' });

await sandbox.runAsync(tool);          // { ok: true, value: 110 }   ("n" of "note n-7: ...")
await sandbox.runAsync(tool);          // { ok: true, value: -2 }    spent: the handle works once
```

`runAsync` runs the tool in a worker thread and kills it at a wall-clock timeout (pass it as the third argument). Return codes below zero come from the handle table: `-1` unknown handle, `-2` spent, `-3` output window too small, `-4` bad memory, `-5` the executor failed, `-6` no executor for that verb.

A use is spent before the executor runs and stays spent if the executor fails. A retry needs a new authorization. Use the operation id as an idempotency key downstream.

## 3. Narrow, expire and revoke

```ts
const parent = sandbox.table.mint(decision, op, { uses: 2, expiresAt: Date.now() + 60_000 });
const child = sandbox.table.attenuate(parent, { uses: 1 }); // takes one use from the parent
sandbox.table.attenuate(parent, { uses: 5 });               // throws attenuate_widens
sandbox.table.revoke(parent);                                // the child is dead too
```

A child can only hold what the parent gives up. Revoking a handle revokes everything derived from it.

## 4. Anything else is refused before it runs

```ts
const greedy = buildTool({ calls: [], extraImports: [{ module: 'wasi:sockets/tcp', name: 'connect' }] });
await sandbox.runAsync(greedy);
// { ok: false, reason: 'ambient_import:wasi:sockets/tcp.connect' }
```

A module that imports a WASI interface, `env`, an extra host function, or that declares a memory with no maximum, shared memory or 64-bit memory is refused with a reason and never instantiated.

## 5. Read the receipts

```ts
import { verifyReceiptChain } from '@atlasauth/pca-sandbox';

sandbox.log.entries.map((e) => `${e.kind}:${e.outcome}:${e.reason}`);
// ['handle_use:ok:used', 'handle_use:refused:spent', 'handle_use:refused:unknown_handle', 'handle_use:refused:spent']
verifyReceiptChain(sandbox.log.entries); // { ok: true }
```

Each receipt names the operation, the verb, the resource, the parameters digest and the runtime class, and links to the one before. A tampered, dropped or reordered receipt breaks the chain. A chain shows consistency, not completeness: publish or sign its head to bound a host that leaves receipts out.

## What the receipts say about the runtime

By default the sandbox records the runtime class `none`. That is on purpose: an operator saying "this is confined" does not count. A class such as `wasi_no_ambient` comes from a signed runtime claim by an attestor you pin (pass it as `runtimeClaim` with the trust it needs), tied to the agent's passport and to evidence your verifier checked. You can then require a class when minting: `mint(decision, op, { requires: 'wasi_no_ambient' })` throws on a weaker table.

## Expected output

The companion script (`npm run sandbox` in the `pca-guides-b` examples):

```
ok   the verifier allowed n-7 -> true
ok   the tool uses its handle -> {"ok":true,"value":110}
ok   a second use finds the handle spent -> {"ok":true,"value":-2}
ok   minting for n-8 from the n-7 decision -> "not_authorized"
ok   revoking the parent kills the child -> {"ok":true,"value":-2}
ok   a tool that imports a socket -> {"ok":false,"reason":"ambient_import:wasi:sockets/tcp.connect"}
ok   the receipt chain verifies -> {"ok":true}

All outcomes as expected.
```

## Limits

- `run` is synchronous and has no time limit. `runAsync` is bounded by time only. To bound a tool by the work it does, run a component under the wasmtime host with a fuel budget (see [Runtime containment](./runtime-containment.md)).
- The engine is your platform's WebAssembly engine. A bug in it is outside this layer; the OS profiles in the containment guide exist for that case.
- The sandbox does not decide policy. It enforces a decision you already made.

## Next

- Tools that are not WebAssembly: the egress proxy and OS profiles in [Runtime containment](./runtime-containment.md).
- Make the decision that feeds `mint`: [Add PCA to your framework](./framework-recipes.md).
