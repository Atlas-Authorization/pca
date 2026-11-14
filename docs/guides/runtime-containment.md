---
title: Runtime containment
order: 40
---

# Runtime containment (optional)

A PCA verifier decides whether an action may happen. It cannot stop an agent process that can already do the thing without asking: the process often has the network, the filesystem and the environment. This optional layer, `@atlasauth/pca-sandbox`, removes that ambient authority, so a bypassed or forgotten check is bounded by what was authorized. It sits outside the verified core. The one wire-visible piece is the signed runtime-class claim, below.

There are three parts. Use one or all.

| Part | For | What bounds the tool |
|---|---|---|
| Capability sandbox | tools you can build as WebAssembly | the tool imports nothing except handles minted from verified PCActns |
| Egress proxy | tools that are not WebAssembly | every outbound request must equal an admitted action; default deny |
| OS profiles | any process | seccomp, Landlock and macOS profiles generated from what was authorized |

The design borrows an idea from capability systems (Capsicum, seL4, CHERI, the WebAssembly component model): authority is a handle you hold, handles derive only narrower, and revoking one revokes what came from it. It makes no hardware-level claim.

## 1. The capability sandbox

A tool is a WebAssembly module. The host refuses it unless its only imports are `invoke`, `handle_count` and `handle_verb` from `pca:act`. A module that asks for a WASI interface, `env`, an extra host function, a memory with no declared maximum, or shared or 64-bit memory is refused before it runs. Two hosts share the same rules. The Node host runs core modules whose ABI mirrors the WIT world shipped with the package. The component host runs real components through the canonical ABI under wasmtime (see below).

```ts
import { createSandbox, buildTool } from '@atlasauth/pca-sandbox';

const sandbox = createSandbox({
  executors: { 'notes.read': async (op) => readNote(String(op.params.id)) }, // host code; gets the SIGNED params
});

// `result` is what authorize / requireAuthorized returned for exactly this operation
const handle = sandbox.table.mint(result, { verb: 'notes.read', resource: 'notes', params: { id: 'n-7' } });

const out = await sandbox.runAsync(toolBytes, 'run', 5000); // worker thread, killed at the timeout
```

What the guarantees are:

- A handle exists only for an operation the verifier allowed: same verb, same resource, params that hash to the signed digest. A denied result, other params or another verb throws at mint.
- The tool cannot change the params. The executor receives a frozen copy of the signed ones.
- A use is spent before the executor runs and stays spent if it fails. Retrying needs a new authorization. Use the operation id as an idempotency key downstream.
- `attenuate` gives a child only what the parent gives up; `revoke` revokes the whole subtree.
- Every use, including a refused one, appends a receipt (operation id, verb, resource, params digest, runtime class, outcome) to a hash chain. `verifyReceiptChain` finds a tampered, dropped or reordered receipt. The chain shows consistency, not completeness: anchor its head (sign it, or publish it) to bound a host that omits receipts.
- A mint can require a minimum class: `mint(result, op, { requires: 'wasi_no_ambient' })`.

### Components and fuel

`runComponent` runs a component built for the `tool` world in `wit/pca-act.wit` (for example with `wit-bindgen` and `wasm-tools`) under wasmtime, through the real canonical ABI. The component's only import is the handle interface; anything else (a WASI interface included) is refused before instantiation with `ambient_import:<name>`. The run is metered: you pass a `fuel` budget (every WebAssembly instruction costs fuel) and a wall-clock timeout, and a tool that spends its fuel stops with `fuel_exhausted`. Fuel counts the tool's instructions, not time spent inside your executors.

The reference host is a small Rust program in `wasmtime-host/`; build it with `cargo build --release` and point `PCA_WASMTIME_HOST` at it (or use the default path). `referenceComponentWat()` is a tiny component in text form for trying it.

Limits. The Node host's `run` is synchronous with no time limit; `runAsync` kills the tool on a wall-clock timeout only. Use `runComponent` when a tool must be bounded by work done. The engine is the platform's WebAssembly engine; a bug there is outside this layer, which is why part 3 exists.

## 2. The egress proxy

For a tool you cannot compile to WebAssembly, make the proxy its only route out. The tool author writes the mapping from an authorized operation to the one request it means:

```ts
import { EgressPolicy, createEgressProxy, ReceiptLog } from '@atlasauth/pca-sandbox';

const policy = new EgressPolicy();
policy.admit(result, operation, (op) => ({ method: 'GET', scheme: 'https', host: 'api.example.com', path: '/v1/items' }));
const proxy = createEgressProxy({ policy, log: new ReceiptLog() });
proxy.listen(3128, '127.0.0.1');
```

A request is allowed only if it equals an admitted template: exact host, port, scheme and method; the exact path (or a prefix on a segment boundary); the admitted query; a body only if its hash was admitted. Userinfo, fragments, encoded slashes and dots, and a CONNECT that was not admitted as a tunnel are refused. Each admission is spent on use. Refusals answer 403 and leave a receipt. Upstream addresses that are private, loopback or link-local are refused unless `allowPrivate` is set.

A tunnel (CONNECT) is admitted at host-and-port grain only, because the proxy cannot see inside TLS. Ask for it explicitly with `tunnel: true`.

The proxy bounds a tool only if the tool has no other route out. That is part 3.

## 3. OS profiles generated from the grant

`compilePolicy` turns authorized operations into a policy, using a mapping you write from operation to needs (paths, hosts). Only operations the verifier allowed contribute. Paths must be absolute, normalized and made of a small safe character set; anything else is refused, never escaped. The same grant gives the same bytes. Any network need is reachable only through the egress proxy, so the policy needs its port.

```ts
const policy = compilePolicy(items, (op) => needsFor(op), 3128);
seccompProfile(policy);   // Docker/OCI seccomp JSON
landlockRuleset(policy);  // Landlock rules (ABI 4 for the TCP port rule)
macosProfile(policy);     // sandbox-exec profile
```

### macOS

The generated profile for a tool that may write one directory, run one binary and reach the proxy on port 8080:

```
(version 1)
(deny default)
(allow sysctl-read)
(allow process-fork)
(allow mach-lookup)
(allow file-read-metadata)
(allow file-read* (literal "/") (literal "/dev/null") (literal "/dev/urandom") (subpath "/usr/lib") (subpath "/System/Library") (subpath "/private/var/db/dyld") (subpath "/System/Volumes/Preboot/Cryptexes"))
(allow process-exec (literal "/opt/tool/bin/run"))
(allow file-read* (literal "/opt/tool/bin/run"))
(allow file-read* (subpath "/srv/work dir"))
(allow file-write* (subpath "/srv/work dir"))
(allow network-outbound (remote tcp "localhost:8080"))
```

Apply it with `sandbox-exec -f profile.sb /opt/tool/bin/run`. The test suite does exactly this on macOS: a granted path is readable, other paths are not, and `curl` under the profile reaches the proxy and nothing else. `sandbox-exec` is deprecated by Apple but present; the base lines let a dynamically linked binary start, and your tool may need more (its own libraries, configuration files); add them as `r` needs.

### Linux

- seccomp: load the JSON as a Docker/OCI profile (`--security-opt seccomp=profile.json`) or with libseccomp. It denies by default, includes network system calls only when the policy has a proxy, restricts `socket` to `AF_INET` and `AF_INET6`, and includes `execve` only when the grant names a binary. The base list suits a statically linked tool that reads, computes and exits. Confirm it against your tool under `strace` before relying on it. seccomp cannot see paths or addresses, so it is not enough alone.
- Landlock: the ruleset lists every access right as handled and allows only the named paths and the proxy port (TCP connect rules need Landlock ABI 4, Linux 6.7 or later). Apply it with a Landlock library, for example the Go or Rust bindings, which take a list of paths with access sets and TCP connect ports. For the generated example:

```json
{
  "fs": [
    {
      "path": "/opt/tool/bin/run",
      "access": [
        "LANDLOCK_ACCESS_FS_EXECUTE",
       "LANDLOCK_ACCESS_FS_READ_FILE"
      ]
    },
    {
      "path": "/srv/work dir",
      "access": [
        "LANDLOCK_ACCESS_FS_READ_FILE",
        "LANDLOCK_ACCESS_FS_READ_DIR",
        "LANDLOCK_ACCESS_FS_WRITE_FILE",
        "LANDLOCK_ACCESS_FS_TRUNCATE",
        "LANDLOCK_ACCESS_FS_MAKE_REG",
        "LANDLOCK_ACCESS_FS_MAKE_DIR",
        "LANDLOCK_ACCESS_FS_REMOVE_FILE",
        "LANDLOCK_ACCESS_FS_REMOVE_DIR"
      ]
    }
  ],
  "net": [
    {
      "port": 8080,
      "access": [
        "LANDLOCK_ACCESS_NET_CONNECT_TCP"
      ]
    }
  ]
}
```

- Network: pair Landlock's port rule with a network namespace or firewall rule so the proxy is the only reachable address; a port rule alone does not pin the address.

`linux/pca-confine.c` is a reference helper (it needs libseccomp): `confineArgs(policy)` turns the generated profiles into its flags, and `pca-confine <flags> -- <command>` applies Landlock and seccomp, then runs the command. CI compiles it on Linux and applies the generated profiles to a test child: an allowed path reads, a read-only path refuses writes, other paths and other binaries are refused, `ptrace` and AF_UNIX sockets fail, and the child can connect to the proxy port and to no other. Treat the helper as a starting point you test on your own kernel.

## Runtime classes

`none` < `os_confined` < `egress_default_deny` < `wasi_no_ambient`. The class comes from a signed runtime-class claim: an attestor you pin signs the class, the digest of the agent's signed passport, the digest of the attestation evidence it looked at, and a validity window (`signRuntimeClaim`, `createSandbox({ runtimeClaim })`). The claim counts only if that evidence digest is one your own attestation verifier accepted (`trustFromAttestation` admits a digest only for evidence that is verified and bound to the instance). A claim that is missing, unsigned, unpinned, expired, tampered, about another passport or carrying an extra member is class `none`, so a mint that requires a minimum cannot be satisfied by an operator saying so. The class appears in every receipt. The nine native verifiers (Python, Go, Rust, Ruby, PHP, Swift, Java, Kotlin, .NET) check the same claim against the same vectors, so the class can be decided where the agent is admitted, not only where the sandbox runs.

## What this does not do

- It does not decide policy. The verifier does; this layer holds an agent to the verifier's answer.
- It is not a hardware capability system and makes no such claim.
- It does not make an executor safe. An executor is host code with whatever authority the host has; keep it small and give it only the operation's signed params.
- The Node WebAssembly host is not CPU-metered; the component host is.

## Sources

- Landlock access-right names and the ABI-4 network rights: the Linux kernel's Landlock user-space API documentation.
- seccomp profile format: the Docker/Moby default seccomp profile (`defaultAction`, `archMap`, `syscalls` with `names`, `action`, `args`).
- WIT worlds and imports: the WebAssembly component model WIT specification. Fuel and the component API: the wasmtime documentation.
- The macOS profile language is not formally documented by Apple; the base lines here were found by running real processes and are exercised by the test described above.
