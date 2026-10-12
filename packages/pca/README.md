# @atlasauth/pca

Proof-Carrying Authority (PCA) core: authorization for AI agents where each action carries its own proof.
Instead of handing an agent a bearer token, the principal signs a **Root Intent Grant** once. The agent then
attaches a signed, self-describing **PCActn** to every action, and the resource server verifies it offline:
is the action inside the granted authority, is the signing chain intact, is it a node of the committed plan,
and is there trust budget left to do it without a human?

This package contains canonical hashing, Ed25519 and post-quantum signatures, Merkle plan commitments,
attenuable capability chains, hardware attestation verifiers, the PCActn verifier, and the resource-server
guard (`requirePCA`). Source and issues: <https://github.com/Atlas-Authorization/pca>.

```
  principal --grant--> agent --PCActn (per action)--> resource server
   (signs envelope,     (holds a capability,         (verifies offline: chain, plan,
    policy, budget)      emits a proof)               signature, audience, budget)
```

## Install

```sh
npm i @atlasauth/pca
```

Node >= 20. The FN-DSA post-quantum suites use `@atlasauth/pca-fndsa-wasm`, which is installed
automatically as a dependency. Optional dependencies (`@xmldom/xmldom`, `asn1js`, `pkijs`, `snarkjs`,
`xml-crypto`) are used only by some attestation and zero-knowledge features.

## Usage

Agent side: mint a grant and sign a PCActn per action.

```ts
import { agent, generateKeyPair, pcaHeaders } from '@atlasauth/pca';

const AUD = 'ins_acme'; // the resource server this grant is for
const a = agent({
  principal: generateKeyPair(), // the human's key; roots the grant
  goal: 'reconcile October refunds',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500/day' },
  aud: AUD,
});

const params = { amount: 42, currency: 'usd' };
const { encoded } = a.act('stripe.refund', 'charge:ch_123', params);
// Send it with the request: fetch(url, { headers: pcaHeaders(encoded), ... })
```

Resource server: verify each inbound action. `requirePCA` is framework-neutral and default-deny: a required
check that is not enforced denies. (For Express, Fastify, Hono, Next and fetch, use the middleware packages
`@atlasauth/pca-express`, `-fastify`, `-hono`, `-next`, `-fetch`.)

```ts
import { requirePCA, memoryPcaStore } from '@atlasauth/pca';

const guard = requirePCA({
  audience: AUD, // a PCActn signed for another audience is denied
  resolveGrant: async (ref) => (ref === a.grant.id ? a.grant : null), // your grant store
  budgetStore: memoryPcaStore(), // replay counter + trust budget (use a durable store in production)
  hooks: { revocation: () => ({ enforced: true, ok: true }) }, // plug your revocation check
  context: (_req, p) => ({
    params, // the plaintext params the RS saw; must hash to action.params_digest
    // The plan and its authorization must come from YOUR authoritative source. Echoing the plan
    // from the proof itself, as this demo does, proves nothing about authorization.
    plan: [{ id: 'n0', verb: p.action.verb, resource: p.action.resource,
             params_digest: p.action.params_digest, reversibility_class: p.action.reversibility_class }],
    planAuthorized: true,
    risk: { reversibility: 1, blastRadius: 0.1, confidence: 1, semanticDistance: 0, taint: 0 },
    budget: a.budget,
  }),
});

const result = await guard({ headers: new Headers(pcaHeaders(encoded)) });
if (result.ok) {
  // result.verdict.allow === true; result.pcactn is the verified action
} else {
  // result.status is 401 or 403; result.wwwAuthenticate holds the challenge
}
```

Sending the same PCActn again is denied as a replay (the counter must increase).

## Verification

A resource server accepts an action only if the PCActn passes, in order: wire (strict canonical form),
version, audience, validity window, capability chain (hash-linked, each hop signed, rooted at the grant),
plan inclusion, leaf signature, and counter (anti-replay). Optional hooks add attestation, revocation and
freshness, a liveness beacon, a taint gate, threshold (guardian or human) co-signs, and zero-knowledge
compliance. Delegation can only narrow authority: caveats are append-only. Autonomous actions spend a trust
budget, which bounds what an agent can do between human co-signs.

## Attestation verifiers

Hardware attestation is exposed as namespaced verifiers that plug into the attestation hook and can be
combined in an N-of-M policy: `attestAmdSnp` (AMD SEV-SNP with Milan/Genoa/Turin root pins),
`attestIntelDcap` and `attestIntelCollateral` (Intel TDX quotes and PCS collateral), `attestAzureMaa`
(Azure Attestation tokens), `attestGcpConfidentialSpace`, `attestNvidiaSpdm` with `attestNvidiaRim` and
`attestNvidiaOcsp` (NVIDIA GPU confidential computing), plus `attestPqSoftware` and `attestPuf`. Verification
is offline against pinned roots; most hardware roots are classical (ECDSA or RSA).

## Post-quantum suites

Signed surfaces take an `alg` from the suite registry: `ed25519` (default), `ml-dsa-65`, `ml-dsa-87`,
`slh-dsa-sha2-128f`, `slh-dsa-sha2-256s`, `fn-dsa-512`, `fn-dsa-1024`, and hybrid Ed25519 plus ML-DSA or
SLH-DSA combinations. Key exchange uses a hybrid X25519 + ML-KEM-768 KEM (`hybridKemKeygen`,
`hybridEncapsulate`).

FN-DSA (Falcon, FIPS 206) runs through `@atlasauth/pca-fndsa-wasm`, a WebAssembly build of the Rust `fn-dsa`
crate. It is loaded lazily on first use. If it cannot be loaded, FN-DSA verification fails closed, and
`isFnDsaBackendActive()` reports whether it is available.

```ts
import { randomBytes } from 'node:crypto';
import { b64u, fnDsa512Keygen, signWithSuite, verifyWithSuite } from '@atlasauth/pca';

const msg = new TextEncoder().encode('hello');
const k = fnDsa512Keygen(new Uint8Array(randomBytes(32)));
const sig = signWithSuite('fn-dsa-512', {
  fnDsa512: { verifyingKey: k.verifyingKey, signingKey: k.signingKey, signSeed: new Uint8Array(randomBytes(32)) },
}, msg);
verifyWithSuite('fn-dsa-512', { fnDsa512Pub: b64u(k.verifyingKey) }, msg, sig); // true
```

## Durable state (Node only)

`@atlasauth/pca/durable-state` provides crash-safe, tamper-evident, multi-process-safe key/value state for
rollback protection (for example, the highest allowlist version or revocation epoch ever accepted). It is a
separate subpath because it imports `node:fs`.

```ts
import { openDurableState } from '@atlasauth/pca/durable-state';

const state = await openDurableState({ dir: '/var/lib/myapp/pca-state', hmacKey }); // hmacKey: 32+ bytes, optional
await state.update('epoch', (prev) => Math.max((prev as number) ?? 0, 5)); // atomic read-modify-write
```

It fails closed on corrupt or rolled-back state (`DurableStateError`). Without an `hmacKey`, replacing the
whole directory with an older consistent copy is not detectable locally.

**Requirements (read before deploying).** The lock coordinates processes on **one host** only: never share the directory between hosts. The directory must be on a **local filesystem with working hard links** (`link(2)` with exclusive-create semantics: ext4, xfs, btrfs, tmpfs, APFS). NFS, SMB/CIFS, FUSE and some overlay/union mounts can grant the lock twice or show stale listings; `openDurableState` probes hard links and **fails closed** with `DurableStateError` code `link-unsupported` when they are unusable, but it cannot detect a filesystem that links correctly locally yet is shared across hosts. A holder that is alive but stalled (blocked fsync, SIGSTOP) **blocks other processes until it dies**: they fail with `lock-timeout` after `lockTimeoutMs` rather than taking the lock; restart or kill a wedged holder.

**Recovering a dead holder the library cannot judge (R5-F1, R6-CORE-01..03).** A holder in another PID namespace (a crashed container sharing the volume), under a changed hostname, an unreadable or incomplete top `state.lock.N` (`{}`, `[]`, no pid/host/nonce), or a legacy single-file `state.lock` from an older version can never be judged dead automatically, so every open fails with `lock-timeout`; the error names the blocking lock file, its recorded holder and the call to use. After you have confirmed the holder is gone, release it out of band: `recoverDurableState({ dir, force: true, expectedHolder: { host, pid, nonce } })` (copy the three values exactly from the lock file; `'unreadable'` for an unreadable or incomplete record; add `legacyLock: true` for the legacy `state.lock`, which is moved aside, not deleted). A mismatch is refused and nothing changes; a holder that is alive in this PID namespace is never released, whatever its hostname. It is not automatic and never runs from `openDurableState`.

*What recovery guarantees if the holder was only paused (SIGSTOP, `docker pause`, a frozen VM).* Recovery takes the lock itself, records a cut (the journal's tail record) in `state.fence`, then frees the lock. Every journal record and the head carry the writer's lock generation. A resumed holder that was paused anywhere before its pre-rename lock check fails with `lock-lost` and writes nothing. A holder paused in the few instructions between that check and its rename still renames when it resumes (rename(2) cannot be made conditional); its late journal is then **refused on load** (`DurableStateError` `corrupt`, naming the fence), never silently accepted. The newer holder's records written after the recovery were replaced on disk by that late rename, so the store fails closed until you run `openDurableState({ ..., recoverFromCorruption: true })`, which quarantines the files (kept for forensics) and restarts. A holder paused between its journal rename and its head rename leaves a stale head, which is recognised and repaired automatically (its record was committed before the recovery). Recovering a holder that is in fact running can only make the store fail closed, never accept a write out of order. Records/heads written by older versions carry no generation (read as generation 0); a directory written by this version cannot be opened by an older one. Model: `formal/tla/DurableFence.tla`.

*If recovery itself dies midway (SIGKILL, OOM, power loss).* Every step is a single atomic `link(2)` or `rename(2)`, so a crash at any point leaves one of a few well-defined shapes, and none of them can let the released holder's late write in. Killed before it took the lock: nothing changed; run recovery again. Killed after it took the lock (`state.lock.<g+1>`, marked `recovering`), whether or not its fence landed: that lock now names a dead process. A waiter in the **same PID namespace** judges it dead and takes it over like any dead holder, and because of the `recovering` mark it first takes its own cut and writes its own fence (under its own, newer generation) before it reads anything; its lock carries the mark on, so a taker that is itself killed before its fence lands hands the duty to the next one. A waiter in **another** namespace cannot judge the dead recovery and fails with `lock-timeout` naming it; run recovery again on that lock. Either way the paused holder stays fenced and writes resume. A crash leaves at most an orphan `state.lock.tmp-*` or `state.fence.<gen>-*.tmp-*` file, which is harmless. Each fence is its own immutable file `state.fence.<gen>-<random>` (the `state.fence` list holds fences from older versions and the genesis fence written by `recoverFromCorruption`), so a fence writer that was paused and resumes late can never drop a fence written in the meantime. Model-checked (`DurableFence.tla`, a crash after every recovery step, safety and liveness) and tested by SIGKILLing a real recovery process at each step.

*Threat model of the lock and the fence (what they do not defend against).* The fence files (`state.fence`, `state.fence.<gen>-*`) and the `state.lock.N` files are **not signed or MACed**, even with `hmacKey`. That is deliberate: anyone who can delete or rewrite them already has write access to the directory and can break the store in simpler ways (delete the journal and head, which is indistinguishable from a first run; or kill the holder). The fence is a defence against a **paused or late process of this library**, not against an attacker with write access to the directory. Rewriting `state.fence` cannot make the store accept a forged record (records and the head are still hash-chained and, with `hmacKey`, MACed); deleting it can at most let a stale record from a recovered holder load, which needs that holder to be paused in the exact window as well. Restrict the directory to the service account (it is created 0700) and anchor what matters (see `attest-allowlist-anchor`). Second, **automatic takeover never breaks a lock held under another hostname**, deliberately: a hostname that differs means another machine (or a container whose PID namespace we cannot see), where `kill(pid, 0)` says nothing about the holder; taking such a lock would let two hosts write at once. Automatic takeover needs the same hostname AND (where recorded) the same PID namespace, plus a dead pid; anything else waits for an operator to run `recoverDurableState` after confirming that holder is gone. This includes a crashed recovery that ran on another host or in another container.

## Related packages

Agent client `@atlasauth/pca-agent`; tool wrappers `@atlasauth/pca-ai-sdk`, `-langchain`, `-openai`,
`-anthropic`, `-mcp`; payment mandates `@atlasauth/pca-payments`; tooling `@atlasauth/pca-cli`,
`@atlasauth/pca-testing`, `@atlasauth/pca-events`, `@atlasauth/pca-otel`.

## Status

Pre-1.0 (0.3.0): the API may change between minor versions. The cryptography and protocol have not been
independently audited, and this is not a substitute for a security review before you protect anything of
value. **Offline, with no hooks and no `require` list, several checks report `not-enforced` and the verdict is
still `allow: true`**: `plan_root_authorized` (the agent supplies its own plan, so plan inclusion alone proves
nothing; it needs your own copy of the plan in `context.plan` plus `context.planAuthorized`), `revocation`,
`threshold`, `attestation`, `freshness` and `beacon`. A resource server must either supply the hooks or demand the
checks: `requirePCA` defaults `require` to `DEFAULT_REQUIRED_CHECKS` (counter, revocation, plan_root_authorized,
audience, validity, grant_ref_bound) so an unenforced one denies; a bare `verifyPCActn` / `verifyPCActnCore` call does not. The zero-knowledge backend currently uses BN254 and is being moved toward a
transparent, post-quantum backend; the AMD SEV-SNP root chain is classical.

The project audits itself in code: mutation testing of the security-critical modules, structure-aware fuzzing of
every parser and verifier entry point (including the attestation evidence formats), static analysis, statistical
timing checks, an eight-language differential run and a supply-chain check. That programme found and fixed real
defects (regular-expression denial of service in signed patterns, untyped exceptions on hostile input, a vulnerable
XML parser), re-runs with `bash scripts/pca-audit-all.sh`, and is described in the security documentation. It is a
set of the project's own tests; it is not an independent audit.

## License

MIT - see LICENSE

## Canonical compact-JWS gate

`assertCanonicalCompactJws(token, {parts, maxBytes, payload})` / `isCanonicalCompactJws` / `assertCanonicalJwsSegments` / `decodeCanonicalBase64url` / `decodeCanonicalJsonSegment` / `compactJwsAliases`: a gate that accepts exactly ONE spelling per compact JWS (strict unpadded base64url alphabet, decode-then-re-encode must equal the segment so trailing-bit aliases die, no whitespace/control characters, bounded length, header and payload are BOM-free UTF-8 strict-JSON objects with no duplicate keys). Typed `CanonicalJwsError` with a `reason`. Third-party JOSE libraries (e.g. `jose` 5.x) accept padded / `+` `/` / trailing-bit / whitespace spellings of the same signature, so anything keyed on the token string or its hash (dedupe, replay caches, ledger entries, binding hashes) is bypassable by re-encoding unless this gate runs first. `compactJwsAliases(token)` derives the alias spellings for conformance tests.

## Suite policy defaults

- No list (`allowedSuites`) means no restriction: the verifier accepts every signature suite it knows.
- An empty list (`allowedSuites: []`) means refuse everything.
- The hosted API defaults to `ed25519` plus the hybrids that include Ed25519, and refuses the pure post-quantum suites (`ml-dsa-*`, `slh-dsa-*`, `fn-dsa-*`, `less-cat1`) unless the operator lists them. To match it offline, pass `allowedSuites` exactly: `ed25519`, `hybrid-ed25519-ml-dsa-65`, `hybrid-nested-ed25519-ml-dsa-65`, `hybrid-ed25519-ml-dsa-87`, `hybrid-ed25519-slh-dsa-sha2-128f`, `hybrid-ed25519-slh-dsa-sha2-256s`, `hybrid-ed25519-less-cat1`. The effective hosted list is readable at `GET /v1/pca/suites`; see docs/pca/reference/wire-formats.md.
