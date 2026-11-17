# @atlasauth/pca-control-plane

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

A live authority control plane for Proof-Carrying Authority. Your gateways report what agents do and what the verifier decided. The control plane keeps a baseline for every agent and for the fleet, notices drift, repeated denials and outliers, and issues **directives**: signed, expiring statements that an agent, session, grant or the whole fleet must be treated more strictly. Your existing verifier hooks (risk policy, revocation registry, Shared Signals) consume them. Nothing here adds a new enforcement path to the verifier.

Two rules hold everywhere:

- **Automatic directives only tighten.** Each kind (`tighten`, `shrink_budget`, `require_step_up`, `freeze`) can only make authorization stricter, and the parameter check refuses any value that would loosen.
- **Loosening is a signed human action.** Lifting a freeze or revoking a directive needs a signature from a pinned human key over a short-lived, single-use statement that names that one directive. No automatic path can produce one.

The anomaly score is a heuristic. It decides how much to tighten, never what to allow.

## Install

```sh
npm i @atlasauth/pca-control-plane @atlasauth/pca
```

## Run it

```ts
import { ControlPlane, InMemoryControlPlaneStore, signIngest } from '@atlasauth/pca-control-plane';

const cp = new ControlPlane({
  store: new InMemoryControlPlaneStore(),   // or your own ControlPlaneStore (see conformance below)
  signer: controlPlaneSecret,               // Ed25519 secret; verifiers pin its public key (cp.publicKey)
  sources: { gateway: gatewayPublicKey },   // source id -> pinned public key; any other source is refused
  humans: [oncallPublicKey],                // pinned keys whose signed action may lift a freeze
  onDirective: (e) => deliver(e),           // webhook / SIEM / signals for every directive
});

// a gateway reports a batch (signed with its own key, with a rising `seq`)
const batch = signIngest(gatewaySecret, { source: 'gateway', seq: 1, sent_at: Date.now(), events });
const result = await cp.ingest(batch);      // { ok: true, accepted, dropped, directives } or { ok: false, reason }
```

An event is `{ id, at, agent, verb, resource, outcome: 'auto' | 'step_up' | 'deny' | 'executed', r }` with `r` the action's risk in [0,1], and optional `session` and `grant`. A batch holds at most 256 events.

What ingest refuses before doing any work: an unknown source, a bad signature, a stale or future clock, a replayed or reordered sequence number, an oversized batch. An event that is not well formed (a NaN or infinite risk or time, an unknown outcome) is not ignored: it counts against its agent as a violation at maximum risk, so garbage tightens rather than reading as calm.

## Freeze and unfreeze

```ts
await cp.freeze({ kind: 'agent', id: agentHolderKey }, 'oncall', 'suspected prompt injection');
await cp.freezeFleet('oncall');             // one call, idempotent, race-safe

// later: a pinned human signs the unfreeze (CLI below), the operator submits it
const result = await cp.lift(signedAction); // refused without a valid signature, a reused action, or the wrong directive
```

```sh
npx @atlasauth/pca-control-plane keygen --out human.key       # prints the public key to pin
npx @atlasauth/pca-control-plane sign unfreeze --directive <id> --key human.key
```

A signed action lasts at most five minutes, works once, and names one directive: a signature for an older freeze never lifts a newer one.

## Consume directives

```ts
import { effectiveOf, tightenPolicy, shrinkBudget, syncRegistry, toSignalEvents } from '@atlasauth/pca-control-plane';

const { effective } = await cp.effective({ agent, session, grant });   // strictest reading of what is in force
if (effective.frozen) deny();
const policy = tightenPolicy(basePolicy, effective);                   // raises kappa, lowers theta; never widens the base
const ceiling = shrinkBudget(budget, effective);

await syncRegistry(registry, await cp.activeDirectives());             // agent freezes -> holder revocations in @atlasauth/pca-revoke
const events = toSignalEvents(directive);                              // kill-switch / grant-revoked / intent-revoked / risk-level-change
```

A verifier that is not in the same process fetches directives (`GET /v1/pca/control/directives`; the API adds unsigned display fields, so pass the view through `directiveOf` first), checks each with `verifyDirective(d, { signer, now, floorSeq })` (signature, expiry, replay) and reads them with `effectiveOf`. A directive that does not verify is skipped, which can only mean less tightening, never a loosening of what is already in force.

## Webhooks and SIEM

`signDirectiveWebhook(secret, event)` returns a body and a `PCA-Signature` header (verify with `verifyWebhook` from `@atlasauth/pca-events`). `directiveSiemEvent(event, 'ocsf' | 'ecs' | 'cef')` renders any directive for a SIEM.

## Stores and conformance

`ControlPlaneStore` needs a monotone sequence, a per-source replay floor, single-use nonces, atomic agent and fleet updates, at most one live freeze per subject, and a lift with one winner. `runStoreConformance(adapter)` checks all of it, including racing clients and a restart:

```ts
import { runStoreConformance } from '@atlasauth/pca-control-plane';
const results = await runStoreConformance({ name: 'mine', create: async () => ({ store, reopen: async () => store2 }) });
```

## Report a `pca-proxy` log

```sh
npx @atlasauth/pca-control-plane keygen --out gateway.key        # prints the public key to pin as a source
ATLAS_SECRET_KEY=sk_... npx @atlasauth/pca-control-plane report --follow \
  --audit ./pca.audit.jsonl --source gateway --key gateway.key --agent my-agent --url https://api.atlasauth.net
```

Each audit receipt becomes one event (`auto`, `deny` for a call the policy refused or would refuse in observe mode, `executed` after a human approval) with the proxy's `mode` (`observe` or `enforce`). Batches are signed with the source key. An offset file next to the log (`<log>.report`) remembers what was sent, so a restart never reports an event twice. A refusal from the control plane ends the run; a network error is retried with `--follow`. The receipt carries no risk score, so allowed calls report a risk of 0.1 and refused ones 0.6.

## Hosted

On Atlas the same engine runs behind `/v1/pca/control/*` and a Fleet control page in the dashboard. Pin your sources and human keys under `auth_config.pca.controlPlane` (`sources`: id to public key, `humans`: list of public keys). Every directive is an audit-log event and a `pca.control.directive.issued` or `pca.control.directive.lifted` webhook.

Remote verifiers can subscribe instead of polling: a Shared Signals stream (`/v1/ssf/*`) that asks for the kill-switch, grant-revoked, intent-revoked or risk-level-change events and adds the subject (`{ "format": "opaque", "id": "<agent, session, grant or *>" }`) receives each directive as a signed SET, pushed or queued for poll delivery. A lift is announced as an informational risk-level change; a SET never un-revokes, so on seeing one a receiver re-reads `GET /v1/pca/control/state`. Event batches are limited to 120 per minute per pinned source and 600 per instance.

In the dashboard, the Fleet control tab follows the live stream (it reconnects by itself and polls while the stream is unavailable) and can approve an unfreeze with a passkey: the passkey's PRF output derives the human key on each use, and you pin its public key under `humans`.
