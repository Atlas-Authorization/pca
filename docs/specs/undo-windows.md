# Undo windows: act now, veto later

Status: internal design (0.5 line, branch 05-undo). Repo paths are intentional here. Do NOT copy any of this into public docs
(the user-facing page is `docs/pca/guides/undo-windows.md`).

Code: `packages/pca/src/undo.ts` (record, state machine, token, receipts, store contract, reference stores),
`packages/pca/src/server/undo.ts` (coordinator: admission, ledger writes, compensation, notifications, fraud-proof rollback),
the `undo` hook in `server/require-pca.ts` and the `undo` option of `server/authorize.ts`, `packages/pca-actions/src/undo.ts`
(the engine over confirmed action definitions; lint LD-010), the `undo_window` obligation kind (`obligations.ts`), the hosted
ledger and veto routes of the Atlas API (`/v1/pca/undo/*`), the vectors
`packages/pca/conformance/undo-vectors.json`.

## 0. The problem and the short version

Approval fatigue: today every action whose policy says "ask a human" (an `escalate` verdict: an unanswered `intent_required`
question, a `tighten[]` rule asking for a human) blocks until a principal signs an `EscalationAnswer`. Humans approve dozens of
low-stakes, reversible actions a day and stop reading them. The fix: a reversible action runs now; the principal is told what
happened and can undo it during a veto window. Prior approval stays for everything that cannot be undone.

The security condition: reversibility is a CLAIM about the world and the agent must never be the one making it. A window is
granted only when reversibility is CONFIRMED: the verifier's own action definition, signed by a pinned human reviewer, says the
action is reversible for these parameters, and it names a compensating action that is itself confirmed, derivable before the
effect runs, and authorized under the same grant. Anything short of that is irreversible and takes the existing path unchanged.

## 1. Model

Two ways to keep a human in the loop for an action the policy flags:

| | staged (prior approval) | executed with undo |
|---|---|---|
| when the effect runs | after the principal answers | at once |
| human cost | one blocking decision per action | none unless something is wrong |
| failure if the human is absent | the action never happens | the action stands when the window closes |
| applicable to | everything | confirmed-reversible actions only |
| mechanism | `escalate` + signed `EscalationAnswer` (existing) | `allow` + `undo_window` obligation + undo ledger (this spec) |

Staged execution is exactly today's escalation path and is not changed. Executed-with-undo is new. A third shape (hold the
effect until the window closes, run unless vetoed) was rejected: it gives the agent no result to continue with, which is the
latency approval already has, and it would need a durable deferred-effect scheduler for no safety gain over prior approval.

## 2. Decision integration (why no fourth decision value)

The decision stays ternary (`deny < escalate < allow`, `meet` is the only combinator; `decision.ts`). An undo-windowed action
is `decision: 'allow'` carrying:

- `result.undo`: `{ id, window_end, converted, compensation: {verb, resource}, token, obligation }`;
- the obligation `{ kind: 'undo_window', params: { id, window_end }, due: window_end }`;
- on the guard verdict a passing check `undo_window` with the reason `undo_window: runs now under a veto window until <t> ...`.

Justification. "allow with undo" is not a new point of the lattice: it is an allow with a duty attached, which is exactly what
decision obligations are (XACML 7.2, `obligations.ts`). Using the obligation means the existing deny-biased PEP rule does the
safety work: a PEP that does not implement undo windows (any native verifier today) sees an unknown obligation kind and turns
the allow into a deny (`pepObligationGate`). A fourth decision value would instead silently become "not allow" in some hosts
and "unknown" in others, and would break every `switch (decision)` and the formal models (`VerdictDecision.dfy`,
`Escalation.tla`). `allow: true` remains exactly `decision === 'allow'`.

Where it happens. `requirePCA` gained one hook, `undo.admit`, called ONLY when the verdict is `escalate` (every failing check
is escalate-class) AND no escalation answer was presented. If it admits, exactly the escalate-class failures are lifted (the
same lift a signed answer performs), `escalation` is dropped, and the replay counter is claimed as for any allow. A presented
answer (allow or deny) is never overridden, a `deny` is never touched, and an admission error leaves the escalation standing.
`authorize` then writes the durable record (section 5) before returning; if that fails for a converted escalation the call is
refused (`undo: ... (fail closed)`; the counter is spent, as for the other post-guard refusals). An already-allowed eligible
action also gets a window by default (it costs nothing and gives the human the same undo); for it a failed write or
notification just yields a plain allow without a window, never less than it would have been without undo windows.

Policy (`UndoCoordinatorOptions.policy(op, grant)`, per grant and operation): `mode` `always` (default) | `escalations` (only
replace approvals) | `off`; `windowMs`; `onRevocation` `keep` (default) | `veto`. Policy can only switch windows off or narrow
them; it cannot make an action eligible.

## 3. Eligibility (all must hold; anything else is irreversible)

1. The policy for (operation, grant) does not turn windows off (`escalations` mode admits only converted escalations).
2. The SIGNED class (`pcactn.action.reversibility_class`) ranks `reversible`. An agent that signs `irreversible` or
   `rate_limited` is taken at its word (the stricter of signed and confirmed applies, as in `effectiveReversibility`). An agent
   that signs `reversible` for an action the definition calls irreversible is overruled by rule 3.
3. The engine (`@atlasauth/pca-actions` `undoEngine({ defs, pins })`) finds the definition by EXACT verb (an alias never confers
   reversibility) and:
   - the definition is CONFIRMED: its review attestation verifies against the pinned reviewer keys (`attestationVerifier`); no
     pins means nothing is confirmed;
   - it is a write (a read needs no undo);
   - its effective class is `reversible`: the declared class joined with every trait floor (`effective(...).eff.rev`; e.g.
     `external_communication`, `public_exposure`, `code_execution`, `legal_binding` floor to irreversible), AND, for a
     value-dependent declaration, the class for THESE params (`reversibilityFor`; an unmapped value takes `default`, else
     irreversible);
   - it names `compensates`, the compensating definition is present and itself confirmed, and the compensation is derivable
     before the effect runs (`compensationShape`):
     - verb: `compensates`; resource: the ORIGINAL operation's resource (the compensating definition must have the same
       resource type);
     - params: the original params the compensating definition declares under the same name and type (a required one the call
       left out makes it ineligible);
     - target: at most one required parameter that is the compensating definition's resource id (role `id.<type>`) and not in
       the original call; it is filled at execution from the original effect's result (default `result.id`);
     - the compensating definition's own idempotency key parameter is never copied: the coordinator hands the executor a
       fresh attempt key (`UndoCompensationCall.idempotencyKey`), so a downstream that dedupes on keys can never mistake the
       undo for a retry of the original;
     - any other required parameter makes the action ineligible;
   - the action can be rendered completely (`renderApproval`): an action that cannot be shown is never put to a human.
4. The compensating action is AUTHORIZED under the original grant: the Policy VM (`decide`) releases it over the original PCActn's
   verified capability chain (envelope predicates, envelope caveats, root caveats, delegated caveats), at the admission time.
   The compensation carries no reversibility class, so a `reversibility_max` caveat refuses it (unknown is most restrictive).
5. A durable store is configured (section 5) and the record is written before the result is returned.

Lint: LD-010 (unchanged id and title, so the pinned rules digest is unchanged) now also fails when some value of the
declaration is reversible (a fixed `reversible`, a map value, or the default) and the named compensating action cannot undo it
(other resource type, a read, an underivable required parameter). The 21 built-ins lint clean: the only built-in reversible
write, `gmail.draft`, is compensated by `gmail.delete` on the same resource type whose only required parameter, `message`, is
the resource-id target filled from the draft's id. The catalog generator applies the same rule when it links a create to its
delete: a GraphQL mutation's top-level required `id` argument carries the entity's resource-id role (so a Linear create is undone
by its delete, filled with the created id), and a create whose delete still cannot be derived (a copy or symlink that may
overwrite, an upsert, a delete that needs two values or a value only the response's metadata carries) is generated
`irreversible`.

**Never for a provenance escalation.** A window replaces only an approval the action needed because of its risk. When `provenance_flow` (or the Intent rule-17 `provenance` check) escalated, the arguments or the choice of action came from content the principal did not supply; reversibility does not make that safe to run, so the escalation stands and only a principal-signed answer admits the call.

## 4. Windows

- Length: policy `windowMs`, clamped into `[max(30 s, minMs), min(maxMs, 24 h)]`, default 15 minutes (`resolveUndoWindow`). The
  30 s floor is the same realistic floor as the optimistic challenge window: a window shorter than human reaction time is no
  window.
- Start: the server clock at admission (`opened_at`), never anything the agent signs. End: `window_end = opened_at + window`,
  extended to the claim's challenge end when the record is linked to an optimistic bond (section 9), so a slashable effect is
  never already final.
- `veto` is accepted while `now <= window_end`; `finalize` only when `now > window_end`. A clock that reads non-finite fails the
  operation.

## 5. The undo ledger

Record (`UndoRecord`, JSON): `id` (the original operation id = the PCActn digest = an optimistic claim's `pcactn_digest`),
`aud`, `grant_ref`, `holder` (leaf key), `principal` (grant issuer), `action {verb, resource, params_digest, def_digest}`,
`compensation {verb, resource, params, undo_of, def_digest, target_param?}`, `compensation_digest`, `render_digest?`,
`opened_at`, `window_end`, `converted`, `state`, `ver`, `pcactn` (the encoded original: its chain is the compensation's
authority), `budget?`, `bond_ref?`, `veto?`, `effect?`, `attempt`, `outcome?`, `receipts[]`.

State machine (`undoTransition`, pure, total, never throws; `refused` carries a code):

| from | event | to | otherwise |
|---|---|---|---|
| open | veto, now <= window_end | vetoed | after the end: `window_closed`; finalized: `finalized` |
| vetoed / compensated / compensation_failed | veto | (replayed, unchanged) | |
| open | finalize, now > window_end | finalized | inside the window: `window_open`; vetoed etc.: `vetoed` |
| open / vetoed, no effect reported | abort | finalized (outcome `aborted`) | effect reported: `effect_recorded` |
| open / vetoed | effect | same state, `effect` set | second report: replayed |
| vetoed / compensation_failed | compensated | compensated | others: `not_vetoed` |
| vetoed | compensation_failed | compensation_failed | others: `not_vetoed` |
| compensation_failed | retry | vetoed, attempt + 1 | others: `not_failed` |

Store contract (`UndoStore`): `durable` (true only when acknowledged writes survive a crash), `get`, `create` (atomic insert if
absent, else the stored record: idempotent), `replace(id, expectedVer, next)` (compare-and-swap on `ver`), `list({state,
windowEndedBy?, grantRef?, bondRef?, limit?})`. Every coordinator write is read, transition, CAS, retried up to 64 times
(`conflict_exhausted`), so two vetoes, a veto racing a finalize, or two workers compensating cannot both win. Reference stores:
`KvUndoStore(kv, durable)` over any `DurableKv` (`durable: true` only over `openDurableState`) and `MemoryUndoStore`
(`durable: false`). `createUndoCoordinator` REFUSES a store whose `durable` is not true (`not_durable`), matching
`admitAggregateAction`; the only way around it is the test-only `insecureVolatileStore: true`. Hosted: a Postgres store (
one row per record, `UPDATE ... WHERE ver = $expected`).

Ordering. The record (state `open`, `opened` receipt) is created after the guard admitted and the replay counter was claimed,
and before `authorize` returns, so it exists before the host can run the effect. The host reports the effect
(`recordEffect(id, result)` or `reportUndoEffect(undo, id, executeAuthorized-outcome)`): a committed effect records its result
(the compensation target), a failed or never-started one aborts the window (nothing to undo, held budget released).

## 6. What the human sees

- `opened`: "Already done: <verb> on <resource>. You can undo it until <time>." with the K7 canonical render of the executed
  parameters (every field, the match code of H(R)), and the one-click undo link. Delivered through the existing approval
  channels (`undoNotifierFromDispatcher` over `createApprovalDispatcher`: Slack, webhook, email, SMS, push). The notifier is
  REQUIRED; if no channel accepts the `opened` notice the record is aborted (it never ran), an alert is raised, and a converted
  escalation is refused. A window the principal was not told about is not a veto window.
- `vetoed`, `compensated`, `compensation_failed` ("UNDO FAILED ... an operator has been alerted"), `finalized`, `revoked`.
- CIBA is not used for the veto itself: CIBA is a poll/push flow for granting authority before an action; a veto withdraws an
  executed effect and is carried by the one-click token. The same channels CIBA notifications use are reused through the
  approval dispatcher.

One-click token (`UndoToken`): `{v:1, kind:'pca-undo-token', record, aud, principal, compensation_digest, render_digest ('' when
none), exp (= window_end), signer, sig}`, Ed25519 by the undo service key over `"atlas-pca/undo-token/v1\0" ||
strictCanonical(body)`. It binds the action (record id = action digest), what the undo does (compensation digest), what the
human was shown (render digest) and the window. Check order (`undoTokenCheck`): `malformed`, `signer` (pinned key),
`signature`, `record`, `binding`, `expired`. Encoded for a URL as base64url of its strict-canonical JSON. The token is a bearer
capability for one veto of one record, delivered only to the principal's channels; hosts that want a second factor put the
veto route behind their own session (the hosted route is public by design so the link works from a phone; it is rate-limited).

Hosted veto relay. The Atlas instance stores records (`POST/PUT /v1/pca/undo/records`, accepted only when the receipt chain
verifies against the pinned `pca.undoSigner` and extends the stored one, with the record identity locked) and takes the public
veto (`POST /v1/pca/undo/:id/veto`). It never holds the undo signer, so it cannot write the `vetoed` receipt: it checks the
token at its own clock, stores the veto with the token as `pending_veto` (202) and refuses any later PUT that finalizes the
record. The resource server reads `GET /v1/pca/undo/vetoes` through `createUndoCoordinator({ relay: hostedUndoVetoRelay(...) })`
and applies each entry with `veto(id, { token, at })`: the token is re-verified as of `at` (so a veto made inside the window
counts even when it is read after the window closed), `at` must lie between the window's opening and now, and the `vetoed`
receipt is written at the current time (receipt time never goes back). The relay is trusted only for `at`; a backdated `at`
still needs the principal's token. Every `finalizeDue` reads the relay first: a relay that cannot be read finalizes nothing
(critical `veto_relay_failed` alert), and with a relay a window is finalized only `UNDO_RELAY_GRACE_MS` (60 s) after it ended,
so a veto in flight at the relay still lands.

### 6a. Contract for the human approval flow (notification kind `undo_window`)

This track does not build notification UI or dispatch. The approval-flow track owns delivery (passkey page, push, email, SMS,
Slack, webhook) and exposes a notification kind `undo_window`; this track supplies what that notification carries and the
endpoint its undo button calls. `undoNotifierFromDispatcher` is only an adapter that hands the notice to whatever
`ApprovalDispatcher` the host already has; any `UndoNotifier` (including the approval-flow's) can replace it.

Notification payload (`UndoNotice`, one per event; `kind: 'opened'` is the one that carries the link):

| field | meaning |
|---|---|
| `kind` | `opened` \| `vetoed` \| `compensated` \| `compensation_failed` \| `finalized` \| `revoked` |
| `record.id` | the action digest (= `AuthorizedOperation.id` = PCActn digest) |
| `record.window_end` | epoch ms; the undo works through this instant inclusive |
| `record.action` | `{verb, resource, params_digest, def_digest}` |
| `record.compensation` | `{verb, resource, params, undo_of, def_digest, target_param?}`: what the undo will run |
| `record.principal` | the principal the window belongs to (the grant issuer) |
| `token` | `opened` only: the encoded one-click undo token (base64url, at most 4096 chars) |
| `render` | `opened` only: the K7 canonical render of the executed action; `record.render_digest` is H(R) |

The notifier must resolve `{delivered: true}` only when a channel accepted the `opened` notice; otherwise the window is aborted
and a converted escalation is refused (section 6).

Undo endpoints:

- In-process (any host): `coordinator.veto(id, { token })` -> `{ok: true, record, replayed}` or `{ok: false, code, reason}`
  with `code` one of `malformed`, `signer`, `signature`, `record`, `binding`, `expired`, `window_closed`, `finalized`, `unknown`.
- Hosted (Atlas API): `POST /v1/pca/undo/:id/veto`, public, rate-limited per source and per record, body `{"token": "<encoded
  token>"}` (the token object is also accepted). Answers: `202 {object: 'pca_undo_veto', record_id, status: 'pending', veto: {at,
  via: 'token', by, evidence}}`; a repeat `200` with `status` `pending` or `vetoed`; `400` (`meta.undo_check: 'malformed'`);
  `403` (`meta.undo_check`: `signer` | `signature` | `record` | `binding` | `expired`); `404` unknown record; `409` record no
  longer open or no `pca.undoSigner` configured. The undo button of the approval page posts exactly this.

## 7. Veto, expiry and failure

Veto (`coordinator.veto(id, {token} | {operator})`, also internal vias `fraud_proof` and `revocation`): CAS `open -> vetoed`
with `{at, via, by, evidence}` (evidence: the token digest or the settlement record digest), receipt, `vetoed` notice, then
compensation. A second veto is a replay (`ok`, `replayed: true`, nothing runs twice). A veto after `window_end` is refused
`window_closed`; after finalize `finalized`.

Compensation (`runCompensation`):
1. If the effect was not reported yet, wait (the veto is durable; `recordEffect` resumes it) until `effectTimeoutMs` (5 min)
   after the veto; then proceed without a result (the compensator must be idempotent on `undo_of`).
2. Resolve the grant; fill the target from the effect result; RE-DECIDE the compensating operation with the Policy VM over the
   original chain at `opened_at` (the grant as it stood when the action was admitted: a grant that expired or a time-of-day
   caveat that lapsed since does not block the undo; the principal's veto is the fresh authority).
3. At most once per attempt: create the operation record `H("atlas-pca/undo-compensation-op/v1", record, attempt)` in the
   `OperationStore` (`pending`), re-read the undo record (it must still be `vetoed` at this attempt), move to `executing`, call
   the executor with that id as the idempotency key, record `committed`/`failed`.
4. Success: `compensated`, budget released with reason `rollback` (signed evidence via `budget.evidence`), `compensated` notice.
5. Any failure (grant unknown, target unknown, policy refuses, executor throws, outcome uncertain): `compensation_failed`, a
   CRITICAL alert (`alert` is REQUIRED; a throwing sink is logged to stderr), a `compensation_failed` notice, budget kept
   reserved. An operator retries (`retry`: `compensation_failed -> vetoed`, attempt + 1) or reconciles.

Crash mid-compensation (`recover()`, run at start-up and periodically): every `vetoed` record is driven again. The operation
record of its attempt decides: `committed` -> mark compensated (no second run); `failed`/`uncertain` -> `compensation_failed`
+ alert (never re-run blind); `aborted` (never started) -> retried under the next attempt number; `pending`/`executing` older
than the timeout -> settled (`aborted` / `uncertain`) first. `recover` then finalizes due windows.

Expiry (`finalizeDue()`, periodic): `open -> finalized` for every window that ended, budget reservations committed, `finalized`
notice; a window that closed without an effect report raises an `effect_unknown` warning (reconcile the original operation).

## 8. Budgets, delegation and revocation

Budgets. The trust budget `B` is debited at admission exactly as for any allow, and is not refunded by an undo (over-restriction
only). Aggregate budgets (`budget-ledger.ts`): the host's `admitAggregateAction` + `startAggregate` reservations are handed to
the record (`holdBudget(id, reservations)`) instead of being committed after the effect. They stay reserved (counting against
every cap) until the window closes: `finalized` commits them; `compensated` releases them with reason `rollback`; `aborted`
releases them with `effect_not_run`; `compensation_failed` keeps them reserved. Spending cannot be laundered through undo: an
undone action's budget comes back only after the compensation really ran.

Delegation. The record names the leaf holder (who acted) and the principal (the grant issuer, the root). Notices and tokens go
to the principal's channels; an intermediate delegator does not get a veto. The compensation is decided over the FULL original
chain, so every delegated caveat that narrowed the original also narrows the undo.

Revocation mid-window. Revocation stops new authority; it does not by itself undo the past. `onRevocation(grantRef)`: per
policy, `keep` (default) leaves every open window of the grant open, alerts (`revoked_open_window`) and sends a `revoked`
notice (the principal can still undo); `veto` vetoes them all (via `revocation`) and compensates. The compensation itself is
not blocked by the revocation (it is decided at `opened_at`), because undoing a revoked agent's effects is exactly what a
principal may want.

## 9. Optimistic claims: a slash really rolls back

`optimistic.ts` decides fraud and `bond-store.ts` (`StoreBondLedger.slashBond`) settles the bond, but nothing used to undo the
effect. `coordinator.open(adm, { bond: { ref, challengeEndsAt } })` links the record to the claim's bond and stretches the
window to the challenge end. `coordinator.rollbackOnSlash(bonds, params)` calls `slashBond` first (the bond ledger re-runs
`verifyFraudProof` itself and refuses outside the challenge window, so a challenger's assertion moves nothing), then vetoes the
linked record with via `fraud_proof` and evidence = H(settlement record), which runs the compensation. A slash whose effect
cannot be rolled back (record finalized, compensation failed) raises a critical `slash_after_window` alert.

## 10. Audit receipts

Every transition appends an `UndoReceipt` `{v:1, kind:'pca-undo-receipt', record, event, state, at, compensation_digest, prev,
note, signer, sig}` signed by the undo service key over `"atlas-pca/undo-receipt/v1\0" || strictCanonical(body)`. `prev` is
`H("atlas-pca/undo-receipt-ref/v1", previous receipt)` ('' for the first), so a record's receipts are a hash chain:
`undoReceiptChainError` checks every signature, the record and compensation binding, the links, that the first is `opened`, that
time never goes back, and that the last receipt's state is the record's state. Events: `opened`, `effect`, `vetoed`, `aborted`,
`finalized`, `compensated`, `compensation_failed`, `retried`. The hosted ledger accepts an update only when the new chain
verifies and extends the stored one.

## 11. Threats and the answer to each

| Threat | Answer |
|---|---|
| agent signs `reversible` for an irreversible action | the class comes from the confirmed definition; signed class can only make it stricter (C-U2) |
| definition claims reversible but is unreviewed / self-signed | only an attestation by a pinned reviewer key counts (C-U3) |
| compensating action not permitted by the grant | refused at admission and re-decided at veto; a refusal at veto is `compensation_failed` + alert (C-U4) |
| veto after expiry | `window_closed`; token also `expired` (C-U5) |
| double veto / veto racing finalize | CAS on `ver`; replays change nothing (C-U6) |
| crash between veto and compensation, or during it | durable `vetoed` + operation record per attempt; `recover` never re-runs an uncertain one (C-U7) |
| forged / replayed / cross-record token | signer pin, signature, record and binding checks (C-U8) |
| window nobody hears about | notifier required; undelivered `opened` aborts the record (C-U9) |
| budget laundering via undo | reservations held through the window; released only after a real compensation (C-U10) |
| volatile ledger loses windows on restart | non-durable store refused (C-U1) |
| PEP that does not run windows | `undo_window` obligation unknown to it -> deny (C-U11) |
| hosted veto lost or outrun by finalize | pending veto blocks a finalizing PUT; relay read before every sweep, unreadable relay = no finalize, 60 s grace (C-U12) |

## 12. Cross-language

Vectors: `packages/pca/conformance/undo-vectors.json` (generated by `src/test-support/undo-vectors.ts`): the state machine
table, token checks (each refusal code), receipt and chain checks, window clamping, the `undo_window` obligation. Natives
implement the pure layer (record transitions, token and receipt verification, obligation kind); the coordinator stays in the
TypeScript server. Brief for the native ports: kept with the 0.5 track briefs (brief-undo-natives).
