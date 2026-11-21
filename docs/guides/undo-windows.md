---
title: Undo windows instead of approvals
order: 46
---

# Undo windows instead of approvals

Asking a person before every agent action trains them to click "approve" without reading. Undo windows ask less: an action that can be **confirmed reversible** runs now, and the person gets a message with a one-click **undo** link that works until the window closes. An irreversible action still needs approval first, exactly as before.

Nothing about this weakens a refusal. A `deny` stays a `deny`. Only an action that would otherwise have been put to a person (`escalate`), or one that was already allowed, can get a window, and only when every condition below holds. Anything that is not confirmed counts as irreversible.

## When an action gets a window

All of these must hold. If any one fails, the action follows the normal path (allow, ask, or refuse).

1. **The agent signed it as reversible.** If the agent signs `irreversible` or `rate_limited`, it is taken at its word.
2. **Your action definition confirms it.** The definition for the exact verb (aliases never count) carries a review signed by a reviewer key you pinned, its effective class is `reversible` after every trait floor (an action that sends mail, publishes, executes code or signs something legal is never reversible), and for a value-dependent class, every possible value is reversible.
3. **There is a confirmed compensating action that can undo it on its own.** The definition names it in `compensates`, that definition is also confirmed, it acts on the same resource type, and its required parameters come from the original call (same name and type) or are the id of the object the action created (filled in from the action's result). The agent never supplies the undo.
4. **The grant allows the undo.** The compensating action is checked against the same grant and delegation chain as the original. If the grant does not permit it, there is no window.
5. **The person can be told.** If no notification channel accepts the "already done, you can undo it" message, the window is cancelled and an action that needed approval is refused.
6. **The ledger is durable.** Windows are kept in a durable store. A store that would lose them on restart is refused at startup.

The linter enforces the definition side: a write declared reversible (fixed, mapped or default) that names no compensating action, or one that cannot actually undo it, fails rule LD-010.

## Quick start

```ts
import {
  createAuthorizer,
  createUndoCoordinator,
  createApprovalDispatcher,
  undoNotifierFromDispatcher,
  executeAuthorized,
  reportUndoEffect,
  KvUndoStore,
} from '@atlasauth/pca';
import { openDurableState } from '@atlasauth/pca/durable-state';
import { undoEngine } from '@atlasauth/pca-actions';

const state = await openDurableState({ dir: '/var/lib/my-api/pca' });

const undo = createUndoCoordinator({
  store: new KvUndoStore(state, true),               // durable: windows survive a restart
  engine: undoEngine({ defs: myActionDefs, pins: myReviewerPins }),
  signerSecret: undoServiceKey,                      // 32-byte Ed25519 secret: signs undo links and receipts
  audience: 'my-api',
  resolveGrant: (ref) => grants.get(ref),
  compensate: async ({ operation, idempotencyKey }) => runConnector(operation, idempotencyKey),
  operations: myOperationStore,                      // at-most-once records for each undo attempt (shared and durable)
  notifier: undoNotifierFromDispatcher(createApprovalDispatcher([slack, email]), {
    undoUrl: (token, id) => `https://my-app.example/undo/${id}?t=${token}`,
  }),
  alert: (a) => pager.send(a),                       // a failed undo is never silent
  policy: () => ({ mode: 'always', windowMs: 15 * 60_000 }),
});

const authorize = createAuthorizer({ audience: 'my-api', resolveGrant, budgetStore, undo });

const r = await authorize({ pcactn, operation });
if (r.allow && r.undo) {
  const outcome = await executeAuthorized(r, () => runConnector(operation), { store: myOperationStore, operation });
  await reportUndoEffect(undo, r.undo.id, outcome);   // the result names what to undo; a failed run closes the window
}
```

`r.decision` is still `allow`. The result carries `r.undo` (the record id, when the window ends, what the undo will do and the encoded one-click token) and an `undo_window` obligation. An enforcement point that does not know the `undo_window` obligation must refuse the action, so an older gateway can never run it without a window.

Run `undo.finalizeDue()` on a timer (every few seconds is fine) and `undo.recover()` on start-up.

## What the person sees

- **Opened:** "Already done: send the draft to Sam. You can undo it until 14:05." with every parameter of the action, rendered the same way an approval request is, and the undo link.
- **Undone**, **Undo failed** (an operator is alerted at the same time), **Final**, and **The agent's grant was revoked, you can still undo it**.

The undo link carries a signed token bound to this one action, to what the undo does, to what the person was shown and to the window end. It works once per action: a second click reports that the undo already happened. A link for another action, an altered link, or a click after the window closes is refused.

## The window

| Setting | Default | Bounds |
|---|---|---|
| `windowMs` (per policy) | 15 minutes | at least 30 seconds, at most 24 hours |
| `mode` | `always`: allowed and to-be-asked actions both get windows | `escalations`: only actions that would have been asked; `off` |
| `onRevocation` | `keep`: the person is told and can still undo | `veto`: revoking the grant undoes the open actions |

A veto at the last millisecond of the window counts; one millisecond later it is refused.

## What happens on undo, and when it fails

1. The undo is recorded first. A second click, or a click racing the window close, changes nothing.
2. If the action has not finished yet, the undo waits for its result and runs as soon as the result is reported.
3. The compensating action is checked against the grant again, then run once, with its own idempotency key. Each attempt is recorded before it starts, so a crash never runs it twice: an attempt that never started is retried, one whose outcome is unknown is marked failed and an operator is alerted.
4. A failed undo is never silent: the record moves to "undo failed", an operator is alerted, the person is told, and you can call `undo.retry(id)` once the cause is fixed.

Every step writes a signed receipt that links to the one before it. `undoReceiptChainError(record, signerPublic)` checks the whole history.

## Budgets

Pass `budget: { ledger }` and call `undo.holdBudget(id, reservations)` after reserving. Spending stays reserved while the window is open, is committed when it closes, and is released only when the undo really happened (or the action never ran). A failed undo keeps the reservation.

## Optimistic claims

If the action also runs as an optimistic claim with a bond, open the window with the bond (`undo.open(admission, { bond: { ref, challengeEndsAt } })`): the window lasts at least until the challenge window ends. `undo.rollbackOnSlash(bondLedger, params)` slashes with the fraud proof first and, only when the slash succeeds, undoes the action. A slash after the window closed still stands, and an operator is alerted that the effect could not be rolled back.

## Hosted ledger

With the Atlas API you can keep the ledger and the public undo endpoint on your instance:

- Pin your undo service's public key in the instance's PCA settings (`pca.undoSigner`).
- `POST /v1/pca/undo/records` and `PUT /v1/pca/undo/records/:id` (secret key, `pca:write`) store records. A record is accepted only when its receipt chain verifies against the pinned key, and an update must extend the stored history without changing what the record is.
- `POST /v1/pca/undo/:id/veto` (public, rate-limited) takes the token from the undo link. The instance checks it and keeps the veto as pending. It never holds your signing key, so your service applies the veto.
- Pass `relay: hostedUndoVetoRelay({ baseUrl, secretKey })` to `createUndoCoordinator`. Every `finalizeDue` reads the pending vetoes first and applies each one as of the moment the person clicked, so a click inside the window counts even if your service reads it later. If the relay cannot be read, nothing is finalized. With a relay, a window is finalized one minute after it ends.

## Limits

- Only actions whose definitions are reviewed and signed by a pinned reviewer get windows. Unreviewed definitions, including unreviewed catalog packs, keep asking first.
- An undo is a new action that reverses the old one, not time travel: anything the first action caused outside your connector (a notification someone already read) is not undone. That is why outbound communication and publishing are never reversible.
- The undo link is a bearer link for one action. If you need a second factor, put the undo endpoint behind your own sign-in.
