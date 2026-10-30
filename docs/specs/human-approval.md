# Human approval of PCA step-ups (passkey approval, channels, agent resume)

Status: implemented for the hosted Atlas API (0.5). This spec is the contract for the hosted approval surface: how a human is
enrolled as an approver, how they are told a step-up is waiting, what they see, how their passkey approval becomes the
principal cosign, how the agent learns the outcome, and how the undo-window track plugs its notices into the same model.

## 1. Problem and goals

A tier-3 action is held as a step-up until the grant's principal adds the `principal` share
(`shareMessage('principal', thresholdMessage(pcactn), signer_set, t)`, Ed25519 under the grant's `principal_pub`). Before this
work nobody was told a step-up existed, and approving meant importing a raw Ed25519 secret into a browser. Goals:

1. A human approves with a passkey on a phone or laptop, from a notification, in under ten seconds.
2. The passkey ceremony is bound to the exact action and the exact screen the human saw (phishing, replay and
   action-substitution resistant).
3. No secret ever travels in a link, a notification, or to the server: the principal key stays non-custodial.
4. Silence, failure and timeout all mean deny.
5. The agent continues by itself once the human decided.

Non-goals: changing the PCA threshold format (the approval ends in the same Ed25519 principal share every verifier already
checks), or letting any channel (Slack, email, CIBA) approve on its own.

## 2. Key model: a passkey-wrapped principal key

The principal key is an ordinary Ed25519 key, generated in the approver's browser at first enrolment. It never leaves the
browser in the clear. It is wrapped (AES-256-GCM) under a key derived from the passkey's WebAuthn PRF output:

```
prf      = WebAuthn PRF extension output, eval.first = prf_salt (32 random bytes per credential, stored server-side)
wrap_key = HKDF-SHA256(ikm = prf, salt = empty, info = "atlas-pca/approval-wrap/v1")
aad      = utf8(instance_id || "\0" || approver_id || "\0" || credential_id)
wrapped  = AES-256-GCM(wrap_key, iv = 12 random bytes, aad, principal_secret)
```

The server stores `{iv, ct}` per credential. It cannot unwrap: the PRF output exists only inside the authenticator and is
released to the page only after user verification on the approval origin. Each enrolled passkey wraps the SAME principal key,
so every device and every delegate signs as the one principal the grant names. Consequences:

- Multiple devices: adding a device unlocks the key with an existing passkey (PRF) and wraps it under the new passkey's PRF.
- Revoking a device deletes its wrapped copy and marks the credential revoked; that passkey can no longer approve through
  Atlas. A device that was ever unlocked could in principle have retained the key, so "Rotate principal key" (a new key,
  re-enrolled as a new principal; existing grants are revoked and re-issued) is the remedy for a lost or compromised device.
- Authenticators without PRF cannot be enrolled for passkey approval; the advanced raw-key path (section 9) remains.

The principal is recorded in the principal registry (`enrolled_via: 'passkey'`) bound to the subject the enrolment named,
so grants this key issues are in the verified tier.

## 3. Enrolment

Enrolment is always started by an authenticated party and completed by the human with a single-use link.

1. Operator (secret key with `pca:write`, or a dashboard owner/admin) creates an enrolment:
   `POST /v1/pca/approvers/enrolments {subject_type, subject_id, display_name?, email?, phone?, approver_id?}` returns
   `{enrolment_url, expires_at, approver_id, member_id}` (24 h). With `approver_id` the enrolment adds a device or a delegate
   to an existing approver (section 6). The dashboard "Approvers & channels" tab has the same form (subject, contact, channels)
   and shows the link to open or send. A new approver's id is derived from the link (`pcaap_` + the first 32 hex of
   SHA-256(`"pca-approver\0" || link_jti`)), so two pages racing on one link cannot create two approvers.
2. The human opens the link (hosted page, mobile first). The page calls `GET /v1/pca/approvals/enrol` with the link token and
   gets creation options: rp `{id, name}`, a fresh random challenge (stored on the link, single use), `pubKeyCredParams`
   ES256 and EdDSA only, `userVerification: 'required'`, `residentKey: 'required'`, the PRF salt, and (when adding to an
   existing approver) the existing credentials + wrapped keys to unlock with.
3. First device: the page generates the principal key, creates the passkey with the PRF extension (evaluating PRF in a
   follow-up `get` when the authenticator does not return it at creation), wraps the key, and posts
   `POST /v1/pca/approvals/enrol {token, attestationObject, clientDataJSON, transports, principal_pub, wrapped, pop}`.
   Additional device / delegate: the page first unlocks the existing key with an enrolled passkey, then does the same.
4. The server verifies the registration (challenge, origin, rpId, UP + UV, ES256/EdDSA key), verifies `pop` - an Ed25519
   signature by the principal key over `"atlas-pca/approver-enrol/v1\0" || link_jti || "\0" || credential_id || "\0" ||
   principal_pub` - so nobody can attach a passkey to a principal key they do not hold, and, for an existing approver,
   requires `principal_pub` to equal the approver's. It stores the credential, enrols the principal, marks the link used and
   writes an audit entry.

Management: `GET /v1/pca/approvers`, `GET /v1/pca/approvers/:id`, `DELETE /v1/pca/approvers/:id/credentials/:cid`
(revoke), `PATCH /v1/pca/approvers/:id` (quorum, member channel preferences), and the same in the dashboard
("Approvers & channels" tab). The last active credential of an approver can be revoked; its pending step-ups then simply
cannot be approved and time out (deny).

## 4. Links

Every link is `<approval origin>/#pca_link=<token>` (the token is in the fragment, so it is never sent to a web server or
logged, and never leaks through `Referer`). The token is `b64u(payload) "." b64u(HMAC-SHA256(k_i, payload))` with
`k_i = deriveInstanceKey(root, instance_id, 'pca-approval-link')` and payload `{v:1, i: instance_id, j: jti, k: kind, e: exp}`;
the row `pca_approval_links(jti)` holds what the link is for (step-up id, approver, member, channel). Properties:

- Expiring: `exp <= step-up expires_at` for approval links; 24 h for enrolment links. Checked server-side on every use.
- Single-use: the jti is consumed by the decision it carries (approve vote, deny, enrol, undo). A consumed link answers
  `410 link_used`. Opening a link (the GET that renders the page) does not consume it, so mail scanners and Slack previews
  cannot burn it, and cannot decide anything either: a GET never changes state.
- Not a secret: a link lets its holder SEE the pending action and DENY it. It cannot approve. Approval requires the passkey of
  an enrolled approver credential of the grant's principal, user verification, the approval origin, and the principal key
  unwrapped by that passkey's PRF.

## 5. The approval page and what is signed

`GET /v1/pca/approvals/link` (token in `Authorization: PcaLink <token>`) returns the step-up as data, never as prose:
`pcactn` (the held action), `signer_set`, `t`, `params`, the server render, `lineage`, `risk`, `expires_at`, `quorum`,
`votes`, the approver's credentials (`id`, `prf_salt`, `wrapped`) and, for an undo link, the undo notice.

The page RE-DERIVES everything it shows and signs; nothing the server returns is trusted as text:

- `action_digest = b64u(sha256(thresholdMessage(pcactn)))` (the FROST action digest, `stepUpChallengeB64u`).
- The canonical render R (K7): `{v:1, kind:'pca-approval-render', verb, def_digest, unreviewed: true, fields}` with one field
  per supplied parameter, sorted by id, class `param`, value verbatim; `def_digest = hashCanonical({d:
  'atlas-pca/hosted-render-def/v1', verb, resource})`. The page refuses if `paramsDigest(params)` does not equal
  `pcactn.action.params_digest` (when the action commits one), or if its own render differs from the server's.
- `H(R) = approvalRenderDigest(R)`; the match code `bindingWords(H(R))` is shown under the fields.
- The WebAuthn challenge is `approvalChallenge(action_digest, H(R)) = SHA-256("atlas-pca/approval-challenge/v1\0" ||
  action_digest || H(R))`. A signature over it proves the approver authorised THIS action as displayed by THIS render.
- The page shows: the verb and resource; every field; "Why: because you asked to ..." (the lineage: the plaintext goal only
  when it opens the grant's goal commitment, otherwise "the grant's committed goal"); the risk class (reversible / costly /
  irreversible, the most dangerous of the agent's declaration and the server's classification) and blast radius; the time
  left; for an undo notice the window end.

Approve: `navigator.credentials.get({challenge, allowCredentials, userVerification:'required', extensions:{prf:{evalByCredential}}})`.
The page unwraps the principal key with the PRF output of the credential used, signs the principal share over
`shareMessage('principal', thresholdMessage(pcactn), signer_set, t)`, wipes the key, and posts
`POST /v1/pca/approvals/approve {token, credential_id, authenticatorData, clientDataJSON, signature, share_sig}`.

The server, in order (every failure is a refusal; nothing is recorded on failure):
1. link: HMAC, kind `approve`, not expired, not used, bound to this step-up;
2. step-up `pending` and not expired; the approver is the one whose `principal_pub` equals the grant's;
3. the credential is active and belongs to that approver;
4. `verifyAssertion` (`@atlasauth/pca-webauthn`): `webauthn.get`, challenge == `approvalChallenge(action_digest, H(R))`
   computed by the SERVER from the held action, origin in the configured approval origins, `rpIdHash == sha256(rpId)`, UP and
   UV set, no cross-origin iframe, signature valid, sign counter rule;
5. sign counter stored with a compare-and-set (a concurrent replay of the same assertion loses);
6. the share signature verifies under the grant's `principal_pub`;
7. the vote is recorded (`pca_approval_votes`, one per member per step-up) with the credential, the assertion digest, H(R),
   the link channel and time: this is the audit receipt of the human decision;
8. when distinct approving members >= the approver's quorum, the share is submitted through the same code path as
   `POST /v1/pca/stepups/:id/cosign` (re-verify everything, re-attestation if stale, anchor, approve). Otherwise 202 with the
   vote count.

Deny: `POST /v1/pca/approvals/deny {token, reason?}`. Deny needs only a valid unused link (deny is the safe direction); it
moves the step-up to `denied`, consumes the link, records a deny vote and is audited.

Security properties:

| attack | why it fails |
|---|---|
| phishing page on a look-alike origin | WebAuthn binds the assertion to the origin and rpId; the PRF output is origin-bound too, so the phisher cannot unwrap the key either |
| replaying an old assertion on a new step-up | the challenge commits to the action digest (counter + nonce inside the PCActn), so it names a different action |
| replaying an assertion on the same step-up | the step-up is single-shot; votes are unique per member; the counter CAS refuses a concurrent duplicate |
| action substitution (show A, sign B) | the page derives the screen and the challenge from the same held action; the server recomputes the challenge from the held action, never from the request |
| render substitution (same action, misleading screen) | the challenge commits to H(R); the server recomputes H(R) |
| stolen link | a link cannot approve; it expires with the step-up and is single-use |
| Slack button clicked | the button is a URL that opens the page; there is no Slack interaction endpoint, and the page still needs the passkey |
| server compromise | the server holds only wrapped keys and public keys; it cannot produce a principal share |

## 6. Multiple approvers, threshold, delegation

An approver (one principal key) has members (humans) and credentials (passkeys; a member may have several). Delegation to an
approver group is an enrolment with `approver_id` naming a new member: the principal unlocks the key with an existing passkey
during the delegate's enrolment, so only the principal (or an existing member) can add a delegate. `quorum` (default 1) is the
number of DISTINCT members whose passkey approval is required before the share is submitted. Quorum only adds restriction: the
cryptographic threshold (agent + FROST guardian + principal) is unchanged, and a quorum of humans still ends in one principal
share. One deny from any member denies the step-up.

## 7. Channels and dispatch

When the hosted API holds a step-up it dispatches notifications after the transaction commits (never inside it; a delivery
problem never fails or delays admission). One delivery row per (step-up, member, channel, kind) - the unique key is the dedupe.
Formatting reuses `@atlasauth/pca` approval channels (`buildTextBody`, `buildSlackMessage`, `buildWebhookBody`), so every
channel shows the same action summary, lineage, render lines and match code.

| channel | scope | transport | link |
|---|---|---|---|
| push | member (instance user) | the instance push sender (BYOK APNS/FCM), every verified device of the member's user, `action: 'approval_request'` | in `context.url` |
| email | member | the instance mailer (BYOK only: never Atlas's own provider keys), template `pca_approval_notice` | in the body |
| sms | member | the instance SMS sender (BYOK), short text | in the body |
| slack | instance | Slack incoming webhook (stored encrypted), Block Kit with URL buttons that open the page | per-delivery link |
| webhook | instance | the instance's signed webhooks, event `pca.approval.requested` (HMAC signed, retried by the webhook worker) | in `approval_url` |
| ciba | member | the instance's enterprise OP (section 8) | none (the OP shows the binding message) |

Configuration: instance settings (`GET/PUT /v1/pca/approvals/settings` and the dashboard) enable channels, hold the Slack
webhook and the CIBA client. The approval origin (where the hosted page lives, and so the passkey rpId) is deployment
configuration (`PCA_APPROVAL_URL`, the page URL; its origin is the WebAuthn origin and its host the rpId); without it passkey approval and enrolment answer `503 approvals_not_configured`. Per member: `channels` (subset of
push/email/sms/ciba) and contact (email, phone, user id for push). Rate limit: at most 30 notifications per member per 10
minutes (excess rows are `rate_limited`, not sent). Retries: a failed attempt is retried by the worker with backoff 30 s, 2 min,
10 min (at most 4 attempts) while the step-up is pending; a step-up that is no longer pending cancels its queued deliveries.
Status (`queued | sent | failed | rate_limited | cancelled | skipped`, attempts, last error without secrets) is returned on
the dashboard step-up list and on `GET /v1/pca/stepups/:id` as `notifications`.

## 8. CIBA (enterprise identity providers)

Per instance, `ciba: {enabled, mode: 'notify' | 'require', backchannel_authentication_endpoint, token_endpoint, client_id,
client_secret, login_hint: 'email' | 'subject_id'}` (`client_secret` stored encrypted). At dispatch the API initiates a CIBA
POLL flow per member with `@atlasauth/pca-ciba` (`binding_message` = the summary + match code) and stores `auth_req_id`,
interval and expiry on the delivery. The decision is pulled lazily (at most once per interval) when the agent polls the
step-up or a member approves.

- `notify`: CIBA is a notification. A CIBA `access_denied` denies the step-up (restriction). A CIBA approval grants nothing.
- `require`: additionally, a member's passkey approval is accepted only after that member's CIBA flow is approved
  (`409 ciba_pending` until then; the page says "Approve in your company app first"). CIBA expiry or denial denies.

CIBA never substitutes for the passkey: an OP's yes/no is a trusted single party, while the principal share is the
non-custodial signature the verifier checks.

## 9. Advanced: hardware and raw principal keys

Grants whose principal key is not passkey-wrapped (an HSM, a hardware key, an operator-held key) keep the existing route
`POST /v1/pca/stepups/:id/cosign {role:'principal', publicKey, sig}`. The dashboard shows it only under "Advanced: sign with a
principal key you hold", collapsed, with the share message to sign; it never stores the key.

## 10. Agent resume and timeouts

- Long poll: `GET /v1/pca/stepups/:id?wait=<seconds>` (at most 25) answers as soon as the status leaves `pending` or the wait
  elapses. `@atlasauth/pca-agent` `awaitStepUp` uses it (one request per 25 s instead of one per second).
- Webhooks: the instance's signed webhooks emit `pca.stepup.approved` (with the receipt), `pca.stepup.denied`,
  `pca.stepup.expired`. A gateway can resume on them.
- Timeout = deny: a step-up expires 15 minutes after it was held; expiry is applied on every read and by the retention
  sweeper, emits `pca.stepup.expired`, cancels deliveries and makes every link answer `410`. The agent SDK returns `timeout`
  when its own deadline passes, and an agent MUST treat `timeout`, `expired`, `denied` and any non-2xx answer as deny.

## 11. Undo windows (hook for the undo track)

Notification kind `undo_window` uses the same links, page and channels. The undo coordinator calls
`notifyUndoWindow(host, instanceId, {principalPub, notice})` with the `UndoNotice` of its section 6a (`kind: 'opened'`, the
record, the one-click token, the render). It resolves `{delivered: true}` only when at least one channel accepted the notice;
the coordinator aborts the window otherwise. The page shows "Already done: <verb> on <resource>. You can undo it until
<window_end>." with the render and match code and an Undo button that posts `POST /v1/pca/approvals/undo {token}`; the API
relays it as `POST /v1/pca/undo/:record_id/veto {token: notice.token}` on the instance host and returns that answer (404 until
the undo routes are deployed, shown as "Undo is not available"). An undo link expires at `window_end` and is single-use.

## 12. Audit

Audit entries. Actor: for decisions made on the page, the member's instance user (`user`) when the member is linked to one,
otherwise `system` with actor id `pca_approver_member:<member id>`; for management, the secret key (`api_key`) or the
dashboard operator (`dashboard_user`). Actions: `pca.approver.enrolment_created`, `pca.approver.enrolled`,
`pca.approver.credential_revoked`, `pca.approver.updated`, `pca.approver.member_updated`, `pca.approval.vote` (decision,
credential, H(R), channel), `pca.approval.rejected` (a passkey assertion that failed, with the reason), `pca.approval.denied`,
`pca.approvals.settings_updated`. The anchored ledger entry of the approved action is the
cryptographic receipt; the vote row is the human-decision receipt and is returned on the step-up as `votes`.

## 13. Data

Migration 0471 (written, applied by hand): `pca_approvers`, `pca_approver_members`, `pca_approver_credentials`,
`pca_approval_links`, `pca_approval_votes`, `pca_approval_deliveries`, `pca_approval_settings`. All rows are instance-scoped
and cascade with the instance.

Shared vectors: `docs/pca/specs/vectors/hosted-approval-render.json` fixes the hosted render (definition domain, field order,
class) and the wrap / enrolment domains; the server and the approval page both test against it.

Webhook catalog: `pca.approval.requested`, `pca.stepup.approved`, `pca.stepup.denied`, `pca.stepup.expired` and the six
`pca.undo_window.*` notices are in the instance webhook event catalog, so endpoints can subscribe to them.
