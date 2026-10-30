---
title: How approvals work
order: 42
---

# How approvals work

Some agent actions are too risky to run on the agent's word alone, for example anything irreversible or above a spending limit. Atlas holds such an action as a **step-up** and asks a person to approve it. This page explains what happens next: who is asked, how they are reached, what their passkey signs, and how the agent finds out.

## In one minute

1. The agent submits an action. Atlas holds it and answers `202` with a `stepup_id`.
2. Atlas notifies the approvers for the grant's principal by push, email, SMS, Slack or your own signed webhook. Every message carries a single-use link to the hosted approval page.
3. The approver opens the link and sees the complete action: the verb, the resource, every parameter, how reversible it is, and a match code.
4. They approve with their passkey (Face ID, Touch ID, Windows Hello or a security key). The passkey signs that exact action as it was shown, so nothing else can be approved with it.
5. The agent learns the outcome by long poll or webhook. If nobody approves in time, the answer is **deny**.

## Setting up approvers

An approver belongs to one principal: the key that issued the agent's grant. To enrol one, create an enrolment link in the dashboard (**Connections → Approvers & channels**) or with the API:

```http
POST /v1/pca/approvers/enrolments
Authorization: Bearer sk_...

{ "subject_type": "org", "subject_id": "org_...", "display_name": "Ada",
  "email": "ada@example.com", "phone": "+14155550100", "channels": ["push", "email"] }
```

The response has an `enrolment_url`. It works once and expires after 24 hours. When the approver opens it, the page asks them to create a passkey. On their device, the page then:

- generates the principal key;
- encrypts the principal key with a secret that only their passkey can produce (the WebAuthn PRF extension);
- sends Atlas the passkey's public key and the encrypted principal key.

Atlas never sees the principal key itself, so a database leak cannot be used to approve anything.

To add a second device or a delegate, create an enrolment with `approver_id`. The new person unlocks the existing key with an enrolled passkey, then wraps it under their own passkey.

`PATCH /v1/pca/approvers/:id` sets the **quorum**, which is how many different members must approve. One deny from any member denies the action. You can revoke a passkey at any time with `DELETE /v1/pca/approvers/:id/credentials/:credentialId`.

## Notification channels

Turn channels on in the dashboard or with `PUT /v1/pca/approvals/settings`. Each member can also choose their own channels.

| Channel | Who receives it | Sent through |
|---|---|---|
| Push | the member's verified devices | your own APNs / FCM credentials |
| Email | the member | your own email provider (Atlas never sends approval mail from its own account) |
| SMS | the member | your own SMS provider |
| Slack | a channel | a Slack incoming webhook you provide (stored encrypted) |
| Webhook | your systems | your signed webhook endpoints, event `pca.approval.requested` |

Every notification has a single-use link to the approval page. **A link can never approve on its own.**

- Opening it changes nothing, so mail scanners and chat previews are harmless.
- The Slack buttons only open the page. Atlas has no Slack interaction endpoint that could approve.
- Approval always needs a passkey on the page. A link alone can only deny, because denying is the safe direction.

Atlas sends each notification once. It retries failures after 30 seconds, then 2 minutes, then 10 minutes, and limits each member to 30 notifications per 10 minutes. Delivery status for each channel (`sent`, `failed`, `rate_limited` and so on) appears on the step-up as `notifications`.

## What the passkey signs

The approval page shows every parameter as Atlas received it. Nothing is summarised and no model writes any of the text. The passkey challenge is built from two values:

- the digest of the held action;
- the digest of exactly what the page displayed.

Atlas computes the challenge itself. The page computes it again and refuses to continue if the two differ. As a result, a passkey approval:

- cannot be replayed against another action;
- cannot be made on another website, because a passkey only works on the site it was created for;
- cannot be reused, because each link works once and the passkey's signature counter has to move forward.

After the passkey check, the page uses the unlocked principal key to sign the step-up. Atlas verifies that signature like any other co-signature and records it, then records who approved, with which passkey, over which render and through which channel. These votes are returned on the step-up as `votes`.

## Enterprise identity providers (CIBA)

If your company approves things in its identity provider's app, configure CIBA in the approval settings:

- **notify:** Atlas also asks the identity provider. A deny there denies the step-up. An approval there grants nothing by itself.
- **require:** a member's passkey approval is accepted only after their identity provider has approved too. Until then the page says to approve in the company app first.

## How the agent resumes

- **Long poll:** `GET /v1/pca/stepups/:id?wait=25` answers as soon as the step-up is decided, or after 25 seconds at most. The agent SDK's `awaitStepUp` does this for you.
- **Webhooks:** subscribe to `pca.stepup.approved` (which includes the receipt), `pca.stepup.denied` and `pca.stepup.expired`. Each event is sent once.
- **Timeout means deny:** a step-up that nobody approves expires. Expiry emits `pca.stepup.expired` and every link stops working. Treat `expired`, `denied`, `timeout` and any error the same way: the action does not run.

## Keys you hold yourself

If the principal key lives in an HSM or a hardware key rather than behind a passkey, the dashboard keeps an **Advanced: sign with a principal key you hold** section. It is collapsed by default, and the key stays in the browser tab's memory only. This path is refused when a quorum of more than one is set or CIBA is in `require` mode, because it would bypass both.

## Undo notices

Some actions run first and can be undone for a short time. For these, approvers receive an "Already done, you can undo it until …" notice on the same channels. Its link opens the same page with an **Undo** button. The link expires when the undo window closes.
