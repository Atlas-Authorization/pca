---
title: Guided setup
order: 6
---

# Guided setup: from zero to an enforced, signed agent policy

**Get started with agents** (in the dashboard, under the agent tabs) takes a new developer from "I have an agent" to "my agent can
only do what I reviewed and signed" in about five minutes. It ties together the pieces you would otherwise wire by hand: the proxy
(watch, then enforce), the autopilot (what the agent did, turned into a proposed policy), the control plane (the live fleet view
and the freeze), and your approvers (a passkey signs the policy).

Your progress is saved on the server for each agent. Close the tab, come back tomorrow, or open the page on another device and it
picks up where it was. If two tabs try to change the same setup, the second one is told to reload; nothing is overwritten.

Nothing is ever granted without a passkey signature. The wizard proposes; you decide.

## Before you start

- Agent authority (PCA) on for the instance. The first step offers to turn it on.
- At least one **approver passkey** under *Approvers & channels*. You need it in step 4. If you do not have one yet, add it and
  come back; the page keeps your place.

## 1. Connect

Pick how your agent runs, name it, and the page gives you **one command** with a one-time setup token:

| You run | The command |
| --- | --- |
| An MCP server | `npx @atlasauth/pca-proxy mcp --observe --connect <token> -- <your MCP server command>` |
| An HTTP API | `npx @atlasauth/pca-proxy http --config pca-proxy.yaml --observe --connect <token>` |
| An SDK in your own app | `npx @atlasauth/pca-cli init --connect <token>` |

That is all. The proxy makes the agent's own key on your machine (it never leaves it), registers the public half with the token, and
reports what the agent does, signed with that key. For an MCP server you need no config: the proxy lists the server's tools and pins
them. The token works once, expires in ten minutes, belongs to this instance and this one setup, and can do nothing except register
that one key. It is not an API key. (The registration answers with an ingest key that can send events and nothing else.)

The page shows **Waiting for the first event** and turns green as soon as Atlas has received one. If the token ran out, make a new one:
the old one stops working.

Advanced: you can still make the key yourself (`npx @atlasauth/pca-control-plane keygen`) and report with
`pca-control-plane report`; the setup page is for the one-command path.

## 2. Observe

Use the agent the way you normally would. Every action appears in a live list with a counter. Around ten events are enough to
propose a policy; more events make a better one, especially for numeric limits and how often the agent acts.

## 3. Propose

Atlas turns what it saw into the smallest policy that covers it, then checks it three ways before you see it:

- **Replay.** Every observed action is run through the real verifier against the proposed policy. All of them must pass.
- **Excess authority.** What the policy would allow *beyond* what the agent did, in plain words (for example "every resource under
  `/drafts`, including ones never seen"), with examples.
- **Lint.** The same checks your policy CI runs.

Actions that look sensitive (dangerous verbs, irreversible actions, credentials, billing, unusual amounts) are **held back**. They are
not in the policy unless you include them, one by one, with a checkbox. Actions the enforcer refused while watching are never
included. Including an item produces a new proposal, which is verified again.

A proposal is made on the server from the events that source reported, never from anything the browser sends.

## 4. Sign

You review the exact proposal and sign it with a passkey. The passkey signs a challenge that commits to the proposal, its
verification report, the items you included and an expiry, so that touch cannot be reused for anything else. Atlas refuses the
approval unless it comes from a passkey enrolled as an approver for this instance, with user verification, unexpired and unused.

You also enter the agent's public key: the grant is for that holder only. The grant is then issued and signed by the instance's
guardian key.

If something sensitive or newly blocked happens between the proposal and your signature, the proposal is **stale** and the signature
is refused. Propose again, review what changed, and sign again.

## 5. Enforce

The page shows the grant. Save it as `grant.json` next to where the proxy runs, and run the same command again, enforcing it. The saved
connection is reused, so there is no token:

- **MCP server:** `npx @atlasauth/pca-proxy mcp --enforce --connect --grant grant.json -- <your MCP server command>`
- **HTTP API:** `npx @atlasauth/pca-proxy http --config pca-proxy.yaml --enforce --connect --grant grant.json`
- **SDK:** `npx @atlasauth/pca-cli init --enforce --grant grant.json`

The proxy refuses to start unless the grant was signed by this instance's key (it saved that key when it connected). From then on a call
goes through only if the grant admits it (the action, the resource, the amount caps, the expiry, the rate); a call it admits no longer waits
for a person, except in a session that has seen untrusted content. Your own rules can only make this stricter: a tool you marked `deny`
stays denied.

The step finishes when Atlas sees the first decision made in enforce mode from your agent, and you land on **Fleet control**, where every
agent is listed and any of them can be frozen in one click.

## Setting up another agent

Use **Run setup again for another agent** on the agent pages. Each agent has its own source id, key, proposal and grant.

## What this does not do

- It never loosens anything on its own. Widening a policy later is a new proposal that you sign again.
- It cannot tell what an action means, only what it looked like. That is why anything sensitive waits for your decision.
- It sees verbs, resources and outcomes, plus the parameters that cannot carry content (whole numbers, true/false, short fixed choices),
  each tied to the audit record it came from. That is what lets a proposal cap an amount. Money-like parameters are recorded only
  when you name them (`--include-params amount`), and free text, credentials and personal data are never recorded.
- A "needs approval" decision is read as blocked, never as allowed.
