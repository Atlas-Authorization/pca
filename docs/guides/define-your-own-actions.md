---
title: Define your own actions
order: 41
---

# Define your own actions

Your agents act on your product: they refund orders, invite users, deploy services. Atlas can only judge such an action well if it knows what the action does. This page shows how to describe your own actions, add your business rules (limits, approvals, hours, recipients), get them reviewed, and publish them to your instance. There are two ways to do it: the `pca` command line for developers, and the **Custom actions** console in the dashboard for everyone else. Both produce the same thing.

## What an action definition is

An action definition describes one thing an agent can ask for, for example `shop.order.refund`. It says:

- what the action does (its effects: read, update, pay, send, delete, ...);
- which object it acts on (an order, a user, a service);
- its parameters, with types and limits (an amount with a currency and a maximum, an email address, an id);
- whether it can be undone, and by which other action;
- its traits: named risk classes such as "moves money" or "changes a production system". Each trait brings a minimum set of checks.

A definition counts only after a **reviewer** has confirmed it. A reviewer is a person you trust to say "yes, this is what the action does". They sign the exact definition with their key. Until then the action is **unconfirmed**, and Atlas treats it as the most dangerous kind of action: it gets every high-risk trait, it can never be undone, and it always needs a person's approval (or is refused when the grant cannot allow that). This holds for anything Atlas did not get from a reviewer: an imported API, a template, a suggestion, a hand-written file. Importers and suggestions can add caution. They can never remove it.

So the work is: describe the actions, have a reviewer confirm them, publish.

## The developer path

Install the CLI (`npm i -g @atlasauth/pca-cli`). A project is a directory (default `actions/`) of YAML files plus a `pca.config.json`.

### 1. Start a project

```sh
pca actions init --ns shop --template ecommerce
```

`--template` takes a small example (`minimal`, `saas`, `db`, `mcp`) or a starter pack for a type of business (`ecommerce`, `fintech`, `healthcare`, `saas_admin`, `devtools`; see [Starter templates](#starter-templates)). It writes `actions/shop.yaml` and `actions/pca.config.json`. The starter packs also write their custom traits into the config. Everything it writes is unconfirmed.

You can also start from what you already have:

```sh
pca actions import openapi.json --from openapi --ns shop --out actions/shop.yaml
```

`--from` is `openapi`, `mcp`, `graphql`, `grpc`, `asyncapi` or `jsonschema`. Every imported action is unconfirmed.

### 2. Describe the actions

A short action in YAML:

```yaml
ns: shop
since: 0.1.0
actions:
  - verb: shop.order.refund
    title: Refund an order
    description: Returns money to the customer for all or part of an order.
    effects: [pay]
    resource: shop.order:ord_*
    params:
      order: id:shop.order
      amount: money(@currency, max=10000000)   # integer minor units (cents), currency from the next parameter
      currency: ccy
      reason: text(500)?
    rules:
      amount: {max: {USD: "500.00", EUR: "450.00"}}
      approval: {above: {USD: "100.00", EUR: "90.00"}, approvers: 1, group: support_leads}
```

The `rules:` block holds your business rules. They are explained in [Business rules](#business-rules).

### 3. Check your work

```sh
pca actions explain shop.order.refund   # the policy card in plain language, plus each business rule as a sentence
pca actions lint                         # mistakes, contradictions, rules that can never fire; exit 1 on an error
pca actions test                         # runs every example, including the examples under rules:
```

`lint` reports rule problems with ids starting `LR-`: a malformed rule or an unknown parameter (`LR-001`), a contradiction that refuses every call (`LR-002`), a rule that can never fire or that another rule already covers (`LR-003`, a warning), and an example that does not decide as it says (`LR-004`).

### 4. Confirm (the reviewer)

The reviewer reads each action and signs it:

```sh
pca actions confirm shop.order.refund --file actions/shop.yaml          # shows the review; signs nothing
pca actions confirm shop.order.refund --file actions/shop.yaml \
  --kid rv_ada --reviewer-key "$REVIEWER_KEY" --yes                      # signs
```

Without `--yes` it only prints what the reviewer is about to sign: the card, the declared, implied and suggested traits. To drop a suggested trait, pass `--dismiss trait=reason`; a reason is required. The confirmation also signs the action's business rules, and those signatures are written to `pca.rules-reviews.json` next to the file.

A confirmation counts only where the reviewer key is pinned: in `pca.config.json` under `reviewers` for your local checks, and on your Atlas instance for the hosted verifier. On the instance, reviewer keys are pinned by enrolling a reviewer with a passkey (see [Reviewers](#reviewers)). A definition signed by a key the instance does not pin is stored, but the instance treats it as unconfirmed. To confirm such an action on the instance, find it under **Overview** and select **Open for review** (or call `POST /v1/pca/action-registry/actions/{verb}/review`): it becomes a draft that an enrolled reviewer confirms with their passkey, and the next publish carries the confirmation.

### 5. Build, sign and publish

```sh
pca actions build                                             # writes .pca/ (pack, schema, cards, rules.json, ...)
pca actions sign --kid shop-publisher --key @publisher.key    # signs the schema and the pack
pca actions publish --api https://YOUR_INSTANCE_API --sk "$ATLAS_SECRET_KEY"
```

`build` refuses to run while lint reports an error. `sign` takes `--key` as a base64url Ed25519 secret or `@file`; `pca keygen` makes one. With `--api` (and `--sk`, or the `ATLAS_SECRET_KEY` environment variable), `publish` anchors the schema in the instance's transparency log, then sends the signed pack, its business rules and its custom traits to the instance's action registry. It prints the new version and what changed for each action.

The instance accepts a pack only if it is signed by a **publisher key** it pins. Pin yours once with a secret key that has `pca:write`:

```http
POST /v1/pca/action-registry/publisher-keys
Authorization: Bearer sk_...

{ "kid": "shop-publisher", "pk": "<base64url Ed25519 public key>", "display_name": "CI" }
```

The public key is in `.pca/keys.json` after `sign`. A key can hold only one role: a publisher key can never confirm an action. Remove a publisher key with `DELETE /v1/pca/action-registry/publisher-keys/:kid`.

A publish is refused when:

| Reason code | Why |
|---|---|
| `widen_unreviewed` (409) | an action would allow more than the active version, and no reviewer signed the new form (see [Widening needs a reviewer](#widening-needs-a-reviewer)). The refusal lists the actions. |
| `not_newer` (409) | the version is not above the active one, or is already stored. Versions are plain `MAJOR.MINOR.PATCH`. |
| `bad_pack` (422) | the pack does not verify under a pinned publisher key. |
| `bad_rules` (422) | a rules block is malformed, names an action not in the pack, or lints with an error. |
| `bad_traits` (422) | a custom trait is malformed or weaker than what it implies. |
| `ns_mismatch`, `bad_version` (422) | another namespace than the active version's, or a malformed version. |

## The dashboard path

Open **Custom actions** in the dashboard. It has six tabs: Overview, Review queue, Import, Publish & history, Sources and Reviewers. Nothing you do here needs code.

### Bring in your actions

On **Import**, choose what you have:

- an **OpenAPI** document: a URL, a file, or pasted text;
- an **MCP server**: its URL (Atlas reads its tool list);
- an **AsyncAPI** document: a URL or pasted text;
- a **GraphQL** schema, a **gRPC** `.proto` file, or a **JSON Schema** for one action: upload or paste it.

Pick a namespace (lowercase, for example `billing`) and select **Import as drafts**. Documents are limited to 8 MB. Atlas fetches URLs only over https and never from private network addresses. Tick **Keep in sync** to re-read a URL later, by hand or hourly or daily (see [Keeping in sync](#keeping-in-sync)).

Or, on the same tab, **Start from a template**: pick a starter pack and a namespace and select **Add the drafts**.

Every imported or template action arrives as an unconfirmed draft.

### Review each draft

**Review queue** lists the drafts, the riskiest first. Each card shows:

- the action in plain language, its risk, whether it can be undone, how it escalates, and what a grant must carry;
- what changed against the published version, if there is one;
- findings about the definition and its rules.

On a card you can:

- **edit** the title, description, parameters and their limits, and the compensating action (the action that undoes this one);
- **set business rules**: amount limits per currency, when approval is needed and by whom, "only the caller's own records", rate limits, business hours, allowed recipients, required fields. The card shows what the rules mean as sentences;
- **keep or dismiss each trait**. Dismissing a trait needs a written reason, which is signed with the confirmation;
- **confirm** with your passkey, if you are a reviewer.

Any edit makes the draft unconfirmed again, so save first, then confirm. When the new rules allow more than the published ones, the card says so, and confirming also signs the rules.

### Reviewers

A reviewer is a separate role from an approver. **Approvers** answer for individual actions when an agent asks (see [How approvals work](./how-approvals-work.md)). **Reviewers** confirm what each action is. The same person can be both, with separate enrolments.

On **Reviewers**, select **Enrol a reviewer** and send them the single-use link (it expires after 24 hours). They open it and create a passkey. Their reviewer key is created in their browser and stored only encrypted under the passkey, so Atlas never holds it. Fill in their dashboard user id to let them confirm in this console. Revoking a reviewer unpins their key: every confirmation they signed stops counting, and those actions are unconfirmed again.

### Publish, history and pinning

On **Publish & history**, choose the namespace and select **Publish**. Atlas builds the new version from the published actions plus your drafts, signs it with the instance's own publisher key, and runs the same checks as a CLI publish. The version is the next patch number unless you type one. If the version would widen an action nobody reviewed, it is not published and the console points you to the review queue.

**History** lists every version of a namespace with what changed. Compare any two versions. **Pin** a version to keep agents on it: while a namespace is pinned, new publishes are stored as `staged` and do not become active until you pin them or **Unpin**.

## Business rules

Business rules are your own limits on one action, written in plain terms. They are kept next to the definition but separate from it, so you can change a limit without re-describing the action.

Rules only make things stricter. A rule can ask for approval or refuse; it can never allow something the definition or the grant does not. Adding a rule, or tightening one, never lets more through.

### Amount ceilings

```yaml
rules:
  amount: {max: {USD: "500.00", EUR: 45000}}
```

The highest amount per currency. A string is in major units (`"500.00"` is 500 dollars), with no more decimals than the amount parameter allows (2 by default). A number is in minor units (`45000` is 450.00 euros). An amount above the ceiling is refused. **A currency not listed is refused.** The action needs exactly one parameter with role `money.amount` that declares its currency (the `money(...)` shorthand does this).

### Approval

```yaml
rules:
  approval: {above: {USD: "100.00"}, approvers: 2, group: finance}
# or
rules:
  approval: {always: true}
```

Above the amount, or always, the action needs a person's approval first. A currency not listed in `above` also needs approval. `approvers` is how many different people must approve (1 to 16, default 1). `group` names the approval group they must belong to (lowercase letters, digits and underscores). You put approvers in a group with `PATCH /v1/pca/approvers/:id/members/:memberId` and `{"groups": ["finance"]}`. When a rule asks for more than one approver or for a group, only the approval flow can satisfy it: a single signature from the grant's principal key is not enough.

### Only the caller's own records

```yaml
rules:
  scope:
    - {param: customer, caller: customer_id}
```

The parameter must equal an attribute of the caller, here the caller's `customer_id`. You can name the parameter by role instead: `{role: id.customer, caller: customer_id}`. A call whose caller has no such attribute is refused.

### Rate limits

```yaml
rules:
  rate:
    - {max: 10, per: hour, by: principal}
    - {max: 50, per: day, by: org}
```

At most `max` calls per `hour` or `day`, counted per principal (the default) or per organisation. Up to four limits. The window slides: "per hour" means the last 60 minutes. The count includes only calls that were allowed. When the caller's organisation is not known, a per-organisation limit refuses the call.

### Business hours

```yaml
rules:
  hours: {days: [mon, tue, wed, thu, fri], from: "09:00", to: "17:00", tz: America/New_York, outside: escalate}
```

The days, a 24-hour window and an IANA time zone. Outside the window the action needs approval (`escalate`, the default) or is refused (`deny`). A window that crosses midnight (`from: "22:00", to: "06:00"`) belongs to the day it starts on.

### Allowed recipients

```yaml
rules:
  recipients: {param: to, domains: [example.com], addresses: [ops@example.net]}
```

An email parameter may only name addresses at these domains or these exact addresses (lowercase). For a list parameter every entry is checked, so the list needs a maximum length of at most 64. Anything else is refused.

### Required fields

```yaml
rules:
  required: [reason]
```

These parameters must be present, and a text parameter must not be empty, even where the definition makes them optional.

### Examples

```yaml
rules:
  amount: {max: {USD: "500.00"}}
  approval: {above: {USD: "100.00"}}
  rate: [{max: 20, per: hour}]
  examples:
    - {params: {order: ord_A1B2C3D4, amount: 2500, currency: USD}, expect: allow}
    - {params: {order: ord_A1B2C3D4, amount: 25000, currency: USD}, expect: escalate}
    - {params: {order: ord_A1B2C3D4, amount: 60000, currency: USD}, expect: deny}
    - {params: {order: ord_A1B2C3D4, amount: 2500, currency: USD}, recent: {"0": 20}, expect: deny}
```

Each example is a call and the decision you expect: `allow`, `escalate` (needs approval) or `deny`. `caller` sets the caller's attributes, `at` the time (UTC, ending in `Z`; default Wednesday 7 January 2026, 15:00 UTC), and `recent` how many calls each rate limit has already counted, by its position in the list (`"0"` is the first). `pca actions test` and `pca actions lint` run them.

### How rules behave

- **When in doubt, the rule fires.** If Atlas cannot decide a rule, it applies it: a missing caller attribute, a missing parameter, an unknown currency, an unreadable clock, an unknown count.
- **Caller attributes come only from a signed context attestation.** The values a scope rule compares against (`customer_id` and so on) are read from the caller attributes in a `context_attestation` signed by an attestor key your instance trusts. Attributes an agent sends on its own are ignored, so a scope rule refuses the call.
- **Rules apply to confirmed and unconfirmed actions alike.** An unconfirmed action is already held to the strictest checks; its rules can make it stricter still.
- **A rule that no longer works refuses.** If a published rules block can no longer be applied to its action, every call of that action is refused.

## Widening needs a reviewer

Atlas compares each new version with the active one, action by action. A change that **narrows** (lowers a limit, adds a rule, adds a trait) is published straight away. A change that **widens**, or that cannot be compared, needs a reviewer's signature over the new form:

- a definition whose effective authority grows. Atlas compares what each version enforces, so a confirmed action replaced by a definition no reviewer signed is published, but it is unconfirmed and therefore held to the strictest checks until a reviewer confirms it;
- business rules that allow more: a higher ceiling or a new currency, a dropped or raised approval threshold, fewer approvers or another group, a removed scope rule, a higher or removed rate limit, longer hours, a time zone change, `outside: deny` changed to `escalate`, more recipients, fewer required fields. Removing all rules is a widening too.

Without that signature the whole version is refused with `widen_unreviewed`, and the refusal names the actions.

**Removed actions are deprecated.** An action that is in the active version but not in the new one stays listed in the history, and the verifier treats it like an action it has never seen: the strictest checks, never undoable. Publishing it again later counts as a new action.

## Keeping in sync

When your API changes, your definitions should follow.

**With the CLI.** List the sources in `pca.config.json`:

```json
{
  "ns": "shop", "version": "0.1.0", "stability": "draft", "site": "https://shop.example.com", "aud": "shop-api",
  "sources": [
    { "name": "api", "from": "openapi", "url": "https://api.shop.example.com/openapi.json" },
    { "name": "tools", "from": "mcp", "file": "mcp-tools.json" }
  ]
}
```

Each source has a `name`, a `from` (`openapi`, `mcp`, `graphql`, `grpc`, `asyncapi`, `jsonschema`; a `jsonschema` source also needs `verb`) and exactly one of `file` (relative to the project directory) or `url` (https only).

```sh
pca actions sync            # re-import every source (or one: --source api)
pca actions sync --check    # write nothing; exit 1 when a source changed
```

`sync` writes one file per source, `<name>.sync.yaml`, and records what it imported in `pca.sync.json`. Commit both. For each operation:

- **added**: it lands unconfirmed;
- **changed**: the new form replaces the old one and is unconfirmed until a reviewer confirms it again; the output shows how it changed;
- **unchanged**: it keeps its confirmation;
- **removed**: it leaves the file, and the next publish deprecates it.

Business rules you write under an action in a `.sync.yaml` file are kept across syncs. Actions you wrote by hand in other files are never touched.

**With GitHub Actions.** The `pca` repository ships a reusable action. Check on every pull request, and sync on a schedule:

```yaml
name: actions-sync
on:
  pull_request:
  schedule:
    - cron: "0 6 * * *"

jobs:
  check:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Atlas-Authorization/pca/packages/pca-cli/github-action@v0.5.0
        with:
          dir: actions
          mode: check

  sync:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - id: pca
        uses: Atlas-Authorization/pca/packages/pca-cli/github-action@v0.5.0
        with:
          dir: actions
          mode: sync
      - if: steps.pca.outputs.changed == 'true'
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          git config user.name "github-actions"
          git config user.email "actions-sync@example.com"   # any address; use your bot account's
          git checkout -b actions-sync-${{ github.run_id }}
          git add actions
          git commit -m "Sync action definitions"
          git push origin HEAD
          gh pr create --fill --title "Sync action definitions" --body "Added and changed actions are unconfirmed until a reviewer confirms them."
```

In `check` mode the job fails when a source changed, which reminds you to sync and review. In `sync` mode it rewrites the generated files and sets the output `changed`. Other inputs: `source` (one source only), `cli-version`, `node-version`, and `publish: 'true'` (sync mode only) with `api-url`, `secret-key`, `signing-kid` and `signing-key`, which then lints, tests, builds, signs and publishes. Pass keys only from repository secrets. The instance still refuses any widening a reviewer has not signed.

**In the dashboard.** A source imported with **Keep in sync** appears on **Sources**. Sync it by hand, or set it to hourly or daily. Added and changed operations become drafts in the review queue, and removed ones become removal drafts that deprecate the action at the next publish. When a sync finds something to review, Atlas emails every reviewer who has an email address (through your instance's own email provider) and records the audit event `pca.actions.sync.review_needed`. A source that keeps failing is retried less often, down to once a week. A sync never confirms or publishes anything by itself.

## Starter templates

Each template is a set of typical actions with custom traits, business rules and rule examples. Every action is an unconfirmed draft: read it, adjust it, and have a reviewer confirm it. Replace the example domains with your own.

| Template | Default namespace | What it contains |
|---|---|---|
| `ecommerce` (Online store) | `shop` | Orders (look up, refund, cancel), discount codes, product prices, customer emails, customer export. Refunds have ceilings per currency and need a support lead's approval above a small amount; shoppers can only cancel their own orders; price changes outside office hours need approval; exports always need approval. |
| `fintech` (Payments and accounts) | `pay` | Balances, transactions, payouts, card freeze and unfreeze, beneficiaries, statements. Payouts are capped per currency, run only on business days in New York hours, stay on the account holder's own account, and need two treasury approvers when large. |
| `healthcare` (Clinic and patient records) | `clinic` | Patient records and record export, clinical notes, prescriptions, appointments, patient messages. Record reads state a purpose, exports always need the privacy office, prescriptions outside clinic hours need approval, and messages only go to the patient portal domain. |
| `saas_admin` (SaaS tenant administration) | `admin` | Users, roles, invitations, suspension and reinstatement, deletion, API keys, audit-log export. Every action stays inside the caller's own tenant; invitations go only to approved domains; role changes and deletions need two tenant owners. |
| `devtools` (Deployments and infrastructure) | `infra` | Deploys, rollbacks, scaling, secret rotation, preview environments, temporary production access. Deploys follow Berlin office hours and rate limits; secret rotation and production access need on-call approval. |

Use one with `pca actions init --ns NAME --template ID`, or from **Import → Start from a template** in the dashboard.

## What the hosted verifier does with your definitions

Once your instance has published at least one version, Atlas's hosted verifier uses the active versions for every agent action:

- **Facts about the action.** For a confirmed action, the definition says which parameters are sensitive and what each one may be derived from. These facts are read-only to the agent.
- **Reversibility.** A confirmed action gets the reversibility its definition declares; anything else is treated as irreversible. When the agent's own description of an action is stricter, the stricter one wins.
- **Minimum checks.** Each action's traits set the minimum the grant must carry (limits, caveats, escalation level). An action whose minimum the grant cannot meet needs approval, or is refused.
- **Business rules.** A rule that asks for approval turns the action into a step-up that needs a person; a rule that refuses denies it. Rate-limit counts are taken and recorded in the same step that admits the action, so two calls at once cannot both slip under a limit.
- **Undo.** An action can be undone only when its definition is confirmed and names a confirmed compensating action (see [Undo windows](./undo-windows.md)).

Responses for an allowed action (and for a dry run) carry an `action` field:

```json
"action": {
  "verb": "shop.order.refund",
  "known": true,
  "confirmed": true,
  "deprecated": false,
  "def_digest": "…",
  "registry_versions": ["shop@1.4.0"],
  "undo": { "eligible": false }
}
```

`undo.eligible` is `true`, with `compensation_verb`, when the action can be undone.

An action the registry does not know, one that is not confirmed by a reviewer key the instance pins, and one that is deprecated are all handled the same way: the strictest checks, irreversible, never undoable. The check is reported as `action_registry`, with the reason in the verdict.

Before the first publish, none of this applies, and your instance behaves as it did before.
