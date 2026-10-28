# @atlasauth/pca-actions

Define each action once. Everything else is derived from the definition: the signed action schema, the operation binding, the policy card text, the risk and the escalation tier. Authorization comes from **traits** (`money_moving`, `destructive`, `external_communication`, ...): a trait is a named restriction floor that can only add restrictions, so tagging an action can never loosen anything, and a policy written against a trait covers every present and future action that carries it.

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

## Hello world (30 seconds)

```sh
npm create pca-app@latest my-app -- --template actions   # or, in any folder: npx pca actions init --ns acme
cd my-app && npm install
```

`actions/acme.yaml`:

```yaml
ns: acme
since: 0.1.0
actions:
  - verb: acme.invoice.send
    title: Send an invoice
    description: Emails an existing invoice to the customer.
    effects: [send]
    resource: acme.invoice:inv_*
    params:
      invoice: id:acme.invoice
      to: email
      note: message(500)
    examples:
      - params: {invoice: inv_12345678, to: a@b.com, note: hi, idempotency_key: k_12345678}
        under:
          allow: {trait: external_communication, where: {to.domain: [b.com]}, caveats: [rate_cap, resource_scope], context: [fresh_revocation]}
        expect: allow
      - params: {invoice: inv_12345678, to: someone-else, note: hi, idempotency_key: k_12345678}
        expect: escalate
```

Everything not written is defaulted: params are required, `idempotency_key` is added for an action that sends, pays or creates (the linter notes it), reversibility is `irreversible` for any write, and the traits `external_communication`, `pii_access` and `irreversible` are implied. Those traits are what the action would have once a person confirms it (see the next section): until then it is treated as the most dangerous action there is.

```sh
npx pca actions lint --strict     # 0 errors, 0 warnings, 1 note
npx pca actions test              # runs the examples and the generic property checks
npx pca actions explain acme.invoice.send
#   Send an invoice. This action has not been reviewed by a person, so it is treated as the most dangerous kind of action: it ...
#   effective: risk 3, irreversible, blast 1000k, escalation: stepup
#   ...
#   review: authored, not confirmed by a signed review
#   until a reviewer signs it this action is treated as the most dangerous kind of action; as written it would be: risk 2, escalation tier 1, traits: pca.external_communication, pca.irreversible, pca.pii_access
npx pca actions confirm acme.invoice.send --kid rev-1 --reviewer-key <32-byte base64url secret> --yes
#   after you list that reviewer key under "reviewers" in pca.config.json, explain, build and sign use the real traits:
#   Send an invoice. This action sends to people outside your organisation, cannot be undone and touches personal data.
#   effective: risk 2, irreversible, blast 50k, escalation: confirm
npx pca actions build             # .pca/schema.json, pack.json, cards.json, ontology.json, mcp.json, types.d.ts
npx pca actions sign --kid site-1 --key <32-byte base64url secret>
npx pca actions publish           # .pca/.well-known/pca-actions.json (add --api and --sk to anchor it in an Atlas instance)
```

## Unconfirmed means maximally dangerous

An action's traits (does it move money, delete things, send messages, run code ...) decide how much a grant must carry before it is allowed. Machines are good at guessing those traits and not good enough to trust: the best rules still miss between 5 and 35 percent of a given trait on real APIs. So **nothing a machine wrote ever lowers what is enforced.**

- An action without a valid human confirmation is treated as having **every** trait: money, deletion, outbound messages, code execution, privilege change, credentials, public exposure ... and `pca.unreviewed`. It needs the strictest step-up, every caveat and every context key. This is true for imported actions, for catalog packs, for actions a model suggested and for actions you wrote by hand and nobody signed.
- A confirmation is a signature by a **reviewer key** you pin (`reviewers` in `pca.config.json`, or `ctx.reviewers` in the verifier) over this exact definition and the trait registry it was reviewed against. It sets the traits to exactly what the reviewer decided (a suggested trait they dropped needs a written reason, and is part of what they signed). Change one character of the definition, or the trait registry, and the confirmation no longer counts and the action is back to the strictest treatment.
- The machine's traits are still useful: `pca actions confirm` shows them, riskiest first, so the reviewer checks and signs instead of starting from nothing. How good the classifier is decides how long review takes, never what is enforced.
- A verifier does not trust the schema's own word either: a signed schema must carry every trait for any action whose confirmation does not verify against the verifier's pinned reviewer keys, otherwise it is refused (rule 22).
- The built-in actions are confirmed at release time by the release key during the release process; a build without that step treats them as unconfirmed too.

Catalog packs ship with the machine's traits as hints. A pack is therefore **inert-strict** until someone reviews it: every action in it needs the strictest treatment. Review a whole pack in one pass (it prints the riskiest first and signs nothing without `--yes`):

```sh
npx pca actions confirm --pack stripe --origin any --packs-dir packs --kid rev-1            # preview
npx pca actions confirm --pack stripe --origin any --kid rev-1 --reviewer-key <secret> --yes  # writes stripe.reviewed.yaml
```

## The TypeScript builder

The same action, with the same digest:

```ts
import { action, p } from '@atlasauth/pca-actions';

export const sendInvoice = action('acme.invoice.send', {
  title: 'Send an invoice',
  description: 'Emails an existing invoice to the customer.',
  effects: ['send'],
  resource: 'acme.invoice:inv_*',
  params: { invoice: p.id('acme.invoice'), to: p.email(), note: p.message(500) },
  since: '0.1.0',
});
```

The builder is a thin constructor over the JSON form: it has no capability the JSON lacks, and `action()` throws a typed error for a definition the strict validator refuses.

## Shorthands

| Param shorthand | Expands to |
|---|---|
| `email`, `phone`, `url`, `uuid`, `country` | a string with the matching role/format (`email` and `phone` are tagged `pii`) |
| `ccy` | a string with role `money.currency`, format `iso_currency` |
| `secret` | a string with role `credential.secret`, tag `secret` |
| `text(N)`, `string(N)` | a string up to N bytes |
| `message(N)` | free text that leaves the organisation (role `text.message`, tag `free_text_outbound`) |
| `int(MIN..MAX)`, `count(MAX)`, `duration(MAXMS)` | bounded integers |
| `money(USD, max=N)` or `money(@currency_param, max=N)` | an integer amount in minor units with a unit, bounded, `provenance_min: first_party` |
| `enum(a\|b)`, `set(a\|b)`, `array(string, max=N)` | an enumeration, a set, a bounded array |
| `id:<type>` | an identifier of a resource type |
| `bool`, `date`, `datetime` | as named |

A trailing `?` makes a parameter optional. Any parameter may instead be written as a full object. A resource is `type`, `type:*`, `type:exact`, `type:prefix*` or `type:prefix*{class,min..max}`, with an optional `@one|set|tenant|global`.

A file that cannot be read the same way by every tool is refused: YAML aliases, anchors, merge keys, duplicate keys and unknown tags, a `__proto__` member, floats, unknown members, and files above 1 MiB.

## Lint

Errors fail a run; warnings fail under `--strict`. Output is plain text or SARIF (`--format sarif`) so findings appear as pull request annotations.

| Id | Finds |
|---|---|
| LD-001 | a destroy-like verb whose effects do not delete |
| LD-002 | a money parameter without a currency, or a currency without `iso_currency` |
| LD-003 | a numeric parameter without min and max |
| LD-004 | a money-moving action without idempotency |
| LD-005 | personal data that can be sent or exported without the matching effect |
| LD-006 | a declared reversibility or blast below the effective floor |
| LD-007 | an unknown trait, role, format, effect or context key; an invalid custom trait |
| LD-008 | resource id `*` with scope one |
| LD-009 | a duplicate verb or alias |
| LD-010 | a write marked reversible with no compensating action |
| LD-011 | `confirmed` without a valid attestation for this digest |
| LD-012 | a structural rule that the action's traits require is violated |
| LD-013 | a read-only action that can mutate, or handles credentials |
| LD-014 | one binding in two definitions |
| LW-001 | description missing or too long; title not imperative |
| LW-002 | a string parameter without `max_len` |
| LW-003 | free text flowing into an outbound action without `free_text_outbound` |
| LW-004 | an unreviewed definition in a stable pack |
| LW-005 | a dismissed suggested trait without a reason |
| LW-006 | an array parameter without `max_items` |
| LW-007 | a critical parameter without `provenance_min` |
| LW-008 | verb naming inconsistent with its siblings or the file namespace |
| LW-009 | a money-moving, destructive or privilege-changing action without an example |
| LW-010 | `since` is missing |

Lint is a safety net for authors, not the control: the floors that traits attach are what bind, and a definition nobody has reviewed takes the most restrictive floor.

## Examples

An example is `{params, under?, expect}`. `pca actions test` checks the params against the derived schema, then decides them through the effective floor of the action. `under.allow` is a small selector (`trait` or `verb`, `where` on parameters, `caveats` the grant carries, `context` the call carries) that stands for a grant: an example without one is decided as if no grant pre-authorized anything. A mismatch between the expected and the actual decision fails the run, as does any mutation of an example (a missing, extra, mistyped or out-of-range parameter) that the schema would accept.

## Importing

```sh
npx pca actions import tools.json --from mcp --ns shop --out actions/shop.yaml
npx pca actions import openapi.json --from openapi --ns shop --out actions/shop.yaml
```

Sources: an MCP `tools/list` result, an OpenAPI 3 document, one JSON Schema (`--from jsonschema --verb ns.noun.action`). The importers are offline and bounded. Every imported definition is **unreviewed**: it takes the most restrictive floor and escalates under any grant until someone reviews it. Tool annotations and HTTP methods only choose the draft effects.

## Diff

`pca actions diff <old> <new>` classifies each action as `equal`, `narrow`, `widen` or `incomparable` (plus `added` and `removed`) and exits non-zero on any widening. A change it cannot show to be no wider counts as a widening.

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| A definition file that is ambiguous (YAML alias, anchor, merge key, duplicate key, unknown tag, `__proto__`, float, unknown member) or above 1 MiB | refused; nothing is loaded |
| A definition nobody has reviewed (including every imported one) | takes the most restrictive floor and escalates under any grant |
| Lint errors (or warnings under `--strict`) | `pca actions lint` exits non-zero; nothing is built |
| An example whose actual decision differs from `expect`, or a mutation of an example that the schema accepts | `pca actions test` fails |
| A change `pca actions diff` cannot show to be no wider | counted as a widening; non-zero exit |
| `verifyPack` on a malformed pack, a bad or unknown-key signature, a trait, role or rule digest that differs from the verifier's tables, a root that does not match the definitions, or an empty or oversized pack | `{ ok: false, reason }`; it does not throw |
| A parameter outside the derived schema | the example is not a valid call; a missing, extra, mistyped or out-of-range parameter fails the mutation check |
| An unconfirmed action under a trait policy | every prohibit selector matches it and no allow selector does, so it is denied |
| A verb outside the pinned pack | denied, or escalated when the policy says so; never allowed |
| An allow selector that uses negation, or `any_of` in an unpinned grant | refused with its reason |
| A resource id pattern that is malformed, over 128 characters or in the wrong class | refused with its reason; a wider or different pattern is never contained |
| A schema whose floors cannot be recomputed, a verb missing from the schema, or floors that are not a valid profile | the schema is refused, or the decision is `deny` |
| A transparency entry for a different pack, or signed by a key that is not pinned | `verifyPackLogEntry` returns `false`; it never throws |

## Limits

- It defines and derives; it does not execute actions, and it does not authorize anything by itself. The grant and the verifier decide.
- Lint is a safety net for authors, not the control. The floors that traits attach are what bind.
- A trait can only add restrictions, so a definition can never loosen another; it also means a wrong trait can make an action more restrictive than you meant.
- The importers are offline and bounded, and they draft from tool annotations and HTTP methods; a human has to review each imported definition.
- Examples show the behaviours you wrote down, not every behaviour.

## Library

Besides the builder: `loadActionsText`, `lintDefs`, `explainDef`, `runDefTests`, `diffDefs`, `buildArtifacts`, `signPack`, `verifyPack`, `toolActionMapOf`, and the derivations (`toSchemaDoc`, `operationOf`, `riskOf`, `cardOf`, ...).
