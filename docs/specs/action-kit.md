# Action kit: one ActionDef, derived authorization

Status: internal design (0.5 line, branch 05-act). Repo paths are intentional here. Do NOT copy any of this into public docs.
Scope: a single, language-neutral, signed, versioned definition of "an action" (ActionDef) from which every other action model in PCA is derived (operation binding, signed action schema, policy predicates, Goal IR ontology terms, policy-card text, risk, escalation), a trait algebra that can only add restrictions, importers, built-in catalog packs, a linter and CLI, signed registries with authority-widening detection, and the cross-language story. The audit that backs Part 1 is in the companion audit report (cited file:line there; the headline findings are repeated in section 1).

Companion: `goal-to-decision.md` (Goal IR, rules 20/21). This spec is the "what is an action" layer under it.

Status of the build: tracks A1, A2 and A4 are implemented (sections 14 to 16 record what they decided and where they differ from the text above); the other tracks are not. Statements about today's code are verified against the 05-act tree (4f6637455); counts of third-party operations are estimates (marked `~`) to be replaced by generator output.
Status of the build: tracks A1 and A2 are implemented (sections 14 and 15 record what they decided and where they differ from the text above); the other tracks are not. Statements about today's code are verified against the 05-act tree (4f6637455); counts of third-party operations are estimates (marked `~`) to be replaced by generator output.
Status of the build: tracks A1 and A4 are implemented (sections 14 and 15 record what they decided and where they differ from the text above); the other tracks are not. Statements about today's code are verified against the 05-act tree (4f6637455); counts of third-party operations are estimates (marked `~`) to be replaced by generator output.

## 0. The short version

The problem: PCA has at least eight separate models of "an action", written by different hands at different times, that disagree with each other today and that an integrator must feed one by one. The fix: ONE `ActionDef` (JSON, versioned, canonical digest). Everything else is a pure, deterministic projection of it. Authorization is derived from TRAITS attached to actions (`money_moving`, `destructive`, ...). A trait is a named restriction floor. The trait algebra is a join-semilattice: tagging an action with a trait can only raise its restrictions, and a policy written against a trait automatically covers every present and future action that carries it.

Design in ten lines:
1. `ActionDef` = verb + resource type/id pattern + typed params (with roles, units, formats, sensitivity, provenance floor) + effects + reversibility + blast + idempotency + required context + traits + bindings (MCP/OpenAPI/HTTP/GraphQL/gRPC) + review state + source digest.
2. `effects` are facts (what happens); `traits` are classes with restriction floors; effects imply traits (delete implies `destructive`), so most integrators write only effects and params.
3. Trait floors form a product of chains and powersets: risk class, reversibility, blast, escalation tier, required caveats, required context, param rules. Join is componentwise max/union. Effective profile of an action = declared values joined with the floors of its trait closure.
4. Adding a trait, or raising a declared value, only moves up the lattice (section 3.4). A declared value below its floor is clamped and linted, never honoured.
5. Decision = meet(policy decision, floor decision). The floor decision is antitone in the profile, so a new trait or a new action can never turn deny/escalate into allow.
6. Allow selectors are positive and PINNED to a registry/pack digest; prohibit and cap selectors FLOAT. Growing the registry can only add prohibitions, never grants.
7. Imported or model-suggested actions start with the trait `unreviewed` (the most restrictive floor). Only a signed review attestation by a pinned reviewer key can lower that to the confirmed set.
8. A signed pack is a Merkle tree of def digests plus a hash chain of versions plus signed evolution records; a semantic diff classifies every change equal/narrow/widen, and a grant pinned to a def digest refuses a widened def until the principal re-approves the diff.
9. The signed ActionSchema on the wire stays (natives already verify it); it gains normative `effects`, `traits`, `def` digest and materialized floors, and a new verifier rule 22 (`traits`). Natives load defs, expand traits, compute digests, conform params and check floors, with shared vectors.
10. `pca actions init|import|lint|test|diff|sign|publish` subsumes `pca schema`; 30 seconds from empty directory to a signed, linted, tested action pack.

## 1. What exists and where it breaks (summary of the audit)

Eight action models today. All paths are under `packages/` unless noted.

| # | Model | Where | Identity of "an action" | What it knows |
|---|---|---|---|---|
| M1 | Signed action schema (ActionVerbDecl) | pca/src/action-schema.ts:91 | `verb` string, free-form | typed params (6 types), semantic string, sensitivity, units on integers, accumulates_into, reversibility(_by), mcp/openapi name; reserved unread members `effects`, `harm`, `world`, `state` (:111-118) |
| M2 | Connector catalog (ActionSpec) | pca/src/catalog.ts:73 | `connector.action` | reversibility (3), blastRadius preset, `amountField`, one resource matcher; 21 entries |
| M3 | Catalog risk | pca/src/catalog-risk.ts:36 | verb lookup | reversibility score, blast = amount/kappa for `amountField` verbs |
| M4 | Operation | pca/src/server/verify.ts:159, server/operations.ts | `{verb, resource, params}` | executes once; its own reversibility vocabulary `reversible|costly|irreversible` (operations.ts:55) |
| M5 | Goal IR ontology | pca-goal/src/ontology.ts:16, ir.ts:158 | `OntVerb.id` (short: `refund`) | effect class (4: read, reversible, external_send, irreversible), param kinds (9), relations, aliases, templates |
| M6 | MCP tool map | pca-mcp/src/schema.ts:66, pca-mcp-rs/src/tool-call.ts:50 | tool name | schema `mcp.tool` binding, or a hand-written `ToolActionMap`; `toolCallRisk` takes a free `amountField` option (:128) |
| M7 | Facade policy | pca/src/facade.ts:114,171 | catalog verb | `parseLimit` ($, period), compiles `amountField` into predicates |
| M8 | Policy bridges / connectors / templates | pca-policy-bridge, pca-connectors, create-pca-app | n/a | bridges translate Cedar/Rego/OpenFGA into predicates with no notion of action classes; pca-connectors is OAuth provider manifests (scopes), not actions; templates hard-code verbs |

Headline inconsistencies (each verified, details and line cites in the audit report):
- Same action, different class. `stripe.refund` is `rate_limited` in the catalog (catalog.ts:76) and `irreversible` in the ontology (ontologies/payments.ts:12); `stripe.charge` is `reversible` (catalog.ts:75) vs `charge_customer` `irreversible` (payments.ts:13). Two verb names for one action (`stripe.charge` vs `charge_customer`), no mapping between them.
- Four reversibility vocabularies: schema `reversible|rate_limited|irreversible`, catalog the same, operations `reversible|costly|irreversible` (revocation.ts:286), ontology effect classes `read|reversible|external_send|irreversible`. No total conversion function exists.
- Five models of "money": catalog `amountField`; schema `semantic: 'money.*'` plus integer `unit`; ontology `kind: 'money'` with `ccys`; envelope `units` tags (rule 20); `toolCallRisk` `amountField` option. A verb can be money in one and plain integer in another.
- Five models of "unit": schema `units{kind,currency,exponent}`, param `unit`, envelope `units: UnitTag`, ontology `OntUnit`, Goal IR `Unit` (ir.ts:10).
- Blast radius exists ONLY in the catalog (a 0..1 float preset); the schema has no equivalent, so a site that publishes only a signed schema gets worst-case risk pricing.
- `effects` is reserved but unread in the signed schema (action-schema.ts:98-106), so the one signed, natively verified action document cannot say "this sends mail".
- The integrator path forks at step one: `defineAction` (catalog, no params), or `pca schema init` (schema, no catalog, no ontology), or hand-written ontology (TS only, signed separately, no relation to the schema's param types). Nothing checks that the three agree.
- Natives (Go, Rust, Swift, .NET, Java, Kotlin full ActionSchema ports; PHP/Python/Ruby embedded in the intent-v2 port) know only M1, no catalog, no ontology, no effects, no traits. Rules 20/21 are primitives only in Go, Rust, Python.
- Name collision to avoid: `@atlasauth/actions` is the auth-pipeline hooks SDK ("Atlas Actions"), unrelated. The new package is `@atlasauth/pca-actions`.

## 2. The ActionDef data model

### 2.1 Shape (normative, JSON, strict canonical)

Document kind `pca-action-def`, `v: 1`. Closed member set (an unknown member is a hard error, as in the schema today). Strings are NFC, no lone surrogates, bounded; integers are safe integers; no floats anywhere (ppm for ratios).

```
ActionDef := {
  v: 1, kind: "pca-action-def",
  verb:      Verb,            // "<ns>.<noun...>.<action>", lowercase [a-z0-9_] segments, 2..6 segments, <= 128 B
  aliases?:  Verb[],          // other names resolving to this def (NL layer, MCP tool names); never ambiguous inside a pack
  title:     string,          // <= 120 B, imperative ("Refund a charge")
  description?: string,
  effects:   Effect[],        // >= 1, closed vocabulary, section 2.2
  resource:  { type: string, id: IdPattern, scope: "one" | "set" | "tenant" | "global" },
  params:    { [name]: ParamDef },   // flat names, plus dotted paths up to depth 3 for nested bodies ("customer.email")
  reversibility?: Rev | { by: paramName, map: {value: Rev}, default?: Rev },
  blast?:    { radius: "one" | "bounded" | "tenant" | "global", ppm?: int },   // radius gives a default ppm; ppm overrides upward only
  side_effects?: [ { target: string, kind: Effect } ],   // downstream effects on other resources ("customer.email" send)
  idempotency: { mode: "key_param" | "natural" | "none", param?: paramName },
  context?:  ContextKey[],    // required context: "approval_ref", "session_taint_max:<level>", "dry_run_first", ...
  traits?:   TraitId[],       // declared traits (additive to effect-implied ones)
  audience?: "resource",      // the audience of a send is the resource itself (a repository, a channel): satisfies recipient_param_declared
  bindings?: { mcp?: {tool}, openapi?: {operationId, method, path}, http?: {method, path}, graphql?: {op, field}, grpc?: {service, method}, asyncapi?: {channel, op} },
  review:    { state: "authored" | "unreviewed" | "suggested" | "confirmed", attestation?: ReviewRef },
  source?:   { kind, uri, spec_digest, licence, imported_at },   // provenance of generated defs
  since?:    string           // pack version that introduced it
}
ParamDef := {
  type: "string"|"integer"|"boolean"|"date"|"datetime"|"duration"|"set"|"array"|"object_ref",
  role?: Role,                // semantic role, section 2.2 (money.amount, money.currency, party.payee, contact.email, path.fs, query.sql, ...)
  required?: bool,            // default true (closed world, as today)
  values?, min?, max?, max_len?, items?, min_items?, max_items?,    // exactly as ActionParamDecl today
  format?: "email"|"url"|"uri_https"|"uuid"|"iban"|"phone_e164"|"cidr"|"iso_country"|"iso_currency"|"semver"|"sha256"|"id:<type>",
  unit?: { kind: "money", ccy: string | { from: paramName }, exp: int } | { kind: "count"|"bytes"|"duration"|"ratio" },
  tags?: ParamTag[],          // "pii", "secret", "credential", "phi", "free_text_outbound", "code", "path", "sql", ...
  provenance_min?: "first_party"|"tool"|"agent",   // least trusted source this value may have (feeds param-provenance)
  sensitivity?: "free"|"material"|"critical",       // floor is derived from role/tags; declared value can only raise
  accumulates?: UnitId[],     // default derived: money.amount accumulates into "money.<ccy>"
  default?, principal_neutral_default?, description?
}
IdPattern := { prefix: string, class: "digits"|"hex"|"alnum"|"slug"|"uuid"|"any_safe", len: [min,max] }  | "*"  | { exact: string }
```

Why a restricted `IdPattern`: containment between two patterns must be decidable (the semantic diff, section 7.3, must prove "new pattern is no wider than the old one"). Arbitrary regex containment is not decidable in general and not cheap in nine languages. `any_safe` is the explicit wide case.

`ContextKey` is the declarative form of "this action is only meaningful with X in the call context"; the verifier gets these from the PCActn context and the grant, never from the agent's claims.

### 2.2 Closed vocabularies

Effects (what the action does; superset of read/write): `read`, `create`, `update`, `delete`, `send` (communication leaves the trust domain), `pay` (money moves), `exec` (runs code/commands), `privilege` (changes who can do what), `export` (data leaves in bulk), `publish` (makes content public), `provision` (creates standing infrastructure/persistence), `sign` (legally or cryptographically binds the principal). An action is `read_only` iff effects = {read}; this is derived, never declared.

Reversibility (canonical, 3 classes, matches the wire): `reversible < rate_limited < irreversible`. `costly` in operations.ts is the same class as `rate_limited` and is renamed in documentation and types (wire value `costly` stays accepted for one release). The ontology's 4-class effect class is DERIVED: `effectClass(def) = read if effects={read}; external_send if effects intersects {send, publish, export} and not irreversible; irreversible if reversibility = irreversible; else reversible`. This function is the ONE adapter and replaces the hand-assigned `effect` field in ontologies.

Blast radius: `radius` default ppm one=50_000, bounded=300_000, tenant=700_000, global=1_000_000 (replaces catalog BLAST presets, which are 0.05..0.9). Money-moving actions take the verifier-priced `amount / kappa` as today (catalog-risk.ts:42), computed from the param with role `money.amount`, never from a hand-named `amountField`.

Roles (param semantics; replace the free `semantic` string and the wallet-floor prefix list, action-schema.ts:461): `money.amount`, `money.currency`, `money.fee`, `party.payee`, `party.payer`, `contact.email`, `contact.phone`, `contact.address`, `person.name`, `person.dob`, `person.national_id`, `credential.secret`, `credential.token`, `credential.key`, `path.fs`, `query.sql`, `query.search`, `code.source`, `code.command`, `url.target`, `text.message`, `text.public`, `id.<type>`, `time.not_before`, `time.not_after`, `count.limit`, `bytes.size`. Roles are an open registry (namespaced custom roles allowed) but a custom role carries only the floors it declares and never lowers a core role's floor. Each core role has a sensitivity floor: the old wallet floor (`money.`, `party.`, `contact.`, `person.`, `credential.`, `text.message`) is the special case.

### 2.3 Canonical digest

`defDigest(d) = b64u(sha256(strictCanonical({d: "atlas-pca/action-def/v1", def: normalize(d)})))`. `normalize` fills every default (required=true, idempotency, blast from radius, derived sensitivities) and sorts every set-like array (effects, traits, tags, aliases) in UTF-8 byte order, so two authoring forms of the same action have one digest. It does NOT include the derived trait closure: that is computed from the trait registry, whose digest the pack pins (`traits_digest`). Pack digest: Merkle root (the existing Merkle construction, Merkle.dfy) over sorted `defDigest`s, domain `atlas-pca/action-pack/v1`; an inclusion proof lets a verifier carry ONE def from a 5,000-def pack.

### 2.4 What an ActionDef yields (the derivation table)

All derivations are pure functions in `@atlasauth/pca-actions`; none is hand-written by the integrator.

| Output | Function | Replaces |
|---|---|---|
| Signed schema verb decl (operation binding, closed-world conform) | `toSchemaVerb(def, registry)` | `draftSchemaFromMcpTools/OpenApi` + `applySchemaDecisions` hand step |
| Operation binding: `PcaOperation{verb, resource, params}` extractor from an HTTP/MCP/GraphQL call | `operationOf(def, call)` (resource from `resource.id` + the param carrying `id.<type>`; params projected to declared ones) | hand-written `ToolActionMap`, `defaultExtract` |
| Risk inputs | `riskOf(def, params, grant)`: reversibility score from effective class, blast ppm, amount/kappa from the `money.amount` param | `catalogRisk`, `toolCallRisk(amountField)` |
| Policy predicates scaffold | `predicatesOf(def, limits)` (ceiling on the `money.amount` param, `gte 0`, resource match) | `compilePolicy` use of `amountField` (facade.ts:212-217) |
| Goal IR ontology terms | `toOntology(pack, domain)`: `OntVerb{id, effect: effectClass(def), resource_type, params}` and traits | hand-written `ontologies/*.ts` verb tables |
| Policy-card text | `cardOf(def, effectiveProfile)`: deterministic sentence from `title`, effect phrases and trait phrases ("moves money", "cannot be undone") | free text in the NL layer |
| Escalation behaviour | effective profile's escalation tier | scattered `reversibility_max` caveats and risk thresholds |
| Units | `unit` becomes schema `units{...}` entries and the rule 20 tag set | five unit models (section 1) |
| MCP annotations (for servers) | `mcpAnnotationsOf(def)` (read-only/destructive/idempotent/open-world hints, advisory) | none |

## 3. Traits

### 3.1 Definition

A trait is a named restriction floor:

```
TraitDef := {
  id: "pca.money_moving" | "<ns>.<name>",     // core traits live in the reserved `pca.` namespace
  implies: TraitId[],                          // DAG, depth <= 8, cycles rejected at load
  floor: Profile,                              // what any action with this trait is at least
  param_rules?: ParamRule[],                   // structural requirements on the def's params (section 3.3)
  card_phrase: string,                         // deterministic, shown on the policy card
  suggest?: SuggestRuleId[]                    // importer heuristics that propose this trait (section 5)
}
Profile := {
  risk: 0..3,                       // low < elevated < high < critical
  rev: Rev,                         // minimum reversibility class
  blast_ppm: int,                   // minimum blast
  esc: 0..3,                        // auto < confirm < cosign < stepup  (minimum escalation tier)
  caveats: Set<CaveatKind>,         // bounds a grant MUST carry before this action is auto-allowed
  context: Set<ContextKey>,         // context a call MUST carry
  prules: Set<ParamRuleId>          // structural param rules the def MUST satisfy (lint + load-time check)
}
CaveatKind := amount_cap | count_cap | window | resource_scope | recipient_scope | approval_ref | short_expiry | rate_cap
```

Order: `p ⊑ q` iff p.risk<=q.risk, p.rev<=q.rev, p.blast_ppm<=q.blast_ppm, p.esc<=q.esc, p.caveats⊆q.caveats, p.context⊆q.context, p.prules⊆q.prules. Join `p ⊔ q` is componentwise max/union. Bottom ⊥ = (0, reversible, 0, 0, ∅, ∅, ∅). Everything is integers and finite sets, so every language implements it in a few lines and the vectors are exact.

### 3.2 Core traits (the first 22; each has a published floor table in the registry, reviewed like code)

| Trait | Implied by effects | Floor highlights |
|---|---|---|
| `pca.money_moving` | pay | risk 3, rev>=rate_limited, blast>=700k, esc>=cosign, caveats {amount_cap, count_cap, window}, context {idempotency}, prules {money_has_currency, money_amount_bounded} |
| `pca.destructive` | delete | risk 2, rev>=rate_limited, esc>=confirm, caveats {resource_scope}, prules {id_not_wildcard} |
| `pca.irreversible` | (from reversibility) | risk 2, rev=irreversible, esc>=confirm, context {fresh_revocation} (re-check before run, as operations.ts does) |
| `pca.external_communication` | send | risk 2, rev=irreversible, caveats {recipient_scope, rate_cap}, prules {recipient_param_declared}, phrase "sends to people outside" |
| `pca.data_export` | export | risk 2, caveats {resource_scope, count_cap}, prules {export_bounded} |
| `pca.privilege_change` | privilege | risk 3, esc>=stepup, caveats {resource_scope, short_expiry}, implies `persistence` when it grants standing access |
| `pca.code_execution` | exec | risk 3, rev=irreversible, esc>=cosign, caveats {resource_scope}, context {sandbox_attested} |
| `pca.credential_access` | (role credential.*) | risk 3, esc>=stepup, prules {secret_not_logged} |
| `pca.bulk` | (array/set unbounded, or scope set/tenant) | risk 2, caveats {count_cap}, prules {array_bounded} |
| `pca.pii_access` | (param tag pii/phi) | risk 1, caveats {resource_scope}, flow rule: label class `pii` may flow only to declared audiences |
| `pca.public_exposure` | publish | risk 2, rev=irreversible, esc>=confirm |
| `pca.persistence` | provision | risk 2, caveats {short_expiry}, context {revocable} |
| `pca.infra_mutation` | (provision/update on infra resources) | risk 2, rev>=rate_limited, caveats {resource_scope} |
| `pca.cost_incurring` | (declared) | risk 1, caveats {amount_cap} |
| `pca.legal_binding` | sign | risk 3, rev=irreversible, esc>=stepup |
| `pca.impersonation` | (send as a person) | risk 2, esc>=confirm, implies `external_communication` |
| `pca.network_egress` | (open-world) | risk 1, caveats {recipient_scope} |
| `pca.financial_data_read` | (role money.* on read) | risk 1, caveats {resource_scope} |
| `pca.regulated_data` | (tag phi/pci) | risk 2, esc>=confirm |
| `pca.scheduled` | provision | risk 2, caveats {short_expiry, count_cap} |
| `pca.unreviewed` | (importer default) | risk 3, rev=irreversible, blast=1_000_000, esc>=cosign, caveats {approval_ref, resource_scope}, context {dry_run_first} (the fail-closed floor) |
| `pca.agent_spawning` | (starts another agent) | risk 2, caveats {count_cap}, delegation narrowing required |

Custom traits (`acme.refund_over_threshold`) are allowed and must EXTEND: `floor(t) ⊒ ⊔ floor(implies(t))` is checked at load (section 3.4, T5). A custom trait cannot reuse a `pca.` id. Core trait floors change only through the pack evolution rules (section 7) and a core change is treated as an authority-widening candidate in both directions: raising a floor is `narrow`, lowering is `widen` and blocked in CI.

### 3.3 Param rules

Prules are structural checks on the def itself, run by the linter and again at load (closed list, versioned, each with a test): `money_has_currency` (a `money.amount` param has a `unit.ccy`, either literal or `{from: p}` where `p` has role `money.currency` with format `iso_currency`), `money_amount_bounded` (integer with finite min and max), `id_not_wildcard` (resource.id is not `*` unless scope is set/tenant), `recipient_param_declared` (a param with role `party.payee`/`contact.*` exists, or the def declares `audience: resource`), `array_bounded`, `export_bounded`, `secret_not_logged` (credential role params carry `tags: [secret]` and are excluded from digests that reach logs), `pay_has_idempotency`. A def violating a prule is not loadable into a registry; it can still be linted into a pack in draft state.

### 3.4 The algebra and its theorems (precise semantics)

Notation: R is a trait registry (trait id to TraitDef, acyclic). `cl_R(S)` is the closure of a set S of trait ids under `implies`. For an ActionDef d: `T(d) = declared(d) ∪ implied(effects(d), roles(d), tags(d)) ∪ {unreviewed if review.state ∈ {unreviewed, suggested}}` where `implied` is the fixed, versioned table in the registry (effect or role or tag to trait). Note: `implied` is itself a monotone function: more effects, roles or tags, more traits.

Definitions:
- `F_R(S) = ⊔ { floor(t) : t ∈ cl_R(S) }` (empty join = ⊥).
- `decl(d)`: the profile the author declared (reversibility, blast, context, and the profile-valued fields implied by params).
- `eff_R(d) = decl(d) ⊔ F_R(T(d))`: the effective profile. A declared value below a floor is clamped by the join (and flagged by the linter), not honoured.

Theorems (each is a stated proof obligation of the build; T1-T3, T5 are mechanized, T4, T6, T7 mechanized for the extracted core and property-tested end to end):

T1 (lattice). `(Profile, ⊑, ⊔)` is a bounded join-semilattice of finite height. Proof sketch: a product of finite chains (risk, rev, esc, blast as a chain of integers bounded by 10^6) and finite powersets (caveats, context, prules); a product of join-semilattices with componentwise join is a join-semilattice.

T2 (traits only add). For all R, d and trait t: `eff_R(d + t) ⊒ eff_R(d)`, where `d + t` adds `t` to declared traits. Also `S ⊆ S'` implies `F_R(S) ⊑ F_R(S')`. Proof: `cl_R` is monotone (closure operators are), join over a larger index set is larger. Order, duplication and nesting of traits are irrelevant: `F_R` is a join over a set, so it is commutative, associative and idempotent.

T3 (inheritance). For any registry R and any def d with `t ∈ T(d)`: `eff_R(d) ⊒ floor(t)`. So any caveat, context or esc tier required by a trait applies to every action tagged with it, including actions added later by anyone, with no change to any policy. Corollary: a trait-keyed prohibition or cap covers a new action the moment it is tagged.

T4 (decision antitone). Define `FloorDecision(G, ρ)` for a grant G and profile ρ: `deny` if ρ.esc demands a tier above the maximum tier the grant authorizes (G.max_esc), else `escalate` if `ρ.caveats \ caveats(G) ≠ ∅` or `ρ.context \ ctx(call) ≠ ∅` or `ρ.esc > 0` and G does not pre-authorize that tier, else `allow`. Then `ρ ⊑ ρ'` implies `FloorDecision(G, ρ') <= FloorDecision(G, ρ)` in the order deny < escalate < allow. The final decision is `Dec = meet(PolicyDecision, FloorDecision(G, eff_R(d)))`, so by T2 adding a trait, or tightening any declared field, never raises `Dec`. (Meet is the existing Goal IR conjunction rule, goal-to-decision.md section 3.2.)

T5 (custom trait soundness). A custom TraitDef is accepted iff `floor(t) ⊒ ⊔ floor(u)` for all `u ∈ implies(t)` and `id` is outside `pca.`. Then no combination of custom and core traits yields a profile below the core floors (by T2). A custom trait cannot weaken `money_moving` because there is no operation that removes a trait or lowers a floor in the algebra. The ONLY non-monotone operation in the system is the review attestation (section 5.4), and it is outside the algebra: it removes `unreviewed` and nothing else.

T6 (registry growth). Let `R ⊆ R'` be registries (same trait definitions, R' has extra actions). (a) Prohibit/cap selectors, which are positive trait selectors (`prohibit any(trait: destructive)`), satisfy `Matched_R ⊆ Matched_R'`: floating, they only ever cover more. (b) Allow selectors are pinned to the digest of R: `Allowed(P_R) over R' = Allowed(P_R) over R`, and an action in `R' \ R` has no allow, so it is `deny` in a closed world (or `escalate` for a grant that opts into `on_new_action: escalate`; never `allow`). (c) Decisions for every a in R are unchanged by moving to R' unless a prohibit now matches, in which case they can only drop. Proof: (a) selector match is a monotone predicate of the trait set; (b) by definition of pinning; (c) from (a) and the meet in T4.

T7 (negation rule). Allow selectors MUST NOT use negated trait predicates (`not trait: X`) and must not use `any_of` over traits unless pinned; absence of a trait is never a safety claim, because a trait is only ever added by a human or by a (union-only) suggestion. Prohibit selectors may use `not`. This is a typing rule of the policy language, enforced by the compiler.

What is NOT claimed: that the author tagged the right traits. The algebra guarantees that a trait is never lost and that mistakes in tagging are repairable monotonically (add a trait, a diff shows the narrowing). Correctness of the tagging itself is supported by the importer heuristics, the review queue and the reviewer key; it is a measured, reviewed property (section 5.4), not a theorem.

Mechanization: Lean `formal/intent/lean/PcaIntent/TraitAlg.lean` (T1, T2, T3, T5 over Finset/Nat chains; small) and Dafny `formal/dafny/TraitExpand.dfy` (the extractable `Expand` and `FloorDecision` functions with T2/T4 as lemmas, extraction to `packages/pca-verified-core/generated` like the other verified cores, 0 assume/axiom). The TS implementation calls the extracted function; natives are checked against it with differential vectors (section 9).

### 3.5 Worked example

`stripe.refund.create` declares `effects: [pay]`, no traits. `implied` adds `money_moving`; the amount param has role `money.amount` so `money_amount_bounded` must hold (author gives `max: 10_000_000`). `eff` = risk 3, rev rate_limited (declared, at floor), blast 700k, esc cosign, caveats {amount_cap, count_cap, window}, context {idempotency}. A grant "refund up to $50, 3 per day" carries amount_cap, count_cap, window, so FloorDecision = escalate only for the cosign tier unless the grant pre-authorizes `esc <= cosign` (a signed field); a grant that carries no amount_cap gets `escalate` for every call. Adding trait `pca.external_communication` (the refund emails the customer) only raises the profile (T2): caveats gain recipient_scope, rev becomes irreversible; the same grant now escalates until it carries recipient_scope.

## 4. Authoring

### 4.1 Hello world (30 seconds)

```
$ npm create pca-app@latest my-app --template actions     # or: pca actions init
$ pca actions init --ns acme
wrote actions/acme.yaml, actions/pca.config.json
```

`actions/acme.yaml`:
```yaml
ns: acme
actions:
  - verb: acme.invoice.send
    title: Send an invoice
    effects: [send]
    resource: acme.invoice:inv_*          # shorthand for {type: acme.invoice, id: {prefix: inv_, class: alnum, len: [8,32]}, scope: one}
    params:
      invoice: id:acme.invoice
      to: email        # shorthand: role contact.email, format email, tag pii
      note: text(500)
```
Everything else is defaulted: required params, `idempotency: {mode: key_param, param: idempotency_key}` auto-added for `send` (the linter complains if the author turns it off), `reversibility: irreversible` (fail-closed default for any write, as reversibilityOf does today, action-schema.ts:437-445), traits `external_communication` and `pii_access` implied, `blast: one` from the id pattern, `review.state: authored`.

TypeScript builder (identical output, same digest):
```ts
import { action, p } from '@atlasauth/pca-actions';
export const sendInvoice = action('acme.invoice.send', {
  effects: ['send'],
  resource: 'acme.invoice:inv_*',
  params: { invoice: p.id('acme.invoice'), to: p.email(), note: p.text(500) },
});
```
The builder is a thin typed constructor over the JSON (no logic that the JSON form lacks; the JSON schema is the source of truth, the builder is generated from it).

```
$ pca actions lint           # 0 errors, 1 note: "acme.invoice.send: idempotency_key auto-added"
$ pca actions explain acme.invoice.send
  Send an invoice.  Sends to people outside your organisation. Cannot be undone.
  effective: risk 2, irreversible, blast 50k, escalation: confirm   (once a pinned reviewer has confirmed it; until then risk 3, step-up)
  grant must carry: recipient_scope, rate_cap
$ pca actions test           # runs examples in the YAML (below) against a policy
$ pca actions sign --kid site-1 --key ./site.key && pca actions publish --api https://api.example.com
```

Examples are part of the def and executable (they are the unit test and the documentation):
```yaml
    examples:
      - params: {invoice: inv_12345678, to: a@b.com, note: hi}
        under: {allow: {trait: external_communication, where: {to.domain: [b.com]}}}
        expect: allow
      - params: {invoice: inv_12345678, to: a@evil.com, note: hi}
        expect: escalate
```

### 4.2 How an ActionDef yields everything (end to end)

`pca actions build` runs the pipeline `load -> validate -> expand traits -> lint -> derive`, emitting: (1) the unsigned ActionSchema document (verbs, params, units, effects, traits, materialized floors, `def` digests); (2) the pack (defs + Merkle root + `traits_digest`); (3) generated TS types for typed call sites; (4) the IntentOntology fragment; (5) the MCP `ToolActionMap` and `mcpAnnotations`; (6) `cards.json` (policy-card text per verb). `sign` signs (1) with the site key exactly as `signActionSchema` does now (the suite comes from the key entry, never the document) and the pack with the registry key. There is no second place to write any fact.

## 5. Importers and trait suggestion

### 5.1 Importers (all produce DRAFT defs with `review.state: unreviewed`)

One interface: `import(source, opts) -> { defs: ActionDef[], todo: Todo[], source: SourceRef }`, deterministic, offline (the caller fetches), bounded (size, depth, ref-expansion limits as flattenSchema already has, action-schema.ts:567-610).

| Source | Maps | Notes |
|---|---|---|
| MCP `tools/list` | tool to def; `inputSchema` to params; annotations: `readOnlyHint` gives effects `read`, `destructiveHint` gives `delete`-class floor, `idempotentHint` gives idempotency natural, `openWorldHint` gives `network_egress` | hints are untrusted lower bounds only (today's rule, action-schema.ts:644-649, kept); upgrades the current `draftSchemaFromMcpTools` (:660) |
| OpenAPI 3.x (and Swagger 2 via conversion) | `operationId` or `method path` to verb; parameters + JSON body to params (nested up to depth 3); `security` scopes to a `required_scope` note; `x-` extensions ignored unless allow-listed; method gives initial effects (GET read, POST create-or-action, PUT/PATCH update, DELETE delete) | unifies and replaces `draftSchemaFromOpenApi` (:727); same $ref resolver |
| GraphQL SDL / introspection | Query field to read; Mutation field to write; args and input objects flattened; `@deprecated` marks the def deprecated | name tokens drive suggestion; no method signal, so more is `unreviewed` |
| gRPC / protobuf | `service.method` to verb; `google.api.http` annotations give method/path; `idempotency_level` option (NO_SIDE_EFFECTS, IDEMPOTENT) gives read / idempotent; field behavior annotations (REQUIRED, OUTPUT_ONLY, IMMUTABLE) refine params; streaming methods get `bulk` | descriptor sets (`.binpb`) or `.proto` |
| AsyncAPI 2/3 | `send` operation to effect `send`; `receive` to `read`; channel to resource; message payload to params | brokers: every publish is `external_communication` unless the channel is declared internal |
| JSON Schema | one schema + a verb given by the caller to one def | the "I have a function signature" path |

### 5.2 Suggestion engine (never auto-trusted)

Two layers, both union-only: they can ADD suggested traits and roles, never remove one and never mark anything confirmed.

1. Deterministic rules: a versioned, signed `suggest-rules.json` of rules `{id, match: {method?, path_re?, name_tokens?, param_names?, param_formats?, roles?}, adds: [trait|role|tag], note}`. Examples: method DELETE adds `destructive`; path/name tokens `refund|charge|payout|transfer|payment|invoice.pay|withdraw` add `money_moving`; `send|notify|email|sms|message|post_to|publish|broadcast|invite` add `external_communication`; `invite|share|grant|role|permission|policy|iam|member|acl|owner|admin|sudo` add `privilege_change`; `export|download|dump|backup|extract|report.generate` add `data_export`; `exec|run|invoke|eval|shell|script|command|deploy|build` add `code_execution`; `token|secret|key|credential|password|api_key|oauth` add `credential_access`; `batch|bulk|all|purge|truncate|wipe` add `bulk`; params named `amount|price|total|fee` with integer type add role `money.amount`; `currency` with iso format add `money.currency`; `email|phone|ssn|dob|iban|address` add contact/person roles and tag `pii`. The rule set carries a labeled corpus and reports precision and recall per trait (section 6.4).
2. Optional model assist (`--suggest model`): a pinned model id and prompt digest, input is the def's name, description and param names/types (never user data), output must be a list of trait ids from the closed vocabulary (anything else is dropped), temperature 0, the call and its digest are recorded in `review.suggested_by`. Several models can be run; the results are UNIONED (union is the restrictive direction, so no N-version intersection is needed here, unlike goal interpretation).

Result: `review.state: suggested`. A suggested def is still `unreviewed` for floor purposes (T(d) contains `pca.unreviewed`). Suggestions improve the card and the review queue ordering; they unlock nothing.

### 5.3 Unconfirmed defaults to the most restrictive set

`pca.unreviewed` (section 3.2) is the maximal floor short of denial: irreversible, blast 1.0, cosign tier, approval and scope caveats required, dry-run first. A pack containing unreviewed defs verifies and signs fine (so imports are usable immediately in a staging policy) but every such action escalates under any grant, and `pca actions lint --strict` (the default in CI for publishing) fails on any unreviewed def in a pack marked `stability: stable`.

### 5.4 Confirmation

`pca actions confirm <verb>...` opens the review (CLI table or the console view): the def, the suggested traits, the derived card, and the semantic diff against the previous version. The reviewer chooses the final trait set; any suggested trait they leave out must be recorded as `dismissed: {trait, reason}` (visible on the card and in diffs; lint warns). Confirmation emits `ReviewAttestation{def_digest, traits_digest, final_traits, dismissed, reviewer_kid, ts}` signed by a key pinned in the registry with role `reviewer`. The attestation covers one `defDigest`: any change to the def invalidates it and the def reverts to unreviewed. Importer and model keys cannot hold the `reviewer` role. This is the single non-monotone step in the system and the single place where human judgement enters; it is the review that the measured precision/recall numbers are about.

## 6. Linter and CLI

### 6.1 Commands

```
pca actions init [--ns N] [--template minimal|saas|db|mcp]      scaffold
pca actions import <src> --from openapi|mcp|graphql|grpc|asyncapi|jsonschema [--ns N] [--suggest rules|model]
pca actions lint [paths] [--strict] [--format sarif|text]        rules below; exit 1 on error
pca actions test [paths]                                          run examples; property-check expansions
pca actions explain <verb>                                        effective profile, card, grant requirements
pca actions diff <old> <new>                                      semantic diff: equal | narrow | widen | incomparable
pca actions confirm <verb>... [--reviewer-key K]                  review + attest
pca actions build                                                 emit schema, pack, types, ontology, cards
pca actions sign --kid K --key F                                  sign schema + pack
pca actions publish --api URL                                     /.well-known/pca-actions.json and the pack registry
```
`pca schema init|sign|publish` (pca-cli/src/cli.ts:140-176) become aliases of `import/sign/publish` for one release and then are removed (0.5 may break).

### 6.2 Lint rules (stable ids; errors fail CI, warnings fail under `--strict`)

Errors:
- LD-001 delete/destroy-like name or `effects ∋ delete` without trait `destructive` (the trait is implied by the effect; this fires when the verb says delete but the effects do not: the def is lying).
- LD-002 `money.amount` param without a currency (`unit.ccy` literal or `{from}`), or currency param without `iso_currency` format.
- LD-003 numeric param with no `min` and `max` (unbounded numeric), unless role is `id.*` or `count.limit` with explicit `max`.
- LD-004 `pay` effect or `money_moving` without idempotency (`key_param` or `natural`).
- LD-005 PII-tagged param (or `contact.*`/`person.*` role) where the action has an `export` or `send` effect but not trait `data_export`/`external_communication` (data can leave without the matching class).
- LD-006 declared reversibility, blast, esc below the effective floor (clamped; the author's number is a lie).
- LD-007 unknown trait id, role, format, effect or context key; trait cycle; custom trait not extending its `implies` floors (T5).
- LD-008 `resource.id` is `*` with `scope: one`.
- LD-009 duplicate verb or alias collision inside a pack.
- LD-010 a write effect with `reversibility: reversible` and no compensating action named (`compensates: verb`) in the pack.
- LD-011 `review.state: confirmed` without a valid attestation for this digest.
- LD-012 prule violations (section 3.3).
- LD-013 `read` is the only effect but a param has role `code.command`, `query.sql` that is not marked read-only-enforced, or any param tagged `credential`: a read that can mutate.
- LD-014 a binding (MCP tool, OpenAPI operationId) present in two defs.
Warnings:
- LW-001 description missing or longer than 400 B; title not imperative.
- LW-002 string param with no `max_len` (defaults to 1024, but say it).
- LW-003 free-text param flowing into an `external_communication` action without `tags: [free_text_outbound]` (prompt-injection channel; feeds provenance).
- LW-004 `unreviewed` def in a pack marked stable.
- LW-005 dismissed suggested trait without reason.
- LW-006 `bulk` suspect: array param with no `max_items`.
- LW-007 `provenance_min` missing on a `critical` param.
- LW-008 verb segments inconsistent with sibling verbs (`create_`/`new_`), ns differs from the file's `ns`.
- LW-009 example missing for any `money_moving`, `destructive` or `privilege_change` action.
- LW-010 `since` missing.

Lint output is SARIF so it appears as PR annotations. Every rule has a fixture def that triggers it and a fixture that does not; the rule list itself is versioned and its digest is pinned by `pca-policy-ci`.

### 6.3 `test`

Runs each def's `examples` through the real pipeline in-process (derive schema, conform params, expand floors, compile the example policy through the Goal compiler, decide), and the generic property checks for the pack: T2 monotonicity over all trait subsets of each def (bounded), digest stability across the YAML/JSON/builder forms, round trip `def -> schema verb -> conformAction` accepts the example params and rejects each mutated one (type swap, out of range, missing, extra).

### 6.4 Measuring the suggestion engine

A labeled corpus `packages/pca-actions/corpus/` of reviewed defs (grows with every pack review); `pca actions eval-suggest` prints per-trait precision and recall with a Clopper-Pearson bound (the repo already has `pca-intent` clopper.ts) and CI fails if recall for `money_moving`, `destructive`, `external_communication`, `privilege_change`, `code_execution` drops below the recorded floor. These numbers are published as what they are: heuristic recall on a reviewed corpus, never a safety guarantee (section 3.4, last paragraph).

## 7. Registries and evolution

### 7.1 Pack and registry wire

```
ActionPack := {
  v: 1, kind: "pca-action-pack", ns, version (semver), stability: "draft"|"beta"|"stable",
  traits_digest, roles_digest, rules_digest,         // the vocabularies this pack was built against
  root: b64u,                                        // Merkle root over sorted defDigest
  defs: [ ActionDef ] | { shards: [ {name, digest, uri} ] },    // large packs are sharded by resource family
  source: { kind, uri, spec_digest, licence, licence_notes },
  prev: b64u | null,                                 // digest of the previous version (hash chain)
  evolution: EvolutionRecord[],                      // signed per-def changes since prev
  sig
}
EvolutionRecord := { verb, from: defDigest|null, to: defDigest|null, class: "equal"|"narrow"|"widen"|"incomparable"|"added"|"removed", reasons: string[] }
```
Signed with the registry key (suite from the pinned key entry, never from the document; same as `signActionSchema`). Domain `atlas-pca/action-pack/v1\0`. Packs are appended to a transparency log (the repo's SCITT package, `pca-scitt`) and carry a monotone version so rollback to an older pack is detectable (verifier keeps `max_version` per ns). Site-published schemas stay at `/.well-known/pca-actions.json` (discovery, action-schema.ts:32) and reference their packs by `{ns, version, root}`.

### 7.2 Pinning in grants

The grant envelope gains `actions: { pack: {ns, root}, defs?: { [verb]: defDigest }, on_new_action: "deny"|"escalate" }`. Meaning: this grant authorizes the verbs it names AS DEFINED by those digests. The verifier compares the digest of the presented/stored def to the pin. Mismatch: `def_changed` deny, unless an `EvolutionRecord` signed by the pinned registry key chains from the pinned digest to the presented one with class `equal` or `narrow` (then allowed: the world only got stricter), or the principal has re-approved (signed approval over the evolution record's `diff` digest). `widen` and `incomparable` always need the re-approval. This is T6 made operational.

### 7.3 Semantic diff (what is widening)

`diff(old, new)` returns the join of per-aspect classes, where each aspect compares sets/ranges/profiles; `incomparable` (one aspect widens while another narrows) counts as `widen` for pin purposes.

Widening (blocks without re-approval): trait removed or floor lowered (T2 reversed); effective profile not `⊒` the old one; effects removed (an action stops claiming it sends); `reversibility` lowered; `blast` lowered; `idempotency` loosened; param `min` lowered / `max` raised / enum values added / `max_len`, `max_items` raised; new OPTIONAL param (opens surface; a new REQUIRED param is narrowing for the same call set but breaks callers: class `narrow`, flagged `breaking`); `required` to optional; `provenance_min` loosened; sensitivity lowered; `unit` changed (rule 20 mismatch: treated as `incomparable`); `resource.id` pattern not contained in the old one (decidable by the IdPattern grammar), `scope` widened; role changed to a lower-floor role; `review.state` from `confirmed` to anything else is narrowing; verb rename = removed + added (fail closed: grants on the old verb do not follow).

Narrowing: the inverse. Equal: description/title/examples/source/since only.

The diff function is TS-only tooling; natives verify the signed `EvolutionRecord`, they do not recompute it (their job is cheap checking of signatures and digests, section 9). A property test checks diff soundness against a brute-force oracle: for random defs d and random mutations m, if `diff(d, m(d))` is `narrow` or `equal` then on random call samples `conform(m(d), x) = ok` implies `conform(d, x) = ok` and `FloorDecision` does not rise.

## 8. Policy authoring against traits and params

### 8.1 Surface

Goal IR gains two generalizations (goal-to-decision.md section 3.1): (i) `Grant.verb` becomes a `VerbSel` and `Prohibit`/`Bound` selectors accept traits; (ii) `Param` terms can be addressed by ROLE instead of a path.

```
VerbSel  := Verb(verb) | Class(all_of: TraitId[], none_of?: TraitId[])    // none_of only on Prohibit/Bound, never on a Grant (T7)
ProhTarget := verb | effect cls | Trait(id)                                // adds Trait
Sel (bound)   := gids | effect | Trait(id)
Term         := Param(path) | ParamRole(role) | Lit | HistAgg
```
Compile-time resolution (the proved compiler, pinned ontology digest = the pack root): `Class(all_of)` expands to the explicit list of verbs in the pinned pack whose effective trait closure contains all of them; `ParamRole(r)` expands, per selected verb, to that verb's unique param with role r; a verb that has no such param, or two, is DROPPED from the grant and listed in the compile report (fail closed, shown on the card). Money comparisons keep the existing typing rule (equal currency, no implicit FX).

Example: "allow any money-moving action under $200/day on these merchants":
```
allow Class(money_moving)
  where ParamRole(money.amount) <= 20000 USD  and  ParamRole(party.payee) in ["m_acme","m_globex"]
  bound sum(ParamRole(money.amount)) over Class(money_moving) <= 20000 USD per sliding(86_400_000)
```
lowers to one LPred per matching verb in the pinned pack (`stripe.charge.create`, `stripe.transfer.create`, `paypal.payout.create`, ...), each with its own path (`amount`, `amount_cents`, `value`), plus one shared bound over the union of their gids. The pinned pack root is in the goal's `ontDigest`, so the grant cannot grow to cover a verb added later (T6b). A prohibition `prohibit Trait(destructive) where true` floats: it covers the verb added next month.

### 8.2 Rules 20, 21, 22

- Rule 20 (units): schema units now come from `ParamDef.unit` (no second declaration). `decideUnits` is unchanged; the Goal compiler's ParamRole expansion carries the unit tag, so `money.amount` params of different currencies in one class selection produce one grant clause per currency (never a silent comparison).
- Rule 21 (tighten): `tighten[]` conditions may reference `trait(t)` of the verb (a plain boolean from the signed schema, not model-derived). Typing is unchanged: model-derived paths stay forbidden in `grants[].where`.
- Rule 22 (`traits`, new, normative): the verifier computes `eff` for the action's verb from the signed schema (materialized floors + trait ids; checks that materialized `⊒` the recomputed floor of the carried trait ids using the embedded core-trait table, else `schema_floor_forged`), then runs `FloorDecision` against the stored grant and the call context. Reported in `decideIntentV2` alongside `units` and `tighten`. Output is `allow | escalate | deny` and it is met into the rest. Failing rule 22 needs no model.
- Parameter-level traits feed provenance: a param with tag `free_text_outbound` or role `code.command` gets a default `provenance_min` of `tool`; critical roles default `critical_tainted: question_typed` exactly as param-provenance.ts:63 already defines for `critical`.

### 8.3 Proof obligations tied to policy

G-A1: for every pack, grant and call, `Dec` computed with traits equals `Dec` computed without traits meet FloorDecision (definitional; checked by differential test of TS vs extracted Dafny). G-A2: T6 registry-growth property test (random packs, random added defs, random trait-selector policies): decisions on old actions never rise; prohibit coverage never shrinks. G-A3: inheritance property test: a randomly generated new def tagged with trait t, under any random policy built from `Class(...)`/`Trait(...)` selectors, has `Dec` no more permissive than the same def under the policy restricted to t's floor. G-A4: compiler soundness for `Class` expansion (the extracted compiler's verb list equals the oracle's set comprehension) reusing the T1/T5 machinery of goal-to-decision.md.

## 9. Cross-language

Scope of the native port (9 languages: Go, Rust, Python, Ruby, PHP, Java, Kotlin, .NET, Swift; the C less verifier stays out, it does not parse schemas): the small, deterministic, security-relevant core only. Importers, linter, suggestion, semantic diff computation, builders, CLI and the NL layer are TypeScript-only tooling.

| Function | In natives? | Notes |
|---|---|---|
| Strict ActionDef/Pack parse (closed members, bounds) | yes | same limits as schema (`MAX_*`) |
| `normalize` + `defDigest` + pack Merkle root + inclusion proof verify | yes | digest equality is the interoperability contract |
| Trait registry load (core table embedded + custom traits from the signed doc), cycle/extends checks | yes | core table is a data file with its own digest |
| `expand(traits) -> Profile`, `eff`, `FloorDecision` (rule 22) | yes | integers and sets only |
| `conformAction` with new param types/formats/roles | yes (extends existing) | |
| Pack signature verify (suite from pinned key) | yes | existing sig code |
| EvolutionRecord signature + chain check, pin comparison (section 7.2) | yes | |
| Semantic diff computation, suggestion, linter | no | TS tooling |

Shared vectors: `packages/pca-conformance/vectors/actions/*.json`, one JSON per case `{id, kind: "digest"|"expand"|"floor"|"conform"|"pack"|"pin", input, expect}`, produced by a deterministic generator (seeded; the `calendar-gen-NNN` goal vectors are the model) plus hand-written adversarial cases (trait cycle, duplicate trait, custom trait weakening, forged floors, unknown member, lone surrogate, huge pack, shard mismatch, replayed old pack, evolution chain gap, widen without approval). Each native has a runner (`pca-conformance/runners/actions` per language) that fails on any differing digest or decision. TS, Go, Rust, Python are required for merge; the other five join the matrix in the same track and are required for release.

Python note: python-pca embeds the schema logic in `intent_v2.py`; the actions port is a separate module `atlas_pca/actions.py` so the intent file does not grow.

## 10. Migration (0.5 may break)

| Today | Becomes | Mechanism |
|---|---|---|
| `ActionSchema` (verbs, params, units) | `ActionSchema` v2: same wire, plus normative `effects`, `traits`, `def` (digest), materialized `floors`; reserved `effects/harm/world/state` become `effects` (normative) and `harm/world/state` stay reserved | `v: 2` accepted alongside `v: 1`; v1 verbs get `traits: [pca.unreviewed]` semantics at load (fail closed) unless a pack supplies the def |
| `catalog.ts` `ActionSpec`, `BUILTIN_ACTIONS`, `defineAction`, `buildCatalog`, `extendCatalog`, `catalogDigest`, `assertCatalogPinned` | `defineActions`, `Pack`, `packDigest`, `pinPack`; `extendCatalog`'s no-downgrade rule becomes `diff` classified `equal|narrow` only | a `fromCatalog(specs)` shim converts and sets `review.state: authored`, reversibility from the spec, blast via nearest radius, `amountField` to `money.amount` role; deprecated for one release |
| `catalogRisk`, `toolCallRisk(amountField)` | `riskOf(def, params, grant)` | one function; old names re-export with a warning |
| `facade.compilePolicy` `permissions: {stripe: ['refund']}` | resolves `stripe.refund` via aliases to a def in the default pack; `$` limits bind to the `money.amount` role param | the 21 built-in entries become hand-reviewed defs in the `core` pack, with the inconsistencies in section 1 resolved explicitly in review |
| Ontologies `ontologies/*.ts` | generated `toOntology(pack)`; aliases/templates remain in the NL layer, pointing at pack verbs | `OntVerb.effect` becomes derived (`effectClass`) |
| `reversible|costly|irreversible` (operations.ts) | `reversible|rate_limited|irreversible` | rename, accept `costly` on input for one release |
| `pca schema *` | `pca actions *` | alias then remove |
| `ToolActionMap` hand functions | generated by `operationOf` from bindings | `authorizeToolCall` accepts either; the generated map is the default |
| Grants | optional `actions` pin block; grants without it are unpinned and act as `on_new_action: deny` over the verbs they name | |
| Natives | add actions module per language | section 9 |

Docs: `docs/pca/migration.md` and the 0.5 upgrade note get an internal section first; public docs only after the owner decides what to publish.

## 11. Built-in catalog packs

### 11.1 Targets

Today: 21 catalog entries. Target for the 0.5 line: >= 2,500 reviewed (`confirmed`) defs across the packs below (~100x), with a generated-but-`unreviewed` long tail >= 10,000 available as opt-in shards. Counts are estimates (`~`) from memory of the public specs; the generator output replaces them.

| Pack | Source | Licence note (verify before shipping; recorded in the pack) | ~defs |
|---|---|---|---|
| `core` (fs, shell/exec, http generic, browser, process, env, clipboard) | hand-written, in-house | ours | ~120 |
| `db` (Postgres, MySQL, SQLite, Mongo, Redis: query classes, DDL, DML, admin) | hand-written from public docs, classes not APIs | ours | ~150 |
| `stripe` | Stripe OpenAPI (public repo) | repo licence permits use; keep names/params only | ~550 |
| `payments-rails` (ACH/NACHA, SEPA, FedNow/RTP, wires, card network refunds/chargebacks, PayPal, Adyen) | hand-written from standards + vendor specs | standards facts only | ~200 |
| `github` | GitHub REST OpenAPI description (public repo) | MIT | ~1,000 |
| `gitlab` | GitLab OpenAPI/REST docs | MIT (CE) | ~1,200 |
| `jira`, `confluence`, `linear`, `notion`, `asana`, `trello` | Atlassian published OpenAPI; Linear public GraphQL schema; Notion/Asana published specs or docs | per-vendor terms: record each; where terms forbid redistribution of the spec, ship only our own names/params/traits derived by the generator and keep `source.spec_digest` | ~900 |
| `slack`, `discord`, `teams` | published method lists / OpenAPI | per vendor | ~450 |
| `google-workspace` (Gmail, Drive, Docs, Sheets, Calendar, Admin SDK, Chat, Meet) | Google discovery documents | Apache-2.0 / CC-BY per document; record | ~900 |
| `m365` (Graph: mail, calendar, files, teams, users, groups, intune subset) | Microsoft Graph OpenAPI metadata | MIT | ~1,500 curated of ~4,500 |
| `aws-core` (S3, EC2, IAM, STS, Lambda, RDS, KMS, SecretsManager, SES, SNS, SQS, DynamoDB, CloudFormation, Route53, ECR/ECS/EKS) | botocore service models | Apache-2.0 | ~1,800 (aws-all ~17,000 as opt-in shards) |
| `gcp-core` | Google discovery + API protos | Apache-2.0 | ~1,200 |
| `azure-core` | Azure REST API specs | MIT | ~1,200 |
| `k8s` | Kubernetes OpenAPI | Apache-2.0 | ~700 |
| `terraform` | provider schemas: create/update/destroy per resource type, generic plan/apply/destroy | MPL-2.0 (schemas from `terraform providers schema -json`) | ~600 for major providers |
| `salesforce`, `hubspot`, `zendesk`, `intercom`, `shopify` (Admin GraphQL), `twilio`, `sendgrid`, `mailgun`, `brevo` | published specs | per-vendor; record | ~2,000 |
| `travel` (Amadeus, Duffel, Sabre-style booking/cancel/modify, loyalty, payments) | published specs + hand-written | per-vendor | ~150 |
| `identity` (Atlas's own BAPI/FAPI, SCIM, OIDC admin) | our OpenAPI | ours | ~400 |

### 11.2 Generation pipeline

`scripts/actions-packs/<pack>/gen.mjs`: fetch is out-of-band (a pinned URL + sha256 in `source.json`; the generator refuses on digest mismatch), then `import -> suggest -> emit draft pack -> review queue`. Output is deterministic and committed as `packs/<ns>/<version>/defs.jsonl` plus `pack.json`. Every pack records `source.uri`, `source.spec_digest`, `source.licence`, `licence_notes`, and `generated_by` (generator + rules digest). A `LICENCES.md` ledger lists, per pack, whether redistribution of derived data is permitted; a pack whose terms forbid it ships generator + digest only (users run `pca actions import` themselves) and our reviewed trait annotations as a separate overlay file (`overlay.jsonl`: `{verb, traits, roles, dismissed}`), which are our own facts. Review is by trait-priority: `money_moving`, `privilege_change`, `code_execution`, `destructive`, `external_communication` suspects first, from the suggestion output; low-risk reads are bulk-confirmed with a sampled audit (a 5 percent random sample of each batch is fully reviewed; any miss fails the batch). Versioning: semver; the pack version bumps with spec digest; every release carries evolution records (section 7). Pin the spec digest in the pack, not just the URL.

### 11.3 Quality gates per pack

Lint clean under `--strict`; 100 percent of money_moving / privilege_change / code_execution defs have a human `confirmed` attestation; sample-audit pass; golden-file test of generator output; size limit per shard (<= 1 MB), Merkle shard proofs verified; licence ledger entry present.

## 12. Build tracks

Seven tracks, each one-agent buildable, verification only on GitHub Actions (no builds or test runs on a developer Mac; each track pushes a `ci/<track>` branch and the workflow named below is the proof). Order and dependencies at the end of the table.

| Track | Scope | Main files | DoD | CI must prove | Depends on |
|---|---|---|---|---|---|
| A1 Core model + trait algebra + proofs | `@atlasauth/pca-actions` package: ActionDef/Pack types + strict validator, normalize + `defDigest` + pack Merkle, trait registry + 22 core traits + roles/effects tables, `expand/eff/FloorDecision`, derivations (`toSchemaVerb`, `riskOf`, `operationOf`, `toOntology`, `cardOf`), ActionSchema v2 (traits/effects/def/floors normative) in `pca` | packages/pca-actions/src/{def,validate,digest,traits,core-traits,roles,derive,card}.ts; packages/pca/src/action-schema.ts (v2); formal/dafny/TraitExpand.dfy; formal/intent/lean/PcaIntent/TraitAlg.lean; packages/pca-verified-core (extraction); docs/pca/security/trusted-base.md row | T1, T2, T3, T5 mechanized (Lean + Dafny 0 assume/axiom); extraction `--check` byte-identical; property tests T2/T3/T4 (fast-check, fixed seeds, >= 10^5 cases); canonical digest vectors generated | Dafny + Lean jobs, vitest-equivalent unit job on GitHub runners, mutation job on `traits.ts` and `digest.ts` (all survivors killed or ledgered) | none (foundation; publishes types first so A2-A5 can start in parallel) |
| A2 Authoring, linter, CLI | YAML/JSON loader with shorthands, TS builder (generated from the JSON schema), `pca actions init|lint|test|explain|build|sign|publish`, 24 lint rules + fixtures, SARIF, SDK `create-pca-app` template `actions`, `pca schema` aliases | packages/pca-actions/src/{author,lint,test-runner}.ts; packages/pca-cli/src/{actions,cli}.ts; packages/create-pca-app/templates/actions | hello world in the README runs end to end in a CI job from an empty dir; every lint rule has positive and negative fixtures; builder == YAML == JSON digest for 200 generated defs; `explain` card golden files | CLI e2e job (empty dir to signed pack), lint fixture job, template build job | A1 types (can start against the published interface) |
| A3 Importers + suggestion + review | importers: MCP, OpenAPI (replacing `draftSchemaFromOpenApi`), GraphQL, gRPC/proto, AsyncAPI, JSON Schema; `suggest-rules.json` + labeled corpus + `eval-suggest`; model-assist adapter (pinned model, closed vocabulary, union-only); `confirm` flow and `ReviewAttestation`; the `unreviewed` default | packages/pca-actions/src/import/*.ts; packages/pca-actions/corpus/; packages/pca-mcp/src/schema.ts (delegate); packages/pca/src/action-schema.ts (importers removed, re-export shim) | every importer output is `unreviewed` or `authored` (property test); suggestions only add (property test); recall floors recorded for 5 core traits on >= 1,500 labeled ops with Clopper-Pearson bounds; ref-bomb and size-limit tests pass for each importer; unreviewed def never gets a confirmed floor without a valid attestation | importer unit + fuzz jobs, `eval-suggest` job publishing the table as an artifact | A1 |
| A4 Registry + evolution + pinning | signed packs, shards, hash chain, transparency-log append (pca-scitt), `EvolutionRecord`, semantic `diff` with brute-force soundness oracle, grant pin block (`actions`) in envelope, verifier rule 22 and `def_changed` in TS, re-approval wire | packages/pca-actions/src/{pack,registry,diff,evolve}.ts; packages/pca/src/{envelope,decision,intent-v2}.ts; packages/pca-scitt; docs/pca/security/security-contract.md (C-54, C-55) | T6 mechanized for the extracted selector semantics + property-tested; diff soundness oracle passes >= 10^5 random mutations; rollback/replay/chain-gap/forged-floor tests (negative controls) all rejected; rule 22 registered in security-contract with trace rows | property/oracle job, security-contract traceability check, negative-control job | A1 |
| A5 Policy integration | Goal IR: `VerbSel`/`Class`, `ProhTarget.Trait`, `Sel.Trait`, `ParamRole`, T7 typing rule; Dafny compiler update + regeneration; `facade.compilePolicy` rewritten over defs; NL grounding on pack verbs/aliases; rules 20/21/22 wiring; policy-card rendering with trait phrases; migration shims (`fromCatalog`, ontologies generated); resolve the section 1 inconsistencies in the `core` pack | formal/dafny/Goal*.dfy; packages/pca-goal/src/{ir,ontology,compiler,card,review}.ts; packages/pca/src/{facade,nl,catalog,catalog-risk,decision}.ts; packages/pca-mcp{,-rs}/src | G-A1..G-A4 pass; the money-moving $200/day example from section 8 compiles, runs, and its compiled form matches a golden file; old tests migrated, 0 skipped; T6 end-to-end (growth) property test green; card golden files for every core trait | Dafny (Goal*), goal differential vectors across TS/Go/Java/Python/C#, full vitest-equivalent job, mutation job on the compiler | A1; A4 for the pin block types (interfaces first) |
| A6 Catalog packs + generation pipeline | generator framework, licence ledger, review-queue tool, packs in waves: wave 1 `core`, `db`, `stripe`, `payments-rails`, `github`, `gitlab`, `slack`, `google-workspace`; wave 2 `m365`, `aws-core`, `gcp-core`, `azure-core`, `k8s`, `terraform`; wave 3 CRM/support/comms/travel/identity; overlay files for no-redistribution specs | scripts/actions-packs/**; packages/pca-actions/packs/**; LICENCES.md; packages/pca-actions/src/review-queue.ts | wave 1 >= 1,200 defs with 100 percent of high-risk traits human-confirmed; wave 2 >= 1,300; every pack lint-clean `--strict`; licence ledger complete; sample audit passes; regenerating from pinned spec digests is byte-identical | pack-build job (matrix by pack), determinism job (two runs equal), licence-ledger check job, size/shard job | A1 for types; A3 for importers (wave 1 `core`/`db` hand packs can start immediately) |
| A7 Natives + shared vectors | actions module in Go, Rust, Python (tier 1), then Ruby, PHP, Java, Kotlin, .NET, Swift (tier 2): strict parse, normalize/digest, Merkle root and inclusion, trait registry load, `expand/eff`, rule 22 `FloorDecision`, pack/evolution signature checks, pin compare; vector generator and per-language runners; zkVM guest note (rule 22 stays out of the guest until the zkVM track asks for it) | sdks/*/ (new files per language, none edited beyond export lists); packages/pca-conformance/vectors/actions/; packages/pca-conformance/runners/actions/; docs/pca/security/traceability row | all 9 produce identical digests and decisions on the full vector set (>= 5,000 generated + 60 adversarial); mutation on each native's expand/floor with differential oracles ported (the k042 recipe); tier 1 required to merge, tier 2 required to release | the existing per-language CI matrix plus an `actions-vectors` job in all nine; a cross-language digest-equality job | A1 (vector format and digests), A4 for rule 22 + pin semantics (can build parse/digest/expand first) |

Order: A1 first, and its interfaces are published in the first hour of the track so A2, A3, A4, A6 (hand packs) start immediately; A5 starts when A1's types and A4's envelope types are in; A7 starts with parse/digest/expand as soon as A1's vector format lands and adds rule 22 when A4 lands. One integration and one deploy at the end (repo convention).

## 13. Risks and open questions

- Tagging correctness is human. The algebra makes errors one-directional and repairable, but a missed `money_moving` on a generated action is a real hole until reviewed; the `unreviewed` floor is the control, and the review queue's priority order and sample audit are the process. Publish precision/recall, not guarantees.
- Pack size. 17,000 AWS ops cannot ride in a grant or a verifier config; sharding with Merkle inclusion proofs is required, not optional (section 2.3).
- Licences. Some specs may not permit redistribution of derived data. The overlay model keeps our reviewed annotations separate from vendor text; legal review of `LICENCES.md` is a release gate.
- Native footprint. Rule 22 adds a new check to nine verifiers and (eventually) the zkVM guest; the check is integer-and-set arithmetic by design, so the port is small, but it must not slip behind TS (tier-2 languages are release-blocking).
- Role/trait vocabulary governance. Core vocabularies change through the same evolution rules as packs; who owns the `reviewer` and registry keys is an operations decision to make before the first publish.
- `pca actions` vs the existing `pca schema` users: one release alias, then removal.
- The 4-level ontology effect class is derived; any ontology author who needs a different class than the derivation gives must raise the def, not override it (no override exists by design).

## 14. Track A1 build notes (what exists, and the decisions that refine the text above)

Package `packages/pca-actions` (`@atlasauth/pca-actions`, private, experimental). Source files: `def.ts` (vocabularies, limits, types, `ActionKitError`), `traits.ts` (Profile lattice, registry, closure, floors, `floorDecision`), `core-traits.ts` (the 22 traits, implication tables, role and tag sensitivity floors), `idpattern.ts`, `normalize.ts`, `validate.ts`, `effective.ts` (T(d), decl, eff, clamps, prules), `digest.ts`, `derive.ts` (schema v2, operation, risk, predicates, ontology, card, escalation, MCP annotations, document integrity), `compat.ts` (migration shims), `builtin.ts` (the 21 reviewed built-ins and the settled disagreements), `selector.ts` (T6/T7 semantics). Schema v2 lives in `packages/pca/src/action-schema.ts`. Proofs: `formal/intent/lean/PcaIntent/TraitAlg.lean`, `formal/dafny/TraitExpand.dfy`. Vectors: `packages/pca-conformance/vectors/actions/` (generator `packages/pca-actions/test/vectors-gen.ts`). CI: `.github/workflows/action-kit.yml`.

Decisions (each is normative for the other tracks):
- **Digest.** `defDigest` covers the normalized def without `review`, `examples`, `source` and `since` (a review attestation signs the digest, so the review cannot be inside it; provenance and tests do not define the action). `title` and `description` are inside (the policy card is derived from the title). Domain `atlas-pca/action-def/v1`; the trait registry digest (`traitsDigest`) and the implication-table digest (`tablesDigest`) are separate and pinned by a pack. Pack root: RFC 6962 Merkle over the sorted def digests, each leaf `{d: "atlas-pca/action-pack/v1", def: digest}`.
- **Aliases** have 1..6 segments (a verb has 2..6): the NL layer's short ids (`refund`) are aliases.
- **Params.** Dotted names (up to three segments) are flattened keys; the caller presents `flattenParams(body)`. A name may not be both a value and the parent of another. `semantic` becomes the role (or `generic.<type>`); the schema decl also carries `role`, `format`, `tags`, `provenance_min`. v2 types add `datetime` (RFC 3339 UTC, `Z`), `duration` (integer milliseconds) and `object_ref`. Formats are syntactic checks (email, url, uri_https, uuid, iban with mod 97, phone_e164, cidr, iso_country, iso_currency, semver, sha256, `id:<type>`).
- **Trait set T(d)** = declared traits, plus traits implied by effects, param tags and roles, by `resource.scope != one` and unbounded arrays (`pca.bulk`), by a worst-case reversibility of `irreversible` (`pca.irreversible`; a def with no declared reversibility is irreversible unless read-only), plus `pca.unreviewed` unless `review.state` is `authored` or `confirmed` with `attestationVerified(def) === true` (absent callback: a confirmed def is still unreviewed; the attestation signature check is the registry layer's).
- **decl(d)** = reversibility (conservative over a value-dependent map), blast ppm (radius default, `ppm` raises only; no `blast` means the scope's radius), declared context keys, and risk 0 for a read, 1 for any other effect, 2 when a parameter is critical; escalation tier, caveats and prules come only from traits.
- **`param_rules`** is not a separate TraitDef member: a trait's structural requirements are the `prules` of its floor.
- **Floor decision inputs.** `GrantFacts = {caveats, max_esc, preauth_esc}`: a tier above `max_esc` denies, a tier above `preauth_esc` (or a missing caveat or context key) escalates.
- **Closure** is eight rounds of one-step implication, which equals the transitive closure for every registry the loader accepts (depth <= 8); the Dafny model and a property test pin this.
- **Schema v2** `traits` are T(d); `floors` are the full effective profile (declared joined with the trait floors). `schemaVerbFloorError` recomputes implied traits from the verb's own facts (all but the resource scope and the review state, which only add) and checks `floors >= F(closure(traits))` and `floors.rev >= worst declared reversibility`.
- **Built-ins.** `stripe.refund` and `stripe.charge` are `irreversible` (the stricter of the old catalog and ontology classes); `slack.post_message` is declared `irreversible` (the send floor); `http.post` is an `update` with the network-egress trait (a generic POST has no recipient parameter).

Not done in A1 (owned by later tracks or open): extraction of `TraitExpand` into `packages/pca-verified-core/generated` (the CI job produces the JavaScript as an artifact; committing it and calling it from `traits.ts` follows the first green proof run); wiring rule 22 into `decideIntentV2`; rewriting `catalog.ts`, `facade.ts` and the ontologies over definitions; the native ports.

## 15. Track A2 build notes (authoring, linter, CLI)

Files: `packages/pca-actions/src/{author,lint,test-runner,explain,defdiff,build,import}.ts`, `packages/pca-cli/src/actions.ts` (commands) and `cli.ts` (dispatch), `packages/create-pca-app/templates/actions`. Tests: `test/{author,lint,tooling}.test.ts`, `test/lint-fixtures.ts`, `test/golden/explain-builtin.txt`, `packages/pca-cli/src/actions.test.ts`. CI: the `authoring` job of `action-kit.yml` and `action-kit-cli-e2e.sh`. Contracts C-320..C-325, threats T-420..T-425.

Decisions that refine the text above:
- **Full form vs authoring form.** An entry with a `kind` member is a full ActionDef and is taken exactly as written (no shorthands, no defaults, no title or idempotency additions); an entry without one is an authoring entry. A def therefore round-trips through JSON and YAML to the same digest, and the builder, the YAML shorthands and the full JSON agree for 200 generated actions.
- **Defaults.** The title defaults to the action word and its nouns ("Send invoice"); the idempotency key (`idempotency_key`, 64 bytes, key_param) is added for `send`, `pay`, `create`, `provision` and `publish` unless declared (a note, `LN-001`, not a finding); the file-level `since` is the default for every action in the file; `money(...)` defaults `provenance_min: first_party`. A resource shorthand is scope `one` for a prefix or exact id, `set` for `type:*`, `tenant` for a bare type.
- **YAML profile.** YAML 1.2 core schema, no aliases or anchors, no merge keys, unique keys, no unknown tags, no warnings, 1 MiB, no `__proto__` anywhere; then the strict JSON profile.
- **Lint.** `LD-000` (not a rule of the list) reports a def that does not pass `validateDef`; `LN-001` reports loader notes; the 24 rules are LD-001..014 and LW-001..010 as in section 6.2. Details the text leaves open: LD-005 fires when a PII-bearing action has a send or export side effect, or a send/export verb name, that its effects do not declare; LD-012 reports only the param rules the effective traits require and excludes the three that LD-002, LD-003 and LD-004 already report; LD-013 treats `context: sandbox_attested` as "read-only enforced"; LW-006 is the unbounded array that no required rule already catches. The ordered list is digested (`lintRulesDigest`) and pinned by a test. The CLI adds three findings outside that list (track K9, so the pinned digest is unchanged): `LP-001` (warning) a beta or stable pack whose `pca.config.json` pins no builder identity (`provenance: {oidc_issuer, identity | identity_prefix, builder_id}`), `LT-000` (error) a configured trace rule that does not compile, `LT-001` (warning) the lethal trifecta: an untrusted-content read and a private-data read can both reach a send that no trace rule cuts off.
- **Examples.** `under` is `{allow: selector | [selector]}` with `selector = {trait | verb, where?, caveats?, context?}`; `where` keys are parameter names (or `<param>.domain` for an email) with a value list, or `{min, max}`. A matching selector pre-authorizes the whole floor except the caveats it names (plus the one a `where` on a recipient, amount, count or id parameter implies) and the context keys it lists; the idempotency key present in the call supplies the `idempotency` context. This is a stand-in for the Goal compiler (track A5): it can only pre-authorize, and it does not run the compiled policy.
- **Pack.** `build` emits the pack of section 7.1 with `prev: null` and no evolution records; `sign` signs the whole canonical pack under the domain `atlas-pca/action-pack/v1\0` (Ed25519; a PQ suite follows with the registry track). Signed packs, shards, the hash chain and the log append remain track A4; `signPack`/`verifyPack` here are the author-side pair and A4 may replace them.
- **Diff.** `diffDefs`/`diffPacks` implement the aspects of section 7.3 for the author CLI. Soundness is property-tested against a brute-force oracle for ranges and optional parameters; the registry track owns the signed, pinned form and the full oracle.
- **Importers** are MCP, OpenAPI 3 and a JSON Schema; GraphQL, gRPC and AsyncAPI register in `IMPORTERS` (track A3 replaces these three with the suggestion-aware versions). All output is `unreviewed`.
- **`pca schema`** is kept for one release as a deprecated command (it prints a notice); the old draft-schema flow and the new definition flow differ in kind, so the commands are not byte-for-byte aliases.
- **Packaging.** `@atlasauth/pca-actions` is no longer private (the CLI depends on it) and depends on `yaml`.

Not done in A2: `confirm` and `eval-suggest` (track A3), the Goal-compiler path of `test` (track A5), transparency-log append and the pack registry endpoint of `publish` (track A4; `publish` writes the discovery file and anchors the schema through the existing intent-schema endpoint), Stryker on the lint module.

## 16. Track A4 build notes (registry, evolution, pinning, rule 22 in TypeScript)
## 15. Track A4 build notes (registry, evolution, pinning, rule 22 in TypeScript)

Code: `packages/pca-actions/src/{diff,evolve,pack,registry,rule22,transparency}.ts` and `packages/pca/src/action-pin.ts` (the part the verifier needs, because `pca` cannot import `pca-actions`). Wire changes: `envelope.actions` (pin block), `IntentV2Context.{rule22,call_context,actions}`, checks `pin` and `traits`. Vectors: kinds `rule22_schema`, `rule22`, `pack_verify`, `evolution_verify`, `reapproval_verify`, `pin`, `pack_proof_verify`, `tracker` (generator `packages/pca-actions/test/vectors-registry.ts`). Contract: C-360..C-366, T-460..T-466.

Decisions (normative for A5 and A7):
- **Rule 22 is injected.** `pca` cannot depend on `pca-actions` (the reverse dependency exists), so the verifier takes a `Rule22Engine {schemaError, decide}` in its context (`RULE22_ENGINE` is the TypeScript one). A version 2 schema with no engine is refused, so a forgotten wiring fails closed. Natives implement the engine directly (they are not layered this way) from the `rule22_schema` and `rule22` vectors.
- **Grant facts for rule 22.** `max_esc` (default 3) and `preauth_esc` (default 0) and `caveats` live in `envelope.actions`; envelope caveats whose `type` is a caveat kind count too. The call context is `ctx.call_context`, verifier state only. `escalate` is reported as a failing check whose reason starts `escalate:`, so the existing decision fold turns it into an escalation.
- **Check names.** `traits` is reported iff the accepted schema is version 2; `pin` iff the envelope carries `actions`. A PCActn with neither verifies byte-identically to before. A grant with `actions` makes `authorize` run the v2 pipeline (like `units`/`tighten`).
- **Semantic diff.** `equal`/`narrow` means: the call set accepted by the new definition is contained in the old one's (closed world, required members, per-type domains), the effective profile did not fall, and no other modelled dimension widened. Differences from section 7.3: a new REQUIRED parameter is `incomparable` (not `narrow`+breaking), because old callers and new callers accept different call sets and the oracle (a call accepted by the new definition must be accepted by the old one) would otherwise fail; a wider resource scope is `incomparable` (it also implies `pca.bulk`); a changed role, unit, default or binding is `incomparable`; new aliases are `widen` (they extend what natural language reaches), removed ones `narrow`; title, description and `compensates` are `equal`. `incomparable` counts as `widen` for pins.
- **Evolution records** are `{v, kind, ns, verb, from, to, class, reasons, sig}` signed under `atlas-pca/action-evolution/v1\0` by the registry key; the diff digest a re-approval signs is the hash of `{ns, verb, from, to, class, reasons}`. A pack's `evolution` must equal the computed change (`verifyUpgrade`); a verifier that holds only records trusts the pinned registry key for the class.
- **Re-approval** is `{v, kind, grant, verb, diff, sig}` signed with the grant issuer's Ed25519 key under `atlas-pca/action-reapproval/v1\0`; `grant` is the root capability's content address.
- **Packs.** `rules_digest` is the digest of the param-rule, caveat and context vocabularies; shards are grouped by the first segment of `resource.type` (`shardDefs`) and referenced by `{name, digest, uri}`; the root covers all shards. Versions are plain MAJOR.MINOR.PATCH. The tracker trusts the first pack of a namespace.
- **Transparency.** `appendPackToLog` signs `{ns, version, digest, root, prev}` as a COSE statement and registers it in a `pca-scitt` log; `verifyPackLogEntry` checks the statement is the pack's own, signed by the registry, and the receipt by the log.
- **Not done here.** Extracting the diff or the pin decision into Dafny (the diff is TypeScript-only tooling by design; the pin decision is covered by property tests and vectors); the TEE/zkVM guest does not run rule 22; the Goal compiler's use of rule 22 and `ProhTarget.Trait` is A5.

## 17. Track A5 build notes (policy integration)
## 15. Track A5 build notes (policy integration)

- **Facade and catalog.** `catalog.ts` `BUILTIN_ACTIONS` is `catalog-builtin.generated.ts`, written by `packages/pca-actions/scripts/gen-catalog.ts` from `BUILTIN_DEFS` via `specOfDef` (CI `--check`). The built-in defs now declare the old blast presets exactly (`blastExactOfFloat`), so no built-in is priced below the old catalog. `ActionSpec` gains `aliases` and `traits`; `Catalog.resolve` maps an alias of exactly one action of a connector.
- **Ontologies.** `domain.ts` holds `DOMAIN_DEFS` and `DOMAIN_VERBS` (NL short id, def, NL resource type, surfaced params); `domainVerbs` derives the ontology `verbs` and `aliases`. mail.send, mail.forward, repo.release and data.export declare `rate_limited` so the derived class stays `external_send`; their effective floors still apply.
- **Selectors.** `packages/pca-goal/src/selectors.ts` mirrors `formal/dafny/GoalSelect.dfy`. Decisions beyond section 8: expanded ids are `<gid>.<verb>` (ids are `[0-9A-Za-z_]`); a prohibition whose role term is unresolved for a verb applies unconditionally; a bound whose role value has different paths per verb but one type reads the act key `@<role>` (supplied by `withRoleParams`, caller-sent `@` keys are stripped); a bound that cannot resolve is a type error; the pin is `selCatalogDigest`.
- **Not done / open.** `GoalSelect.dfy` and `TraitExpand.dfy` are unverified until the first CI run. The extracted JS of GoalSelect is not committed or called from TS (the TS expansion is tied to the model by tests); a differential harness against the extracted code follows the first green proof run. Rule 22 wiring in `decideIntentV2` and the MCP packages (`pca-mcp`, `pca-mcp-rs` `toolCallRisk(amountField)`) are not changed.

## 16. Track act-zero build notes (unconfirmed means maximally dangerous)

Owner requirement: this is authorization, so a classifier miss must have no security effect by construction. Decisions:

- **The effective trait set is decided only by a signed confirmation.** `T(d)` is `hint(d)` (declared plus implied by the def's own facts) when a review attestation by a pinned `reviewer` key verifies over this def digest and an accepted registry digest, and `Top(R)` (every trait of the registry, custom traits included, hence `pca.unreviewed`) otherwise. Top rather than "all high-risk core traits" so that the decision for an unconfirmed def is at most the decision for EVERY confirmed version (a confirmed version may carry a custom trait with a floor above the core ones); the named high-risk traits are a subset. The implied traits of a confirmed def are a function of the signed def and only add.
- **Hint view.** `effective` also returns `hint` (declared plus implied), used by review, lint and authoring tests; never by enforcement. Lint rule LD-012, the example runner and the facade catalog generator read the hint view.
- **Authored no longer counts.** `review.state: authored` is unconfirmed. The attestation requires `state: confirmed`.
- **Schema.** A v2 verb carries `confirmation` (the attestation). Rule 22 verifies it against `ctx.reviewers`; a verb without a valid one must carry every trait of the document's registry (so a schema that claims fewer traits for an unconfirmed def is refused). The attestation binds the def digest AND the facts digest (`factsDigest`: the verb minus traits, floors, def and confirmation, hashed under `atlas-pca/action-verb-facts/v1`; the review message domain is `atlas-pca/action-review/v2`). The verifier recomputes the facts digest from the verb it is presented and accepts the confirmation only on an exact match, so editing a fact after confirmation or claiming another definition's digest is unconfirmed; the full ActionDef is not needed on the wire because everything the verb does not show is covered by the signed def digest.
- **Selectors.** Forbid and cap selectors match an unconfirmed action regardless of content (a carve-out would otherwise rescue it, since the top contains every trait); allow selectors never match one. In `pca-goal` the catalog marks an unconfirmed verb by `pca.unreviewed` in its closure; `GoalSelect.dfy` mirrors it (`FloatClassVerbs`, allow = class with `pca.unreviewed` added to `none_of`).
- **Pin and evolution.** `diffDefs`: `confirmation`, `effective.traits`, `effective.profile` dimensions. Confirmed to unconfirmed (a changed digest makes the attestation stale) is `narrow`; unconfirmed to confirmed is `widen` (principal re-approval) at a new digest. At the same digest a newly valid signed confirmation follows the pin: the verifier checks the signature itself against its own pins.
- **Built-ins.** Confirmed by `scripts/sign-builtins.ts` at release (key from the environment); `builtin-release.generated.ts` is a placeholder until then. The generated facade catalog uses the reviewed view of the built-ins.
- **Proofs.** `TraitAlg.lean` T8 and `TraitExpand.dfy` (`UnconfirmedIsTop`, `NoMachineInputLowers`, `UnconfirmedAboveEveryConfirmed`, `UnconfirmedFinalAntitone`, `UnconfirmedNeverAllowed`, `ProhibitCoversUnconfirmed`); not run on the Mac, the `lean` and `dafny` jobs run them.
- **K2.** The static analyzer reads verb and parameter shapes of defs and schemas only (no traits), so it needs no change.
- **Release step for the built-ins (owner action; no key lives in the repository).** 1. Choose the release reviewer key (an Ed25519 secret held outside the repository; it is pinned as `reviewer`, never as an importer or model key). 2. From the repo root: `PCA_RELEASE_REVIEW_KEY=<secret, base64url> pnpm --filter @atlasauth/pca-actions exec tsx scripts/sign-builtins.ts --sign --kid <kid>` writes `packages/pca-actions/src/builtin-release.generated.ts` (the public key as the pinned reviewer and one attestation per built-in verb). 3. Commit that file with the release. 4. The release pipeline runs `PCA_REQUIRE_BUILTIN_RELEASE=1 ... scripts/sign-builtins.ts --check`, which fails unless every built-in is attested and every attestation verifies (a changed built-in or trait registry makes it stale: sign again). Consumers that want the built-ins confirmed use `releasedBuiltinDefs()` with `builtinReviewOpts()`.

## 18. Hosted action registry, business rules, sync and starter packs

Goal: a platform (developers and non-developers) defines its own actions and configures PCA to its business on its Atlas instance: a per-instance registry of signed, versioned namespaces, business rules per action, a review workflow with passkey-held reviewer keys, sync from the sources the definitions were imported from, and starter packs. Shipped in 0.5.0. Public guide: `guides/define-your-own-actions.md`.

Code: `packages/pca-actions/src/{business-rules,hosted,sync,templates}.ts`; CLI `packages/pca-cli/src/actions.ts` (`cmdInit`, `cmdConfirm`, `cmdBuild`/`rulesDocOf`, `cmdPublish`/`publishToRegistry`, `cmdSync`) and `packages/pca-cli/github-action/action.yml`. The hosted registry, review workflow and "Custom actions" console are part of the Atlas service.

### 18.1 Data model

- **`BusinessRules`** (authoring form, per verb, the `rules:` member of an authoring entry; NOT part of `defDigest`; the loader returns it in `LoadResult.rules[verb]`). Closed members `amount`, `approval`, `scope`, `rate`, `hours`, `recipients`, `required`, `examples`; at least one rule besides `examples`. Money values: an integer is minor units (non-negative safe integer), a string is a decimal in major units (`^(0|[1-9]\d{0,14})(\.\d{1,6})?$`) with at most the amount parameter's exponent of decimals. `amount` and `approval.above` need exactly one integer parameter with role `money.amount` and a money unit; its currency is a literal or another parameter. Bounds: 1..32 currencies per map, 1..64 entries per list, `approvers` 1..16, `group` `[a-z][a-z0-9_]{0,63}`, `rate` 1..4 limits with `max` 1..1 000 000 and `per` `hour` | `day`, `by` `principal` (default) | `org`; `hours.days` distinct of `sun..sat`, `from`/`to` `HH:MM`, `tz` an IANA zone the runtime knows, `outside` `escalate` (default) | `deny`; `recipients` names a string parameter or an array/set of strings with `max_items <= 64`, with lowercase `domains` and/or `addresses`; `required` names existing parameters; at most 32 `examples` (`params`, `caller`, `at` RFC 3339 UTC `Z`, `recent` by rate index, `expect`). A malformed block is `ActionKitError('bad_rules')`.
- **`RulesDoc`** `{v: 1, kind: 'pca-action-rules', ns, rules: {verb: BusinessRules}, reviews?: {verb: RulesReview}}`. `rulesDocError` (closed members, ns equal to the pack's, every verb in the pack, no `LR-*` error) gates it. `pca actions build` writes it as `rules.json`, carrying only the reviews from `pca.rules-reviews.json` whose `def_digest` and `rules_digest` still match.
- **`RulesReview`** `{verb, def_digest, rules_digest, reviewer_kid, ts, sig}`: a reviewer's Ed25519 signature over `utf8("atlas-pca/action-rules-review/v1\0") || canonicalBytesStrict({verb, def_digest, rules_digest, reviewer_kid, ts})`. `rules_digest = hashCanonical({d: "atlas-pca/action-business-rules/v1", verb, rules})` with `examples` removed. `rulesReviewError(r, def, rules, pins)` is null iff the verb, the def digest and the rules digest match, the kid is pinned with role `reviewer`, `ts` lies in the key's validity, and the signature verifies. `pca actions confirm --yes` signs one for every confirmed verb that has rules.
- **`HostedVersion`** `{ns, version, digest, prev, pack: SignedActionPack, rules: RulesDoc, traits: TraitDef[], deprecated: string[], changes: HostedChange[]}`; `digest = hashCanonical({d: "atlas-pca/hosted-action-version/v1", pack, rules, traits, deprecated: sorted})`, `prev` the replaced version's digest (null for the first). `HostedChange {verb, class: DiffClass | added | removed | deprecated, reasons, rules?: {class, reasons}, reviewed?}`.
- **Storage.** A version row per `(instance, ns, version)` (status `active` | `staged` | superseded), one head per `(instance, ns)` `{active_version, active_digest, pinned}`, keys `{kid, pk, role: publisher | reviewer, reviewer_id?, not_before?, not_after?}` with `(instance, pk)` unique (one key material never holds two roles). The instance's own publisher key (kid `atlas-instance`) is derived from the root key per instance (`deriveInstanceKey(..., 'pca-action-publisher')`), never stored, pinned on first use and never revocable; customer publisher kids may not be `atlas-instance` or start with `rv_`. Reviewer keys (kid `rv_<reviewer id>`) are pinned only by the reviewer enrolment ceremony.

### 18.2 Compilation (`compileBusinessRules`)

Output `CompiledRules {v: 1, verb, rules_digest, def_digest, tighten: TightenRule[], accumulators: AccumulatorDecl[], clock_tz?, approval?: {approvers, group?}}`: only existing wire forms (rule 21 tighten rules over `action.params.*`, `subject.*`, `env.*`, and count accumulators whose pre-state is `env.acc.<id>`). Deterministic. Every signal is `escalate` or `deny`. A rule fires when its condition evaluates `true` OR `unknown` (`evaluateConditionTri` not `false`).

| Rule | Tighten rule id | Condition (fires when) | Signal |
|---|---|---|---|
| `amount.max.C` | `amount_max_c` | currency is C and amount > max | deny |
| `amount` (unlisted currency) | `amount_currency` | currency not in the listed set (literal: always, if unlisted) | deny |
| `approval.always` | `approval_always` | always | escalate |
| `approval.above.C` | `approval_above_c` | currency is C and amount > threshold | escalate |
| `approval` (unlisted currency) | `approval_currency` | currency not in the listed set | escalate |
| `scope[i]` | `scope_<i>` | `not (param eq ref subject.<caller>)` | deny |
| `rate[i]` | `rate_<i>` | `env.acc.rate_<i> >= max` | deny |
| `hours` | `hours` | not (day in days and from <= min < to); overnight window: the named day is the start day | `outside` |
| `recipients` | `recipients` | not every present entry matches `*@domain` or an address (lists: indexes `0..max_items-1`, index `max_items` absent) | deny |
| `required[i]` | `required_<i>` | parameter absent (strings: or empty) | deny |

Each `rate[i]` also emits the accumulator `{id: rate_<i>, agg: count, sel: {verbs: [verb]}, win: sliding <period ms>, key: null, domain_max: max, cap: max, holder: site_local, scope: by}`. `hours` sets `clock_tz`; the evaluator supplies `env.clock = {dow, min}` in that zone (absent when it cannot be computed). `approval` sets `CompiledRules.approval = {approvers: approvers ?? 1, group?}`.

`evaluateBusinessRules(c, {params, subject?, now, counts?, resource?})` is the meet of `allow` with every fired rule's signal; never throws (an exception is `deny`). A count that is absent or not a non-negative safe integer is not placed in `env.acc`, so its rule is unknown and fires. `verdict.approval` is set iff an `approval_*` rule escalated. `withBusinessRules(base, v) = meet(base, v.decision)`: rules never raise a decision. `explainBusinessRules` gives one plain sentence per rule; `lintBusinessRules` gives `LR-001` (malformed), `LR-002` (a contradiction: no listed currency the action uses, a ceiling below the parameter's minimum, an empty hours window), `LR-003` (dead or covered rules), `LR-004` (an example that does not decide as expected); `LR-*` sit outside `LINT_RULES`, so `lintRulesDigest` is unchanged.

`diffBusinessRules(def, prev, next)` classifies per rule kind (`eq`, `narrow`, `widen`, `incomparable`; mixed narrow and widen is incomparable): adding a rule narrows and dropping one widens; ceiling and threshold maps compare the currency sets (a new currency widens) and the shared amounts; `always` vs `above`, approver count (more narrows), group (any change incomparable); scope bindings and required fields (more narrows); rates per `(per, by)` by the lowest max (a removed limit widens); hours by the set of minutes of the week (a changed `tz` is incomparable; `deny` to `escalate` widens); recipients by allowed set (an address covered by an allowed domain counts as allowed; another parameter is incomparable).

### 18.3 The publish gate (`publishGate`)

Input: the active version (absent for the first publish), `pack`, `rules?`, `traits?`, the pinned publisher keys, the reviewer pins, `pin?`. Steps, in order:

1. `traits` must be a list; `registryOfTraits(traits)` (core extended by the custom traits) must load, else `bad_traits`.
2. `verifyPack(pack, publisherKeys, registry)` (signature under a pinned publisher key, Merkle root, every def valid), else `bad_pack`.
3. `pack.version` must be plain `MAJOR.MINOR.PATCH`, else `bad_version`; `pack.ns` must equal the active version's, else `ns_mismatch`; unless `pin`, the version must be above the active one, else `not_newer`.
4. `rules` (default the empty `RulesDoc`) must pass `rulesDocError`, else `bad_rules`.
5. Per def of the new pack: a verb new to the namespace, or one the active version deprecated, is `added` (`reviewed` when confirmed). Otherwise `diffDefs` runs with each side under its own registry and review options (a registry change shows as `effective.profile`); if any of the dimensions `confirmation`, `effective.traits`, `effective.profile` is `widen` or `incomparable`, the new def must be confirmed (a valid attestation by a pinned reviewer over this def), else the verb is blocked. Independently, when either side has rules, `diffBusinessRules` runs (an exception is `incomparable`); `widen` or `incomparable` needs `rulesReviewError(reviews[verb], newDef, newRules ?? {}, pins) === null` (removing all rules is reviewed as the empty block), else the verb is blocked. Rules are gated whatever the def's confirmation state.
6. Verbs of the active version absent from the new pack become `deprecated` (change class `deprecated`); earlier deprecations not re-added carry over.
7. Any blocked verb: `widen_unreviewed` with the sorted verbs, the reasons and the changes. Otherwise the `HostedVersion`.

Unconfirmed new or changed definitions are accepted: they are enforced as the top of the registry. API mapping: `widen_unreviewed` and `not_newer` are 409, the others 422; `error.meta = {reason_code, verbs?, changes?}`; a body above 8 MiB is 413. Storage (`publishVersion`): in one transaction, take `pg_advisory_xact_lock` on `pca-action-ns:<instance>:<ns>`, re-read the head `FOR UPDATE`, gate against it, refuse a version string already stored (409 `not_newer`), store; activate unless the head is pinned (then `staged`, gated against the pinned version). `pinNamespace` runs the same gate with `pin: true` against the active version and activates and pins the target; `unpinNamespace` clears the flag. Every write invalidates the per-instance view cache.

### 18.4 The verifier view and hosted adjudication

`hostedView(activeVersions, pins)`: per verb the first version that defines it (a version whose custom traits no longer load contributes nothing); deprecated verbs are removed. `lookup(verb)` returns `{known, confirmed, deprecated, def_digest?, idempotency_param?, profile, traits, serverClass, rules?}`: for a confirmed def its effective profile and traits and `serverClass` from its reversibility (`reversible`, `rate_limited` → `costly`, `irreversible`); otherwise the join of the top profiles of the active registries, every top trait, `irreversible`. Rules compile for confirmed and unconfirmed known verbs; a def or rules block that throws yields `rules_broken` (deny every call). `provenance(op)` answers only for confirmed exact verbs (else undefined: sensitive). `undo.plan` comes from `undoEngine` over the confirmed defs. `floor(verb, grantFacts, callContext)` is `floorDecision` over the lookup profile (an exception is `deny`). `grantFactsOf(grant)` reads envelope caveat types plus `envelope.actions.{caveats, max_esc (default 3), preauth_esc (default 0)}`. `hostedCallContext` is `fresh_revocation` always, plus `idempotency` when the def's key parameter is a non-empty string in the params. The API caches the view per instance for 5 s, keyed by the heads' digests and the reviewer pins.

Adjudication (check `action_registry`): registry mode iff the view has at least one version (`actionView.versions.length > 0`); otherwise nothing changes. The reversibility class is the stricter of the heuristic class and `serverClass`. `registryGate(scope, locked)` meets the floor decision with the business rules: the caller is `principal = <subject_type>:<subject_id>` for a verified principal else `pub:<principal pub>`, `org` = the verified org principal's id or else the attested `subject.org`; `rateKeysOf(compiled, who)` gives per accumulator the key `<verb>|<window_ms>|<principal|org>:<id>` (no rule index or digest, so editing or reordering rules never resets a count), absent when the id is unknown (the count is then absent and the rule fires). Counts are `count(events with key, at >= now - window)`. `subject` comes only from a `context_attestation` signed by a trusted attestor and bound to the grant, action digest and counter; unattested body `subject`/`env` are ignored. Before the admission transaction the gate runs unlocked (an early `deny` returns at once); inside it (`locked`) the gate takes `pg_advisory_xact_lock` on `pca-action-rate:<instance>:<key>` for each distinct key in sorted order, then re-reads the counts. `deny` returns a denial with the reasons. `escalate` raises the required threshold to `t = 3` (strong proof, no optimistic path); the enforced verify satisfies it only when it allows under that threshold and, if `approval` asks for more than one approver or a group, only on a human-touch re-adjudication (the approval flow). A held step-up stores `approval: {approvers, group?}` in its `HeldAction`. The approval flow then needs distinct approving members `>= max(approver quorum, approvers)`, counting only active members whose `groups` include `group` when one is named (a malformed requirement cannot be approved with a passkey and times out as a deny); the raw principal-key cosign route refuses such a step-up. On allow, the transaction records one event per distinct key at `now` and prunes that key's events older than two days, so a rollback un-counts the admission. Allow and dry-run responses carry `action: {verb, known, confirmed, deprecated, def_digest?, registry_versions, undo: {eligible, compensation_verb?}}`.

### 18.5 Review workflow (hosted)

Drafts are per `(instance, verb)` with `origin` `import` | `sync` | `template` and `change` `added` | `changed` | `removed`. Imports (`POST .../imports {ns, from, url | source, verb?, track?, schedule?}`) run `importAndSuggest` with rule suggestions only (no model assist), so every result is unreviewed or suggested. URLs are fetched behind the webhook SSRF guard (`validateWebhookUrl`: https, every resolved address checked before each request, at most 3 re-validated redirects, 15 s deadline, streamed 8 MiB cap, document content types); MCP uses `initialize` then `tools/list` over Streamable HTTP (protocol 2025-06-18), at most 20 pages and 8 MiB in all. Pasted sources are capped at 8 MiB. Any `PATCH` of a draft re-validates it (`validateDef`, `businessRulesError`) and drops its attestation. A template apply drops any confirmation in the template. Confirm (`POST .../drafts/:verb/confirm {attestation, rules_review?, assertion}`): the reviewer key is unwrapped in the browser by the passkey PRF and signs the attestation (and the rules review, same kid); the server requires `ts` within 600 s past / 120 s ahead, an active reviewer credential whose reviewer owns the active `reviewer` key of that kid, a WebAuthn assertion with user verification on the approval origin over `sha256(utf8("atlas-pca/action-review-challenge/v1\0") || reviewMessage(attestation without sig) || rulesReviewMessage(rules review without sig) | empty)`, `verifyAttestation` of the decision applied to exactly the stored draft under the instance pins, `rulesReviewError` for the rules review, a strictly advancing sign count (replay refused), and an unchanged draft. Reviewer enrolment is a single-use link of kind `review_enrol` (24 h; an approver link can never enrol a reviewer); revoking a reviewer disables it, unpins its key and revokes its credentials. Publish (`POST .../publish {ns, version?}`): the active defs overlaid with the drafts (a removal draft drops its verb), the `RulesDoc` from the drafts' rules and rules reviews (else the active ones), built with stability `stable`, signed with the `atlas-instance` key, then `publishVersion`; the version defaults to the active one's patch bump (`1.0.0` first); the published drafts are deleted.

### 18.6 Sync

`syncSource({current, imported, specDigest, lock?, now})` → `{defs, entries, deprecated, lock, needsReview}`. `SourceLock {spec_digest, ops: {verb: defDigest as imported}, synced_at}`. Per imported verb: absent from `current` → `added` (imported form); `lock.ops[verb]` equals the imported digest (or, without a lock entry, the current def's digest equals it) → `unchanged` (the current def, review included, kept); else `changed` (the imported form, stripped to unreviewed, with `diffDefs` against the current def). Verbs in the old lock missing from the import → `removed` (deprecated). Verbs the lock does not attribute to this source are never touched. `needsReview` iff any `added` or `changed`.

CLI: `pca.config.json` `sources: [{name, from, file | url, verb?}]` (1..32, unique `[a-z][a-z0-9_-]{0,31}` names, https URLs, `verb` iff `jsonschema`). `pca actions sync [--source N] [--check]` reads each source (file relative to the project directory, or https GET with `redirect: 'error'`, 30 s, 16 MiB), imports it with rule suggestions, merges into `<name>.sync.yaml` (keeping the rules of the defs it keeps), and writes the locks to `pca.sync.json`; `--check` writes nothing and fails when any entry is not `unchanged`. The composite GitHub Action runs `check` (fails on change) or `sync` (output `changed` from `git status`), and with `publish: 'true'` in sync mode lints, tests, builds, signs (key via a mode-600 temp file) and publishes with `--api`.

Hosted: a tracked source (`pca_action_sources`, schedule `off` | `hourly` | `daily`) is synced by `POST .../sources/:id/sync` or the worker sweep. The sweep claims due sources with a compare-and-set lease (10 min), skips instances with PCA off (rescheduled), and merges like an import (drafts with origin `sync`; `removed` becomes a removal draft). Failure backs off `interval * 2^failures`, capped at 7 days. When a sync drafted anything, it audits `pca.actions.sync.review_needed` and emails every active reviewer with an address through the instance's own mailer. Nothing a sync writes is confirmed or published.

### 18.7 Starter packs

`STARTER_TEMPLATES` (`ecommerce`/`shop`, `fintech`/`pay`, `healthcare`/`clinic`, `saas_admin`/`admin`, `devtools`/`infra`), each `{id, title, description, ns, traits(ns), yaml(ns)}`: authoring YAML with custom traits under `<ns>.*` (each a floor joined with the floors it implies, so it only extends them), `rules:` blocks and rule examples. `ns` must be `[a-z][a-z0-9_]{0,31}` and not `pca`. Every action is `authored` (unconfirmed under section 16), never `confirmed`. `pca actions init --template <id>` writes the YAML and puts the traits in `pca.config.json`; `POST .../templates/:id/apply {ns?}` writes drafts with origin `template`.

### 18.8 API routes

Secret key (`pca:read` for GET, `pca:write` otherwise) under `/v1/pca/action-registry`, and the same handlers for the dashboard (owner/admin for writes) under `/v1/dashboard/accounts/:accountId/instances/:instanceId/pca/actions`:

- `GET /` (`registry_mode`, namespaces with counts, publisher and reviewer keys); `POST /publisher-keys {kid, pk, display_name?}`, `DELETE /publisher-keys/:kid`; `POST /packs {pack, rules?, traits?}`.
- `GET /namespaces/:ns/versions`, `GET /namespaces/:ns/versions/:version`, `GET /namespaces/:ns/diff?from=&to=` (the gate with `pin: true`; `{ok, changes}` or `{ok: false, code, message, verbs, changes}`), `PUT /namespaces/:ns/pin {version}`, `DELETE /namespaces/:ns/pin`.
- `GET /actions?q=&state=&ns=&limit=` (state `confirmed` | `unconfirmed` | `stale` | `deprecated`; limit 1..200, default 50), `GET /actions/:verb` (def, digest, card, effective and hint profiles, rules, `rules_text`, `compiled_rules`, history).
- `POST /imports`, `GET /drafts?ns=`, `GET|PATCH|DELETE /drafts/:verb`, `POST /drafts/:verb/confirm`, `POST /publish`.
- `POST /actions/:verb/review` (open a published action as a draft).
- `POST /reviewers/enrolments`, `GET /reviewers`, `DELETE /reviewers/:id`; dashboard only: `GET /review-session`. Ceremony: `GET|POST /v1/pca/action-reviewers/enrol` (link-token authenticated, rate limited).
- `GET|POST /sources`, `PATCH|DELETE /sources/:id`, `POST /sources/:id/sync`; `GET /templates`, `POST /templates/:id/apply`.

Audit events: `pca.actions.publisher_key.pinned|revoked`, `pca.actions.version.published`, `pca.actions.namespace.pinned|unpinned`, `pca.actions.draft.confirmed`, `pca.actions.reviewer.enrolled`, `pca.actions.reviewer.enrolment_created`, `pca.actions.sync.review_needed`.

### 18.9 Known limits

- Reviewer keys are pinned on an instance only through the passkey enrolment, by design: a secret key can pin publisher keys but never a reviewer key, so whoever holds the secret key cannot confirm its own definitions. A confirmation or rules review signed by `pca actions confirm` with a local key therefore counts on the instance only if that kid and key are pinned there, so a CLI-published pack is stored with such actions unconfirmed, and a CLI pack that widens rules is refused (`widen_unreviewed`).
- An action published unconfirmed (for example from the CLI) is confirmed by opening it for review: `POST /actions/:verb/review` turns the active definition and rules into a draft.
- A version whose custom traits no longer load keeps the instance in registry mode; every action it names is treated as known, unconfirmed and denied by its rules until a version that loads replaces it.
- Rate limits are sliding windows of one hour or one day only; events are kept two days. The org scope needs a verified org principal or an attested `subject.org`.
- The business-rules evaluation and the registry gate are TypeScript (hosted) only; no native verifier evaluates `CompiledRules` or the hosted view.
