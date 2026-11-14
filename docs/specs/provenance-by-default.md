# Provenance by default (0.5, track prov)

Status: built in the TypeScript reference (`@atlasauth/pca`, default-on in `authorize()`); native ports follow the shared vectors
`packages/pca/conformance/arg-provenance-vectors.json`.

## 1. The claim

> An agent protected by PCA cannot be steered by injected content (a tool output, a web page, an email, a retrieved document)
> into choosing **who**, **where** or **how much** for a sensitive action.

Concretely: if the operation the verifier is asked to admit is a sensitive action, and either the decision to perform that action
or the value of any of its sink arguments was influenced by content that did not come from the principal, `authorize()` returns
`escalate`, never `allow`. Only a principal-signed escalation answer (the existing WYSIWYS machinery: bound to the policy, the
exact PCActn and the history head, optionally to the recomputed approval render) turns that call into `allow`.

This is the CaMeL discipline (Debenedetti et al., "Defeating Prompt Injections by Design", arXiv:2503.18813): control flow and
the data that reaches a sensitive sink must derive from the trusted query. CaMeL enforces it by running the plan in an
interpreter; PCA enforces it at the verifier, where the action is admitted, with the agent's context as the unit of provenance.

## 2. Threat model

- **Adversary.** Controls any content that reaches the model's context other than the principal's own messages: tool results,
  fetched pages, inbound email, retrieved documents, MCP server responses, the output of other agents. It may also control the
  model completely (a fully jailbroken model is the worst case of injection): the agent process's model-facing side can emit any
  operation, any PCActn the holder key signs, and any bundle bytes.
- **Trusted.** The principal; the principal's signing key (grants, escalation answers); the verifier and its configuration;
  the **mediator**: the harness component that sees bytes enter the context (the agent loop that builds the prompt, an MCP
  client, a gateway) and holds a signing key the model cannot reach.
- **Out of scope.** Injection into the principal's own message (the principal is the source of trust by definition); a
  compromised mediator key or harness; side channels; what a read-only action returns (reads are not sinks; exfiltration
  happens at a later sensitive action, which this gate covers).

## 3. The guarantee and its one assumption

**Assumption (labels at the boundary).** Every segment that enters the model's context passes through a mediator that records
it with its true origin before the model sees it. The framework adapters do this automatically: the user message is
`principal`; every tool, retriever, MCP or fetch result is `tool`, `retrieval` or `web`.

**Guarantee.** Under the assumption, for every operation `op` admitted with `allow` by `authorize()` without an escalation
answer, where `op` is sensitive and the grant does not carry the signed opt-out:

1. the context that preceded the choice of `op` contained only principal segments, **or** the principal committed to the step
   (an executable principal-authorized plan from the plan registry, or an admitted step of a principal-signed workflow); and
2. every sink argument of `op` either came from a purely principal context, or occurs verbatim as a whole token in a principal
   message whose bytes the chain binds, or was fixed by the principal in an authorized plan node, or is explicitly relaxed by a
   signed, confirmed action definition (`provenance_min: tool | agent`).

If the assumption fails (no mediator, an unpinned mediator, a missing receipt), the verifier sees no verified chain and every
value is labelled `agent` (the top): the call escalates. **A missing label never allows.**

## 4. Lattice

The taint lattice, shared with the data-flow model (`@atlasauth/pca/dataflow`) and the `taint` risk input:

```
trusted < first_party < tool < web < agent
```

| Segment origin | Level |
|---|---|
| `principal` | `trusted` |
| `tool` | `tool` |
| `retrieval` | `tool` |
| `web` | `web` |
| no verified chain / unlabelled | `agent` |

The level of a set of segments is their join (maximum). `action` receipts (the model's own earlier choices) contribute
nothing: their effect is already captured by the context that produced them.

## 5. Sensitivity and sinks (action kit)

An action is **non-sensitive** iff its facts say it only reads: `effects` is non-empty and every effect is `read`, and every
trait is in `READ_SAFE_TRAITS` (`pca.financial_data_read`, `pca.pii_access`, `pca.regulated_data`). Anything else is sensitive,
including an action the verifier has no facts for, and an action kit def that is not confirmed (signed review): an unconfirmed
def reports no effects, so it is sensitive, and its relaxations are ignored.

Every parameter of a sensitive action is a **sink**. Its floor is `first_party` unless the confirmed def declares
`provenance_min` for it (`tool` or `agent`); the floor of a parameter of a non-sensitive action is `agent` (no constraint). A
parameter is **tainted** when its label ranks above its floor. `@atlasauth/pca-actions` derives the facts:
`provenanceActions(defs)` is the `provenance.actions` resolver for `authorize()`.

## 6. Wire format

### 6.1 Receipt (`pca-prov`)

One receipt per context segment, signed by the mediator with the artifact signature profile (Ed25519, optionally the PQ suite
members `alg`, `pq_pk`, `pq_sig`) under the domain `atlas-pca/prov-receipt/v1\0`. Closed members:

| Member | Type | Meaning |
|---|---|---|
| `v` | `1` | |
| `kind` | `"pca-prov"` | |
| `mediator` | string, 1..256 bytes | the labeller; pinned with `kid` |
| `kid` | string, 1..64 bytes | |
| `session` | b64u, 32 bytes | one chain per agent session |
| `seq` | safe integer >= 0 | position, contiguous from 0 |
| `prev` | b64u 32 bytes, or `null` for seq 0 | `provReceiptRef` of the previous receipt |
| `origin` | `principal` \| `tool` \| `retrieval` \| `web` \| `action` | |
| `source` | string, 1..256 bytes | `user`, the tool name, document id or URL; the verb for `action` |
| `content_digest` | b64u, 32 bytes | `hashCanonical(text)` of the segment; for `action`, `provActionDigest(op)` |
| `issued_at` | safe integer >= 0 (ms) | non-decreasing along the chain |
| `sig` | string | |

`provReceiptRef(r) = artifactRef('atlas-pca/prov-receipt-ref/v1', 'r', r)` (signature included).
`provActionDigest(op) = hashCanonical({d: 'atlas-pca/prov-action/v1', verb, resource, params})`.

### 6.2 Bundle (`pca-provenance`)

```json
{ "v": 1, "kind": "pca-provenance", "receipts": [ ... ], "contents": { "0": "Email the Q3 report to bob@acme.example" } }
```

`receipts`: the session's whole chain, 1..256 receipts, the last one the `action` receipt of this operation. `contents`
(optional): the text of principal segments keyed by decimal seq (no leading zeros), at most 65536 UTF-8 bytes each. Contents
for non-principal receipts are refused: the verifier never needs untrusted text.

Transport: header `PCA-Provenance` (base64url of the JSON; adapters use it up to 8192 characters) or the request body member
`pca_provenance`; `authorize()` also takes `input.provenance` directly.

### 6.3 Grant envelope member `provenance`

Signed by the principal with the rest of the grant: `{ mode?: 'enforce' | 'insecure_off', mediators?: Pin[] }` (closed; at most
16 pins `{mediator, kid, pk, pq_pk?}`). `mediators` designates the principal's own harness keys; the verifier joins them to its
own pins. `mode: 'insecure_off'` is the **only** opt-out and is documented as dangerous (section 9).

## 7. The decision (`decideArgProvenance`)

Inputs: the bundle (or none), the operation, the pinned mediator keys, the action facts (or none), two principal-commitment
flags established by the host (`principalPlan`, `principalControl`), and server observations. Pure, total, no clock. Steps,
first failure wins:

0. **Inputs.** Pins, operation and action facts well-formed, else `deny` (`malformed_config`, `malformed_operation`,
   `malformed_action`).
1. **Chain.** When a bundle is present: wire (closed members, bounds), contiguous `seq`, one session/mediator/kid, `prev` links,
   non-decreasing `issued_at` (`broken_chain`); the last receipt is the `action` receipt of this operation (`unbound_action`);
   every content names a principal receipt and hashes to it (`malformed_bundle`, `content_mismatch`). Any failure is `deny`.
   A chain whose `(mediator, kid)` no pin names is **ignored** (no trust, not deny: the call is unlabelled). Under a pin, every
   signature must verify (`bad_signature`, deny).
   Context = join of the non-action segments; `agent` when there are none or no verified chain. Path = `origin:source` of every
   non-principal segment; `unlabelled` without a verified chain.
2. **Observations.** Every `{origin, source}` the server itself saw reach this session joins into the context (raise only).
3. **Control.** `trusted` with `principalPlan` or `principalControl`; else the context.
4. **Labels.** Per top-level parameter: `trusted` under `principalPlan`; else the join over its leaves (`provLeaves`: strings
   as is, other scalars in strict canonical form, object keys included, at most 4096 leaves and depth 32), where a leaf is
   `trusted` when the context is `trusted` or the leaf occurs as a whole token in a verified principal content, else the
   context. No leaves: `trusted`. Too large to examine: the context.
5. **Floors and taint** (section 5).
6. **Outcome.** A sensitive action whose control is not `trusted` (no segment origin maps to `first_party`), or any tainted
   parameter: `escalate` (`untrusted_control`,
   `untrusted_args`, `untrusted_control_and_args`); otherwise `pass`.

Whole-token match: an occurrence counts when the character before it is not a word character (or the needle starts with a
non-word character), and likewise after it. Word characters: ASCII letters and digits, `_`, and every code unit at or above
0x80 (fail closed: fewer matches). Exact, case-sensitive, on UTF-16 code units, no normalization.

## 8. Composition

- **`authorize()` (default on).** The gate runs inside the guard after the required checks, as check `provenance_flow` (its
  own name: `provenance` is Intent Layer v2 rule 17). An escalate outcome adds the reason
  `provenance_flow: escalate: <why> [<path>]: the principal must confirm (prompt-injection path)`, which `decisionOf` reads as
  escalate-class; a deny outcome adds `provenance_flow: <code>: <why>` (deny). `requirePCA` exposes the same gate as an opt-in
  option for hosts that build their own pipeline.
- **Goal compiler and plans.** A plan the principal authorized in the plan registry (executable state) is a principal
  commitment to every node, values included: `principalPlan`. A context-supplied plan (`context().plan`) is not: the agent
  can supply it.
- **Workflows.** An admitted step of the principal-signed workflow commits the **choice** of the action (`principalControl`);
  its values still need provenance.
- **Escalation.** The existing answer path upgrades only escalate-class failures; a forged chain is deny and stays deny.
- **Delegation.** A sub-agent shares its parent's recorder (one session chain): the parent's untrusted context taints the
  child's actions, and vice versa. A delegated grant inherits the root envelope (and with it the principal's mediators and
  mode); a hop cannot add mediators or turn the gate off.
- **Gateway.** `@atlasauth/pca-gateway` reads the bundle from the request, and in full-policy mode keeps its own per-session
  log of the tool calls it admitted; each one joins the context of later calls in that session (server observations).
- **Data-flow model.** The CaMeL-style value-level model moved into core (`@atlasauth/pca/dataflow`; `levelOf(value)` maps its
  capabilities to this lattice) for hosts that run a plan interpreter: they can present `principalDirectProvenance` bundles
  for values the interpreter proves principal-derived.

### 8.1 Hosted adjudication

The hosted action route runs the same decision inside adjudication, after the grant-state gate and before the Policy VM:

- `principalPlan`: the plan is principal-authorized. An `agent_commit` plan does not count.
- `principalControl`: the request presented a workflow step that the gate admitted.
- The pins are the grant envelope's `provenance.mediators`.
- Action facts are unknown to the hosted verifier, so every action is sensitive.
- If the params plaintext is absent and the action's params digest is not that of `{}`, the arguments are unlabelled and
  the outcome is escalate (fail closed).

A `deny` refuses the request with a `403` and check `provenance_flow`. An `escalate` raises the required threshold to
`t = 3`: the action is held as a step-up, and only a principal-device cosign over this exact action admits it. A principal
confirmation is the only answer to an escalation. The dry-run reports an escalation as `step_up_required`.

## 9. The opt-out

The grant member `provenance: { mode: 'insecure_off' }` turns the gate off for that grant (check `provenance_flow` is
`not-enforced`). It is signed by the principal, so neither the agent nor a verifier option can set it. **Dangerous:** injected
content can then steer every sensitive action within the grant's other limits. It exists for grants whose every action is
harmless, or whose principal reviews each call by other means. There is no verifier-side switch.

## 10. Proof sketch

Fix a sensitive `op` admitted `allow` without an escalation answer, under a grant without the opt-out. The gate passed, so
`control = trusted` and no parameter is tainted.

- *No forged trust.* Every input to the labels is either verifier-side (pins, facts, flags, observations) or a receipt chain
  that verified under a pinned key. A receipt's origin, source, content digest and position are signed; reordering, dropping
  or splicing breaks `seq`/`prev`/session; relabelling breaks a signature; a chain for another operation fails the action
  binding; principal text must hash to its signed digest. By EUF-CMA of the mediator signature and collision resistance of the
  hash, any bundle the gate accepts was produced by the pinned mediator, so its labels are the mediator's labels.
- *Control.* `control` is `trusted` only with a host-established principal commitment, or when the context (the join of every
  segment the mediator recorded before the action) is `trusted`, i.e. every recorded segment is principal. By the boundary
  assumption every segment the model saw was recorded, so the model's input was purely principal, and the choice derived from
  the principal.
- *Values.* A parameter is untainted only when every leaf is `trusted` (or the signed def relaxes its floor): a purely
  principal context, a principal plan node, or a verbatim occurrence in signed principal text. In the last case the value is
  one the principal typed: injected content may have *influenced which* principal-typed token was used, but cannot introduce
  a recipient, URL, account or amount the principal did not write.
- *Unlabelled.* Without a verified chain the context is `agent`, so `control = agent > first_party` and the outcome is
  escalate for every sensitive action.
- *Escalate is not allow.* `decisionOf` returns escalate only when every failing check is escalate-class; the guard turns it
  into `allow` only after `verifyEscalationAnswer` with a pinned principal key bound to this PCActn. ∎

Residual risk, stated precisely: (a) a principal message that itself contains attacker text (pasted email) is trusted by
definition; (b) verbatim matching admits a principal-typed token chosen under influence (for example the principal wrote two
recipients and the injection picks one); (c) short numeric values the principal typed (e.g. `5`) match any later use of the
same token. A def that needs stricter handling keeps the floor at `first_party` and the host uses a principal plan.

## 11. Adapters (automatic labelling)

| Package | What it records |
|---|---|
| `@atlasauth/pca` facade `agent()` | one recorder per agent; key named in the grant envelope; `act()` returns the bundle |
| `pca-agent` | `act` appends the action and posts `pca_provenance`; `delegate` shares the recorder |
| `pca-langchain`, `pca-ai-sdk`, `pca-llamaindex` | `withPCAAgent` / `withPCAGenerate` / `withPCAEngine`: user turns as principal, tool results as tool |
| `pca-openai`, `pca-anthropic` | `withPCACompletions` / `withPCAMessages`; tool dispatch records each result |
| `pca-openai-agents`, `pca-vercel-ai`, `pca-mastra` | tool guards read the bundle from the run context and record each result |
| `pca-mcp` (incl. `pcaFetch`) | every `tools/call` response recorded as tool |
| `pca-rag` | every admitted retrieved document recorded as retrieval |
| `pca-gateway` | bundle from header/body; per-session server observations |

## 12. Conformance

`packages/pca/conformance/arg-provenance-vectors.json` (`pca-arg-provenance-vectors/1`), generated by
`scripts/gen-conformance-arg-provenance.mjs` with fixed keys and replayed by `src/arg-provenance-vectors.test.ts`: token
matching, leaves, sensitivity, and full decisions (bundle, pins, facts, flags, observations to outcome, code, control, labels,
tainted, path). Every native verifier replays the same file.
