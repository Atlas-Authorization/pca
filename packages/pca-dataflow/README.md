# @atlasauth/pca-dataflow

A capability-tagged, **positive** data-flow model for PCA. Where `@atlasauth/pca`'s `dlp.ts` + `taint.ts`
answer *"how dirty is this action's lineage?"* heuristically (a scalar taint compared to a ceiling), this
package proves the complementary property: **an untrusted value cannot reach an exfiltrating sink**.

It follows **CaMeL** — Debenedetti, Shumailov, et al., *"Defeating Prompt Injections by Design"*, Google
DeepMind / ETH Zürich / Google, [arXiv:2503.18813](https://arxiv.org/abs/2503.18813) (March 2025). CaMeL
reframes prompt injection as a **data-flow problem** rather than a detection problem:

1. **Control flow derives only from the trusted query** — never from tool output or retrieved text.
2. **Every value carries capabilities** describing its provenance (`sources`, `isTrusted`) and the sinks it
   may reach (`readers`).
3. **An interpreter enforces a policy on every flow to a sink.** A value whose lineage includes an untrusted
   source is *provably* unable to reach a forbidden sink — no string matching, no classifier.

## Shape

- `Tagged<T> = { value: T; cap: Capability }` — a value and its data-flow label.
- Boundary constructors: `fromTrustedQuery`, `fromToolOutput`, `fromSource`, `tag`.
- Combinators that **propagate** capabilities: `derive` (sources union; trusted iff *all* inputs trusted;
  readers meet/intersection), `combineCaps`, `unionSources`.
- Interpreter: `classifyFlow` / `canFlow` → a value→sink decision; `checkAction` gates a PCA action and maps
  to the shared `allow | step_up | deny` (`DlpOutcome`) vocabulary.
- `dualContext` — the privileged-planner / quarantined-handler separation: the planner sees only the trusted
  query; untrusted content is handled in quarantine and re-enters only as a capability-tagged result.

## The trust assumption (honest statement)

This is a **capability model, not a classifier.** Its guarantee of non-exfiltration is **provable _given
correct tagging at the boundaries_** — exactly CaMeL's assumption. The interpreter is sound, so the whole
trust surface collapses to one thing a human must get right: labelling inputs where data **enters** the
system (`fromTrustedQuery` for the genuine user query; untrusted tags for everything a tool or document
returns). Mis-tag untrusted text as trusted and the proof is void; this module does **not** detect that — it
is not a detector. Run it alongside the heuristic `dlp.ts`/`taint.ts` floor for defence in depth: this
package proves *"untrusted cannot reach the sink"*, the heuristic catches mis-tagging.

Pure, deterministic, immutable: no time, no randomness, no I/O; capabilities only ever lose trust through a
combinator, never gain it.
