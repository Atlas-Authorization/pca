/**
 * @atlasauth/pca-rag — FGA-for-RAG.
 *
 * Retrieval-time, per-principal document filtering driven by the PCA policy engine. Given a
 * principal (or a verified PCActn's holder), a candidate set of documents that each carry ACL
 * metadata (a `{ relation, object }` ACL entry, or `relation:object` tags), and a policy (raw PCA
 * predicates, or an imported OpenFGA/Zanzibar ReBAC model+tuples), this returns ONLY the documents
 * the principal may see — deciding every candidate through the core evaluator / `member_of` relation
 * closure in `@atlasauth/pca`, and reusing `@atlasauth/pca-policy-bridge` to compile ReBAC relation
 * checks into PCA predicates.
 *
 * Two properties make this suitable for the PCA proof trace:
 *   1. FAIL CLOSED. A document is admitted ONLY when a permit predicate cleanly matches (verb =
 *      relation, resource = object, every `where` condition `true`) and no deny predicate matches.
 *      Anything unknown — no ACL, an unresolved relation, a malformed document, an incomplete policy
 *      translation — drops the document. The model can never see an unauthorized chunk.
 *   2. AUDITABLE. Every decision is captured in a {@link FilterDecision}: which documents passed,
 *      which were dropped and why, the exact permit predicate that authorized each one, and a
 *      content-addressed `digest` of the whole decision set that can be bound into a receipt / proof.
 *
 * Decisions use the SAME evaluator the adjudicator uses, so "what the retriever filtered" and "what
 * the authority system would admit" cannot drift apart.
 */

import type { ActionContext, CapabilityChain, PCActn, Predicate, PredicateResult } from '@atlasauth/pca';
import { hashCanonical } from '@atlasauth/pca';
import { decide, openfgaToPca, type TranslationReport } from '@atlasauth/pca-policy-bridge';

// ---- principal -----------------------------------------------------------------------------------

/**
 * The retrieval principal. `id` is matched against the policy's subject (`subject.id` in a PCA
 * predicate, the `user` of an OpenFGA tuple). `attributes` are exposed to policy conditions as
 * `subject.*`; `env` is exposed as `env.*` (e.g. a group-adjacency map a `member_of` condition's
 * `collection` resolves against).
 */
export interface Principal {
  id: string;
  attributes?: Record<string, unknown>;
  env?: Record<string, unknown>;
}

/** A principal, or just its id (shorthand for `{ id }`). */
export type PrincipalInput = Principal | string;

function toPrincipal(p: PrincipalInput): Principal {
  return typeof p === 'string' ? { id: p } : p;
}

/**
 * Derive a {@link Principal} from a (already verified) PCActn: the acting identity is the LEAF
 * capability holder — the key the action was ultimately delegated to. Pass `opts.id` to map that
 * holder key to the identity your policy is keyed on (e.g. an OpenFGA `user:alice`); it defaults to
 * the raw leaf-holder key. Throws on a PCActn with no capability chain (a malformed / unverified
 * object), rather than silently producing an empty principal.
 */
export function principalFromPCActn(
  p: Pick<PCActn, 'cap_chain'>,
  opts?: { id?: string; attributes?: Record<string, unknown>; env?: Record<string, unknown> },
): Principal {
  const chain: CapabilityChain = Array.isArray(p?.cap_chain) ? p.cap_chain : [];
  const leaf = chain.at(-1);
  if (!leaf || typeof leaf.holder !== 'string' || leaf.holder.length === 0) {
    throw new TypeError('principalFromPCActn: PCActn has no leaf capability holder');
  }
  const principal: Principal = { id: opts?.id ?? leaf.holder };
  if (opts?.attributes !== undefined) principal.attributes = opts.attributes;
  if (opts?.env !== undefined) principal.env = opts.env;
  return principal;
}

// ---- documents + ACLs ----------------------------------------------------------------------------

/** One ACL entry: the principal must hold `relation` on `object` (an OpenFGA relation check). */
export interface DocAcl {
  relation: string;
  object: string;
}

/**
 * The minimal document shape the default extractor understands: a stable `id`, plus ACL metadata as
 * an `acl` entry (single or list) and/or `relation:object` tag strings. A document needs AT LEAST ONE
 * decidable ACL entry (via `acl` or `tags`) to be admissible — one with none fails closed.
 */
export interface AclDocument {
  id: string;
  acl?: DocAcl | DocAcl[];
  tags?: string[];
  [k: string]: unknown;
}

function isDocAcl(v: unknown): v is DocAcl {
  if (v === null || typeof v !== 'object') return false;
  const rel = (v as { relation?: unknown }).relation;
  const obj = (v as { object?: unknown }).object;
  return typeof rel === 'string' && rel.length > 0 && typeof obj === 'string' && obj.length > 0;
}

function aclArray(acl: unknown): DocAcl[] {
  if (Array.isArray(acl)) return acl.filter(isDocAcl);
  return isDocAcl(acl) ? [acl] : [];
}

/** A `relation:object` tag → an ACL entry. The split is at the FIRST ':' so an object id may itself
 *  contain ':' (e.g. `viewer:document:readme` → relation `viewer`, object `document:readme`). */
function tagToAcl(tag: unknown): DocAcl | null {
  if (typeof tag !== 'string') return null;
  const i = tag.indexOf(':');
  if (i <= 0 || i >= tag.length - 1) return null;
  return { relation: tag.slice(0, i), object: tag.slice(i + 1) };
}

/** Collect ACL entries from freeform `acl` + `tags` metadata (both `unknown`; proto-safe narrowing). */
export function aclsFromMetadata(acl: unknown, tags: unknown): DocAcl[] {
  const out = aclArray(acl);
  if (Array.isArray(tags)) {
    for (const t of tags) {
      const a = tagToAcl(t);
      if (a !== null) out.push(a);
    }
  }
  return out;
}

// ---- policy compilation --------------------------------------------------------------------------

/**
 * A policy for the filter. One of:
 *   - a bare `Predicate[]` (raw PCA permits);
 *   - `{ openfga: { model, tuples } }` — an OpenFGA/Zanzibar authorization model + relationship
 *     tuples, compiled via {@link openfgaToPca} (relation closures — computedUserset, union,
 *     intersection, difference, tupleToUserset — are resolved into concrete permits);
 *   - `{ predicates, denies?, report? }` — an envelope-shaped result (e.g. a bridge `BridgeResult`),
 *     where `denies` is applied with deny-overrides-permit semantics.
 */
export type PolicyInput =
  | Predicate[]
  | { openfga: { model: unknown; tuples: unknown } }
  | { predicates: Predicate[]; denies?: Predicate[]; report?: TranslationReport };

/**
 * A compiled policy: a permit list, a deny list and whether the source translation was INCOMPLETE
 * (a non-empty `report.errors` — in which case the whole policy fails closed and nothing is admitted).
 * Compile once with {@link compilePolicy} and reuse across retrievals to avoid recompiling per call.
 */
export interface CompiledPolicy {
  readonly predicates: Predicate[];
  readonly denies: Predicate[];
  readonly incomplete: boolean;
  readonly report?: TranslationReport;
}

function isCompiledPolicy(p: PolicyInput | CompiledPolicy): p is CompiledPolicy {
  return (
    p !== null &&
    typeof p === 'object' &&
    !Array.isArray(p) &&
    'incomplete' in p &&
    typeof (p as { incomplete?: unknown }).incomplete === 'boolean'
  );
}

/** Compile any {@link PolicyInput} (or pass through an already-{@link CompiledPolicy}). */
export function compilePolicy(policy: PolicyInput | CompiledPolicy): CompiledPolicy {
  if (isCompiledPolicy(policy)) return policy;
  if (Array.isArray(policy)) return { predicates: policy, denies: [], incomplete: false };
  if ('openfga' in policy) {
    const br = openfgaToPca(policy.openfga.model, policy.openfga.tuples);
    return {
      predicates: br.predicates,
      denies: br.denies,
      report: br.report,
      incomplete: br.report.errors.length > 0,
    };
  }
  const predicates = Array.isArray(policy.predicates) ? policy.predicates : [];
  const denies = Array.isArray(policy.denies) ? policy.denies : [];
  const report = policy.report;
  return { predicates, denies, report, incomplete: report !== undefined && report.errors.length > 0 };
}

// ---- filter decision (proof trace) ---------------------------------------------------------------

/** Per-document decision — the auditable record of why one candidate passed or was dropped. */
export interface DocDecision {
  id: string;
  allowed: boolean;
  /** The ACL entry that granted access (present only when `allowed`). */
  via?: DocAcl;
  /** The exact permit predicate that matched (proof: which grant authorized this document). */
  matched?: Predicate;
  /** Human-readable reason — the fail-closed cause for a drop, or the grant for an allow. */
  reason: string;
}

/**
 * The full decision for a filter run — suitable to attach to a PCA proof / receipt. `digest` is a
 * content-addressed commitment to the decision (principal + the admitted/dropped id sets), so a
 * verifier can confirm the model was handed exactly these documents and no others.
 */
export interface FilterDecision {
  principal: string;
  considered: number;
  /** IDs admitted (the model may see these), in candidate order. */
  allowedIds: string[];
  /** IDs dropped (not authorized / unknown — fail closed), in candidate order. */
  droppedIds: string[];
  /** One record per candidate. */
  decisions: DocDecision[];
  /** True when the policy translation was incomplete → every candidate fails closed. */
  policyIncomplete: boolean;
  /** The policy-translation report, when the policy was imported (OpenFGA). */
  report?: TranslationReport;
  /** b64u content-address of this decision set (binds into the proof trace). */
  digest: string;
}

/** Result of {@link filterDocuments}: the admitted documents plus the {@link FilterDecision}. */
export interface FilterResult<D> {
  documents: D[];
  decision: FilterDecision;
}

// ---- core filter ---------------------------------------------------------------------------------

interface Extractors<D> {
  id: (doc: D, index: number) => string;
  acls: (doc: D) => DocAcl[];
}

/** Build the evaluation context for checking ONE ACL entry for a principal. */
function buildContext(principal: Principal, acl: DocAcl): ActionContext {
  const subject: Record<string, unknown> = { ...(principal.attributes ?? {}), id: principal.id };
  const ctx: ActionContext = {
    action: { verb: acl.relation, resource: acl.object },
    subject,
  };
  if (principal.env !== undefined) ctx.env = principal.env;
  return ctx;
}

/** Decide a single document. Returns the per-document record; `allowed` governs admission. */
function decideDocument(
  id: string,
  acls: DocAcl[],
  principal: Principal,
  compiled: CompiledPolicy,
): DocDecision {
  if (compiled.incomplete) {
    return { id, allowed: false, reason: 'policy translation incomplete (fail closed)' };
  }
  if (acls.length === 0) {
    return { id, allowed: false, reason: 'no decidable ACL metadata (fail closed)' };
  }
  let lastReason = 'no relation grants access (fail closed)';
  for (const acl of acls) {
    let res: PredicateResult;
    try {
      res = decide({ predicates: compiled.predicates, denies: compiled.denies }, buildContext(principal, acl));
    } catch {
      lastReason = 'evaluator error (fail closed)';
      continue;
    }
    if (res.allowed) {
      const d: DocDecision = {
        id,
        allowed: true,
        via: acl,
        reason: `granted: ${principal.id} has ${acl.relation} on ${acl.object}`,
      };
      if (res.matched !== undefined) d.matched = res.matched;
      return d;
    }
    if (res.reason !== undefined) lastReason = res.reason;
  }
  return { id, allowed: false, reason: lastReason };
}

function runFilter<D>(
  principalInput: PrincipalInput,
  candidates: D[],
  policyInput: PolicyInput | CompiledPolicy,
  ex: Extractors<D>,
): FilterResult<D> {
  const principal = toPrincipal(principalInput);
  const compiled = compilePolicy(policyInput);
  const list = Array.isArray(candidates) ? candidates : [];

  const documents: D[] = [];
  const decisions: DocDecision[] = [];
  const allowedIds: string[] = [];
  const droppedIds: string[] = [];

  for (let i = 0; i < list.length; i++) {
    const doc = list[i]!;
    let id: string;
    let acls: DocAcl[];
    try {
      id = ex.id(doc, i);
      acls = ex.acls(doc);
    } catch {
      // A document whose metadata cannot even be read is unknown → fail closed.
      const fid = `doc#${i}`;
      decisions.push({ id: fid, allowed: false, reason: 'unreadable document metadata (fail closed)' });
      droppedIds.push(fid);
      continue;
    }
    if (typeof id !== 'string' || id.length === 0) id = `doc#${i}`;

    const decision = decideDocument(id, acls, principal, compiled);
    decisions.push(decision);
    if (decision.allowed) {
      documents.push(doc);
      allowedIds.push(id);
    } else {
      droppedIds.push(id);
    }
  }

  const base = {
    principal: principal.id,
    considered: list.length,
    allowedIds,
    droppedIds,
    policyIncomplete: compiled.incomplete,
  };
  const digest = hashCanonical({ v: 1, kind: 'pca-rag/filter', ...base });
  const decision: FilterDecision = { ...base, decisions, digest };
  if (compiled.report !== undefined) decision.report = compiled.report;

  return { documents, decision };
}

/** Options controlling how ACL metadata is read from a document. */
export interface FilterOptions<D extends AclDocument> {
  /** Stable id for a document (default: `doc.id`, else a positional `doc#<index>`). */
  getId?: (doc: D, index: number) => string;
  /** ACL entries for a document (default: `doc.acl` + `relation:object` `doc.tags`). */
  getAcls?: (doc: D) => DocAcl[];
}

/**
 * Filter a candidate set to the documents `principal` may see under `policy`. Returns the admitted
 * documents (in candidate order) and a {@link FilterDecision} proof trace. FAILS CLOSED: a document
 * is admitted only when a permit predicate cleanly matches one of its ACL entries and no deny matches;
 * anything unknown is dropped.
 */
export function filterDocuments<D extends AclDocument>(
  principal: PrincipalInput,
  candidates: D[],
  policy: PolicyInput | CompiledPolicy,
  opts?: FilterOptions<D>,
): FilterResult<D> {
  const ex: Extractors<D> = {
    id: opts?.getId ?? ((doc: D) => doc.id),
    acls: opts?.getAcls ?? ((doc: D) => aclsFromMetadata(doc.acl, doc.tags)),
  };
  return runFilter(principal, candidates, policy, ex);
}

// ---- generic retriever wrapper -------------------------------------------------------------------

/** A generic retriever: returns candidate documents for a query. */
export interface RagRetriever<D extends AclDocument = AclDocument> {
  retrieve(query: string, k?: number): Promise<D[]> | D[];
}

/** A retriever whose results are PCA-filtered before they reach the model. */
export interface FilteredRetriever<D extends AclDocument = AclDocument> {
  retrieve(query: string, k?: number): Promise<D[]>;
  /** The decision from the most recent `retrieve` (the proof trace), or `undefined` if none yet. */
  lastDecision(): FilterDecision | undefined;
}

/**
 * Wrap a generic {@link RagRetriever} so every result set is filtered to what `principal` may see
 * BEFORE it reaches the model. The wrapper exposes the same `retrieve` plus `lastDecision()` for audit.
 */
export function withPcaFilter<D extends AclDocument>(
  retriever: RagRetriever<D>,
  principal: PrincipalInput,
  policy: PolicyInput | CompiledPolicy,
  opts?: FilterOptions<D>,
): FilteredRetriever<D> {
  const compiled = compilePolicy(policy);
  let last: FilterDecision | undefined;
  return {
    async retrieve(query: string, k?: number): Promise<D[]> {
      const docs = await retriever.retrieve(query, k);
      const res = filterDocuments(principal, Array.isArray(docs) ? docs : [], compiled, opts);
      last = res.decision;
      return res.documents;
    },
    lastDecision(): FilterDecision | undefined {
      return last;
    },
  };
}

// ---- framework-shaped adapters (structural, optional-peer; no heavy deps imported) ---------------

function metaString(meta: Record<string, unknown> | undefined, key: string): string | undefined {
  if (meta === undefined || meta === null) return undefined;
  const v = meta[key];
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

/** Minimal structural shape of a LangChain `Document` (we never import `@langchain/*`). */
export interface LangChainDocumentLike {
  pageContent: string;
  metadata?: Record<string, unknown>;
}

/** Minimal structural shape of a LangChain retriever (`invoke` or the older `getRelevantDocuments`). */
export interface LangChainRetrieverLike<D extends LangChainDocumentLike = LangChainDocumentLike> {
  invoke?(input: string): Promise<D[]> | D[];
  getRelevantDocuments?(query: string): Promise<D[]> | D[];
}

/** How to read ACL metadata off a LangChain document (defaults read `metadata.acl` + `metadata.tags`). */
export interface LangChainAdapterOptions<D extends LangChainDocumentLike = LangChainDocumentLike> {
  getId?: (doc: D, index: number) => string;
  getAcls?: (doc: D) => DocAcl[];
}

/** A LangChain-shaped retriever whose results are PCA-filtered post-retrieval. */
export interface FilteredLangChainRetriever<D extends LangChainDocumentLike = LangChainDocumentLike> {
  invoke(input: string): Promise<D[]>;
  getRelevantDocuments(query: string): Promise<D[]>;
  lastDecision(): FilterDecision | undefined;
}

/**
 * Wrap a LangChain-shaped retriever. Results are filtered post-retrieval (before they reach the
 * model); ACLs are read from each document's `metadata` by default. The underlying retriever is
 * called via `invoke` when present, else `getRelevantDocuments`.
 */
export function withLangChainPcaFilter<D extends LangChainDocumentLike>(
  retriever: LangChainRetrieverLike<D>,
  principal: PrincipalInput,
  policy: PolicyInput | CompiledPolicy,
  opts?: LangChainAdapterOptions<D>,
): FilteredLangChainRetriever<D> {
  const compiled = compilePolicy(policy);
  let last: FilterDecision | undefined;
  const ex: Extractors<D> = {
    id: opts?.getId ?? ((doc: D, i: number) => metaString(doc.metadata, 'id') ?? metaString(doc.metadata, 'source') ?? `doc#${i}`),
    acls: opts?.getAcls ?? ((doc: D) => aclsFromMetadata(doc.metadata?.['acl'], doc.metadata?.['tags'])),
  };

  const fetch = async (input: string): Promise<D[]> => {
    if (typeof retriever.invoke === 'function') return await retriever.invoke(input);
    if (typeof retriever.getRelevantDocuments === 'function') return await retriever.getRelevantDocuments(input);
    throw new TypeError('withLangChainPcaFilter: retriever has neither invoke nor getRelevantDocuments');
  };
  const run = async (input: string): Promise<D[]> => {
    const docs = await fetch(input);
    const res = runFilter(principal, Array.isArray(docs) ? docs : [], compiled, ex);
    last = res.decision;
    return res.documents;
  };

  return {
    invoke: run,
    getRelevantDocuments: run,
    lastDecision: () => last,
  };
}

/** Minimal structural shape of a LlamaIndex node. */
export interface LlamaIndexNodeLike {
  id_?: string;
  metadata?: Record<string, unknown>;
}

/** Minimal structural shape of a LlamaIndex `NodeWithScore`. */
export interface LlamaIndexNodeWithScoreLike<N extends LlamaIndexNodeLike = LlamaIndexNodeLike> {
  node: N;
  score?: number;
}

/** Minimal structural shape of a LlamaIndex retriever. */
export interface LlamaIndexRetrieverLike<N extends LlamaIndexNodeLike = LlamaIndexNodeLike> {
  retrieve(params: { query: string } | string): Promise<Array<LlamaIndexNodeWithScoreLike<N>>> | Array<LlamaIndexNodeWithScoreLike<N>>;
}

/** How to read ACL metadata off a LlamaIndex node (defaults read `node.metadata.acl` + `.tags`). */
export interface LlamaIndexAdapterOptions<N extends LlamaIndexNodeLike = LlamaIndexNodeLike> {
  getId?: (item: LlamaIndexNodeWithScoreLike<N>, index: number) => string;
  getAcls?: (item: LlamaIndexNodeWithScoreLike<N>) => DocAcl[];
}

/** A LlamaIndex-shaped retriever whose results are PCA-filtered post-retrieval. */
export interface FilteredLlamaIndexRetriever<N extends LlamaIndexNodeLike = LlamaIndexNodeLike> {
  retrieve(params: { query: string } | string): Promise<Array<LlamaIndexNodeWithScoreLike<N>>>;
  lastDecision(): FilterDecision | undefined;
}

/**
 * Wrap a LlamaIndex-shaped retriever. The returned `NodeWithScore[]` is filtered post-retrieval
 * (before it reaches the model); ACLs are read from each node's `metadata` by default.
 */
export function withLlamaIndexPcaFilter<N extends LlamaIndexNodeLike>(
  retriever: LlamaIndexRetrieverLike<N>,
  principal: PrincipalInput,
  policy: PolicyInput | CompiledPolicy,
  opts?: LlamaIndexAdapterOptions<N>,
): FilteredLlamaIndexRetriever<N> {
  const compiled = compilePolicy(policy);
  let last: FilterDecision | undefined;
  const ex: Extractors<LlamaIndexNodeWithScoreLike<N>> = {
    id:
      opts?.getId ??
      ((item: LlamaIndexNodeWithScoreLike<N>, i: number) =>
        (typeof item.node?.id_ === 'string' && item.node.id_.length > 0 ? item.node.id_ : undefined) ??
        metaString(item.node?.metadata, 'id') ??
        `node#${i}`),
    acls:
      opts?.getAcls ??
      ((item: LlamaIndexNodeWithScoreLike<N>) => aclsFromMetadata(item.node?.metadata?.['acl'], item.node?.metadata?.['tags'])),
  };

  return {
    async retrieve(params: { query: string } | string): Promise<Array<LlamaIndexNodeWithScoreLike<N>>> {
      const items = await retriever.retrieve(params);
      const res = runFilter(principal, Array.isArray(items) ? items : [], compiled, ex);
      last = res.decision;
      return res.documents;
    },
    lastDecision: () => last,
  };
}
