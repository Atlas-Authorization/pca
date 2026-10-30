/**
 * `pca actions ...`: the authoring workflow of the action kit (init, import, lint, test, explain, diff, build, sign, publish).
 *
 * Files in, text out. A project is a directory (default `actions/`) of `*.yaml`, `*.yml` or `*.json` action files plus a
 * `pca.config.json` ({ns, version, stability, site, aud, traits?, reviewers?, sources?}). `build` writes its outputs to `.pca/`
 * (override with `--out`); `sign` and `publish` read them back and re-check everything before they sign or send. An action's
 * `rules:` block (business rules) is kept apart from its def: `build` writes them to `rules.json`, with the reviewers'
 * signatures over them from `pca.rules-reviews.json` (written by `confirm`). `sync` re-imports the configured `sources`.
 *
 * Every command returns {ok, text} (and never throws for a bad input file) so the CLI sets the exit code and tests read the text.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname, join } from 'node:path';
import { hashCanonical, unb64u } from '@atlasauth/pca';
import { actionSchemaDigest, actionSchemaKeyOf, signActionSchema, verifyActionSchema, type ActionSchema, type UnsignedActionSchema } from '@atlasauth/pca/ext/intent';
import {
  CORE_REGISTRY, DEFAULT_RULES, modelConfigFromEnv, providerAdapter, suggestDefs, type FetchLike as ModelFetch, IMPORTERS, applySuggestion, rulesDigest, suggestWithRules, confirmDef, prepareReview, reviewQueueOrder, buildArtifacts, defsToYaml, diffPacks, explainDef, extendRegistry, loadActionsText, lintDefs, lintFails, lintText, packConsistencyError, packKeyOf,
  runDefTests, schemaFloorError, signPack, testText, toSarif, toSchemaDoc, verifyPack, attestationVerifier, reviewerPinsError, effective, type ReviewOpts, type ReviewerPins,
  RULES_DOC_KIND, STARTER_TEMPLATES, starterTemplate, businessRulesDigest, defDigest, explainBusinessRules, lintBusinessRules, runRuleExamples, signRulesReview, syncSource, syncText,
  type BusinessRules, type RulesDoc, type RulesReview, type SourceLock,
  type ActionDef, type ActionLoc, type ActionPackBody, type BuildConfig, type Finding, type Registry, type SignedActionPack, type Stability, type TraitDef,
} from '@atlasauth/pca-actions';
import { compileTraceRules, lethalTrifecta, parseTraceRule, TraceRuleError, type VerbTable } from '@atlasauth/pca-dataflow';
import { cmdSchemaPublish } from './schema';

export interface Out { ok: boolean; text: string }
const fail = (text: string): Out => ({ ok: false, text });

// ---- project files ---------------------------------------------------------------------------------------------------------

export const CONFIG_NAME = 'pca.config.json';
const SRC_EXT = new Set(['.yaml', '.yml', '.json']);
/** Project files that are not action files (the config, the sync lock, the reviewers' rules signatures). */
const PROJECT_META = new Set([CONFIG_NAME, 'pca.sync.json', 'pca.rules-reviews.json']);

/** The action files under `paths` (a file, or a directory searched recursively; dot-directories and node_modules skipped). Sorted. */
export function collectFiles(paths: readonly string[]): string[] {
  const out: string[] = [];
  const walk = (p: string, depth: number): void => {
    if (depth > 8) return;
    const st = statSync(p);
    if (st.isDirectory()) {
      for (const n of readdirSync(p).sort()) {
        if (n.startsWith('.') || n === 'node_modules') continue;
        walk(join(p, n), depth + 1);
      }
    } else if (SRC_EXT.has(extname(p)) && !PROJECT_META.has(basename(p))) out.push(p);
  };
  for (const p of paths) {
    if (!existsSync(p)) throw new Error(`no such file or directory: ${p}`);
    walk(p, 0);
  }
  return [...new Set(out)].sort();
}

/** `reviewers`: the reviewer keys YOUR registry pins. Only a confirmation signed by one of them counts; everything else is unconfirmed. */
/** The pinned identity of the builder that publishes this pack (a Sigstore signer-builder pair, track K9). */
export interface ProvenancePin { oidc_issuer: string; identity?: string; identity_prefix?: string; builder_id: string }
/** Trace rules (`<id>: never <B> after <A> within <duration>`) and the verbs whose output is untrusted content. */
export interface TraceConfig { rules: string[]; untrusted?: string[] }
/** An import source `pca actions sync` re-reads: a local file or an https URL of an OpenAPI / MCP tools / GraphQL / ... document. */
export interface SyncSourceConfig { name: string; from: string; file?: string; url?: string; verb?: string }
export interface Config extends BuildConfig { traits?: TraitDef[]; reviewers?: ReviewerPins; provenance?: ProvenancePin; trace?: TraceConfig; sources?: SyncSourceConfig[] }

/** K9 lint findings live outside LINT_RULES (whose digest pca-policy-ci pins). */
export const K9_LINT_RULES = [
  { id: 'LP-001', severity: 'warning', title: 'a beta or stable pack pins no builder identity (provenance)' },
  { id: 'LT-000', severity: 'error', title: 'a trace rule does not compile' },
  { id: 'LT-001', severity: 'warning', title: 'the lethal trifecta: untrusted content and private data can reach a send with no trace rule cutting either' },
] as const;

const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

/** Parse and check a config document. Returns the config or the reason. */
export function parseConfig(text: string): Config | string {
  let c: unknown;
  try { c = JSON.parse(text); } catch (e) { return `${CONFIG_NAME} is not JSON: ${(e as Error).message}`; }
  if (c === null || typeof c !== 'object' || Array.isArray(c)) return `${CONFIG_NAME} must be an object`;
  const o = c as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!['ns', 'version', 'stability', 'site', 'aud', 'traits', 'reviewers', 'provenance', 'trace', 'sources'].includes(k)) return `${CONFIG_NAME}: unknown member '${k}'`;
  if (typeof o.ns !== 'string' || !/^[a-z][a-z0-9_]{0,31}$/.test(o.ns)) return `${CONFIG_NAME}: ns must be a lowercase identifier`;
  if (typeof o.version !== 'string' || !SEMVER_RE.test(o.version)) return `${CONFIG_NAME}: version must be a semantic version`;
  if (!['draft', 'beta', 'stable'].includes(o.stability as string)) return `${CONFIG_NAME}: stability must be draft, beta or stable`;
  if (typeof o.site !== 'string' || o.site.length === 0 || o.site.length > 256) return `${CONFIG_NAME}: site is required`;
  if (typeof o.aud !== 'string' || o.aud.length === 0 || o.aud.length > 256) return `${CONFIG_NAME}: aud is required`;
  if (o.traits !== undefined && !Array.isArray(o.traits)) return `${CONFIG_NAME}: traits must be a list of trait definitions`;
  if (o.reviewers !== undefined) {
    const pe = reviewerPinsError(o.reviewers as ReviewerPins);
    if (pe) return `${CONFIG_NAME}: reviewers: ${pe}`;
  }
  if (o.provenance !== undefined) {
    const p = o.provenance as Record<string, unknown>;
    const s = (v: unknown) => typeof v === 'string' && v.length > 0 && v.length <= 2048;
    if (p === null || typeof p !== 'object' || Array.isArray(p) || Object.keys(p).some((k) => !['oidc_issuer', 'identity', 'identity_prefix', 'builder_id'].includes(k))) return `${CONFIG_NAME}: provenance must be {oidc_issuer, identity | identity_prefix, builder_id}`;
    if (!s(p.oidc_issuer) || !s(p.builder_id) || (p.identity === undefined) === (p.identity_prefix === undefined) || !(s(p.identity) || (s(p.identity_prefix) && (p.identity_prefix as string).length >= 10))) return `${CONFIG_NAME}: provenance needs oidc_issuer, builder_id and exactly one of identity / identity_prefix (at least 10 characters)`;
  }
  if (o.trace !== undefined) {
    const t = o.trace as Record<string, unknown>;
    if (t === null || typeof t !== 'object' || Array.isArray(t) || Object.keys(t).some((k) => !['rules', 'untrusted'].includes(k)) || !Array.isArray(t.rules) || !t.rules.every((r) => typeof r === 'string') || (t.untrusted !== undefined && !(Array.isArray(t.untrusted) && t.untrusted.every((u) => typeof u === 'string')))) return `${CONFIG_NAME}: trace must be {rules: string[], untrusted?: string[]}`;
  }
  if (o.sources !== undefined) {
    const se = sourcesError(o.sources);
    if (se) return `${CONFIG_NAME}: sources: ${se}`;
  }
  return { ns: o.ns, version: o.version, stability: o.stability as Stability, site: o.site, aud: o.aud, ...(o.traits ? { traits: o.traits as TraitDef[] } : {}), ...(o.reviewers ? { reviewers: o.reviewers as ReviewerPins } : {}), ...(o.provenance ? { provenance: o.provenance as ProvenancePin } : {}), ...(o.trace ? { trace: o.trace as TraceConfig } : {}), ...(o.sources ? { sources: o.sources as SyncSourceConfig[] } : {}) };
}

const SOURCE_KINDS = ['openapi', 'mcp', 'graphql', 'grpc', 'asyncapi', 'jsonschema'];

function sourcesError(x: unknown): string | null {
  if (!Array.isArray(x) || x.length === 0 || x.length > 32) return 'must be a list of 1..32 sources';
  const names = new Set<string>();
  for (const [i, v] of x.entries()) {
    const at = `sources[${i}]`;
    if (v === null || typeof v !== 'object' || Array.isArray(v)) return `${at} must be an object`;
    const e = v as Record<string, unknown>;
    for (const k of Object.keys(e)) if (!['name', 'from', 'file', 'url', 'verb'].includes(k)) return `${at}: unknown member '${k}'`;
    if (typeof e.name !== 'string' || !/^[a-z][a-z0-9_-]{0,31}$/.test(e.name) || names.has(e.name)) return `${at}: name must be a unique lowercase identifier`;
    names.add(e.name);
    if (!SOURCE_KINDS.includes(e.from as string)) return `${at}: from must be one of ${SOURCE_KINDS.join(', ')}`;
    if ((e.file === undefined) === (e.url === undefined)) return `${at}: exactly one of file / url`;
    if (e.file !== undefined && (typeof e.file !== 'string' || e.file.length === 0 || e.file.length > 1024)) return `${at}: file must be a path`;
    if (e.url !== undefined && (typeof e.url !== 'string' || !/^https:\/\/[^\s]{1,2040}$/.test(e.url))) return `${at}: url must be an https URL`;
    if ((e.from === 'jsonschema') !== (typeof e.verb === 'string')) return `${at}: verb is required for (and only for) a jsonschema source`;
  }
  return null;
}

/** The config next to the first path (a directory) or the file's directory. null if there is none. */
export function findConfig(paths: readonly string[]): Config | string | null {
  for (const p of paths) {
    const dir = existsSync(p) && statSync(p).isDirectory() ? p : dirname(p);
    const f = join(dir, CONFIG_NAME);
    if (existsSync(f)) return parseConfig(readFileSync(f, 'utf8'));
  }
  return null;
}

export interface Loaded {
  defs: ActionDef[];
  /** Verb to the file it came from. */
  files: Map<string, string>;
  /** Verb to the source position of its action (and params). */
  locs: Map<string, ActionLoc>;
  /** Namespace when every file agrees (else undefined). */
  ns: string | undefined;
  findings: Finding[];
  /** The business rules blocks by verb. */
  rules: Record<string, BusinessRules>;
}

/** Load every file. Load errors and notes become findings (LD-000 / LN-001); the defs that loaded are returned. */
export function loadProject(paths: readonly string[]): Loaded {
  const defs: ActionDef[] = [];
  const files = new Map<string, string>();
  const locs = new Map<string, ActionLoc>();
  const findings: Finding[] = [];
  const nss = new Set<string>();
  const rules: Record<string, BusinessRules> = {};
  for (const f of collectFiles(paths)) {
    const r = loadActionsText(readFileSync(f, 'utf8'), extname(f) === '.json' ? 'json' : 'yaml');
    if (r.ns) nss.add(r.ns);
    for (const e of r.errors) findings.push({ rule: 'LD-000', severity: 'error', file: f, ...(e.verb ? { verb: e.verb } : {}), message: e.message, ...(e.line !== undefined ? { line: e.line, column: e.column ?? 1 } : {}) });
    for (const n of r.notes) findings.push({ rule: 'LN-001', severity: 'note', file: f, ...(n.verb ? { verb: n.verb } : {}), message: n.message, ...(n.verb && r.locs[n.verb] ? { line: r.locs[n.verb]!.line, column: r.locs[n.verb]!.column } : {}) });
    for (const d of r.defs) {
      defs.push(d);
      if (!files.has(d.verb)) { files.set(d.verb, f); if (r.locs[d.verb]) locs.set(d.verb, r.locs[d.verb]!); }
      if (r.rules[d.verb] !== undefined && rules[d.verb] === undefined) rules[d.verb] = r.rules[d.verb]!;
    }
  }
  return { defs, files, locs, ns: nss.size === 1 ? [...nss][0] : undefined, findings, rules };
}

/** The review options under which a def counts as confirmed: a valid signature by a key the config pins as `reviewer`. Without pins nothing is. */
const reviewOf = (cfg: Config | null, reg: Registry): ReviewOpts => (cfg?.reviewers ? { attestationVerified: attestationVerifier({ pins: cfg.reviewers, registry: reg }) } : {});

/** One line telling the author how many actions are unconfirmed (and so treated as the most dangerous kind of action). */
function unconfirmedNote(defs: readonly ActionDef[], reg: Registry, review: ReviewOpts): string {
  const n = defs.filter((d) => !effective(d, reg, review).confirmed).length;
  return n === 0 ? '' : `
${n} of ${defs.length} action${defs.length === 1 ? ' is' : 's are'} not confirmed by a pinned reviewer: ${n === 1 ? 'it is' : 'they are'} treated as the most dangerous kind of action (every high-risk trait, step-up) until confirmed (pca actions confirm)`;
}

const registryOf = (cfg: Config | null): Registry | string => {
  if (!cfg?.traits || cfg.traits.length === 0) return CORE_REGISTRY;
  try { return extendRegistry(CORE_REGISTRY, cfg.traits); } catch (e) { return `custom traits: ${(e as Error).message}`; }
};

/** Lint a loaded project: load findings plus the rule findings, each attributed to its file. */
function lintLoaded(l: Loaded, cfg: Config | null): Finding[] {
  const reg = registryOf(cfg);
  const review = typeof reg === 'string' ? {} : reviewOf(cfg, reg);
  const fs = lintDefs(l.defs, { ...(cfg?.traits ? { customTraits: cfg.traits } : {}), ...review, ...(cfg ? { stability: cfg.stability } : {}), ...(l.ns ? { ns: l.ns } : {}) });
  const rf = l.defs.flatMap((d) => (l.rules[d.verb] !== undefined ? lintBusinessRules(d, l.rules[d.verb]) : []));
  return [...l.findings, ...[...fs, ...rf, ...(typeof reg === 'string' ? [] : k9Findings(l.defs, cfg, reg))].map((f) => {
    const loc = f.verb ? l.locs.get(f.verb) : undefined;
    const at = (f.param ? loc?.params[f.param] : undefined) ?? loc;
    return { ...f, ...(f.verb && l.files.has(f.verb) ? { file: l.files.get(f.verb)! } : {}), ...(at ? { line: at.line, column: at.column } : {}) };
  })];
}

/**
 * Track K9 lint: LP-001 (a beta or stable pack without a pinned builder identity), LT-000 (a trace rule that does not
 * compile) and LT-001 (the lethal trifecta left open). Rules compile against the union of the effective and hint trait
 * closures (an unconfirmed action has every trait: the strict reading for enforcement); the trifecta is classified from the
 * hint (declared and implied traits).
 */
export function k9Findings(defs: readonly ActionDef[], cfg: Config | null, reg: Registry): Finding[] {
  const out: Finding[] = [];
  if (cfg && cfg.stability !== 'draft' && !cfg.provenance) out.push({ rule: 'LP-001', severity: 'warning', message: `a ${cfg.stability} pack must pin the identity that builds it: add provenance {oidc_issuer, identity | identity_prefix, builder_id} to ${CONFIG_NAME}` });
  // compile against the strict table (an unconfirmed action has every trait, so a trait selector catches it); classify the
  // trifecta from what the actions declare and imply (the hint), so an unreviewed template is not reported as every leg at once
  const table: Record<string, { traits: string[]; effects: string[] }> = {};
  const declared: Record<string, { traits: string[]; effects: string[] }> = {};
  for (const d of defs) {
    const e = effective(d, reg);
    table[d.verb] = { traits: [...new Set([...e.closure, ...e.hint.closure])].sort(), effects: [...d.effects] };
    declared[d.verb] = { traits: [...e.hint.closure].sort(), effects: [...d.effects] };
  }
  let edges: ReturnType<typeof compileTraceRules>['edges'] = [];
  try {
    const rules = (cfg?.trace?.rules ?? []).map((r) => {
      const m = /^([a-z][a-z0-9_]{0,39}):\s*(.*)$/s.exec(r);
      if (!m) throw new TraceRuleError('syntax', `'${r}' must be '<id>: never <B> after <A> within <duration>'`);
      return parseTraceRule(m[1]!, m[2]!);
    });
    edges = compileTraceRules(rules, table as VerbTable).edges;
  } catch (e) {
    out.push({ rule: 'LT-000', severity: 'error', message: e instanceof Error ? e.message : 'trace rules do not compile' });
    return out;
  }
  for (const f of lethalTrifecta(declared, edges, { untrusted: cfg?.trace?.untrusted ?? [] }).findings) {
    out.push({ rule: 'LT-001', severity: 'warning', verb: f.send, message: `untrusted content (${f.from_untrusted.join(', ')}) and private data (${f.from_private.join(', ')}) can reach this send: add a trace rule 'never tool:${f.send} after tool:${f.from_untrusted[0]} within <duration>' (or cut the private leg)` });
  }
  return out;
}

// ---- init ------------------------------------------------------------------------------------------------------------------------

const HELLO = (ns: string): string => `# Actions for ${ns}. Everything not written here is defaulted: run \`pca actions explain ${ns}.invoice.send\` to see the result.
ns: ${ns}
since: 0.1.0
actions:
  - verb: ${ns}.invoice.send
    title: Send an invoice
    description: Emails an existing invoice to the customer.
    effects: [send]
    resource: ${ns}.invoice:inv_*       # {type: ${ns}.invoice, id: {prefix: inv_, class: alnum, len: [8, 32]}, scope: one}
    params:
      invoice: id:${ns}.invoice
      to: email                         # role contact.email, format email, tag pii
      note: message(500)                # free text that leaves the organisation
    # idempotency_key is added for you (send is not safe to repeat); reversibility defaults to irreversible
    examples:
      - params: {invoice: inv_12345678, to: a@b.com, note: hi, idempotency_key: k_12345678}
        under:
          allow: {trait: external_communication, where: {to.domain: [b.com]}, caveats: [rate_cap, resource_scope], context: [fresh_revocation]}
        expect: allow
      - params: {invoice: inv_12345678, to: a@evil.com, note: hi, idempotency_key: k_12345678}
        expect: escalate
`;

const SAAS = (ns: string): string => `ns: ${ns}
since: 0.1.0
actions:
  - verb: ${ns}.invoice.send
    title: Send an invoice
    description: Emails an existing invoice to the customer.
    effects: [send]
    resource: ${ns}.invoice:inv_*
    params:
      invoice: id:${ns}.invoice
      to: email
      note: message(500)
    examples:
      - params: {invoice: inv_12345678, to: a@b.com, note: hi, idempotency_key: k_12345678}
        under:
          allow: {trait: external_communication, where: {to.domain: [b.com]}, caveats: [rate_cap, resource_scope], context: [fresh_revocation]}
        expect: allow
  - verb: ${ns}.charge.refund
    title: Refund a charge
    description: Returns money for a charge to the customer.
    effects: [pay]
    resource: ${ns}.charge:ch_*
    params:
      charge: id:${ns}.charge
      amount: money(USD, max=100000)
    examples:
      - params: {charge: ch_12345678, amount: 2500, idempotency_key: k_12345678}
        under:
          allow: {trait: money_moving, where: {amount: {max: 5000}}, caveats: [count_cap, window], context: [fresh_revocation]}
        expect: allow
      - params: {charge: ch_12345678, amount: 2500, idempotency_key: k_12345678}
        expect: escalate
  - verb: ${ns}.customer.delete
    title: Delete a customer
    description: Permanently deletes a customer record.
    effects: [delete]
    resource: ${ns}.customer:cus_*
    params:
      customer: id:${ns}.customer
    examples:
      - params: {customer: cus_12345678}
        expect: escalate
`;

const DB = (ns: string): string => `ns: ${ns}
since: 0.1.0
actions:
  - verb: ${ns}.row.get
    title: Read a row
    description: Reads one row by its key.
    effects: [read]
    resource: ${ns}.row:row_*
    params:
      row: id:${ns}.row
  - verb: ${ns}.row.delete
    title: Delete a row
    description: Deletes one row by its key.
    effects: [delete]
    resource: ${ns}.row:row_*
    params:
      row: id:${ns}.row
    examples:
      - params: {row: row_12345678}
        expect: escalate
`;

const MCP = (ns: string): string => `ns: ${ns}
since: 0.1.0
actions:
  - verb: ${ns}.note.append
    title: Append a note
    description: Adds a note to a document through the MCP tool of the same name.
    effects: [update]
    resource: ${ns}.document:doc_*
    params:
      document: id:${ns}.document
      text: message(2000)
    bindings: {mcp: {tool: append_note}}
`;

export const ACTION_TEMPLATES: Record<string, (ns: string) => string> = { minimal: HELLO, saas: SAAS, db: DB, mcp: MCP };

/**
 * Scaffold a project. `template` is a small authoring example (minimal, saas, db, mcp) or a starter pack for a business type
 * (ecommerce, fintech, healthcare, saas_admin, devtools: typical actions, custom traits written to the config, business rules
 * with examples). A starter pack is a draft the platform must review: nothing in it is confirmed.
 */
export function cmdInit(o: { dir: string; ns: string; template?: string; force?: boolean }): Out {
  const id = o.template ?? 'minimal';
  const tpl = ACTION_TEMPLATES[id];
  const starter = tpl ? undefined : starterTemplate(id);
  if (!tpl && !starter) return fail(`unknown template '${o.template}' (${[...Object.keys(ACTION_TEMPLATES), ...STARTER_TEMPLATES.map((t) => t.id)].join(', ')})`);
  if (!/^[a-z][a-z0-9_]{0,31}$/.test(o.ns) || (starter && o.ns === 'pca')) return fail('--ns must be a lowercase identifier (a-z, 0-9, _)');
  const yaml = join(o.dir, `${o.ns}.yaml`);
  const cfg = join(o.dir, CONFIG_NAME);
  if (!o.force && (existsSync(yaml) || existsSync(cfg))) return fail(`${existsSync(yaml) ? yaml : cfg} already exists (use --force to overwrite)`);
  mkdirSync(o.dir, { recursive: true });
  writeFileSync(yaml, starter ? starter.yaml(o.ns) : tpl!(o.ns));
  const config = { ns: o.ns, version: '0.1.0', stability: 'draft', site: `https://${o.ns}.example.com`, aud: `${o.ns}-api`, ...(starter ? { traits: starter.traits(o.ns) } : {}) };
  writeFileSync(cfg, JSON.stringify(config, null, 2) + '\n');
  return { ok: true, text: `wrote ${yaml}, ${cfg}${starter ? `\n${starter.title}: a starter pack to adapt. Every action is unreviewed (treated as the most dangerous kind) until a reviewer confirms it (pca actions confirm).` : ''}` };
}

// ---- import ----------------------------------------------------------------------------------------------------------------------

export function cmdImport(src: string, o: { from: string; ns: string; uri?: string; licence?: string; verb?: string; suggest?: string }): { ok: boolean; yaml: string; todo: string[]; text: string } {
  const imp = IMPORTERS[o.from];
  if (!imp) return { ok: false, yaml: '', todo: [], text: `unknown source '${o.from}' (${Object.keys(IMPORTERS).sort().join(', ')})` };
  if (!/^[a-z][a-z0-9_]{0,31}$/.test(o.ns)) return { ok: false, yaml: '', todo: [], text: '--ns must be a lowercase identifier (a-z, 0-9, _)' };
  if (o.suggest !== undefined && o.suggest !== 'rules' && o.suggest !== 'none') return { ok: false, yaml: '', todo: [], text: '--suggest rules|none (model assist: cmdImportModel / the CLI with --suggest model)' };
  let doc: unknown;
  // GraphQL SDL and .proto are text; the rest are JSON
  if (o.from === 'graphql' || o.from === 'grpc') {
    if (o.from === 'graphql' && src.trimStart().startsWith('{')) { try { doc = JSON.parse(src); } catch { doc = src; } } else doc = src;
  } else {
    try { doc = JSON.parse(src); } catch (e) { return { ok: false, yaml: '', todo: [], text: `the source is not JSON: ${(e as Error).message}` }; }
  }
  try {
    const r = imp(doc, { ns: o.ns, ...(o.uri ? { uri: o.uri } : {}), ...(o.licence ? { licence: o.licence } : {}), ...(o.verb ? { verb: o.verb } : {}) });
    if (o.suggest !== 'none') {
      const rules = DEFAULT_RULES;
      r.defs = r.defs.map((d) => { const sg = suggestWithRules(d, rules, CORE_REGISTRY); return applySuggestion(d, sg, { rules: { version: rules.version, digest: rulesDigest(rules), fired: sg.fired } }); });
    }
    return { ok: true, yaml: defsToYaml(o.ns, r.defs), todo: r.todo, text: `${r.defs.length} draft action${r.defs.length === 1 ? '' : 's'} (unreviewed: every one escalates until confirmed)` };
  } catch (e) {
    return { ok: false, yaml: '', todo: [], text: (e as Error).message };
  }
}

/**
 * The defs of a catalog pack as an actions document, for the batch review: `ref` is a pack directory (it holds pack.json) or a pack name
 * under `packsDir` (the newest version). A pack ships with the machine's traits as HINTS only: every def is unconfirmed (maximally
 * dangerous) until `pca actions confirm --pack <name> --origin any` signs it with a pinned reviewer key.
 */
export function packText(ref: string, packsDir = 'packs'): { ok: boolean; text: string; ns?: string } {
  const dir = existsSync(join(ref, 'pack.json')) ? ref : (() => {
    const base = join(packsDir, ref);
    if (!existsSync(base)) return null;
    const vs = readdirSync(base).filter((v) => existsSync(join(base, v, 'pack.json'))).sort();
    return vs.length ? join(base, vs[vs.length - 1]!) : null;
  })();
  if (dir === null) return { ok: false, text: `no pack '${ref}' (a pack directory, or a name under ${packsDir})` };
  try {
    const m = JSON.parse(readFileSync(join(dir, 'pack.json'), 'utf8')) as { ns: string[] | string; shards: { file: string }[] };
    const defs: ActionDef[] = [];
    for (const sh of m.shards) for (const line of readFileSync(join(dir, sh.file), 'utf8').split('\n')) if (line) defs.push(JSON.parse(line) as ActionDef);
    const ns = Array.isArray(m.ns) ? m.ns[0]! : m.ns;
    return { ok: true, text: defsToYaml(ns, defs), ns };
  } catch (e) {
    return { ok: false, text: `cannot read pack '${ref}': ${(e as Error).message}` };
  }
}

/**
 * `pca actions confirm <verb>... --reviewer-key K --kid ID [--final t1,t2] [--dismiss trait=reason ...]`: review and sign. Without
 * `--yes` it only prints the review (def, suggested traits, card). `keyHex` is the reviewer secret as base64url; the caller pins it.
 */
export function cmdConfirm(text: string, o: { verbs: string[]; kid: string; secret?: string; final?: string[]; dismiss?: string[]; yes: boolean; ts: number; origin?: string; trait?: string }): { ok: boolean; yaml: string; text: string; rulesReviews?: Record<string, RulesReview> } {
  const l = loadActionsText(text);
  if (l.errors.length > 0) return { ok: false, yaml: '', text: l.errors[0]!.message };
  // --origin union [--trait T]: batch-review the traits the fail-strict union added from the suggestion rules (every such def, or those that
  // carry T); a verb list narrows it further. Dropping such a trait still needs --dismiss trait=reason and a signed attestation (--yes).
  // --origin any: every def of the input (a whole pack via --pack): the batch flow that turns an inert-strict pack into a reviewed one.
  if (o.origin !== undefined && o.origin !== 'union' && o.origin !== 'any') return { ok: false, yaml: '', text: `--origin must be 'union' or 'any' (got '${o.origin}')` };
  const wantTrait = o.trait === undefined ? undefined : o.trait.startsWith('pca.') ? o.trait : `pca.${o.trait}`;
  if (o.origin !== 'union' && o.trait !== undefined) return { ok: false, yaml: '', text: '--trait needs --origin union' };
  const byOrigin = (d: ActionDef): boolean => o.origin === undefined || o.origin === 'any' || (d.review.provenance?.union ?? []).some((t) => wantTrait === undefined || t === wantTrait);
  const missing = o.verbs.filter((v) => !l.defs.some((d) => d.verb === v));
  if (missing.length > 0) return { ok: false, yaml: '', text: `no such verb: ${missing.join(', ')}` };
  const want = new Set(l.defs.filter((d) => (o.verbs.length === 0 ? o.origin !== undefined : o.verbs.includes(d.verb)) && byOrigin(d)).map((d) => d.verb));
  if (want.size === 0) return { ok: false, yaml: '', text: o.origin ? `no def carries a union-added ${wantTrait ?? 'trait'} to review` : 'nothing to review' };
  const targets = reviewQueueOrder(l.defs.filter((d) => want.has(d.verb)), CORE_REGISTRY);
  const fromUnion = (d: ActionDef): string => ((d.review.provenance?.union ?? []).length ? `  added from the suggestion rules (union): ${(d.review.provenance?.union ?? []).join(', ')}` : '');
  const lines: string[] = [];
  // a whole pack is thousands of defs: print the first 40 (riskiest first), then the count; nothing is signed without --yes
  for (const d of o.origin === 'any' ? targets.slice(0, 40) : targets) {
    const v = prepareReview(d, CORE_REGISTRY);
    lines.push(`${d.verb}  [${v.state}]  risk ${v.card.risk}, ${v.card.escalation}, ${v.card.reversibility}`, `  ${v.card.text}`, `  declared: ${v.declared_traits.join(', ') || '-'}`, `  implied: ${v.implied_traits.join(', ') || '-'}`, `  suggested: ${v.suggested.traits.join(', ') || '-'}`);
    if (fromUnion(d)) lines.push(fromUnion(d));
  }
  if (o.origin === 'any' && targets.length > 40) lines.push(`... and ${targets.length - 40} more (${targets.length} in all)`);
  if (!o.yes) return { ok: true, yaml: '', text: lines.join('\n') + '\n(nothing signed: pass --yes with --reviewer-key to confirm)' };
  if (!o.secret) return { ok: false, yaml: '', text: '--reviewer-key is required to confirm' };
  let sk: Uint8Array;
  try { sk = unb64u(o.secret); if (sk.length !== 32) throw new Error('length'); } catch { return { ok: false, yaml: '', text: '--reviewer-key must be a 32-byte Ed25519 secret as base64url' }; }
  const dismissed = (o.dismiss ?? []).map((x) => { const i = x.indexOf('='); return { trait: x.slice(0, i), reason: x.slice(i + 1) }; });
  try {
    const out = l.defs.map((d) => {
      if (!want.has(d.verb)) return d;
      const sb = (d.review.suggested_by ?? {}) as { added?: { traits?: string[] } };
      const final = o.final ?? [...new Set([...(d.traits ?? []), ...(sb.added?.traits ?? [])])].filter((t) => !dismissed.some((x) => x.trait === t));
      return confirmDef(d, { registry: CORE_REGISTRY, reviewer: { kid: o.kid, secret: sk }, finalTraits: final, dismissed, ts: o.ts });
    });
    // the reviewer confirms each confirmed action's business rules too (a signature over the def and the rules digests)
    const rulesReviews: Record<string, RulesReview> = {};
    for (const d of out) {
      const rules = l.rules[d.verb];
      if (!want.has(d.verb) || rules === undefined) continue;
      rulesReviews[d.verb] = signRulesReview({ verb: d.verb, def_digest: defDigest(d), rules_digest: businessRulesDigest(d.verb, rules), reviewer_kid: o.kid, ts: o.ts }, sk);
    }
    const nr = Object.keys(rulesReviews).length;
    return { ok: true, yaml: defsToYaml(l.ns ?? 'ns', out, l.rules), rulesReviews, text: `${targets.length} confirmed by ${o.kid}${nr ? ` (and the business rules of ${nr})` : ''} (the attestation is valid only against the reviewer keys your registry pins)` };
  } catch (e) {
    return { ok: false, yaml: '', text: (e as Error).message };
  }
}

/**
 * `import --suggest model`: the rules plus a pinned model (names and types only). Async because it calls the provider; the key
 * is read from the environment only. Output defs are `suggested`, still unreviewed.
 */
export async function cmdImportModel(src: string, o: Parameters<typeof cmdImport>[1] & { model?: string; provider?: string }, env: Record<string, string | undefined>, fetchImpl: ModelFetch): Promise<ReturnType<typeof cmdImport>> {
  const base = cmdImport(src, { ...o, suggest: 'rules' });
  if (!base.ok) return base;
  try {
    const cfg = modelConfigFromEnv(env, { ...(o.model ? { model: o.model } : {}), ...(o.provider ? { provider: o.provider } : {}) });
    const imp = IMPORTERS[o.from]!;
    const doc = o.from === 'graphql' || o.from === 'grpc' ? src : JSON.parse(src);
    const r = imp(doc, { ns: o.ns, ...(o.uri ? { uri: o.uri } : {}), ...(o.licence ? { licence: o.licence } : {}), ...(o.verb ? { verb: o.verb } : {}) });
    const s = await suggestDefs(r.defs, { mode: 'model', models: [providerAdapter(cfg, fetchImpl)] });
    const todo = [...r.todo, ...s.errors.map((e) => `${e.verb}: model ${e.model} gave no suggestion (${e.error})`)];
    return { ok: true, yaml: defsToYaml(o.ns, s.defs), todo, text: `${s.defs.length} draft action${s.defs.length === 1 ? '' : 's'} (suggested by rules and ${cfg.provider}:${cfg.model}; still unreviewed: every one escalates until confirmed)` };
  } catch (e) {
    return { ok: false, yaml: '', todo: [], text: (e as Error).message };
  }
}

// ---- lint / test / explain / diff -------------------------------------------------------------------------------------------

export function cmdLint(paths: readonly string[], o: { strict?: boolean; format?: 'text' | 'sarif' } = {}): Out {
  const cfg = findConfig(paths);
  if (typeof cfg === 'string') return fail(cfg);
  const l = loadProject(paths);
  const fs = lintLoaded(l, cfg);
  const bad = lintFails(fs, o.strict === true);
  if (o.format === 'sarif') return { ok: !bad, text: JSON.stringify(toSarif(fs), null, 2) };
  return { ok: !bad, text: lintText(fs) };
}

export function cmdTest(paths: readonly string[]): Out {
  const cfg = findConfig(paths);
  if (typeof cfg === 'string') return fail(cfg);
  const reg = registryOf(cfg);
  if (typeof reg === 'string') return fail(reg);
  const l = loadProject(paths);
  const errs = l.findings.filter((f) => f.severity === 'error');
  if (errs.length > 0) return fail(lintText(errs));
  const r = runDefTests(l.defs, reg);
  const ruleLines: string[] = [];
  let rulesOk = true;
  for (const d of l.defs) {
    const rules = l.rules[d.verb];
    if (rules === undefined) continue;
    try {
      for (const x of runRuleExamples(d, rules)) {
        if (!x.ok) rulesOk = false;
        ruleLines.push(`${x.ok ? 'PASS' : 'FAIL'}  ${d.verb} rules example ${x.index + 1}: expected ${x.expect}, got ${x.got} (${x.why})`);
      }
    } catch (e) {
      rulesOk = false;
      ruleLines.push(`FAIL  ${d.verb} rules: ${(e as Error).message}`);
    }
  }
  return { ok: r.ok && rulesOk, text: testText(r) + (ruleLines.length ? `\n${ruleLines.join('\n')}` : '') + unconfirmedNote(l.defs, reg, reviewOf(cfg, reg)) };
}

export function cmdActionExplain(paths: readonly string[], verb: string): Out {
  const cfg = findConfig(paths);
  if (typeof cfg === 'string') return fail(cfg);
  const reg = registryOf(cfg);
  if (typeof reg === 'string') return fail(reg);
  const l = loadProject(paths);
  const d = l.defs.find((x) => x.verb === verb || (x.aliases ?? []).includes(verb));
  if (!d) return fail(`no action '${verb}' in ${paths.join(', ')}`);
  const rules = l.rules[d.verb];
  let rulesText = '';
  if (rules !== undefined) {
    try { rulesText = `\nbusiness rules:\n${explainBusinessRules(d, rules).map((x) => `  - ${x}`).join('\n')}`; } catch (e) { return fail(`business rules of ${d.verb}: ${(e as Error).message}`); }
  }
  return { ok: true, text: explainDef(d, reg, reviewOf(cfg, reg)) + rulesText };
}

export function cmdDiff(oldPaths: readonly string[], newPaths: readonly string[]): Out {
  const cfg = findConfig(newPaths);
  if (typeof cfg === 'string') return fail(cfg);
  const reg = registryOf(cfg);
  if (typeof reg === 'string') return fail(reg);
  const a = loadProject(oldPaths);
  const b = loadProject(newPaths);
  const errs = [...a.findings, ...b.findings].filter((f) => f.severity === 'error');
  if (errs.length > 0) return fail(lintText(errs));
  const rows = diffPacks(a.defs, b.defs, reg);
  const lines = rows.map((r) => `${r.class.padEnd(12)} ${r.verb}${r.breaking ? '  (breaking)' : ''}${r.reasons.length ? '\n' + r.reasons.map((x) => `    ${x}`).join('\n') : ''}`);
  const worst = rows.some((r) => r.class === 'widen' || r.class === 'incomparable' || r.class === 'removed');
  return { ok: !worst, text: `${lines.join('\n') || 'no actions'}\n${worst ? 'widens authority (needs re-approval)' : 'no widening'}` };
}

// ---- build / sign / publish --------------------------------------------------------------------------------------------------

export const DEFAULT_OUT = '.pca';

export function cmdBuild(paths: readonly string[], o: { out?: string } = {}): Out {
  const cfg = findConfig(paths);
  if (cfg === null) return fail(`no ${CONFIG_NAME} next to ${paths.join(', ')} (run pca actions init)`);
  if (typeof cfg === 'string') return fail(cfg);
  const reg = registryOf(cfg);
  if (typeof reg === 'string') return fail(reg);
  const l = loadProject(paths);
  const fs = lintLoaded(l, cfg);
  if (lintFails(fs)) return fail(`${lintText(fs)}\nnot building: fix the errors above`);
  let b;
  const review = reviewOf(cfg, reg);
  try { b = buildArtifacts(l.defs, cfg, reg, review); } catch (e) { return fail((e as Error).message); }
  const out = o.out ?? DEFAULT_OUT;
  mkdirSync(out, { recursive: true });
  const w = (n: string, v: unknown): void => writeFileSync(join(out, n), typeof v === 'string' ? v : JSON.stringify(v, null, 2) + '\n');
  w('schema.json', b.schema); w('pack.json', b.pack); w('cards.json', b.cards); w('ontology.json', b.ontology); w('mcp.json', b.mcp); w('types.d.ts', b.types);
  w('rules.json', rulesDocOf(cfg.ns, l, projectDir(paths)));
  return { ok: true, text: `built ${l.defs.length} action${l.defs.length === 1 ? '' : 's'} into ${out} (pack root ${b.pack.root})${unconfirmedNote(l.defs, reg, review)}` };
}

const readJson = (f: string): unknown => JSON.parse(readFileSync(f, 'utf8'));

/** The directory holding the project's config (the first path when a directory, else its directory). */
export function projectDir(paths: readonly string[]): string {
  const p = paths[0] ?? 'actions';
  return existsSync(p) && statSync(p).isDirectory() ? p : dirname(p);
}

export const RULES_REVIEWS_NAME = 'pca.rules-reviews.json';

/** Merge rules reviews into the project's reviews file (a later review of a verb replaces the earlier one). */
export function writeRulesReviews(dir: string, add: Record<string, RulesReview>): string {
  const f = join(dir, RULES_REVIEWS_NAME);
  let cur: Record<string, RulesReview> = {};
  if (existsSync(f)) { try { cur = readJson(f) as Record<string, RulesReview>; } catch { cur = {}; } }
  writeFileSync(f, JSON.stringify({ ...cur, ...add }, null, 2) + '\n');
  return f;
}

/** The rules document of a build: every action's business rules, with the reviews that still match them (a stale one is dropped). */
function rulesDocOf(ns: string, l: Loaded, dir: string): RulesDoc {
  let reviews: Record<string, RulesReview> = {};
  const f = join(dir, RULES_REVIEWS_NAME);
  if (existsSync(f)) { try { reviews = readJson(f) as Record<string, RulesReview>; } catch { reviews = {}; } }
  const keep: Record<string, RulesReview> = {};
  for (const d of l.defs) {
    const r = reviews[d.verb];
    const rules = l.rules[d.verb] ?? {};
    if (r && r.def_digest === defDigest(d) && r.rules_digest === businessRulesDigest(d.verb, rules)) keep[d.verb] = r;
  }
  return { v: 1, kind: RULES_DOC_KIND, ns, rules: l.rules, ...(Object.keys(keep).length ? { reviews: keep } : {}) };
}

function secretOf(key: string): Uint8Array {
  const raw = key.startsWith('@') ? readFileSync(key.slice(1), 'utf8') : key;
  const sk = unb64u(raw.trim());
  if (sk.length !== 32) throw new Error('a signing key must be a base64url 32-byte Ed25519 secret');
  return sk;
}

/**
 * Sign the built schema (as the site) and pack (as the registry). Re-derives the schema from the pack's defs and refuses a
 * build whose files disagree, a pack that is not internally consistent, a schema whose floors do not match its traits, and (for
 * a stable pack) any lint warning.
 */
export function cmdSign(paths: readonly string[], o: { out?: string; kid: string; key: string; packKid?: string; packKey?: string }): Out {
  const out = o.out ?? DEFAULT_OUT;
  const cfg = findConfig(paths);
  if (cfg === null) return fail(`no ${CONFIG_NAME} next to ${paths.join(', ')}`);
  if (typeof cfg === 'string') return fail(cfg);
  const reg = registryOf(cfg);
  if (typeof reg === 'string') return fail(reg);
  let schema: UnsignedActionSchema;
  let pack: ActionPackBody;
  try { schema = readJson(join(out, 'schema.json')) as UnsignedActionSchema; pack = readJson(join(out, 'pack.json')) as ActionPackBody; } catch (e) { return fail(`run pca actions build first (${(e as Error).message})`); }
  const bad = packConsistencyError(pack, reg);
  if (bad) return fail(`not signing: ${bad}`);
  const review = reviewOf(cfg, reg);
  const again = toSchemaDoc(pack.defs, reg, { site: cfg.site, aud: cfg.aud, version: pack.version, pack: { ns: pack.ns, version: pack.version, root: pack.root } }, review);
  if (hashCanonical(again) !== hashCanonical(schema)) return fail('not signing: schema.json is not what the pack derives (rebuild)');
  const fe = schemaFloorError(schema as ActionSchema, cfg.reviewers);
  if (fe) return fail(`not signing: ${fe}`);
  const lint = lintDefs(pack.defs, { ...(cfg.traits ? { customTraits: cfg.traits } : {}), ...review, stability: pack.stability });
  if (lintFails(lint, pack.stability === 'stable')) return fail(`${lintText(lint)}\nnot signing: ${pack.stability === 'stable' ? 'a stable pack must be lint-clean' : 'fix the errors above'}`);
  try {
    const sk = secretOf(o.key);
    const psk = o.packKey !== undefined ? secretOf(o.packKey) : sk;
    const signed = signActionSchema(schema, o.kid, sk);
    const signedPack = signPack(pack, o.packKid ?? o.kid, psk, reg);
    const keys = [actionSchemaKeyOf(o.kid, sk), ...(o.packKey !== undefined || o.packKid !== undefined ? [packKeyOf(o.packKid ?? o.kid, psk)] : [])];
    writeFileSync(join(out, 'pca-actions.json'), JSON.stringify(signed, null, 2) + '\n');
    writeFileSync(join(out, 'pack.signed.json'), JSON.stringify(signedPack, null, 2) + '\n');
    writeFileSync(join(out, 'keys.json'), JSON.stringify(keys, null, 2) + '\n');
    return { ok: true, text: `signed schema ${actionSchemaDigest(signed)} and pack ${pack.root}\nkeys: ${join(out, 'keys.json')} (list them under intent.schema_keys in your discovery document)` };
  } catch (e) {
    return fail(`not signing: ${(e as Error).message}`);
  }
}

type FetchLike = Parameters<typeof cmdSchemaPublish>[2]['fetchImpl'];

/**
 * Publish: verify the signed schema and pack, write the discovery file (`<out>/.well-known/pca-actions.json`) and, with
 * `--api` and `--sk`, anchor the schema in an Atlas instance's intent transparency log.
 */
export async function cmdPublish(paths: readonly string[], o: { out?: string; api?: string; sk?: string; fetchImpl?: FetchLike }): Promise<Out> {
  const out = o.out ?? DEFAULT_OUT;
  const cfg = findConfig(paths);
  if (typeof cfg === 'string') return fail(cfg);
  const reg = registryOf(cfg);
  if (typeof reg === 'string') return fail(reg);
  let schemaText: string;
  let keysText: string;
  let pack: SignedActionPack;
  try {
    schemaText = readFileSync(join(out, 'pca-actions.json'), 'utf8');
    keysText = readFileSync(join(out, 'keys.json'), 'utf8');
    pack = readJson(join(out, 'pack.signed.json')) as SignedActionPack;
  } catch (e) { return fail(`run pca actions build and sign first (${(e as Error).message})`); }
  const keys = JSON.parse(keysText) as { kid: string; alg: 'ed25519'; pk: string }[];
  const sv = verifyActionSchema(JSON.parse(schemaText), keys as never);
  if (!sv.ok) return fail(`not publishing: ${sv.reason}`);
  const pv = verifyPack(pack, keys, reg);
  if (!pv.ok) return fail(`not publishing: ${pv.reason}`);
  const wk = join(out, '.well-known');
  mkdirSync(wk, { recursive: true });
  writeFileSync(join(wk, 'pca-actions.json'), schemaText);
  let text = `wrote ${join(wk, 'pca-actions.json')}`;
  if (o.api !== undefined || o.sk !== undefined) {
    if (!o.api || !o.sk) return fail('publish: --api and --sk go together');
    const r = await cmdSchemaPublish(schemaText, keysText, { api: o.api, secretKey: o.sk, ...(o.fetchImpl ? { fetchImpl: o.fetchImpl } : {}) });
    if (!r.ok) return fail(r.text);
    text += `\n${r.text}`;
    let rules: unknown;
    try { rules = existsSync(join(out, 'rules.json')) ? readJson(join(out, 'rules.json')) : undefined; } catch (e) { return fail(`rules.json is not JSON: ${(e as Error).message}`); }
    const reg2 = await publishToRegistry({ api: o.api, sk: o.sk, pack, ...(rules !== undefined ? { rules } : {}), ...(cfg?.traits ? { traits: cfg.traits } : {}), ...(o.fetchImpl ? { fetchImpl: o.fetchImpl } : {}) });
    if (!reg2.ok) return fail(`${text}\n${reg2.text}`);
    text += `\n${reg2.text}`;
  }
  return { ok: true, text };
}

/**
 * Publish the signed pack (with its business rules and custom traits) to the instance's hosted action registry. The pack key
 * must be pinned on the instance as a publisher key. A version that widens an action's authority or rules without a reviewer's
 * signature is refused, and the refusal names the actions to review.
 */
export async function publishToRegistry(o: { api: string; sk: string; pack: SignedActionPack; rules?: unknown; traits?: TraitDef[]; fetchImpl?: FetchLike }): Promise<Out> {
  const f = (o.fetchImpl ?? (globalThis as { fetch?: FetchLike }).fetch) as FetchLike | undefined;
  if (!f) return fail('no fetch available');
  const res = await f(o.api.replace(/\/+$/, '') + '/v1/pca/action-registry/packs', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${o.sk}` },
    body: JSON.stringify({ pack: o.pack, ...(o.rules !== undefined ? { rules: o.rules } : {}), ...(o.traits ? { traits: o.traits } : {}) }),
  });
  const body = (await res.json().catch(() => null)) as {
    version?: string; status?: string; changes?: Array<{ verb: string; class: string; reasons?: string[] }>;
    errors?: Array<{ message?: string; meta?: { reason_code?: string; verbs?: string[] } }>;
  } | null;
  if (!(res.status >= 200 && res.status < 300)) {
    const e = body?.errors?.[0];
    const verbs = e?.meta?.verbs ?? [];
    return fail(`FAIL  the registry refused the pack (${res.status}${e?.meta?.reason_code ? ` ${e.meta.reason_code}` : ''}): ${e?.message ?? 'no reason given'}${verbs.length ? `\n  needs a reviewer: ${verbs.join(', ')}` : ''}`);
  }
  const changes = (body?.changes ?? []).map((c) => `  ${c.class.padEnd(12)} ${c.verb}${c.reasons?.length ? `: ${c.reasons.join(', ')}` : ''}`);
  return { ok: true, text: `registry: ${o.pack.ns}@${body?.version ?? o.pack.version} ${body?.status ?? 'stored'}${changes.length ? `\n${changes.join('\n')}` : ''}` };
}

// ---- sync ----------------------------------------------------------------------------------------------------------------------

export const SYNC_LOCK_NAME = 'pca.sync.json';
/** A fetched source above this is refused (the import's own limits apply on top). */
export const SYNC_MAX_BYTES = 16 * 1024 * 1024;
const SYNC_TIMEOUT_MS = 30_000;

/** Read a source: a file relative to the project directory, or an https URL (no redirects, bounded size and time). */
/** The fetch `sync` reads an https source with (injectable for tests). */
export type SourceFetch = (url: string, init: { method: 'GET'; headers: Record<string, string>; redirect: 'error'; signal: AbortSignal }) => Promise<{ ok: boolean; status: number; headers: { get(name: string): string | null }; text(): Promise<string> }>;

async function readSourceOf(src: SyncSourceConfig, dir: string, fetchImpl?: SourceFetch): Promise<string> {
  if (src.file !== undefined) {
    const f = join(dir, src.file);
    if (statSync(f).size > SYNC_MAX_BYTES) throw new Error(`${src.file} is larger than ${SYNC_MAX_BYTES} bytes`);
    return readFileSync(f, 'utf8');
  }
  const fx = (fetchImpl ?? (globalThis as { fetch?: SourceFetch }).fetch) as SourceFetch | undefined;
  if (!fx) throw new Error('no fetch available');
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), SYNC_TIMEOUT_MS);
  try {
    const res = await fx(src.url!, { method: 'GET', headers: { accept: 'application/json, application/yaml, text/plain' }, redirect: 'error', signal: ctl.signal });
    if (!res.ok) throw new Error(`${src.url} answered ${res.status}`);
    const len = Number(res.headers.get('content-length') ?? 0);
    if (len > SYNC_MAX_BYTES) throw new Error(`${src.url} is larger than ${SYNC_MAX_BYTES} bytes`);
    const text = await res.text();
    if (text.length > SYNC_MAX_BYTES) throw new Error(`${src.url} is larger than ${SYNC_MAX_BYTES} bytes`);
    return text;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Re-import every configured source (or one, `source`), compare with the last sync (`pca.sync.json`) and rewrite the source's
 * file `<name>.sync.yaml`: added and changed operations land UNREVIEWED (strict until a reviewer confirms them), unchanged ones
 * keep their review and business rules, removed ones leave the file (the next publish deprecates them). With `check`, nothing
 * is written and the result fails when anything changed (for CI).
 */
export async function cmdSync(paths: readonly string[], o: { source?: string; check?: boolean; now?: number; fetchImpl?: SourceFetch } = {}): Promise<Out> {
  const cfg = findConfig(paths);
  if (cfg === null) return fail(`no ${CONFIG_NAME} next to ${paths.join(', ')}`);
  if (typeof cfg === 'string') return fail(cfg);
  if (!cfg.sources || cfg.sources.length === 0) return fail(`${CONFIG_NAME} names no sources (add "sources": [{"name", "from", "url" | "file"}])`);
  const reg = registryOf(cfg);
  if (typeof reg === 'string') return fail(reg);
  const dir = projectDir(paths);
  const lockFile = join(dir, SYNC_LOCK_NAME);
  let locks: Record<string, SourceLock> = {};
  if (existsSync(lockFile)) { try { locks = readJson(lockFile) as Record<string, SourceLock>; } catch (e) { return fail(`${SYNC_LOCK_NAME} is not JSON: ${(e as Error).message}`); } }
  const wanted = o.source === undefined ? cfg.sources : cfg.sources.filter((x) => x.name === o.source);
  if (wanted.length === 0) return fail(`no source named '${o.source}'`);
  const now = o.now ?? Date.now();
  const lines: string[] = [];
  let changed = false;
  for (const src of wanted) {
    const file = join(dir, `${src.name}.sync.yaml`);
    let text: string;
    try { text = await readSourceOf(src, dir, o.fetchImpl); } catch (e) { return fail(`${src.name}: ${(e as Error).message}`); }
    const imp = cmdImport(text, { from: src.from, ns: cfg.ns, uri: src.url ?? src.file!, ...(src.verb ? { verb: src.verb } : {}) });
    if (!imp.ok) return fail(`${src.name}: ${imp.text}`);
    const imported = loadActionsText(imp.yaml);
    if (imported.errors.length > 0) return fail(`${src.name}: ${imported.errors[0]!.message}`);
    const current = existsSync(file) ? loadActionsText(readFileSync(file, 'utf8')) : undefined;
    if (current && current.errors.length > 0) return fail(`${file}: ${current.errors[0]!.message}`);
    const r = syncSource({ current: current?.defs ?? [], imported: imported.defs, specDigest: hashCanonical(text), ...(locks[src.name] ? { lock: locks[src.name] } : {}), now: Math.floor(now / 1000), registry: reg, review: reviewOf(cfg, reg) });
    const moved = r.entries.some((e) => e.change !== 'unchanged');
    changed = changed || moved;
    lines.push(`${src.name} (${src.from}):`, ...syncText(r).split('\n').map((x) => `  ${x}`));
    if (o.check) continue;
    // keep the business rules of the actions that stayed (a changed one keeps them too: rules only tighten, and a reviewer re-signs)
    const keptRules: Record<string, BusinessRules> = {};
    for (const d of r.defs) if (current?.rules[d.verb] !== undefined) keptRules[d.verb] = current.rules[d.verb]!;
    writeFileSync(file, `# Generated by pca actions sync from ${src.url ?? src.file} (${src.from}). Add rules under an action; re-run sync to refresh.\n${defsToYaml(cfg.ns, r.defs, keptRules)}`);
    locks[src.name] = r.lock;
  }
  if (!o.check) writeFileSync(lockFile, JSON.stringify(locks, null, 2) + '\n');
  return { ok: !(o.check && changed), text: `${lines.join('\n')}${o.check && changed ? '\nthe sources changed: run pca actions sync and review the added and changed actions' : ''}` };
}
