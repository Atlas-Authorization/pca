// lint.ts - the 24 stable lint rules (spec section 6.2): 14 errors (LD-001..014) and 10 warnings (LW-001..010), SARIF output,
// and the digest of the rule list that pca-policy-ci pins. Pure: defs in, findings out, deterministic order.
// Structural failures (a def that does not pass validateDef) are reported as LD-000 and the def is not linted further.

import { hashCanonical } from '@atlasauth/pca';
import {
  CONTEXT_KEYS, EFFECTS, SENSITIVITY_RANK, isReadOnly,
  type ActionDef, type ParamRuleId,
} from './def';
import { CORE_REGISTRY } from './core-traits';
import { defDigest, traitsDigest } from './digest';
import { effective, prulesViolations } from './effective';
import { effectiveParamSensitivity, normalize, worstReversibility } from './normalize';
import { extendRegistry, isContextKey, type Registry, type TraitDef } from './traits';
import { isFormat, isPlainObject, isRole, validateDef } from './validate';

export type Severity = 'error' | 'warning' | 'note';
export interface Finding {
  rule: string;
  severity: Severity;
  verb?: string;
  param?: string;
  message: string;
  file?: string;
  /** 1-based source position (set by the CLI from the loader). */
  line?: number;
  column?: number;
}

export interface LintRule { id: string; severity: 'error' | 'warning'; title: string }

/** The rule list. Order and wording are part of {@link lintRulesDigest}; change them only with a version bump. */
export const LINT_RULES: readonly LintRule[] = Object.freeze([
  { id: 'LD-001', severity: 'error', title: 'a destroy-like verb whose effects do not delete' },
  { id: 'LD-002', severity: 'error', title: 'a money parameter without a currency, or a currency without the iso_currency format' },
  { id: 'LD-003', severity: 'error', title: 'a numeric parameter without min and max' },
  { id: 'LD-004', severity: 'error', title: 'a money-moving action without idempotency' },
  { id: 'LD-005', severity: 'error', title: 'personal data can leave without the matching effect' },
  { id: 'LD-006', severity: 'error', title: 'a declared reversibility or blast below the effective floor' },
  { id: 'LD-007', severity: 'error', title: 'an unknown trait, role, format, effect or context key, or an invalid custom trait' },
  { id: 'LD-008', severity: 'error', title: "resource id '*' with scope one" },
  { id: 'LD-009', severity: 'error', title: 'a duplicate verb or alias collision' },
  { id: 'LD-010', severity: 'error', title: 'a write marked reversible with no compensating action in the pack' },
  { id: 'LD-011', severity: 'error', title: 'review state confirmed without a valid attestation for this digest' },
  { id: 'LD-012', severity: 'error', title: 'a structural param rule that the effective traits require is violated' },
  { id: 'LD-013', severity: 'error', title: 'a read-only action that can mutate or handles credentials' },
  { id: 'LD-014', severity: 'error', title: 'one binding in two defs' },
  { id: 'LW-001', severity: 'warning', title: 'description missing or too long, or title not imperative' },
  { id: 'LW-002', severity: 'warning', title: 'a string parameter without max_len' },
  { id: 'LW-003', severity: 'warning', title: 'free text flows into an outbound action without the free_text_outbound tag' },
  { id: 'LW-004', severity: 'warning', title: 'an unreviewed def in a stable pack' },
  { id: 'LW-005', severity: 'warning', title: 'a dismissed suggested trait without a reason' },
  { id: 'LW-006', severity: 'warning', title: 'an array parameter without max_items' },
  { id: 'LW-007', severity: 'warning', title: 'a critical parameter without provenance_min' },
  { id: 'LW-008', severity: 'warning', title: 'verb naming inconsistent with its siblings or with the file namespace' },
  { id: 'LW-009', severity: 'warning', title: 'a money-moving, destructive or privilege-changing action without an example' },
  { id: 'LW-010', severity: 'warning', title: 'since is missing' },
]);

/** Informational notes (for example an auto-added idempotency key) are reported under this id; they never fail a run. */
export const NOTE_RULE = { id: 'LN-001', severity: 'note' as const, title: 'an informational note from the loader' };

/** Structural failures are not a rule of the list; they are reported under this id. */
export const STRUCTURE_RULE: LintRule = { id: 'LD-000', severity: 'error', title: 'the def is not well formed and cannot be loaded' };

export const LINT_RULES_DIGEST_DOMAIN = 'atlas-pca/action-lint-rules/v1';
/** The digest pca-policy-ci pins: the ordered (id, severity, title) list. */
export const lintRulesDigest = (): string => hashCanonical({ d: LINT_RULES_DIGEST_DOMAIN, rules: LINT_RULES.map((r) => ({ id: r.id, severity: r.severity, title: r.title })) });

export interface LintOptions {
  /** Custom traits added to the core registry (a bad set is reported as LD-007). */
  customTraits?: readonly TraitDef[];
  /** Stability of the pack the defs belong to (LW-004). */
  stability?: 'draft' | 'beta' | 'stable';
  /** The namespace of the file (LW-008). */
  ns?: string;
  /** Signature check of a def's attestation (the registry layer). Absent: an attestation needs a `sig` member to count. */
  attestationVerified?: (def: ActionDef) => boolean;
}

const enc = new TextEncoder();
const u8 = (s: string): number => enc.encode(s).length;

const DESTROY_RE = /^(delete|destroy|remove|purge|drop|erase|wipe|revoke|terminate|truncate)(_|$)/;
const SEND_RE = /^(send|email|notify|sms|message|post_to|broadcast|invite)(_|$)/;
const EXPORT_RE = /^(export|download|dump|backup|extract)(_|$)/;
const lastSeg = (verb: string): string => verb.split('.').pop() ?? verb;

function bindingKeys(d: ActionDef): string[] {
  const b = d.bindings ?? {};
  const out: string[] = [];
  if (b.mcp) out.push(`mcp:${b.mcp.tool}`);
  if (b.openapi) out.push(`openapi:${b.openapi.operationId}`);
  if (b.http) out.push(`http:${b.http.method.toUpperCase()} ${b.http.path}`);
  if (b.graphql) out.push(`graphql:${b.graphql.op}.${b.graphql.field}`);
  if (b.grpc) out.push(`grpc:${b.grpc.service}/${b.grpc.method}`);
  if (b.asyncapi) out.push(`asyncapi:${b.asyncapi.op} ${b.asyncapi.channel}`);
  return out;
}

const NAME_GROUPS: readonly (readonly string[])[] = [['create_', 'new_', 'add_', 'make_'], ['delete_', 'remove_', 'destroy_']];

/** Vocabulary problems of a raw def (LD-007). Reads only what a malformed def can still be asked. */
function vocabularyIssues(x: unknown, reg: Registry): string[] {
  if (!isPlainObject(x)) return [];
  const out: string[] = [];
  if (Array.isArray(x.effects)) for (const e of x.effects) if (!(EFFECTS as readonly unknown[]).includes(e)) out.push(`unknown effect '${String(e)}'`);
  if (isPlainObject(x.params)) {
    for (const [n, q] of Object.entries(x.params)) {
      if (!isPlainObject(q)) continue;
      if (q.role !== undefined && !isRole(q.role)) out.push(`${n}: unknown role '${String(q.role)}'`);
      if (q.format !== undefined && !isFormat(q.format)) out.push(`${n}: unknown format '${String(q.format)}'`);
    }
  }
  if (Array.isArray(x.context)) for (const c of x.context) if (!isContextKey(c)) out.push(`unknown context key '${String(c)}' (known: ${CONTEXT_KEYS.join(', ')}, session_taint_max:<level>)`);
  if (Array.isArray(x.traits)) for (const t of x.traits) if (typeof t === 'string' && !reg.traits.has(t)) out.push(`unknown trait '${t}'`);
  return out;
}

/**
 * Lint a pack's defs (raw values, so a malformed one is still reported). Findings are sorted by verb, rule, param, message.
 * Errors fail CI; warnings fail under `--strict`.
 */
export function lintDefs(raw: readonly unknown[], opts: LintOptions = {}): Finding[] {
  const out: Finding[] = [];
  const add = (rule: string, d: { verb?: string } | undefined, message: string, param?: string): void => {
    const sev = rule === STRUCTURE_RULE.id ? 'error' : LINT_RULES.find((r) => r.id === rule)!.severity;
    out.push({ rule, severity: sev, ...(d?.verb !== undefined ? { verb: d.verb } : {}), ...(param !== undefined ? { param } : {}), message });
  };

  let reg: Registry = CORE_REGISTRY;
  if (opts.customTraits && opts.customTraits.length > 0) {
    try { reg = extendRegistry(CORE_REGISTRY, opts.customTraits); } catch (e) { add('LD-007', undefined, `invalid custom traits: ${(e as Error).message}`); }
  }

  const defs: ActionDef[] = [];
  for (const x of raw) {
    const verb = isPlainObject(x) && typeof x.verb === 'string' ? x.verb : undefined;
    const vocab = vocabularyIssues(x, reg);
    if (vocab.length > 0) { for (const v of vocab) add('LD-007', { verb }, v); continue; }
    const bad = validateDef(x);
    if (bad) { add(STRUCTURE_RULE.id, { verb }, bad); continue; }
    defs.push(x as ActionDef);
  }

  // ---- pack-level rules --------------------------------------------------------------------------------------------------
  const byVerb = new Map<string, ActionDef>();
  const names = new Map<string, string>(); // verb or alias -> owner verb
  for (const d of defs) {
    if (byVerb.has(d.verb)) add('LD-009', d, `verb '${d.verb}' is defined twice`);
    byVerb.set(d.verb, d);
  }
  for (const d of defs) {
    for (const n of [d.verb, ...(d.aliases ?? [])]) {
      const owner = names.get(n);
      if (owner !== undefined && owner !== d.verb) add('LD-009', d, `'${n}' is also a name of '${owner}'`);
      else if (!names.has(n)) names.set(n, d.verb);
    }
  }
  const bound = new Map<string, string>();
  for (const d of defs) {
    for (const k of bindingKeys(d)) {
      const owner = bound.get(k);
      if (owner !== undefined && owner !== d.verb) add('LD-014', d, `binding ${k} is also bound by '${owner}'`);
      else bound.set(k, d.verb);
    }
  }
  // LW-008: sibling naming (create_/new_ ...) and namespace
  for (const grp of NAME_GROUPS) {
    const used = new Map<string, number>();
    for (const d of defs) { const g = grp.find((pfx) => lastSeg(d.verb).startsWith(pfx)); if (g) used.set(g, (used.get(g) ?? 0) + 1); }
    if (used.size > 1) {
      const win = [...used.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))[0]![0];
      for (const d of defs) { const g = grp.find((pfx) => lastSeg(d.verb).startsWith(pfx)); if (g && g !== win) add('LW-008', d, `uses '${g}' where its siblings use '${win}'`); }
    }
  }
  if (opts.ns !== undefined) for (const d of defs) if (d.verb.split('.')[0] !== opts.ns) add('LW-008', d, `verb namespace '${d.verb.split('.')[0]}' differs from the file namespace '${opts.ns}'`);

  // ---- per-def rules --------------------------------------------------------------------------------------------------
  for (const d of defs) {
    const n = normalize(d);
    const pnames = Object.keys(n.params).sort();
    const eff = effective(d, reg, opts.attestationVerified ? { attestationVerified: opts.attestationVerified } : {});
    const tset = new Set(eff.hint.traits);
    const cl = new Set(eff.hint.closure);
    const params = (pred: (q: ActionDef['params'][string]) => boolean): string[] => pnames.filter((k) => pred(n.params[k]!));

    // LD-001
    if (DESTROY_RE.test(lastSeg(d.verb)) && !d.effects.includes('delete')) add('LD-001', d, `the verb says '${lastSeg(d.verb)}' but effects do not include delete`);
    // LD-002
    for (const k of params((q) => q.role === 'money.amount' || q.role === 'money.fee')) {
      const u = n.params[k]!.unit;
      if (!u || u.kind !== 'money') add('LD-002', d, 'a money parameter needs a unit of kind money with a currency', k);
      else if (typeof u.ccy !== 'string') {
        const c = n.params[u.ccy.from];
        if (!c || c.role !== 'money.currency' || c.format !== 'iso_currency') add('LD-002', d, `the currency parameter '${u.ccy.from}' needs role money.currency and format iso_currency`, k);
      }
    }
    for (const k of params((q) => q.role === 'money.currency')) if (n.params[k]!.format !== 'iso_currency') add('LD-002', d, 'a currency parameter needs the iso_currency format', k);
    // LD-003
    for (const k of params((q) => q.type === 'integer' || q.type === 'duration')) {
      const q = n.params[k]!;
      if (q.role !== undefined && q.role.startsWith('id.')) continue;
      if (q.role === 'count.limit' && q.max !== undefined) continue;
      if (q.min === undefined || q.max === undefined) add('LD-003', d, `a numeric parameter needs both min and max (has ${q.min === undefined ? 'no min' : 'min'}, ${q.max === undefined ? 'no max' : 'max'})`, k);
    }
    // LD-004
    if ((d.effects.includes('pay') || tset.has('pca.money_moving')) && n.idempotency.mode === 'none') add('LD-004', d, 'a money-moving action needs idempotency key_param or natural');
    // LD-005
    const pii = params((q) => (q.tags ?? []).includes('pii') || (q.role !== undefined && (q.role.startsWith('contact.') || q.role.startsWith('person.'))));
    if (pii.length > 0) {
      const expected = new Set<string>();
      for (const s of d.side_effects ?? []) if (s.kind === 'send' || s.kind === 'export') expected.add(s.kind);
      if (SEND_RE.test(lastSeg(d.verb))) expected.add('send');
      if (EXPORT_RE.test(lastSeg(d.verb))) expected.add('export');
      for (const e of [...expected].sort()) if (!d.effects.includes(e as 'send' | 'export')) add('LD-005', d, `personal data can ${e === 'send' ? 'be sent' : 'be exported'} (${pii.join(', ')}) but effects do not include ${e}`);
    }
    // LD-006
    for (const c of eff.clamps) add('LD-006', d, `declared ${c.field === 'rev' ? 'reversibility' : 'blast'} ${String(c.declared)} is below the floor ${String(c.floor)}`);
    // LD-008
    if (n.resource.id === '*' && n.resource.scope === 'one') add('LD-008', d, "resource id '*' with scope one names every resource at once");
    // LD-010
    if (!isReadOnly(d.effects) && d.reversibility !== undefined && worstReversibility(n.reversibility, n.params) === 'reversible') {
      if (d.compensates === undefined) add('LD-010', d, 'a write declared reversible must name its compensating action (compensates)');
      else if (!byVerb.has(d.compensates)) add('LD-010', d, `compensates '${d.compensates}', which is not in the pack`);
    }
    // LD-011
    if (d.review.state === 'confirmed') {
      const a = d.review.attestation;
      if (!a) add('LD-011', d, 'confirmed without an attestation');
      else if (a.def_digest !== defDigest(d)) add('LD-011', d, 'the attestation covers a different digest of this def');
      else if (a.traits_digest !== traitsDigest(reg)) add('LD-011', d, 'the attestation was made against a different trait registry');
      else if (opts.attestationVerified ? !opts.attestationVerified(d) : a.sig === undefined) add('LD-011', d, 'the attestation is not signed by a pinned reviewer');
    }
    // LD-011 (continued): a trait added by the fail-strict union leaves a def only with a signed dismissal naming it
    const dismissedNames = new Set(d.review.state === 'confirmed' ? (d.review.attestation?.dismissed ?? []).map((x) => x.trait) : []);
    for (const t of d.review.provenance?.union ?? []) if (!cl.has(t) && !dismissedNames.has(t)) add('LD-011', d, `the union-added trait ${t} was removed without a signed dismissal`);
    // LD-012: prules the effective profile requires, except the ones with their own rule
    const own: ParamRuleId[] = ['money_has_currency', 'money_amount_bounded', 'pay_has_idempotency'];
    for (const r of prulesViolations(d, eff.hint.eff.prules)) if (!own.includes(r)) add('LD-012', d, `structural rule ${r} is required by the action's traits and violated`);
    // LD-013
    if (isReadOnly(d.effects)) {
      const enforced = (d.context ?? []).includes('sandbox_attested');
      for (const k of params((q) => q.role === 'code.command' || q.role === 'query.sql')) if (!enforced) add('LD-013', d, 'a read-only action takes code or a query it cannot prove read-only (declare context sandbox_attested)', k);
      for (const k of params((q) => (q.tags ?? []).includes('credential'))) add('LD-013', d, 'a read-only action handles a credential', k);
    }

    // ---- warnings ----
    if (d.description === undefined) add('LW-001', d, 'description is missing');
    else if (u8(d.description) > 400) add('LW-001', d, 'description is longer than 400 bytes');
    const first = (d.title.split(/\s+/)[0] ?? '').toLowerCase();
    if (/(ing|ed)$/.test(first) || (/[^s]s$/.test(first) && !/(us|is)$/.test(first)) || ['a', 'an', 'the'].includes(first)) add('LW-001', d, `title '${d.title}' is not imperative`);
    for (const k of params((q) => q.type === 'string' && q.max_len === undefined && q.values === undefined)) add('LW-002', d, 'a string parameter without max_len (the default is 1024; say it)', k);
    if (cl.has('pca.external_communication')) {
      for (const k of params((q) => q.type === 'string' && q.values === undefined && q.format === undefined && (q.role === undefined || q.role.startsWith('text.')) && !(q.tags ?? []).includes('free_text_outbound')).filter((k) => k !== n.idempotency.param)) {
        add('LW-003', d, 'free text flows into an outbound action without tags: [free_text_outbound]', k);
      }
    }
    if (opts.stability === 'stable' && (d.review.state === 'unreviewed' || d.review.state === 'suggested')) add('LW-004', d, `a ${d.review.state} def in a stable pack`);
    for (const x of d.review.attestation?.dismissed ?? []) if (x.reason.trim().length < 5) add('LW-005', d, `dismissed trait ${x.trait} has no reason`);
    for (const k of params((q) => q.type === 'array' && q.max_items === undefined)) add('LW-006', d, 'an array parameter without max_items', k);
    for (const k of params((q) => SENSITIVITY_RANK[effectiveParamSensitivity(q)] >= SENSITIVITY_RANK.critical && q.provenance_min === undefined)) add('LW-007', d, 'a critical parameter without provenance_min', k);
    if ((tset.has('pca.money_moving') || tset.has('pca.destructive') || tset.has('pca.privilege_change')) && (d.examples ?? []).length === 0) add('LW-009', d, 'no example for a money-moving, destructive or privilege-changing action');
    if (d.since === undefined) add('LW-010', d, 'since is missing');
  }

  const cmp = (a: string | undefined, b: string | undefined): number => ((a ?? '') < (b ?? '') ? -1 : (a ?? '') > (b ?? '') ? 1 : 0);
  return out.sort((a, b) => cmp(a.verb, b.verb) || cmp(a.rule, b.rule) || cmp(a.param, b.param) || cmp(a.message, b.message));
}

/** Does the run fail? Errors always; warnings under `strict`. */
export const lintFails = (fs: readonly Finding[], strict = false): boolean => fs.some((f) => f.severity === 'error' || (strict && f.severity === 'warning'));

/** Plain text, one line per finding. */
export function lintText(fs: readonly Finding[]): string {
  if (fs.length === 0) return '0 errors, 0 warnings';
  const e = fs.filter((f) => f.severity === 'error').length;
  const w = fs.filter((f) => f.severity === 'warning').length;
  const lines = fs.map((f) => `${f.severity.padEnd(7)} ${f.rule}  ${f.file ? `${f.file}${f.line !== undefined ? `:${f.line}:${f.column ?? 1}` : ''}: ` : ''}${f.verb ?? ''}${f.param ? ` [${f.param}]` : ''}${f.verb || f.param ? ': ' : ''}${f.message}`);
  return `${lines.join('\n')}\n${e} error${e === 1 ? '' : 's'}, ${w} warning${w === 1 ? '' : 's'}${fs.length - e - w > 0 ? `, ${fs.length - e - w} note${fs.length - e - w === 1 ? '' : 's'}` : ''}`;
}

/** SARIF 2.1.0, so findings appear as pull request annotations. */
export function toSarif(fs: readonly Finding[], tool: { name?: string; version?: string } = {}): unknown {
  const rules: { id: string; severity: Severity; title: string }[] = [STRUCTURE_RULE, NOTE_RULE, ...LINT_RULES];
  const level = (s: Severity): string => (s === 'error' ? 'error' : s === 'warning' ? 'warning' : 'note');
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: tool.name ?? 'pca actions lint', ...(tool.version ? { version: tool.version } : {}), rules: rules.map((r) => ({ id: r.id, shortDescription: { text: r.title }, defaultConfiguration: { level: level(r.severity) } })) } },
      results: fs.map((f) => ({
        ruleId: f.rule,
        level: level(f.severity),
        message: { text: `${f.verb ? `${f.verb}${f.param ? ` [${f.param}]` : ''}: ` : ''}${f.message}` },
        locations: [{
          ...(f.file ? { physicalLocation: { artifactLocation: { uri: f.file }, ...(f.line !== undefined ? { region: { startLine: f.line, startColumn: f.column ?? 1 } } : {}) } } : {}),
          ...(f.verb ? { logicalLocations: [{ name: f.verb, kind: 'member' }] } : {}),
        }],
      })),
    }],
  };
}
