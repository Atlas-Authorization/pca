/**
 * TRACE RULES: Invariant-style "never B after A" guardrails compiled into checks the verifier already enforces (track K9).
 *
 * A trace rule says an effect class must not follow a read class within a window, the shape of the "toxic flow" rules of
 * Invariant Labs' guardrails (invariantlabs-ai/invariant README and docs `mcp-scan/guardrails-reference.md`, fetched
 * 2026-10-27: `raise "..." if: (a: ToolOutput) -> (b: ToolCall), a is tool:get_website, b is tool:send_email`, where `->`
 * means "a happens before b in the trace"). PCA does not run a rule engine: {@link compileTraceRules} lowers each rule to
 * K1 `derive` caveats (caveat-language section 4), which every native verifier evaluates over the verifier's own signed
 * action history (`k1.history`). A caveat only removes authority, so a compiled rule is a restriction by construction.
 *
 *   rule  never <B> after <A> within <duration>
 *   sel   atom (',' atom)*      atom: tool:<verb> | trait:<trait id> | resource:<prefix> (A side only) | any
 *
 * Fail-strict compilation. Anything the target cannot express exactly is an error, never skipped: an unknown tool, a
 * selector matching no action, a resource selector on the B side (the check reads the action's verb), a window over 30
 * days, more than {@link MAX_TRACE_CAVEATS} caveats. The Invariant importer accepts only `(x: ToolCall|ToolOutput) ->
 * (y: ToolCall)` with `x is tool:<name>` lines; any other condition is an error unless the caller opts into
 * `dropUnsupported`, which removes conjuncts from the RAISE condition (a weaker condition fires more often: strictly more
 * refusals, listed in `dropped`). Invariant rules carry no window, so the caller must state the horizon.
 */
import { DERIVE_MAX_WINDOW_MS, deriveError, hashCanonical, type DeriveCaveat, type DeriveExpr } from '@atlasauth/pca';

export interface TraceSelector {
  tools: string[];
  traits: string[];
  /** Resource prefixes (A side only: the history records the resource of past actions). */
  resources: string[];
  /** Every action in the verb table. */
  any: boolean;
}
export interface TraceRule {
  id: string;
  never: TraceSelector;
  after: TraceSelector;
  within_ms: number;
  reason?: string;
}
/** verb -> its traits (the effective closure; an unconfirmed def should list every trait, as the action kit treats it). */
export type VerbTable = Readonly<Record<string, { traits: readonly string[]; effects?: readonly string[] }>>;
export interface TraceEdge {
  rule: string;
  from: { tool: string } | { resource: string };
  to: string;
  within_ms: number;
}
export interface CompiledTrace {
  caveats: DeriveCaveat[];
  edges: TraceEdge[];
  /** hashCanonical({d: "atlas-pca/trace-rules/v1", caveats}): what a grant or a review pins. */
  digest: string;
}

export class TraceRuleError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = 'TraceRuleError';
  }
}

export const MAX_TRACE_CAVEATS = 64;
const B_CHUNK = 8; // 7 + 3k expression nodes <= DERIVE_MAX_NODES (32)
const RULE_ID_RE = /^[a-z][a-z0-9_]{0,39}$/;
const VERB_RE = /^[A-Za-z0-9_.:/-]{1,256}$/;
const fail = (code: string, m: string): never => {
  throw new TraceRuleError(code, m);
};

const UNIT: Record<string, number> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };
function duration(t: string): number {
  const m = /^([1-9][0-9]{0,9})(ms|s|m|h|d)$/.exec(t);
  if (!m) return fail('duration', `'${t}' is not a duration like 10m, 2h or 7d`);
  const ms = Number(m[1]) * UNIT[m[2]!]!;
  if (ms > DERIVE_MAX_WINDOW_MS) fail('window', `a window of ${t} exceeds the 30-day history the verifier keeps`);
  return ms;
}

function selector(text: string, side: 'never' | 'after'): TraceSelector {
  const s: TraceSelector = { tools: [], traits: [], resources: [], any: false };
  for (const raw of text.split(',')) {
    const a = raw.trim();
    if (a === 'any') s.any = true;
    else if (a.startsWith('tool:') && VERB_RE.test(a.slice(5))) s.tools.push(a.slice(5));
    else if (a.startsWith('trait:') && VERB_RE.test(a.slice(6))) s.traits.push(a.slice(6));
    else if (a.startsWith('resource:') && a.length > 9 && a.length <= 9 + 256) {
      if (side === 'never') fail('resource_on_effect', 'a resource selector can only name the earlier action (the check reads the current verb)');
      s.resources.push(a.slice(9));
    } else fail('selector', `'${a}' is not tool:<verb>, trait:<id>, resource:<prefix> or any`);
  }
  return s;
}

/** Parse `never <B> after <A> within <duration>`. Throws {@link TraceRuleError}. */
export function parseTraceRule(id: string, text: string, reason?: string): TraceRule {
  if (!RULE_ID_RE.test(id)) fail('id', `rule id '${id}' must match ${RULE_ID_RE.source}`);
  const m = /^\s*never\s+(.+?)\s+after\s+(.+?)\s+within\s+(\S+)\s*$/.exec(text);
  if (!m) return fail('syntax', `expected 'never <selector> after <selector> within <duration>', got '${text}'`);
  return { id, never: selector(m[1]!, 'never'), after: selector(m[2]!, 'after'), within_ms: duration(m[3]!), ...(reason !== undefined ? { reason } : {}) };
}

export interface InvariantImport {
  rule: TraceRule;
  /** Conditions removed under `dropUnsupported` (each removal makes the rule refuse more, never less). */
  dropped: string[];
}

/**
 * Import the Invariant subset `raise "<msg>" if: (x: ToolCall|ToolOutput) -> (y: ToolCall)` plus `x is tool:<name>` /
 * `y is tool:<name>` lines. `horizon` (a duration like `7d`) is required: Invariant's `->` spans the whole trace, PCA's
 * check spans the verifier's history window, and silently choosing one would change the rule.
 */
export function parseInvariantRule(id: string, text: string, o: { horizon: string; dropUnsupported?: boolean }): InvariantImport {
  if (!RULE_ID_RE.test(id)) fail('id', `rule id '${id}' must match ${RULE_ID_RE.source}`);
  if (typeof o?.horizon !== 'string') fail('horizon', 'an Invariant rule has no window: pass the horizon explicitly');
  const within_ms = duration(o.horizon);
  const lines = text.split('\n').map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith('#'));
  const head = /^raise\s+(?:"([^"]*)"|'([^']*)')\s+if:$/.exec(lines[0] ?? '');
  if (!head) fail('syntax', `the first line must be raise "<message>" if:`);
  const flow = /^\((\w+):\s*(ToolCall|ToolOutput|Message)\)\s*->\s*\((\w+):\s*(ToolCall|ToolOutput|Message)\)$/.exec(lines[1] ?? '');
  if (!flow) fail('unsupported', `the second line must be one flow '(x: ToolCall|ToolOutput) -> (y: ToolCall)' (chains of three and other patterns are not supported)`);
  const [, a, ta, b, tb] = flow!;
  if (ta === 'Message' || tb !== 'ToolCall') fail('unsupported', 'only a tool call or tool output followed by a tool call can be compiled');
  if (a === b) fail('syntax', 'the two events need distinct names');
  const tools: Record<string, string[]> = { [a!]: [], [b!]: [] };
  const dropped: string[] = [];
  for (const l of lines.slice(2)) {
    const m = /^(\w+)\s+is\s+tool:([A-Za-z0-9_.:/-]+)(\(.*\))?$/.exec(l);
    if (m && tools[m[1]!] !== undefined && m[3] === undefined) {
      tools[m[1]!]!.push(m[2]!);
      continue;
    }
    if (o.dropUnsupported === true) {
      // `x is tool:name({args})` keeps the tool and drops the argument pattern: a wider match, so more refusals
      if (m && tools[m[1]!] !== undefined) tools[m[1]!]!.push(m[2]!);
      dropped.push(l);
      continue;
    }
    fail('unsupported', `'${l}' is outside the compilable subset (x is tool:<name>); pass dropUnsupported to refuse more instead`);
  }
  for (const v of [a!, b!]) if (tools[v]!.length > 1) fail('unsatisfiable', `'${v}' is constrained to two different tools, so the rule can never fire`);
  const sel = (v: string): TraceSelector => ({ tools: tools[v]!, traits: [], resources: [], any: tools[v]!.length === 0 });
  return { rule: { id, never: sel(b!), after: sel(a!), within_ms, reason: head![1] ?? head![2] ?? '' }, dropped };
}

function expand(s: TraceSelector, table: VerbTable, what: string): string[] {
  const verbs = Object.keys(table).sort();
  const out = new Set<string>();
  if (s.any) for (const v of verbs) out.add(v);
  for (const t of s.tools) {
    if (!Object.prototype.hasOwnProperty.call(table, t)) fail('unknown_tool', `${what}: tool '${t}' is not an action in the verb table`);
    out.add(t);
  }
  for (const tr of s.traits) {
    const hit = verbs.filter((v) => table[v]!.traits.includes(tr));
    if (hit.length === 0) fail('empty_selector', `${what}: trait '${tr}' matches no action`);
    for (const v of hit) out.add(v);
  }
  return [...out].sort();
}

/** Lower rules to K1 derive caveats over the verifier's history. Throws {@link TraceRuleError} on anything not expressible. */
export function compileTraceRules(rules: readonly TraceRule[], table: VerbTable): CompiledTrace {
  const caveats: DeriveCaveat[] = [];
  const edges: TraceEdge[] = [];
  const ids = new Set<string>();
  for (const r of rules) {
    if (!RULE_ID_RE.test(r.id) || ids.has(r.id)) fail('id', `rule id '${r.id}' is malformed or repeated`);
    ids.add(r.id);
    if (!(Number.isSafeInteger(r.within_ms) && r.within_ms >= 1 && r.within_ms <= DERIVE_MAX_WINDOW_MS)) fail('window', `rule '${r.id}': within_ms must be 1..30 days`);
    if (r.never.resources.length > 0) fail('resource_on_effect', `rule '${r.id}': a resource selector cannot name the later action`);
    const bs = expand(r.never, table, `rule '${r.id}' never`);
    const as = [...expand(r.after, table, `rule '${r.id}' after`).map((v) => ({ verb: v })), ...[...new Set(r.after.resources)].sort().map((p) => ({ resource_prefix: p }))];
    if (bs.length === 0 || as.length === 0) fail('empty_selector', `rule '${r.id}': a side matches nothing`);
    let n = 0;
    for (const a of as) {
      for (let i = 0; i < bs.length; i += B_CHUNK) {
        const chunk = bs.slice(i, i + B_CHUNK);
        const isB: DeriveExpr = { op: 'or', args: chunk.map((v) => ({ op: 'eq' as const, a: { ref: 'verb' }, b: { const: v } })) };
        const c: DeriveCaveat = {
          type: 'derive',
          id: `trace.${r.id}.${n++}`,
          defs: [{ name: 'seen', kind: 'count', window_ms: r.within_ms, ...a }, { name: 'verb', kind: 'action', field: 'verb' }, { name: 'is_b', kind: 'expr', expr: isB }],
          // refused iff an A happened within the window AND this action is a B; unknown (no history, no verb) refuses too
          check: { op: 'not', arg: { op: 'and', args: [{ op: 'gt', a: { ref: 'seen' }, b: { const: 0 } }, { ref: 'is_b' }] } },
        };
        const e = deriveError(c);
        if (e) fail('internal', `rule '${r.id}' compiled to an invalid caveat: ${e}`);
        caveats.push(c);
        if (caveats.length > MAX_TRACE_CAVEATS) fail('too_large', `more than ${MAX_TRACE_CAVEATS} caveats: split the rule set or narrow the selectors`);
      }
      for (const v of bs) edges.push({ rule: r.id, from: 'verb' in a ? { tool: a.verb } : { resource: a.resource_prefix }, to: v, within_ms: r.within_ms });
    }
  }
  return { caveats, edges, digest: hashCanonical({ d: 'atlas-pca/trace-rules/v1', caveats }) };
}

// ------------------------------------------------------------------------------------------------ lethal trifecta lint

/** Traits that mean "reads private data". */
export const PRIVATE_READ_TRAITS: readonly string[] = ['pca.pii_access', 'pca.financial_data_read', 'pca.credential_access', 'pca.regulated_data'];
/** Traits that mean "can send data out". */
export const EXTERNAL_SEND_TRAITS: readonly string[] = ['pca.external_communication', 'pca.network_egress', 'pca.data_export', 'pca.public_exposure'];

export interface TrifectaFinding {
  /** The send action left open. */
  send: string;
  /** Untrusted-content reads with no rule to `send`. */
  from_untrusted: string[];
  /** Private reads with no rule to `send`. */
  from_private: string[];
}
export interface TrifectaReport {
  private_reads: string[];
  untrusted_reads: string[];
  sends: string[];
  /** Empty when the set does not form the trifecta or every send is cut off. */
  findings: TrifectaFinding[];
}

/**
 * The lethal trifecta: private data, untrusted content and a way out in one action set. A send `s` is cut off when every
 * untrusted read, or every private read, has an edge rule to `s` (a trace rule removing that leg). Untrusted reads are the
 * verbs in `untrusted`, those with a trait in `untrusted_traits`, and read-only actions with `pca.network_egress` (fetched
 * content is written by anyone). A lint only: it reports, it does not enforce.
 */
export function lethalTrifecta(table: VerbTable, edges: readonly TraceEdge[], o: { untrusted?: readonly string[]; untrusted_traits?: readonly string[] } = {}): TrifectaReport {
  const verbs = Object.keys(table).sort();
  const has = (v: string, ts: readonly string[]) => table[v]!.traits.some((t) => ts.includes(t));
  const readOnly = (v: string) => (table[v]!.effects ?? []).length > 0 && table[v]!.effects!.every((e) => e === 'read');
  const priv = verbs.filter((v) => has(v, PRIVATE_READ_TRAITS));
  const untrusted = verbs.filter((v) => (o.untrusted ?? []).includes(v) || has(v, o.untrusted_traits ?? []) || (readOnly(v) && table[v]!.traits.includes('pca.network_egress')));
  const sends = verbs.filter((v) => has(v, EXTERNAL_SEND_TRAITS) && !readOnly(v));
  const findings: TrifectaFinding[] = [];
  if (priv.length > 0 && untrusted.length > 0 && sends.length > 0) {
    const ruled = (from: string, to: string) => edges.some((e) => 'tool' in e.from && e.from.tool === from && e.to === to);
    for (const s of sends) {
      const fu = untrusted.filter((u) => !ruled(u, s));
      const fp = priv.filter((p) => !ruled(p, s));
      if (fu.length > 0 && fp.length > 0) findings.push({ send: s, from_untrusted: fu, from_private: fp });
    }
  }
  return { private_reads: priv, untrusted_reads: untrusted, sends, findings };
}
