import { declaredSuites, judge, PASSING, type Outcome } from './judge';
import { isFault, runDriver, type DriverSpec } from './driver';
import { sendLine, type CorpusItem, type LoadedCorpus } from './corpus';
import { canonicalJson, RUNNER_NAME, runnerVersion, sha256hex, sameJson, type Json } from './util';

export const REPORT_FORMAT = 'pca-verified-report/1';

export interface Implementation {
  name: string;
  version: string;
  vendor?: string;
}

export interface CaseResult {
  id: string;
  layer: string;
  outcome: Outcome;
  why?: string;
}

export type ProfileStatus = 'pass' | 'fail' | 'unsupported' | 'incomplete';

export interface ProfileResult {
  status: ProfileStatus;
  total: number;
  passed: number;
  failed: number;
  unsupported: number;
  faults: number;
  by_layer: Record<string, { total: number; passed: number }>;
  results_digest: string;
  reasons: string[];
}

export interface Report {
  format: typeof REPORT_FORMAT;
  runner: { name: string; version: string };
  protocol: string;
  corpus: { version: string; sha256: string; items: number };
  implementation: Implementation;
  declared_suites: string[];
  /** True when every item of every requested profile ran (a `limit` or a subset makes it false and nothing can be claimed). */
  complete: boolean;
  protocol_violations: number;
  profiles: Record<string, ProfileResult>;
  cases: CaseResult[];
}

export interface RunOptions {
  corpus: LoadedCorpus;
  driver: DriverSpec;
  profiles: string[];
  implementation: Implementation;
  /** Development aid: run only the first N items of each profile. The report is then incomplete and cannot be attested. */
  limit?: number;
  log?: (line: string) => void;
}

export function resultsDigest(corpusSha: string, profile: string, cases: readonly { id: string; outcome: Outcome }[]): string {
  return sha256hex(canonicalJson({ corpus: corpusSha, profile, cases: cases.map((c) => [c.id, c.outcome]) }));
}

/**
 * Derive every per-profile figure from the per-case outcomes. The runner and the report check use this one function, so a
 * report whose profile block does not follow from its cases is detectable.
 */
export function summarize(corpus: LoadedCorpus, cases: readonly CaseResult[], declared: readonly string[], violations: number, complete: boolean, profiles: readonly string[]): Record<string, ProfileResult> {
  const byId = new Map(cases.map((c) => [c.id, c]));
  const out: Record<string, ProfileResult> = {};
  for (const p of profiles) {
    const info = corpus.manifest.profiles[p];
    if (!info) continue;
    const its = corpus.items.filter((it) => it.profiles.includes(p));
    const rs = its.map((it) => byId.get(it.id));
    const by_layer: Record<string, { total: number; passed: number }> = {};
    let passed = 0, failed = 0, unsupported = 0, faults = 0, missing = 0;
    its.forEach((it, i) => {
      const r = rs[i];
      const l = (by_layer[it.layer] ??= { total: 0, passed: 0 });
      l.total++;
      if (!r) { missing++; return; }
      if (PASSING.has(r.outcome)) { passed++; l.passed++; } else if (r.outcome === 'fail') failed++; else if (r.outcome === 'unsupported') unsupported++; else faults++;
    });
    const reasons: string[] = [];
    if (!complete || missing) reasons.push(`incomplete run: ${its.length - missing} of ${its.length} items ran`);
    if (violations > 0) reasons.push(`${violations} protocol violation(s) in the driver output`);
    const need = info.requires_suites ?? [];
    const lacking = need.filter((s) => !declared.includes(s));
    if (lacking.length) reasons.push(`suite manifest lacks ${lacking.join(', ')}`);
    if (failed) reasons.push(`${failed} item(s) answered wrongly`);
    if (faults) reasons.push(`${faults} item(s) hung, crashed or went unanswered`);
    if (unsupported) reasons.push(`${unsupported} item(s) not implemented by the driver`);
    const status: ProfileStatus = !complete || missing ? 'incomplete' : failed || faults || violations > 0 || lacking.length ? 'fail' : unsupported ? 'unsupported' : 'pass';
    const done = its.flatMap((it, i) => (rs[i] ? [{ id: it.id, outcome: (rs[i] as CaseResult).outcome }] : []));
    out[p] = { status, total: its.length, passed, failed, unsupported, faults, by_layer, results_digest: resultsDigest(corpus.manifest.sha256, p, done), reasons };
  }
  return out;
}

function pick(items: CorpusItem[], profiles: readonly string[], limit?: number): CorpusItem[] {
  const chosen = new Set<string>();
  for (const p of profiles) {
    let n = 0;
    for (const it of items) {
      if (!it.profiles.includes(p)) continue;
      if (limit !== undefined && n++ >= limit) break;
      chosen.add(it.id);
    }
  }
  return items.filter((it) => chosen.has(it.id));
}

/** Drive an implementation over the corpus and build the report. Never throws on a bad driver: that is a result. */
export async function runConformance(opts: RunOptions): Promise<Report> {
  const { corpus } = opts;
  for (const p of opts.profiles) if (!corpus.manifest.profiles[p]) throw new Error(`unknown profile: ${p}`);
  const log = opts.log ?? (() => undefined);
  const items = pick(corpus.items, opts.profiles, opts.limit);
  const complete = opts.limit === undefined;
  const manifestItem = corpus.items.find((it) => it.kind === 'suites');
  const registered = corpus.manifest.registered_suites;
  const answers = new Map<string, Json>();
  const violations: string[] = [];

  // 1. the suite manifest alone first: it decides which vectors are judged strictly and which must be refused
  let declared = declaredSuites(undefined, registered);
  if (manifestItem) {
    const r = await runDriver(opts.driver, [sendLine(manifestItem, corpus.header)], 1);
    violations.push(...r.violations);
    const a = r.answers.get(manifestItem.id);
    if (a !== undefined) answers.set(manifestItem.id, a);
    declared = declaredSuites(isFault(a) ? undefined : a, registered);
  }
  // 2. everything else, producer items in small batches
  const rest = items.filter((it) => it.id !== manifestItem?.id);
  for (const group of [rest.filter((it) => it.kind !== 'produce'), rest.filter((it) => it.kind === 'produce')]) {
    if (!group.length) continue;
    const r = await runDriver(opts.driver, group.map((it) => sendLine(it, corpus.header)), group[0]!.kind === 'produce' ? 8 : opts.driver.batchSize ?? 200);
    violations.push(...r.violations);
    for (const [k, v] of r.answers) answers.set(k, v);
    log(`${group.length} item(s) ran${r.violations.length ? `, ${r.violations.length} protocol violation(s)` : ''}`);
    if (r.stderrTail) log(`driver stderr (tail): ${r.stderrTail.trim().slice(-200)}`);
  }

  const cases: CaseResult[] = items.map((it) => {
    const a = answers.get(it.id);
    if (a === undefined || isFault(a)) return { id: it.id, layer: it.layer, outcome: 'fault', why: a === undefined ? 'missing' : a.fault };
    const v = judge(it, a, declared, registered);
    return { id: it.id, layer: it.layer, outcome: v.outcome, ...(v.why !== undefined ? { why: v.why } : {}) };
  });
  const declaredList = [...declared].sort();
  return {
    format: REPORT_FORMAT,
    runner: { name: RUNNER_NAME, version: runnerVersion() },
    protocol: corpus.manifest.protocol_version,
    corpus: { version: corpus.manifest.corpus_version, sha256: corpus.manifest.sha256, items: corpus.manifest.items },
    implementation: opts.implementation,
    declared_suites: declaredList,
    complete,
    protocol_violations: violations.length,
    profiles: summarize(corpus, cases, declaredList, violations.length, complete, opts.profiles),
    cases,
  };
}

export interface ReportCheck {
  ok: boolean;
  reasons: string[];
}

/** Check a report against the corpus: its profile blocks must follow from its cases, and its cases from the corpus. */
export function verifyReport(report: Report, corpus: LoadedCorpus): ReportCheck {
  const reasons: string[] = [];
  try {
    if (report?.format !== REPORT_FORMAT) return { ok: false, reasons: ['not a pca-verified report'] };
    if (report.corpus?.sha256 !== corpus.manifest.sha256) reasons.push('report is for a different corpus');
    const ids = new Map(corpus.items.map((it) => [it.id, it]));
    for (const c of report.cases) {
      const it = ids.get(c.id);
      if (!it || it.layer !== c.layer) { reasons.push(`case ${String(c.id)} is not in the corpus`); break; }
    }
    if (new Set(report.cases.map((c) => c.id)).size !== report.cases.length) reasons.push('a case appears twice');
    const names = Object.keys(report.profiles);
    const derived = summarize(corpus, report.cases, report.declared_suites, report.protocol_violations, report.complete, names);
    if (!sameJson(derived, report.profiles)) reasons.push('profile results do not follow from the cases');
  } catch (e) {
    reasons.push(`malformed report: ${(e as Error).message}`);
  }
  return { ok: reasons.length === 0, reasons };
}

/** The human summary: one line per profile, then the first failures. */
export function formatSummary(r: Report): string {
  const lines = [`PCA Verified ${r.runner.version}  corpus ${r.corpus.version} (${r.corpus.sha256.slice(0, 12)})  ${r.implementation.name} ${r.implementation.version}`];
  lines.push(`declared suites: ${r.declared_suites.join(', ') || 'none'}`);
  for (const [p, x] of Object.entries(r.profiles)) {
    lines.push(`${x.status === 'pass' ? 'PASS' : x.status.toUpperCase().padEnd(4)}  ${p.padEnd(14)} ${x.passed}/${x.total}` + (x.reasons.length ? `  (${x.reasons.join('; ')})` : ''));
    for (const [l, v] of Object.entries(x.by_layer)) lines.push(`        ${l.padEnd(10)} ${v.passed}/${v.total}`);
  }
  const bad = r.cases.filter((c) => !PASSING.has(c.outcome)).slice(0, 10);
  if (bad.length) {
    lines.push('first non-passing items:');
    for (const c of bad) lines.push(`  ${c.id} [${c.layer}] ${c.outcome}${c.why ? ': ' + c.why : ''}`);
  }
  return lines.join('\n');
}
