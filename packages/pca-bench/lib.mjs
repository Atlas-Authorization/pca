// Shared, dependency-free statistics and the regression-gate decision logic. Pure functions: the same inputs give the same
// verdict on every machine (no clocks, no randomness, no I/O), so the gate cannot be flaky by construction; only its inputs can
// be noisy, and the rules below are written so that noise alone cannot fail a run.

export const RESULT_SCHEMA = 'pca-bench-result/1';
export const DEFAULTS = { threshold: 0.2, alpha: 0.05, minRounds: 5, denyTolerance: 0.1 };

export const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const n = s.length;
  return n === 0 ? NaN : n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
};

/** Nearest-rank quantile of an ascending array (q in (0,1]). */
export const quantile = (sorted, q) => sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(q * sorted.length) - 1))];

/**
 * Summarise per-operation latencies in ns, in the order they were measured. `rounds_ns` are the medians of `rounds`
 * contiguous chunks: that is the sample the gate tests (time-ordered chunks, so a slow stretch hits one round, not all).
 */
export function summarize(samplesNs, rounds = 7) {
  const n = samplesNs.length;
  if (n === 0) throw new Error('summarize: no samples');
  const sorted = [...samplesNs].sort((a, b) => a - b);
  const mean = samplesNs.reduce((a, b) => a + b, 0) / n;
  const r = Math.max(1, Math.min(rounds, n));
  const per = Math.floor(n / r);
  const rounds_ns = Array.from({ length: r }, (_, i) => median(samplesNs.slice(i * per, (i + 1) * per)));
  return { ops_per_sec: 1e9 / mean, mean_ns: mean, p50_ns: quantile(sorted, 0.5), p95_ns: quantile(sorted, 0.95), p99_ns: quantile(sorted, 0.99), rounds_ns };
}

/**
 * Exact one-sided Mann-Whitney U p-value that `a` is stochastically GREATER than `b` (a slower than b), with mid-ranks for
 * ties. Exact by counting: doubled mid-ranks are integers, and a subset-sum table over them gives the number of equally likely
 * assignments whose rank-sum is at least the observed one. Deterministic; fine for the small n (5..40) the gate uses.
 */
export function mannWhitneyGreaterP(a, b) {
  const n1 = a.length;
  const n2 = b.length;
  const all = [...a.map((v) => [v, 0]), ...b.map((v) => [v, 1])].sort((x, y) => x[0] - y[0]);
  const N = all.length;
  const r2 = new Array(N); // doubled mid-rank of each sorted item
  for (let i = 0; i < N; ) {
    let j = i;
    while (j + 1 < N && all[j + 1][0] === all[i][0]) j++;
    const doubled = i + 1 + (j + 1); // 2 * mean(rank i+1 .. j+1)
    for (let k = i; k <= j; k++) r2[k] = doubled;
    i = j + 1;
  }
  let observed = 0;
  all.forEach(([, g], i) => {
    if (g === 0) observed += r2[i];
  });
  const total = r2.reduce((s, x) => s + x, 0);
  // ways[k][s]: number of k-subsets of the items seen so far with doubled rank-sum s
  const ways = Array.from({ length: n1 + 1 }, () => new Map());
  ways[0].set(0, 1);
  for (let i = 0; i < N; i++) {
    for (let k = Math.min(n1, i + 1); k >= 1; k--) {
      for (const [s, c] of ways[k - 1]) ways[k].set(s + r2[i], (ways[k].get(s + r2[i]) ?? 0) + c);
    }
  }
  let ge = 0;
  let all_ = 0;
  for (const [s, c] of ways[n1]) {
    all_ += c;
    if (s >= observed) ge += c;
  }
  void total;
  void n2;
  return ge / all_;
}

/** A slower-than test used for both gates: ratio of round medians above `1 + tol` AND a significant one-sided rank test. */
export function slower(candRounds, baseRounds, tol, alpha) {
  const ratio = median(candRounds) / median(baseRounds);
  const p = mannWhitneyGreaterP(candRounds, baseRounds);
  return { ratio, p, slower: ratio > 1 + tol && p < alpha };
}

/** Concatenate repeated runs of one lane into one result (rounds are pooled per scenario; first run supplies the metadata). */
export function mergeRuns(runs) {
  if (runs.length === 0) throw new Error('mergeRuns: no runs');
  const out = JSON.parse(JSON.stringify(runs[0]));
  for (const s of out.scenarios) {
    const peers = runs.map((r) => r.scenarios.find((x) => x.id === s.id)).filter((x) => x && x.status === 'ok');
    if (s.status !== 'ok' || peers.length === 0) continue;
    s.rounds_ns = peers.flatMap((x) => x.rounds_ns);
    const mean = peers.reduce((a, x) => a + x.mean_ns, 0) / peers.length;
    s.mean_ns = mean;
    s.ops_per_sec = 1e9 / mean;
    for (const k of ['p50_ns', 'p95_ns', 'p99_ns']) s[k] = median(peers.map((x) => x[k]));
  }
  out.repeats = runs.length;
  if (runs.every((r) => typeof r.cold_start_ns === 'object' && r.cold_start_ns)) {
    out.cold_start_ns = Object.fromEntries(Object.keys(runs[0].cold_start_ns).map((k) => [k, median(runs.map((r) => r.cold_start_ns[k]).filter(Number.isFinite))]));
  }
  return out;
}

const runnerClass = (r) => `${r?.runner?.os ?? '?'}|${r?.runner?.arch ?? '?'}|${r?.runner?.cpu ?? '?'}`;

/**
 * The gate. `baseline` may be null (no baseline yet: pass with a notice). Returns { verdict: 'pass'|'fail', rows, notices }.
 * A scenario FAILS only when (a) it slowed by more than `threshold` on the median of its rounds AND (b) a one-sided exact rank
 * test over the rounds rejects "no change" at `alpha`. Everything else (too few rounds, other hardware, new scenario, a corpus
 * change that only needs a refresh) is a notice, never a failure; an error in a scenario that used to run IS a failure.
 */
export function gate(baseline, candidate, opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  const rows = [];
  const notices = [];
  let fail = false;
  const bad = (id, why) => {
    fail = true;
    rows.push({ id, status: 'FAIL', note: why });
  };

  // 1) deny paths, judged inside the candidate run (hardware cancels out): never slower than the allow path they derive from
  const byId = new Map(candidate.scenarios.map((s) => [s.id, s]));
  for (const s of candidate.scenarios) {
    if (!s.pair || s.status !== 'ok') continue;
    const p = byId.get(s.pair);
    if (!p || p.status !== 'ok') continue;
    if (s.rounds_ns.length < o.minRounds || p.rounds_ns.length < o.minRounds) continue;
    const t = slower(s.rounds_ns, p.rounds_ns, o.denyTolerance, o.alpha);
    if (t.slower) bad(s.id, `deny path is ${t.ratio.toFixed(2)}x its allow path ${s.pair} (p=${t.p.toFixed(4)}): must be as fast or faster`);
  }

  // 2) no baseline yet
  const errored = candidate.scenarios.filter((s) => s.status === 'error').map((s) => s.id);
  if (errored.length) notices.push(`scenarios that did not run (fix the harness or the lane; they fail the gate once a baseline exists): ${errored.join(', ')}`);
  if (!baseline) {
    notices.push('no baseline yet: regression comparison skipped (deny-path rule still enforced). Commit this run as the baseline, see docs.');
    return finish();
  }
  if (baseline.corpus?.digest !== candidate.corpus?.digest) {
    notices.push(`corpus changed (baseline ${String(baseline.corpus?.digest).slice(0, 12)}, now ${String(candidate.corpus?.digest).slice(0, 12)}): baseline is stale, regression comparison skipped. Refresh the baseline.`);
    return finish();
  }
  if (runnerClass(baseline) !== runnerClass(candidate)) {
    notices.push(`baseline was recorded on different hardware (${runnerClass(baseline)} vs ${runnerClass(candidate)}): regression comparison skipped. Refresh the baseline on this runner class.`);
    return finish();
  }

  // 3) regression check, scenario by scenario
  for (const s of candidate.scenarios) {
    if (s.pair && rows.some((r) => r.id === s.id)) continue;
    const b = baseline.scenarios.find((x) => x.id === s.id);
    if (!b) {
      rows.push({ id: s.id, status: 'new', note: 'not in the baseline' });
      continue;
    }
    if (s.status === 'error' && b.status === 'ok') {
      bad(s.id, `now errors (${s.note ?? 'no detail'}), baseline ran`);
      continue;
    }
    if (s.status !== 'ok' || b.status !== 'ok') {
      rows.push({ id: s.id, status: s.status === 'ok' ? 'new' : s.status, note: s.note ?? '' });
      continue;
    }
    if (s.rounds_ns.length < o.minRounds || b.rounds_ns.length < o.minRounds) {
      rows.push({ id: s.id, status: 'warn', note: `fewer than ${o.minRounds} rounds: not judged` });
      continue;
    }
    const t = slower(s.rounds_ns, b.rounds_ns, o.threshold, o.alpha);
    const better = slower(b.rounds_ns, s.rounds_ns, o.threshold, o.alpha);
    if (t.slower) bad(s.id, `median ${t.ratio.toFixed(2)}x baseline (limit ${(1 + o.threshold).toFixed(2)}x, p=${t.p.toFixed(4)})`);
    else rows.push({ id: s.id, status: better.slower ? 'faster' : 'ok', note: `${t.ratio.toFixed(2)}x`, ratio: t.ratio });
  }
  for (const b of baseline.scenarios) {
    if (b.status === 'ok' && !byId.has(b.id)) bad(b.id, 'present in the baseline, missing from this run');
  }
  // cold start: one sample per process, so reported but never a failure
  for (const [k, v] of Object.entries(candidate.cold_start_ns ?? {})) {
    const bv = baseline.cold_start_ns?.[k];
    if (Number.isFinite(v) && Number.isFinite(bv) && v > 3 * bv) notices.push(`cold start ${k}: ${(v / 1e6).toFixed(2)} ms vs baseline ${(bv / 1e6).toFixed(2)} ms (informational, one sample per process)`);
  }
  return finish();

  function finish() {
    return { verdict: fail ? 'fail' : 'pass', rows, notices };
  }
}

const fmtNs = (ns) => (ns >= 1e6 ? `${(ns / 1e6).toFixed(2)} ms` : ns >= 1e3 ? `${(ns / 1e3).toFixed(1)} us` : `${ns.toFixed(0)} ns`);
export { fmtNs };

/** The results table the docs page and CI summary show: one row per scenario, one column pair per language. */
export function markdownTable(results, ids) {
  const langs = results.map((r) => r.lang);
  const all = ids ?? [...new Set(results.flatMap((r) => r.scenarios.map((s) => s.id)))];
  const head = `| scenario | ${langs.map((l) => `${l} p50 | ${l} ops/s`).join(' | ')} |`;
  const sep = `|---|${langs.map(() => '---:|---:').join('|')}|`;
  const body = all.map((id) => {
    const cells = results.map((r) => {
      const s = r.scenarios.find((x) => x.id === id);
      return s && s.status === 'ok' ? `${fmtNs(s.p50_ns)} | ${Math.round(s.ops_per_sec).toLocaleString('en-US')}` : `${s ? s.status : 'n/a'} | -`;
    });
    return `| ${id} | ${cells.join(' | ')} |`;
  });
  return [head, sep, ...body].join('\n');
}
