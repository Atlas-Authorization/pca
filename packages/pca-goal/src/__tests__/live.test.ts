import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { hostileCases, mainCases, DOMAINS } from '../../benchmarks/data';
import { DOMAIN_ALPHA, evalCase, summarize, compileWideningCount, truthGoal, truthOnt, type CaseOutcome } from '../bench';
import { renderReportMarkdown, type DomainReport } from '../crc';
import { anthropicCompletion, openaiCompletion } from '../interpret';

/**
 * Scheduled live-model evaluation. Skipped unless PCA_GOAL_LIVE=1. Keys come ONLY from the environment (the workflow maps
 * GitHub secrets into it); the completions redact the key from any error and nothing here prints an environment value.
 * Models are pinned by exact id through PCA_GOAL_MODEL_A / PCA_GOAL_MODEL_B.
 */
const live = process.env.PCA_GOAL_LIVE === '1';
const N = Number(process.env.PCA_GOAL_LIVE_N ?? '60');

describe.skipIf(!live)('live model evaluation', () => {
  it('measures per-domain widening with live models and writes the report', async () => {
    const a = process.env.ANTHROPIC_API_KEY, o = process.env.OPENAI_API_KEY;
    const ma = process.env.PCA_GOAL_MODEL_A, mb = process.env.PCA_GOAL_MODEL_B;
    if (!a || !o || !ma || !mb) throw new Error('live evaluation needs both API keys and both pinned model ids in the environment');
    const comp = { 'model-a': anthropicCompletion({ apiKey: a, model: ma }), 'model-b': openaiCompletion({ apiKey: o, model: mb }) };
    const reports: DomainReport[] = [];
    for (const d of DOMAINS) {
      const cases = [...mainCases(d).slice(0, N), ...hostileCases(d).slice(0, Math.ceil(N / 2))];
      const outcomes: CaseOutcome[] = [];
      for (const c of cases) outcomes.push(await evalCase(c, comp));
      const r = summarize(d, outcomes, `${ma} + ${mb} + rule`, compileWideningCount(cases.slice(0, 25).map((c) => { const goal = truthGoal(c); return { goal, ont: truthOnt(c, goal) }; })));
      reports.push(r);
      expect(r.compileWidening.k).toBe(0); // release blocker
    }
    const dir = process.env.PCA_GOAL_REPORT_DIR ?? 'live-report';
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'intent-fidelity-live.md'), renderReportMarkdown(reports, { source: 'live', modelSet: `${ma} + ${mb} + rule` }));
    writeFileSync(join(dir, 'intent-fidelity-live.json'), JSON.stringify(reports, null, 1));
    // the N-version level must hold its alpha with live models; the single-model level is reported, not gated
    for (const r of reports) expect(r.perLevel[1]!.widening.cpUpper95, r.domain).toBeLessThanOrEqual(Math.max(DOMAIN_ALPHA[r.domain]!, 3 / Math.max(1, r.perLevel[1]!.widening.n)));
  }, 3_600_000);
});
