#!/usr/bin/env node
// Every planned mutant is reported (pca-rust mutation merge): the shard reports' counts add up to the plan the snapshot job
// listed (cargo-mutants + stmt-mut), each statement shard holds exactly its round-robin slice, and every shard lists one
// survivor per missed mutant. A dropped mutant or survivor fails the merge. The check runs twice more on doctored copies of
// the reports (one real mutant dropped, one survivor dropped) and fails unless both are refused: the negative control.
//   node plan-check.mjs --reports=<dir> --plan=<plan.json> --shards=<N>
// plan.json: { cargo_mutants: <count>, cm_shards: <n>, stmt: <count>, stmt_shards: <n> }; shards 1..cm_shards are
// cargo-mutants', the rest statement shards.
import fs from 'node:fs';
import path from 'node:path';

const opt = (n) => process.argv.slice(2).find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);

export function check(reports, plan, shards) {
  const errs = [];
  if (plan.cm_shards + plan.stmt_shards !== shards) errs.push(`plan has ${plan.cm_shards} + ${plan.stmt_shards} shards, the run ${shards}`);
  let cm = 0, st = 0;
  for (const r of reports) {
    const n = Object.values(r.counts ?? {}).reduce((a, b) => a + b, 0);
    if ((r.survivors ?? []).length !== (r.counts?.missed ?? 0)) errs.push(`shard ${r.shard}: ${r.survivors?.length} survivor record(s) for ${r.counts?.missed} missed`);
    if (r.shard <= plan.cm_shards) cm += n;
    else {
      st += n;
      const k0 = r.shard - plan.cm_shards - 1, want = Math.floor(plan.stmt / plan.stmt_shards) + (k0 < plan.stmt % plan.stmt_shards ? 1 : 0);
      if (n !== want) errs.push(`statement shard ${r.shard}: ${n} mutant(s) reported, its slice has ${want}`);
    }
  }
  if (cm !== plan.cargo_mutants) errs.push(`cargo-mutants shards report ${cm} mutant(s), the plan lists ${plan.cargo_mutants}`);
  if (st !== plan.stmt) errs.push(`statement shards report ${st} mutant(s), the plan lists ${plan.stmt}`);
  return errs;
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const plan = JSON.parse(fs.readFileSync(opt('plan'), 'utf8')), shards = Number(opt('shards'));
  const reports = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (/^shard-\d+\.json$/.test(e.name)) reports.push(JSON.parse(fs.readFileSync(p, 'utf8'))); } };
  walk(opt('reports'));
  const errs = check(reports, plan, shards);
  for (const e of errs) console.error('::error::' + e);
  // negative control: the same check must refuse the reports with one real mutant, or one survivor record, taken out
  const clone = () => JSON.parse(JSON.stringify(reports));
  const dropMutant = clone(), dropSurvivor = clone();
  const withMissed = dropMutant.find((r) => (r.counts?.missed ?? 0) > 0) ?? dropMutant.find((r) => (r.counts?.caught ?? 0) > 0);
  if (withMissed?.counts.missed > 0) { withMissed.counts.missed--; withMissed.survivors.pop(); } else if (withMissed) withMissed.counts.caught--;
  const s = dropSurvivor.find((r) => (r.survivors ?? []).length > 0);
  if (s) s.survivors.pop();
  const ctl = [['one mutant dropped', dropMutant, true], ['one survivor record dropped', dropSurvivor, !!s]];
  let ctlBad = 0;
  for (const [what, rs, applies] of ctl) {
    if (!applies) { console.log(`negative control (${what}): no survivor in this run to drop`); continue; }
    const e = check(rs, plan, shards);
    if (e.length === 0) { console.error(`::error::negative control failed: the check passes with ${what}`); ctlBad++; }
    else console.log(`negative control (${what}): refused (${e[0]})`);
  }
  const total = reports.reduce((a, r) => a + Object.values(r.counts ?? {}).reduce((x, y) => x + y, 0), 0);
  console.log(`${total} mutant(s) reported over ${reports.length} shard(s); plan ${plan.cargo_mutants} cargo-mutants + ${plan.stmt} statement; ${errs.length} problem(s)`);
  process.exit(errs.length || ctlBad ? 1 : 0);
}
