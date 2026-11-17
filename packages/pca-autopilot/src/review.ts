/** The reviewer's page: plain language first, then the facts a signature should rest on. */
import { cleanText } from '@atlasauth/pca-explain';
import type { Report } from './verify';
import type { Proposal } from './types';

const when = (ms: number): string => new Date(ms).toISOString().slice(0, 16).replace('T', ' ');
const c = (s: unknown): string => cleanText(String(s));

export function summarize(p: Proposal, r?: Report): string {
  const L: string[] = [];
  L.push(`PROPOSED GRANT${p.tenant ? ` for tenant ${c(p.tenant)}` : ''}  (digest ${p.digest.slice(0, 16)})${p.amends ? `  amends ${p.amends.slice(0, 16)}` : ''}`);
  L.push(`Built from ${p.basis.included} observed action(s), ${when(p.basis.from)} to ${when(p.basis.to)} UTC. This is a proposal: it grants nothing until a pinned reviewer signs it.`);
  L.push('', 'It would let the agent:');
  for (const x of p.rules) {
    L.push(`  - ${c(x.verb)} on ${c(x.resource)}${x.rung === 1 ? '  (generalized: every resource under that parent)' : ''}, seen ${x.observed} time(s)`);
    for (const n of x.params) L.push(`      ${c(n)}`);
    L.push(`      why: ${c(x.why)}`);
  }
  const ex = p.policy.caveats.find((v) => v.type === 'expires');
  const rate = p.policy.caveats.find((v) => v.type === 'rate');
  const rev = p.policy.caveats.find((v) => v.type === 'reversibility_max');
  L.push('', 'Limits:');
  if (rate) L.push(`  - at most ${c(rate.max)} action(s) per ${c(rate.per_secs)} seconds`);
  if (rev) L.push(`  - nothing less reversible than "${c(rev.class)}"`);
  if (ex) L.push(`  - expires ${when(ex.at as number)} UTC`);
  L.push(`  - budget: ${p.riskPolicy.bMax} units (a human is asked again when it runs out)`);
  for (const n of p.notes) L.push(`  note: ${c(n)}`);
  if (p.confirmedSensitive.length) L.push('', `Sensitive actions INCLUDED because they were confirmed by id: ${p.confirmedSensitive.join(', ')}`);
  if (p.heldBack.length) {
    L.push('', 'HELD BACK (not in this proposal; each needs your explicit per-item confirmation):');
    for (const h of p.heldBack) L.push(`  - ${h.id}  ${c(h.verb)} on ${c(h.resource)} x${h.count}  [${h.reasons.map(c).join(', ')}]`);
  }
  if (r) {
    L.push('', `VERIFICATION: ${r.ok ? 'PASSED' : 'FAILED'}`);
    L.push(`  replayed ${r.replay.total} action(s) through the verifier: ${r.replay.passed} pass, ${r.replay.total - r.replay.passed} fail; ${r.replay.autonomous} fully autonomous, ${r.replay.humanSteps} still ask a human by risk tier`);
    if (!r.intact) L.push('  the proposal was modified after it was made');
    if (!r.basisMatches) L.push('  the traces are not the ones this proposal was built from');
    for (const f of r.replay.failures.slice(0, 5)) L.push(`  FAIL ${c(f.verb)} ${c(f.resource)}: ${f.failed.map(c).join(', ') || `${f.policy}/${f.verifier}`}`);
    L.push('', 'EXCESS AUTHORITY (what else this admits beyond what was observed):');
    for (const s of r.excess.summary) L.push(`  - ${c(s)}`);
    for (const w of r.excess.witnesses) L.push(`  - e.g. ${c(w.verb)} on ${c(w.resource)} ${c(JSON.stringify(w.params))} [${w.kinds.join(', ')}]`);
    if (r.excess.approximate) L.push('  (the analysis could not be exact for part of this policy; read it as incomplete, not as clean)');
    if (r.lint.length) { L.push('', 'LINT:'); for (const f of r.lint) L.push(`  ${f.severity}: ${c(f.message)}`); }
    if (r.diff) {
      L.push('', `COMPARED WITH THE POLICY IN FORCE: ${r.diff.equivalent ? 'equivalent' : r.diff.widens ? 'WIDER in places' : 'narrower'}${r.diff.approximate ? ' (inexact)' : ''}`);
      for (const s of r.diff.summary) L.push(`  - ${c(s)}`);
    }
  } else L.push('', 'Not verified yet: run `pca autopilot verify` first.');
  return L.join('\n');
}
