/**
 * Run every attack against every approach (fresh keys and state per cell) and render the matrix.
 */
import { ATTACKS, type Outcome } from './attacks.js';
import type { Approach } from './common.js';
import { oauthApproach } from './approaches/oauth.js';
import { rarApproach } from './approaches/rar.js';
import { macaroonApproach } from './approaches/macaroon.js';
import { ucanApproach } from './approaches/ucan.js';
import { pcaApproach } from './approaches/pca.js';

export const APPROACHES: Array<() => Approach> = [oauthApproach, rarApproach, macaroonApproach, ucanApproach, pcaApproach];

export interface Row {
  attack: (typeof ATTACKS)[number];
  results: Array<{ ap: Approach; out: Outcome }>;
}

export async function runAll(): Promise<Row[]> {
  const rows: Row[] = [];
  for (const attack of ATTACKS) {
    const results: Row['results'] = [];
    for (const make of APPROACHES) {
      const ap = make(); // fresh keys and state per cell
      results.push({ ap, out: await attack.run(ap) });
    }
    rows.push({ attack, results });
  }
  return rows;
}

export function matrix(rows: Row[]): string {
  const labels = rows[0]!.results.map((r) => r.ap.label);
  const lines = [
    `| Attack | ${labels.join(' | ')} |`,
    `|---|${labels.map(() => '---').join('|')}|`,
    ...rows.map((r) => `| ${r.attack.id}. ${r.attack.title} | ${r.results.map((x) => (x.out.stopped ? 'Stopped' : '**Not stopped**')).join(' | ')} |`),
  ];
  return lines.join('\n');
}
