// explain.ts - the plain-language profile of one def (spec section 4.1): its policy card, the effective profile, and what a
// grant must carry before the action is auto-allowed. Deterministic text (golden-file tested).

import type { ActionDef } from './def';
import { cardOf } from './derive';
import { effective, type ReviewOpts } from './effective';
import type { Registry } from './traits';

const blastText = (ppm: number): string => (ppm % 1000 === 0 ? `${ppm / 1000}k` : `${ppm}ppm`);

export function explainDef(d: ActionDef, reg: Registry, opts: ReviewOpts = {}): string {
  const eff = effective(d, reg, opts);
  const card = cardOf(d, eff, reg);
  const e = eff.eff;
  const lines = [
    card.text,
    `effective: risk ${e.risk}, ${e.rev === 'irreversible' ? 'irreversible' : e.rev === 'rate_limited' ? 'rate limited' : 'reversible'}, blast ${blastText(e.blast_ppm)}, escalation: ${card.escalation}`,
    `grant must carry: ${card.needs.length > 0 ? card.needs.join(', ') : 'nothing'}`,
  ];
  if (card.context.length > 0) lines.push(`call must carry: ${card.context.join(', ')}`);
  lines.push(`traits: ${eff.closure.join(', ') || 'none'}`, `review: ${eff.confirmed ? d.review.state : `${d.review.state}, not confirmed by a signed review`}`);
  if (!eff.confirmed) {
    // what a reviewer would be signing: the machine/author traits are a HINT until then, and enforcement uses the top
    const h = eff.hint;
    lines.push(`until a reviewer signs it this action is treated as the most dangerous kind of action; as written it would be: risk ${h.eff.risk}, escalation tier ${h.eff.esc}, traits: ${h.closure.join(', ') || 'none'}`);
  }
  return lines.join('\n');
}
