import { bundledManifest } from './corpus';
import { verifyStatementEnvelope, type StatementEnvelope, type VerifyStatementOptions } from './statement';

export class BadgeError extends Error {
  constructor(readonly reasons: string[]) {
    super(`no badge: the statement does not verify (${reasons.join('; ')})`);
    this.name = 'BadgeError';
  }
}

/** shields.io endpoint schema (https://shields.io/badges/endpoint-badge), so the JSON can be served as a live badge. */
export interface BadgeEndpoint {
  schemaVersion: 1;
  label: string;
  message: string;
  color: string;
}

export interface Badge {
  svg: string;
  endpoint: BadgeEndpoint;
}

const esc = (s: string): string => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
const textWidth = (s: string): number => Math.ceil(s.length * 6.6) + 10;

/** Render a badge from a statement. The statement is verified first (with `opts`); anything that does not verify produces no badge. */
export function makeBadge(env: StatementEnvelope, opts: VerifyStatementOptions = {}): Badge {
  const v = verifyStatementEnvelope(env, opts);
  if (!v.ok || !v.payload) throw new BadgeError(v.reasons);
  const p = v.payload;
  const title = (opts.corpora ?? [bundledManifest()]).find((c) => c.sha256 === p.corpus.sha256)?.profiles[p.profile]?.title ?? p.profile;
  const label = 'PCA Verified';
  const message = `${title} · corpus ${p.corpus.version}`;
  const lw = textWidth(label);
  const mw = textWidth(message);
  const svg = [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${lw + mw}" height="20" role="img" aria-label="${esc(label)}: ${esc(message)}">`,
    `<title>${esc(label)}: ${esc(message)}</title>`,
    `<rect width="${lw}" height="20" fill="#555"/><rect x="${lw}" width="${mw}" height="20" fill="#2e8b57"/>`,
    `<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">`,
    `<text x="${lw / 2}" y="14">${esc(label)}</text><text x="${lw + mw / 2}" y="14">${esc(message)}</text></g></svg>`,
  ].join('');
  return { svg, endpoint: { schemaVersion: 1, label, message, color: 'brightgreen' } };
}
