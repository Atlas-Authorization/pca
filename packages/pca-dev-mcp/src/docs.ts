/** Offline search over the PCA docs (markdown) that ship in this package. No network, no index file: sections are scored in memory. */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

export interface DocHit { file: string; heading: string; anchor: string; score: number; snippet: string }
interface Section { file: string; heading: string; anchor: string; body: string }

/** The bundled docs (npm package), or the repository's docs/pca (docs/ in the public layout) when running from a checkout. */
export function defaultDocsDir(): string | undefined {
  for (const c of [resolve(__dirname, '../docs-bundle'), resolve(__dirname, '../../../docs/pca'), resolve(__dirname, '../../../docs')]) if (existsSync(c)) return c;
  return undefined;
}

const EXCLUDE = new Set(['specs', 'release-notes', 'validation', 'advisories', 'diagrams', 'public']);
function files(dir: string, rel = ''): string[] {
  const out: string[] = [];
  for (const n of readdirSync(join(dir, rel)).sort()) {
    if (n.startsWith('_') || n.startsWith('.')) continue;
    const r = rel ? `${rel}/${n}` : n;
    if (statSync(join(dir, r)).isDirectory()) { if (!EXCLUDE.has(n)) out.push(...files(dir, r)); } else if (n.endsWith('.md')) out.push(r);
  }
  return out;
}

const anchorOf = (h: string): string => h.toLowerCase().replace(/[^a-z0-9 _-]/g, '').trim().replace(/\s+/g, '-');

function sections(dir: string): Section[] {
  const out: Section[] = [];
  for (const file of files(dir)) {
    const text = readFileSync(join(dir, file), 'utf8').replace(/^---\n[\s\S]*?\n---\n/, '');
    let heading = file;
    let buf: string[] = [];
    const flush = (): void => { if (buf.join('').trim()) out.push({ file, heading, anchor: anchorOf(heading), body: buf.join('\n') }); buf = []; };
    for (const line of text.split('\n')) {
      const m = /^#{1,3}\s+(.*)$/.exec(line);
      if (m) { flush(); heading = m[1]!.trim(); } else buf.push(line);
    }
    flush();
  }
  return out;
}

const words = (s: string): string[] => s.toLowerCase().split(/[^a-z0-9_.]+/).filter((w) => w.length > 1);

export function searchDocs(query: string, dir: string | undefined, limit = 5): DocHit[] {
  if (dir === undefined || !existsSync(dir)) throw new Error('the PCA docs are not bundled in this install');
  const q = words(query);
  if (q.length === 0) throw new Error('query must contain at least one word');
  const hits: DocHit[] = [];
  for (const s of sections(dir)) {
    const head = words(s.heading + ' ' + s.file);
    const body = s.body.toLowerCase();
    let score = 0;
    for (const w of q) {
      if (head.includes(w)) score += 5;
      let i = body.indexOf(w), n = 0;
      while (i >= 0 && n < 10) { n++; i = body.indexOf(w, i + w.length); }
      score += n;
    }
    if (score === 0) continue;
    const at = Math.max(0, body.indexOf(q.find((w) => body.includes(w)) ?? ''));
    hits.push({ file: s.file, heading: s.heading, anchor: s.anchor, score, snippet: s.body.slice(Math.max(0, at - 80), at + 400).trim() });
  }
  return hits.sort((a, b) => b.score - a.score || a.file.localeCompare(b.file)).slice(0, Math.max(1, Math.min(limit, 20)));
}
