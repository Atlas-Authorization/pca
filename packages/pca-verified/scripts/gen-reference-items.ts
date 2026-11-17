// Computes the REFERENCE verdicts that the bundled corpus carries for the generated adversarial / mutation items and the regression
// vectors. Runs in the PCA repository only (the TypeScript reference is the oracle); a third party only ever sees its output, which
// is bundled into the corpus, versioned and hash-pinned.
//
//   tsx scripts/gen-reference-items.ts --adversarial-corpus FILE --out FILE
//     FILE = the output of `gen-adversarial.ts --corpus FILE` (the full generated items with the reference verdict recorded at generation)
//
// Drift check: every generated item must agree (id, category, name, kind, length, reference verdict) with the committed
// adversarial/manifest.jsonl, so a corpus that no longer matches what the repository pins is refused here.
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { refCanon, refChain, refVerify } from '../../pca-conformance/adversarial/ref';

const ADV = join(__dirname, '../../pca-conformance/adversarial');
const argv = process.argv.slice(2);
const opt = (k: string): string | undefined => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : undefined; };
const corpusFile = opt('--adversarial-corpus');
const outFile = opt('--out');
if (!corpusFile || !outFile) { console.error('usage: gen-reference-items.ts --adversarial-corpus FILE --out FILE'); process.exit(2); }

type Json = any; // eslint-disable-line @typescript-eslint/no-explicit-any
const stable = (v: Json): string => JSON.stringify(v, (_k, x) => (x && typeof x === 'object' && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, x[k]])) : x));
const lines = (f: string): Json[] => readFileSync(f, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
// the reference's live-only tag is not part of the recorded expectation (the manifest drops it too)
const clean = (r: Json): Json => { const { unsupported_suite: _u, ...rest } = r; return rest; };

async function main(): Promise<void> {
  const gen = lines(corpusFile!);
  const pinned = new Map<string, Json>(lines(join(ADV, 'manifest.jsonl')).map((m) => [m.id, m]));
  if (gen.length !== pinned.size) throw new Error(`drift: ${gen.length} generated items, ${pinned.size} pinned in manifest.jsonl`);
  const out: Json[] = [];
  for (const g of gen) {
    const m = pinned.get(g.id);
    if (!m || m.category !== g.category || m.name !== g.name || m.kind !== g.kind || m.rawLen !== g.raw.length || stable(m.ref) !== stable(clean(g.ref))) throw new Error(`drift: item ${g.id} (${g.category}/${g.name}) differs from manifest.jsonl`);
    const { intent: _i, rawLen: _r, refDeviates: _d, ...item } = g;
    out.push({ source: 'adversarial', ...item, ref: clean(g.ref) });
  }
  const regDir = join(ADV, 'regressions');
  if (existsSync(regDir)) {
    for (const f of readdirSync(regDir).filter((x) => x.endsWith('.json')).sort()) {
      const j = JSON.parse(readFileSync(join(regDir, f), 'utf8'));
      const kind = j.kind as string;
      const grant = j.grant ?? '';
      const ref = clean(kind === 'verify' ? await refVerify(j.raw, grant, j.now ?? 0, j.aud ?? '') : kind === 'chain' ? refChain(j.raw) : refCanon(j.raw));
      out.push({ source: 'regression', id: 'reg-' + f.replace(/\.json$/, ''), category: 'regression', name: j.name ?? f, kind, raw: j.raw, grant, now: j.now ?? 0, aud: j.aud ?? '', ref });
    }
  }
  writeFileSync(outFile!, out.map((o) => JSON.stringify(o)).join('\n') + '\n');
  console.log(`wrote ${out.length} reference items (${gen.length} generated, ${out.length - gen.length} regressions)`);
}
void main().catch((e) => { console.error(String((e as Error).message)); process.exit(1); });
