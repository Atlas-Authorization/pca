// gen.ts - the pack generator CLI.
//   pin <pack> --dir D          download the sources of a pack, pin ref + sha256 into packs/<pack>.sources.json
//   build <pack|all> --dir D    generate packages/pca-actions/packs/<pack>/<version>/ from the pinned sources
//   repro <pack|all> --dir D    build into a temp dir and require byte-identical output to the committed pack
//   verify [pack|all]           offline checks of the committed packs (digests, root, lint, sizes, ledger)
//   ledger [--check]            write (or check) packages/pca-actions/packs/LICENCES.md
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadSource, pin, readSources } from './lib/source';
import { PACKS_ROOT, writePack, type PackDef } from './lib/pack';
import { ALL_PACKS } from './packs/index';
import { verifyAll, ledgerText } from './lib/verify';

const args = process.argv.slice(2);
const flag = (n: string): string | undefined => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1] : undefined; };
const [cmd, which] = args;
const dir = flag('dir') ?? join(tmpdir(), 'pca-pack-src');

async function packs(sel: string | undefined): Promise<PackDef[]> {
  const all = await ALL_PACKS();
  if (!sel || sel === 'all') return all;
  const p = all.filter((x) => x.name === sel);
  if (!p.length) throw new Error(`unknown pack ${sel}`);
  return p;
}

async function generate(p: PackDef, outRoot: string): Promise<void> {
  const cache = new Map<string, unknown>();
  for (const s of p.sources) if (s.kind !== 'table') cache.set(s.id, await loadSource(p.name, s, dir));
  const built = p.generate((id) => { if (!cache.has(id)) throw new Error(`no source ${id}`); return cache.get(id); });
  const r = writePack(p, built, join(outRoot, p.name), p.sources);
  console.log(`${p.name}: ${r.stats.total} defs (${r.stats.authored} authored, ${r.stats.unreviewed} unreviewed), skipped ${JSON.stringify(r.stats.skipped)}, root ${r.root}`);
}

function sameTree(a: string, b: string): string[] {
  const diffs: string[] = [];
  const walk = (d: string): string[] => readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)).map((x) => join(f, x)) : [f]));
  const fa = walk(a), fb = walk(b);
  for (const f of new Set([...fa, ...fb])) {
    if (!fa.includes(f) || !fb.includes(f)) diffs.push(`only one side: ${f}`);
    else if (!readFileSync(join(a, f)).equals(readFileSync(join(b, f)))) diffs.push(`differs: ${f}`);
  }
  return diffs;
}

async function main(): Promise<void> {
  if (cmd === 'pin') { for (const p of await packs(which)) { await pin(p.name, dir); console.log(`pinned ${p.name}`); } return; }
  if (cmd === 'build') { for (const p of await packs(which)) await generate(p, PACKS_ROOT); return; }
  if (cmd === 'repro') {
    let bad = 0;
    for (const p of await packs(which)) {
      const tmp = mkdtempSync(join(tmpdir(), 'pca-repro-'));
      await generate(p, tmp);
      const diffs = sameTree(join(tmp, p.name, p.version), join(PACKS_ROOT, p.name, p.version));
      rmSync(tmp, { recursive: true });
      if (diffs.length) { bad++; console.error(`${p.name}: NOT byte-identical:\n  ${diffs.slice(0, 8).join('\n  ')}`); } else console.log(`${p.name}: byte-identical`);
    }
    if (bad) process.exit(1);
    return;
  }
  if (cmd === 'verify') { const errs = await verifyAll(which && which !== 'all' ? which : undefined); if (errs.length) { console.error(errs.slice(0, 40).join('\n')); console.error(`${errs.length} problem(s)`); process.exit(1); } console.log('verify OK'); return; }
  if (cmd === 'ledger') {
    const text = await ledgerText();
    const f = join(PACKS_ROOT, 'LICENCES.md');
    if (args.includes('--check')) { if (!existsSync(f) || readFileSync(f, 'utf8') !== text) { console.error('LICENCES.md is stale: run ledger'); process.exit(1); } console.log('ledger OK'); } else writeFileSync(f, text);
    return;
  }
  console.error('usage: gen.ts pin|build|repro|verify|ledger');
  process.exit(2);
}
main().catch((e) => { console.error(e); process.exit(1); });
void readSources;
