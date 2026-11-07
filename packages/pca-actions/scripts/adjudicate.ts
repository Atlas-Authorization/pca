// adjudicate.ts - blind adjudication of the disagreements between the pack labels and the suggestion rules (track ADJ).
//   tsx scripts/adjudicate.ts sample <packs-dir> <out-dir> [--n 200] [--seed S]
//        draws, per trait, a stratified (by pack, proportional) random sample of each disagreement set (rules say it / pack does not, and the
//        reverse), shuffles both into one blind file per trait (no label, no direction shown) and writes sample-key.json.
//   tsx scripts/adjudicate.ts estimate <packs-dir> <adjudication.tsv> [--out FILE]
//        reads the committed verdicts (rows keyed pack:verb) and, against the CURRENT packs and rules, estimates per trait the pack
//        under-labelling rate and the rule over-flag rate with 95% confidence bounds.
// Verdicts are a person's reading of what the operation does (name, method, path, parameters); neither labeler is consulted.
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { loadPackDefs, packTraits, rulesTraits, type PackDef } from './lib/xcheck-core';

export const ADJ_TRAITS = ['money_moving', 'external_communication', 'code_execution', 'privilege_change', 'destructive', 'public_exposure', 'data_export', 'financial_data_read', 'scheduled'];
const args = process.argv.slice(2);
const flag = (n: string, d: string): string => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1]! : d; };

function rng(seed: string): () => number {
  let h = 1779033703 ^ seed.length;
  for (let i = 0; i < seed.length; i++) { h = Math.imul(h ^ seed.charCodeAt(i), 3432918353); h = (h << 13) | (h >>> 19); }
  let a = h >>> 0;
  return () => { a = (a + 0x6d2b79f5) >>> 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return (((t ^ (t >>> 14)) >>> 0) / 4294967296); };
}
function shuffle<T>(a: T[], r: () => number): T[] { for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [a[i], a[j]] = [a[j]!, a[i]!]; } return a; }

export interface Facts { pack: string; verb: string; method: string; path: string; params: string; title: string; desc: string }
export function factsOf({ pack, def }: PackDef): Facts {
  const b = (def.bindings ?? {}) as Record<string, Record<string, string>>;
  const o = b.openapi ?? b.graphql ?? b.rpc ?? b.grpc ?? {};
  const method = o.method ?? o.op ?? Object.keys(b)[0] ?? '';
  const path = o.path ?? o.field ?? o.operationId ?? '';
  const params = Object.entries(def.params).slice(0, 30).map(([k, p]) => `${k}${(p as { required?: boolean }).required === false ? '' : '*'}:${(p as { type: string }).type}`).join(' ');
  const desc = (def.description ?? '').replace(/\s*Effects?:.*$/i, '').replace(/^(GET|POST|PUT|PATCH|DELETE|HEAD)\s+\S+\.?\s*/i, '').trim();
  return { pack, verb: def.verb, method, path, params, title: def.title ?? '', desc };
}

const dir = resolve(args[1] ?? '');
const all = loadPackDefs(dir);
const lab = all.map((x) => ({ x, p: packTraits(x.def), r: rulesTraits(x.def) }));

if (args[0] === 'sample') {
  const out = resolve(args[2] ?? '.'); mkdirSync(out, { recursive: true });
  const n = Number(flag('n', '200')), r = rng(flag('seed', 'pca-adj-1'));
  const key: Record<string, unknown>[] = [];
  const pop: Record<string, unknown> = {};
  for (const t of ADJ_TRAITS) {
    const rows: { id: string; dir: string; f: Facts }[] = [];
    pop[`${t}/both`] = { all: lab.filter((l) => l.p.has(`pca.${t}`) && l.r.has(`pca.${t}`)).length };
    for (const [d, pick] of [['rules_only', (l: typeof lab[number]) => l.r.has(`pca.${t}`) && !l.p.has(`pca.${t}`)], ['pack_only', (l: typeof lab[number]) => l.p.has(`pca.${t}`) && !l.r.has(`pca.${t}`)]] as const) {
      const set = lab.filter(pick);
      const byPack = new Map<string, typeof set>();
      for (const l of set) byPack.set(l.x.pack, [...(byPack.get(l.x.pack) ?? []), l]);
      pop[`${t}/${d}`] = Object.fromEntries([...byPack].sort().map(([k, v]) => [k, v.length]));
      const chosen: typeof set = [];
      for (const [, items] of [...byPack].sort()) {
        const k = Math.min(items.length, Math.max(1, Math.ceil((n * items.length) / set.length)));
        chosen.push(...shuffle([...items], r).slice(0, k));
      }
      for (const l of chosen) rows.push({ id: '', dir: d, f: factsOf(l.x) });
    }
    shuffle(rows, r);
    rows.forEach((row, i) => { row.id = `${t}#${String(i + 1).padStart(3, '0')}`; key.push({ id: row.id, trait: t, direction: row.dir, ...row.f }); });
    const fmt = (row: typeof rows[number]): string => `${row.id} | ${row.f.verb} | ${row.f.method} ${row.f.path} | ${row.f.title} | ${row.f.desc} | ${row.f.params}`;
    for (let c = 0; c * 230 < rows.length; c++) {
      const part = Math.ceil(rows.length / 230) > 1 ? `-${c + 1}` : '';
      writeFileSync(join(out, `${t}${part}.txt`), rows.slice(c * 230, (c + 1) * 230).map(fmt).join('\n') + '\n');
    }
  }
  writeFileSync(join(out, 'sample-key.json'), JSON.stringify({ population: pop, rows: key }, null, 1));
  console.log(key.length, 'sampled');
}

// freeze: join the blind verdict files (id<TAB>y|n|u<TAB>reason) to the sample key and write the committed adjudication TSV + population JSON.
if (args[0] === 'freeze') {
  const [, , keyFile, vdir, outTsv, outPop] = args as string[];
  const key = JSON.parse(readFileSync(resolve(keyFile!), 'utf8')) as { population: Record<string, Record<string, number>>; rows: (Facts & { id: string; trait: string; direction: string; paramNames?: string })[] };
  const verdict = new Map<string, [string, string]>();
  for (const f of readdirSync(resolve(vdir!)).filter((x) => x.endsWith('.tsv'))) for (const l of readFileSync(join(resolve(vdir!), f), 'utf8').split('\n')) { if (!l.trim()) continue; const [id, v, why] = l.split('\t'); verdict.set(id!, [v!, (why ?? '').replace(/\s+/g, ' ')]); }
  const lines = ['id\ttrait\tdirection\tpack\tverb\tmethod\tpath\tparams\tverdict\treason'];
  for (const r of key.rows) {
    const v = verdict.get(r.id); if (!v || !'ynu'.includes(v[0])) throw new Error(`missing or bad verdict for ${r.id}`);
    lines.push([r.id, r.trait, r.direction, r.pack, r.verb, r.method, r.path, r.params.split(' ').map((x) => x.replace(/[*]?:.*$/, '')).join(','), v[0], v[1]].join('\t'));
  }
  writeFileSync(resolve(outTsv!), lines.join('\n') + '\n');
  writeFileSync(resolve(outPop!), JSON.stringify(key.population, null, 1) + '\n');
  console.log(key.rows.length, 'rows frozen');
}

// estimate: against the CURRENT packs and rules, using the frozen adjudicated sample and its strata (pack x direction x trait).
if (args[0] === 'estimate') {
  const { clopperPearsonUpper } = require('@atlasauth/pca-intent') as typeof import('@atlasauth/pca-intent');
  const rows = readFileSync(resolve(args[2]!), 'utf8').trim().split('\n').slice(1).map((l) => { const c = l.split('\t'); return { trait: c[1]!, dir: c[2]!, pack: c[3]!, verb: c[4]!, v: c[8]! }; });
  const pop = JSON.parse(readFileSync(resolve(args[3] ?? join(resolve(args[2]!, '..'), 'adjudication-population.json')), 'utf8')) as Record<string, Record<string, number>>;
  const byKey = new Map(lab.map((l) => [`${l.x.pack}:${l.x.def.verb}`, l]));
  const ci = (k: number, n: number): [number, number] => n === 0 ? [0, 1] : [k === 0 ? 0 : 1 - clopperPearsonUpper(n - k, n, 0.025), k === n ? 1 : clopperPearsonUpper(k, n, 0.025)];
  const pct = (x: number): string => (100 * x).toFixed(1) + '%';
  const out = ['| trait | rules-only N | sampled (y/n/u) | pack-only N | sampled (y/n/u) | pack under-label: true-trait defs neither labelled nor unreviewed (strict: labelled only) | rate of true carriers [95% CI] | pack over-label rate | rule over-flag rate [95% CI] | rule miss rate |', '|---|---:|---|---:|---|---:|---|---:|---|---:|'];
  const res: Record<string, unknown> = {};
  for (const t of ADJ_TRAITS) {
    const full = `pca.${t}`;
    const sets = { R: rows.filter((r) => r.trait === t && r.dir === 'rules_only' && r.v !== 'u'), P: rows.filter((r) => r.trait === t && r.dir === 'pack_only' && r.v !== 'u') };
    const cnt = (d: string): string => { const a = rows.filter((r) => r.trait === t && r.dir === d); return `${a.filter((r) => r.v === 'y').length}/${a.filter((r) => r.v === 'n').length}/${a.filter((r) => r.v === 'u').length}`; };
    const NR = Object.values(pop[`${t}/rules_only`] ?? {}).reduce((a, b) => a + b, 0), NP = Object.values(pop[`${t}/pack_only`] ?? {}).reduce((a, b) => a + b, 0);
    // weighted estimate of "number of frozen-stratum defs satisfying f", with a pooled Clopper-Pearson interval on the sampled share
    const est = (S: typeof sets.R, d: string, f: (r: typeof S[number], l: typeof lab[number]) => boolean): { n: number; lo: number; hi: number } => {
      const per = new Map<string, { N: number; n: number; k: number }>();
      for (const r of S) per.set(r.pack, per.get(r.pack) ?? { N: pop[`${t}/${d}`]?.[r.pack] ?? 0, n: 0, k: 0 });
      let k = 0;
      for (const r of S) { const l = byKey.get(`${r.pack}:${r.verb}`); const s = per.get(r.pack)!; s.n++; if (l && f(r, l)) { s.k++; k++; } }
      const N = [...per.values()].reduce((a, s) => a + s.N, 0);
      const point = [...per.values()].reduce((a, s) => a + (s.n ? (s.N * s.k) / s.n : 0), 0);
      const [lo, hi] = ci(Math.round((point / (N || 1)) * S.length), S.length);
      return { n: point, lo: lo * N, hi: hi * N };
    };
    // frozen truth (independent of current labels)
    const TPR = est(sets.R, 'rules_only', (r) => r.v === 'y'), TPP = est(sets.P, 'pack_only', (r) => r.v === 'y');
    const B0 = pop[`${t}/both`]?.all ?? 0; // defs both labelers carried at freeze time; assumed true (not sampled)
    const T0 = B0 + TPR.n + TPP.n; // estimated true carriers of the trait in the frozen strata
    // a def left `unreviewed` sits on the maximal floor, so it is covered even without the trait; `underStrict` ignores that
    const covered = (l: typeof lab[number]): boolean => l.p.has(full) || l.x.def.review?.state === 'unreviewed';
    const under = est(sets.R, 'rules_only', (r, l) => r.v === 'y' && !covered(l));
    const underStrict = est(sets.R, 'rules_only', (r, l) => r.v === 'y' && !l.p.has(full));
    const packFalse = { a: est(sets.P, 'pack_only', (r, l) => r.v === 'n' && l.p.has(full)), b: est(sets.R, 'rules_only', (r, l) => r.v === 'n' && l.p.has(full)) };
    const ruleFalse = { a: est(sets.R, 'rules_only', (r, l) => r.v === 'n' && l.r.has(full)), b: est(sets.P, 'pack_only', (r, l) => r.v === 'n' && l.r.has(full)) };
    const ruleMiss = { a: est(sets.P, 'pack_only', (r, l) => r.v === 'y' && !l.r.has(full)), b: est(sets.R, 'rules_only', (r, l) => r.v === 'y' && !l.r.has(full)) };
    // rates are taken inside the frozen strata so a before and an after figure share one denominator: all defs of the disagreement sets that
    // carry (pack) or are flagged (rules) now, plus the defs both labelers carried at freeze time
    const carries = B0 + est(sets.R, 'rules_only', (_r, l) => l.p.has(full)).n + est(sets.P, 'pack_only', (_r, l) => l.p.has(full)).n;
    const flagged = B0 + est(sets.R, 'rules_only', (_r, l) => l.r.has(full)).n + est(sets.P, 'pack_only', (_r, l) => l.r.has(full)).n;
    const Tx = (x: number): number => B0 + TPP.n + Math.max(TPR.n, x);
    const rUnder = [under.lo / Tx(under.lo), under.n / Tx(under.n), under.hi / Tx(under.hi)], rOver = [(ruleFalse.a.lo + ruleFalse.b.n) / (flagged || 1), (ruleFalse.a.n + ruleFalse.b.n) / (flagged || 1), (ruleFalse.a.hi + ruleFalse.b.n) / (flagged || 1)];
    out.push(`| ${t} | ${NR} | ${cnt('rules_only')} | ${NP} | ${cnt('pack_only')} | ${Math.round(under.n)} (${Math.round(under.lo)}..${Math.round(under.hi)}); strict ${Math.round(underStrict.n)} | ${pct(rUnder[1]!)} [${pct(rUnder[0]!)}, ${pct(rUnder[2]!)}] | ${pct((packFalse.a.n + packFalse.b.n) / (carries || 1))} | ${pct(rOver[1]!)} [${pct(rOver[0]!)}, ${pct(rOver[2]!)}] | ${pct((ruleMiss.a.n + ruleMiss.b.n) / T0)} |`);
    res[t] = { B0, T0, under, underStrict, packFalse, ruleFalse, ruleMiss, carries, flagged };
  }
  const md = out.join('\n') + '\n';
  console.log(md);
  const o = args.indexOf('--out'); if (o >= 0) writeFileSync(resolve(args[o + 1]!), md);
  const j = args.indexOf('--json'); if (j >= 0) writeFileSync(resolve(args[j + 1]!), JSON.stringify(res, null, 1));
}

// ---- residual under-labelling: a FRESH sample of the pack defs that still LACK each high-risk trait -----------------------------------------
//   tsx scripts/adjudicate.ts resample <packs> <out-dir> [--n 300] [--seed S] [--exclude adjudication.tsv,...]
//   tsx scripts/adjudicate.ts residual <packs> <residual.tsv> <population.json>      (upper 95% bound on the share of lacking defs that have the trait)
// "Lack" = does not carry the trait and is not `unreviewed` (an unreviewed def already sits on the maximal floor).
const HIGH = ['money_moving', 'external_communication', 'code_execution', 'privilege_change', 'destructive', 'data_export', 'financial_data_read', 'credential_access'];
const lacks = (l: typeof lab[number], t: string): boolean => !l.p.has(`pca.${t}`) && l.x.def.review?.state !== 'unreviewed';
if (args[0] === 'resample') {
  const out = resolve(args[2] ?? '.'); mkdirSync(out, { recursive: true });
  const n = Number(flag('n', '300')), r = rng(flag('seed', 'pca-adj-2'));
  const skip = new Set<string>();
  for (const f of flag('exclude', '').split(',').filter(Boolean)) for (const l of readFileSync(resolve(f), 'utf8').trim().split('\n').slice(1)) { const c = l.split('\t'); skip.add(`${c[1]}|${c[3]}:${c[4]}`); }
  const key: Record<string, unknown>[] = []; const pop: Record<string, Record<string, number>> = {};
  for (const t of HIGH.filter((x) => !flag('traits', '') || flag('traits', '').split(',').includes(x))) {
    const set = lab.filter((l) => lacks(l, t) && !skip.has(`${t}|${l.x.pack}:${l.x.def.verb}`));
    const byPack = new Map<string, typeof set>();
    for (const l of set) byPack.set(l.x.pack, [...(byPack.get(l.x.pack) ?? []), l]);
    pop[t] = Object.fromEntries([...byPack].sort().map(([k, v]) => [k, v.length]));
    const chosen: typeof set = [];
    for (const [, items] of [...byPack].sort()) chosen.push(...shuffle([...items], r).slice(0, Math.min(items.length, Math.max(1, Math.ceil((n * items.length) / set.length)))));
    shuffle(chosen, r);
    const rows = chosen.map((l, i) => ({ id: `${t}#${String(i + 1).padStart(3, '0')}`, f: factsOf(l.x) }));
    rows.forEach((row) => key.push({ id: row.id, trait: t, direction: 'residual', ...row.f }));
    for (let c = 0; c * 230 < rows.length; c++) writeFileSync(join(out, `${t}${rows.length > 230 ? `-${c + 1}` : ''}.txt`), rows.slice(c * 230, (c + 1) * 230).map((row) => `${row.id} | ${row.f.verb} | ${row.f.method} ${row.f.path} | ${row.f.title} | ${row.f.desc} | ${row.f.params}`).join('\n') + '\n');
  }
  writeFileSync(join(out, 'sample-key.json'), JSON.stringify({ population: pop, rows: key }, null, 1));
  console.log(key.length, 'sampled', JSON.stringify(Object.fromEntries(Object.entries(pop).map(([k, v]) => [k, Object.values(v).reduce((a, b) => a + b, 0)]))));
}
if (args[0] === 'residual') {
  const { clopperPearsonUpper } = require('@atlasauth/pca-intent') as typeof import('@atlasauth/pca-intent');
  const rows = readFileSync(resolve(args[2]!), 'utf8').trim().split('\n').slice(1).map((l) => { const c = l.split('\t'); return { trait: c[1]!, pack: c[3]!, verb: c[4]!, v: c[8]! }; });
  const pop = JSON.parse(readFileSync(resolve(args[3]!), 'utf8')) as Record<string, Record<string, number>>;
  const out = ['| trait | lacking defs | sampled | judged to have it (or doubtful) | rate | upper 95% bound | defs (point / bound) |', '|---|---:|---:|---:|---:|---:|---|'];
  for (const t of HIGH) {
    const S = rows.filter((r) => r.trait === t); const k = S.filter((r) => r.v !== 'n').length; // a doubtful verdict counts against the pack (fail strict)
    const N = Object.values(pop[t] ?? {}).reduce((a, b) => a + b, 0);
    const ub = clopperPearsonUpper(k, S.length, 0.05);
    out.push(`| ${t} | ${N} | ${S.length} | ${k} | ${(100 * k / (S.length || 1)).toFixed(2)}% | **${(100 * ub).toFixed(2)}%** | ${Math.round(N * k / (S.length || 1))} / ${Math.round(N * ub)} |`);
  }
  console.log(out.join('\n'));
  const o = args.indexOf('--out'); if (o >= 0) writeFileSync(resolve(args[o + 1]!), out.join('\n') + '\n');
}
