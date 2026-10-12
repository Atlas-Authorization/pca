#!/usr/bin/env node
// Native-verifier equivalent-mutant ledger checker (Go/Python/Rust/PHP/.NET/Java/Kotlin/Swift mutation testing).
//   node native-check-equivalents.mjs                 static check: every entry in native-mutation-equivalents.json is well formed
//                                                     and names exactly one site of sdks/<crate>/<file>
//   node native-check-equivalents.mjs --merge         first merge sdks/*/mutation-equivalents.part.json into the ledger
//   node native-check-equivalents.mjs survivors.json  full check: every survivor in the list matches exactly one entry and every
//                                                     entry of a listed crate matches exactly one survivor site (else STALE).
//   --root=<dir> --ledger=<file>                       overrides (used by check-equivalents.selftest.mjs)
//   --crate=<crate>                                    crate for survivor records that do not carry one (go-mutate -out JSON)
//
// Entries: { crate, file, mutant, line, occurrence, fn?, lineno, multiplicity?, reason }. A SITE is (crate, file, mutant,
// trimmed line text, occurrence): occurrence = which copy of that text in the file (1-based); `fn` (enclosing function /
// method, when the tool reports it) must also agree when both sides carry it; `lineno` is a hint only. `multiplicity` (>= 2)
// covers mutants the tool reports more than once at the same site with the same description (e.g. two `1`s on one line).
// An entry whose text occurs more than once in the file without `occurrence` is an AMBIGUOUS error. See site-key.mjs.
//
// Survivor lists: [{ crate, file, mutant, line, occurrence?, lineno?|lineNo?|srcline?, fn?|method? }]. A producer that knows the
// source it mutated should emit `occurrence` (exact); otherwise the site is placed by the line hint against the current source.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkEntrySite, checkSites, place } from './site-key.mjs';
const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (n) => args.find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);
const root = path.resolve(opt('root') ?? path.resolve(here, '../..'));
const ledgerPath = path.resolve(opt('ledger') ?? path.join(here, 'native-mutation-equivalents.json'));
const ledger = fs.existsSync(ledgerPath) ? JSON.parse(fs.readFileSync(ledgerPath, 'utf8')) : { about: 'Surviving native-verifier mutants justified as equivalent. Checked by native-check-equivalents.mjs.', equivalents: [] };
const sources = new Map();
const srcLines = (crate, file) => {
  const p = path.join(root, 'sdks', crate, file);
  if (!sources.has(p)) sources.set(p, fs.existsSync(p) ? fs.readFileSync(p, 'utf8').split('\n') : null);
  return sources.get(p);
};
const siteKey = (crate, file, mutant, line, occ) => [crate, file, mutant, line.trim(), occ].join('\u0000');
const label = (e, ln) => `${e.crate}/${e.file}:${ln ?? e.lineno ?? '?'}${e.occurrence ? ` (#${e.occurrence})` : ''}${e.fn ? ` in ${e.fn}` : ''}: ${e.mutant.slice(0, 90)} | ${e.line.slice(0, 70)}`;

if (args.includes('--merge')) {
  const have = new Set(ledger.equivalents.map((e) => siteKey(e.crate, e.file, e.mutant, e.line, e.occurrence ?? 1)));
  for (const crate of fs.readdirSync(path.join(root, 'sdks'))) {
    for (const sub of ['', 'core/', 'verify/']) {
      const p = path.join(root, 'sdks', crate, sub, 'mutation-equivalents.part.json');
      if (!fs.existsSync(p)) continue;
      for (const e of JSON.parse(fs.readFileSync(p, 'utf8'))) {
        const n = { crate: e.crate ?? crate, file: e.file, mutant: e.mutant ?? e.description, line: (e.line ?? '').trim(), ...(e.occurrence ? { occurrence: e.occurrence } : {}), ...(e.fn ? { fn: e.fn } : {}), ...(e.lineno ? { lineno: e.lineno } : {}), reason: e.reason };
        const k = siteKey(n.crate, n.file, n.mutant, n.line, n.occurrence ?? 1);
        if (!have.has(k)) { ledger.equivalents.push(n); have.add(k); }
      }
    }
  }
  fs.writeFileSync(ledgerPath, JSON.stringify(ledger, null, 1) + '\n');
}

const errors = [];
const entries = [];
const seen = new Set();
let drift = 0;
for (const e of ledger.equivalents) {
  let bad = false;
  for (const f of ['crate', 'file', 'mutant', 'line', 'reason']) if (typeof e[f] !== 'string' || !e[f] || (f === 'reason' && e[f].length < 12)) { errors.push(`missing/short '${f}': ${JSON.stringify(e).slice(0, 120)}`); bad = true; }
  if (e.fn !== undefined && (typeof e.fn !== 'string' || !e.fn)) { errors.push(`bad fn: ${JSON.stringify(e).slice(0, 120)}`); bad = true; }
  if (bad) continue;
  const lines = srcLines(e.crate, e.file);
  if (!lines) { errors.push(`source file gone: sdks/${e.crate}/${e.file}`); continue; }
  const r = checkEntrySite(lines, e, label(e));
  errors.push(...r.errors);
  if (r.errors.length) continue;
  if (e.lineno !== undefined && e.lineno !== r.lineno) drift++;
  // light sanity check of fn: its last plain identifier segment must appear in the file (synthetic names such as <init> or
  // lambda$x$1 are not checked; a JVM property accessor getX / setX / isX also passes on the property name x)
  const fnId = e.fn?.split(/::|\./).pop();
  if (fnId && /^[A-Za-z_][A-Za-z0-9_]*$/.test(fnId)) {
    const acc = /^(?:get|set|is)([A-Z].*)$/.exec(fnId)?.[1];
    const names = [fnId, ...(acc ? [acc[0].toLowerCase() + acc.slice(1)] : [])];
    const text = lines.join('\n');
    if (!names.some((n) => new RegExp(`\\b${n}\\b`).test(text))) errors.push(`fn '${e.fn}' not found in the file: ${label(e)}`);
  }
  const k = siteKey(e.crate, e.file, e.mutant, e.line, e.occurrence ?? 1);
  const dk = k + '\u0000' + (e.fn ?? '');
  if (seen.has(dk)) errors.push(`duplicate entry: ${label(e)}`);
  seen.add(dk);
  entries.push({ key: k, fn: e.fn, multiplicity: e.multiplicity, unit: e.crate, label: label(e, r.lineno) });
}

const reports = args.filter((a) => !a.startsWith('--'));
let nSurv = 0;
if (reports.length) {
  const survivors = [];
  const units = new Set();
  for (const r of reports) {
    for (const raw of JSON.parse(fs.readFileSync(r, 'utf8'))) {
      // go-mutate -out records ({file, line: <number>, mutant, line_text, status}) are accepted as-is with --crate=go-pca
      const s = typeof raw.line === 'number' ? { crate: raw.crate ?? opt('crate'), file: raw.file, mutant: raw.mutant, line: raw.line_text, lineno: raw.line, status: raw.status } : raw;
      if (s.status && !['SURVIVED', 'NO_COVERAGE', 'Survived', 'NoCoverage'].includes(s.status)) continue;
      if (!s.crate) { errors.push(`survivor without crate (pass --crate=): ${JSON.stringify(raw).slice(0, 120)}`); continue; }
      units.add(s.crate);
      nSurv++;
      const lines = srcLines(s.crate, s.file);
      const hint = s.lineno ?? s.lineNo ?? s.srcline;
      const fn = s.fn ?? s.method;
      const where = `${s.crate}/${s.file}:${hint ?? '?'}${fn ? ` in ${fn}` : ''}: ${s.mutant.slice(0, 90)} | ${String(s.line).slice(0, 70)}`;
      if (!lines) { errors.push(`survivor source file gone: ${where}`); continue; }
      const p = place(lines, s.line, { occurrence: s.occurrence, hint });
      if (p.error) { errors.push(`UNPLACEABLE SURVIVOR (${p.error}): ${where}`); continue; }
      survivors.push({ key: siteKey(s.crate, s.file, s.mutant, s.line, p.occurrence), fn, unit: s.crate, label: `${where} (#${p.occurrence})` });
    }
  }
  errors.push(...checkSites(entries, survivors, units));
}
if (errors.length) { console.error(errors.join('\n')); console.error(`FAIL: ${errors.length} problem(s); ${ledger.equivalents.length} entries`); process.exit(1); }
console.log(`native equivalents ok: ${ledger.equivalents.length} entries (one site each${drift ? `; ${drift} line hint(s) drifted, informational` : ''})${reports.length ? `; ${nSurv} survivors all matched` : ' (static check)'}`);
