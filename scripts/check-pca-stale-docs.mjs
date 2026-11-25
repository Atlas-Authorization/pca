#!/usr/bin/env node
// Retired-statement gate for the PCA public surfaces. Each phrase below was once true of PCA, became false, and was
// read by an external reviewer as a current claim (0.4.2 peer review, stale statements S1-S13). The gate fails when one
// comes back in a public doc, a package README, a native SDK README or a shipped source comment.
//
// Scanned: docs/pca/** (or docs/** in the flagship layout), packages/pca*/README.md, packages/pca/conformance/README.md,
// packages/pca/src/*.ts (non-test: module comments ship in the npm dist), sdks/*/README.md, and the README assets of the
// published mirror repositories (scripts/pca-mirror-assets, scripts/pca-flagship-assets).
// Not scanned: CHANGELOG.md files, the dated audit and review reports and the internal validation notes, which record
// what was true at the time.
//
// Run: node scripts/check-pca-stale-docs.mjs [--self-test]   (exit 1 on any finding). Also run by scripts/pca-audit-all.sh
// and packages/pca/src/stale-docs-scan.test.ts.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** [id, pattern, what is true instead] */
export const RETIRED = [
  ['corpus-172', /\b172-vector\b/i, 'the core corpus has 676 PCActn vectors plus primitives and a 4,358-vector adversarial set'],
  ['corpus-394', /\b394 vectors\b/i, 'the core corpus has 676 PCActn vectors (129 positive, 547 negative)'],
  ['zk-seam-only', /\bSeam only\b/, 'Groth16 and Policy VM SNARK backends, STARK and zkVM provers ship'],
  ['zk-no-prover', /no circuit, trusted setup or prover/i, 'Groth16 and Policy VM SNARK backends, STARK and zkVM provers ship'],
  ['zk-hosted-unwired', /hosted\s+`?\/v1\/pca\/actions`?\s+does not (currently )?wire the ZK hook/i, 'the hosted surface wires the ZK hook when configured'],
  ['plan-auto-authorized', /auto-authori[sz]ed/i, 'hosted plans need principal authorization unless plan_policy is agent_commit'],
  ['attest-no-quote-parsing', /DO NOT implement SEV-SNP\s*\/\s*TDX quote parsing/i, 'SEV-SNP, TDX, MAA, Confidential Space and NVIDIA SPDM verifiers are implemented'],
  ['taint-gate-unenforced', /separate\s+`?taint_gate`?\s+check reports/i, 'enforce.taint is a fail-closed gate'],
  ['taint-gate-unenforced', /taint gate is not enforced/i, 'enforce.taint is a fail-closed gate'],
  ['taint-claim-default', /claimed (value|`?taint_level`?) is (used )?only (as )?a default/i, 'verifyPCActn never reads the claimed taint; hosted uses max(server, claim)'],
  ['threshold-reads-claim', /default threshold verifier reads/i, 'createThresholdVerifier requires t or requiredT'],
  ['blast-radius-neutral', /neutral constant \(0\.5\)/i, 'hosted blastRadius is 0.5 / 0.5 / 0.75 per class'],
  ['blast-radius-flat', /^\|\s*`blastRadius`\s*\|\s*0\.5\s*\|/m, 'hosted blastRadius is 0.5 / 0.5 / 0.75 per class'],
];

const SKIP_FILE = /(^|\/)(CHANGELOG\.md|[^/]*-report[^/]*\.md|audit-[^/]*\.md)$/;
const SKIP_DIR = /(^|\/)(node_modules|dist|validation)(\/|$)/;

function walk(dir, out, accept) {
  if (!fs.existsSync(dir)) return;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIR.test(p + '/')) walk(p, out, accept);
    } else if (accept(p)) out.push(p);
  }
}

/** The files the gate reads under `root` (monorepo layout, or the flagship layout where docs/pca is docs/). */
export function targets(root = ROOT) {
  const out = [];
  const md = (p) => p.endsWith('.md') && !SKIP_FILE.test(p);
  const docs = fs.existsSync(path.join(root, 'docs/pca')) ? path.join(root, 'docs/pca') : path.join(root, 'docs');
  walk(docs, out, md);
  const pk = path.join(root, 'packages');
  if (fs.existsSync(pk)) {
    for (const d of fs.readdirSync(pk)) {
      if (!/^pca(-|$)/.test(d)) continue;
      const r = path.join(pk, d, 'README.md');
      if (fs.existsSync(r)) out.push(r);
    }
    const conf = path.join(pk, 'pca/conformance/README.md');
    if (fs.existsSync(conf)) out.push(conf);
    walk(path.join(pk, 'pca/src'), out, (p) => p.endsWith('.ts') && !/\.test(-util)?\.ts$|\.test\.ts$/.test(p) && !/test-(util|support)/.test(p));
  }
  // README assets of the published repositories (native SDK mirrors, the flagship's root README).
  for (const a of ['scripts/pca-mirror-assets', 'scripts/pca-flagship-assets']) walk(path.join(root, a), out, md);
  const sd = path.join(root, 'sdks');
  if (fs.existsSync(sd)) {
    for (const d of fs.readdirSync(sd)) {
      const r = path.join(sd, d, 'README.md');
      if (fs.existsSync(r)) out.push(r);
    }
  }
  return [...new Set(out)].sort();
}

/** Findings as `file:line: id: matched text (truth)`; [] when clean. */
export function scan(root = ROOT, files = targets(root)) {
  const findings = [];
  for (const f of files) {
    const text = fs.readFileSync(f, 'utf8');
    const lines = text.split('\n');
    for (const [id, re, truth] of RETIRED) {
      if (re.flags.includes('m')) {
        const m = text.match(re);
        if (m) findings.push(`${path.relative(root, f)}:${text.slice(0, m.index).split('\n').length}: ${id}: ${JSON.stringify(m[0].trim())} (now: ${truth})`);
        continue;
      }
      lines.forEach((l, i) => {
        const m = l.match(re);
        if (m) findings.push(`${path.relative(root, f)}:${i + 1}: ${id}: ${JSON.stringify(m[0])} (now: ${truth})`);
      });
    }
  }
  return findings;
}

function selfTest() {
  const tmp = fs.mkdtempSync(path.join(fs.realpathSync(process.env.TMPDIR || '/tmp'), 'stale-docs-'));
  const put = (rel, s) => {
    fs.mkdirSync(path.dirname(path.join(tmp, rel)), { recursive: true });
    fs.writeFileSync(path.join(tmp, rel), s);
  };
  put('docs/pca/concepts/a.md', 'In this release a committed plan is auto-authorized.\n| `blastRadius` | 0.5 | raise |\n');
  put('docs/pca/CHANGELOG.md', 'Plans were auto-authorized before 0.4.\n');
  put('docs/pca/validation/notes.md', 'Seam only.\n');
  put('packages/pca/src/attestation.ts', '/* We deliberately DO NOT implement SEV-SNP/TDX quote parsing here */\n');
  put('packages/pca/src/attestation.test.ts', '// Seam only\n');
  put('sdks/rust-pca/README.md', 'The crate passes the shared 172-vector PCA conformance corpus.\n');
  const got = scan(tmp).map((s) => s.split(': ')[1]).sort();
  const want = ['attest-no-quote-parsing', 'blast-radius-flat', 'corpus-172', 'plan-auto-authorized'].sort();
  fs.rmSync(tmp, { recursive: true, force: true });
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    console.error(`self-test FAILED: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    process.exit(1);
  }
  console.log('self-test OK');
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  if (process.argv.includes('--self-test')) selfTest();
  const files = targets();
  const f = scan(ROOT, files);
  console.log(`retired-statement gate: ${files.length} files, ${RETIRED.length} patterns, ${f.length} finding(s)`);
  if (f.length) {
    for (const x of f) console.error(' - ' + x);
    process.exit(1);
  }
  console.log('OK');
}
