import { existsSync, mkdirSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * R6-CORE-05: both scanners were regex-based and evadable (lowercase headers, req.get, destructuring, slice/shift, variable
 * index, computed keys, grantFromArtifact: false, a dummy pqPins nearby, string literals that fool the comment stripper,
 * multi-line). They now analyse the TypeScript AST with local data flow. Every red-team evasion (round-5 and round-6
 * PoC directories, verbatim) and every corpus case must be caught; the legit shapes must stay clean.
 */
type Case = { id: string; path: string; code: string; unsafe?: boolean; pq?: boolean; rule?: RegExp };
type Evasion = { code: string; art?: boolean; req?: boolean; unbound?: boolean };

const REPO = join(__dirname, '..', '..', '..');
// Repository tooling under scripts/ (and the private red-team PoC directories): absent from trees that ship this package
// without them (the public package repository). The suites skip there instead of failing to load.
const TOOLING = ['scripts/check-pq-pinning.mjs', 'scripts/check-unsafe-trusted-root.mjs', 'scripts/fixtures/pca-scan/cases.mjs'];
const HAVE = TOOLING.every((f) => existsSync(join(REPO, f)));
const HAVE_POC = HAVE && existsSync(join(REPO, 'redteam/round6/core'));
/* eslint-disable @typescript-eslint/no-explicit-any -- plain ESM scripts / data module, no types */
let pqScan: any, unsafeScan: any, CASES: any, EVASIONS: any, SRC: any, TPL: any, evasionExpect: any;
const load = async (): Promise<void> => {
  if (pqScan) return;
  const [pq, unsafe, cases] = await Promise.all(TOOLING.map((f) => import(pathToFileURL(join(REPO, f)).href)));
  ({ scan: pqScan } = pq);
  ({ scan: unsafeScan } = unsafe);
  ({ CASES, EVASIONS, SRC, TPL, evasionExpect } = cases);
};
/* eslint-enable @typescript-eslint/no-explicit-any */
const H = "import { verifyPCActnCore, verifyPCActn, verifyChain } from '@atlasauth/pca';\nexport async function h(req: any, p: any, store: any) {\n";

const pqFiles = (root: string): string[] => (pqScan(root, {}) as string[]).map((v) => v.split(':')[0]!);
const unsafeFindings = (root: string): string[] => unsafeScan(root, ['packages', 'apps', 'sdks', 'examples', 'samples', 'docs', 'tools/pca-playground']) as string[];
const hit = (findings: string[], rel: string): boolean => findings.some((v) => v.startsWith(rel + ':'));

function plant(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'pcascan6-'));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return root;
}

describe.skipIf(!HAVE)('R6-CORE-05: AST scanners catch every evasion', async () => {
  // describe.skipIf still RUNS this collector; without the tooling there is nothing to load or enumerate
  if (!HAVE) return;
  await load();
  const files: Record<string, string> = {};
  for (const [id, e] of Object.entries(EVASIONS as Record<string, Evasion>)) {
    files[`${TPL}/${id}.ts`] = `${H}${e.code}\n}\n`;
    files[`${SRC}/${id}.ts`] = `${H}${e.code}\n}\n`;
  }
  for (const c of CASES as Case[]) files[c.path] = c.code;
  const root = plant(files);
  const pq = pqScan(root, {}) as string[];
  const unsafe = unsafeFindings(root);

  for (const [id, e] of Object.entries(EVASIONS as Record<string, Evasion>)) {
    for (const [where, base] of [['tpl', TPL], ['src', SRC]] as const) {
      it(`${id} (${where})`, () => {
        const rel = `${base}/${id}.ts`;
        const want = evasionExpect(e, where) as { pq?: boolean; unsafe?: boolean };
        if (want.pq !== undefined) expect(pq.some((v) => v.startsWith(rel + ':')), `pq-pinning on ${rel}\n${pq.join('\n')}`).toBe(want.pq);
        if (want.unsafe !== undefined) expect(hit(unsafe, rel), `unsafe-trusted-root on ${rel}\n${unsafe.join('\n')}`).toBe(want.unsafe);
      });
    }
  }

  for (const c of CASES as Case[]) {
    it(`${c.id}`, () => {
      if (c.pq !== undefined) expect(pq.some((v) => v.startsWith(c.path + ':')), `pq-pinning on ${c.path}\n${pq.join('\n')}`).toBe(c.pq);
      if (c.unsafe !== undefined) expect(hit(unsafe, c.path), `unsafe-trusted-root on ${c.path}\n${unsafe.join('\n')}`).toBe(c.unsafe);
      if (c.rule) expect(unsafe.filter((v) => v.startsWith(c.path + ':')).join('\n')).toMatch(c.rule);
    });
  }
});

describe.skipIf(!HAVE_POC)('R6-CORE-05: the red-team PoC directories, verbatim', async () => {
  if (HAVE_POC) await load();
  it('round-6 core/scan2: every evasion file is caught by the scanner responsible for it', () => {
    const root = join(REPO, 'redteam/round6/core/scan2');
    const pq = pqFiles(root);
    const unsafe = unsafeFindings(root);
    const missed: string[] = [];
    for (const [base, where] of [['packages/create-pca-app/templates/evil/src', 'tpl'], ['packages/evil/src', 'src']] as const) {
      for (const f of readdirSync(join(root, base)).sort()) {
        const id = f.replace(/\.ts$/, '');
        const e = (EVASIONS as Record<string, Evasion>)[id];
        expect(e, `corpus lacks ${id}`).toBeDefined();
        const want = evasionExpect(e, where) as { pq?: boolean; unsafe?: boolean };
        const rel = `${base}/${f}`;
        if (want.pq && !pq.includes(rel)) missed.push(`pq-pinning missed ${rel}`);
        if (want.unsafe && !hit(unsafe, rel)) missed.push(`unsafe-trusted-root missed ${rel}`);
        if (!pq.includes(rel) && !hit(unsafe, rel)) missed.push(`BOTH missed ${rel}`);
      }
    }
    expect(missed).toEqual([]);
  });

  it('round-6 core/scan (round-5 evasions: .vue, src/fixtures, mutation-kill names, template shapes)', () => {
    const root = join(REPO, 'redteam/round6/core/scan');
    const pq = pqFiles(root);
    const unsafe = unsafeFindings(root);
    for (const rel of ['examples/demo/app.vue', 'packages/evil/src/verify.ts', 'packages/evil/src/mutation-kill-gate.ts', 'packages/evil/src/fixtures/gate.ts', 'packages/create-pca-app/templates/evil/src/server.ts']) {
      expect(pq.includes(rel), `pq-pinning ${rel}`).toBe(true);
    }
    for (const rel of ['examples/demo/app.vue', 'packages/evil/src/verify.ts', 'packages/evil/src/mutation-kill-gate.ts', 'packages/evil/src/fixtures/gate.ts', 'packages/create-pca-app/templates/evil/src/server.ts']) {
      expect(hit(unsafe, rel), `unsafe-trusted-root ${rel}\n${unsafe.join('\n')}`).toBe(true);
    }
    // every evasion line of the template file (E1..E10) is reported, not just the first
    const lines = unsafe.filter((v) => v.startsWith('packages/create-pca-app/templates/evil/src/server.ts:')).map((v) => Number(v.split(':')[1]));
    for (const l of [4, 5, 8, 11, 16, 20, 23, 26, 28, 30]) expect(lines, `server.ts line ${l}`).toContain(l);
  });

  it('round-5 ts-callers/scanfix: the shapes the round-5 fix targeted stay caught', () => {
    const pq = pqFiles(join(REPO, 'redteam/round5/ts-callers/scanfix'));
    for (const rel of ['packages/evil/lib/c.ts', 'packages/evil/src/a.ts', 'packages/evil/src/b.ts', 'packages/evil/src/d.js']) expect(pq, rel).toContain(rel);
  });
});

describe.skipIf(!HAVE)('R6-CORE-05: self-test modes', () => {
  it('both scripts expose a passing --self-test', async () => {
    const { spawnSync } = await import('node:child_process');
    for (const s of ['scripts/check-unsafe-trusted-root.mjs', 'scripts/check-pq-pinning.mjs']) {
      const r = spawnSync(process.execPath, [join(REPO, s), '--self-test'], { encoding: 'utf8', timeout: 120_000 });
      expect(r.status, `${s}\n${r.stdout}\n${r.stderr}`).toBe(0);
      expect(r.stdout).toMatch(/self-test: \d+ case\(s\) ok/);
    }
  }, 180_000);
});
