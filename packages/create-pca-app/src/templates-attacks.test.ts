import { existsSync, mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { scaffold } from './index';

/** The template's suite module, loaded at run time (it lives outside this package's rootDir). */
interface SuiteRow {
  attack: { id: string };
  results: Array<{ ap: { id: string }; out: { stopped: boolean; reason: string } }>;
}
interface Suite {
  runAll(): Promise<SuiteRow[]>;
  matrix(rows: SuiteRow[]): string;
}
const loadSuite = async (): Promise<Suite> => (await import(join(__dirname, '..', 'templates', 'attacks', 'src', 'suite.ts'))) as Suite;

/**
 * The `attacks` template: seven agent-authorization attacks against five approaches. It is a copy of the repo's
 * examples/pca-attacks (kept byte-identical), its results are pinned here, and the public comparison page must carry
 * its matrix verbatim.
 */
const REPO = (() => {
  let dir = __dirname;
  for (let i = 0; i < 8; i++) {
    if (existsSync(join(dir, 'pnpm-workspace.yaml'))) return dir;
    dir = dirname(dir);
  }
  return null;
})();

const SRC_FILES = [
  'src/approaches/macaroon.ts',
  'src/approaches/oauth.ts',
  'src/approaches/pca.ts',
  'src/approaches/rar.ts',
  'src/approaches/ucan.ts',
  'src/attacks.ts',
  'src/common.ts',
  'src/run.ts',
  'src/suite.ts',
];

/** attack -> [oauth, rar, macaroon, ucan, pca]: true = stopped. */
const EXPECTED: Record<string, [boolean, boolean, boolean, boolean, boolean]> = {
  A1: [false, true, true, true, true],
  A2: [false, false, true, true, true],
  A3: [false, false, false, true, true],
  A4: [false, false, false, true, true],
  A5: [false, true, true, true, true],
  A6: [false, true, true, true, true],
  A7: [false, true, true, false, true],
};

describe('create-pca-app attacks template', () => {
  it('scaffolds the suite with the project name substituted', () => {
    const target = join(mkdtempSync(join(tmpdir(), 'tpl-attacks-')), 'my-attacks');
    const res = scaffold({ dir: target, template: 'attacks' });
    expect(res.template).toBe('attacks');
    expect(res.files).toEqual(['.gitignore', 'README.md', 'package.json', ...SRC_FILES, 'tsconfig.json'].sort());
    const pkg = JSON.parse(readFileSync(join(target, 'package.json'), 'utf8')) as { name: string; scripts: Record<string, string>; dependencies: Record<string, string> };
    expect(pkg.name).toBe('my-attacks');
    expect(pkg.scripts.start).toBe('tsx src/run.ts');
    expect(pkg.dependencies).toEqual({ '@atlasauth/pca': '^0.5.0' });
  });

  it('is byte-identical to examples/pca-attacks (apart from the name token)', () => {
    if (!REPO) return;
    const example = join(REPO, 'examples/pca-attacks');
    const tpl = join(__dirname, '..', 'templates', 'attacks');
    expect(readdirSync(join(example, 'src/approaches')).sort()).toEqual(readdirSync(join(tpl, 'src/approaches')).sort());
    for (const f of [...SRC_FILES, 'README.md', 'tsconfig.json']) {
      expect(readFileSync(join(tpl, f), 'utf8'), f).toBe(readFileSync(join(example, f), 'utf8'));
    }
    const ex = readFileSync(join(example, 'package.json'), 'utf8');
    expect(readFileSync(join(tpl, 'package.json'), 'utf8')).toBe(ex.replace('"name": "pca-attacks"', '"name": "__PCA_APP_NAME__"'));
  });

  it('every attack produces the documented outcome, and the comparison page carries the matrix verbatim', async () => {
    const { runAll, matrix } = await loadSuite();
    const rows = await runAll(); // throws SetupError if any legitimate control request is refused
    const got = Object.fromEntries(rows.map((r) => [r.attack.id, r.results.map((x) => x.out.stopped)]));
    expect(got).toEqual(EXPECTED);
    expect(rows[0]!.results.map((x) => x.ap.id)).toEqual(['oauth', 'rar', 'macaroon', 'ucan', 'pca']);
    // PCA refuses for the specific reason each attack targets.
    const pcaReason = (id: string) => rows.find((r) => r.attack.id === id)!.results[4]!.out.reason;
    expect(pcaReason('A1')).toMatch(/plan_root_authorized/);
    // A2: refused by the provenance predicates (Intent Layer v2): the payee is vouched for, the $180 amount is not.
    expect(pcaReason('A2')).toMatch(/env\.prov\.action\.params\.amount in \[.*\] not satisfied for payments\.send on payments.*provenance: amount agent, payee tool/);
    expect(pcaReason('A3')).toMatch(/leaf_signature/);
    expect(pcaReason('A4')).toMatch(/replay:.*\(replay\)/);
    expect(pcaReason('A5')).toMatch(/delegated_caveats/);
    expect(pcaReason('A6')).toMatch(/params_digest/);
    expect(pcaReason('A7')).toMatch(/trust budget depleted/);
    if (!REPO) return;
    const page = join(REPO, 'docs/pca/concepts/comparison.md');
    if (existsSync(page)) expect(readFileSync(page, 'utf8')).toContain(matrix(rows));
  }, 60_000);
});
