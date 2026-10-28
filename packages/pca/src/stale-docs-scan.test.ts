import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

// Repository tooling under scripts/: absent from trees that ship this package without the repository scripts. The suite
// skips there instead of failing to load.
const SCRIPT = join(__dirname, '..', '..', '..', 'scripts', 'check-pca-stale-docs.mjs');
const HAVE = existsSync(SCRIPT);
/* eslint-disable-next-line @typescript-eslint/no-explicit-any -- plain ESM script, no types */
let mod: any;

/** Retired public statements (0.4.2 peer review, S1-S13) must not come back in docs, READMEs or shipped comments. */
describe.skipIf(!HAVE)('scripts/check-pca-stale-docs.mjs', async () => {
  if (HAVE) mod = await import(pathToFileURL(SCRIPT).href);

  const plant = (files: Record<string, string>): string[] => {
    const root = mkdtempSync(join(tmpdir(), 'stale-'));
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), text);
    }
    return (mod.scan(root) as string[]).map((s) => s.split(': ').slice(0, 2).join(': '));
  };

  it('the repository carries none of the retired statements', () => {
    expect(mod.scan()).toEqual([]);
  });

  it('flags each statement the 0.4.2 review read as current, at its file and line', () => {
    expect(
      plant({
        'docs/pca/concepts/optimistic-and-zk.md': 'x\n| SNARK | **Seam only.** No circuit, trusted setup or prover is implemented. |\nThe hosted `/v1/pca/actions` does not currently wire the ZK hook.\n',
        'docs/pca/concepts/plan-commitment.md': 'In the current release plans are auto-authorized on commit.\n',
        'docs/pca/concepts/policy-and-risk.md':
          "the agent's claimed value is used only as a default. The separate `taint_gate` check reports `not-enforced`.\n| `blastRadius` | 0.5 | raise |\n",
        'docs/pca/security/trust-model.md': '- **The default threshold verifier reads `risk_claim.r`.**\n- baseline `blastRadius` is a neutral constant (0.5)\n- **The taint gate is not enforced as a separate check.**\n',
        'packages/pca/conformance/README.md': '| `vectors.json` | **Curated core**: 394 vectors (71 positive) |\n',
        'packages/pca/src/attestation.ts': ' * binding). We deliberately DO NOT implement SEV-SNP/TDX quote parsing here\n',
        'sdks/rust-pca/README.md': 'The crate passes the shared 172-vector PCA conformance corpus.\n',
      }),
    ).toEqual([
      'docs/pca/concepts/optimistic-and-zk.md:2: zk-seam-only',
      'docs/pca/concepts/optimistic-and-zk.md:2: zk-no-prover',
      'docs/pca/concepts/optimistic-and-zk.md:3: zk-hosted-unwired',
      'docs/pca/concepts/plan-commitment.md:1: plan-auto-authorized',
      'docs/pca/concepts/policy-and-risk.md:1: taint-gate-unenforced',
      'docs/pca/concepts/policy-and-risk.md:1: taint-claim-default',
      'docs/pca/concepts/policy-and-risk.md:2: blast-radius-flat',
      'docs/pca/security/trust-model.md:3: taint-gate-unenforced',
      'docs/pca/security/trust-model.md:1: threshold-reads-claim',
      'docs/pca/security/trust-model.md:2: blast-radius-neutral',
      'packages/pca/conformance/README.md:1: corpus-394',
      'packages/pca/src/attestation.ts:1: attest-no-quote-parsing',
      'sdks/rust-pca/README.md:1: corpus-172',
    ]);
  });

  it('reads the flagship layout (docs/ instead of docs/pca/)', () => {
    expect(plant({ 'docs/reference/api.md': 'In this release a committed plan is auto-authorized.\n' })).toEqual(['docs/reference/api.md:1: plan-auto-authorized']);
  });

  it('leaves history alone: changelogs, dated audit reports, internal validation notes, tests', () => {
    expect(
      plant({
        'docs/pca/CHANGELOG.md': 'Plans were auto-authorized before 0.5.\n',
        'sdks/rust-pca/CHANGELOG.md': 'Aligned with the 172-vector corpus.\n',
        'docs/pca/security/audit-verifiers.md': 'a test hard-coded the 172-vector corpus size\n',
        'docs/pca/security/review-report-round3.md': 'Seam only\n',
        'docs/pca/validation/gap.md': 'Seam only\n',
        'packages/pca/src/zk.test.ts': '// Seam only\n',
      }),
    ).toEqual([]);
  });

  it('accurate replacements do not trip the gate', () => {
    expect(
      plant({
        'docs/pca/concepts/policy-and-risk.md':
          'Without `enforce.taint`, `taint_gate` reports `not-enforced`.\n| `blastRadius` | Per class: `reversible` 0.5, `costly` 0.5, `irreversible` 0.75 | may only raise |\n',
        'docs/pca/reference/api.md': 'Committing does not authorize.\n',
      }),
    ).toEqual([]);
  });
});
