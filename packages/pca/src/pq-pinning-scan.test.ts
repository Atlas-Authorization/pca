import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

// Repository tooling under scripts/: absent from trees that ship this package without the repository scripts (the public
// package repository). The suite skips there instead of failing to load.
const SCRIPT = join(__dirname, '..', '..', '..', 'scripts', 'check-pq-pinning.mjs');
const HAVE = existsSync(SCRIPT);
/* eslint-disable @typescript-eslint/no-explicit-any -- plain ESM script, no types */
let ALLOW: any;
let scan: any;

/**
 * R3-01 structural guard: no production file may verify a post-quantum signature outside the choke point
 * (packages/pca/src/pq.ts) unless it is allowlisted with a reason. A forgotten surface cannot recur silently.
 */
describe.skipIf(!HAVE)('scripts/check-pq-pinning.mjs', async () => {
  // describe.skipIf still RUNS this collector (to register the skipped tests), so the import itself must be guarded
  if (HAVE) ({ ALLOW, scan } = await import(pathToFileURL(SCRIPT).href));
  it('the repository has no un-allowlisted PQ verification path', () => {
    expect(scan()).toEqual([]);
  });

  it('every allowlist entry carries a non-trivial reason', () => {
    for (const [file, rules] of Object.entries(ALLOW as Record<string, Record<string, string>>)) {
      for (const [rule, reason] of Object.entries(rules)) expect(reason.length, `${file}:${rule}`).toBeGreaterThan(15);
    }
  });

  it('flags a new file that calls the low-level verifiers, mints a key, or asserts an unbound key', () => {
    const root = mkdtempSync(join(tmpdir(), 'pqscan-'));
    const src = join(root, 'packages', 'evil', 'src');
    mkdirSync(src, { recursive: true });
    writeFileSync(join(src, 'a.ts'), "import { verifyWithSuite } from '@atlasauth/pca';\nexport const f = () => verifyWithSuite('ml-dsa-65', {}, new Uint8Array(), {});\n");
    writeFileSync(join(src, 'b.ts'), "import { mlDsa65VerifyB64u } from '@atlasauth/pca';\nexport const f = (pk: string) => mlDsa65VerifyB64u(pk, new Uint8Array(), 'x');\n");
    writeFileSync(join(src, 'c.ts'), "export const k = PinnedPqKey.mint('x', 'pin');\nexport const o = { allowUnboundPq: true, trustedPk: 'x' };\n");
    writeFileSync(join(src, 'd.ts'), "import { verifyWithSuite } from './pq-test-support';\n");
    writeFileSync(join(src, 'ok.test.ts'), "verifyWithSuite('x', {}, new Uint8Array(), {});\n");
    writeFileSync(join(src, 'doc.ts'), "// verifyWithSuite(alg, keys) is documented here\n/** mlDsa65Verify( */\nexport const x = 1;\n");
    const v = scan(root, {}) as string[];
    const joined = v.join('\n');
    expect(joined).toMatch(/a\.ts: verifyWithSuite/);
    expect(joined).toMatch(/b\.ts: raw post-quantum/);
    expect(joined).toMatch(/c\.ts: PinnedPqKey minted/);
    expect(joined).toMatch(/c\.ts: allowUnboundPq/);
    expect(joined).toMatch(/c\.ts: trustedPk/);
    expect(joined).toMatch(/d\.ts: production code imports the test-only/);
    expect(joined).not.toMatch(/ok\.test\.ts|doc\.ts/);
  });

  // R5-B2: the shapes the round-5 red team showed the scan was blind to.
  const planted = (files: Record<string, string>): string => {
    const root = mkdtempSync(join(tmpdir(), 'pqscan5-'));
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), text);
    }
    return (scan(root, {}) as string[]).join('\n');
  };

  it('flags trustedRoot / grant lifted from cap_chain[0], the allowUnboundPq shorthand and variable form', () => {
    const j = planted({
      'packages/evil/src/a.ts': 'verifyChain(p.cap_chain, i, { trustedRoot: p.cap_chain[0] });\n',
      'packages/evil/src/b.ts': 'verifyPCActnCore(p, { insecureSkipPlanRootCheck: true, grant: p.cap_chain[0], audience: null });\n',
      'packages/evil/src/c.ts': 'const allowUnboundPq = true;\nverifyChain(c, undefined, { allowUnboundPq });\n',
      'packages/evil/src/d.ts': 'verifyChain(c, undefined, { allowUnboundPq: extra });\n',
      'packages/evil/src/e.ts': 'verifyChain(c, undefined, { trustedRoot: p.capChain.at(0) });\n',
    });
    expect(j).toMatch(/a\.ts: trustedRoot lifted from the artifact/);
    expect(j).toMatch(/b\.ts: grant lifted from the artifact/);
    expect(j).toMatch(/c\.ts: allowUnboundPq: true/);
    expect(j).toMatch(/d\.ts: allowUnboundPq: true/);
    expect(j).toMatch(/e\.ts: trustedRoot lifted from the artifact/);
  });

  it('accepts the safe forms: pqPins / grantFromArtifact next to a lifted grant, forwarded allowUnboundPq, comments', () => {
    const j = planted({
      'packages/ok/src/a.ts': 'verifyPCActnCore(p, { insecureSkipPlanRootCheck: true, grant: p.cap_chain[0], grantFromArtifact: true, pqPins });\n',
      'packages/ok/src/b.ts': 'resolve({ allowUnboundPq: opts.allowUnboundPq, x: policy?.allowUnboundPq });\nf({ allowUnboundPq: false });\n',
      'packages/ok/src/c.ts': '/* trustedRoot: p.cap_chain[0] and allowUnboundPq: true */\n// grant: p.cap_chain[0]\nexport const x = 1;\n',
    });
    expect(j).toBe('');
  });

  it('sees code after a leading block comment, multi-line block comments, .js/.mjs files and directories outside <pkg>/src', () => {
    const j = planted({
      'packages/evil/src/b.ts': "/* hidden */ export const x = mlDsa65Verify(new Uint8Array(1952), new Uint8Array(1), new Uint8Array(3309));\n",
      'packages/evil/src/d.js': 'verifyWithSuite("ml-dsa-65", {}, new Uint8Array(), {});\n',
      'packages/evil/lib/e.mjs': 'export const k = { allowUnboundPq: true };\n',
      'tools/evil/t.ts': 'export const o = { trustedPk: "x" };\n',
      'apps/evil/server/s.ts': 'PinnedPqKey.mint("x", "pin");\n',
      'examples/evil/x.ts': 'verifyWithSuite("x", {}, new Uint8Array(), {});\n',
      'sdks/evil/y.cjs': 'mlDsa65Verify(a, b, c);\n',
      'packages/evil/src/m.ts': '/*\n * multi-line\n */ verifyWithSuite("a", {}, new Uint8Array(), {});\n',
      'tools/pca-redteam/round5/p.ts': 'verifyWithSuite("a", {}, new Uint8Array(), {});\n',
    });
    expect(j).toMatch(/b\.ts: raw post-quantum/);
    expect(j).toMatch(/d\.js: verifyWithSuite/);
    expect(j).toMatch(/e\.mjs: allowUnboundPq: true/);
    expect(j).toMatch(/tools\/evil\/t\.ts: trustedPk/);
    expect(j).toMatch(/apps\/evil\/server\/s\.ts: PinnedPqKey minted/);
    expect(j).toMatch(/examples\/evil\/x\.ts: verifyWithSuite/);
    expect(j).toMatch(/y\.cjs: raw post-quantum/);
    expect(j).toMatch(/m\.ts: verifyWithSuite/);
    expect(j).not.toMatch(/pca-redteam/);
  });
});
