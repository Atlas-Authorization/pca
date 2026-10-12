import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
// @ts-expect-error - plain ESM script, no types
import { scan } from '../../../scripts/check-unsafe-trusted-root.mjs';

/**
 * R5-B1 structural guard: no template / example / doc / README / sample / playground may teach a grant or trusted root taken
 * from the request or from the presented artifact's own `cap_chain[0]`.
 */
describe('scripts/check-unsafe-trusted-root.mjs', () => {
  it('the repository teaches no artifact-rooted or request-rooted trusted root', () => {
    expect(scan()).toEqual([]);
  });

  const plant = (files: Record<string, string>): string[] => {
    const root = mkdtempSync(join(tmpdir(), 'utr-'));
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), text);
    }
    return scan(root, ['packages', 'examples', 'docs', 'samples', 'tools/pca-playground']) as string[];
  };

  it('flags the original express-rs template shape (PCA-Grant header -> grant)', () => {
    const v = plant({
      'packages/create-pca-app/templates/express-rs/src/server.ts':
        "const grantHeader = req.header('PCA-Grant');\nconst grant = JSON.parse(Buffer.from(grantHeader, 'base64url').toString('utf8'));\nawait verifyPCActnCore(decodePCActn(encoded), { grant, audience: AUDIENCE });\n",
    });
    expect(v.join('\n')).toMatch(/express-rs\/src\/server\.ts:1: grant-from-request/);
    expect(v.join('\n')).toMatch(/server\.ts:2: grant-from-header-var/);
  });

  it('flags trustedRoot / grant derived from cap_chain[0] in TS, Python, Ruby, Java, Go, Rust, docs and html', () => {
    const v = plant({
      'examples/a/src/a.ts': 'verifyChain(p.cap_chain, iss, { trustedRoot: p.cap_chain[0] });\n',
      'examples/a/src/b.ts': 'await verifyPCActnCore(p, { grant: p.cap_chain[0], audience });\n',
      'examples/a/src/c.ts': 'const grant = req.body.pcactn.cap_chain[0];\n',
      'examples/a/src/d.ts': 'verifyChain(c, i, { trustedRoot: pcactn.capChain.at(0) });\n',
      'examples/p/a.py': 'ok = verify_chain(chain, iss, trusted_root=pcactn["cap_chain"][0])\n',
      'examples/r/a.rb': 'AtlasPca.verify_chain(chain, iss, trusted_root: pcactn["cap_chain"][0])\n',
      'examples/j/A.java': 'Pca.verifyChain(chain, iss, TrustedRoot = pcactn.capChain[0]);\n',
      'examples/g/a.go': 'grant := p.CapChain[0]\n',
      'examples/rs/a.rs': 'let trusted_root = p.cap_chain[0].clone();\n',
      'docs/guide.md': 'Use it like:\n\n```ts\nconst r = await verifyPCActnCore(p, { grant: p.cap_chain[0] });\n```\n',
      'tools/pca-playground/page.html': '<script>P.verifyChain(c, i, {trustedRoot: art.cap_chain[0]})</script>\n',
      'samples/s/x.js': 'verifyPCActnCore(a, { grant: req.headers["x-grant"] ? JSON.parse(req.headers.grant) : null, grant: request.body.grant });\n',
    });
    const j = v.join('\n');
    for (const f of ['a.ts', 'b.ts', 'c.ts', 'd.ts', 'a.py', 'a.rb', 'A.java', 'a.go', 'a.rs', 'guide.md', 'page.html', 'x.js']) expect(j, f).toContain(f + ':');
  });

  it('flags grantFromArtifact without pqPins and the allowUnboundPq shorthand, but not with pqPins', () => {
    const v = plant({
      'examples/a/bad.ts': 'verifyPCActnCore(p, { grant: g, grantFromArtifact: true });\n',
      'examples/a/bad2.ts': 'const policy = { allowUnboundPq };\n',
      'examples/a/bad3.ts': 'const policy = { allowUnboundPq: true };\n',
      // R6-CORE-04: a teaching surface authorizes with the full verifier, never verifyPCActnCore (that is now its own finding)
      'examples/a/ok.ts': 'verifyPCActn(p, { grant: g, grantFromArtifact: true, pqPins: PINS });\n',
    });
    const j = v.join('\n');
    expect(j).toMatch(/bad\.ts:1: grant-from-artifact-no-pins/);
    expect(j).toMatch(/bad2\.ts:1: unbound-pq/);
    expect(j).toMatch(/bad3\.ts:1: unbound-pq/);
    expect(j).not.toMatch(/ok\.ts/);
  });

  it('catches a shape after a leading block comment and honours only reasoned allow markers; ignores comments and tests', () => {
    const v = plant({
      'examples/a/lead.ts': '/* header */ const x = { trustedRoot: p.cap_chain[0] };\n',
      'examples/a/marked.ts': '// pca-unsafe-root: allow counter-example shown to demonstrate the attack\nconst x = { trustedRoot: p.cap_chain[0] };\n',
      'examples/a/badmark.ts': '// pca-unsafe-root: allow ok\nconst x = { trustedRoot: p.cap_chain[0] };\n',
      'examples/a/comment.ts': '// do not write trustedRoot: p.cap_chain[0]\n/** grant: p.cap_chain[0] */\nconst y = 1;\n',
      'examples/a/safe.ts': 'verifyPCActn(p, { grant: store.get(p.grant_ref), pqPins, allowedSuites: ["ed25519"] });\n',
      'examples/a/x.test.ts': 'const x = { trustedRoot: p.cap_chain[0] };\n',
    });
    const j = v.join('\n');
    expect(j).toMatch(/lead\.ts:1/);
    expect(j).toMatch(/badmark\.ts:2/);
    expect(j).not.toMatch(/marked\.ts|comment\.ts|safe\.ts|x\.test\.ts/);
  });
});
