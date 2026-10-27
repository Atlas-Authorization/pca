/**
 * The runnable samples of the intent layer page (concepts/intent-layer.md): every ```ts block is executed against this
 * source, and what it prints must equal the ```text block that follows it.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';
import * as root from './index';
import * as intent from './ext/intent';

// the monorepo keeps the docs under docs/pca; the flagship repository carries them 1:1 under docs/
const docsRoot = [join('docs', 'pca'), 'docs'].map((d) => join(__dirname, '..', '..', '..', d)).find((d) => existsSync(join(d, 'concepts', 'intent-layer.md')))!;
const page = readFileSync(join(docsRoot, 'concepts', 'intent-layer.md'), 'utf8');
const blocks = [...page.matchAll(/```ts\n([\s\S]*?)```\n\n```text\n([\s\S]*?)```/g)].map((m) => ({ code: m[1]!, out: m[2]!.trimEnd() }));
const AsyncFunction = Object.getPrototypeOf(async () => undefined).constructor as new (...a: string[]) => (...args: unknown[]) => Promise<void>;

describe('intent layer page samples', () => {
  it('has the quick start and the schema / session sample', () => {
    expect(blocks.length).toBe(2);
  });
  for (const [i, b] of blocks.entries()) {
    it(`sample ${i + 1} runs and prints what the page says`, async () => {
      const js = ts.transpileModule(b.code, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
      const body = js.replace(/^import \{([^}]*)\} from '([^']+)';?$/gm, (_m, names: string, spec: string) => `const {${names.replace(/ as /g, ': ')}} = __m['${spec}'];`);
      const lines: string[] = [];
      const log = { log: (...a: unknown[]) => void lines.push(a.map(String).join(' ')) };
      await new AsyncFunction('__m', 'console', body)({ '@atlasauth/pca': root, '@atlasauth/pca/ext/intent': intent }, log);
      expect(lines.join('\n')).toBe(b.out);
    });
  }
});
