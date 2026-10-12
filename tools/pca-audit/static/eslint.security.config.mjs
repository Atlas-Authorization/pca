// eslint-plugin-security over the PCA lineup's production sources (tests excluded). Flat config, ESLint 9.
// Run from the repo root:  node_modules/.bin/eslint -c tools/pca-audit/static/eslint.security.config.mjs 'packages/pca*/src/**/*.ts'
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));
const rootReq = createRequire(join(here, '../../../package.json'));
const auditReq = createRequire(join(here, '../package.json'));
const security = auditReq('eslint-plugin-security');
const tsParser = rootReq('@typescript-eslint/parser');
export default [
  { ignores: ['**/*.test.ts', '**/*.test-util.ts', '**/dist/**', '**/node_modules/**', '**/.stryker-tmp/**', '**/audit/**'] },
  {
    files: ['**/*.ts'],
    languageOptions: { parser: tsParser, ecmaVersion: 2023, sourceType: 'module' },
    plugins: { security: security.default ?? security },
    rules: {
      'security/detect-unsafe-regex': 'error',
      'security/detect-non-literal-regexp': 'error',
      'security/detect-eval-with-expression': 'error',
      'security/detect-new-buffer': 'error',
      'security/detect-buffer-noassert': 'error',
      'security/detect-child-process': 'error',
      'security/detect-disable-mustache-escape': 'error',
      'security/detect-no-csrf-before-method-override': 'error',
      'security/detect-non-literal-fs-filename': 'error',
      'security/detect-non-literal-require': 'error',
      'security/detect-possible-timing-attacks': 'error',
      'security/detect-pseudoRandomBytes': 'error',
      'security/detect-bidi-characters': 'error',
      'security/detect-object-injection': 'warn',
    },
  },
];
