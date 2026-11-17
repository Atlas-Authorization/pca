import { describe, expect, it } from 'vitest';
import { editEntry, type RegSpec } from './ast';

const express: RegSpec = { callees: ['express'], statement: (v) => `registerPca(${v});`, binding: 'registerPca' };
const hono: RegSpec = { callees: ['Hono'], statement: (v) => `registerPca(${v});`, binding: 'registerPca' };
const nest: RegSpec = { callees: ['NestFactory.create'], statement: (v) => `${v}.useGlobalGuards(new PcaGuard());`, binding: 'PcaGuard' };

const ok = (r: ReturnType<typeof editEntry>): string => {
  if (!r.ok) throw new Error(r.reason);
  return r.text;
};

describe('editEntry', () => {
  it('adds exactly one import and one registration, touching nothing else', () => {
    const src = `import express from 'express';\nimport cors from 'cors'; // keep\n\n// the app\nconst app = express();\napp.use(cors());\n`;
    const out = ok(editEntry(src, 'a.ts', express, './pca.setup', false));
    expect(out).toBe(`import express from 'express';\nimport cors from 'cors'; // keep\nimport { registerPca } from './pca.setup';\n\n// the app\nconst app = express();\nregisterPca(app);\napp.use(cors());\n`);
  });
  it('uses require in a CommonJS file and keeps a use-strict directive first', () => {
    const src = `'use strict';\nconst express = require('express');\nconst app = express();\n`;
    expect(ok(editEntry(src, 'a.js', express, './pca.setup', false))).toBe(`'use strict';\nconst express = require('express');\nconst { registerPca } = require('./pca.setup');\nconst app = express();\nregisterPca(app);\n`);
  });
  it('writes ESM imports when package.json says module', () => {
    const src = `const app = express();\n`;
    expect(ok(editEntry(src, 'a.js', express, './pca.setup.js', true))).toContain(`import { registerPca } from './pca.setup.js';`);
  });
  it('keeps a shebang first and indents inside a function', () => {
    const src = `#!/usr/bin/env node\nfunction build() {\n  const app = express();\n  return app;\n}\n`;
    const out = ok(editEntry(src, 'a.js', express, './pca.setup', false));
    expect(out.startsWith('#!/usr/bin/env node\nconst { registerPca }')).toBe(true);
    expect(out).toContain('  const app = express();\n  registerPca(app);\n  return app;');
  });
  it('handles new Hono<Env>() and a NestJS await', () => {
    expect(ok(editEntry(`import { Hono } from 'hono';\nconst app = new Hono<{ Bindings: B }>();\n`, 'a.ts', hono, './pca.setup', false))).toContain('const app = new Hono<{ Bindings: B }>();\nregisterPca(app);');
    expect(ok(editEntry(`import { NestFactory } from '@nestjs/core';\nasync function b() {\n  const app = await NestFactory.create(AppModule);\n}\n`, 'main.ts', nest, './pca.setup', false))).toContain('  app.useGlobalGuards(new PcaGuard());');
  });
  it('is idempotent', () => {
    const once = ok(editEntry(`import express from 'express';\nconst app = express();\n`, 'a.ts', express, './pca.setup', false));
    const twice = editEntry(once, 'a.ts', express, './pca.setup', false);
    expect(twice).toEqual({ ok: true, text: once, changed: false });
  });
  it('refuses a file that does not parse, has no app, or has two', () => {
    expect(editEntry('const app = express(;\n', 'a.ts', express, './p', false)).toMatchObject({ ok: false, reason: expect.stringContaining('does not parse') });
    expect(editEntry('const x = 1;\n', 'a.ts', express, './p', false)).toMatchObject({ ok: false, reason: expect.stringContaining('no line creating') });
    expect(editEntry('const a = express();\nconst b = express();\n', 'a.ts', express, './p', false)).toMatchObject({ ok: false, reason: expect.stringContaining('more than one') });
  });
  it('does not match a similarly named call', () => {
    expect(editEntry('const app = expressive();\n', 'a.ts', express, './p', false).ok).toBe(false);
  });
});
