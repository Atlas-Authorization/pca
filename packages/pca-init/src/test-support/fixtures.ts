/** Tiny fixture projects, one per framework. Written to a temp directory per test; nothing here is a real dependency. */
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { Git, InitDeps } from '../types';

export type Files = Record<string, string>;

const pkg = (o: object): string => JSON.stringify(o, null, 2) + '\n';

export const FIXTURES: Record<string, Files> = {
  'express-ts': {
    'package.json': pkg({ name: 'shop-api', scripts: { dev: 'tsx src/server.ts' }, dependencies: { express: '^4.19.0', '@anthropic-ai/sdk': '^0.30.0' }, devDependencies: { typescript: '^5.6.0' } }),
    'tsconfig.json': '{ "compilerOptions": { "module": "commonjs", "rootDir": "src" }, "include": ["src"] }\n',
    'src/server.ts': `import express from 'express';\n\nconst app = express();\napp.use(express.json());\napp.get('/orders', (_req, res) => res.json([]));\napp.post('/orders/:id/refund', (_req, res) => res.json({ ok: true }));\napp.listen(3000);\n`,
  },
  'fastify-js': {
    'package.json': pkg({ name: 'fast-js', scripts: { start: 'node index.js' }, dependencies: { fastify: '^4.0.0', langchain: '^0.3.0' } }),
    'index.js': `'use strict';\nconst fastify = require('fastify');\nconst app = fastify();\napp.get('/ping', async () => ({ pong: true }));\napp.listen({ port: 3000 });\n`,
  },
  'hono-esm': {
    'package.json': pkg({ name: 'edge', type: 'module', scripts: { dev: 'node server.js' }, dependencies: { hono: '^4.0.0', ai: '^3.0.0' } }),
    'server.js': `import { Hono } from 'hono';\n\nconst app = new Hono();\napp.get('/health', (c) => c.text('ok'));\nexport default app;\n`,
  },
  'next-ts': {
    'package.json': pkg({ name: 'web', scripts: { dev: 'next dev' }, dependencies: { next: '^14.0.0', '@modelcontextprotocol/sdk': '^1.0.0' }, devDependencies: { typescript: '^5.6.0' } }),
    'app/api/orders/[id]/route.ts': `export async function GET() {\n  return Response.json({});\n}\nexport async function DELETE() {\n  return Response.json({});\n}\n`,
  },
  'nest-ts': {
    'package.json': pkg({ name: 'nest-app', scripts: { start: 'nest start' }, dependencies: { '@nestjs/core': '^10.0.0', '@nestjs/common': '^10.0.0' }, devDependencies: { typescript: '^5.6.0' } }),
    'src/main.ts': `import { NestFactory } from '@nestjs/core';\nimport { AppModule } from './app.module';\n\nasync function bootstrap() {\n  const app = await NestFactory.create(AppModule);\n  await app.listen(3000);\n}\nbootstrap();\n`,
  },
  'fastapi': {
    'pyproject.toml': '[project]\nname = "svc"\ndependencies = ["fastapi>=0.110", "langchain>=0.3", "uvicorn"]\n',
    'main.py': `from fastapi import FastAPI\n\napp = FastAPI()\n\n@app.get("/items/{item_id}")\ndef item(item_id: int):\n    return {}\n\n@app.post("/items")\ndef create():\n    return {}\n`,
  },
  'flask': {
    'requirements.txt': 'Flask==3.0.0\nanthropic\n',
    'app.py': `from flask import Flask\napp = Flask(__name__)\n\n@app.route("/hello", methods=["GET", "POST"])\ndef hello():\n    return "hi"\n`,
  },
  'django': {
    'requirements.txt': 'Django>=5\n',
    'config/settings.py': 'MIDDLEWARE = [\n    "django.middleware.security.SecurityMiddleware",\n]\n',
  },
  'rails': { Gemfile: "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\n", 'config/application.rb': 'module Shop\n  class Application < Rails::Application\n  end\nend\n' },
  'sinatra': { Gemfile: "gem 'sinatra'\n", 'app.rb': "require 'sinatra'\n\nget '/ping' do\n  'pong'\nend\n" },
  'go-gin': { 'go.mod': 'module example.com/shop\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.10.0\n', 'main.go': 'package main\n\nfunc main() {\n\tr := gin.Default()\n\tr.GET("/orders/:id", nil)\n\tr.Run()\n}\n' },
  'go-http': { 'go.mod': 'module example.com/plain\n\ngo 1.22\n', 'main.go': 'package main\n\nimport "net/http"\n\nfunc main() {\n\thttp.ListenAndServe(":8080", nil)\n}\n' },
  'spring': { 'pom.xml': '<project><dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>\n', 'src/main/resources/application.yml': 'server:\n  port: 8080\n' },
  'aspnet': { 'Shop.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>\n', 'Program.cs': 'var builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();\napp.Run();\n' },
  'laravel': { 'composer.json': '{"require":{"laravel/framework":"^11.0"}}\n', 'routes/api.php': "<?php\nRoute::get('/ping', fn () => 'pong');\n" },
  'symfony': { 'composer.json': '{"require":{"symfony/framework-bundle":"^7.0"}}\n' },
  'axum': { 'Cargo.toml': '[package]\nname = "svc"\nversion = "0.1.0"\n\n[dependencies]\naxum = "0.7"\n', 'src/main.rs': 'fn main() {\n    let app = Router::new();\n}\n' },
  'vapor': { 'Package.swift': '// swift-tools-version:5.9\nimport PackageDescription\nlet package = Package(name: "x", dependencies: [.package(url: "https://github.com/vapor/vapor.git", from: "4.0.0")])\n', 'Sources/App/configure.swift': 'func configure(_ app: Application) throws {\n}\n' },
  'openapi-express': {
    'package.json': pkg({ name: 'billing', dependencies: { express: '^4.19.0' } }),
    'openapi.json': JSON.stringify({ openapi: '3.0.3', info: { title: 'billing', version: '1' }, paths: { '/invoices': { get: { operationId: 'listInvoices', responses: { '200': { description: 'ok' } } } }, '/invoices/{id}/void': { post: { operationId: 'voidInvoice', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { '200': { description: 'ok' } } } } } }),
    'index.js': `const express = require('express');\nconst app = express();\napp.listen(3000);\n`,
  },
  'mcp-only': {
    'package.json': pkg({ name: 'agent-box', dependencies: { '@modelcontextprotocol/sdk': '^1.0.0' } }),
    '.mcp.json': JSON.stringify({ mcpServers: { github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'], env: { GITHUB_TOKEN: 'placeholder' } }, docs: { url: 'https://mcp.example.com/mcp' } } }),
  },
  'monorepo': {
    'package.json': pkg({ name: 'root', private: true, workspaces: ['apps/*'] }),
    'services/web/package.json': pkg({ name: 'web', dependencies: { next: '^14.0.0' } }),
    'services/api/package.json': pkg({ name: 'api', dependencies: { express: '^4.19.0' } }),
    'services/api/index.js': `const express = require('express');\nconst app = express();\n`,
  },
};

export function materialize(files: Files): string {
  const root = mkdtempSync(join(tmpdir(), 'pca-init-'));
  for (const [rel, text] of Object.entries(files)) {
    const abs = join(root, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, text);
  }
  return root;
}

export interface FakeGitState {
  repo?: boolean;
  status?: string;
  tracked?: string[];
  /** check-ignore answers 0 (ignored) unless this is false. */
  ignores?: boolean;
}

/** A git double: answers from a state object, records nothing, runs nothing. */
export function fakeGit(s: FakeGitState = {}): Git {
  return (_cwd, args) => {
    switch (args[0]) {
      case 'rev-parse': return { code: s.repo === false ? 128 : 0, out: 'true\n' };
      case 'status': return { code: 0, out: s.status ?? '' };
      case 'ls-files': return { code: (s.tracked ?? []).includes(args[args.length - 1]!) ? 0 : 1, out: '' };
      case 'check-ignore': return { code: s.ignores === false ? 1 : 0, out: '' };
      default: return { code: 1, out: '' };
    }
  };
}

export const fakeDeps = (s: FakeGitState = {}, fetchImpl?: typeof fetch): InitDeps => {
  let n = 0;
  return {
    git: fakeGit(s),
    ...(fetchImpl ? { fetch: fetchImpl } : {}),
    // the first key is a fixed value (tests read it back); later keys are distinct so two keypairs can be told apart
    newKey: () => (n++ === 0 ? { secret: 'c2VjcmV0LXNlZWQtMzItYnl0ZXMtbG9uZy1leGFjdGx5', publicKey: 'cHVibGljLWtleS1mb3ItdGVzdHM' } : { secret: `${'A'.repeat(20)}S${'A'.repeat(22)}`, publicKey: `${'A'.repeat(20)}P${'A'.repeat(22)}` }),
  };
};
