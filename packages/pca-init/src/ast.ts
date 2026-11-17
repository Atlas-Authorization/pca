/**
 * The syntax-aware entry-file edit. It parses the file with the TypeScript compiler, finds the variable the app is created into
 * (`const app = express()`), and splices exactly two lines into the original text: one import (or require) and one registration
 * statement after the declaration. Nothing else is reprinted, so the file's formatting and comments stay as they were.
 */
import ts from 'typescript';

export interface RegSpec {
  /** Callee texts that create the app: `express`, `Fastify`, `NestFactory.create`. `new X()` counts as a call. */
  callees: readonly string[];
  /** The registration statement for the app variable `v`, without indentation. */
  statement: (v: string) => string;
  /** The binding the generated module exports and the statement uses. */
  binding: string;
}

export type EditResult = { ok: true; text: string; changed: boolean } | { ok: false; reason: string };

const unwrap = (e: ts.Expression): ts.Expression => {
  let x = e;
  for (;;) {
    if (ts.isAwaitExpression(x) || ts.isParenthesizedExpression(x) || ts.isNonNullExpression(x) || ts.isAsExpression(x) || ts.isSatisfiesExpression(x)) x = x.expression;
    else return x;
  }
};

const sourceOf = (text: string, name: string): ts.SourceFile | null => {
  const sf = ts.createSourceFile(name, text, ts.ScriptTarget.Latest, true);
  const diags = (sf as unknown as { parseDiagnostics?: unknown[] }).parseDiagnostics;
  return diags !== undefined && diags.length > 0 ? null : sf;
};

/** Variables that hold a freshly created app, with the end offset of their statement. */
export function findAppVars(text: string, fileName: string, spec: RegSpec): { name: string; end: number; indent: string }[] | null {
  const sf = sourceOf(text, fileName);
  if (sf === null) return null;
  const found: { name: string; end: number; indent: string }[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer !== undefined) {
      const init = unwrap(n.initializer);
      if (ts.isCallExpression(init) || ts.isNewExpression(init)) {
        const callee = init.expression.getText(sf);
        if (spec.callees.includes(callee)) {
          let stmt: ts.Node = n;
          while (!ts.isVariableStatement(stmt) && stmt.parent !== undefined) stmt = stmt.parent;
          if (ts.isVariableStatement(stmt)) {
            const lineStart = text.lastIndexOf('\n', stmt.getStart(sf) - 1) + 1;
            found.push({ name: n.name.text, end: stmt.end, indent: /^[ \t]*/.exec(text.slice(lineStart))![0] });
          }
        }
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return found;
}

/** Add the import and the registration. `importSpec` is the path of the generated module as the entry file should write it. */
export function editEntry(text: string, fileName: string, spec: RegSpec, importSpec: string, esmHint: boolean): EditResult {
  if (new RegExp(`\\b${spec.binding}\\b`).test(text)) return { ok: true, text, changed: false };
  const vars = findAppVars(text, fileName, spec);
  if (vars === null) return { ok: false, reason: 'the file does not parse as TypeScript/JavaScript' };
  if (vars.length === 0) return { ok: false, reason: `no line creating the app (${spec.callees.join(' / ')}) found` };
  if (new Set(vars.map((v) => v.name)).size > 1 || vars.length > 1) return { ok: false, reason: `more than one app is created here (${vars.map((v) => v.name).join(', ')})` };
  const v = vars[0]!;
  v.end = eol(text, v.end);
  const sf = sourceOf(text, fileName)!;
  const imports = sf.statements.filter(ts.isImportDeclaration);
  const esm = imports.length > 0 || /\.(m?ts|tsx)$/.test(fileName) || fileName.endsWith('.mjs') || (esmHint && !fileName.endsWith('.cjs'));
  let importLine: string;
  let pos: number;
  if (esm) {
    importLine = `import { ${spec.binding} } from '${importSpec}';`;
    pos = imports.length > 0 ? eol(text, imports[imports.length - 1]!.end) : afterPrologue(text, sf);
  } else {
    importLine = `const { ${spec.binding} } = require('${importSpec}');`;
    const reqs = sf.statements.filter((s) => ts.isVariableStatement(s) && /\brequire\(/.test(s.getText(sf)));
    pos = reqs.length > 0 ? eol(text, reqs[reqs.length - 1]!.end) : afterPrologue(text, sf);
  }
  // splice from the back so the earlier offset stays valid
  const reg = `\n${v.indent}${spec.statement(v.name)}`;
  let out = text.slice(0, v.end) + reg + text.slice(v.end);
  if (pos > v.end) pos += reg.length;
  out = pos === 0 ? `${importLine}\n${out}` : out.slice(0, pos) + `\n${importLine}` + out.slice(pos);
  return { ok: true, text: out, changed: true };
}

/** The end of the line `pos` is on, so a trailing comment stays with its statement. */
const eol = (text: string, pos: number): number => {
  const i = text.indexOf('\n', pos);
  return i < 0 ? text.length : i;
};

/** The offset after a shebang and any `'use strict'` style directives (the import goes below them), or 0. */
function afterPrologue(text: string, sf: ts.SourceFile): number {
  let pos = 0;
  const m = /^#![^\n]*/.exec(text);
  if (m) pos = m[0].length;
  for (const s of sf.statements) {
    if (ts.isExpressionStatement(s) && ts.isStringLiteral(s.expression)) pos = s.end;
    else break;
  }
  return pos;
}
