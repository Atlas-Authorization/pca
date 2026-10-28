// registry.ts - the importer registry the `pca actions import` command reads (`IMPORTERS`). Each entry has the CLI shape
// `(document, {ns, uri?, licence?, verb?}) -> {defs, todo: string[]}` and delegates to the importers in this folder, so every
// source kind (including GraphQL, gRPC, AsyncAPI) is reachable from the CLI and every def comes out `unreviewed`.

import { stringify } from 'yaml';
import type { ActionDef } from '../def';
import type { ImportKind, ImportReport, Todo } from './common';
import { importAsyncApi } from './asyncapi';
import { importGraphql } from './graphql';
import { importGrpc } from './grpc';
import { importJsonSchema } from './jsonschema';
import { importMcp } from './mcp';
import { importOpenApi } from './openapi';

export interface ImportOptions {
  ns: string;
  uri?: string;
  licence?: string;
  /** Required by the JSON Schema importer. */
  verb?: string;
}
export interface ImportResult { defs: ActionDef[]; todo: string[] }
export type Importer = (doc: unknown, opts: ImportOptions) => ImportResult;

/** Kept for callers of the first importer: the default operation bound. */
export const MAX_IMPORT_OPS = 20_000;

const todoText = (t: Todo): string => `${t.where}: ${t.message}`;
const adapt = (f: (doc: unknown, o: ImportOptions) => ImportReport): Importer => (doc, o) => {
  const r = f(doc, o);
  return { defs: r.defs, todo: r.todo.map(todoText) };
};

export const IMPORTERS: Record<string, Importer> & Record<ImportKind, Importer> = {
  mcp: adapt((d, o) => importMcp(d, o)),
  openapi: adapt((d, o) => importOpenApi(d, o)),
  graphql: adapt((d, o) => importGraphql(d, o)),
  grpc: adapt((d, o) => importGrpc(d, o)),
  asyncapi: adapt((d, o) => importAsyncApi(d, o)),
  jsonschema: adapt((d, o) => {
    if (!o.verb) throw new Error('a JSON Schema import needs --verb <ns.noun.action>');
    return importJsonSchema(d, { ...o, verb: o.verb });
  }),
};

/** The YAML an `import` writes: full-form defs (taken as written by the loader). */
export const defsToYaml = (ns: string, defs: readonly ActionDef[]): string => stringify({ ns, actions: defs });
