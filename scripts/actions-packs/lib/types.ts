// types.ts - the shapes shared by the importers, the classifier and the pack writer.
import type { ActionDef, Effect, Rev } from '@atlasauth/pca-actions';

export type RawType = 'string' | 'integer' | 'boolean' | 'array' | 'object';

export interface RawParam {
  name: string;
  where: 'path' | 'query' | 'header' | 'body' | 'arg';
  required: boolean;
  type: RawType;
  format?: string;
  values?: string[];
  min?: number;
  max?: number;
  maxLength?: number;
  items?: 'string' | 'integer' | 'boolean' | 'object';
  maxItems?: number;
  desc?: string;
}

/** One operation of a source API, in the shape every importer produces. */
export interface RawOp {
  /** Verb segments after the namespace (already snake_case, a-z0-9_). The last is the action. */
  path: string[];
  method?: string;
  httpPath?: string;
  opId?: string;
  summary: string;
  desc: string;
  tags: string[];
  params: RawParam[];
  deprecated?: boolean;
  /** GraphQL / RPC style kind when there is no HTTP method. */
  kind?: 'query' | 'mutation' | 'subscription';
  /** The importer knows this op only reads (a discovery GET, a botocore Describe*). */
  bindings?: ActionDef['bindings'];
}

export interface Verdict {
  effects: Effect[];
  rev: Rev;
  scope: 'one' | 'set';
  traits: string[];
  /** Name of the param that carries the recipient(s) when they are inside an opaque payload (Gmail's raw message). */
  recipient?: string;
  /** True when the classification rests on an unambiguous rule; false leaves the def `unreviewed`. */
  sure: boolean;
  why: string;
  /** Effects added by the noun/parameter inference (lib/infer.ts); `send`/`export`/`pay` among them may need a parameter the op lacks. */
  inferred?: Effect[];
  /** An inference that can break a required parameter rule applied (or would have applied, in the fallback pass). */
  soft?: boolean;
}

export interface SourceDecl {
  /** Short id of the source file inside the pack, e.g. `api` or `gmail-v1`. */
  id: string;
  /** GitHub raw source: repo + commit + path; or a plain url. */
  repo?: string;
  ref?: string;
  path?: string;
  url?: string;
  /** sha256 (hex) of the downloaded bytes. Empty until `pin`. */
  sha256: string;
  bytes?: number;
  kind: 'openapi' | 'discovery' | 'botocore' | 'graphql' | 'table';
  gz?: boolean;
  licence: string;
  licence_url?: string;
  /** Free-form per-source options the pack's importer reads (service name, version, prefix, ...). */
  opts?: Record<string, string>;
}

export interface PackSource {
  pack: string;
  sources: SourceDecl[];
}
