// factory.ts - the common shape of an OpenAPI-sourced pack.
import { buildAll, type PackDef } from './pack';
import type { BuildOpts } from './build';
import { importBotocore, type BotocoreOpts } from './botocore';
import { importDiscovery, type DiscoveryOpts } from './discovery';
import { importGraphql, type GraphqlOpts } from './graphql';
import { importOpenApi, type OpenApiOpts } from './openapi';
import { readSources } from './source';
import type { RawOp } from './types';

export interface OpenApiPackCfg {
  name: string;
  /** Default namespace (first verb segment) for the pack's sources. */
  ns: string;
  redistribution: PackDef['redistribution'];
  licence_notes: string;
  config_file: string;
  version?: string;
  /** Per-source importer options (by source id). */
  oa: (srcId: string) => OpenApiOpts;
  /** Per-source namespace override. */
  nsOf?: (srcId: string) => string;
  build: (srcId: string) => BuildOpts;
  /** Post-filter / transform of the imported ops. */
  ops?: (srcId: string, ops: RawOp[]) => RawOp[];
}

export function openApiPack(c: OpenApiPackCfg): PackDef {
  const sources = readSources(c.name);
  return {
    name: c.name, version: c.version ?? '0.5.0', redistribution: c.redistribution, licence_notes: c.licence_notes, config_file: c.config_file, sources,
    generate(load) {
      const used = new Set<string>();
      return sources.flatMap((s) => {
        let ops = importOpenApi(load(s.id) as Record<string, unknown>, c.oa(s.id));
        if (c.ops) ops = c.ops(s.id, ops);
        return buildAll(c.nsOf?.(s.id) ?? c.ns, ops, { ...c.build(s.id), pack: c.name }, used);
      });
    },
  };
}

export interface DiscoveryPackCfg extends Omit<OpenApiPackCfg, 'oa'> {
  disc: (srcId: string) => DiscoveryOpts;
}

export function discoveryPack(c: DiscoveryPackCfg): PackDef {
  const sources = readSources(c.name);
  return {
    name: c.name, version: c.version ?? '0.5.0', redistribution: c.redistribution, licence_notes: c.licence_notes, config_file: c.config_file, sources,
    generate(load) {
      const used = new Set<string>();
      return sources.flatMap((s) => {
        let ops = importDiscovery(load(s.id) as Record<string, unknown>, c.disc(s.id));
        if (c.ops) ops = c.ops(s.id, ops);
        return buildAll(c.nsOf?.(s.id) ?? c.ns, ops, { ...c.build(s.id), pack: c.name }, used);
      });
    },
  };
}

export interface BotocorePackCfg extends Omit<OpenApiPackCfg, 'oa'> {
  bc: (srcId: string) => BotocoreOpts;
}

export function botocorePack(c: BotocorePackCfg): PackDef {
  const sources = readSources(c.name);
  return {
    name: c.name, version: c.version ?? '0.5.0', redistribution: c.redistribution, licence_notes: c.licence_notes, config_file: c.config_file, sources,
    generate(load) {
      const used = new Set<string>();
      return sources.flatMap((s) => {
        let ops = importBotocore(load(s.id) as Record<string, unknown>, c.bc(s.id));
        if (c.ops) ops = c.ops(s.id, ops);
        return buildAll(c.nsOf?.(s.id) ?? c.ns, ops, { ...c.build(s.id), pack: c.name }, used);
      });
    },
  };
}

export interface GraphqlPackCfg extends Omit<OpenApiPackCfg, 'oa'> {
  gql: (srcId: string) => GraphqlOpts;
}

export function graphqlPack(c: GraphqlPackCfg): PackDef {
  const sources = readSources(c.name);
  return {
    name: c.name, version: c.version ?? '0.5.0', redistribution: c.redistribution, licence_notes: c.licence_notes, config_file: c.config_file, sources,
    generate(load) {
      const used = new Set<string>();
      return sources.flatMap((s) => {
        let ops = importGraphql(load(s.id) as string, c.gql(s.id));
        if (c.ops) ops = c.ops(s.id, ops);
        return buildAll(c.nsOf?.(s.id) ?? c.ns, ops, { ...c.build(s.id), pack: c.name }, used);
      });
    },
  };
}
