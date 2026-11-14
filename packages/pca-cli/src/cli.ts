#!/usr/bin/env node
/**
 * `pca` — the PCA developer CLI entrypoint.
 *
 * A tiny, dependency-free argv parser dispatches to the pure command functions in `./index`. Input
 * that is a PCActn / JSON is read from a file path argument, or from STDIN when the argument is `-`.
 * Errors print to stderr and set a non-zero `process.exitCode` (we never call `process.exit`, so
 * buffered stdout always flushes first).
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import { cmdDecode, cmdDiscovery, cmdExplain, cmdKeygen, cmdSimulate } from './index';
import { cmdBuild, cmdConfirm, packText, cmdImportModel, cmdDiff, cmdActionExplain, cmdImport, cmdInit, cmdLint, cmdPublish, cmdSign, cmdSync, cmdTest, writeRulesReviews } from './actions';
import { cmdSchemaConform, cmdSchemaInit, cmdSchemaPublish, cmdSchemaSign, cmdSchemaVerify } from './schema';

const USAGE = `pca — Proof-Carrying Authority dev CLI

Usage:
  pca decode <file|->                 Summarize a PCActn (JSON or base64url).
  pca explain <file|-> [--aud <id>]   Run the real verifier and explain each check (PASS/FAIL/—).
  pca keygen                          Mint a throwaway Ed25519 dev keypair (base64url).
  pca simulate <policy.json> <actions.json>
                                      Replay actions against a compiled policy (auto/step_up/deny).
  pca discovery --aud <id> [--suites a,b] [--stepup <url>] [--revocation <url>] [--beacon <url>] [--attest <url>]
                                      Emit a .well-known/pca-configuration document.
  pca actions init [--ns N] [--template minimal|saas|db|mcp|ecommerce|fintech|healthcare|saas_admin|devtools] [--dir actions] [--force]
                                      Scaffold actions/<ns>.yaml and actions/pca.config.json (the business-type
                                      templates add custom traits and business rules; all unreviewed).
  pca actions confirm <verb>... | --origin union [--trait T] | --pack NAME|DIR --origin any [--packs-dir D] [--file F] --kid ID [--reviewer-key K --yes] [--final t1,t2] [--dismiss trait=reason;;...]
  pca actions import <file|-> --from mcp|openapi|graphql|grpc|asyncapi|jsonschema --ns N [--suggest rules|none|model [--model ID] [--provider anthropic|openai]] [--verb V] [--uri U] [--licence L] [--out file]
                                      Draft actions (all unreviewed) from a tool list, an OpenAPI 3 document or a JSON Schema.
  pca actions lint [paths...] [--strict] [--format text|sarif]
                                      24 rules, plus LP-001 (pinned builder identity) and LT-000/LT-001 (trace rules,
                                      lethal trifecta); exit 1 on an error (on a warning too with --strict).
  pca actions test [paths...]         Run each action's examples and the generic property checks.
  pca actions explain <verb> [paths...]
                                      The policy card, effective profile and what a grant must carry.
  pca actions diff <old> <new>        Semantic diff per action: equal | narrow | widen | incomparable | added | removed.
  pca actions build [paths...] [--out .pca]
                                      Emit schema.json, pack.json, cards.json, ontology.json, mcp.json, types.d.ts.
  pca actions sign --kid K --key <b64u-secret|@file> [--pack-kid K --pack-key ...] [paths...] [--out .pca]
                                      Sign the built schema (site key) and pack (registry key).
  pca actions publish [paths...] [--out .pca] [--api <https://instance> [--sk <sk_...> | env ATLAS_SECRET_KEY]]
                                      Write .well-known/pca-actions.json; with --api anchor it in an Atlas instance and
                                      publish the signed pack, its business rules and custom traits to the instance's
                                      action registry (refused when it widens an action without a reviewer's signature).
  pca actions sync [paths...] [--source NAME] [--check]
                                      Re-import the sources named in pca.config.json and show the semantic diff: added and
                                      changed actions land unreviewed, removed ones are deprecated at the next publish.
                                      --check writes nothing and fails when a source changed (for CI).
  (default paths: actions)

Legacy (deprecated, removed next release; use pca actions):
  pca schema init --from openapi|mcp <file|-> --site <url> --aud <id> --version <v> [--prefix <verb.>]
                                      Draft an action schema (decisions to make go to stderr).
  pca schema sign <draft.json> --kid <kid> --key <b64u-secret|@file>
                                      Sign it as the site (stdout: /.well-known/pca-actions.json; stderr: the key entry).
  pca schema verify <schema.json> <keys.json|discovery.json>
  pca schema conform <schema.json> <verb> <params.json>
                                      Closed-world check of one action (DENY = schema_violation).
  pca schema publish <schema.json> <keys.json> --api <https://instance> --sk <sk_...>
                                      Anchor it in an Atlas instance's intent transparency log.

Notes:
  <-> reads from STDIN. Nothing here authorizes anything — the resource server's verifier decides.
`;

/** Read a positional file argument, or STDIN when it is '-'. */
function readSource(arg: string): string {
  if (arg === '-') return readFileSync(0, 'utf8');
  return readFileSync(arg, 'utf8');
}

interface ParsedArgs {
  positionals: string[];
  flags: Record<string, string>;
}

/**
 * Minimal hand-rolled parser (no dependency): everything after the sub-command, splitting
 * `--flag value` and `--flag=value` out of the positionals. A bare `--flag` with no value is treated
 * as the empty string.
 */
const BOOL_FLAGS = new Set(['strict', 'force', 'check']);

function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === undefined) continue;
    if (a.startsWith('--')) {
      const body = a.slice(2);
      const eq = body.indexOf('=');
      if (eq >= 0) {
        flags[body.slice(0, eq)] = body.slice(eq + 1);
      } else {
        const next = argv[i + 1];
        if (!BOOL_FLAGS.has(body) && next !== undefined && !next.startsWith('--')) {
          flags[body] = next;
          i++;
        } else {
          flags[body] = '';
        }
      }
    } else {
      positionals.push(a);
    }
  }
  return { positionals, flags };
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const command = argv[0];

  if (command === undefined || command === '--help' || command === '-h' || command === 'help') {
    process.stdout.write(USAGE);
    return;
  }

  const { positionals, flags } = parseArgs(argv.slice(1));

  switch (command) {
    case 'decode': {
      const src = positionals[0];
      if (src === undefined) throw new Error("decode: expected a file path or '-' for STDIN");
      process.stdout.write(cmdDecode(readSource(src)) + '\n');
      return;
    }
    case 'explain': {
      const src = positionals[0];
      if (src === undefined) throw new Error("explain: expected a file path or '-' for STDIN");
      const opts: { audience?: string } = {};
      if (flags.aud !== undefined && flags.aud !== '') opts.audience = flags.aud;
      const res = await cmdExplain(readSource(src), opts);
      process.stdout.write(res.text + '\n');
      if (!res.allow) process.exitCode = 1;
      return;
    }
    case 'keygen': {
      process.stdout.write(cmdKeygen().text + '\n');
      return;
    }
    case 'simulate': {
      const policyPath = positionals[0];
      const actionsPath = positionals[1];
      if (policyPath === undefined || actionsPath === undefined) {
        throw new Error('simulate: expected <policy.json> <actions.json>');
      }
      process.stdout.write(cmdSimulate(readSource(policyPath), readSource(actionsPath)) + '\n');
      return;
    }
    case 'discovery': {
      if (flags.aud === undefined || flags.aud === '') throw new Error('discovery: --aud <id> is required');
      const endpoints: { attestation_challenge?: string; revocation_epoch?: string; liveness_beacon?: string; stepup?: string } = {};
      if (flags.attest) endpoints.attestation_challenge = flags.attest;
      if (flags.revocation) endpoints.revocation_epoch = flags.revocation;
      if (flags.beacon) endpoints.liveness_beacon = flags.beacon;
      if (flags.stepup) endpoints.stepup = flags.stepup;
      process.stdout.write(
        cmdDiscovery({
          audience: flags.aud,
          ...(flags.suites ? { suites: flags.suites.split(',').map((s) => s.trim()).filter(Boolean) } : {}),
          ...(Object.keys(endpoints).length ? { endpoints } : {}),
        }) + '\n',
      );
      break;
    }
    case 'actions': {
      const sub = positionals[0];
      const rest = positionals.slice(1);
      const dflt = (xs: string[]): string[] => (xs.length > 0 ? xs : ['actions']);
      const done = (r: { ok: boolean; text: string }): void => {
        process.stdout.write(r.text + '\n');
        if (!r.ok) process.exitCode = 1;
      };
      switch (sub) {
        case 'init': {
          const dir = flags.dir || 'actions';
          done(cmdInit({ dir, ns: flags.ns || 'acme', ...(flags.template ? { template: flags.template } : {}), force: 'force' in flags }));
          return;
        }
        case 'import': {
          if (rest[0] === undefined || !flags.from || !flags.ns) throw new Error('actions import: <file|-> --from --ns are required');
          const impOpts = { from: flags.from!, ns: flags.ns!, ...(flags.uri ? { uri: flags.uri } : {}), ...(flags.licence ? { licence: flags.licence } : {}), ...(flags.verb ? { verb: flags.verb } : {}), ...(flags.suggest ? { suggest: flags.suggest } : {}) };
          const src = readSource(rest[0]);
          const r = flags.suggest === 'model'
            ? await cmdImportModel(src, { ...impOpts, suggest: 'rules', ...(flags.model ? { model: flags.model } : {}), ...(flags.provider ? { provider: flags.provider } : {}) }, process.env, (u, i) => fetch(u, i) as never)
            : cmdImport(src, impOpts);
          if (!r.ok) { done(r); return; }
          if (flags.out) writeFileSync(flags.out, r.yaml);
          else process.stdout.write(r.yaml);
          for (const t of r.todo) process.stderr.write(`todo: ${t}\n`);
          process.stderr.write(r.text + '\n');
          return;
        }
        case 'review': // alias: `pca actions review --origin union --trait T` is the batch form of confirm
        case 'confirm': {
          if (rest.length === 0 && flags.origin === undefined) throw new Error('actions confirm: <verb>... or --origin union|any is required');
          const file = flags.file ?? 'actions.yaml';
          let source: string;
          if (flags.pack !== undefined) {
            if (flags.origin !== 'any' && rest.length === 0) throw new Error('actions confirm --pack: pass --origin any (every def of the pack) or the verbs to review');
            const p = packText(flags.pack, flags['packs-dir'] ?? 'packs');
            if (!p.ok) throw new Error(p.text);
            source = p.text;
          } else source = readFileSync(file, 'utf8');
          const r = cmdConfirm(source, { verbs: rest, kid: flags.kid ?? '', ...(flags['reviewer-key'] ? { secret: flags['reviewer-key'] } : {}), ...(flags.final ? { final: flags.final.split(',').filter(Boolean) } : {}), dismiss: flags.dismiss ? flags.dismiss.split(';;') : [], yes: 'yes' in flags, ts: Math.floor(Date.now() / 1000), ...(flags.origin ? { origin: flags.origin } : {}), ...(flags.trait ? { trait: flags.trait } : {}) });
          if (r.ok && r.yaml) writeFileSync(flags.out ?? (flags.pack !== undefined ? `${flags.pack.replace(/[^A-Za-z0-9._-]/g, '_')}.reviewed.yaml` : file), r.yaml);
          // the reviewer's signatures over the confirmed actions' business rules, next to the reviewed file (build reads them)
          if (r.ok && r.rulesReviews && Object.keys(r.rulesReviews).length > 0) writeRulesReviews(dirname(flags.out ?? file), r.rulesReviews);
          done({ ok: r.ok, text: r.text });
          return;
        }
        case 'lint': done(cmdLint(dflt(rest), { strict: 'strict' in flags, format: flags.format === 'sarif' ? 'sarif' : 'text' })); return;
        case 'test': done(cmdTest(dflt(rest))); return;
        case 'explain': {
          if (rest[0] === undefined) throw new Error('actions explain: <verb> is required');
          done(cmdActionExplain(dflt(rest.slice(1)), rest[0]));
          return;
        }
        case 'diff': {
          if (rest.length !== 2) throw new Error('actions diff: <old> <new> are required');
          done(cmdDiff([rest[0]!], [rest[1]!]));
          return;
        }
        case 'build': done(cmdBuild(dflt(rest), flags.out ? { out: flags.out } : {})); return;
        case 'sign': {
          if (!flags.kid || !flags.key) throw new Error('actions sign: --kid and --key are required');
          done(cmdSign(dflt(rest), { kid: flags.kid!, key: flags.key!, ...(flags.out ? { out: flags.out } : {}), ...(flags['pack-kid'] ? { packKid: flags['pack-kid'] } : {}), ...(flags['pack-key'] ? { packKey: flags['pack-key'] } : {}) }));
          return;
        }
        case 'publish': {
          // the secret key may come from ATLAS_SECRET_KEY instead of the command line (CI)
          const sk = flags.sk ?? (flags.api ? process.env.ATLAS_SECRET_KEY : undefined);
          done(await cmdPublish(dflt(rest), { ...(flags.out ? { out: flags.out } : {}), ...(flags.api ? { api: flags.api } : {}), ...(sk ? { sk } : {}) }));
          return;
        }
        case 'sync': done(await cmdSync(dflt(rest), { ...(flags.source ? { source: flags.source } : {}), check: 'check' in flags })); return;
        default: throw new Error(`actions: unknown sub-command '${String(sub)}'\n\n${USAGE}`);
      }
    }
    case 'schema': {
      process.stderr.write('pca schema is deprecated and will be removed in the next release; use pca actions (import, sign, publish)\n');
      const sub = positionals[0];
      const a = positionals.slice(1);
      if (sub === 'init') {
        const src = a[0];
        if (src === undefined || (flags.from !== 'openapi' && flags.from !== 'mcp') || !flags.site || !flags.aud || !flags.version) {
          throw new Error('schema init: --from openapi|mcp <file|-> --site --aud --version are required');
        }
        const r = cmdSchemaInit(readSource(src), { from: flags.from as 'openapi' | 'mcp', site: flags.site!, aud: flags.aud!, version: flags.version!, ...(flags.prefix ? { verbPrefix: flags.prefix } : {}) });
        process.stdout.write(r.schema + '\n');
        for (const t of r.todo) process.stderr.write(`decide: ${t}\n`);
        return;
      }
      if (sub === 'sign') {
        if (a[0] === undefined || !flags.kid || !flags.key) throw new Error('schema sign: <draft.json> --kid --key are required');
        const key = flags.key!;
        const secret = key.startsWith('@') ? readFileSync(key.slice(1), 'utf8') : key;
        const r = cmdSchemaSign(readSource(a[0]!), { kid: flags.kid!, secret });
        process.stdout.write(r.schema + '\n');
        process.stderr.write(`digest ${r.digest}\nintent.schema_keys entry: ${JSON.stringify(r.key)}\n`);
        return;
      }
      if (sub === 'verify' || sub === 'conform') {
        const r = sub === 'verify' ? (a.length === 2 ? cmdSchemaVerify(readSource(a[0]!), readSource(a[1]!)) : null) : a.length === 3 ? cmdSchemaConform(readSource(a[0]!), a[1]!, readSource(a[2]!)) : null;
        if (!r) throw new Error(`schema ${sub}: wrong arguments\n\n${USAGE}`);
        process.stdout.write(r.text + '\n');
        if (!r.ok) process.exitCode = 1;
        return;
      }
      if (sub === 'publish') {
        if (a.length !== 2 || !flags.api || !flags.sk) throw new Error('schema publish: <schema.json> <keys.json> --api --sk are required');
        const r = await cmdSchemaPublish(readSource(a[0]!), readSource(a[1]!), { api: flags.api!, secretKey: flags.sk! });
        process.stdout.write(r.text + '\n');
        if (!r.ok) process.exitCode = 1;
        return;
      }
      throw new Error(`schema: unknown sub-command '${String(sub)}'\n\n${USAGE}`);
    }
    default:
      throw new Error(`unknown command '${command}'\n\n${USAGE}`);
  }
}

main().catch((e: unknown) => {
  process.stderr.write(`pca: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exitCode = 1;
});
