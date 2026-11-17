#!/usr/bin/env node
import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { parseArgs } from 'node:util';
import { parseTrustedRoot } from '@atlasauth/pca-attest-eat';
import type { CiPolicy, Tier } from './attest';
import { makeBadge } from './badge';
import { bundledManifest, loadBundledCorpus, loadCorpusFiles, type LoadedCorpus } from './corpus';
import { registryAdd, registryExport, registryInit, renderRegistryMarkdown, renderRegistryPage, updateRegistryPage, verifyRegistryExport, type RegistryExport } from './registry';
import { formatSummary, runConformance, type Report } from './run';
import { createStatements, publicKeyB64u, verifyStatementEnvelope, type StatementEnvelope } from './statement';

import { runnerVersion } from './util';

export const USAGE = `pca-verified: prove that a PCA verifier or producer conforms

  pca-verified run --driver "<command>" [options]
      Drive the implementation behind <command> over the corpus. The command is run as
      "<command> <in.jsonl> <out.jsonl>" (or with {in} / {out} placeholders, or --io stdio).
      --profile P[,P]    core-verifier (default), producer, pq, stateful, or all
      --name N --impl-version V [--vendor X]   what the statement attests (required with --key / --generate-key)
      --out DIR          report.json, summary.txt and statements are written here (default ./pca-verified-out)
      --key FILE         Ed25519 private key (PKCS8 PEM) that signs the statements
      --generate-key     create a signing key in DIR/signing-key.pem and use it
      --io files|stdio   driver framing (default files)    --cwd DIR   --env K=V (repeatable)
      --timeout-ms N     per-item time budget (default 15000)
      --corpus FILE --corpus-manifest FILE   use another corpus (its manifest hash is the pin)
      --limit N          development only: run N items per profile; nothing can be attested
      exit 0 when every requested profile passes, 1 when one does not, 2 on a usage error

  pca-verified verify <statement.json> [--report report.json] [--trust-key FILE|B64U]... [--corpus FILE --corpus-manifest FILE]
      [--attestation bundle.json --ci-repo owner/name [--ci-workflow verified.yml] [--ci-ref refs/tags/v1] [--sigstore-root FILE]] [--require-tier ci-attested]
      Reports the trust tier: self-attested (signed by a key) or ci-attested (a GitHub Actions workflow of --ci-repo attested these exact bytes).
  pca-verified badge <statement.json> --out DIR [--trust-key ...]       writes badge.svg and badge.json (only for a statement that verifies)
  pca-verified corpus                                                  print the bundled corpus manifest
  pca-verified pubkey <private-key.pem>                                print the public key (the value to pin and publish)
  pca-verified registry init DIR
  pca-verified registry add DIR <statement.json> [--attestation bundle.json --ci-repo owner/name ...]
  pca-verified registry export DIR --out registry.json
  pca-verified registry verify registry.json --key REGISTRY_KEY [--previous old.json] [--ci-repo owner/name ...]
  pca-verified registry docs registry.json --key REGISTRY_KEY --page docs/verified.md [--ci-repo ...]   rewrite the generated block of a docs page
  pca-verified registry page registry.json --key REGISTRY_KEY --out DIR
`;

class Usage extends Error {}

const readJson = <T>(f: string): T => JSON.parse(readFileSync(f, 'utf8')) as T;
const keyArg = (s: string): string => {
  // a public key given as SPKI base64url, or as a PEM / DER file
  if (existsSync(s)) return publicKeyB64u(createPublicKey(readFileSync(s)));
  return s;
};

type CiArgs = { 'ci-repo'?: string; 'ci-workflow'?: string; 'ci-ref'?: string; 'sigstore-root'?: string };
const CI_OPTIONS = { 'ci-repo': { type: 'string' }, 'ci-workflow': { type: 'string' }, 'ci-ref': { type: 'string' }, 'sigstore-root': { type: 'string' } } as const;
function ciPolicy(v: CiArgs): CiPolicy | undefined {
  if (!v['ci-repo']) {
    if (v['ci-workflow'] || v['ci-ref'] || v['sigstore-root']) throw new Usage('--ci-workflow, --ci-ref and --sigstore-root need --ci-repo');
    return undefined;
  }
  return { repo: v['ci-repo'], ...(v['ci-workflow'] ? { workflow: v['ci-workflow'] } : {}), ...(v['ci-ref'] ? { ref: v['ci-ref'] } : {}), ...(v['sigstore-root'] ? { roots: parseTrustedRoot(readJson(v['sigstore-root'])) } : {}) };
}

function loadCorpus(v: { corpus?: string; 'corpus-manifest'?: string }): LoadedCorpus {
  if (v.corpus || v['corpus-manifest']) {
    if (!v.corpus || !v['corpus-manifest']) throw new Usage('--corpus and --corpus-manifest go together');
    return loadCorpusFiles(v.corpus, v['corpus-manifest']);
  }
  return loadBundledCorpus();
}

function verifyOpts(v: { 'trust-key'?: string[]; corpus?: string; 'corpus-manifest'?: string }) {
  const corpora = [bundledManifest()];
  if (v.corpus && v['corpus-manifest']) corpora.push(loadCorpusFiles(v.corpus, v['corpus-manifest']).manifest);
  return { corpora, ...(v['trust-key']?.length ? { trustKeys: v['trust-key'].map(keyArg) } : {}) };
}

export async function main(argv: string[], out: (s: string) => void = (s) => process.stdout.write(s + '\n')): Promise<number> {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') { out(USAGE); return cmd ? 0 : 2; }
  try {
    switch (cmd) {
      case 'run': return await cmdRun(rest, out);
      case 'verify': return cmdVerify(rest, out);
      case 'badge': return cmdBadge(rest, out);
      case 'corpus': out(JSON.stringify(bundledManifest(), null, 2)); return 0;
      case 'pubkey': {
        if (rest.length !== 1) throw new Usage('pubkey wants one private key file');
        out(publicKeyB64u(createPrivateKey(readFileSync(rest[0]!))));
        return 0;
      }
      case 'registry': return await cmdRegistry(rest, out);
      case '--version': out(runnerVersion()); return 0;
      default: throw new Usage(`unknown command: ${cmd}`);
    }
  } catch (e) {
    if (e instanceof Usage || /^ERR_PARSE_ARGS/.test(String((e as { code?: string }).code))) { out(`error: ${(e as Error).message}\n\n${USAGE}`); return 2; }
    out(`error: ${(e as Error).message}`);
    return 1;
  }
}

async function cmdRun(args: string[], out: (s: string) => void): Promise<number> {
  const { values: v } = parseArgs({
    args,
    options: {
      driver: { type: 'string' }, profile: { type: 'string', default: 'core-verifier' }, name: { type: 'string' }, 'impl-version': { type: 'string' }, vendor: { type: 'string' },
      out: { type: 'string', default: 'pca-verified-out' }, key: { type: 'string' }, 'generate-key': { type: 'boolean' }, io: { type: 'string', default: 'files' }, cwd: { type: 'string' },
      env: { type: 'string', multiple: true }, 'timeout-ms': { type: 'string' }, corpus: { type: 'string' }, 'corpus-manifest': { type: 'string' }, limit: { type: 'string' },
    },
  });
  if (!v.driver) throw new Usage('--driver is required');
  if (v.io !== 'files' && v.io !== 'stdio') throw new Usage('--io is files or stdio');
  const corpus = loadCorpus(v);
  const profiles = v.profile === 'all' ? Object.keys(corpus.manifest.profiles) : v.profile!.split(',').filter(Boolean);
  for (const p of profiles) if (!corpus.manifest.profiles[p]) throw new Usage(`unknown profile ${p} (have: ${Object.keys(corpus.manifest.profiles).join(', ')})`);
  const signing = Boolean(v.key || v['generate-key']);
  if (signing && (!v.name || !v['impl-version'])) throw new Usage('--name and --impl-version are required to sign a statement');
  const env: Record<string, string> = {};
  for (const kv of v.env ?? []) { const i = kv.indexOf('='); if (i < 1) throw new Usage('--env wants K=V'); env[kv.slice(0, i)] = kv.slice(i + 1); }
  const limit = v.limit === undefined ? undefined : Number(v.limit);
  if (limit !== undefined && (!Number.isSafeInteger(limit) || limit < 1)) throw new Usage('--limit is a positive integer');
  const timeout = v['timeout-ms'] === undefined ? undefined : Number(v['timeout-ms']);
  if (timeout !== undefined && (!Number.isSafeInteger(timeout) || timeout < 1)) throw new Usage('--timeout-ms is a positive integer');

  const report = await runConformance({
    corpus, profiles, ...(limit !== undefined ? { limit } : {}),
    implementation: { name: v.name ?? 'unnamed', version: v['impl-version'] ?? '0', ...(v.vendor ? { vendor: v.vendor } : {}) },
    driver: { command: v.driver, io: v.io, ...(v.cwd ? { cwd: v.cwd } : {}), env, ...(timeout !== undefined ? { caseTimeoutMs: timeout } : {}) },
    log: (l) => out(`  ${l}`),
  });
  const dir = v.out!;
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'report.json'), JSON.stringify(report, null, 1) + '\n');
  const summary = formatSummary(report);
  writeFileSync(join(dir, 'summary.txt'), summary + '\n');
  out(summary);
  if (signing) {
    let key: KeyObject;
    if (v['generate-key']) {
      const kp = join(dir, 'signing-key.pem');
      if (existsSync(kp)) throw new Usage(`${kp} exists: pass it with --key instead of --generate-key`);
      const { privateKey } = generateKeyPairSync('ed25519');
      writeFileSync(kp, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
      key = privateKey;
      out(`signing key written to ${kp} (keep it: it is the identity of these statements)`);
    } else key = createPrivateKey(readFileSync(v.key!));
    const stmts = createStatements(report, { key, issuer: v.vendor ?? v.name! });
    out(`signer public key (publish and pin this): ${publicKeyB64u(key)}`);
    for (const s of stmts) {
      const f = join(dir, `${s.payload.profile}.statement.json`);
      writeFileSync(f, JSON.stringify(s, null, 1) + '\n');
      writeFileSync(join(dir, `${s.payload.profile}.statement.cose`), Buffer.from(s.statement, 'base64url')); // the exact bytes a CI attestation covers
      out(`statement: ${f}`);
    }
    if (!stmts.length) out('no statement issued: no profile passed in full');
  }
  return profiles.every((p) => report.profiles[p]?.status === 'pass') ? 0 : 1;
}

function cmdVerify(args: string[], out: (s: string) => void): number {
  const { values: v, positionals } = parseArgs({ args, allowPositionals: true, options: { report: { type: 'string' }, 'trust-key': { type: 'string', multiple: true }, corpus: { type: 'string' }, 'corpus-manifest': { type: 'string' }, attestation: { type: 'string' }, 'require-tier': { type: 'string' }, ...CI_OPTIONS } });
  if (positionals.length !== 1) throw new Usage('verify wants one statement file');
  const policy = ciPolicy(v);
  if (v.attestation && !policy) throw new Usage('--attestation needs --ci-repo');
  if (v['require-tier'] !== undefined && v['require-tier'] !== 'ci-attested' && v['require-tier'] !== 'self-attested') throw new Usage('--require-tier is ci-attested or self-attested');
  const opts = verifyOpts(v);
  const report = v.report ? readJson<Report>(v.report) : undefined;
  const r = verifyStatementEnvelope(readJson<StatementEnvelope>(positionals[0]!), { ...opts, ...(report ? { report } : {}), ...(v.attestation && policy ? { attestation: { bundle: readJson<unknown>(v.attestation), policy } } : {}), ...(v['require-tier'] === 'ci-attested' ? { requireTier: 'ci-attested' as Tier } : {}), ...(v.corpus && v['corpus-manifest'] && report ? { reportCorpus: loadCorpus(v) } : {}) });
  if (r.ok && r.payload) {
    const p = r.payload;
    out(`VERIFIED  ${p.implementation.name} ${p.implementation.version}  profile ${p.profile}  corpus ${p.corpus.version}  ${p.summary.passed}/${p.summary.total}`);
    out(`tier: ${r.tier ?? 'self-attested'}` + (r.attestation ? `  (${r.attestation.identity}${r.attestation.ref ? ' on ' + r.attestation.ref : ''}, rekor #${r.attestation.rekor_log_index})` : '  (signed by a key; no CI attestation)'));
    out(`signer ${p.signer_key}${v['trust-key']?.length ? ' (trusted)' : ' (NOT pinned: anyone can sign a statement; pin the signer with --trust-key)'}`);
    return 0;
  }
  out('NOT VERIFIED');
  for (const x of r.reasons) out(`  - ${x}`);
  return 1;
}

function cmdBadge(args: string[], out: (s: string) => void): number {
  const { values: v, positionals } = parseArgs({ args, allowPositionals: true, options: { out: { type: 'string' }, 'trust-key': { type: 'string', multiple: true }, corpus: { type: 'string' }, 'corpus-manifest': { type: 'string' } } });
  if (positionals.length !== 1 || !v.out) throw new Usage('badge wants one statement file and --out DIR');
  const b = makeBadge(readJson<StatementEnvelope>(positionals[0]!), verifyOpts(v));
  mkdirSync(v.out, { recursive: true });
  writeFileSync(join(v.out, 'badge.svg'), b.svg);
  writeFileSync(join(v.out, 'badge.json'), JSON.stringify(b.endpoint) + '\n');
  out(`wrote ${join(v.out, 'badge.svg')} and ${join(v.out, 'badge.json')}`);
  return 0;
}

async function cmdRegistry(args: string[], out: (s: string) => void): Promise<number> {
  const [sub, ...rest] = args;
  const { values: v, positionals } = parseArgs({ args: rest, allowPositionals: true, options: { out: { type: 'string' }, key: { type: 'string' }, previous: { type: 'string' }, page: { type: 'string' }, attestation: { type: 'string' }, ...CI_OPTIONS } });
  const ci = ciPolicy(v);
  switch (sub) {
    case 'init': {
      if (positionals.length !== 1) throw new Usage('registry init DIR');
      out(`registry key (pin this): ${registryInit(positionals[0]!).registryKey}`);
      return 0;
    }
    case 'add': {
      if (positionals.length !== 2) throw new Usage('registry add DIR STATEMENT');
      const r = await registryAdd(positionals[0]!, readJson<StatementEnvelope>(positionals[1]!), { ...(v.attestation ? { attestationBundle: readJson<unknown>(v.attestation) } : {}), ...(ci ? { ci } : {}) });
      out(`registered at index ${r.index} (${r.tier}), log root ${r.root}`);
      return 0;
    }
    case 'export': {
      if (positionals.length !== 1 || !v.out) throw new Usage('registry export DIR --out FILE');
      mkdirSync(dirname(v.out), { recursive: true });
      writeFileSync(v.out, JSON.stringify(await registryExport(positionals[0]!), null, 1) + '\n');
      out(`wrote ${v.out}`);
      return 0;
    }
    case 'verify': {
      if (positionals.length !== 1 || !v.key) throw new Usage('registry verify FILE --key REGISTRY_KEY');
      const r = verifyRegistryExport(readJson<RegistryExport>(positionals[0]!), { registryKey: keyArg(v.key), ...(ci ? { ci } : {}), ...(v.previous ? { previous: readJson<RegistryExport>(v.previous) } : {}) });
      out(r.ok ? `registry verified: ${r.verified.length} statement(s), ${r.verified.filter((x) => x.tier === 'ci-attested').length} CI-attested` : 'registry NOT verified');
      for (const x of r.reasons) out(`  - ${x}`);
      return r.ok ? 0 : 1;
    }
    case 'page': {
      if (positionals.length !== 1 || !v.key || !v.out) throw new Usage('registry page FILE --key REGISTRY_KEY --out DIR');
      const page = renderRegistryPage(readJson<RegistryExport>(positionals[0]!), { registryKey: keyArg(v.key), ...(ci ? { ci } : {}) });
      for (const [rel, body] of Object.entries(page.files)) {
        const f = join(v.out, rel);
        mkdirSync(dirname(f), { recursive: true });
        writeFileSync(f, body);
      }
      out(`wrote ${Object.keys(page.files).length} file(s) under ${v.out}`);
      return 0;
    }
    case 'docs': {
      if (positionals.length !== 1 || !v.key || !v.page) throw new Usage('registry docs FILE --key REGISTRY_KEY --page FILE');
      const listing = renderRegistryMarkdown(readJson<RegistryExport>(positionals[0]!), { registryKey: keyArg(v.key), ...(ci ? { ci } : {}) });
      writeFileSync(v.page, updateRegistryPage(readFileSync(v.page, 'utf8'), listing));
      out(`updated ${v.page}`);
      return 0;
    }
    default: throw new Usage('registry init | add | export | verify | page | docs');
  }
}

if (require.main === module) void main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
