import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DurableTransparencyService, FileScittLogStore, statementPayload, verifyReceipt } from '@atlasauth/pca-scitt';
import { makeBadge } from './badge';
import type { CiAttestation, CiPolicy, Tier } from './attest';
import { keyFingerprint, publicKeyB64u, STATEMENT_FORMAT, verifyStatementEnvelope, type StatementEnvelope, type StatementPayload, type VerifyStatementOptions } from './statement';
import { b64u, fromB64u } from './util';

export const REGISTRY_FORMAT = 'pca-verified-registry/1';

export interface RegistryEntry {
  index: number;
  /** COSE Signed Statement, base64url: the exact log leaf. */
  statement: string;
  /** COSE receipt (RFC 9942 inclusion proof against `head.root`), base64url. */
  receipt: string;
  /** The Sigstore build-provenance bundle that makes this entry CI-attested (not part of the log leaf; checked against the statement bytes). */
  attestation?: unknown;
}

export interface RegistryExport {
  format: typeof REGISTRY_FORMAT;
  /** The transparency service key (SPKI base64url). Pin it out of band: this copy is only for convenience. */
  registry_key: string;
  head: { size: number; root: string };
  entries: RegistryEntry[];
}

const LOG = 'log.bin';
const KEY = 'registry-key.pem';

/** Create a registry directory with its own signing key (the transparency service key). */
export function registryInit(dir: string): { registryKey: string } {
  mkdirSync(dir, { recursive: true });
  const kp = join(dir, KEY);
  if (existsSync(kp)) throw new Error('registry already initialised');
  const { privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(kp, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  FileScittLogStore.open(join(dir, LOG));
  return { registryKey: publicKeyB64u(privateKey) };
}

function open(dir: string): { svc: DurableTransparencyService; key: KeyObject } {
  const key = createPrivateKey(readFileSync(join(dir, KEY)));
  const svc = new DurableTransparencyService({ store: FileScittLogStore.open(join(dir, LOG)), alg: 'EdDSA', key, issuer: 'pca-verified-registry' });
  return { svc, key };
}

/** The envelope for a COSE statement found in the log (its payload is decoded from the signed bytes, never taken on trust). */
export function envelopeOf(cose: Uint8Array): StatementEnvelope {
  const payload = JSON.parse(Buffer.from(statementPayload(cose)).toString('utf8')) as StatementPayload;
  return { format: STATEMENT_FORMAT, statement: b64u(cose), public_key: payload.signer_key, payload };
}

/** Append a statement that verifies. A statement that does not verify, or is already in the log, is refused and nothing is written. */
export interface RegistryAddOptions extends VerifyStatementOptions {
  /** A CI attestation bundle for the statement, and the policy it must meet. An attestation that does not verify refuses the add. */
  attestationBundle?: unknown;
  ci?: CiPolicy;
}

export async function registryAdd(dir: string, env: StatementEnvelope, ro: RegistryAddOptions = {}): Promise<{ index: number; root: string; tier: Tier }> {
  const { attestationBundle, ci, ...base } = ro;
  if (attestationBundle !== undefined && !ci) throw new Error('refused: an attestation needs the CI policy (repository) it must meet');
  const opts: VerifyStatementOptions = { ...base, ...(attestationBundle !== undefined && ci ? { attestation: { bundle: attestationBundle, policy: ci } } : {}) };
  const v = verifyStatementEnvelope(env, opts);
  if (!v.ok) throw new Error(`refused: the statement does not verify (${v.reasons.join('; ')})`);
  const { svc } = open(dir);
  const size = await svc.size();
  for (let i = 0; i < size; i++) if (b64u(await svc.getEntry(i)) === env.statement) throw new Error('refused: the statement is already registered');
  const r = await svc.register(fromB64u(env.statement));
  if (attestationBundle !== undefined) {
    mkdirSync(join(dir, 'attestations'), { recursive: true });
    writeFileSync(join(dir, 'attestations', `${r.index}.json`), JSON.stringify(attestationBundle));
  }
  return { index: r.index, root: r.root, tier: v.tier ?? 'self-attested' };
}

/** Everything a third party needs to audit the registry: every statement, a receipt for each, the current head. */
export async function registryExport(dir: string): Promise<RegistryExport> {
  const { svc, key } = open(dir);
  const size = await svc.size();
  const entries: RegistryEntry[] = [];
  for (let i = 0; i < size; i++) {
    const r = await svc.getReceipt(i);
    const af = join(dir, 'attestations', `${i}.json`);
    entries.push({ index: i, statement: b64u(await svc.getEntry(i)), receipt: b64u(r.receipt), ...(existsSync(af) ? { attestation: JSON.parse(readFileSync(af, 'utf8')) as unknown } : {}) });
  }
  return { format: REGISTRY_FORMAT, registry_key: publicKeyB64u(key), head: { size, root: size ? await svc.root() : '' }, entries };
}

export interface RegistryCheck {
  ok: boolean;
  reasons: string[];
  /** Entries that verified, with their decoded payloads. */
  verified: { index: number; payload: StatementPayload; tier: Tier; attestation?: CiAttestation }[];
}

export interface RegistryVerifyOptions extends VerifyStatementOptions {
  /** The registry's public key (SPKI base64url), pinned by the caller. Required: the key inside the export proves nothing. */
  registryKey: string;
  /** The CI policy that entries' attestation bundles must meet to be listed as CI-attested. Without it every entry is self-attested. */
  ci?: CiPolicy;
  /** An earlier export of the same registry: this one must contain it unchanged as a prefix (append-only). */
  previous?: RegistryExport;
}

/** Verify a registry export: the pinned key, every receipt against the head, every statement, and (optionally) append-only against an earlier export. */
export function verifyRegistryExport(exp: RegistryExport, opts: RegistryVerifyOptions): RegistryCheck {
  const reasons: string[] = [];
  const verified: RegistryCheck['verified'] = [];
  try {
    if (exp?.format !== REGISTRY_FORMAT || !Array.isArray(exp.entries)) return { ok: false, reasons: ['not a pca-verified registry export'], verified };
    if (!opts.registryKey) return { ok: false, reasons: ['the registry key must be pinned'], verified };
    if (exp.registry_key !== opts.registryKey) reasons.push('export is signed by a different registry key than the pinned one');
    const vk = createPublicKey({ key: Buffer.from(fromB64u(opts.registryKey)), format: 'der', type: 'spki' });
    if (exp.head.size !== exp.entries.length) reasons.push('head size does not match the number of entries');
    exp.entries.forEach((e, i) => {
      if (e.index !== i) { reasons.push(`entry ${i}: index out of order`); return; }
      let cose: Uint8Array;
      let rec: Uint8Array;
      try { cose = fromB64u(e.statement); rec = fromB64u(e.receipt); } catch { reasons.push(`entry ${i}: malformed`); return; }
      if (!verifyReceipt(rec, cose, { verificationKey: vk, treeRoot: exp.head.root })) { reasons.push(`entry ${i}: receipt does not verify against the head`); return; }
      let env: StatementEnvelope;
      try { env = envelopeOf(cose); } catch { reasons.push(`entry ${i}: statement is not decodable`); return; }
      const { ci, registryKey: _k, previous: _p, ...base } = opts;
      const v = verifyStatementEnvelope(env, { ...base, ...(e.attestation !== undefined && ci ? { attestation: { bundle: e.attestation, policy: ci } } : {}) });
      if (!v.ok || !v.payload) { reasons.push(`entry ${i}: ${v.reasons.join('; ')}`); return; }
      verified.push({ index: i, payload: v.payload, tier: v.tier ?? 'self-attested', ...(v.attestation ? { attestation: v.attestation } : {}) });
    });
    if (opts.previous) {
      const prev = opts.previous;
      if (prev.registry_key !== exp.registry_key) reasons.push('previous export is from a different registry');
      if (prev.entries.length > exp.entries.length) reasons.push('the registry shrank');
      else prev.entries.forEach((p, i) => { if (exp.entries[i]?.statement !== p.statement) reasons.push(`entry ${i} changed since the previous export`); });
    }
  } catch (e) {
    reasons.push(`unexpected: ${(e as Error).message}`);
  }
  return { ok: reasons.length === 0, reasons, verified };
}

const esc = (s: string): string => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
const tierCell = (t: Tier, a?: CiAttestation): string => (t === 'ci-attested' && a ? `<strong>CI-attested</strong> <span class="v">${esc(a.repo)}${a.ref ? ' @ ' + esc(a.ref) : ''}</span>` : 'self-attested');
const slug = (s: string): string => s.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'x';

export interface RegistryPage {
  /** Relative path -> content. `index.html`, `registry.json`, and one badge pair per entry under `badges/`. */
  files: Record<string, string>;
}

/**
 * The static listing: implementations that hold a verified statement, grouped by profile. Refuses to render a registry that does not
 * verify (a listing is a claim; it is never built from entries that failed). No scripts, no external requests.
 */
export function renderRegistryPage(exp: RegistryExport, opts: RegistryVerifyOptions): RegistryPage {
  const check = verifyRegistryExport(exp, opts);
  if (!check.ok) throw new Error(`refused: the registry does not verify (${check.reasons.join('; ')})`);
  const files: Record<string, string> = { 'registry.json': JSON.stringify(exp, null, 1) + '\n' };
  const byProfile = new Map<string, { index: number; payload: StatementPayload; file: string; tier: Tier; att?: CiAttestation }[]>();
  for (const v of check.verified) {
    const p = v.payload;
    const file = `badges/${slug(p.profile)}/${slug(p.implementation.name)}-${slug(p.implementation.version)}-${v.index}`;
    const badge = makeBadge(envelopeOf(fromB64u((exp.entries[v.index] as RegistryEntry).statement)), opts);
    files[`${file}.svg`] = badge.svg;
    files[`${file}.json`] = JSON.stringify(badge.endpoint) + '\n';
    const list = byProfile.get(p.profile) ?? [];
    list.push({ index: v.index, payload: p, file, tier: v.tier, ...(v.attestation ? { att: v.attestation } : {}) });
    byProfile.set(p.profile, list);
  }
  const sections = [...byProfile.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([profile, rows]) => {
    rows.sort((a, b) => (a.payload.implementation.name === b.payload.implementation.name ? b.index - a.index : a.payload.implementation.name < b.payload.implementation.name ? -1 : 1));
    const trs = rows.map((r) => {
      const p = r.payload;
      const day = new Date(p.issued_at).toISOString().slice(0, 10);
      return `<tr><td>${esc(p.implementation.name)}${p.implementation.vendor ? ` <span class="v">${esc(p.implementation.vendor)}</span>` : ''}</td><td>${esc(p.implementation.version)}</td><td>${esc(p.corpus.version)}</td><td>${day}</td><td>${tierCell(r.tier, r.att)}</td><td><code>${keyFingerprint(p.signer_key)}</code></td><td>#${r.index}</td><td><img alt="badge" src="${esc(r.file)}.svg"></td></tr>`;
    });
    return `<h2>${esc(profile)}</h2><table><thead><tr><th>Implementation</th><th>Version</th><th>Corpus</th><th>Attested</th><th>Tier</th><th>Signer</th><th>Log</th><th></th></tr></thead><tbody>${trs.join('')}</tbody></table>`;
  });
  files['index.html'] = [
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PCA Verified registry</title>',
    '<style>body{font:16px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%;margin-bottom:2rem}th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #8884}.v{opacity:.7}code{font-size:.9em}</style></head><body>',
    `<h1>PCA Verified registry</h1><p>Implementations with a signed conformance statement, listed by profile. ${verifiedCount(check)} statement(s), log size ${exp.head.size}, log root <code>${esc(exp.head.root)}</code>. Every entry was checked when this page was built; check them yourself with <code>pca-verified registry verify registry.json --key ${esc(exp.registry_key)}</code>.</p>`,
    ...sections,
    '</body></html>',
  ].join('\n');
  return { files };
}
const verifiedCount = (c: RegistryCheck): number => c.verified.length;

const BEGIN = '<!-- verified:registry:start -->';
const END = '<!-- verified:registry:end -->';

/** The registry as a markdown listing (verified entries only, grouped by profile, with the trust tier of each). */
export function renderRegistryMarkdown(exp: RegistryExport, opts: RegistryVerifyOptions): string {
  const check = verifyRegistryExport(exp, opts);
  if (!check.ok) throw new Error(`refused: the registry does not verify (${check.reasons.join('; ')})`);
  if (!check.verified.length) return '_No implementation has been registered yet._\n';
  const profiles = [...new Set(check.verified.map((v) => v.payload.profile))].sort();
  const md = (s: string): string => s.replace(/[\\`*_{}\[\]<>()#+!|]/g, '\\$&').replace(/\s+/g, ' ');
  const out: string[] = [`Log size ${exp.head.size}, root \`${exp.head.root}\`, registry key \`${exp.registry_key}\`.\n`];
  for (const p of profiles) {
    out.push(`### ${p}\n`, '| Implementation | Version | Corpus | Attested | Tier | Signer |', '|---|---|---|---|---|---|');
    for (const v of check.verified.filter((x) => x.payload.profile === p).sort((a, b) => b.index - a.index)) {
      const x = v.payload;
      const tier = v.tier === 'ci-attested' && v.attestation ? `CI-attested (${md(v.attestation.repo)})` : 'self-attested';
      out.push(`| ${md(x.implementation.name)} | ${md(x.implementation.version)} | ${md(x.corpus.version)} | ${new Date(x.issued_at).toISOString().slice(0, 10)} | ${tier} | \`${keyFingerprint(x.signer_key)}\` |`);
    }
    out.push('');
  }
  return out.join('\n');
}

/** Replace the generated block of a docs page (between the registry markers) with `listing`. */
export function updateRegistryPage(page: string, listing: string): string {
  const a = page.indexOf(BEGIN);
  const b = page.indexOf(END);
  if (a < 0 || b < a) throw new Error('the page has no registry markers');
  return `${page.slice(0, a + BEGIN.length)}\n\n${listing.trim()}\n\n${page.slice(b)}`;
}
